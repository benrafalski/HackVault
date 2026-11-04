---
title: "Kernel Architecture Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[Kernel Architecture]]"
updated: 2026-11-03
---
# Kernel Architecture Security

> [!abstract] TL;DR
> Invalid waits, pageable access at elevated IRQL, lock inversions, and lifetime races can crash or corrupt the kernel.

> [!info] Agent scope
> Security of IRQL, DPC/APC, scheduling, synchronization, execution context, residency, and lifetime. Defensive validation and crash triage only.

## Attack Surface

- Invalid waits, pageable access at elevated IRQL, lock inversions, and lifetime races can crash or corrupt the kernel.
- Requests, cancellation, timer expiry, power transitions, and device removal can race even with harmless inputs. Untrusted callers can increase concurrency, but ordinary workload already exposes the defects.

## Learn

```text
Teach defensive Windows kernel concurrency review at expert depth. Assume C,
IRQL, and basic lock semantics; target Windows 11 x64 and WDK 10.0.26100.
Trace DPC-to-worker handoff, cancellation, removal, and unload. Distinguish
residency, APC restrictions, request ownership, references, and exclusion.
Explain use-after-free root causes with harmless state-machine interleavings,
lock inversion, elevated-IRQL waits, and lost wakeups. Show documented rundown
and KMDF ownership alternatives, including their failure modes and version
requirements. Supply complete offline regression fixtures and separate VM-only
verification criteria. Explain what crash evidence can and cannot attribute.
Use Microsoft DDI/WDF sources; no exploitation, protection changes on a host,
or undocumented patching. Teach in conversation, without editing files.
```

## Cheatsheet

### Root Causes and Defensive Review

| Defect | Causal chain | Required invariant |
|---|---|---|
| Pageable DPC helper | Elevated IRQL reaches pageable instruction/data | Entire transitive path resident, including indirect calls |
| Lock inversion | Worker owns A and waits for B; completion owns B and waits for A | One global lock order; no external callbacks under internal locks |
| Use after free | Queued work holds pointer; removal frees owner | Stop admissions, drain producers and consumers, then free |
| Double completion | Cancellation and success both complete request | Exactly one owner wins transition to terminal state |
| Incorrect process context | Worker dereferences requestor virtual address | Capture/copy or lock/map through documented request APIs |
| Lost wakeup | Worker sees empty queue while producer sees worker as active | Queue contents and scheduling flag share synchronization |

Nonpaged memory can still be freed. A reference can keep memory alive without serializing mutations. A spin lock can serialize mutations without keeping memory alive. `volatile` establishes neither lifetime nor cross-thread protocol. Interlocked operations provide atomicity and ordering for their documented operations, not a complete cancellation design.

Normal kernel APC suppression is not the same as raising IRQL. Calling APIs that depend on APC delivery inside a critical region can deadlock despite PASSIVE_LEVEL. SAL annotations are valuable compile-time contracts, not runtime enforcement. Modern WDK analysis availability varies; do not assume legacy Static Driver Verifier is present in every kit.

### Genuine Rundown Helper

Complete `rundown.c`, a WDM helper translation unit, not a loadable driver. Windows XP+ provides these rundown DDIs; this example targets Windows 11 x64. All entry points deliberately require PASSIVE_LEVEL, a stricter constraint than some underlying DDIs. The owner must stay allocated until producers have lost access to its address and teardown returns. A lock protecting a global owner pointer or framework-owned lifetime is still necessary.

### File: rundown.c

```c
#include <ntddk.h>

typedef struct _LAB_OWNER {
	EX_RUNDOWN_REF Rundown;
	volatile LONG Count;
} LAB_OWNER;

_IRQL_requires_(PASSIVE_LEVEL)
VOID OwnerInitialize(LAB_OWNER *owner)
{
	ExInitializeRundownProtection(&owner->Rundown);
	owner->Count = 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN OwnerRecord(LAB_OWNER *owner)
{
	if (!ExAcquireRundownProtection(&owner->Rundown)) {
		return FALSE;
	}
	InterlockedIncrement(&owner->Count);
	ExReleaseRundownProtection(&owner->Rundown);
	return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID OwnerDrain(LAB_OWNER *owner)
{
	ExWaitForRundownProtectionRelease(&owner->Rundown);
}
```

`OwnerDrain` must not run while holding a lock that a protected user needs, or while the current thread holds its own rundown reference. Rundown is one-way until explicitly reinitialized under documented conditions; do not reuse an owner while old producers can still reach it. Worker handoff requires retaining protection until the worker finishes, not releasing immediately after enqueue.

## Detection and Defense

Use documented DDIs, framework queues and cancellation APIs, bounded elevated-IRQL work, allocation-failure handling, and explicit shutdown state machines. Review every early return for reference and lock balancing. Retain OS build, driver version/hash, workload, timestamps, dump provenance, and matched symbols; stacks show where failure surfaced, not necessarily where corruption began. Use [[WinDbg]] for crash-analysis commands.

Driver Verifier IRQL checking, pool checks, deadlock detection, and I/O verification are VM-only runtime gates for a complete driver. Select only the reviewed test driver and retain a snapshot/console recovery route; no Verifier or boot-setting commands are part of this offline lab. HVCI does not repair logical races in permitted driver code.

## Labs

### Environment and Complete Files

Python 3.11+ standard library, ordinary user, empty scratch directory. Save the helper as `rundown.c` and this entire fixture as `rundown_test.py`. It deterministically demonstrates a lifetime failure without allocating or dereferencing kernel memory.

### File: rundown_test.py

```python
from pathlib import Path

class Owner:
	def __init__(self):
		self.closing = False
		self.references = 0
		self.alive = True

	def acquire(self):
		if self.closing or not self.alive:
			return False
		self.references += 1
		return True

	def release(self):
		assert self.references > 0
		self.references -= 1

	def drain(self):
		self.closing = True
		return self.references == 0

	def free(self):
		assert self.closing and self.references == 0
		self.alive = False

def touch(owner):
	if not owner.alive:
		raise RuntimeError("stale-owner")

unsafe = Owner()
unsafe.alive = False
try:
	touch(unsafe)
except RuntimeError as error:
	assert str(error) == "stale-owner"
else:
	raise AssertionError("baseline must expose lifetime failure")

fixed = Owner()
assert fixed.acquire()
assert not fixed.drain()
assert not fixed.acquire()
touch(fixed)
fixed.release()
assert fixed.drain()
fixed.free()
assert not fixed.acquire()

source = Path("rundown.c").read_text(encoding="utf-8")
for name in ("ExInitializeRundownProtection", "ExAcquireRundownProtection",
			 "ExReleaseRundownProtection", "ExWaitForRundownProtectionRelease"):
	assert name in source, name
assert source.index("InterlockedIncrement") < source.index("ExReleaseRundownProtection")
print("PASS: stale baseline detected; protected work drains; new work denied")
```

### Objectives, Hints, and Worked Solution

Run `python rundown_test.py`. Explain why the admitted operation may finish after shutdown starts, while the next acquisition must fail. Hint: shutdown closes admission before it waits; simply observing a zero count is racy if admission stays open.

The baseline models removal freeing state before queued work uses it; the exception is the intended observation. The fixed path retains a reference, rejects new admission, permits the existing touch, then frees only after release. Expected output is the single PASS line in the file. Changing `free` to ignore the reference count destroys the safety invariant; do not reproduce the defect in a driver.

### Verification, Troubleshooting, and Cleanup

No author execution. This model checks one interleaving and source API presence, not the C implementation's concurrency correctness. No build required offline. Optional helper compilation requires an existing x64 WDK developer environment and `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" rundown.c`. A missing kit is a prerequisite failure, not a reason to install or weaken host settings.

Actual unload/cancellation stress needs an independently reviewed complete driver in a disposable VM, not supplied by this helper. `FileNotFoundError` means incorrect scratch location. Delete the two files and any object output to reset. No host configuration, network, or VPN changes.

### Existing Study Checklist

- [ ] Local Kernel Architecture exercise: Study a benign documented driver sample and annotate dispatch, callback, DPC, and worker-thread contexts. Verify its IRQL assumptions in a disposable debug VM using [[WinDbg]].
- [ ] Boundary check: Run a benign sample under appropriate Driver Verifier checks in a snapshot-backed target and confirm supported workloads produce no reported IRQL or lock violations.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[WinDbg]]
- [[Kernel Architecture]]

## References

- [Managing hardware priorities](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities)
- [Run-down protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection)
- [ExWaitForRundownProtectionRelease](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exwaitforrundownprotectionrelease)
- [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
