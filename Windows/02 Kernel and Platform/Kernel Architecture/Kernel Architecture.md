---
title: "Kernel Architecture"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[Kernel Architecture Security]]"
updated: 2026-11-03
---
# Kernel Architecture

> [!abstract] TL;DR
> A kernel path has five independent contracts: IRQL, thread context, residency, synchronization, and lifetime. Satisfying one does not satisfy the others.

> [!info] Agent scope
> IRQL; DPC/APC; scheduler; synchronization; execution context; pageable versus nonpageable code.

## Prerequisites

- C pointer ownership and concurrency; Windows x64 terminology. Offline lab: Python 3.11+ standard library, no administrator rights or network.
- Kernel source below targets Windows 11 x64 and WDK 10.0.26100 headers. It is a translation-unit example, not an installable driver. Runtime work requires a separately approved, snapshot-backed Windows VM with matching symbols, console access, and a recovery plan. Never change host protections or VPN.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows kernel execution contracts at expert driver-engineering depth.
Assume C, x64, and basic threading. Target Windows 11 x64; identify API minimum
versions and differences from older WDM and current KMDF. Trace an interrupt,
ordinary DPC, queued work item, and request completion. Separate CPU-local IRQL
from thread priority, process address context, APC delivery, and authorization.
Explain preemption, priority inversion, pageable code/data, blocking versus
zero-timeout waits, spin locks, executive locks, and object rundown. Work through
lock ordering and cancellation interleavings. Supply benign complete examples,
contract assertions, expected failure evidence, and a disposable-VM test plan.
Use Microsoft DDI/WDF sources; distinguish a model from kernel execution.
Exclude exploitation and undocumented modification. Give difficult scenarios
with worked answers. Teach here without file edits or study-state changes.
```

## Cheatsheet

### Execution Context

| Context | Typical IRQL and constraints | Appropriate work |
|---|---|---|
| DriverEntry, unload, system worker | PASSIVE_LEVEL; not necessarily the requesting process | Initialization, bounded passive processing, teardown |
| Normal kernel APC | PASSIVE_LEVEL, delivery depends on thread/APC state | Thread-associated work; not an arbitrary notification mechanism |
| Special kernel APC | APC_LEVEL | Restricted kernel work; normal APC delivery is disabled |
| Ordinary DPC | DISPATCH_LEVEL; arbitrary thread context | Short nonblocking processing on resident state |
| ISR | Device IRQL for traditional interrupts | Acknowledge interrupt and queue deferred work |

These are not universal dispatch guarantees. Completion routines can run at DISPATCH_LEVEL; storage requests can arrive at APC_LEVEL. Threaded DPCs and passive-level interrupt handling are distinct documented mechanisms, not exceptions to assume for ordinary DPCs.

IRQL masks classes of interrupts on the current processor. Raising it neither excludes another processor nor grants access rights. The scheduler chooses ready threads using priorities and affinity; ordinary DPC execution is not a newly scheduled application thread. Long DPCs delay normal work and can trigger watchdog failures. Raising a thread's priority cannot repair a deadlock.

At DISPATCH_LEVEL or above, the entire reachable code/data path must be resident. Marking the entry routine nonpageable is insufficient if it calls pageable helpers. `PAGED_CODE()` is a checked-build assertion, not a way to make unsafe code safe. An allocation succeeding once does not prove its residency or lifetime.

### Synchronization and Waiting

| Primitive | Contract | Frequent mistake |
|---|---|---|
| `KeAcquireSpinLock` / `KeReleaseSpinLock` | Caller <= DISPATCH_LEVEL; raises to DISPATCH_LEVEL, restores saved IRQL | Sleeping, pageable access, or calling unknown callbacks while held |
| `KeAcquireSpinLockAtDpcLevel` | Caller already at DISPATCH_LEVEL; pair with FromDpcLevel release | Mixing release families and losing the original IRQL |
| `FAST_MUTEX` | Acquire at <= APC_LEVEL; ordinary acquisition raises to APC_LEVEL | Assuming PASSIVE_LEVEL after acquiring it |
| `ERESOURCE` | <= APC_LEVEL; normal kernel APCs must be disabled as required | Forgetting critical-region pairing or lock ordering |
| Interlocked operation | Atomic operation on suitably aligned resident storage | Assuming atomic counter update protects an entire object |
| Rundown protection | Blocks new acquisitions during shutdown and drains existing holders | Acquiring through a pointer that was already freed |

For `KeWaitForSingleObject`, a zero timeout allows a nonblocking test at <= DISPATCH_LEVEL. A nonzero or NULL timeout requires <= APC_LEVEL and an appropriate thread context; individual callers can impose stronger constraints. PASSIVE_LEVEL alone does not make waiting safe: a lock holder can deadlock the worker needed to signal the event. Never lower an inherited IRQL to make an otherwise illegal operation appear legal.

### Genuine Kernel Source

Complete helper translation unit `counter.c`; initialized and owned by a hypothetical device object. No allocation, I/O, registration, or entry point is supplied or implied. All callers must stop before owner destruction. It can be compiled with an existing x64 WDK environment; this lab does not install one.

### File: counter.c

```c
#include <ntddk.h>

typedef struct _LAB_COUNTER {
	KSPIN_LOCK Lock;
	ULONG Value;
} LAB_COUNTER;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID CounterInitialize(LAB_COUNTER *counter)
{
	KeInitializeSpinLock(&counter->Lock);
	counter->Value = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG CounterIncrement(LAB_COUNTER *counter)
{
	KIRQL previousIrql;
	ULONG snapshot;
	KeAcquireSpinLock(&counter->Lock, &previousIrql);
	counter->Value += 1;
	snapshot = counter->Value;
	KeReleaseSpinLock(&counter->Lock, previousIrql);
	return snapshot;
}
```

The counter wraps modulo 2^32; it is telemetry, not a unique identifier. A lock serializes updates but does not keep `counter` alive. Use a single lock order if a path touches multiple owners. An interlocked increment would be preferable for this isolated counter; the lock illustrates a multi-field critical-section pattern.

## Gotchas

Queued work runs later at PASSIVE_LEVEL but generally not in the caller's process. Capture owned data before queuing; never carry a transient stack address or unreferenced request buffer into the worker. KMDF parenting helps disposal but does not replace explicit producer shutdown. Debugging and Driver Verifier belong only in the disposable VM; see [[WinDbg]].

## Labs

### Environment and Complete Files

Create an empty scratch directory, containing `counter.c` above and `contracts.py` below. No kernel module is loaded. Python interprets explicit contract traces, not Windows scheduling. The source checks detect specific regressions only, not arbitrary C errors.

### File: contracts.py

```python
from pathlib import Path

def violations(steps):
	level, held, errors = 0, [], []
	for action, value in steps:
		if action == "irql":
			level = value
		elif action == "lock":
			if held and value <= held[-1]:
				errors.append("lock-order")
			held.append(value)
		elif action == "unlock":
			if not held or held.pop() != value:
				errors.append("unlock-order")
		elif action == "page" and level >= 2:
			errors.append("page-at-dispatch")
		elif action == "wait" and (level >= 2 or held):
			errors.append("blocking-wait")
		elif action == "user-pointer" and value != "captured":
			errors.append("uncaptured-pointer")
	if held:
		errors.append("lock-leak")
	return errors

cases = [
	([("irql", 2), ("page", None)], ["page-at-dispatch"]),
	([("irql", 2), ("wait", None)], ["blocking-wait"]),
	([("lock", 2), ("lock", 1), ("unlock", 1), ("unlock", 2)],
	 ["lock-order"]),
	([("irql", 0), ("user-pointer", "raw")], ["uncaptured-pointer"]),
	([("irql", 2), ("lock", 1), ("unlock", 1),
	  ("irql", 0), ("user-pointer", "captured"), ("wait", None)], []),
]
for steps, expected in cases:
	assert violations(steps) == expected, steps
source = Path("counter.c").read_text(encoding="utf-8")
assert "KeAcquireSpinLock(&counter->Lock, &previousIrql);" in source
assert "KeReleaseSpinLock(&counter->Lock, previousIrql);" in source
assert "KeWaitForSingleObject" not in source
print("PASS: 5 traces and counter source contract")
```

### Objectives and Steps

1. Annotate why each of the first four traces violates a different contract.
2. Run `python contracts.py` from the scratch directory. No build is needed for the offline exercise.
3. Optional compile-only check, in an already provisioned WDK developer prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" counter.c`. The WDK include root must point to an existing matching kit; no SYS/INF or runtime result follows from a successful object compilation.

### Hints

A lock order is global, not local to a single function. The trace's `wait` means a blocking wait, not a zero-timeout test. The model deliberately adopts the stronger rule of no blocking while holding any modeled lock.

### Solution and Expected Results

Move pageable/blocking processing to owned passive work, keep the DPC resident and short, acquire lock 1 before lock 2 everywhere, and capture data while its originating request remains valid. The fifth trace models these corrections. Expected output is `PASS: 5 traces and counter source contract`; deleting the matching release line should fail a source assertion.

### Verification, Troubleshooting, and Cleanup

Not executed during authoring. `FileNotFoundError` means the current directory lacks `counter.c`; an unavailable `cl`/WDK means skip the optional compile. This fixture cannot establish real IRQL, race freedom, scheduler latency, or safe unload. Those require a complete reviewed driver and VM runtime tests, which are outside this helper lab. Delete the scratch directory and any object file; no system state changed.

### Existing Study Checklist

- [ ] Local Kernel Architecture exercise: Study a benign documented driver sample and annotate dispatch, callback, DPC, and worker-thread contexts. Verify its IRQL assumptions in a disposable debug VM using [[WinDbg]].
- [ ] Boundary check: Run a benign sample under appropriate Driver Verifier checks in a snapshot-backed target and confirm supported workloads produce no reported IRQL or lock violations.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[WinDbg]]
- [[Kernel Architecture Security]]

## References

- [Managing hardware priorities](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities)
- [KeWaitForSingleObject contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject)
- [Framework work items](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-framework-work-items)
- [Introduction to DPC objects](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-dpc-objects)
