---
title: "PatchGuard"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[PatchGuard Security]]"
updated: 2026-11-03
---
# PatchGuard

> [!abstract] TL;DR
> Do not patch kernel internals. Record the supported extension point and its coverage limits; link [[WinDbg]] for crash-analysis commands.

> [!info] Agent scope
> Kernel Patch Protection purpose; unsupported modification risks; version sensitivity; supported alternatives; crash-analysis links only.

## Prerequisites

- C, kernel callback lifetime, driver signing, and [[Kernel Architecture]]. Offline lab: Python 3.11+ standard library. Optional source compilation: already installed VS 2022 x64 tools and WDK 10.0.26100.
- Runtime validation requires an approved disposable Windows 11 x64 VM, snapshot, local console, and matching symbols. No kernel patching, induced bug checks, protection changes, host boot modifications, or VPN disruption are part of this note.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows Kernel Patch Protection (PatchGuard) at expert defensive driver
design depth. Assume C, kernel execution contracts, and driver lifecycle.
Focus on documented x64 patching policy, supported extension points, and
integrity-failure interpretation on Windows 11; distinguish historical versions
and nonpublic implementation details. Explain detection versus prevention,
delayed failure, why no-crash tests do not establish support, and separation
from signing, HVCI, Secure Boot, and ordinary driver correctness. Map concrete
requirements to notifications, object callbacks, minifilters, WFP, and ETW with
coverage limits. Supply genuine benign source and complete offline review tests.
Use Microsoft sources; debugger procedures remain in a dedicated tool reference.
No bypasses, patching recipes, induced corruption, or host security changes.
Teach here without file edits or study-state changes.
```

## Cheatsheet

### Policy, Not an Extension Interface

Kernel Patch Protection is commonly called PatchGuard. Its engineering consequence is straightforward: third-party drivers must not modify protected kernel code/data or rely on undocumented replacement of system behavior. Microsoft's 0x109 documentation identifies the x64 restriction from Windows Server 2003 SP1 onward and distinguishes authorized Microsoft-originated hotpatching. This is not permission for third parties to reproduce internal hotpatch mechanisms.

Protected regions, checks, timing, and implementation evolve across builds and are not a supported ABI. Avoid claims that a fixed list or interval describes every Windows release. This note's scope is x64; do not infer identical behavior for all architectures from the name alone. An internal symbol found in a particular build is not a supported registration interface.

Detection may occur after the offending operation. A crash stack can therefore show the detecting path rather than the original writer. A short successful load/unload test proves only that no observed failure occurred during that interval; it does not turn an unsupported modification into a supported design. Do not use absence of a bug check as a compatibility test for patching.

### Keep the Protections Separate

| Mechanism | Relevant question | Not a substitute for |
|---|---|---|
| Secure Boot | Was this early executable authorized under boot trust policy? | Runtime driver correctness |
| Driver signing / Code Integrity | Is the image eligible to load under current policy? | Safe IOCTLs or correct synchronization |
| HVCI | Are code-integrity decisions isolated and executable-memory rules enforced? | Lifetime, cancellation, and logic checks |
| Kernel Patch Protection | Was selected protected state found corrupted/modified? | General input validation or complete prevention of kernel defects |
| Driver Verifier | Did an exercised driver violate selected runtime rules? | Proof of all possible interleavings |

These are complementary controls. A permitted driver may still be buggy; a driver using only documented DDIs may still misuse them. A protected-state corruption report does not imply malicious intent, and a malicious-intent conclusion requires independent evidence.

### Supported Requirement Mapping

| Requirement | Supported mechanism | Coverage/contract to preserve |
|---|---|---|
| Observe process lifecycle | Process notification APIs | Temporary data, PASSIVE/APC restrictions, removal before unload |
| Observe image mappings | Image notification APIs | Observation, not universal deny or retroactive inventory |
| Restrict selected new handle rights | Object callbacks | Supported object types/operations; remove allowed rights only |
| Observe/filter filesystem I/O | Filter Manager minifilter | Attached volumes, registered operations, pre/post/draining semantics |
| Network authorization/inspection | WFP filters/callouts | Correct layer/family, arbitration rights, flow/packet lifetime |
| Publish diagnostics | WPP/ETW with documented providers | Loss/latency/privacy limits; telemetry is not enforcement |

If the requirement has no supported extension point, narrow or redesign the feature rather than inventing a hook. A user-mode service can often perform policy analysis while the kernel component supplies minimal documented observations. That split reduces kernel complexity but introduces service availability, message authorization, and queue-limit decisions.

### Genuine Supported Image Observer

Complete `image_observer.c` counts only notifications; it never edits image state, retains input pointers, or denies a load. Source uses documented Windows 2000+ notification APIs; the target exercise baseline is Windows 11 x64. Callback capacity changed across historical Windows updates, so always handle registration failure instead of assuming a fixed global slot count.

### File: image_observer.c

```c
#include <ntddk.h>

static volatile LONG ImageEvents;
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ObserverUnload;

static VOID ObserveImage(PUNICODE_STRING fullImageName, HANDLE processId,
						 PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(fullImageName);
	UNREFERENCED_PARAMETER(processId);
	UNREFERENCED_PARAMETER(imageInfo);
	InterlockedIncrement(&ImageEvents);
}

VOID ObserverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
	(VOID)PsRemoveLoadImageNotifyRoutine(ObserveImage);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(registryPath);
	ImageEvents = 0;
	status = PsSetLoadImageNotifyRoutine(ObserveImage);
	if (!NT_SUCCESS(status)) return status;
	driver->DriverUnload = ObserverUnload;
	return STATUS_SUCCESS;
}
```

The callback runs at PASSIVE_LEVEL under documented notification constraints; it still must not perform arbitrary blocking or recursive work. The image name can be absent, which is harmless because it is not dereferenced. Counter wrap is acceptable telemetry loss. Removal must occur outside the callback and before image unload; this example relies on the documented successful-registration pairing. A production driver must diagnose unexpected removal failure and also drain any independently queued work before freeing state.

## Gotchas

Do not treat registration success as complete behavioral coverage. The observer sees future notifications while registered, not every prior image or every application execution decision. No public fixed "PatchGuard healthy" query proves all protected state is safe. Use [[WinDbg]] for crash analysis; this note intentionally includes no debugger commands.

## Labs

### Environment and Complete Files

Save `image_observer.c` and `review_observer.py` in an empty scratch directory. Python 3.11+ is sufficient; no driver loads, administrator rights, or network. The fixture checks actual supplied source against a narrow checklist and models notification lifetime, not PatchGuard internals.

### File: review_observer.py

```python
from pathlib import Path

def review(source):
	required = [
		"PsSetLoadImageNotifyRoutine(ObserveImage)",
		"PsRemoveLoadImageNotifyRoutine(ObserveImage)",
		"if (!NT_SUCCESS(status)) return status;",
		"InterlockedIncrement(&ImageEvents);",
	]
	return [text for text in required if text not in source]

source = Path("image_observer.c").read_text(encoding="utf-8")
assert review(source) == []
missing_remove = source.replace("PsRemoveLoadImageNotifyRoutine(ObserveImage)", "0")
assert review(missing_remove) == ["PsRemoveLoadImageNotifyRoutine(ObserveImage)"]

class Observer:
	def __init__(self):
		self.registered = False
		self.active = 0
		self.count = 0

	def register(self, success):
		self.registered = success
		return success

	def enter(self):
		if not self.registered:
			return False
		self.active += 1
		self.count += 1
		return True

	def leave(self):
		assert self.active > 0
		self.active -= 1

	def remove(self):
		self.registered = False
		return self.active == 0

failed = Observer()
assert not failed.register(False) and not failed.enter()
live = Observer()
assert live.register(True) and live.enter()
assert not live.remove()
assert not live.enter()
live.leave()
assert live.remove() and live.count == 1
print("PASS: source pairing, broken-source detection, observer lifetime")
```

### Objectives, Hints, and Worked Solution

Run `python review_observer.py`. Explain why missing unregister is a lifecycle defect even without any kernel patching. The deliberately broken source string omits the removal call and fails the required-symbol check; the supplied source passes. The live model admits one callback, closes admission, waits for that callback, then permits unload.

Hint: source-token presence is a review aid, not semantic proof. The requirement "observe image mappings" is met using a documented notification; a new requirement "deny every image" is not met by this API and requires a different supported policy design. The correct answer is not to mutate the callback's image argument.

### Build, Verification, and Cleanup

No author execution. Optional object compilation in an existing x64 WDK prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" image_observer.c`. Missing headers mean the optional prerequisite is absent. No INF, catalog, signing, install, or runtime package is supplied.

The expected Python result is the PASS line. Runtime registration capacity, real callback context, unload races, signing policy, and load/work/unload stability remain unexecuted scope for a reviewed package in a snapshot-backed VM. No corruption should ever be induced to test PatchGuard. Delete scratch files and object output. Nothing requires host reconfiguration or service removal.

### Existing Study Checklist

- [ ] Local PatchGuard exercise: Review a driver design and replace proposed kernel patching with documented callbacks or filters. Study a public sample crash analysis without modifying protected kernel structures.
- [ ] Boundary check: Validate that the benign lab driver uses only documented registration/unregistration paths and remains stable through load, workload, and unload cycles.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[PatchGuard Security]]

## References

- [0x109 and Microsoft's documented x64 patching restriction](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption)
- [Driver security checklist](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist)
- [Image notification registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)
- [Image notification removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremoveloadimagenotifyroutine)
