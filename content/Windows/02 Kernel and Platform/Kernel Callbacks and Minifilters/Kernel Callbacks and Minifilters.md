---
title: "Kernel Callbacks and Minifilters"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[Kernel Callbacks and Minifilters Security]]"
updated: 2026-11-03
---
# Kernel Callbacks and Minifilters

> [!abstract] TL;DR
> Choose the documented extension point; record IRQL, reentrancy, object lifetime, and completion semantics. Avoid blocking or recursive I/O where prohibited.

> [!info] Agent scope
> Documented callbacks; process/thread/image notifications; object callbacks; filesystem minifilters; altitude; lifetime and synchronization.

## Prerequisites

- C, IRQL, ownership, and [[Windows Drivers]]. Offline: Python 3.11+ standard library. Source baseline: Windows 11 x64, WDK 10.0.26100; API minimum versions are distinguished below.
- Driver runtime requires a disposable, snapshot-backed VM with local console and matching symbols. The source is for offline review/optional object compilation, not a signed deployment package. No host boot, security, or VPN changes.
- [[Windows Lab Setup]]

## Learn

```text
Teach documented Windows process/thread/image callbacks, object callbacks, and
filesystem minifilters at expert depth. Assume C, IRQL, and reference ownership.
Target Windows 11 x64; state minimum OS/DDI versions and signed-image conditions.
Compare observation versus veto/access reduction. Trace registration, callback
context, transient parameters, queued work, failure unwind, and unregister.
Explain minifilter altitude, instances, pre/post statuses, draining, name queries,
contexts, reentrancy, and communication ports. Work complete benign source and
offline fixtures with expected evidence; distinguish static checks from runtime.
Use Microsoft DDI/Filter Manager documentation. No patching, unhooking, evasion,
or host protection changes. Teach here without file edits or study-state changes.
```

## Cheatsheet

### Choose the Actual Contract

| Extension | Meaning and limits | Context/lifetime |
|---|---|---|
| `PsSetCreateProcessNotifyRoutineEx` | Creation/exit; creation callback can set failing `CreationStatus` | Vista SP1+; PASSIVE_LEVEL, critical region, normal kernel APCs disabled; `CreateInfo == NULL` means exit |
| `PsSetCreateThreadNotifyRoutine` | Thread create/delete observation, not general veto | PASSIVE_LEVEL; classic API and Ex notification variants have different execution-context details |
| `PsSetLoadImageNotifyRoutine` | Image mapping notifications, not a general image-blocking API | PASSIVE_LEVEL; callback string can be NULL; never assume NUL termination or a stable retained pointer |
| `ObRegisterCallbacks` | Pre/post handle create/duplicate for supported object types; can remove permitted access bits | Vista SP1+; registration <= APC_LEVEL; callbacks PASSIVE_LEVEL with normal kernel APCs disabled |
| Filter Manager | Registered filesystem operations at attached instances | Preoperation usually PASSIVE/APC; postoperation can be DISPATCH_LEVEL; operation-specific exceptions matter |

Object callbacks cannot add rights, rewrite arbitrary object internals, or revoke every existing handle. For supported process/thread access masks, reduce `DesiredAccess` only as documented; distinguish create and duplicate unions. Desktop object callback support starts with Windows 10. `ObRegisterCallbacks` requires callbacks in a signed kernel image and a unique altitude; do not borrow another product's altitude. Process Ex notification additionally requires the image's FORCE_INTEGRITY characteristic; a successful compile alone does not satisfy this.

Copy only needed callback data while valid. Counted `UNICODE_STRING` values are byte-counted and need not be terminated. Retaining an `EPROCESS` requires a reference and an explicit later dereference; a PID can be reused. Unregister outside the callback itself. Process-notify removal waits for active callbacks, but queued workers carrying copied data/references have their own drain protocol.

### Minifilter Ordering and Completion

`FltRegisterFilter` registers the driver; `FltStartFiltering` enables participation and may trigger callbacks before it returns. Initialize state first. On start failure, unregister. Instances attach to volumes, so filter presence alone does not prove coverage of a given volume. Altitude orders instances within Filter Manager: higher altitudes see preoperations earlier, while completion unwinds in the reverse direction. Use Microsoft's allocation process for production altitudes.

| Preoperation result | Ownership consequence |
|---|---|
| `FLT_PREOP_SUCCESS_NO_CALLBACK` | Continue; no post callback requested for this operation |
| `FLT_PREOP_SUCCESS_WITH_CALLBACK` | Continue and receive post callback; completion context must survive |
| `FLT_PREOP_COMPLETE` | Finish here; set valid `IoStatus.Status` and `Information` |
| `FLT_PREOP_PENDING` | Driver owns pending operation; complete later through documented API |
| `FLT_PREOP_SYNCHRONIZE` | For supported IRP operations, post executes <= APC_LEVEL in same thread; not a universal fix for async/paging paths |

Post callbacks return `FLT_POSTOP_FINISHED_PROCESSING`, or retain eligible IRP-based completion with `FLT_POSTOP_MORE_PROCESSING_REQUIRED` and later `FltCompletePendedPostOperation`. On `FLTFL_POST_OPERATION_DRAINING`, release completion context and finish; do not start normal processing or pend. Post-create is PASSIVE_LEVEL; ordinary post-I/O must tolerate DISPATCH_LEVEL unless its specific contract guarantees otherwise.

`FltGet*Context` and successful context allocation return references requiring `FltReleaseContext`. File-name queries have IRQL, top-level-I/O, and paging restrictions; a normalized path is not a permanent object identity. Reparse points, rename, hard links, alternate streams, cached I/O, and paging I/O all affect coverage. A pre-create callback sees a requested open, not necessarily a successful final file object.

### Genuine Notification Source

Complete `notify.c` uses documented registration and removal and only increments synthetic counters. It performs no policy enforcement or logging of process data. The interlocked counters reside in the driver's nonpaged image; overflow is acceptable telemetry loss, not an identifier.

### File: notify.c

```c
#include <ntddk.h>

static volatile LONG Creates;
static volatile LONG Exits;
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD LabUnload;

static VOID LabProcess(PEPROCESS process, HANDLE processId,
					   PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(processId);
	if (createInfo != NULL) {
		InterlockedIncrement(&Creates);
	} else {
		InterlockedIncrement(&Exits);
	}
}

VOID LabUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
	(VOID)PsSetCreateProcessNotifyRoutineEx(LabProcess, TRUE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(registryPath);
	Creates = 0;
	Exits = 0;
	status = PsSetCreateProcessNotifyRoutineEx(LabProcess, FALSE);
	if (!NT_SUCCESS(status)) return status;
	driver->DriverUnload = LabUnload;
	return STATUS_SUCCESS;
}
```

Unload relies on the documented successful-registration/removal pairing; a real driver must diagnose any unexpected removal failure before treating teardown as safe. There is no separate worker to drain here. Do not copy this design into a queued telemetry pipeline without adding bounded storage, rundown, and error handling.

## Gotchas

PASSIVE_LEVEL does not mean unrestricted blocking: callback callers may hold locks, disable APCs, or depend on forward progress. Avoid synchronous user-service round trips in process/image callbacks. Filter communication ports require ACLs, bounded message formats, disconnect handling, and timeouts; user-mode service availability is not guaranteed. Read-only VM inventory can use `fltmc filters` and `fltmc instances`; these do not enumerate every kernel callback.

## Labs

### Environment and Complete Files

Save `notify.c` above and `notify_test.py` below in an empty scratch directory. Python 3.11+ is sufficient; no driver installation, administrator access, or network.

### File: notify_test.py

```python
from pathlib import Path

class Registration:
	def __init__(self):
		self.registered = False
		self.active = 0
		self.creates = 0
		self.exits = 0

	def register(self, succeeds):
		self.registered = succeeds
		return succeeds

	def enter(self, creating):
		if not self.registered:
			return False
		self.active += 1
		if creating:
			self.creates += 1
		else:
			self.exits += 1
		return True

	def leave(self):
		assert self.active > 0
		self.active -= 1

	def remove(self):
		self.registered = False
		return self.active == 0

failed = Registration()
assert not failed.register(False)
assert not failed.enter(True)
live = Registration()
assert live.register(True)
assert live.enter(True)
assert not live.remove()
assert not live.enter(False)
live.leave()
assert live.remove()
assert (live.creates, live.exits) == (1, 0)
source = Path("notify.c").read_text(encoding="utf-8")
assert "PsSetCreateProcessNotifyRoutineEx(LabProcess, FALSE)" in source
assert "PsSetCreateProcessNotifyRoutineEx(LabProcess, TRUE)" in source
assert "if (createInfo != NULL)" in source
assert "if (!NT_SUCCESS(status)) return status;" in source
assert "CreationStatus =" not in source
print("PASS: registration failure, in-flight removal, source pairing")
```

### Objectives, Hints, and Worked Solution

Run `python notify_test.py`. Explain why unregister cannot finish at the first modeled removal, why a new callback cannot start, and why creation failures should not leave an unloadable half-initialized driver. Hint: the model's `remove()` returns whether the real API's wait could finish, not the real API's NTSTATUS.

Expected output is the PASS line. `active == 1` delays completion; after `leave`, removal is complete and no callback can access the image. Removing the TRUE registration counterpart fails the static check. The model tests one deterministic schedule; it does not call the OS.

### Build, Troubleshooting, and Cleanup

No author execution. Optional object compilation in an existing x64 WDK prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" notify.c`. No link, INF, catalog, signing, or runtime installation is supplied; linking would additionally need the documented integrity characteristic and signing requirements. A compile success proves neither callback admission nor unload safety.

Missing headers mean skip optional compilation. Real notification/minifilter attach/unload stress remains VM-only, unexecuted scope; use [[WinDbg]] for any debugger procedure. Delete the scratch directory and object file. No callback was registered by the offline lab.

### Existing Study Checklist

- [ ] Local Kernel Callbacks and Minifilters exercise: Inspect or build a benign notification/minifilter sample that records only synthetic file activity. Annotate callback context and verify clean registration/unregistration in a disposable VM.
- [ ] Boundary check: Exercise open/close/cancel/unload paths with synthetic files and verify callbacks cannot access freed state or prevent clean teardown.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Kernel Callbacks and Minifilters Security]]

## References

- [Filter Manager concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
- [Process Ex notification contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [Object callback registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [Writing postoperation callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-postoperation-callback-routines)
- [Minifilter load order and altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
