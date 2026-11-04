---
title: "Kernel Callbacks and Minifilters Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[Kernel Callbacks and Minifilters]]"
updated: 2026-11-03
---
# Kernel Callbacks and Minifilters Security

> [!abstract] TL;DR
> Unsafe callbacks, stale contexts, recursion, and incorrect filtering assumptions can crash systems or leave policy gaps.

> [!info] Agent scope
> Security of: Documented callbacks; process/thread/image notifications; object callbacks; filesystem minifilters; altitude; lifetime and synchronization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsafe callbacks, stale contexts, recursion, and incorrect filtering assumptions can crash systems or leave policy gaps.
- Callback arguments are temporary, file names can change, communication-port clients are separate principals, and callbacks may race teardown. Security checks must match the operation and object actually being authorized.

## Learn

```text
Teach defensive auditing of Windows notifications, object callbacks, and
filesystem minifilters at expert depth. Assume C, IRQL, and ownership knowledge.
Target Windows 11 x64 with WDK 10.0.26100. Explain transient counted strings,
PID reuse, reference balancing, callback/unload races, postoperation draining,
name-query restrictions, reparse/rename identity, and recursive I/O deadlocks.
Compare observation with enforceable decisions and explain coverage limits.
Give genuine benign callback source and complete offline failure/fix tests,
including denied port messages and permitted traffic. Use Microsoft sources;
separate static evidence from VM runtime assurance. No exploitation, unhooking,
evasion, or host protection changes. Teach here without file edits.
```

## Cheatsheet

### Root Causes and Supported Fixes

| Defect | Evidence and consequence | Supported correction |
|---|---|---|
| Retain callback string pointer | Worker reads invalid storage after callback return | Copy bounded bytes before return; owned allocation and explicit free |
| PID-only authorization | Reused PID inherits stale allow entry | Reference correct object and scope state to lifecycle |
| Blanket path-string policy | Reparse/rename/alternate stream changes meaning | Define object/operation coverage; use documented name/context APIs |
| Wait for service in callback | Deadlock or unbounded latency when service needs same I/O | Asynchronous bounded design where supported; explicit failure policy |
| Post callback assumes PASSIVE | Pageable helper reached at DISPATCH_LEVEL | Resident completion or eligible safe-completion deferral |
| Ignore draining | New work queued during detach; stale completion context | Cleanup-only draining branch, balanced references |
| Port lacks ACL/validation | Untrusted client controls kernel policy | Restrictive port descriptor; capture fixed bounded messages |

`ObRegisterCallbacks` supports only documented object operations and removable rights. A handle filter is not a universal process isolation boundary, and it does not revoke all previously granted access. Image notifications are observations, not a universal image-denial hook. Do not overstate a minifilter's reach to volumes without attached instances or to I/O types it has not registered.

`FltDoCompletionProcessingWhenSafe` is constrained by operation type and draining; it can fail to arrange safe completion. A correct caller must handle that failure, not assume a worker will always run. `FLT_PREOP_SYNCHRONIZE` is not valid for every path and can add serialization/latency. `FltGetFileNameInformation` is not safe at arbitrary IRQL or in all paging/top-level-I/O contexts.

### Genuine Completion Helper

Complete callback translation unit `post.c`, WDK 10.0.26100, Windows 11 x64. `LAB_COMPLETION` is owned nonpaged memory allocated by a preoperation callback that acquired one `PFLT_CONTEXT` reference. This helper consumes both exactly once. It is not a registered/packaged minifilter; the offline lab validates this local ownership contract only.

### File: post.c

```c
#include <fltKernel.h>

#define LAB_TAG 'cLbH'
typedef struct _LAB_COMPLETION {
	PFLT_CONTEXT Context;
} LAB_COMPLETION;

static VOID ReleaseCompletion(LAB_COMPLETION *completion)
{
	if (completion == NULL) return;
	if (completion->Context != NULL) {
		FltReleaseContext(completion->Context);
	}
	ExFreePoolWithTag(completion, LAB_TAG);
}

FLT_POSTOP_CALLBACK_STATUS LabPost(PFLT_CALLBACK_DATA data,
	PCFLT_RELATED_OBJECTS objects, PVOID completionContext,
	FLT_POST_OPERATION_FLAGS flags)
{
	UNREFERENCED_PARAMETER(data);
	UNREFERENCED_PARAMETER(objects);
	if (FlagOn(flags, FLTFL_POST_OPERATION_DRAINING)) {
		ReleaseCompletion((LAB_COMPLETION *)completionContext);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	ReleaseCompletion((LAB_COMPLETION *)completionContext);
	return FLT_POSTOP_FINISHED_PROCESSING;
}
```

This intentionally does no post-I/O policy work. `FltReleaseContext` accepts <= DISPATCH_LEVEL, but any context cleanup callback must obey its own context/residency contract. A context reference keeps the context alive, not the original transient `FltObjects` pointer. Adding pageable name inspection to the normal branch would invalidate the helper's general postoperation contract.

### Port Message Boundary

For `FltCreateCommunicationPort`, use a restrictive security descriptor and bounded maximum connections. `FltBuildDefaultSecurityDescriptor` is a supported starting point; tailor principals to the service design. Disconnect callbacks must release per-connection state. Filter Manager messaging callbacks expose user buffers under documented conditions; validate lengths, capture fields, and handle exceptions for user-memory access. Never retain the message pointer after returning. An ACL and a message parser address different boundaries.

## Detection and Defense

Inventory filter name, driver version/hash, altitude, attached volumes, service identity, and expected operations. In a disposable VM, read-only `fltmc filters` and `fltmc instances` show Filter Manager state, not callback completeness or correctness. Capture latency, queue depth, allocation failures, timeouts, canceled operations, and draining counts in bounded telemetry. A missing event can mean no attachment, no matching registration, buffering loss, or collector failure, not necessarily malicious removal.

Runtime acceptance must exercise success, failed create, cancel, service disconnect, instance teardown, and unload while work is active. No kernel module runs in the offline exercise. Debugger commands belong only in [[WinDbg]].

## Labs

### Environment and Complete Files

Python 3.11+ standard library; empty scratch directory with `post.c` above and `filter_test.py` below. No administrator, service, network, or installed driver needed. This is a reference-accounting and message-capture fixture, not a generic policy questionnaire.

### File: filter_test.py

```python
import struct
from pathlib import Path

def post(draining, corrected):
	references = 1
	queued = False
	if draining and not corrected:
		queued = True
	else:
		references -= 1
	return references, queued

def message(packet, caller):
	if caller != "LabService":
		return "DENIED", None
	captured = bytes(packet)
	if len(captured) != 8:
		return "SIZE", None
	version, capacity = struct.unpack("<II", captured)
	if version != 1 or not 1 <= capacity <= 64:
		return "FIELDS", None
	return "OK", capacity

assert post(True, False) == (1, True)
assert post(True, True) == (0, False)
assert post(False, True) == (0, False)
packet = bytearray(struct.pack("<II", 1, 16))
assert message(packet, "LabService") == ("OK", 16)
assert message(packet, "OrdinaryUser") == ("DENIED", None)
assert message(packet[:-1], "LabService")[0] == "SIZE"
assert message(struct.pack("<II", 1, 65), "LabService")[0] == "FIELDS"
captured = message(packet, "LabService")
packet[:] = bytes(8)
assert captured == ("OK", 16)
source = Path("post.c").read_text(encoding="utf-8")
assert "FLTFL_POST_OPERATION_DRAINING" in source
assert "FltReleaseContext(completion->Context);" in source
assert "ExFreePoolWithTag(completion, LAB_TAG);" in source
assert "FLT_POSTOP_MORE_PROCESSING_REQUIRED" not in source
print("PASS: draining fixed, references balanced, messages bounded and captured")
```

### Objectives, Hints, and Worked Solution

Run `python filter_test.py`. Baseline: a draining callback queues work and leaves one outstanding reference. Correction: both normal and draining paths consume the reference, with no pending work. For messages, intended service input succeeds while unauthorized, truncated, and excessive-capacity cases fail. Mutating the original bytearray does not alter the already captured result.

Hint: draining is cleanup, not another chance to finish ordinary policy work. The modeled service string is a synthetic identity supplied by the test; a real client must be authenticated through OS access control, never a self-asserted field in the message.

### Build, Verification, and Cleanup

No author execution. Optional object compilation in an existing x64 WDK developer prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" post.c`. Missing kit headers mean skip this optional step. Linking a minifilter additionally needs Filter Manager imports, full registration, instance configuration, package/signing, and production altitude handling; none is claimed by this helper.

Expected offline result is the PASS line. Static assertions cannot prove actual context allocation/residency or port ACL enforcement. Those remain unexecuted work in an approved snapshot-backed Windows 11 VM with console access. No host protections/VPN changes. Delete the scratch directory and object output to reset; no callback, port, or instance was installed.

### Existing Study Checklist

- [ ] Local Kernel Callbacks and Minifilters exercise: Inspect or build a benign notification/minifilter sample that records only synthetic file activity. Annotate callback context and verify clean registration/unregistration in a disposable VM.
- [ ] Boundary check: Exercise open/close/cancel/unload paths with synthetic files and verify callbacks cannot access freed state or prevent clean teardown.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Kernel Callbacks and Minifilters]]

## References

- [Postoperation callback contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback)
- [FltReleaseContext](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltreleasecontext)
- [FltDoCompletionProcessingWhenSafe](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltdocompletionprocessingwhensafe)
- [Communication between user mode and kernel mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode)
