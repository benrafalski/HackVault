---
title: "Drivers (WDM and KMDF)"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[Windows Drivers Security]]"
updated: 2026-11-03
---
# Drivers (WDM and KMDF)

> [!abstract] TL;DR
> Validate lengths, integer arithmetic, requestor access, buffer method, and lifetime before use. Complete each request exactly once and keep debugger commands in [[WinDbg]].

> [!info] Agent scope
> Driver/device objects; WDM and KMDF; IRPs; dispatch; IOCTL transfer methods; lifecycle; user/kernel input boundary.

## Prerequisites

- C, NTSTATUS, object ownership, and [[Kernel Architecture]]. Offline exercise: Python 3.11+ standard library. Optional source compilation: existing Visual Studio 2022 C++ tools, WDK 10.0.26100, KMDF 1.33 headers, x64.
- Runtime driver work requires an authorized disposable Windows 11 x64 VM, snapshot, local console, and recovery access. This note supplies no installable package or signing/deployment steps. Do not change host security, boot options, or VPN.
- [[Windows Lab Setup]]

## Learn

```text
Teach WDM and KMDF request processing at expert depth, assuming C and kernel
IRQL/lifetime knowledge. Target Windows 11 x64, WDK 10.0.26100, KMDF 1.33.
Trace CreateFile and DeviceIoControl through driver/device/file objects, IRP
stack locations, framework queues, dispatch, completion, cleanup, and removal.
Compare all four IOCTL methods, access bits, device ACLs, pointer-free versioned
ABIs, cancellation ownership, power-managed queues, and buffer lifetime.
Work a benign fixed query from bytes to returned status/information. Provide
complete offline protocol tests and genuine DDI code with explicit build and
runtime limits. Explain WDM responsibilities that KMDF automates and those it
does not. Use primary Microsoft/WDF documentation; no arbitrary kernel access,
exploitation, or host protection changes. Teach here without editing files.
```

## Cheatsheet

### Objects and Request Ownership

`DRIVER_OBJECT` owns dispatch entry points and driver lifetime; a `DEVICE_OBJECT` represents a stack participant, not necessarily a physical device. A stack commonly contains PDO, FDO, and filter DOs. A file object represents an open instance; device-wide state and per-open state need different lifetimes. An IRP carries operation parameters and per-stack-location state; forwarding does not transfer arbitrary driver context ownership.

WDM dispatch either completes, forwards, or retains an IRP under a documented pending/cancellation protocol. `IoStatus.Status` and `IoStatus.Information` must be set consistently; completing twice is a bug. KMDF wraps requests in `WDFREQUEST`, routes them through queues, handles much PnP/power plumbing, and enforces object relationships. It does not validate application semantics or choose the correct security descriptor.

Sequential queues serialize delivery from that queue, not every callback in the device. Parallel queues require explicit shared-state synchronization. Manual queues retain requests until retrieved. A request still in a framework queue has different cancellation ownership from one already delivered to the driver. If marking a delivered request cancelable, coordinate `WdfRequestMarkCancelableEx`, `EvtRequestCancel`, and `WdfRequestUnmarkCancelable`; `STATUS_CANCELLED` means the normal path must not also complete it.

`IRP_MJ_CLEANUP` corresponds to the last user handle for a file object closing; outstanding I/O may remain. `IRP_MJ_CLOSE` occurs when final references are released. Removal must stop new work, resolve queued/active requests, release hardware resources, and finally destroy state. A surprise removal is not a normal successful I/O completion.

### IOCTL Buffer Contract

| Method | Input | Second buffer | Design consequence |
|---|---|---|---|
| METHOD_BUFFERED | SystemBuffer copy | Same SystemBuffer, copied back for completed byte count | Input/output can alias; capture input before writing output |
| METHOD_IN_DIRECT | SystemBuffer for first buffer | MDL describes second buffer with read access | Name describes driver access, not an intuitive request direction |
| METHOD_OUT_DIRECT | SystemBuffer for first buffer | MDL describes second buffer with write access | Check mapping failures, output length, and completion count |
| METHOD_NEITHER | Raw caller address | Raw caller address | No I/O-manager validation/mapping; avoid for new user-facing interfaces |

The IOCTL Method bits govern device-control buffers; `DO_BUFFERED_IO`/`DO_DIRECT_IO` govern read/write paths, not these IOCTL bits. Locking a direct buffer does not freeze its contents. A user can mutate data during use; copy decision-critical fields once. Embedded pointers remain untrusted even inside a buffered top-level structure. Use fixed-width fields and offsets for WOW64 compatibility.

`CTL_CODE(DeviceType, Function, Method, Access)` packs a 32-bit value. Vendor device types use 0x8000-0xFFFF; vendor function numbers use 0x800-0xFFF. Access bits are checked against the opened handle; they complement, not replace, the device ACL. `FILE_ANY_ACCESS` means any suitable handle, not a bypass of device-open security. Treat unknown IOCTLs as invalid, not as query aliases.

### Genuine KMDF Query Handler

Complete callback translation unit `query.c`. This is not a complete driver: a device/queue, INF, signing, installation, and user-mode device path are intentionally absent. It exposes no privileged operation. A production device must use DeviceType 0x8000, a restrictive security descriptor, and a queue wired to this callback. The APIs used exist from KMDF 1.0; the proposed build baseline is 1.33.

### File: query.c

```c
#include <ntddk.h>
#include <wdf.h>

#define IOCTL_LAB_QUERY CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
typedef struct _LAB_QUERY { ULONG Version; ULONG Reserved; } LAB_QUERY;
typedef struct _LAB_REPLY { ULONG Version; ULONG Capabilities; } LAB_REPLY;
C_ASSERT(sizeof(LAB_QUERY) == 8);
C_ASSERT(sizeof(LAB_REPLY) == 8);
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LabQuery;

VOID LabQuery(WDFQUEUE queue, WDFREQUEST request, size_t outputLength,
			  size_t inputLength, ULONG code)
{
	LAB_QUERY *input;
	LAB_REPLY *output;
	LAB_QUERY captured;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(queue);
	if (code != IOCTL_LAB_QUERY) {
		WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
		return;
	}
	if (inputLength != sizeof(LAB_QUERY) || outputLength < sizeof(LAB_REPLY)) {
		WdfRequestComplete(request, STATUS_INVALID_BUFFER_SIZE);
		return;
	}
	status = WdfRequestRetrieveInputBuffer(request, sizeof(*input), (PVOID *)&input, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}
	captured = *input;
	if (captured.Version != 1 || captured.Reserved != 0) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}
	status = WdfRequestRetrieveOutputBuffer(request, sizeof(*output), (PVOID *)&output, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}
	output->Version = 1;
	output->Capabilities = 0;
	WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(*output));
}
```

The callback uses only resident fixed data, has no pending path, and retains nothing after completion. No cancellation registration is needed for this immediate handler. Eight output bytes are initialized before reporting eight; larger caller output capacity does not justify reporting it all. The exact input size is a deliberate ABI choice: future versions require explicit dispatch rather than silently accepting tails.

## Gotchas

A signed driver can still violate its contract. `WdfRequestRetrieveInputBuffer` validates availability and minimum size, not the meaning of fields. Its returned pointer is usable only until request completion. A framework reference to a request does not extend an underlying completed I/O buffer's usable lifetime. Crash commands live only in [[WinDbg]].

## Labs

### Complete Offline Fixture

Save `query.c` above and `query_test.py` below in an empty scratch directory. The fixture models byte-level ABI behavior and inspects the actual supplied source. It does not call `DeviceIoControl` or emulate WDF.

### File: query_test.py

```python
from pathlib import Path
import struct

CODE = (0x8000 << 16) | (1 << 14) | (0x800 << 2)

def query(code, packet, output_size, readable=True):
	if not readable:
		return "ACCESS_DENIED", b""
	if code != CODE:
		return "INVALID_DEVICE_REQUEST", b""
	if len(packet) != 8 or output_size < 8:
		return "INVALID_BUFFER_SIZE", b""
	version, reserved = struct.unpack("<II", packet)
	if version != 1 or reserved != 0:
		return "INVALID_PARAMETER", b""
	return "SUCCESS", struct.pack("<II", 1, 0)

valid = struct.pack("<II", 1, 0)
assert CODE == 0x80006000
assert query(CODE, valid, 8) == ("SUCCESS", valid)
assert query(CODE, valid, 64) == ("SUCCESS", valid)
assert query(CODE, valid, 8, False)[0] == "ACCESS_DENIED"
assert query(CODE + 4, valid, 8)[0] == "INVALID_DEVICE_REQUEST"
for packet, size in [(b"", 8), (valid[:-1], 8), (valid + b"x", 8), (valid, 7)]:
	assert query(CODE, packet, size)[0] == "INVALID_BUFFER_SIZE"
for packet in [struct.pack("<II", 2, 0), struct.pack("<II", 1, 1)]:
	assert query(CODE, packet, 8)[0] == "INVALID_PARAMETER"
source = Path("query.c").read_text(encoding="utf-8")
assert "METHOD_BUFFERED, FILE_READ_DATA" in source
assert source.index("captured = *input;") < source.index("output->Version = 1;")
assert "STATUS_SUCCESS, sizeof(*output)" in source
print("PASS: query ABI, 10 requests, source invariants")
```

### Objectives, Hints, and Worked Solution

Run `python query_test.py`. Decode 0x80006000 into device type 0x8000, read access, function 0x800, method 0. Explain why the two large/small output cases differ and why a reserved field is rejected. Hint: capacity and returned length are different; reserved fields make future interpretation explicit.

The supplied handler captures before overwriting the shared buffered storage. Valid input bytes `01 00 00 00 00 00 00 00` yield the same eight reply bytes. Ten requests should pass their expected status/payload assertions. The access-denied branch models I/O-manager handle access, not code within the callback; a real denial may prevent the callback from running at all.

### Build, Verification, and Cleanup

No build is needed for the offline exercise; no author execution. Optional compile-only command in an existing x64 WDK developer prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" /I "%WDKContentRoot%Include\wdf\kmdf\1.33" query.c`. Confirm the actual installed header paths first. This produces an object, not a driver package.

Missing headers mean the optional build prerequisite is absent. Failed source assertions mean the printed source and fixture differ. Real ACL, cancellation, PnP, IRQL, and unload validation remain unexecuted VM scope requiring a complete reviewed package. Delete the scratch directory and object file; no services/devices were created.

### Existing Study Checklist

- [ ] Local Windows Drivers exercise: Build a benign KMDF sample in a dedicated VM and add only a fixed echo/query request. Test valid, short, oversized, cancelled, and unauthorized requests without privileged memory operations.
- [ ] Boundary check: Send malformed sizes and a denied caller to the toy IOCTL and require clean status errors with no crash, leak, or unintended write.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Kernel Exploitation]]
- [[WinDbg]]
- [[Windows Drivers Security]]

## References

- [Defining IOCTLs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)
- [Buffer descriptions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes)
- [WdfRequestRetrieveInputBuffer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nf-wdfrequest-wdfrequestretrieveinputbuffer)
- [Canceling I/O requests](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/canceling-i-o-requests)
