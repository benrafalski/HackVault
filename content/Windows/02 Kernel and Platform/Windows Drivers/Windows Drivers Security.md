---
title: "Drivers (WDM and KMDF) Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[Windows Drivers]]"
updated: 2026-11-03
---
# Drivers (WDM and KMDF) Security

> [!abstract] TL;DR
> Permissive device access, unchecked buffers, unsafe user pointers, and request lifetime errors can expose kernel privileges.

> [!info] Agent scope
> Security of: Driver/device objects; WDM and KMDF; IRPs; dispatch; IOCTL transfer methods; lifecycle; user/kernel input boundary. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Permissive device access, unchecked buffers, unsafe user pointers, and request lifetime errors can expose kernel privileges.
- Review device opens, IOCTLs, per-file state, cancellation, PnP/power, and teardown independently. The lab accepts only synthetic counted records and has no kernel memory operation.

## Learn

```text
Teach defensive WDM/KMDF interface auditing at expert depth. Assume C, IRQL,
NTSTATUS, and Windows access control. Target Windows 11 x64 and KMDF 1.33.
Explain device ACL versus IOCTL access, transfer methods, RequestorMode,
pointer-free WOW64-safe ABIs, integer validation, capture versus probe, output
initialization, request completion, cancellation races, and unload ownership.
Work benign malformed packets through flawed and fixed validators without
executing unsafe kernel code. Give complete regression files, expected statuses,
and source-review gates; separate offline evidence from VM runtime assurance.
Use Microsoft/WDF sources. No exploitation, arbitrary memory APIs, host security
changes, or undocumented internals. Teach here without editing files.
```

## Cheatsheet

### Boundary Review

| Boundary | Failure | Concrete defensive contract |
|---|---|---|
| Device open | Everyone can obtain privileged capability | Restrictive INF/device security; distinguish service SID, SYSTEM, administrators |
| IOCTL dispatch | Access bits too broad or unknown function accepted | Exact code allowlist and appropriate READ/WRITE access |
| Buffer interpretation | Count multiplication wraps; short packet accepted | Bound count first; checked arithmetic; validate full captured size |
| User pointer | Probe followed by later unsafe use | Prefer buffered pointer-free messages; capture once while valid |
| Result | Uninitialized padding or oversized Information | Initialize exact reply; return only initialized byte count |
| Lifetime | Cancel and normal path both complete | Single terminal owner; no buffer use after completion |

Illustrative SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` grants SYSTEM and administrators full access, not ordinary users. It is not a universal recommendation: a dedicated service SID with narrower rights is often preferable. Apply device security through the documented INF/device initialization path. A symbolic-link name is not an authorization boundary; `FILE_DEVICE_SECURE_OPEN` matters for device namespace checks. An elevated administrator test does not prove a standard user is denied.

`IoValidateDeviceIoControlAccess` can strengthen WDM access requirements for an IOCTL. Do not infer identity from PID alone or treat kernel-originated input as semantically valid. `ProbeForRead` can raise an exception and does not freeze data or grant indefinite access; subsequent user accesses still need correct exception/context handling. KMDF unsafe-user-buffer APIs belong to the narrowly constrained caller-context capture path, not arbitrary workers.

### Integer and Buffer Validation

Protocol: 8-byte little-endian header (`Version`, `Count`) followed by `Count` eight-byte records, at most four records. A flawed length expression using 32-bit `8 + Count * 8` can wrap. The fixed implementation bounds before multiplication and requires exact size. No malicious pointer or write is needed to test this defect.

Complete portable C `packet.c`, suitable as an algorithmic validator inside a driver after safe capture. It intentionally has no WDK dependencies; this makes the exact routine compilable in user mode. Kernel callers still own residency, lifetime, access checks, and transfer-method correctness.

### File: packet.c

```c
#include <stddef.h>
#include <stdint.h>

static uint32_t Read32(const unsigned char *data)
{
	return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
		   ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

int ValidatePacket(const unsigned char *data, size_t length)
{
	uint32_t count;
	if (data == NULL || length < 8) return 0;
	if (Read32(data) != 1) return 0;
	count = Read32(data + 4);
	if (count > 4) return 0;
	return length == 8 + (size_t)count * 8;
}
```

No cast to an unaligned struct and no pointer fields means x86/x64 structure packing does not alter this wire format. Exact length rejects tails; if future extension is needed, introduce explicit version/size rules. Zero records are permitted intentionally, not accidentally.

## Detection and Defense

Use a tiny capability surface, deny-by-default dispatch, bounded input, no arbitrary address/port operations, maintained signing, and source/runtime analysis. Capture caller category, IOCTL, lengths, status, duration, cancellation outcome, and driver build without logging packet secrets. Driver-load and Code Integrity events support inventory; they do not prove which caller issued an IOCTL. ETW instrumentation must be explicitly implemented if per-request evidence is required.

VM-only runtime gates: standard-user open denial, intended service success, malformed-request status, concurrent cancel/close, allocation failure, power transition, removal, and no leaks after repeated cycles. A clean Driver Verifier run is workload-specific evidence, not proof of absence. Use [[WinDbg]] for crash triage.

## Labs

### Environment and Complete Files

Python 3.11+ for the offline baseline/fix fixture. Optional exact C execution requires an already installed VS 2022 x64 Native Tools prompt. No admin, network, driver, signing, or VM required offline. Save `packet.c` above and both files below in one scratch directory.

### File: packet_test.py

```python
import struct
from pathlib import Path

def flawed(packet):
	if len(packet) < 8:
		return False
	version, count = struct.unpack_from("<II", packet)
	return version == 1 and len(packet) == ((8 + count * 8) & 0xFFFFFFFF)

def fixed(packet, authorized=True):
	if not authorized or len(packet) < 8:
		return False
	version, count = struct.unpack_from("<II", packet)
	return version == 1 and count <= 4 and len(packet) == 8 + count * 8

overflow = struct.pack("<II", 1, 0x20000000)
assert flawed(overflow) and not fixed(overflow)
for count in range(5):
	packet = struct.pack("<II", 1, count) + bytes(count * 8)
	assert fixed(packet)
	assert not fixed(packet, authorized=False)
	assert not fixed(packet + b"x")
	assert not fixed(packet[:-1])
assert not fixed(struct.pack("<II", 2, 0))
source = Path("packet.c").read_text(encoding="utf-8")
assert source.index("if (count > 4)") < source.index("(size_t)count * 8")
print("PASS: wrap baseline, fixed bounds, authorized/denied callers")
```

### File: packet_test.c

```c
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
int ValidatePacket(const unsigned char *data, size_t length);

int main(void)
{
	unsigned char empty[8] = {1, 0, 0, 0, 0, 0, 0, 0};
	unsigned char one[16] = {1, 0, 0, 0, 1, 0, 0, 0};
	unsigned char wrap[8] = {1, 0, 0, 0, 0, 0, 0, 0x20};
	assert(ValidatePacket(empty, sizeof(empty)));
	assert(ValidatePacket(one, sizeof(one)));
	assert(!ValidatePacket(one, 15));
	assert(!ValidatePacket(wrap, sizeof(wrap)));
	assert(!ValidatePacket(NULL, 8));
	puts("PASS: exact C validator, 5 cases");
	return 0;
}
```

### Objectives, Hints, and Solution

1. Run `python packet_test.py`. Explain why the flawed validator accepts the eight-byte overflow fixture even though it advertises many records. No record is accessed.
2. Optional exact C test: `cl /nologo /W4 /WX packet.c packet_test.c /Fe:packet_test.exe`, then `.\packet_test.exe`.
3. Keep the same input after fixing the length check. The wrapped count is rejected, counts 0-4 still work, and denied synthetic callers remain denied.

Hint: `0x20000000 * 8` is 2^32; masking to 32 bits turns it into zero. In the solution, `count > 4` rejects the input before arithmetic. The Python authorization parameter models an upstream gate, not a replacement for a real device ACL. Expected outputs are the two PASS strings in the fixtures.

### Verification, Troubleshooting, and Cleanup

Not executed during authoring. Python verifies the model and source ordering; the optional C command tests the supplied validator itself. Missing `cl` is a prerequisite issue, not permission to install tools. C assertions must remain enabled (do not define `NDEBUG`). No complete driver package is supplied, so ACL enforcement, KMDF integration, IRQL, cancellation, and unload remain unexecuted VM scope. Any such runtime test requires a snapshot-backed Windows 11 VM with local console; never modify host protections/VPN. Delete the scratch directory, executable, and object files to reset.

### Existing Study Checklist

- [ ] Local Windows Drivers exercise: Build a benign KMDF sample in a dedicated VM and add only a fixed echo/query request. Test valid, short, oversized, cancelled, and unauthorized requests without privileged memory operations.
- [ ] Boundary check: Send malformed sizes and a denied caller to the toy IOCTL and require clean status errors with no crash, leak, or unintended write.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Kernel Exploitation]]
- [[WinDbg]]
- [[Windows Drivers]]

## References

- [Security issues for IOCTLs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes)
- [Security descriptor definition language for devices](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects)
- [ProbeForRead](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread)
- [WdfRequestUnmarkCancelable](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nf-wdfrequest-wdfrequestunmarkcancelable)
