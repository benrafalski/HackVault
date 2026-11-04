---
title: "VBS, HVCI, Credential Guard, and Hyper-V Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[Windows Virtualization Security]]"
updated: 2026-11-03
---
# VBS, HVCI, Credential Guard, and Hyper-V Security

> [!abstract] TL;DR
> Disabled or unsupported protections, vulnerable trusted drivers, and overbroad assumptions can leave credentials or kernel execution exposed.

> [!info] Agent scope
> Security of: Hyper-V isolation; VBS; virtual trust levels; HVCI; Credential Guard; prerequisites; configuration; protection boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Disabled or unsupported protections, vulnerable trusted drivers, and overbroad assumptions can leave credentials or kernel execution exposed.
- Review incompatible drivers, configuration drift, failed secure-kernel startup, stale/partial telemetry, overbroad credential claims, and unsupported virtual hardware. The lab checks compatibility and reporting, not protection bypass.

## Learn

```text
Teach defensive validation of VBS, HVCI, Credential Guard, and Hyper-V boundaries
at expert depth. Assume Windows boot, kernel IRQL/lifetime, PE sections, and
basic access control. Target Windows 11 x64 and identify edition/build/default
differences. Explain why configured is not running, why HVCI-compatible signing
does not prove safe logic, and why Credential Guard protects selected secrets
rather than every authenticated action. Work through PE writable/executable
sections, NX data allocation, driver compatibility, runtime evidence, and
recovery-safe staged deployment. Give complete benign offline fixtures and
genuine driver helper source, with separate VM-only validation limits. Use
Microsoft sources. No exploitation, secret extraction, protection bypass,
host security changes, or file edits. Teach in conversation.
```

## Cheatsheet

### Compatibility and Assurance

| Risk | Specific defensive check | Limitation |
|---|---|---|
| HVCI configured, not running | VBS status 2 and service code 2 in running array | Registry/policy intent alone is insufficient |
| Credential Guard assumed from HVCI | Independently require running code 1 | HVCI and Credential Guard protect different assets |
| W+X driver section | Inspect PE section Characteristics; separate executable code from writable data | Static section scan does not prove all runtime compatibility |
| Executable data allocation | Use NX/non-executable pool for data; no generated kernel code | Correct allocation flags do not fix use-after-free or input validation |
| Signed but unsafe driver | Maintained release, restrictive interface, defensive tests, application control | Signature establishes publisher/integrity context, not correctness |
| Stale telemetry | Boot/session timestamp and fresh collection from trusted channel | Local state is not independent attestation |

HVCI-compatible drivers must not have writable executable sections, generate kernel executable code dynamically, or modify protected executable code. Follow documented section alignment, relocation, and image-layout requirements in addition to this lab's W+X check. Avoid unsupported assumptions about system structures; use documented APIs. Windows 10 version 2004 introduced `ExAllocatePool2`; `POOL_FLAG_NON_PAGED` requests nonpaged non-executable memory, while the explicitly executable flag is a different choice that this data helper never uses. Older-target support needs the documented down-level allocation strategy, not silently importing an unavailable DDI.

Credential Guard is not a universal credential vault. Local account material, application-managed secrets, user-entered passwords, and the authority of an already authenticated session have different boundaries. Combine isolation with phishing-resistant authentication, least privilege, service restrictions, and credential hygiene. Enabling protection after prior exposure does not retroactively revoke credentials; incident response and rotation remain separate decisions.

### Genuine NX Data Helper

Complete `nx_buffer.c`, Windows 11 x64 / WDK 10.0.26100, minimum runtime Windows 10 2004 for `ExAllocatePool2`. It allocates a fixed data record at PASSIVE_LEVEL and exposes no IOCTL. Not a complete driver/package.

### File: nx_buffer.c

```c
#include <ntddk.h>

#define LAB_TAG 'bLbH'
typedef struct _LAB_RECORD {
	ULONG Version;
	UCHAR Payload[60];
} LAB_RECORD;

_IRQL_requires_(PASSIVE_LEVEL)
LAB_RECORD *RecordCreate(VOID)
{
	LAB_RECORD *record = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LAB_RECORD), LAB_TAG);
	if (record != NULL) record->Version = 1;
	return record;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID RecordDestroy(LAB_RECORD *record)
{
	if (record != NULL) ExFreePoolWithTag(record, LAB_TAG);
}
```

`ExAllocatePool2` zero-initializes by default unless the uninitialized flag is requested, which this code does not do. The caller must handle NULL and drain all readers before destroy. NX is an execution permission, not an ownership or confidentiality guarantee. The helper is deliberately passive-only even though nonpaged allocation has a wider DDI IRQL allowance.

## Detection and Defense

Use supported firmware/drivers, staged deployment rings, compatibility testing, and observed runtime state. UEFI lock and mandatory modes change recovery requirements; choose them through approved deployment planning, not ad hoc troubleshooting. Update/replace incompatible drivers rather than disabling protection on a work host. Record performance against actual workload and hardware capabilities.

Read-only checks inside a preprovisioned disposable Windows 11 VM:

```powershell
$guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
$guard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=13,14,15,16,17} -MaxEvents 20 |
	Select-Object TimeCreated, Id, Message
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 |
	Select-Object TimeCreated, Id, Message
```

WinInit 13 reports Credential Guard startup; 15 reports configured without the secure kernel, 16 launch failure, and 17 UEFI configuration-read failure. Correlate with the current boot; old successful events are not current assurance. Code Integrity event schemas vary; use actual event text/XML and OS build rather than guessing a universal ID for every incompatibility. Missing events can mean retention/collection gaps. Do not change audit policy to force an expected output.

## Labs

### Environment and Complete Files

Python 3.11+ standard library; ordinary user; scratch directory containing `nx_buffer.c` above and `hvci_static.py` below. The fixture constructs only minimal synthetic PE headers in memory, never loads an image, and makes no live policy change. It checks W+X and basic parse boundaries, not all HVCI certification rules.

### File: hvci_static.py

```python
import struct
from pathlib import Path

EXECUTE = 0x20000000
READ = 0x40000000
WRITE = 0x80000000

def image(characteristics):
	data = bytearray(0x200)
	data[:2] = b"MZ"
	struct.pack_into("<I", data, 0x3C, 0x80)
	data[0x80:0x84] = b"PE\0\0"
	struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
	struct.pack_into("<H", data, 0x98, 0x20B)
	section = 0x98 + 0xF0
	data[section:section + 8] = b".text\0\0\0"
	struct.pack_into("<I", data, section + 36, characteristics)
	return bytes(data)

def check(data):
	if len(data) < 0x40 or data[:2] != b"MZ":
		return "MALFORMED"
	offset = struct.unpack_from("<I", data, 0x3C)[0]
	if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
		return "MALFORMED"
	count = struct.unpack_from("<H", data, offset + 6)[0]
	optional_size = struct.unpack_from("<H", data, offset + 20)[0]
	table = offset + 24 + optional_size
	if table + count * 40 > len(data):
		return "MALFORMED"
	for index in range(count):
		flags = struct.unpack_from("<I", data, table + index * 40 + 36)[0]
		if flags & EXECUTE and flags & WRITE:
			return "WRITABLE_EXECUTABLE"
	return "NO_WX_FOUND"

assert check(image(READ | WRITE | EXECUTE)) == "WRITABLE_EXECUTABLE"
assert check(image(READ | EXECUTE)) == "NO_WX_FOUND"
assert check(image(READ | WRITE)) == "NO_WX_FOUND"
assert check(image(READ | EXECUTE)[:0x100]) == "MALFORMED"
assert check(b"not a PE") == "MALFORMED"

def runtime_ok(row):
	return (row.get("QueryStatus") == "OK"
			and row.get("VirtualizationBasedSecurityStatus") == 2
			and {1, 2}.issubset(set(row.get("SecurityServicesRunning", []))))

configured_only = dict(QueryStatus="OK", VirtualizationBasedSecurityStatus=1,
					   SecurityServicesConfigured=[1, 2], SecurityServicesRunning=[])
running = {**configured_only, "VirtualizationBasedSecurityStatus": 2,
		   "SecurityServicesRunning": [1, 2]}
assert not runtime_ok(configured_only)
assert runtime_ok(running)
assert not runtime_ok({"QueryStatus": "UNKNOWN"})
source = Path("nx_buffer.c").read_text(encoding="utf-8")
assert "ExAllocatePool2(POOL_FLAG_NON_PAGED," in source
assert "POOL_FLAG_NON_PAGED_EXECUTE" not in source
assert "ExFreePoolWithTag(record, LAB_TAG)" in source
print("PASS: W+X baseline/fix, malformed images, runtime evidence, NX helper")
```

### Objectives, Hints, and Worked Solution

Run `python hvci_static.py`. The baseline section has both execute and write bits. The fixed code section has read/execute only, and the data section read/write only. Both permitted patterns remain accepted, while truncation remains malformed rather than "safe." Hint: `NO_WX_FOUND` deliberately does not say `HVCI_COMPATIBLE`.

The runtime check independently requires VBS running and both service codes. A configured-only row fails despite matching intended configuration. The source assertion checks the actual allocation API/flags printed above. These checks cover separate static and reporting properties; neither executes secure-kernel code nor handles credential data.

### Build, Troubleshooting, and Cleanup

No author execution. Optional helper compilation in an existing x64 WDK prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" nx_buffer.c`. Missing API/header means the stated kit prerequisite is unmet. No installable driver, load test, or signing procedure is supplied.

Real HVCI-compatible driver loading, runtime allocation checks, performance, Credential Guard behavior, and policy/reboot recovery are unexecuted VM-only scope. A supported snapshot-backed VM with local console is mandatory for later deployment work; never change host protections, virtualization settings, or VPN. Delete scratch files and object output. No system state changed.

### Existing Study Checklist

- [ ] Local Windows Virtualization Security exercise: Inspect VBS/HVCI/Credential Guard status in a supported disposable VM and record prerequisites and incompatible-driver observations. Keep host security settings unchanged.
- [ ] Boundary check: Compare configured and reported runtime protection state in the lab, and verify monitoring detects an intentionally changed test policy without attempting protection bypass.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Virtualization Security]]

## References

- [Implement HVCI-compatible code](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hvci-compatible-code)
- [ExAllocatePool2](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2)
- [Memory integrity configuration and status](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Credential Guard considerations](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues)
- [Credential Guard verification](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
