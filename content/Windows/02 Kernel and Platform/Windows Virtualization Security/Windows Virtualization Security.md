---
title: "VBS, HVCI, Credential Guard, and Hyper-V"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[Windows Virtualization Security Security]]"
updated: 2026-11-03
---
# VBS, HVCI, Credential Guard, and Hyper-V

> [!abstract] TL;DR
> Map protection -> asset -> prerequisite -> runtime evidence -> known limitation. Separate virtualization enablement from individual security feature activation.

> [!info] Agent scope
> Hyper-V isolation; VBS; virtual trust levels; HVCI; Credential Guard; prerequisites; configuration; protection boundaries.

## Prerequisites

- Windows kernel/user separation, boot trust, and PowerShell objects. Offline lab: Python 3.11+ standard library. Optional collection: an already provisioned Windows 11 x64 VM and elevated Windows PowerShell 5.1.
- The VM owner must supply supported virtualization exposure, UEFI/Secure Boot, compatible drivers, and any required vTPM/nested-virtualization configuration before this lab. Do not alter host Hyper-V, firmware, security, VPN, or nested-virtualization settings. A snapshot and console are required for later runtime deployment studies.
- [[Windows Lab Setup]]

## Learn

```text
Teach Hyper-V, VBS, HVCI/memory integrity, and Credential Guard at expert platform
depth. Assume Windows kernel/user boundaries and verified/measured boot. Target
Windows 11 x64 and explain Windows 10/Server version and edition differences.
Distinguish hypervisor presence, virtual trust levels, secure kernel/services,
code-integrity enforcement, credential isolation, and management policy.
Explain hardware/firmware/driver prerequisites, nested-VM constraints, UEFI lock
tradeoffs, deployment defaults, and configured versus running evidence. Work
complete read-only Win32_DeviceGuard collection and offline decoding examples,
including unknown/error states, arrays, compatibility failures, and rollout
verification. Use Microsoft sources; no secret extraction, protection bypass,
host security/VPN changes, or file edits. End with worked diagnostic scenarios.
```

## Cheatsheet

### Mechanisms and Boundaries

| Mechanism | Protected boundary | Does not establish |
|---|---|---|
| Hyper-V hypervisor | Virtualization and isolation foundation | That VBS or either security service runs |
| VBS | Isolated security environment using virtual trust levels | That every VBS-backed service is enabled |
| HVCI / memory integrity | Kernel code-integrity decisions isolated from ordinary kernel environment; executable code constrained | Correctness of all permitted driver logic |
| Credential Guard | Selected reusable credentials/operations isolated from ordinary LSA environment | Protection for all credentials, all application secrets, or all authenticated actions |

VTL0 contains the ordinary Windows environment, including its kernel. VTL1 hosts the isolated security environment and secure services; a higher trust level is not merely another process privilege. The hypervisor enforces the isolation contract. Ordinary kernel privilege is not automatically permission to read isolated service memory. This depends on the platform trust chain and does not make firmware or the host administrator universally untrusted-safe.

The full Hyper-V management role is not a necessary UI indicator for VBS; the Windows hypervisor can support security features without a user's normal VM-management workflow. Conversely, seeing a hypervisor or a running VM proves neither HVCI nor Credential Guard. "Device Guard" persists in namespace/policy names even though it is not one single present-day feature.

HVCI moves kernel code-integrity validation into the VBS environment and constrains executable-memory behavior. Drivers must separate code/data, avoid writable executable sections and dynamic kernel code, use non-executable data allocations, and follow supported loading. A valid signature is necessary in many deployment paths but does not guarantee HVCI compatibility or safe behavior.

Credential Guard separates selected LSA credential material and operations using the isolated LSA component (`LsaIso`). Examples include NTLM-derived secrets and Kerberos TGT-related secrets. It does not protect every credential store, user-entered application password, browser secret, or local account database; it also does not prevent misuse of every already-authorized session. Do not use presence of the process alone as the health check.

### Requirements and Version Decisions

| Area | Practical check |
|---|---|
| Hardware/firmware | Supported 64-bit virtualization capabilities, Secure Boot policy, platform isolation support; TPM requirements depend on feature/deployment assurance |
| Memory-integrity performance | MBEC/GMET-capable processors avoid some older emulation overhead; measure workload rather than promise zero cost |
| Drivers | HVCI-compatible image layout, allocations, and runtime behavior; update/replace incompatible drivers |
| VM | Supported virtual hardware and virtualization exposure; guest state is not independent of host administration |
| Edition/build | Verify feature availability/licensing and actual defaults for the installed OS |
| Recovery | Console, snapshot, supported rollback plan before a future approved rollout |

Win32_DeviceGuard is documented for Windows 10, Windows 11, and Server 2016+. Credential Guard default enablement begins with eligible Windows 11 22H2 and Windows Server 2025 systems; prior explicit disablement can persist across upgrade. Memory integrity default enablement also depends on clean-install/device eligibility and prior configuration. Never infer either service's state solely from release name.

### Configuration Intent Versus Runtime

Supported management surfaces include Group Policy at `Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`, MDM settings, and documented registry configuration. Credential Guard `LsaCfgFlags` uses 1 for enabled with UEFI lock and 2 for enabled without lock. These are configuration meanings, not commands to apply in this lab. UEFI lock strengthens resistance to remote policy reversal but complicates recovery and requires explicit operational planning. Mandatory modes can prevent boot when dependencies fail; do not casually enable them.

`RequirePlatformSecurityFeatures` choices can make a feature configured but unable to start on a platform lacking the demanded capabilities. Policy refresh, reboot, driver compatibility, and conflicting management sources all matter. Record the effective management origin and boot timestamp alongside runtime state.

| Win32_DeviceGuard property | Correct interpretation |
|---|---|
| `VirtualizationBasedSecurityStatus` | 0 not enabled; 1 enabled but not running; 2 enabled and running |
| `SecurityServicesConfigured` | Array: 1 Credential Guard, 2 memory integrity; other values describe other services |
| `SecurityServicesRunning` | Same service-code interpretation for actual running state; array membership, not equality to one scalar |
| `AvailableSecurityProperties` | Available capability codes, not running services |
| `RequiredSecurityProperties` | Required capability codes, not evidence that they are met |
| `CodeIntegrityPolicyEnforcementStatus` | 0 off, 1 audit, 2 enforced; not interchangeable with HVCI runtime state |

Retain unknown future codes rather than discarding them. `[1, 2]` means two services, not an integer bitmask. Missing property/query failure is unknown, not zero. Some newer service codes represent other protections; decode only what the current schema/documentation supports.

### Complete Read-Only Collector

`Observe-Vbs.ps1` produces a small JSON object with genuine documented property names. Run only inside the authorized VM; it writes no policy and collects no credential material.

```powershell
$ErrorActionPreference = 'Stop'
try {
	$os = Get-CimInstance Win32_OperatingSystem
	$guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
	if ($null -eq $guard) { throw 'No DeviceGuard instance' }
	[pscustomobject]@{
		QueryStatus = 'OK'
		CapturedUtc = [DateTime]::UtcNow.ToString('o')
		Build = $os.BuildNumber
		LastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
		VirtualizationBasedSecurityStatus = $guard.VirtualizationBasedSecurityStatus
		SecurityServicesConfigured = @($guard.SecurityServicesConfigured)
		SecurityServicesRunning = @($guard.SecurityServicesRunning)
		AvailableSecurityProperties = @($guard.AvailableSecurityProperties)
		RequiredSecurityProperties = @($guard.RequiredSecurityProperties)
	} | ConvertTo-Json -Depth 4
} catch {
	[pscustomobject]@{
		QueryStatus = 'UNKNOWN'
		ErrorType = $_.Exception.GetType().FullName
	} | ConvertTo-Json
}
```

## Gotchas

Task Manager process names and registry flags are insufficient runtime evidence. A collector run before a required reboot may accurately show a transition state. Guest VBS does not add protection against every host-administrator action. Unknown telemetry must remain visible instead of becoming a green compliance result.

## Labs

### Complete Offline Files

Save `states.json` and `decode_vbs.py` below. Python 3.11+ standard library; no administrator, VM, build, network, or policy modification required.

### File: states.json

```json
[
  {"QueryStatus":"OK","VirtualizationBasedSecurityStatus":2,"SecurityServicesConfigured":[1,2],"SecurityServicesRunning":[1,2],"expected":"CG+HVCI"},
  {"QueryStatus":"OK","VirtualizationBasedSecurityStatus":1,"SecurityServicesConfigured":[1,2],"SecurityServicesRunning":[],"expected":"CONFIGURED_NOT_RUNNING"},
  {"QueryStatus":"OK","VirtualizationBasedSecurityStatus":2,"SecurityServicesConfigured":[2],"SecurityServicesRunning":[2],"expected":"HVCI_ONLY"},
  {"QueryStatus":"OK","VirtualizationBasedSecurityStatus":0,"SecurityServicesConfigured":[],"SecurityServicesRunning":[],"expected":"NOT_ENABLED"},
  {"QueryStatus":"UNKNOWN","expected":"UNKNOWN"},
  {"QueryStatus":"OK","VirtualizationBasedSecurityStatus":2,"SecurityServicesConfigured":[1,2,99],"SecurityServicesRunning":[1,2,99],"expected":"CG+HVCI"}
]
```

### File: decode_vbs.py

```python
import json
from pathlib import Path

def decode(row):
	if row.get("QueryStatus") != "OK":
		return "UNKNOWN"
	status = row.get("VirtualizationBasedSecurityStatus")
	running = row.get("SecurityServicesRunning")
	if not isinstance(running, list) or status not in (0, 1, 2):
		return "UNKNOWN"
	if status == 0:
		return "NOT_ENABLED" if not set(running) - {0} else "INCONSISTENT"
	if status == 1:
		return "CONFIGURED_NOT_RUNNING" if not set(running) - {0} else "INCONSISTENT"
	if 1 in running and 2 in running:
		return "CG+HVCI"
	if 2 in running:
		return "HVCI_ONLY"
	if 1 in running:
		return "CG_ONLY"
	return "VBS_WITHOUT_CG_OR_HVCI"

rows = json.loads(Path("states.json").read_text(encoding="utf-8"))
for index, row in enumerate(rows, 1):
	result = decode(row)
	assert result == row["expected"], (index, result)
	print(index, result)
assert decode({"QueryStatus": "OK", "VirtualizationBasedSecurityStatus": 2}) == "UNKNOWN"
assert decode({"QueryStatus": "OK", "VirtualizationBasedSecurityStatus": 1,
			   "SecurityServicesRunning": [2]}) == "INCONSISTENT"
print("PASS: six states plus missing and contradictory telemetry")
```

### Objectives, Hints, and Worked Solution

Run `python decode_vbs.py`. Identify configured-but-not-running, HVCI without Credential Guard, and unknown collection. Hint: service arrays contain enumeration values, not bit flags. The six labeled outputs must match the JSON `expected` fields. Code 99 is retained by the fixture and does not erase the recognized services; a production report should also display unknown codes for schema review.

Optional real observation: save the collector and run `powershell.exe -NoProfile -File .\Observe-Vbs.ps1` inside the approved VM. Compare raw configured/running arrays with `msinfo32.exe` System Summary. The lab does not require the features to be enabled; an accurately reported disabled/unknown state is valid evidence, not proof of compliance.

### Verification, Troubleshooting, and Cleanup

No author execution. Missing namespace/instance, access denial, or unsupported virtual hardware must remain UNKNOWN or an explicitly observed nonrunning state. Do not enable nested virtualization or change firmware on the host to make a test green. Actual policy rollout, reboot transitions, driver compatibility/performance, UEFI-lock recovery, and credential isolation remain unexecuted VM-only scope. Delete scratch files and privately held collection output. No policy needs reverting.

### Existing Study Checklist

- [ ] Local Windows Virtualization Security exercise: Inspect VBS/HVCI/Credential Guard status in a supported disposable VM and record prerequisites and incompatible-driver observations. Keep host security settings unchanged.
- [ ] Boundary check: Compare configured and reported runtime protection state in the lab, and verify monitoring detects an intentionally changed test policy without attempting protection bypass.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Virtualization Security Security]]

## References

- [VBS platform requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
- [Memory integrity and Win32_DeviceGuard schema](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Credential Guard configuration and runtime verification](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
