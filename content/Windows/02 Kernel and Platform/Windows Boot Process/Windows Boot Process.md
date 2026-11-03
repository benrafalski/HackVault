---
title: "Windows Boot Process"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[Windows Boot Process Security]]"
updated: 2026-11-03
---
# Windows Boot Process

> [!abstract] TL;DR
> Secure Boot verifies; Measured Boot records; attestation evaluates evidence under policy. Document firmware mode, trust state, OS build, and recovery material handling.

> [!info] Agent scope
> UEFI; Secure Boot; boot manager and loader; ELAM; Measured Boot; TPM; trust chain and recovery.

## Prerequisites

- Windows startup, signatures versus hashes, and basic PowerShell. Offline lab: Python 3.11+ standard library, no elevation. Optional observation: pre-existing Windows 11 UEFI VM, Secure Boot and vTPM provisioned by its owner, Windows PowerShell 5.1, local administrator for read-only firmware/TPM queries.
- Use a disposable VM with snapshot and console. Do not modify physical-host firmware, boot options, protections, VPN, TPM state, or recovery material. No reboot/configuration change is needed by these exercises.
- [[Windows Lab Setup]]

## Learn

```text
Teach the Windows UEFI boot and trust chain at expert platform depth. Assume
basic OS startup, cryptographic hashes, and signatures. Target Windows 11 UEFI
with TPM 2.0; distinguish legacy paths and version-dependent Windows behavior.
Trace firmware, boot manager, BCD selection, OS loader, kernel, boot drivers,
ELAM, and user-mode startup. Explain PK/KEK/db/dbx, Secure Boot versus Trusted
Boot, measurement extension, event-log replay, TPM quotes, nonce freshness,
attestation policy, and BitLocker recovery dependencies. Work complete benign
offline replay examples and read-only VM inventory, with expected outputs and
limits. Cover updates, revocation, recovery media, and 2026 certificate servicing
without firmware changes or recovery secrets. Use Microsoft primary sources.
No exploitation or host protection changes. Teach here without file edits.
```

## Cheatsheet

### Boot Sequence and Responsibility

| Stage | Responsibility | Important boundary |
|---|---|---|
| UEFI firmware | Initialize platform and select boot entry | Secure Boot authorizes eligible executable images under firmware policy |
| Windows Boot Manager (`bootmgfw.efi`) | Read BCD and select boot application | BCD is configuration, not proof of system health |
| OS loader (`winload.efi`) | Load kernel, HAL, boot drivers and required security components | Image validation and platform policy constrain what starts |
| Kernel initialization | Initialize executive/I/O system and boot drivers | Trusted Boot continues integrity checks; ELAM supplies early classification |
| Session/service startup | Start user-mode system components and services | Later application behavior is not certified by an earlier valid boot |

Resume and recovery are distinct boot paths; do not assume normal cold-boot evidence applies unchanged. Hypervisor/VBS components participate when configured and supported. Startup order has version/platform detail beyond this conceptual sequence; preserve the exact OS build and firmware version in evidence.

### Authorization, Measurement, and Attestation

UEFI Secure Boot uses authenticated policy variables. PK establishes platform ownership; KEK authorizes updates to signature databases; `db` contains allowed certificates/hashes and `dbx` contains revoked entries. Revocation can make an otherwise correctly signed component unacceptable. Secure Boot does not require the TPM merely to perform signature authorization; a TPM is used for measurement/key-protection scenarios. Firmware self-integrity and vendor update security are separate platform responsibilities, not guaranteed by checking a bootloader signature alone.

Trusted Boot extends Windows integrity validation into loader/kernel/startup components. ELAM is a specially provisioned early anti-malware driver, not a general third-party callback anyone can install. It classifies boot-start drivers as good, bad, bad-but-boot-critical, or unknown; Windows initialization policy decides how those classifications affect loading. Do not simplify this to "all unknown drivers are always rejected." ELAM is not the full runtime antimalware engine.

Measured Boot records events and extends selected TPM PCRs. For a SHA-256 PCR, conceptual extension is `new = SHA256(old || event_digest)`. Order matters. PCR contents are accumulators, not a file list; the event log lets a verifier reconstruct what contributed. The log lives outside the TPM and must be checked against authenticated PCR evidence. PCR assignments, algorithms, resets, and event types depend on platform/specification; the lab uses a deliberately synthetic single accumulator, not a real Windows log parser.

A TPM quote signs selected PCR state and caller-supplied freshness data with an attestation key. A verifier validates key trust, quote signature, challenge freshness, selection/algorithm, log replay, and acceptable measurement policy. Hash agreement alone proves neither trustworthy measurements nor fresh hardware evidence. Attestation can gate access under explicit policy; it does not prove all runtime activity is benign.

### Recovery and Servicing

BitLocker can seal key access to acceptable platform state. Firmware/boot changes can legitimately trigger recovery; Secure Boot and BitLocker solve different problems. Recovery keys must be available to authorized recovery staff but never logged into public lab notes. TPM clear, firmware key replacement, and trust-database edits can destroy access or alter trust and are not troubleshooting steps here.

Secure Boot certificate/revocation servicing is version- and firmware-sensitive. During the 2011-to-2023 certificate transition relevant to 2026, check current Microsoft/OEM deployment guidance, serviced recovery media, and actual update evidence. A valid signature, a recent OS build, and an enabled Secure Boot flag are three different observations. Do not infer completion of revocation/certificate rollout from any one of them.

### Read-Only VM Collector

Complete `Observe-Boot.ps1`, run only inside the approved VM. It prints no TPM keys, protector secrets, or recovery passwords. A failed query stays unknown rather than being converted to false.

```powershell
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$secureBoot = $null
$secureBootError = $null
$tpmPresent = $null
$tpmReady = $null
$tpmError = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI) }
catch { $secureBootError = $_.Exception.GetType().FullName }
try {
	$tpm = Get-Tpm
	$tpmPresent = [bool]$tpm.TpmPresent
	$tpmReady = [bool]$tpm.TpmReady
} catch { $tpmError = $_.Exception.GetType().FullName }
[pscustomobject]@{
	CapturedUtc = [DateTime]::UtcNow.ToString('o')
	Build = $os.BuildNumber
	LastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
	SecureBoot = $secureBoot
	SecureBootQueryError = $secureBootError
	TpmPresent = $tpmPresent
	TpmReady = $tpmReady
	TpmQueryError = $tpmError
} | ConvertTo-Json
```

Additional VM-only read commands: `bcdedit /enum '{current}'` in PowerShell, and `Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod`. BCD output is configuration evidence; disk encryption status is not a quote. Do not enumerate/export recovery passwords.

## Gotchas

An unsupported firmware query and an explicitly disabled feature are different outcomes. A vTPM represents the hypervisor's virtual trust boundary; it does not make the guest independent of its host administrator. Never interpret a synthetic replay as a quote or a real PCR reading.

## Labs

### Environment and Complete Files

Offline exercise uses only Python 3.11+. Save `events.json` and `replay.py` in an empty scratch directory. The components are literal synthetic text, not real boot binaries.

### File: events.json

```json
[
  {"component":"firmware","payload":"lab-firmware-v1"},
  {"component":"boot-manager","payload":"lab-bootmgr-v1"},
  {"component":"loader","payload":"lab-loader-v1"},
  {"component":"kernel","payload":"lab-kernel-v1"},
  {"component":"elam","payload":"lab-elam-v1"}
]
```

### File: replay.py

```python
import hashlib
import json
from pathlib import Path

def digest(payload):
	return hashlib.sha256(payload.encode("utf-8")).digest()

def replay(events):
	accumulator = bytes(32)
	for event in events:
		accumulator = hashlib.sha256(accumulator + digest(event["payload"])).digest()
	return accumulator

events = json.loads(Path("events.json").read_text(encoding="utf-8"))
baseline = replay(events)
assert len(baseline) == 32
assert replay(events) == baseline
assert replay(list(reversed(events))) != baseline
assert replay(events[:-1]) != baseline
changed = [dict(event) for event in events]
changed[2]["payload"] = "lab-loader-v2"
assert replay(changed) != baseline
assert replay([]) == bytes(32)
print("synthetic-sha256-pcr=" + baseline.hex())
print("PASS: deterministic replay; order, omission, and update detected")
```

### Objectives and Steps

1. Run `python replay.py`. Explain why even a benign loader update changes downstream accumulated state.
2. Derive why reversing events cannot be repaired merely by keeping the same set of hashes.
3. Optional live observation: save the complete collector above and run `powershell.exe -NoProfile -File .\Observe-Boot.ps1` inside an already provisioned disposable VM. No build is needed for either script. Keep raw output private and compare only nonsecret state.

### Hints and Worked Solution

The accumulator includes its previous value, so each extension depends on sequence. The expected output is a 64-hex-character synthetic digest plus the PASS line; no measured real-world digest is claimed. A changed digest is expected after an authorized update and needs policy evaluation, not automatic incident attribution. Live expected fields depend on the VM: true/false/null must remain distinct. TPM ready plus Secure Boot true still says nothing about quote validation or fresh attestation.

### Verification, Troubleshooting, and Cleanup

No author execution. JSON parse failures usually mean copied punctuation or a wrong directory. `Confirm-SecureBootUEFI` can fail for insufficient privilege or unsupported firmware; record the error rather than changing firmware. `Get-Tpm` may be unavailable in the selected shell; use the stated Windows PowerShell environment, or retain unknown. Real event-log replay, TPM quotes, certificate rollout, ELAM behavior, and recovery boot remain unexecuted VM scope. Delete scratch files; there is no configuration to revert.

### Existing Study Checklist

- [ ] Local Windows Boot Process exercise: In a disposable VM, inspect Secure Boot and TPM availability, record boot configuration, and compare documented measured/verified boot roles. Do not disable the host's protections.
- [ ] Boundary check: Verify a test VM reports its configured Secure Boot state and that policy changes are detectable; use only supported benign configuration checks.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Boot Process Security]]

## References

- [Secure the Windows boot process](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [UEFI Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot)
- [ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)
- [Confirm-SecureBootUEFI](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi)
- [TPM overview](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview)
