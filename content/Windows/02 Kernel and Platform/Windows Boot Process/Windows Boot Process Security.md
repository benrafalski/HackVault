---
title: "Windows Boot Process Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[Windows Boot Process]]"
updated: 2026-11-03
---
# Windows Boot Process Security

> [!abstract] TL;DR
> Untrusted boot components, stale revocation policy, exposed recovery keys, and firmware misconfiguration can undermine early trust.

> [!info] Agent scope
> Security of: UEFI; Secure Boot; boot manager and loader; ELAM; Measured Boot; TPM; trust chain and recovery. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Untrusted boot components, stale revocation policy, exposed recovery keys, and firmware misconfiguration can undermine early trust.
- Review firmware supply/update trust, boot-image authorization/revocation, measured evidence freshness, attestation identity, recovery media, and recovery-key handling as separate boundaries. This note performs no boot modification.

## Learn

```text
Teach defensive Windows boot-trust auditing at expert depth. Assume UEFI startup,
hashes, signatures, and TPM basics. Target Windows 11 UEFI/TPM 2.0 and distinguish
OS/firmware-specific servicing. Explain PK/KEK/db/dbx, authorization versus
measurement, ELAM classifications, quote key trust, nonce freshness, PCR/log
binding, and allowlist evolution. Cover revocation and 2026 certificate servicing,
BitLocker recovery dependencies, vTPM trust, and safe evidence collection.
Give complete harmless offline failure/fix tests and read-only VM observations.
Do not treat hashes or synthetic MACs as real TPM attestation. Use Microsoft
primary sources; no boot exploitation, firmware changes, recovery secrets,
or host protection/VPN changes. Teach here without editing files.
```

## Cheatsheet

### Evidence Is Not Interchangeable

| Evidence | What it supports | What it does not prove |
|---|---|---|
| Secure Boot state | Firmware reports enforcement enabled for this boot | Current db/dbx servicing or trustworthy runtime |
| Authenticode signature | File signature validation under that verifier's trust policy | UEFI db/dbx authorization or absence of known defects |
| TPM present/ready | Platform exposes a usable TPM interface | Correct PCR policy, quote freshness, or attestation-key trust |
| Event-log replay match | Listed measurements produce the quoted/claimed accumulator | That the claim is signed, fresh, or accepted by policy |
| Valid fresh quote | Trusted attestation key signed selected state bound to challenge | Every runtime operation remains trustworthy |
| Recovery inventory | Authorized recovery path exists | Recovery image is current or recovery secrets are protected |

Secure Boot deny policy can supersede an allowed signer. A correctly signed old component can still be revoked or below an organization's approved baseline. Do not re-enable obsolete trust to make stale media boot. Refresh recovery media using the vendor-supported process and validate on a disposable clone before rollout. Firmware trust-variable changes and certificate updates need their own evidence; OS patch level is not a substitute.

ELAM classifications feed boot policy. Unknown and bad-but-boot-critical are not synonyms for trusted; policy trades availability against risk. A health report must include the effective policy and platform constraints. An ELAM driver is not proof that all later drivers or user applications were inspected by it.

### Attestation Verifier Contract

1. Issue an unpredictable, single-use challenge bound to the session/device and expiry.
2. Validate the attestation key's enrollment/certification, quote signature, and expected algorithm/selection.
3. Check nonce/session binding and reject stale/replayed evidence.
4. Replay the appropriate event log into the quoted PCR selection; handle reset/separator semantics using the actual log format.
5. Apply an explicit accepted-measurement/policy baseline and distinguish unknown from failed.

Do not trust a client-supplied Boolean named `healthy`, a raw hash, or an unverified log. Local administrator-visible reports are useful triage evidence but not a remote root of trust. In ordinary VMs the host administrator controls important parts of virtual platform trust; guest attestation claims must be scoped accordingly.

### Read-Only VM Evidence

These commands gather nonsecret observations inside an approved disposable Windows 11 VM. They neither certify UEFI authorization nor change configuration.

```powershell
Confirm-SecureBootUEFI
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated
$loader = Join-Path $env:SystemRoot 'System32\winload.efi'
Get-FileHash -Algorithm SHA256 -LiteralPath $loader
Get-AuthenticodeSignature -LiteralPath $loader | Select-Object Status, StatusMessage
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus
```

The on-disk loader query is not evidence that these exact bytes ran at boot. Authenticode and UEFI use different validation contexts. Do not export TPM owner secrets, BitLocker recovery passwords, or actual corporate boot logs. Exact firmware/certificate servicing and recovery requirements should come from current Microsoft/OEM guidance, not a guessed universal registry recipe.

## Detection and Defense

Use staged firmware/OS/revocation servicing, controlled recovery-key access, refreshed recovery media, independent attestation where required, and explicit unknown-state handling. Investigate changed boot measurements alongside approved maintenance before labeling them hostile. Preserve timestamp, build, boot/session identity, verifier policy version, and query failures; do not silently drop unsupported machines from compliance reports. Recovery tests require a disposable clone, known authorized recovery custody, and console access; no recovery-key disclosure or protection-disable procedure is included.

## Labs

### Environment and Complete File

Python 3.11+ standard library; empty scratch directory; no VM/TPM/network needed for this fixture. Save `boot_evidence.py` below. It uses a public test HMAC key solely to demonstrate authenticated message/freshness binding. It is not a TPM quote implementation, not asymmetric device identity, and not production attestation. The byte-level measurement extension is real SHA-256 logic over synthetic data.

### File: boot_evidence.py

```python
import hashlib
import hmac
import json

KEY = b"public-lab-fixture-key-not-a-secret"
EVENTS = ["lab-firmware-v1", "lab-loader-v1", "lab-kernel-v1"]

def replay(events):
	state = bytes(32)
	for event in events:
		state = hashlib.sha256(state + hashlib.sha256(event.encode()).digest()).digest()
	return state.hex()

def encode(body):
	return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

def issue(events, nonce):
	body = {"device": "lab-vm", "nonce": nonce, "pcr": replay(events)}
	return body, hmac.new(KEY, encode(body), hashlib.sha256).hexdigest()

def flawed(body, events):
	return body["pcr"] == replay(events)

def verify(body, signature, events, challenge, accepted):
	expected = hmac.new(KEY, encode(body), hashlib.sha256).hexdigest()
	if not hmac.compare_digest(signature, expected):
		return "AUTHENTICITY"
	if body["device"] != "lab-vm" or body["nonce"] != challenge:
		return "FRESHNESS_OR_IDENTITY"
	if body["pcr"] != replay(events):
		return "LOG_MISMATCH"
	if body["pcr"] not in accepted:
		return "UNAPPROVED_MEASUREMENT"
	return "ACCEPT"

accepted = {replay(EVENTS)}
body, signature = issue(EVENTS, "challenge-2")
assert verify(body, signature, EVENTS, "challenge-2", accepted) == "ACCEPT"
stale, stale_sig = issue(EVENTS, "challenge-1")
assert flawed(stale, EVENTS)
assert verify(stale, stale_sig, EVENTS, "challenge-2", accepted) == "FRESHNESS_OR_IDENTITY"
tampered = {**body, "pcr": "00" * 32}
assert verify(tampered, signature, EVENTS, "challenge-2", accepted) == "AUTHENTICITY"
assert verify(body, signature, EVENTS[::-1], "challenge-2", accepted) == "LOG_MISMATCH"
updated = ["lab-firmware-v1", "lab-loader-v2", "lab-kernel-v1"]
new_body, new_sig = issue(updated, "challenge-2")
assert verify(new_body, new_sig, updated, "challenge-2", accepted) == "UNAPPROVED_MEASUREMENT"
accepted.add(replay(updated))
assert verify(new_body, new_sig, updated, "challenge-2", accepted) == "ACCEPT"
assert verify(body, signature, EVENTS, "challenge-2", accepted) == "ACCEPT"
print("PASS: stale baseline rejected; authentication, replay, and rollout checks")
```

### Objectives, Hints, and Worked Solution

Run `python boot_evidence.py`. The baseline accepts an old observation because the same event list replays to the same digest. The fixed verifier first authenticates the envelope, then checks challenge/device binding, log consistency, and approved state. It preserves current valid evidence and accepts a deliberately approved updated loader baseline.

Hint: freshness is not a hash property. The fixed deterministic challenge is test data only; a real service must generate fresh unpredictable challenges and consume them once, with expiry and session binding. The fixture does not implement that service or TPM key validation. Changing the accepted set is a simulated reviewed rollout, not automatic trust in any new measurement.

### Verification, Troubleshooting, and Cleanup

Expected output is the PASS line; no author execution. Python standard-library availability is the only offline prerequisite, and no build is needed. A signature mismatch after editing a body is the intended result. Optional live observations need Windows PowerShell 5.1 and VM administrator rights; query errors remain unknown, not compliant. Real quotes, PCR/event formats, Secure Boot certificate rollout, ELAM, and recovery boot remain unexecuted VM scope. Delete the single scratch file. No firmware, host protections, network, or VPN changes occurred or are needed.

### Existing Study Checklist

- [ ] Local Windows Boot Process exercise: In a disposable VM, inspect Secure Boot and TPM availability, record boot configuration, and compare documented measured/verified boot roles. Do not disable the host's protections.
- [ ] Boundary check: Verify a test VM reports its configured Secure Boot state and that policy changes are detectable; use only supported benign configuration checks.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[Windows Boot Process]]

## References

- [Secure the Windows boot process](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [UEFI Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot)
- [TPM fundamentals](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals)
- [BitLocker recovery overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
