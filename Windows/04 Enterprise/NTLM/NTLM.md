---
title: "NTLM"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[NTLM Security]]"
updated: 2026-11-03
---
# NTLM

> [!abstract] TL;DR
> NTLM is a challenge-response authentication family carried by services through SSPI/SPNEGO or protocol-specific framing. The response is sensitive; version 2, negotiated flags and a successful logon do not by themselves prove intended-server binding or protected application traffic.

> [!info] Agent scope
> Challenge-response; NTLM versions; authentication flow; session security; relay prerequisites; auditing and reduction.

## Prerequisites

- Challenge-response vocabulary, Windows local/domain identities, SSPI/Negotiate, and the difference between authentication and application session security.
- Required exercise uses Python 3.12 standard library only and synthetic metadata, not passwords, hashes, responses, packets, AD or network services.

## Learn

```text
Teach NTLM at expert protocol and Windows authentication depth. Assume SSPI,
SPNEGO, challenge-response and local/domain identities. Trace NEGOTIATE,
CHALLENGE and AUTHENTICATE, security-buffer lengths/offsets, flags, target-info
AV pairs, MIC, session-key derivation roles, signing/sealing and service use.
Compare LM/NTLMv1/NTLMv2, extended session security versus response version,
local validation versus domain pass-through, and Negotiate fallback causes.
Explain intended-server binding limits, service signing, EPA/CBT and relay
prerequisites conceptually only. Do not generate or capture responses, hashes,
credentials, or provide guessing, theft, relay, movement or bypass procedures.
Give read-only audit commands, version/deprecation caveats, failure diagnosis
and a complete Python 3.12 stdlib offline metadata-state lab with tests. Label
all modeled facts as non-cryptographic, not proof of NTLM enforcement. Use
MS-NLMP and public Microsoft primary sources. No production targets, file
editing, study-status changes or invented execution. End with worked questions.
```

## Cheatsheet

### Actors and Message Flow

The client application requests an SSPI security context; a server application accepts it. For domain accounts, validation can be passed through a secure Netlogon channel to a DC; a member server need not store the user's password. Local accounts are validated by the relevant local authority. NTLM authentication is not a Kerberos ticket and does not inherently create delegation authority for a second service.

| Message | Important fields | Meaning and caution |
|---|---|---|
| Type 1 NEGOTIATE_MESSAGE | Signature `NTLMSSP`, MessageType, NegotiateFlags, optional domain/workstation buffers | Proposes capabilities. A flag is not evidence that the final application uses it. |
| Type 2 CHALLENGE_MESSAGE | ServerChallenge (8 bytes), flags, TargetName, TargetInfo | Server freshness challenge and metadata. TargetInfo AV pairs can contain names, timestamp, flags and channel/service-binding information. |
| Type 3 AUTHENTICATE_MESSAGE | Domain/User/Workstation buffers, LM/NT response fields, flags, optional encrypted random session key and MIC | Proves knowledge through the protocol response and establishes key material. Do not log or publish response/key fields. |

Security buffers carry length, maximum length and payload offset; offsets are relative to the message, not arbitrary pointers. A decoder must validate bounds and optional-field presence before interpretation. Unicode fields and negotiation-dependent layout mean a fixed-offset string scraper is not a protocol parser. This note deliberately supplies no raw authenticate-message generator or response computation.

NTLMv2 uses a password-derived key with challenge/client metadata to produce its proof; the NT response includes a proof and a structured client challenge blob (timestamp, client challenge, target info). That is not sending plaintext, but the result is still sensitive authentication material. MIC, when present/required, binds handshake messages using session key material; it is not application message signing, TLS server validation or a universal substitute for EPA.

### Version and Session Security

| Concept | Meaning |
|---|---|
| LM / NTLMv1 | Obsolete response mechanisms; do not enable for compatibility. NTLMv1 is removed from Windows 11 24H2 and Server 2025. |
| NTLMv2 | Stronger response construction than v1, but not a modern intended-service identity guarantee by itself. |
| Extended session security | A negotiated session-security feature/flag, not proof that the response is NTLMv2; historical naming is confusing. |
| SIGN | Supports per-message integrity through the security context when the application requests/uses it. |
| SEAL | Supports confidentiality plus integrity through the security context, using legacy NTLM session cryptography. |
| KEY_EXCH | Affects exported session key exchange/handling; not a new identity check. |
| EPA/service binding/CBT | Service-specific validation of intended service and/or outer TLS channel, where supported and enforced. |

Application use matters. SMB applies its own signing/encryption with session-derived keys; WinRM can use message protection; HTTP integrated authentication does not imply arbitrary HTTP bodies are NTLM-signed. Channel binding is supplied/validated by the surrounding authentication/service stack. A TLS proxy changes the channel boundary and must be part of a supported design.

NTLMv2 does not alone eliminate relay risk: conceptually, an authentication exchange can be misdirected when the service accepts it without required binding/protection and the identity has authority there. This is distinct from offline password guessing and from reuse of a stolen secret. No such procedures or credential material belong in this exercise.

### Fallback, Errors and Observation

Negotiate is a selection mechanism, not a synonym for Kerberos. Missing/incorrect SPNs, name aliases, IP literals, domain/trust unavailability and application choices can lead to NTLM. Determine which package was actually selected and why before restricting it. NTLM is deprecated across current Windows releases; deprecation is not blanket removal of NTLMv2 or proof it is disabled everywhere.

Local read-only commands on an owned disposable Windows VM; log access may need elevation, policy/event availability varies. They do not authenticate to another machine. Runtime unverified.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object LmCompatibilityLevel
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue | Select-Object NtlmMinClientSec,NtlmMinServerSec,RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic
Get-WinEvent -ListLog 'Microsoft-Windows-NTLM/Operational'
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4776; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20
```

Security 4776 records credential validation on the authenticating authority and can help identify NTLM use, but it does not prove a particular resource was accessed or identify every destination detail. 4624/4625 authentication package, logon type and status fields give host-specific context. A displayed package name or key length alone is not proof of confidentiality/signature enforcement. Missing audit events can mean policy, channel, retention or collection gaps.

| Symptom | Likely layer to inspect |
|---|---|
| `STATUS_LOGON_FAILURE` (`0xC000006D`) | Identity format, authority, policy, account state; use accompanying status details locally. |
| Wrong-password substatus (`0xC000006A`) | Credential validation; do not expose distinctions to anonymous clients. |
| `STATUS_ACCOUNT_RESTRICTION` (`0xC000006E`) | Logon restrictions/policy, not necessarily incorrect password. |
| Authentication succeeds, operation denied | Service authorization/ACL after logon. |
| Failure after restriction rollout | Required NTLM dependency or wrongly scoped exception; diagnose names/SPNs and client behavior, not automatic downgrade. |
| TLS/EPA failure | Peer identity/channel-binding architecture and supported client versions. |

## Gotchas

No protocol version flag proves an actual response version by itself. No response bytes should be needed for this lab. Do not translate a protected SMB session into a claim that every service accepting the same identity is protected.

## Labs

### Environment and Complete Files

Create an empty `ntlm-tech-offline` directory with this single file. Python 3.12 standard library only; all records are synthetic metadata. No Windows, AD, network, packages, credentials, responses, hashes or administrator rights. The model checks sequence/context/policy only and performs no NTLM cryptography. A 30-second budget is a lab rule, not a specified universal NTLM timeout. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Record:
	kind: str
	second: int
	context: str = "synthetic-context-1"
	response_version: str = "v2"
	sign_used: bool = True
	seal_used: bool = True


RECORDS = (Record("NEGOTIATE", 0), Record("CHALLENGE", 1),
		   Record("AUTHENTICATE", 2))


def diagnose(records, require_confidentiality=True):
	if tuple(record.kind for record in records) != (
			"NEGOTIATE", "CHALLENGE", "AUTHENTICATE"):
		return "bad-sequence"
	if len({record.context for record in records}) != 1:
		return "context-mismatch"
	times = [record.second for record in records]
	if times != sorted(times) or times[-1] - times[0] > 30:
		return "outside-lab-time-budget"
	final = records[-1]
	if final.response_version != "v2":
		return "legacy-or-unknown-response"
	if not final.sign_used:
		return "integrity-not-observed"
	if require_confidentiality and not final.seal_used:
		return "confidentiality-not-observed"
	return "metadata-contract-met"


class ExampleTests(unittest.TestCase):
	def test_complete_metadata(self):
		self.assertEqual(diagnose(RECORDS), "metadata-contract-met")

	def test_order_and_missing_message(self):
		self.assertEqual(diagnose(RECORDS[:2]), "bad-sequence")
		self.assertEqual(diagnose(tuple(reversed(RECORDS))), "bad-sequence")

	def test_context_and_time(self):
		mixed = RECORDS[:2] + (replace(RECORDS[-1], context="other"),)
		self.assertEqual(diagnose(mixed), "context-mismatch")
		late = RECORDS[:2] + (replace(RECORDS[-1], second=31),)
		self.assertEqual(diagnose(late), "outside-lab-time-budget")

	def test_version_evidence(self):
		for version in ("v1", "unknown"):
			changed = RECORDS[:2] + (replace(RECORDS[-1], response_version=version),)
			self.assertEqual(diagnose(changed), "legacy-or-unknown-response")

	def test_application_protection(self):
		unsigned = RECORDS[:2] + (replace(RECORDS[-1], sign_used=False),)
		self.assertEqual(diagnose(unsigned), "integrity-not-observed")
		unsealed = RECORDS[:2] + (replace(RECORDS[-1], seal_used=False),)
		self.assertEqual(diagnose(unsealed), "confidentiality-not-observed")
		self.assertEqual(diagnose(unsealed, False), "metadata-contract-met")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Confirm Python 3.12 using `python --version`; run `python -m unittest -v test_example` in the fixture directory (`py -3.12` can replace `python`).
2. Explain why a complete sequence with v2 metadata can still fail the declared confidentiality profile. Explain why `metadata-contract-met` is not "authentication verified."
3. Temporarily remove the `sign_used` rejection from `diagnose`; rerun to detect the integrity regression. Restore and rerun.

### Hints

All protocol evidence is assumed by the fixture. The checker cannot infer a MIC, channel binding, a valid proof or a trustworthy service from flags. The context identifier exists only for this model.

### Solution and Expected Results

Five tests should pass. Reordered/missing messages, context mixing, out-of-budget time, legacy/unknown version and insufficient application protection yield separate diagnostics. A profile that does not require confidentiality may accept the unsealed metadata; that is an explicit requirement difference, not automatic fallback. Removing the signing check causes the expected diagnostic assertion to fail.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoration and a clear statement that no actual NTLM exchange was performed or verified. Wrong directory causes import failures. Delete the directory and cache; no secrets or host configuration need cleanup.

### Retained Study Checklist

- [ ] Local NTLM exercise: Observe a synthetic NTLM authentication in an isolated lab and identify challenge/response and negotiated protection without attempting real credential recovery.
- [ ] Boundary check: Validate a lab service's required signing or channel-binding policy using supported diagnostics and confirm clients cannot silently negotiate below it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[NTLM Security]]

## References

- [MS-NLMP protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [Microsoft NTLM](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm)
- [NTLM overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Extended Protection for Authentication](https://learn.microsoft.com/en-us/windows/win32/secauthn/extended-protection-for-authentication)
- [Windows removed features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [Event 4776](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)
