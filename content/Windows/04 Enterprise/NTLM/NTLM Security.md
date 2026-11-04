---
title: "NTLM Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[NTLM]]"
updated: 2026-11-03
---
# NTLM Security

> [!abstract] TL;DR
> Audit NTLM dependencies, repair avoidable fallback, harden each accepting service, and enforce scoped restrictions with expiring exceptions. NTLMv2 is not a substitute for service binding, message protection or least privilege.

> [!info] Agent scope
> Security of: Challenge-response; NTLM versions; authentication flow; session security; relay prerequisites; auditing and reduction. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Negotiate fallback, application authentication choice, accepting-service protection, legacy response policy, domain/local authority, exception scope and credential-validation telemetry.
- Conceptual relay prerequisites include an available authentication exchange, a service accepting it without adequate binding/protection, and relevant identity permissions. This differs from guessing a captured response or reusing a stolen secret. No procedures for any of those actions are included.

## Learn

```text
Teach defensive NTLM reduction and diagnosis at expert depth. Assume NTLM
challenge-response, SSPI/Negotiate and Windows service authorization. Explain
v1/v2 and extended-session-security distinctions, MIC versus application
signing, EPA/service binding/CBT, local versus domain validation, fallback
causes, per-service controls, and audit-first restriction rollout. Explain
relay/guessing/secret-reuse prerequisites only conceptually, never instructions
for theft, collection, relay, movement, exploitation, bypass or evasion.
Provide exact read-only observations, policy names/semantics, version limits,
event correlation and false-positive analysis. Build a complete Python 3.12
stdlib offline migration-policy lab with an unsafe baseline, strict fix,
expiring scoped exceptions, positive operations and negative regressions.
No real credentials, targets or network; label metadata decisions as a model,
not cryptographic or OS enforcement. Use Microsoft primary sources, no invented
execution, file editing or study-status changes. End with worked scenarios.
```

## Cheatsheet

### Mechanisms and Defensive Boundaries

NTLM's Type 1/2/3 negotiation, challenge and authenticate messages establish an authentication context and session key material; they do not carry a Kerberos service ticket. A MIC protects handshake consistency in applicable cases, whereas application signing/sealing protects subsequent messages. Extended session security is not a reliable proxy for NTLMv2 response use. A service can accept NTLMv2 yet fail a service-binding or message-protection requirement.

| Service/context | Defensive control | Do not assume |
|---|---|---|
| SMB | Required signing and sensitive-share encryption; no insecure guest | NTLMv2 alone guarantees message integrity or confidential file contents. |
| LDAP | Required signing for non-TLS SASL, TLS/sealing as required, appropriate SASL-over-TLS CBT | TLS alone means CBT is enforced; signing means confidentiality. |
| HTTP integrated authentication | Validated TLS and supported EPA/service-binding configuration | HTTP payloads are automatically protected merely because NTLM authenticated. |
| WinRM | Intended server identity, protected WSMan messages, endpoint least privilege | TrustedHosts is a server-authentication mechanism or inbound ACL. |
| All services | Reduce NTLM dependencies and identity rights; patch both endpoints | One service's hardening transfers to every other service. |

TLS termination, load balancers, aliases and service accounts can affect authentication/service binding. Keep a documented supported path; do not weaken validation to accommodate an unreviewed intermediary. NTLMv1 is removed in Windows 11 24H2/Server 2025; NTLMv2 is deprecated, not universally removed or disabled. Older appliances and libraries need explicit compatibility inventory, not assumed Windows defaults.

### Exact Policy Semantics

Owned snapshot-backed lab only. Policies under `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`; inspect/audit before enforcing. Optional changes are not required for the offline lab and are runtime-unverified here.

| Policy | Staged defensive setting | Scope |
|---|---|---|
| Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM | Response/acceptance compatibility; this is not "disable all NTLM." Historical `LmCompatibilityLevel=5`; exact effect depends on role/version. |
| Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers | Audit all, then Deny all after dependencies are addressed | Client outbound use; server exceptions need independent review. |
| Network security: Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts | Observes inbound dependency; audit does not block. |
| Network security: Restrict NTLM: Incoming NTLM traffic | Deny all accounts only after validated migration | Local receiving-host restriction, not a domain-wide substitute. |
| Network security: Restrict NTLM: Audit NTLM authentication in this domain | Enable all in a dedicated AD lab | Domain-controller-side audit; not identical to member-server logs. |

There are separate domain enforcement and exception policies; do not translate a member-server setting into a domain-wide guarantee. Exceptions should have owner, reason, exact client/service/destination scope where the management system supports it, review date and expiry. Windows exception mechanisms do not necessarily enforce all of those dimensions or expiry automatically: use change management and removal automation. The lab's multi-field exception model is a desired governance contract, not the native policy syntax.

Local read-only observations, owned disposable VM only; elevation/logging configuration may be required:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object LmCompatibilityLevel
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue | Select-Object RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic,AuditReceivingNTLMTraffic
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 30
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776,4624,4625; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 30
gpresult /Scope Computer /r
```

Absent values are not proof of disabled policy. `gpresult /r` lists applied GPOs rather than a complete effective security-settings report. Document build, policy source and service outcome; restore optional lab changes through the snapshot, not by guessing defaults.

### Migration and Failure Diagnosis

1. Inventory package, client process, intended service/name, local/domain identity, direction and owner using authorized audit metadata.
2. Repair avoidable name/SPN/DNS/time/trust/application-selection problems. A service using an IP literal or unregistered alias may not obtain the intended Kerberos context.
3. Validate service-specific protection and least privilege; a restriction exception is not an exemption from those controls.
4. Compare audit would-block cases against required workflows, then enforce by a small reviewed scope; keep a rollback snapshot for the isolated lab.

Do not treat every fallback as malicious. Workgroup/local accounts, legacy software and legitimate application constraints produce NTLM. Conversely, an event count dropping to zero may mean the log collector broke. Authentication failures after enforcement need policy/package correlation rather than immediate relaxation.

## Detection and Defense

NTLM Operational events depend on enabled audit/restriction settings and OS version; inspect message and direction, not one universal event ID rule. Security 4776 records validation at the authority and can show a workstation but not a complete service path. 4624/4625 at the destination provide package/logon information; logon type 3 is network logon, not proof of SMB. Correlate source, destination, time, identity, status and process where available. Never retain challenge/response blobs or real credentials in study notes.

Track coverage separately from results: which hosts, time range, policy mode and event channels were observed? Alert on new/expanded exceptions, protection weakening and unexpected NTLM dependencies, with expected inventory/backup/service activity as context. Audit-only results must not be reported as prevented access.

## Labs

### Environment and Complete Files

New empty `ntlm-security-offline` directory; single file below, embedded synthetic records, Python 3.12 standard library. No packages, network, services, Windows/AD, credentials, challenge responses or elevation. This is a migration governance model, not an NTLM stack or native policy importer. Protection flags are trusted test inputs, not verified cryptography. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
from datetime import date
import unittest


TODAY = date(2026, 11, 3)


@dataclass(frozen=True)
class Event:
	package: str = "NTLMv2"
	client: str = "legacy-reader.example.invalid"
	service: str = "inventory"
	destination: str = "lab.example.invalid"
	authenticated: bool = True
	protection_verified: bool = True


@dataclass(frozen=True)
class ExceptionRule:
	client: str = "legacy-reader.example.invalid"
	service: str = "inventory"
	destination: str = "lab.example.invalid"
	expires: date = date(2026, 11, 10)


def baseline(event):
	return event.authenticated


def decide(event, mode="enforce", exception=None, today=TODAY):
	if mode not in {"audit", "enforce"}:
		raise ValueError("unknown policy mode")
	if not event.authenticated:
		return "deny-authentication"
	if not event.protection_verified:
		return "deny-service-protection"
	if event.package == "Kerberos":
		return "allow"
	eligible = (event.package == "NTLMv2" and exception is not None
				and today < exception.expires
				and (event.client, event.service, event.destination) ==
				(exception.client, exception.service, exception.destination))
	if eligible:
		return "allow-exception"
	return "audit-would-deny" if mode == "audit" else "deny-package"


class ExampleTests(unittest.TestCase):
	def test_baseline_audit_and_enforcement(self):
		self.assertTrue(baseline(Event()))
		self.assertEqual(decide(Event(), "audit"), "audit-would-deny")
		self.assertEqual(decide(Event()), "deny-package")

	def test_permitted_migration_and_exception(self):
		self.assertEqual(decide(replace(Event(), package="Kerberos")), "allow")
		self.assertEqual(decide(Event(), exception=ExceptionRule()), "allow-exception")

	def test_exception_scope(self):
		for changes in ({"client": "other.example.invalid"},
						{"service": "other"}, {"destination": "other.example.invalid"}):
			self.assertEqual(decide(replace(Event(), **changes),
									exception=ExceptionRule()), "deny-package")

	def test_expiry_and_legacy(self):
		self.assertEqual(decide(Event(), exception=ExceptionRule(expires=TODAY)),
						 "deny-package")
		self.assertEqual(decide(replace(Event(), package="NTLMv1"),
								exception=ExceptionRule()), "deny-package")

	def test_exception_does_not_remove_other_gates(self):
		self.assertEqual(decide(replace(Event(), protection_verified=False),
								exception=ExceptionRule()), "deny-service-protection")
		self.assertEqual(decide(replace(Event(), authenticated=False),
								exception=ExceptionRule()), "deny-authentication")


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Confirm `python --version` is 3.12; run `python -m unittest -v test_example` from the directory (`py -3.12` can replace `python`). No system date change is needed; the fixture fixes the review date.
2. Explain the difference between `audit-would-deny` and `deny-package`. Identify the permitted migrated workflow and bounded legacy exception.
3. Temporarily change `today < exception.expires` to `today <= exception.expires`; rerun to detect the expiry-boundary regression. Restore and rerun.

### Hints

The exception expires at the start of its stated date under this model. Audit mode only changes the package-policy decision, not the independent authentication/protection gates. The fixture never attempts an authentication.

### Solution and Fixed Retest

Five tests should pass. Authenticated NTLMv2 is accepted by the unsafe baseline, would be flagged in audit mode and is denied under enforcement unless the exact unexpired exception matches. Kerberos metadata remains permitted; legacy v1 and scope/expiry mismatches do not. The expiry experiment fails at the boundary date. These are desired policy decisions, not evidence that Windows natively implements an expiring three-field exception.

### Verification, Troubleshooting, and Cleanup

Acceptance: five tests pass after restoration, boundary regression detected, and audit is never described as blocking. Import errors mean wrong directory/file; system date is irrelevant. Delete the directory/cache. Optional Windows policy work requires a separately controlled snapshot-backed lab and remains unverified.

### Retained Study Checklist

- [ ] Local NTLM exercise: Observe a synthetic NTLM authentication in an isolated lab and identify challenge/response and negotiated protection without attempting real credential recovery.
- [ ] Boundary check: Validate a lab service's required signing or channel-binding policy using supported diagnostics and confirm clients cannot silently negotiate below it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[NTLM]]

## References

- [NTLM overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Restrict outgoing NTLM policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)
- [LAN Manager authentication level](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
- [Extended Protection for Authentication](https://learn.microsoft.com/en-us/windows/win32/secauthn/extended-protection-for-authentication)
- [Event 4776](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)
