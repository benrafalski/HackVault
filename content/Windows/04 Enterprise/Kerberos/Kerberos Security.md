---
title: "Kerberos Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[Kerberos]]"
updated: 2026-11-03
---
# Kerberos Security

> [!abstract] TL;DR
> Protect KDC and service keys, require appropriate preauthentication and encryption, constrain delegation and trust, and validate authorization after authentication. A plausible decoded ticket or PAC is not verified identity evidence.

> [!info] Agent scope
> Security of: KDC; principals and SPNs; TGT and service tickets; preauthentication; PAC; delegation; trust and time. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Principal/SPN ownership, key lifecycle, preauthentication policy, ticket/session encryption, KDC/PAC validation, service authorization, delegation permissions, trust paths and time dependencies.
- Risks depend on weak/provisioned secrets, missing account safeguards, excessive directory write rights or control of a trusted authority. Explain those prerequisites conceptually; no ticket forgery, extraction, roasting, credential theft or delegated-access procedures are included.

## Learn

```text
Teach defensive Kerberos security at expert Windows identity depth. Assume
AS/TGS/AP exchanges, SPNs, PACs, AD ACLs and ticket lifetimes. Analyze KDC and
service key trust, preauthentication, managed service identities, actual AES
key availability, ticket versus session encryption, PAC validation, service
authorization, delegation, nondelegable users, trusts and time. Give threat
prerequisites conceptually only: no theft, ticket generation/forgery/export,
roasting, relay, movement, privilege escalation, bypass, evasion or persistence.
Provide exact read-only metadata commands, secure lab-only configuration
semantics, version/patch caveats, event correlation and false-positive analysis.
Build a complete Python 3.12 stdlib offline posture/admission model with a
permissive baseline, concrete fix and positive/negative regression tests.
No AD, secrets or real targets; label booleans as assumed facts, not PAC or
cryptographic verification. Use RFC4120, MS-KILE/MS-PAC and Microsoft primary
sources. No invented results, file edits or study-status changes. End with
worked diagnosis questions distinguishing authentication from authorization.
```

## Cheatsheet

### Trust and Key Boundaries

| Boundary | Required defensive property | Limit |
|---|---|---|
| AS/preauthentication | Normal identities require appropriate preauthentication; certificate methods require valid PKI/mapping | A normal preauthentication-required response is not a password failure. Do not remove the requirement to repair clients. |
| KDC/TGT | Protect DCs, `krbtgt` authority and replication/admin permissions | A compromised issuing authority invalidates assumptions beyond one application. Recovery is an incident-response procedure, not this lab. |
| Service/SPN/key | Unique correct SPN owner; strong managed secret lifecycle and matching deployed keys | DNS alias reachability alone does not establish key ownership; rotation can cause stale-key failures. |
| Ticket/session crypto | Compatible permitted algorithms and actual available keys at each participant | An AES session key does not prove the ticket itself used AES; supported-type flags do not create missing keys. |
| PAC/security context | Supported Windows validation and patched KDC/services | Parsed claims are not trusted claims; application authorization still follows. |
| Delegation | Explicit minimal downstream scope and nondelegable sensitive identities | A forwardable flag is not an authorization list. Resource ACLs and delegation configuration rights need protection. |
| Trust/resource | Approved trust direction/path, selective authentication and SID filtering as applicable | Trust provides an authentication path, not universal resource authorization. |

A TGT is encrypted for KDC authority; a service ticket for the service account. The application validates AP context/freshness and then evaluates rights. PAC signatures and KDC validation behavior have changed through hardening updates; keep all participating components on supported patch levels rather than assuming old acceptance behavior. Existing sessions/tickets may retain authorization context after account/group changes; plan revocation and incident response separately from ordinary expiration.

### Defensive Configuration Semantics

Only for a separate owned snapshot-backed AD lab. None of these optional administrative changes are prerequisites for the offline exercise, and none were runtime-verified here.

- In Active Directory Users and Computers, synthetic user > Account > Account options: leave "Do not require Kerberos preauthentication" unchecked; use "Account is sensitive and cannot be delegated" for the synthetic protected identity. Review actual application compatibility rather than applying a blanket production edit.
- Prefer gMSAs for supported services. Restrict which computers/principals may retrieve the managed password, keep service rights minimal, and review SPNs. Managed passwords do not make a broadly privileged service safe. Do not retrieve password material for a study exercise.
- Under `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`, "Network security: Configure encryption types allowed for Kerberos" controls permitted algorithms. For a compatible isolated lab, select AES128_HMAC_SHA1 and AES256_HMAC_SHA1, exclude DES/RC4, and validate actual key availability before enforcement. Do not equate algorithm labels with an account-attribute bitmask or assume this is a universal latest-production baseline.
- Under `Account Policies > Kerberos Policy`, "Enforce user logon restrictions" should remain enabled; "Maximum tolerance for computer clock synchronization" commonly defaults to 5 minutes. Diagnose time sources rather than widening skew to silence errors. Domain ticket lifetime/renewal policy is not immediate revocation.
- Remove unnecessary unconstrained delegation through approved administration. For constrained/resource-based designs, review the exact front-end identity, downstream SPNs/resources, nondelegable users and who can modify the delegation configuration. This note provides no delegation-enabling commands.

Classic AES etypes are 17/18 (`0x11`/`0x12`); RC4-HMAC is 23 (`0x17`). `msDS-SupportedEncryptionTypes` uses separate bit flags (AES128 `0x08`, AES256 `0x10`, RC4 `0x04`). An unset attribute is not a complete algorithm verdict; KDC defaults, policy, account keys and patch level participate. Server 2025 ignores the legacy Kerberos `SupportedEncryptionTypes` registry configuration described in Microsoft's overview; use supported policy instead. Account password/key lifecycle work needs change control, not an arbitrary reset to fix an event.

### Read-only Metadata and Error Triage

Owned isolated lab only, with pre-existing synthetic objects. The AD cmdlets require the already-installed ActiveDirectory module/RSAT and authorized directory read access; do not install it for this offline exercise. Queries read metadata and do not request/export tickets or retrieve passwords. Names intentionally use the reserved `.invalid` namespace. Runtime unverified.

```powershell
klist
w32tm /query /status
setspn -Q HTTP/inventory.example.invalid
Get-ADUser -Identity 'lab-reader' -Properties DoesNotRequirePreAuth,AccountNotDelegated,ServicePrincipalNames | Select-Object Name,DoesNotRequirePreAuth,AccountNotDelegated,ServicePrincipalNames
Get-ADServiceAccount -Identity 'lab-inventory' -Properties ServicePrincipalNames,msDS-SupportedEncryptionTypes,PrincipalsAllowedToRetrieveManagedPassword | Select-Object Name,ServicePrincipalNames,msDS-SupportedEncryptionTypes,PrincipalsAllowedToRetrieveManagedPassword
```

If the module/object/domain is absent, skip optional observations; do not create a domain or weaken policy to make them run. A service ticket missing from the current `klist` cache does not prove the application never used Kerberos; it can have a different logon session/cache or an existing service session.

`KDC_ERR_S_PRINCIPAL_UNKNOWN` points to naming/mapping; `ETYPE_NOTSUPP` to incompatible policy or keys; `PREAUTH_FAILED` to credential/preauthentication validation; `KRB_AP_ERR_MODIFIED` often to wrong service keys/SPN owner; `SKEW` to time. Distinguish requested options from issued ticket flags, ticket validity from renewal, and successful ticket issuance from actual resource access.

## Detection and Defense

DC Security 4768 records TGT requests; 4769 records service-ticket requests; 4771 records preauthentication failures under the relevant audit policies. Destination 4624 and application logs support service-use correlation. A successful 4769 is not proof of access, and a cached ticket can be used without a new 4769 for each operation. SPN/service account names and LogonGuid availability vary; a zero GUID is not a valid universal join key.

Read-only DC lab query: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4771; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 30`. Updated Server 2016+ schemas after January 2025 updates expose additional supported-type, available-key and session-key fields. Parse EventData by name and event version; missing fields mean unknown, not "secure." Monitor ticket and session encryption separately. Do not collect ticket blobs or include live account data in notes.

Legitimate service restarts, inventory jobs, changed passwords, stale DNS and time drift can produce bursts/failures. Correlate changes in SPNs, delegation attributes and account options with approved change records and directory-change audit/SACL coverage. Weak encryption or unexpected delegation is a review signal, not standalone proof of an attack. Protect KDC/admin authority and service-account lifecycle first; thresholds alone cannot repair a trust failure.

## Labs

### Environment and Complete Files

Create an empty `kerberos-security-offline` directory with the one file below. Python 3.12 standard library only; fixtures embedded. No AD/KDC, packages, network, real credentials, ticket bytes/keys or elevation. This compares a declared defensive posture against assumed authentication metadata. It neither creates nor validates tickets/PACs, and its combined admission predicate is a teaching contract rather than a native Windows algorithm. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Context:
	authenticated: bool = True
	pac_validated: bool = True
	preauth_required: bool = True
	managed_service_secret: bool = True
	aes_keys_available: bool = True
	ticket_etype: int = 18
	session_etype: int = 18
	spn: str = "HTTP/inventory.example.invalid"
	realm: str = "EXAMPLE.INVALID"
	operation: str = "read-inventory"
	delegated: bool = False
	nondelegable_user: bool = False
	downstream: str = "HTTP/reports.example.invalid"


def baseline(context):
	return context.authenticated


def hardened(context):
	if not all((context.authenticated, context.pac_validated,
				context.preauth_required, context.managed_service_secret,
				context.aes_keys_available)):
		return False
	if context.ticket_etype not in {17, 18} or context.session_etype not in {17, 18}:
		return False
	if (context.spn, context.realm) != (
			"HTTP/inventory.example.invalid", "EXAMPLE.INVALID"):
		return False
	if context.operation != "read-inventory":
		return False
	if context.delegated:
		return (not context.nondelegable_user
				and context.downstream == "HTTP/reports.example.invalid")
	return True


class ExampleTests(unittest.TestCase):
	def test_allowed_operation_survives(self):
		self.assertTrue(baseline(Context()))
		self.assertTrue(hardened(Context()))
		self.assertTrue(hardened(replace(Context(), nondelegable_user=True)))

	def test_identity_validation_and_account_posture(self):
		for field in ("authenticated", "pac_validated", "preauth_required",
					  "managed_service_secret", "aes_keys_available"):
			with self.subTest(field=field):
				self.assertFalse(hardened(replace(Context(), **{field: False})))

	def test_ticket_and_session_algorithms(self):
		for changes in ({"ticket_etype": 23}, {"session_etype": 23},
						{"ticket_etype": 0}):
			context = replace(Context(), **changes)
			self.assertTrue(baseline(context))
			self.assertFalse(hardened(context))

	def test_service_trust_and_authorization(self):
		for changes in ({"spn": "HTTP/other.example.invalid"},
						{"realm": "OTHER.INVALID"}, {"operation": "write-inventory"}):
			context = replace(Context(), **changes)
			self.assertTrue(baseline(context))
			self.assertFalse(hardened(context))

	def test_delegation_policy(self):
		delegated = replace(Context(), delegated=True)
		self.assertTrue(hardened(delegated))
		self.assertFalse(hardened(replace(delegated, nondelegable_user=True)))
		self.assertFalse(hardened(replace(delegated,
										 downstream="HTTP/other.example.invalid")))


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Confirm `python --version` is 3.12 and run `python -m unittest -v test_example` from the directory (`py -3.12` can replace `python`). No authentication attempt is made.
2. Explain why authenticated synthetic metadata can fail posture, service/realm or operation checks. Explain why a nondelegable identity can still perform the permitted direct read.
3. Temporarily remove `not context.nondelegable_user and` from the delegation return expression, retaining parentheses. Rerun to detect the nondelegable-user regression; restore and rerun.

### Hints

Delegation is a specific added authority, not a requirement for every service operation. Ticket and session encryption must be assessed separately. `managed_service_secret` is this lab's declared profile, not a claim that Kerberos rejects every non-gMSA service.

### Solution and Fixed Retest

Five tests should pass. The baseline admits any authenticated record. The fixed profile additionally checks assumed PAC validation, account posture, available AES keys, both algorithms, service/realm and operation. Its one declared delegated route remains allowed only for a delegable identity; direct reads by nondelegable users remain permitted. The temporary defect fails the delegation test. No returned boolean proves actual key possession, trust validation or a verified PAC.

### Verification, Troubleshooting, and Cleanup

Acceptance: five tests pass after restoration, nondelegable regression detected and direct permitted operation preserved. Import/syntax errors are local fixture issues, not Kerberos errors. Delete the directory and cache. Optional AD changes are separate, unverified work requiring snapshot rollback; no secrets or tickets were produced by this exercise.

### Retained Study Checklist

- [ ] Local Kerberos exercise: In a disposable AD lab, access a service by its proper hostname/SPN and inspect ticket metadata with supported tools. Compare an intentional SPN mismatch and time/configuration failure.
- [ ] Boundary check: Verify synthetic privileged users cannot be delegated where policy forbids it and that service accounts use managed/strong secrets and expected SPNs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[Kerberos]]

## References

- [Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [MS-KILE protocol extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)
- [MS-PAC validation and authorization data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/)
- [Group managed service accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Event 4769 and encryption fields](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
