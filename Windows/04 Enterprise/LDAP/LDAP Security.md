---
title: "LDAP Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[LDAP]]"
updated: 2026-11-03
---
# LDAP Security

> [!abstract] TL;DR
> Keep user text out of filter structure, protect the bind/channel, and authorize each directory operation. Signing, TLS and channel binding protect different boundaries; none repairs excessive directory rights.

> [!info] Agent scope
> Security of: Directory tree; distinguished names; searches; filters; binds; TLS; signing and channel binding; authorization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Filter values versus syntax, DNs versus filter strings, connection-pool identity, referrals, bind mode, TLS validation, SASL signing/sealing, CBT and object/attribute permissions.
- Untrusted query structure requires an application that concatenates uncontrolled input. Network authentication risks require a relevant network/identity context and missing binding protections. Directory changes require actual write/extended rights. Exercises only use harmless names and declared policy facts.

## Learn

```text
Teach defensive LDAP security at expert depth. Assume LDAPv3 search/bind, TLS
and AD ACLs. Explain assertion-value versus DN escaping, schema/attribute
allowlists, connection identity reuse, empty-password binds, referrals, partial
results, simple versus SASL bind, signing/sealing, TLS validation and CBT.
Distinguish directory object/attribute authorization from protected transport.
Explain root causes and threat prerequisites conceptually, with no credential
theft, relay, exploitation, bypass or privilege-escalation procedures. Use
literal synthetic names and read-only diagnosis. Provide exact lab-only policy
semantics, version/default distinctions, relevant events and false positives.
Supply a complete Python 3.12 stdlib offline baseline/fix/retest lab preserving
allowed reads and rejecting unwanted changes; label it as a model, not LDAP
or cryptographic enforcement. Use RFC and Microsoft primary sources. No real
credentials, directory targets, invented execution, file edits or status changes.
Finish with difficult worked failure-stage questions.
```

## Cheatsheet

### Query and Identity Boundaries

Literal `Iris*(Lab)` must render as `(cn=Iris\2a\28Lab\29)` in RFC4515 syntax. A safe filter value encoder does not validate `cn`, base DN, matching-rule OID, scope or referral targets. Keep those structural choices fixed/allowlisted. RFC4514 DN escaping is different; use the directory library's DN constructor, not the filter escape function. Avoid raw interpolation into filter syntax, and do not invent a home-grown LDAP parser for a real application.

Reject missing/empty passwords at application validation before any password-based bind. LDAP has anonymous and unauthenticated bind cases; a successful bind response does not always prove a supplied user's password. Reset pooled connection identity and protection state deliberately. A referral is another destination: validate ownership/trust and credential-forwarding policy before following it. Search limits may return partial entries; require the terminal result code and an explicit completeness decision.

### Protection Matrix

| Session | Integrity/confidentiality | Channel-binding relevance |
|---|---|---|
| Simple bind, no TLS | Password has no LDAP-layer confidentiality; unacceptable | CBT does not repair it. |
| Simple bind, validated TLS | TLS protects credentials and operations | Not the SASL CBT case; do not require a fictitious simple-bind CBT. |
| SASL, no TLS, signing | Integrity only | TLS CBT is inapplicable; confidentiality needs sealing or TLS. |
| SASL, no TLS, sealing | SASL confidentiality plus integrity | Authentication mechanism must establish intended peer identity. |
| SASL over validated TLS | TLS confidentiality/integrity | Supported CBT binds SASL authentication to the TLS channel; enforce appropriate policy and client support. |

Signing required on a DC rejects unsigned non-TLS SASL and clear simple binds, but accepts qualifying TLS sessions. `When supported` channel binding is not equivalent to `Always`: compatibility allowance for missing tokens differs from validation of supplied tokens. CBT policy does not repair a client accepting an untrusted TLS certificate or an over-permitted directory account. A TLS-terminating intermediary can affect channel binding; review supported architecture rather than turning off enforcement.

### Exact Lab-only Policy and Read-only Checks

Only on a separate owned snapshot-backed AD lab, never a production DC. Required offline exercise needs none of this. Under `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`:

| Policy | Strict lab setting | Effect |
|---|---|---|
| Domain controller: LDAP server signing requirements | Require signing | Require protected LDAP sessions according to bind/transport semantics above. |
| Network security: LDAP client signing requirements | Require signing | Windows LDAP clients must request/require appropriate integrity; third-party APIs need separate configuration. |
| Domain controller: LDAP server channel binding token requirements | Always | Require applicable SASL-over-TLS clients to provide valid CBT; audit compatibility first. |

Server 2025 adds "Domain controller: LDAP server signing requirements enforcement"; enabled on new deployments, it takes precedence over the signing-level setting. Upgraded policy and installed updates matter. Historical registry levels: `LDAPServerIntegrity` 1/2 = none/require; `LDAPClientIntegrity` 0/1/2 = none/negotiate/require; `LdapEnforceChannelBinding` 0/1/2 = never/when supported/always. Missing values require default/effective-policy analysis, not an automatic zero. These examples are documented but runtime-unverified here.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' | Select-Object LDAPServerIntegrity,LdapEnforceChannelBinding
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' | Select-Object LDAPClientIntegrity
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' | Select-Object '16 LDAP Interface Events'
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=2886,2887,2888,2889,3039,3040,3041,3074,3075} -MaxEvents 30
```

These are local observations, no bind or discovery query. DC-only keys/logs are absent on ordinary clients. Use snapshots to restore optional policy changes; do not guess original values or disable controls to clear an application error.

### Authorization and Errors

Directory authorization is per object, property/property set and extended right, with inheritance and identity groups. A read-only service account should not have unnecessary object creation, attribute modification or privileged extended rights. An attribute projection is data minimization, not an ACL. Result 49 is a bind failure; 50 is insufficient access; 8/13 indicate stronger authentication/confidentiality requirements; 3/4 indicate partial-result limits. Keep detailed diagnostic strings out of user-visible errors.

## Detection and Defense

Directory Service 2886 warns about permissive signing; 2887 summarizes permitted unsigned/clear binds; 2888 summarizes rejected attempts. Per-client 2889 requires diagnostic category "16 LDAP Interface Events" at level 2; without it, absence of details is inconclusive. Channel-binding events 3039-3041 and newer 3074/3075 depend on update/policy context. Interpret the event message and build, not only an ID. Temporary detailed diagnostics can increase volume and expose identities; scope, protect and revert them.

Security 5136 requires Directory Service Changes auditing and suitable object SACLs; it helps identify directory modifications, not every LDAP read. Legitimate synchronization, inventory and certificate/account lifecycle jobs can generate changes. Correlate subject, object, attribute, time and change approval. Never collect production account values for this exercise.

## Labs

### Environment and Complete Files

Use an empty `ldap-security-offline` directory, one file below, Python 3.12 stdlib only. Seeds embedded; no LDAP server, AD, network, packages, credentials or elevation. The model accepts trusted synthetic protection facts; no bind, TLS, CBT or ACL enforcement is implemented. Baseline is only a local predicate. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Request:
	authenticated: bool = True
	bind: str = "sasl"
	tls: bool = True
	peer_verified: bool = True
	signed: bool = False
	sealed: bool = False
	cbt_valid: bool = True
	operation: str = "read"
	attribute: str = "displayName"


def baseline(request):
	return request.authenticated


def hardened(request):
	if not request.authenticated or not request.peer_verified:
		return False
	if request.bind not in {"simple", "sasl"}:
		return False
	if request.bind == "simple" and not request.tls:
		return False
	if not request.tls and not (request.bind == "sasl" and request.sealed):
		return False
	if request.bind == "sasl" and request.tls and not request.cbt_valid:
		return False
	return request.operation == "read" and request.attribute == "displayName"


def literal_filter(value):
	escaped = "".join(f"\\{octet:02x}" if octet in (0, 40, 41, 42, 92)
					  or octet >= 128 else chr(octet)
					  for octet in value.encode("utf-8"))
	return f"(cn={escaped})"


class ExampleTests(unittest.TestCase):
	def test_allowed_read_and_literal(self):
		self.assertTrue(hardened(Request()))
		self.assertEqual(literal_filter("Iris*(Lab)"), r"(cn=Iris\2a\28Lab\29)")

	def test_transport_profiles(self):
		self.assertTrue(hardened(replace(Request(), bind="simple", cbt_valid=False)))
		self.assertTrue(hardened(replace(Request(), tls=False, sealed=True)))
		for request in (replace(Request(), bind="simple", tls=False),
						replace(Request(), tls=False, signed=True)):
			self.assertTrue(baseline(request))
			self.assertFalse(hardened(request))

	def test_binding_and_peer(self):
		for field in ("cbt_valid", "peer_verified"):
			request = replace(Request(), **{field: False})
			self.assertTrue(baseline(request))
			self.assertFalse(hardened(request))

	def test_directory_rights(self):
		for request in (replace(Request(), operation="modify"),
						replace(Request(), attribute="restrictedSyntheticAttribute")):
			self.assertTrue(baseline(request))
			self.assertFalse(hardened(request))

	def test_identity_required(self):
		self.assertFalse(hardened(replace(Request(), authenticated=False)))
		self.assertFalse(hardened(replace(Request(), bind="anonymous")))


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Check `python --version` is 3.12 and run `python -m unittest -v test_example` from the directory (`py -3.12` is an alternative launcher).
2. Explain why signed-only SASL fails this lab's confidential-directory profile, while sealed SASL without TLS passes. Why is simple-over-TLS not subjected to a fictitious SASL CBT requirement?
3. Temporarily replace the final authorization predicate in `hardened` with `return True`; rerun to detect unauthorized synthetic modification/attribute reads. Restore and rerun.

### Hints

This profile requires confidentiality, which is stricter than integrity-only LDAP signing. Transport protection never supplies directory rights. The fixed filter uses a constant attribute and operator; it does not accept caller-controlled filter structure.

### Solution and Fixed Retest

Five tests should pass. Baseline authenticated requests can still be unprotected or over-authorized. The fix requires a recognized authenticated bind, intended peer, confidentiality, applicable SASL CBT, and the one permitted read/attribute. Simple-over-TLS and sealed SASL are accepted under the stated model; a signed-only session is not confidential. The temporary authorization removal fails the directory-rights test while the permitted read remains valid after restoration.

### Verification, Troubleshooting, and Cleanup

Acceptance: five tests pass after restoration, failed regression observed, and no claim that these booleans validate actual TLS/CBT. Wrong directory/filename causes imports to fail. No AD logs should be produced. Delete the directory and cache; optional AD policy work is separate, unverified and requires snapshot rollback.

### Retained Study Checklist

- [ ] Local LDAP exercise: Query a disposable directory for synthetic users with a narrow search base and limited account. Test filter escaping and a denied attribute modification.
- [ ] Boundary check: Submit a harmless filter-metacharacter name through a safe query builder and verify literal matching; confirm unauthorized modifications fail.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[LDAP]]

## References

- [LDAP signing overview and defaults](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [LDAP channel binding for AD DS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
- [Enable LDAP signing and diagnostic events](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- [RFC4513 LDAP authentication](https://www.rfc-editor.org/rfc/rfc4513)
- [RFC4515 filter encoding](https://www.rfc-editor.org/rfc/rfc4515)
- [Event 5136](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)
