---
title: "Kerberos"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[Kerberos Security]]"
updated: 2026-11-03
---
# Kerberos

> [!abstract] TL;DR
> A KDC issues a TGT for later ticket requests and service tickets for particular service principals. The service validates the presented authentication context, then separately authorizes operations. Names, keys, time, trust and delegation policy are independent failure points.

> [!info] Agent scope
> KDC; principals and SPNs; TGT and service tickets; preauthentication; PAC; delegation; trust and time.

## Prerequisites

- Symmetric keys, authentication versus authorization, DNS names, Windows identities and UTC time. No cryptographic implementation is required.
- Required exercise: Python 3.12 standard library only, synthetic metadata. No domain, KDC, tickets, secrets, packages, network or elevated permissions.

## Learn

```text
Teach Kerberos V5 and Windows KILE at expert protocol and operational depth.
Assume symmetric cryptography, Windows identities, DNS and UTC. Trace AS-REQ/
AS-REP, preauthentication negotiation, TGT, TGS-REQ/TGS-REP, service ticket,
AP-REQ/AP-REP, authenticator freshness, replay detection and session protection.
Explain principal/realm/SPN mapping, key ownership, kvno, ticket versus session
encryption types, lifetime versus renewable window, PAC validation and final
service authorization. Compare password preauthentication, PKINIT, FAST,
referrals/trust direction, selective authentication, delegation and protected
identities at a conceptual level. Give exact read-only metadata observations,
error-code diagnosis, current Windows version caveats and a complete Python
3.12 stdlib offline metadata exercise with tests. No ticket generation/export,
forgery, roasting, credentials, relay, movement, privilege escalation or bypass
procedures. Label the model as not a Kerberos or PAC validator. Use RFC4120,
MS-KILE/MS-PAC and Microsoft public sources. No production targets, fabricated
results, file edits or study-status changes. End with worked hard questions.
```

## Cheatsheet

### Exchanges and Key Ownership

| Exchange | Inputs and outputs | Who can interpret protected material? |
|---|---|---|
| AS-REQ / AS-REP | Client principal/realm, requested etypes, nonce, times, options and preauthentication; returns TGT and client-TGS session key | TGT is protected for `krbtgt`/KDC. Client receives its session key in a separately protected reply part. |
| TGS-REQ / TGS-REP | TGT plus authenticator, requested service principal and options; returns service ticket and client-service session key | Service ticket is protected with the target service account's key; reply key material is protected for the client using the established TGS context/subkey. |
| AP-REQ | Service ticket plus fresh authenticator, optional flags/subkey | Service uses its key to read the ticket, then the ticket's session key to validate the authenticator and bind the client identity. |
| AP-REP | Mutual-authentication reply when requested | Demonstrates possession of the session context; the client must verify it, not just assume mutual authentication occurred. |

The KDC runs on AD DCs and combines authentication service and ticket-granting service roles. TCP/UDP 88 carry Kerberos; TCP framing includes a length prefix. Larger tickets/PACs can require TCP. DNS/KDC discovery, domain membership and time services are dependencies, not part of the AP exchange itself.

Preauthentication demonstrates possession of an appropriate credential before normal TGT issuance. An initial `KDC_ERR_PREAUTH_REQUIRED` can be normal negotiation, not a bad password. Password-based encrypted timestamp preauthentication, PKINIT public-key/certificate mechanisms and FAST armoring have different prerequisites. FAST protects applicable KDC exchanges; it does not replace account policy, trusted certificates or application authorization.

### Names, Metadata and Authorization

| Field/concept | Interpretation |
|---|---|
| Client principal and realm | Identity and issuing namespace; a display name is not an immutable security identifier. |
| SPN / service principal | Such as `HTTP/inventory.example.invalid` or `cifs/files.example.invalid`; maps to the account whose key the service uses. Aliases require correct ownership/mapping, not just DNS reachability. |
| `kvno` | Key version helps select an available service key after rotation; it is not an encryption algorithm. |
| Ticket `etype` | Algorithm protecting the encrypted ticket part for the service/KDC. |
| Session key `etype` | Algorithm of the client-service or client-TGS session key; can differ from ticket encryption type. |
| authtime/starttime/endtime | Original authentication time, validity start, expiration. Renewal does not imply a fresh password authentication. |
| renew-till / renewable | Bounds a KDC-mediated renewal opportunity; an expired ticket cannot simply be treated as valid because renew-till is later. |
| forwardable / forwarded / ok-as-delegate | Different flags, not a blanket authorization to delegate any user to any service. |
| PAC | Windows authorization data: identity/group information and other buffers plus validation signatures. Not a signed command to grant every requested operation. |

The service must validate the security context and applicable PAC signatures through supported Windows mechanisms, then perform its own access checks. PAC checks and KDC consultation depend on implementation, role and updates; do not treat an unverified decoded PAC as an access token. A token/service session can outlive a ticket cache entry; disabling an account or changing groups is not an instant universal revocation mechanism for already-established sessions.

### Trust, Delegation and Time

Cross-realm referrals allow a client to obtain a ticket through a configured trust path, not through arbitrary realm strings. Trust direction, transitivity, selective authentication, SID filtering and resource ACLs each matter. "A trusts B" means A can accept identities from B subject to policy; it does not grant those identities all A resources.

Unconstrained delegation permits broad reuse of delegated context and has a large trust surface. Classic constrained delegation restricts allowed downstream SPNs on the front-end identity; resource-based constrained delegation expresses allowed front-end principals on the resource side. S4U2Self and S4U2Proxy serve protocol-transition/delegated-service roles under KDC policy. None should be inferred solely from `forwardable=True`; sensitive/nondelegable users and policy can prohibit delegation. No delegation configuration or ticket manipulation exercise is supplied here.

Clocks must agree within effective policy. The common Windows default tolerance is five minutes, not a reason to run clocks deliberately skewed. Ticket lifetime and authenticator freshness are different checks. Replay detection tracks previously used authenticators in the relevant service context; an authenticated timestamp is not sufficient without replay handling. Applications must use supported SSPI/GSS mechanisms, not implement their own ticket acceptance.

### Read-only Observations and Failure Diagnosis

On an owned disposable domain lab client, these first commands inspect only the current cache/time configuration. They do not request, export, purge or inject tickets. Output can identify users/services, so keep it inside the lab. Runtime unverified.

```powershell
klist
w32tm /query /status
w32tm /query /configuration
```

Optional bounded SPN lookup in that isolated lab only: `setspn -Q HTTP/inventory.example.invalid`. It queries directory metadata and requires domain connectivity/read access; it does not register or repair anything. No match is expected unless that synthetic service was already configured. Never replace the name with a production target for this exercise.

| Error (hex) | Stage and discriminating check |
|---|---|
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` (0x7) | Requested SPN not resolved; inspect exact service name/realm. |
| `KDC_ERR_PRINCIPAL_NOT_UNIQUE` (0x8) | Ambiguous principal mapping; fix registration ownership through approved administration. |
| `KDC_ERR_ETYPE_NOTSUPP` (0xE) | No compatible usable key/etype set; policy, advertised support and actual available keys differ. |
| `KDC_ERR_PREAUTH_FAILED` (0x18) | Credential/preauthentication validation failed. |
| `KDC_ERR_PREAUTH_REQUIRED` (0x19) | Often normal initial negotiation. |
| `KRB_AP_ERR_TKT_EXPIRED` (0x20) / `TKT_NYV` (0x21) | Validity/time issue; renewable is not currently valid. |
| `KRB_AP_ERR_REPEAT` (0x22) / `SKEW` (0x25) | Replay/freshness or time-sync issue. Diagnose without replaying captured traffic. |
| `KRB_AP_ERR_MODIFIED` (0x29) | Frequently wrong service key/SPN ownership, stale keys or wrong destination; not automatically malicious tampering. |

AES128/AES256 classic Windows Kerberos etypes are decimal 17/18 (`0x11`/`0x12`); RC4-HMAC is decimal 23 (`0x17`). Do not confuse these IDs with `msDS-SupportedEncryptionTypes`, which is a bitmask. Server 2025 no longer honors the legacy Kerberos `SupportedEncryptionTypes` registry setting documented by Microsoft; use supported Group Policy. Updated Server 2016+ 4769 schemas after January 2025 updates can include session-key type, supported types and available keys; parse by event version/field name, not positional indices.

## Gotchas

A TGT is for requesting tickets, not direct application access. A service ticket alone is not a complete fresh AP authentication. Ticket renewal, current ticket validity and the lifetime of an already-created application session are distinct.

## Labs

### Environment and Complete Files

Create an empty `kerberos-tech-offline` directory with this single file. Python 3.12 standard library only; seed metadata embedded. No KDC, AD, network, packages, tickets, keys, responses, credentials or admin rights. Records are fictional observations, not serialized tickets, and cannot authenticate anywhere. Cryptographic/PAC verification is intentionally absent. Timing and equality rules are simplified lab policy, not full RFC acceptance semantics. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Metadata:
	service: str = "HTTP/inventory.example.invalid"
	realm: str = "EXAMPLE.INVALID"
	start: int = 1000
	end: int = 2000
	renew_until: int = 5000
	key_version: int = 4
	authenticator_second: int = 1500
	observation_id: str = "synthetic-observation-1"


def diagnose(metadata, now, seen, service="HTTP/inventory.example.invalid",
			 realm="EXAMPLE.INVALID", available_key_versions=(4,)):
	if metadata.service != service or metadata.realm != realm:
		return "wrong-service-or-realm"
	if metadata.key_version not in available_key_versions:
		return "service-key-version-unavailable"
	if not metadata.start <= now < metadata.end:
		return "outside-ticket-validity"
	if abs(now - metadata.authenticator_second) > 300:
		return "authenticator-outside-skew"
	marker = (metadata.service, metadata.realm, metadata.observation_id)
	if marker in seen:
		return "duplicate-observation"
	seen.add(marker)
	return "metadata-checks-only"


class ExampleTests(unittest.TestCase):
	def test_expected_metadata(self):
		self.assertEqual(diagnose(Metadata(), 1500, set()), "metadata-checks-only")

	def test_service_realm_and_key(self):
		for metadata in (replace(Metadata(), service="cifs/files.example.invalid"),
						 replace(Metadata(), realm="OTHER.INVALID")):
			self.assertEqual(diagnose(metadata, 1500, set()), "wrong-service-or-realm")
		self.assertEqual(diagnose(replace(Metadata(), key_version=3), 1500, set()),
						 "service-key-version-unavailable")

	def test_validity_not_renewal_window(self):
		for now in (999, 2000, 4000):
			self.assertEqual(diagnose(Metadata(), now, set()), "outside-ticket-validity")

	def test_authenticator_freshness(self):
		self.assertEqual(diagnose(replace(Metadata(), authenticator_second=1199),
								  1500, set()), "authenticator-outside-skew")
		self.assertEqual(diagnose(replace(Metadata(), authenticator_second=1200),
								  1500, set()), "metadata-checks-only")

	def test_duplicate_observation(self):
		seen = set()
		self.assertEqual(diagnose(Metadata(), 1500, seen), "metadata-checks-only")
		self.assertEqual(diagnose(Metadata(), 1500, seen), "duplicate-observation")
		self.assertEqual(diagnose(replace(Metadata(), observation_id="synthetic-2"),
								  1500, seen), "metadata-checks-only")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Confirm `python --version` is 3.12 and run `python -m unittest -v test_example` in the fixture directory (`py -3.12` can replace `python`). No system clock changes.
2. Explain why time 4000 is rejected despite `renew_until=5000`. Separate the lifetime failure from authenticator skew.
3. Temporarily change the validity predicate to use `metadata.renew_until` instead of `metadata.end`; rerun and inspect the failing validity test. Restore and rerun.

### Hints

Renewal requires a KDC exchange and policy; it does not extend an existing ticket's acceptance window by itself. The duplicate marker is an educational log identifier, not a real Kerberos replay-cache key.

### Solution and Expected Results

Five tests should pass. Service/realm and available key version are checked separately from validity and freshness. A previously observed synthetic marker is flagged, while a new one passes only these metadata checks. Changing expiry to renewal breaks the expected validity diagnostics. `metadata-checks-only` deliberately avoids claiming a valid ticket, PAC, authenticator or authorized application operation.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoring expiry logic and correct explanation of renewal/skew/authorization differences. A missing module means the wrong directory/file; system time cannot affect these fixed integers. Delete the directory/cache; no live cache, key or system policy was altered.

### Retained Study Checklist

- [ ] Local Kerberos exercise: In a disposable AD lab, access a service by its proper hostname/SPN and inspect ticket metadata with supported tools. Compare an intentional SPN mismatch and time/configuration failure.
- [ ] Boundary check: Verify synthetic privileged users cannot be delegated where policy forbids it and that service accounts use managed/strong secrets and expected SPNs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[Kerberos Security]]

## References

- [RFC4120 Kerberos V5](https://www.rfc-editor.org/rfc/rfc4120)
- [MS-KILE Windows Kerberos extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)
- [MS-PAC authorization data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/)
- [Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [klist command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)
- [Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
