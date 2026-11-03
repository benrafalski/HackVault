---
title: "DNS Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[DNS]]"
updated: 2026-11-03
---
# DNS Security

> [!abstract] TL;DR
> Protect the registration/delegation plane, the authoritative publishing plane, and the recursive validation plane separately. Encrypted DNS protects a transport hop; it does not repair bad zone data or authorize a DNS update.

## Attack Surface

Registrar accounts control delegation; DNS-provider accounts control records; application hosting accounts control the destinations those records reference. These are separate ownership relationships. A dangling CNAME can outlive a decommissioned service. Recursion, authoritative queries, transfers, and dynamic updates are different operations with different ACLs.

## Learn

```text
Teach me DNS defense assuming record types and recursive resolution. Trace
registrar-to-parent delegation, authoritative publication, recursive caching,
and the stub-resolver channel. Explain open-recursion risk without generating
traffic, cache validation, DNSSEC secure/insecure/bogus states, negative TTL,
key rollover and clock failure, DoH/DoT identity and privacy, split DNS, and
dangling service inventory. Give least-privilege BIND configuration fragments
and an offline synthetic policy lab for update, transfer, recursion and record
ownership. Establish unsafe baselines as data only, then fix and retest them.
Do not scan, spoof, poison, transfer third-party zones, or claim a policy model
proves wire behavior. Include monitoring, false positives and primary sources.
Teach here without file edits; finish with worked incident-triage questions.
```

## Cheatsheet

### Trust Boundaries and Failure Modes

| Boundary | Failure prerequisite | Control and evidence |
|---|---|---|
| Registrar / parent NS and DS | Unauthorized account or mistaken change | MFA, scoped roles, change approval, delegation/DS audit |
| Authoritative zone | Broad API token or dynamic update key | Zone-scoped permissions; audit serial, actor, old/new RRset |
| Zone transfer | AXFR/IXFR permitted to unintended clients | Explicit secondary identity/ACL; monitor transfer requests |
| Recursive service | Unrestricted recursion/cache access | Approved client networks; separate public authoritative service |
| Cache acceptance | Unvalidated/misassociated upstream answer | Maintained resolver with DNSSEC validation, bailiwick and response matching |
| CNAME to hosted service | DNS record survives resource deletion | Remove DNS before release; reconcile record/resource ownership |
| Stub to resolver | Untrusted transport or endpoint | Authenticated DoT/DoH where policy permits; known resolver |

DNSSEC verifies RRsets and authenticated absence through a trust chain. It does not stop an authorized publisher from signing bad data. An unsigned but correctly delegated branch is `insecure`, not automatically `bogus`. A wrong DS, expired signature, or incorrect clock can make signed data bogus and produce SERVFAIL. Do not treat disabling validation as the permanent remedy; inspect the chain and fix the signer/delegation. Query logs can reveal sensitive user behavior, so minimize retention and access.

### Concrete Configuration

BIND 9.18/9.20-style fragments for review, not a complete server deployment. A dedicated public authoritative server normally has recursion off; it still answers its zones. A private recursive server instead needs a deliberate client ACL. Check the installed version's ARM and distribution patches before deployment.

```text
options {
	recursion no;
	allow-transfer { none; };
};
zone "example.test" {
	type primary;
	file "example.test.zone";
	allow-update { none; };
	allow-transfer { none; };
};
```

For a separate private recursive role, this is the relevant options fragment:

```text
acl lab_clients { 127.0.0.1; ::1; };
options {
	listen-on { 127.0.0.1; };
	listen-on-v6 { ::1; };
	recursion yes;
	allow-recursion { lab_clients; };
	allow-query-cache { lab_clients; };
	allow-transfer { none; };
	dnssec-validation auto;
};
```

Do not combine the two `options` blocks. TSIG can authenticate server-to-server messages and update principals; it is not encryption or DNSSEC. Use narrowly scoped update policies if updates are required, not an unrestricted shared key. Generate and store actual keys outside notes and repositories. DNS record data in TXT is public unless served in a genuinely private view; never use TXT as secret storage.

### Response and Transport Policy

| Signal | Interpretation | Defensive action |
|---|---|---|
| AD bit from authenticated validating resolver | Resolver asserts validated data | Preserve endpoint trust; distinguish from local validation |
| `dig +dnssec` prints RRSIG | Signatures supplied, not necessarily verified | Use resolver validation telemetry |
| SERVFAIL after DS change | Possible chain mismatch; also other causes | Compare parent DS, child DNSKEY and timestamps |
| DoH success but private name fails | Public resolver may not know private view | Keep enterprise split-DNS policy; do not silently leak names |
| Repeated old answer after edit | TTL, negative cache, stale serving, app cache | Record each cache layer and expiry before concluding tampering |

## Detection and Defense

Alert on unexpected NS/DS/MX/CAA changes, signing expiry, validation-failure increases, unknown update actors, and retired service targets. Compare against approved inventory, not merely yesterday's answer. CDN rotation, planned rollover, and split views can legitimately change answers. Record TTL and view when comparing. Stage rollovers with overlap and parent coordination; TTL controls cache duration, not instantaneous propagation.

## Labs

### Environment and Complete Files

Python 3.12+, standard library only; no DNS queries, servers or credentials. All strings below are synthetic. This is a policy and inventory test, not a DNSSEC implementation or a claim that a real server denies operations.

### File: test_example.py

```python
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
	recursive_clients: frozenset
	transfer_clients: frozenset
	update_principals: frozenset

	def allows(self, operation, identity):
		allowed = {"recurse": self.recursive_clients,
				   "transfer": self.transfer_clients,
				   "update": self.update_principals}.get(operation, frozenset())
		return identity in allowed or "*" in allowed


def answer_acceptable(validation, authenticated_resolver):
	return authenticated_resolver and validation in {"secure", "insecure"}


def dangling(records, owned_services):
	return {name for name, target in records.items() if target not in owned_services}


class DNSPolicyTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		baseline = Policy(frozenset({"*"}), frozenset({"*"}), frozenset({"*"}))
		fixed = Policy(frozenset({"lab-stub"}), frozenset({"secondary-a"}),
					   frozenset({"zone-publisher"}))
		for operation, permitted in (("recurse", "lab-stub"),
									 ("transfer", "secondary-a"),
									 ("update", "zone-publisher")):
			with self.subTest(operation=operation):
				self.assertTrue(baseline.allows(operation, "unlisted"))
				self.assertFalse(fixed.allows(operation, "unlisted"))
				self.assertTrue(fixed.allows(operation, permitted))
		self.assertFalse(fixed.allows("unknown", "zone-publisher"))

	def test_validation_contract(self):
		self.assertTrue(answer_acceptable("secure", True))
		self.assertTrue(answer_acceptable("insecure", True))
		self.assertFalse(answer_acceptable("bogus", True))
		self.assertFalse(answer_acceptable("indeterminate", True))
		self.assertFalse(answer_acceptable("secure", False))

	def test_retirement(self):
		records = {"live.example.test": "service-a", "old.example.test": "service-b"}
		self.assertEqual(dangling(records, {"service-a"}), {"old.example.test"})
		del records["old.example.test"]
		self.assertEqual(dangling(records, {"service-a"}), set())


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run `python -m unittest -v test_example`. The baseline explicitly demonstrates overbroad authorization in data, without issuing a DNS operation.
2. Explain why `secondary-a` must not inherit `zone-publisher` update permission. Add a negative assertion for this separation.
3. Temporarily replace the fixed recursion set with `{"*"}`; confirm the same negative check fails, then restore it.
4. Identify and remove only the retired CNAME inventory entry, preserving the active service.

### Hints

The string `secure` is an input label from a hypothetical validator, not proof by itself. A stronger application policy can require signed names; ordinary DNSSEC deployment still permits legitimate unsigned delegations.

### Solution and Fixed Retest

The baseline authorizes every listed operation for `unlisted`. The fixed policy denies it while preserving each designated principal. A bogus result fails even over encrypted transport. `old.example.test` is the only inventory mismatch; removing it leaves an empty finding set. Expected: three tests pass, and the wildcard mutation fails `test_baseline_and_fix`.

### Verification, Troubleshooting, and Cleanup

Author execution was prohibited. `python -m pytest -q test_example.py` also works if pytest is installed. No package installation is necessary for unittest. An actual rollout still needs configuration syntax checks, authorized client tests, and resolver validation telemetry; this fixture cannot certify them. Delete the disposable directory; there are no keys, zones, or listeners to revoke.

- [ ] Explain separate recursion, transfer, and update authorizations.
- [ ] Record baseline/fixed policy results and retained permitted behavior.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[DNS]]

## References

- [BIND 9 Administrator Reference Manual](https://bind9.readthedocs.io/en/stable/)
- [DNSSEC protocol modifications, RFC 4035](https://www.rfc-editor.org/rfc/rfc4035)
- [DNS over TLS, RFC 7858](https://www.rfc-editor.org/rfc/rfc7858)
- [TSIG, RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
