---
title: "Recon and Subdomain Enumeration"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Recon and Subdomain Enumeration

> [!abstract] TL;DR
> Track asset, evidence, owner, scope, resolver result, service identity, and next hypothesis. Discovery is not exploitation authorization.

> [!info] Agent scope
> Written scope; passive versus active discovery; DNS and certificate sources; asset validation; rate limits; evidence organization.

## Prerequisites

- DNS records, TLS certificate names, HTTP origins, and written assessment authorization; [[Web Lab Setup]].
- Lab: Python 3.12 standard library only. All names, addresses, owners, and timestamps below are synthetic. No DNS resolver, browser, account, network access, or external dataset is needed.

## Learn

```text
Teach me evidence-driven web asset reconnaissance and subdomain inventory at
expert depth. Assume I understand DNS records, TLS, HTTP origins, and Python.
Separate authorization, ownership, observed resolution, and service identity.
Explain written inclusions/exclusions, certificate SANs and wildcard names,
CT provenance and historical records, passive-DNS timestamps, NXDOMAIN versus
NODATA versus resolver failure, CNAME delegation, shared hosting, wildcard DNS,
split-horizon results, TTL, and conflicting evidence. Work through an OFFLINE
synthetic inventory with duplicate and stale observations and an explicit
third-party exclusion. Show normalization, provenance-preserving deduplication,
confidence decisions, and regression tests in Python 3.12 standard library.
Explain what each source proves and cannot prove, how to set request budgets
and stop conditions in an authorized engagement, and how to organize and redact
evidence. Do not query or scan live targets, enumerate public services, claim
resources, provide exploitation instructions, or infer permission from a name.
Use public primary sources; distinguish CT protocol specifications from actual
deployment versions. Finish with difficult inventory decisions and worked
answers. Teach in this conversation without editing files or study status.
```

## Cheatsheet

### Four Independent Questions

1. **Authorized?** The signed scope names an origin/resource and an allowed activity during a valid window. A wildcard inclusion does not override an exclusion. Preserve the exact policy revision.
2. **Owned or administered?** An owner inventory is stronger than branding. A CNAME often denotes a supplier boundary; the supplier's infrastructure is not implicitly authorized.
3. **Observed when and where?** DNS is a time- and vantage-dependent observation. Store resolver/vantage, query type, response code, answer chain, TTL, and capture time separately from the source's original observation time.
4. **Which service?** A name resolving to an address does not establish a web application. HTTP authority, TLS SNI, port, deployment, and tenant can distinguish services on one address. Here service identity comes only from supplied owner records, not fresh connections.

Use separate fields, not one `in_scope=true` that silently implies all four. An offline inventory can recommend owner verification, never authorize network activity.

### Source Semantics

| Source | Useful evidence | Cannot establish |
|---|---|---|
| Owner-approved inventory | Named service, accountable team, approved activity | Current deployment unless inventory is fresh |
| Certificate SAN / CT entry | Name appeared in a certificate or issuance artifact at a time | Current resolution, ownership, or permission to test |
| Passive DNS export | A collector observed a record at a vantage/time | Present resolution everywhere or complete coverage |
| Supplied zone snapshot | Record configuration in that zone at export time | Resolver caches, application availability, child-zone contents |
| Captured HTTP response | Authority, status, headers, body at capture time | Other roles, deployments, or a redirect destination's scope |

"Passive" means no direct interaction with the assessed asset, not no side effects. Querying an external dataset still discloses interest and uses a provider's service. This note's exercise consumes local fixtures only.

CT logs expose certificate data; they are not an asset registry. A wildcard SAN such as `*.lab.test` is a pattern, not a concrete host, and is not the same mechanism as wildcard DNS synthesis. RFC 9162 specifies CT v2; do not assume every log or browser uses that version. Record the actual export format/version when processing real authorized evidence.

### Normalization Without Losing Provenance

- Retain the original string and normalize a separate comparison key. DNS case is insensitive; a single final dot can denote the root. Reject malformed labels, ports, paths, and wildcard patterns from the concrete-host field.
- Keep Unicode display labels and validated ASCII forms separate when internationalized names are in scope. The lab deliberately accepts only ASCII LDH hostnames; it is not an IDNA implementation.
- Deduplicate by normalized host **and retain every source observation**. Do not deduplicate addresses: many unrelated services share a CDN address.
- Match exclusions first. For an explicitly authorized DNS suffix, label-boundary matching is `name == root or name.endswith('.' + root)`, never a bare substring. This lab uses an even narrower exact-name allowlist.
- Do not collapse HTTP/HTTPS, explicit ports, API versions, or tenant identities into one asset. DNS normalization is not URL normalization.

### Interpret Ambiguity Conservatively

| Observation | Decision | Reason / discriminating evidence |
|---|---|---|
| Two supplied nonexistent-name controls and a candidate share an answer | Flag wildcard/shared-answer ambiguity | Matching addresses alone do not prove wildcard synthesis; inspect supplied zone/owner data |
| Explicit CNAME to supplier | Exclude or hold for owner clarification | Delegation is not authorization over the destination |
| CT name plus old NXDOMAIN snapshot | Historical candidate, no current claim | NXDOMAIN is time/vantage-specific; never claim an abandoned service |
| NOERROR with no answer for AAAA | NODATA for that type | Does not prove the name lacks A/MX records |
| SERVFAIL / timeout | Indeterminate | Do not convert transport or DNSSEC failure to absence |
| Different answers by vantage | Preserve both | Split-horizon, geo-routing, deployment changes, and caches are plausible |

TTL is a cache lifetime attached to an observation, not an ownership lease or evidence freshness guarantee. Pick a documented freshness policy for the decision being made; the lab uses 30 days simply to exercise stale-record handling.

### Evidence and Work Queue

Example complete inventory record, not a live observation:

```json
{"asset":"api.lab.test","scope_revision":"R7","authorization":"offline-review-only","owner":"demo-team","source_ids":["D1","C1"],"captured_at":"2026-11-03T09:00:00Z","service_identity":"owner inventory: inventory-api/v1","confidence":"corroborated within fixtures","next_action":"review supplied route inventory","network_requests":0}
```

Preserve raw export bytes and their SHA-256; store transformed inventories separately with transformation version, source IDs, analyst, and UTC timestamps. A hash detects subsequent byte changes relative to a trusted manifest; it does not authenticate the original collector or prove completeness. Protect raw data with access controls; share a minimized derivative without credentials, private hostnames, or unrelated tenant information.

For a separately authorized engagement, define a per-origin budget, concurrency ceiling, maximum total requests, time window, redirect policy, and escalation contact before collection. Stop on 429/503, unexpected sensitive data, supplier transitions, or uncertain scope. A rate ceiling is not permission. For this note: total network budget **zero**; do not turn the fixture processor into a resolver or scanner.

## Gotchas

- More names is not better coverage if ownership and provenance are missing. Report confirmed, excluded, ambiguous, stale, and unobserved categories separately.
- A browser-followed redirect can cross scope even when the initial host is approved. A network allowlist and tool scope are distinct controls.
- Absence from the supplied data means "not observed in this dataset," not "does not exist."

## Labs

### Case and Setup

You receive a synthetic owner inventory, DNS export, CT export, and two negative controls. Produce a defensible decision for each candidate. Authorization R7 covers **offline review only** of four exact names; `help.lab.test` is explicitly excluded. No account or real domain is involved. Documentation addresses below are data, never destinations.

Create an empty disposable directory outside the vault. Put the following complete file in it. All seed data is embedded; no downloads or generated input files are required. The implementation is the supplied reference solution; first predict the classification table before running it.

### File: test_example.py

```python
import hashlib
import json
import re
import unittest
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 3, 9, tzinfo=timezone.utc)
ALLOWED = {"api.lab.test", "help.lab.test", "old.lab.test", "preview.lab.test"}
EXCLUDED = {"help.lab.test"}
OWNERS = {"api.lab.test": "demo-team", "preview.lab.test": "demo-team"}
CONTROLS = [("192.0.2.90",), ("192.0.2.90",)]
OBSERVATIONS = [
	{"id": "D1", "name": "API.LAB.TEST.", "source": "dns-export",
	 "at": "2026-11-03T08:00:00Z", "rcode": "NOERROR",
	 "answers": ["192.0.2.10"], "cname": ""},
	{"id": "C1", "name": "api.lab.test", "source": "ct-export",
	 "at": "2026-11-02T08:00:00Z"},
	{"id": "D2", "name": "help.lab.test", "source": "dns-export",
	 "at": "2026-11-03T08:00:00Z", "rcode": "NOERROR",
	 "answers": ["192.0.2.20"], "cname": "tenant.vendor.test"},
	{"id": "D3", "name": "old.lab.test", "source": "dns-export",
	 "at": "2026-09-01T08:00:00Z", "rcode": "NXDOMAIN",
	 "answers": [], "cname": ""},
	{"id": "D4", "name": "preview.lab.test", "source": "dns-export",
	 "at": "2026-11-03T08:00:00Z", "rcode": "NOERROR",
	 "answers": ["192.0.2.90"], "cname": ""},
	{"id": "C2", "name": "*.lab.test", "source": "ct-export",
	 "at": "2026-11-03T08:00:00Z"},
	{"id": "C3", "name": "api.lab.test.other.test", "source": "ct-export",
	 "at": "2026-11-03T08:00:00Z"},
]


def hostname(value):
	name = value[:-1] if value.endswith(".") else value
	name = name.lower()
	labels = name.split(".")
	if len(name) > 253 or not all(
		re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
		for label in labels
	):
		raise ValueError("not a concrete ASCII hostname")
	return name


def classify(name, records):
	if name in EXCLUDED:
		return "excluded"
	if name not in ALLOWED:
		return "outside-exact-scope"
	dns = [record for record in records if record["source"] == "dns-export"]
	if any(record.get("cname") for record in dns):
		return "review-delegation"
	if not dns:
		return "unvalidated"
	fresh = [record for record in dns if timedelta(0) <=
			 NOW - datetime.fromisoformat(record["at"]) <= timedelta(days=30)]
	if not fresh:
		return "stale"
	signatures = {(record["rcode"], tuple(sorted(record["answers"])))
				  for record in fresh}
	if len(signatures) != 1:
		return "conflicting-observations"
	rcode, answers = next(iter(signatures))
	if rcode != "NOERROR" or not answers:
		return "unvalidated"
	if len(CONTROLS) >= 2 and all(answers == control for control in CONTROLS):
		return "review-wildcard-or-shared-answer"
	if name not in OWNERS:
		return "review-owner"
	return "corroborated-offline"


def inventory():
	grouped = {}
	rejected = []
	for record in OBSERVATIONS:
		try:
			name = hostname(record["name"])
		except ValueError:
			rejected.append(record["id"])
			continue
		grouped.setdefault(name, []).append(record)
	rows = [{"name": name, "decision": classify(name, records),
			 "sources": [record["id"] for record in records]}
			for name, records in sorted(grouped.items())]
	return rows, rejected


class InventoryTests(unittest.TestCase):
	def test_decisions(self):
		rows, rejected = inventory()
		self.assertEqual({row["name"]: row["decision"] for row in rows}, {
			"api.lab.test": "corroborated-offline",
			"api.lab.test.other.test": "outside-exact-scope",
			"help.lab.test": "excluded",
			"old.lab.test": "stale",
			"preview.lab.test": "review-wildcard-or-shared-answer",
		})
		self.assertEqual(rejected, ["C2"])

	def test_provenance(self):
		rows, _ = inventory()
		row = next(row for row in rows if row["name"] == "api.lab.test")
		self.assertEqual(row["sources"], ["D1", "C1"])

	def test_normalization(self):
		self.assertEqual(hostname("API.LAB.TEST."), "api.lab.test")
		for value in ("*.lab.test", "api.lab.test:443", "api..lab.test", "-api.test"):
			with self.subTest(value=value), self.assertRaises(ValueError):
				hostname(value)

	def test_unknown_and_conflicting_evidence(self):
		self.assertEqual(classify("api.lab.test", []), "unvalidated")
		changed = dict(OBSERVATIONS[0], answers=["192.0.2.11"])
		self.assertEqual(classify("api.lab.test", [OBSERVATIONS[0], changed]),
						 "conflicting-observations")
		delegated = dict(OBSERVATIONS[0], cname="tenant.vendor.test")
		self.assertEqual(classify("api.lab.test", [delegated]), "review-delegation")


if __name__ == "__main__":
	serialized = json.dumps(OBSERVATIONS, sort_keys=True).encode("utf-8")
	print("normalized-fixture-sha256", hashlib.sha256(serialized).hexdigest())
	print(json.dumps(inventory(), indent=2))
	unittest.main()
```

### Objectives and Commands

1. Write predicted decisions and the evidence IDs supporting them. Explain why C2 cannot become a host and why D2 remains excluded despite an apparent DNS answer.
2. Run from the disposable directory:

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 -m unittest -v test_example
```

3. Preserve the printed inventory, interpreter version, and actual test result as local evidence. The printed hash covers normalized embedded JSON, **not** original collector bytes. For a real export, hash the original file before parsing instead.
4. Explain which decision would change if a fresh owner-confirmed record were supplied. Do not obtain one from the network.

### Hints

Exclusions precede ownership; normalization must not merge source records away. Two matching controls justify a review flag, not proof that every host with that address is nonexistent. Freshness and successful resolution are different dimensions.

### Solution and Expected Results

The expected five rows are `api` corroborated offline (D1+C1), the lookalike outside exact scope (C3), `help` excluded (D2), `old` stale (D3), and `preview` requiring wildcard/shared-answer review (D4). C2 is retained in the source dataset but rejected from the concrete-host inventory. Four tests are expected to pass. These are predicted results, not an executed run.

The naïve baseline "NOERROR means owned and testable" would wrongly approve `help` and `preview`. The reference control separates exclusion, delegation, freshness, ambiguity, and owner corroboration. Even `corroborated-offline` grants no active-test permission. A useful handoff is five disposition rows, six concrete-name source observations retained, one rejected pattern, and zero network requests.

### Acceptance, Troubleshooting, and Cleanup

- [ ] Reproduce the five decisions and retained source IDs from the printed file alone.
- [ ] Explain the wildcard/shared-answer and third-party boundaries without making network requests.
- [ ] Record actual Python version and test outcome; preserve all study statuses.

`py` missing means select an already installed Python 3.12 executable and substitute its path; no package installation is needed. A different row count usually means wildcard C2 was treated as a host or duplicate C1 was discarded incorrectly. The date is intentionally frozen for deterministic tests, not taken from the machine clock. Delete only the disposable directory and its `__pycache__` after retaining the synthetic result; there is no server, DNS zone, or account to remove.

Author validation: static review only; printed commands and tests were not executed. The processor is deliberately conservative, not a general DNS/IDNA parser, freshness authority, or proof of inventory completeness.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - assessment methodology; use a versioned edition for engagement traceability.
- [RFC 1034: Domain Names, Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034) - DNS names, aliases, and resolution.
- [RFC 4592: The Role of Wildcards in DNS](https://www.rfc-editor.org/rfc/rfc4592) - wildcard synthesis, not certificate matching.
- [RFC 9162: Certificate Transparency v2](https://www.rfc-editor.org/rfc/rfc9162) - logging guarantees and limits; specification does not imply universal deployment.
- [Python 3.12 unittest](https://docs.python.org/3.12/library/unittest.html) - offline acceptance checks.
