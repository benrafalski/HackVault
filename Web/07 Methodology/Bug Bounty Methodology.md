---
title: "Bug Bounty Methodology"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Bug Bounty Methodology

> [!abstract] TL;DR
> Scope first; minimize impact; stop on unexpected sensitive data; report promptly; retest only within authorization.

> [!info] Agent scope
> Program rules; scope; hypothesis-driven testing; evidence; impact validation without unnecessary data access; disclosure and retesting.

## Prerequisites

- HTTP and evidence interpretation; [[Web Lab Setup]]. Understand that authorization, program eligibility, reward decisions, and publication permission are separate.
- Lab: Python 3.12 standard library, local JSON fixtures, no accounts, network, exploitation, platform enrollment, or package installation.

## Learn

```text
Teach me bug bounty methodology as disciplined, authorized security research,
not an exploitation playbook. Assume HTTP, sessions, and basic report writing.
Explain program policy versions, exact scope and exclusions, safe-harbor limits,
third-party services, permitted methods, request budgets, data minimization,
stop/escalation rules, duplicate handling, impact versus speculation, severity
versus reward, private submission, disclosure consent, and fresh retest approval.
Work through a complete fictional program using offline supplied captures only.
Use a harmless cache-policy hardening observation with two synthetic identities;
do not retrieve other users' data or demonstrate exploitation. Provide concrete
policy decisions, an evidence ledger, a completed submission draft, a timeline,
and Python 3.12 stdlib acceptance tests. Contrast actionable uncertainty with
unsupported claims, and explain what would require written clarification.
No live discovery, scans, bypasses, real credentials, external accounts, or
automatic submission/publication. Cite public primary program/disclosure
guidance; do not treat one platform's policy as universal legal advice. Finish
with difficult scope/disclosure decisions and worked answers. Teach here,
without requesting file edits or changing learning status.
```

## Cheatsheet

### Four Permissions, Not One

| Question | Authoritative evidence | What it does not imply |
|---|---|---|
| May I perform this activity? | Current written authorization covering asset, action, identity, time, and limits | Reward eligibility or authority over a supplier |
| Is it eligible for this program? | Program exclusions, submission requirements, researcher eligibility | That an excluded issue is safe to test |
| Is a reward due? | Program triage and reward policy | Payment for every valid report |
| May I disclose? | Applicable confidentiality terms and disclosure approval/process | Automatic permission because fixed, public-facing, duplicate, or closed |

Safe-harbor language is bounded by its terms and the authorizing party's authority; it is not immunity from every law or third-party claim. Ambiguity is a reason to pause and obtain clarification, not to choose the broadest interpretation. Employer and jurisdictional obligations can apply separately. Do not collect employer data for public research notes.

### Rules-of-Engagement Card

Archive the exact policy text, URL, revision/capture time, and hash before work. Keep subsequent changes as new versions. Record exact schemes/hosts/ports/path boundaries, exclusions, permitted test classes, synthetic-account rules, prohibited data access, rate/concurrency/total limits, time window, reporting channel, emergency contact, retention, and disclosure rules.

The fictional lab policy below authorizes **offline analysis only**. Even its allowed origin is a string in a fixture, not permission to connect. A redirect to a supplier is an observed boundary. Do not follow it. Parent-domain ownership, visual branding, a CNAME, or an acquisition announcement does not silently expand scope.

### Hypothesis-Driven Work

Use a short research card instead of collecting unbounded endpoints:

```text
H1: Personalized /preferences captures should not permit shared caching.
Policy: DEMO-R1, offline review only, roles member-A and member-B.
Minimum evidence: one supplied response per role plus supplied fixed response.
Expected contract: personal responses carry Cache-Control: no-store.
Observed fixture: build before uses public, max-age=600; fixed uses no-store.
Stop: unrelated data, uncertain provenance, out-of-scope redirect, revoked permission.
Disconfirming evidence: endpoint content is intentionally public under the owner policy.
Limit: no cache replay or cross-user retrieval; actual disclosure is not demonstrated.
```

Prioritize by documented importance, evidence quality, uncertainty, and cost within scope. The objective is a supported conclusion, not maximum apparent severity. Timebox each hypothesis; unresolved cases become questions rather than increasingly invasive experiments.

### Evidence and Impact Ladder

1. **Observation:** the supplied response includes `Cache-Control: public, max-age=600` and a synthetic preference body.
2. **Policy conflict:** the owner contract declares that body personal and requires `no-store`.
3. **Conditioned risk:** a compatible shared cache might store or reuse the representation under the deployment's cache rules.
4. **Not demonstrated:** cross-user disclosure, affected real users, intermediary configuration, and exploitability at scale.

Stop at the evidence you have. Do not fetch extra records, try alternate accounts, expand scope, or chain techniques to upgrade severity. A minimal report can state a hardening issue and ask the program to assess deployment impact. For actual unexpectedly sensitive data, stop collection, restrict the existing artifact, notify the designated channel, and follow retention instructions; do not circulate or continue gathering it for "proof."

Use stable synthetic identity labels, request/response IDs, UTC times, affected build, prerequisite state, expected and actual behavior, artifact hashes, and a precise limitation statement. Keep restricted originals separate from redacted derivatives. Review headers, bodies, query strings, screenshots, filenames, metadata, and attachments for secrets. Do not upload evidence to unapproved paste sites or analysis services.

### Submission and Triage

Submit through the program's approved private channel only. Include one coherent root cause per report unless the program requests grouping; describe related variants without redundant noise. A complete report identifies the prerequisite, smallest permitted reproduction, observed boundary, realistic impact, concrete remediation, and a bounded retest plan. Provide text evidence plus screenshots only when needed.

For a duplicate decision, compare root cause, affected boundary, build, and evidence with information the program chooses to share; do not seek other researchers' private reports. Provide new material only if it changes the assessment. Severity metrics describe technical impact under assumptions; business priority and bounty amount are separate program decisions. Never promise a reward or equate "informative" with legal permission to publish.

### Disclosure and Retest State Machine

```text
policy-reviewed -> scoped-hypothesis -> minimal-evidence -> private-draft
private-draft -> submitted -> triage -> remediation -> authorized-retest -> closure
any stage + scope uncertainty or sensitive data -> paused -> explicit clarification
closure + applicable disclosure approval + redaction review -> publication candidate
```

These are workflow states, not automatic platform transitions. Log who authorized each consequential step, what changed, and when. A fix announcement is not retest approval. Obtain the exact target/build/window and repeat only the original harmless check plus a positive control. A closed report is not necessarily publishable: platform settings, program-specific terms, and confidentiality agreements control. There is no universal "wait N days, then publish" rule.

Retest outcomes are `fixed`, `partially fixed`, `not fixed`, or `inconclusive`, supported by the same invariant. Missing credentials, expired authorization, unreachable fixture, or unrelated build changes mean inconclusive, not fixed. Preserve the original finding and append retest evidence rather than rewriting history.

## Gotchas

- "Public program" describes enrollment, not freedom to publish evidence or test every company asset.
- A machine-readable policy gate can enforce a narrow workflow, but cannot interpret a contract or prove legal authority. Its conservative rejection should not be weakened to make a case pass.
- A body labelled synthetic must actually be synthetic. Removing names from real data does not turn it into safe lab content.

## Labs

### Case and Setup

You are reviewing a fictional program's supplied evidence. Nothing is submitted and no host is contacted. Your deliverable is an authorization ledger, a private submission draft, a retest decision, and a disclosure decision. Create an empty disposable directory outside the vault with the four files below. Python 3.12 standard library is the only dependency.

### File: policy.json

```json
{
  "revision": "DEMO-R1",
  "mode": "offline-only",
  "start": "2026-11-03T09:00:00Z",
  "end": "2026-11-03T17:00:00Z",
  "origin": "https://app.lab.test",
  "paths": ["/preferences"],
  "roles": ["member-A", "member-B"],
  "excluded_paths": ["/billing"],
  "network_budget": 0,
  "retest_approvals": ["RT-1"],
  "disclosure_approved": false,
  "report_channel": "offline private-draft artifact; do not transmit",
  "retention": "delete disposable synthetic artifacts after review"
}
```

### File: evidence.json

```json
[
  {"id":"E1","build":"before","role":"member-A","path":"/preferences","status":200,"cache_control":"public, max-age=600","body":{"owner":"member-A","view":"blue"},"captured_at":"2026-11-03T10:00:00Z","synthetic":true},
  {"id":"E2","build":"before","role":"member-B","path":"/preferences","status":200,"cache_control":"public, max-age=600","body":{"owner":"member-B","view":"green"},"captured_at":"2026-11-03T10:01:00Z","synthetic":true},
  {"id":"E3","build":"fixed","role":"member-A","path":"/preferences","status":200,"cache_control":"no-store","body":{"owner":"member-A","view":"blue"},"captured_at":"2026-11-03T11:00:00Z","synthetic":true},
  {"id":"E4","build":"fixed","role":"member-B","path":"/preferences","status":200,"cache_control":"no-store","body":{"owner":"member-B","view":"green"},"captured_at":"2026-11-03T11:01:00Z","synthetic":true}
]
```

### File: triage.py

```python
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
POLICY = json.loads((ROOT / "policy.json").read_text(encoding="utf-8"))
EVIDENCE = json.loads((ROOT / "evidence.json").read_text(encoding="utf-8"))


def decision(action, url, role, at, *, sensitive=False, redirect="",
			 approval="", redacted=False, policy=POLICY):
	if sensitive:
		return "stop-and-notify"
	if policy["mode"] != "offline-only" or policy["network_budget"] != 0:
		return "reject-policy"
	when = datetime.fromisoformat(at)
	if when.tzinfo is None:
		return "reject-timezone"
	if not datetime.fromisoformat(policy["start"]) <= when < datetime.fromisoformat(policy["end"]):
		return "expired-or-not-started"
	parsed = urlsplit(url)
	origin = f"{parsed.scheme}://{parsed.netloc}"
	if origin != policy["origin"] or parsed.query or parsed.fragment:
		return "outside-scope"
	if parsed.path in policy["excluded_paths"] or parsed.path not in policy["paths"]:
		return "outside-scope"
	if role not in policy["roles"]:
		return "unapproved-identity"
	if redirect:
		return "pause-redirect-review"
	if action == "review-capture":
		return "allow-offline-review"
	if action == "retest-capture":
		return "allow-offline-retest" if approval in policy["retest_approvals"] else "need-retest-approval"
	if action == "publish":
		return "eligible-draft-only" if policy["disclosure_approved"] and redacted else "hold-disclosure"
	return "prohibited-action"


def assess():
	before = [row for row in EVIDENCE if row["build"] == "before"]
	fixed = [row for row in EVIDENCE if row["build"] == "fixed"]
	if len(before) != 2 or len(fixed) != 2:
		raise ValueError("incomplete evidence")
	for role in POLICY["roles"]:
		old = next(row for row in before if row["role"] == role)
		new = next(row for row in fixed if row["role"] == role)
		if not (old["synthetic"] and new["synthetic"] and old["status"] == new["status"] == 200
				and old["body"] == new["body"] and old["cache_control"] == "public, max-age=600"
				and new["cache_control"] == "no-store"):
			raise ValueError("retained behavior or cache contract differs")
	return {"finding": "DEMO-01", "observed": "personal-response cache policy mismatch",
			"impact": "hardening risk; no cross-user disclosure demonstrated",
			"evidence": [row["id"] for row in EVIDENCE],
			"retest": "fixture contract corrected; deployment unverified",
			"publication": "not approved"}


if __name__ == "__main__":
	print(json.dumps(assess(), indent=2))
```

The gate operates on already supplied synthetic proposals. It is not a request library, a robust general URL allowlist, a platform integration, or a legal decision engine. Malformed input may raise a parsing exception and must be treated as rejected, never allowed. Even `eligible-draft-only` has no transmission capability.

### File: test_example.py

```python
import unittest
from triage import POLICY, assess, decision

URL = "https://app.lab.test/preferences"
AT = "2026-11-03T12:00:00Z"


class BountyTests(unittest.TestCase):
	def gate(self, action="review-capture", url=URL, role="member-A", at=AT, **options):
		return decision(action, url, role, at, **options)

	def test_allowed_review(self):
		self.assertEqual(self.gate(), "allow-offline-review")
		self.assertEqual(self.gate(role="member-B"), "allow-offline-review")
		self.assertEqual(self.gate(action="scan"), "prohibited-action")

	def test_scope_and_redirect(self):
		self.assertEqual(self.gate(url="https://vendor.test/preferences"), "outside-scope")
		self.assertEqual(self.gate(url="https://app.lab.test/billing"), "outside-scope")
		self.assertEqual(self.gate(redirect="https://vendor.test/help"), "pause-redirect-review")

	def test_identity(self):
		self.assertEqual(self.gate(role="unrelated-person"), "unapproved-identity")

	def test_sensitive_stop(self):
		self.assertEqual(self.gate(sensitive=True), "stop-and-notify")

	def test_time_boundary(self):
		self.assertEqual(self.gate(at="2026-11-03T17:00:00Z"), "expired-or-not-started")
		self.assertEqual(self.gate(at="2026-11-03T12:00:00"), "reject-timezone")

	def test_retest_approval(self):
		self.assertEqual(self.gate(action="retest-capture"), "need-retest-approval")
		self.assertEqual(self.gate(action="retest-capture", approval="RT-1"), "allow-offline-retest")

	def test_disclosure_is_separate(self):
		self.assertEqual(self.gate(action="publish", redacted=True), "hold-disclosure")
		approved = dict(POLICY, disclosure_approved=True)
		self.assertEqual(self.gate(action="publish", policy=approved), "hold-disclosure")
		self.assertEqual(self.gate(action="publish", policy=approved, redacted=True),
						 "eligible-draft-only")

	def test_evidence_and_limits(self):
		report = assess()
		self.assertEqual(report["evidence"], ["E1", "E2", "E3", "E4"])
		self.assertIn("no cross-user disclosure demonstrated", report["impact"])
		self.assertEqual(report["publication"], "not approved")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Commands

1. Classify seven proposals: ordinary offline review; supplier redirect; billing path; unexpected sensitive-data marker; end-of-window review; retest without RT-1; publication without consent. Never act on the URLs.
2. Compare E1/E2 with E3/E4. State what changed and what the captures do not establish about deployed caches.
3. Run locally in this directory:

```powershell
py -3.12 --version
py -3.12 triage.py
py -3.12 -m unittest -v test_example
```

4. Produce the completed private draft below and a decision ledger. This is a role-play artifact, not a platform submission or a request for real program approval.

### Hints

Redaction does not grant disclosure permission. A fix does not grant a retest window. An in-scope initial URL does not authorize a supplier redirect. `public` is evidence of a caching directive, not proof anyone received someone else's representation.

### Solution: Completed Submission Draft

**DEMO-01: Personalized preference responses conflict with the program's cache contract.** Synthetic training report, not a real vulnerability submission.

**Scope and prerequisites:** DEMO-R1 permits offline analysis of supplied `/preferences` captures for member-A and member-B between 09:00 and 17:00 UTC on 2026-11-03. No network activity is authorized. The owner contract requires `no-store` for personal responses.

**Reproduction:** Load the supplied evidence; inspect E1 and E2 from build `before`. Both successful responses contain a role-specific preference and `public, max-age=600`. Compare each with E3/E4 from build `fixed`: status and body are unchanged, while cache policy is `no-store`. Run the eight acceptance tests using the supplied files.

**Impact and severity:** A cache-policy hardening gap is supported. Shared-cache storage/reuse depends on deployment behavior; cross-user disclosure and affected real users were not demonstrated. Suggested disposition: informational hardening review pending program assessment. No numerical severity or reward is asserted.

**Remediation and retest:** Apply `Cache-Control: no-store` to personal responses at the response-policy boundary and ensure intermediary rules do not override it. The supplied RT-1 approval permits offline retest only; E3/E4 satisfy the fixture contract and preserve intended responses. Deployed behavior remains unverified.

**Handling:** All four records are synthetic. No secrets or third-party data are included. Keep this as a private draft; DEMO-R1 has not approved disclosure. Delete the disposable lab artifacts after review. No submission, payment, or publication occurred.

### Expected Ledger and Acceptance

| Proposal | Expected decision |
|---|---|
| Review member-A capture at noon | Allow offline review |
| Follow supplier redirect | Pause for redirect review; no follow |
| Review billing as an authorized test | Outside scope |
| Sensitive-data marker | Stop and notify through designated process |
| Review at 17:00 UTC | Expired; end is exclusive |
| Retest without RT-1 | Need new approval |
| Publish redacted draft | Hold; disclosure not approved |

Eight tests are expected to pass. They check workflow gates and supplied evidence, not actual program compliance or HTTP behavior. All timeline entries above are fictional case data, not author activity.

- [ ] Reproduce the decision ledger without live requests or account access.
- [ ] Deliver the completed private draft with evidence and explicit impact limits.
- [ ] Distinguish approved offline retest from prohibited publication; record actual test results.

### Troubleshooting and Cleanup

Keep JSON files beside the Python modules; loading is relative to the module directory. Use UTF-8 JSON with double quotes and no comments. If `py` is missing, use an existing Python 3.12 executable. Tests must run in this lab's isolated directory so same-named modules from other labs cannot collide. Delete only that directory and `__pycache__` after retaining synthetic results. There are no sessions, network services, platform submissions, or real program artifacts to remove.

Author validation: static review only; tests not executed. The consent flag and approval ID simulate an externally documented decision; they cannot establish real authorization. Current program terms must be consulted for any real work.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]

## References

- [HackerOne Vulnerability Disclosure Standards](https://www.hackerone.com/disclosure-guidelines) - program-specific terms, report confidentiality, and disclosure settings; do not generalize one setting to all programs.
- [CISA Vulnerability Disclosure Policy Template](https://www.cisa.gov/resources-tools/resources/vulnerability-disclosure-policy-template) - explicit authorization, scope, reporting, and sensitive-data stop rules.
- [RFC 9116: security.txt](https://www.rfc-editor.org/rfc/rfc9116) - finding a disclosure contact is not permission to test.
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111) - caching directives and conditions, not proof of actual disclosure.
