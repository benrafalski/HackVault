---
title: "Reporting"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Reporting

> [!abstract] TL;DR
> Summary -> prerequisites -> steps -> evidence -> impact -> root cause -> fix -> retest. Label unknowns and avoid unsupported execution claims.

> [!info] Agent scope
> Reproduction steps; prerequisites; evidence; impact; severity rationale; remediation; retest; redaction; audience-specific summaries.

## Prerequisites

- HTTP, prerequisites versus observations, evidence minimization, and [[Web Lab Setup]].
- Python 3.12 standard library only for this independent lab. No account, external target, network, server, report platform, dependency install, or other note's lab files are required.

## Learn

```text
Teach me evidence-driven security reporting at expert depth. Assume HTTP,
assessment scope, and basic testing. Explain how to construct an independently
reproducible report: authorization, build/environment, identity and state,
minimum steps, expected/observed behavior, evidence IDs, root cause, realistic
impact, severity assumptions, remediation, positive controls, retest outcomes,
and limits. Separate executive, engineering, and operational audiences without
changing the underlying facts. Work through a complete synthetic offline
cache-policy case with a fully populated evidence pack and sample report,
not an empty template. Show Python 3.12 stdlib checks for reproducibility,
evidence integrity, redaction derivatives, and retained legitimate behavior.
Explain original versus derivative artifacts, hashing versus authenticity,
timestamp provenance, CVSS version/vector assumptions, publication permissions,
and fixed versus inconclusive retests. No real data, exploitation, bypass,
live requests, external account, or invented execution evidence. Use public
primary sources. End with difficult report-review questions and worked answers.
Teach here without editing files or changing study status.
```

## Cheatsheet

### The Report Is an Evidence Argument

A report should let another authorized reader answer: what invariant failed, under which prerequisites, how do the artifacts establish it, what is the narrowest effective fix, and how will we know the fix preserved legitimate behavior? The title states the failure and affected boundary, not a tool name or speculative worst case.

| Component | Concrete content | Common failure |
|---|---|---|
| Scope | Authorization revision, allowed asset/action/window, exclusions | "Public website" substituted for permission |
| Environment | Build/revision, relevant config/runtime, role and state | A screenshot with no deployment or identity context |
| Reproduction | Ordered minimal steps, all inputs, reset state, expected result | An omitted prerequisite requiring the original researcher |
| Observation | Evidence IDs, exact response fields and state change | Inference presented as direct measurement |
| Impact | Demonstrated effect, affected boundary, assumptions and unknowns | Hypothetical chains described as established compromise |
| Root cause | Owning policy/function/config and causal mechanism | Tool finding or keyword hit treated as explanation |
| Fix | Control at the correct boundary, compatibility and rollout | UI-only change or broad denial of legitimate operations |
| Retest | Same invariant, same preconditions, fixed build, positive control | A blocked/unreachable test called fixed |

Example title: "Personal preference responses use a shared-cache directive contrary to the response contract." This is narrower and more defensible than "all user data exposed" when no cross-user disclosure was observed.

### Reproduction Contract

Specify exact input, not "send a modified request." Identify the role and how a legitimate test principal is obtained, but keep credentials out of the report. State whether an artifact is an original capture, a normalized application-layer reconstruction, or synthetic data. A tool-exported HTTP/2 view may not be the original wire bytes; line endings, decompression, and charset transformations matter when claiming byte-level identity.

For the lab, the complete normalized request is:

```http
GET /preferences HTTP/1.1
Host: app.lab.test
Accept: application/json
Cookie: sid=fixture-A
```

The before response is:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=600
X-Request-ID: E1

{"owner":"member-A","view":"blue"}
```

These are synthetic application-layer representations, not a wire capture or an instruction to contact the host. The fixture records below carry the full case context, including build and UTC case time. The model generates the response without sockets.

### Observation, Inference, and Impact

Separate the argument into levels:

- **Observed:** E1/E2 contain personal synthetic preferences and a `public` directive; the owner contract requires `no-store`.
- **Root cause in the supplied model:** the before-build response policy assigns a public cache directive to successful personal responses.
- **Conditioned risk:** an intermediary respecting that policy may store/reuse responses depending on cache keys and deployment configuration.
- **Not established:** actual shared-cache reuse, cross-user access, user population, production affected versions, or incident history.

For this case, informational hardening priority is justified pending deployment assessment. Do not assign a numerical CVSS score from the header alone. If a demonstrated vulnerability warrants CVSS, identify the version (for example 4.0), provide the full vector, justify each metric, distinguish vulnerable/subsequent system impact, and separately state environmental/business priority. A severity calculator cannot supply missing facts. CWE is a root-cause taxonomy, not severity; omit uncertain mappings rather than selecting a dramatic label.

### Evidence Handling

Preserve original bytes in restricted storage and make redacted derivatives. Record artifact ID, collector, source, UTC timestamp with provenance, tool/runtime version, policy/build, transformation, hash, and access/retention classification. Distinguish machine capture time from a case's fictional time. Never relabel a supplied fixture as measured evidence.

Use consistent synthetic aliases so identity relationships remain visible. Review Authorization, Cookie, Set-Cookie, URLs, query strings, bodies, screenshots, document metadata, and attachment names. Replace secrets with explicit placeholders in derivatives, not a hidden overlay. Redaction should preserve the facts needed for reasoning; exact-length preservation is useful only when length is relevant and allowed to disclose.

SHA-256 manifests detect changes relative to a trusted manifest; they do not prove source authenticity, chain of custody, collection legality, or completeness. Store the manifest through a separately trusted channel or sign it when authenticity matters. A person who can replace both evidence and manifest can recompute hashes. Hashing a low-entropy secret is not safe redaction.

### Remediation and Retest

Fix the policy where responses are constructed and verify the externally relevant behavior. For personal responses, `no-store` is appropriate when storage is forbidden; `private` permits private caches and `no-cache` permits storage with revalidation, so they are not equivalent alternatives. Ensure an intermediary does not override the directive. Changing a directive does not purge previously stored copies: handle approved cache invalidation and incident assessment separately, without testing unrelated users' data.

Retest the original observation, an unchanged legitimate response, and an unauthenticated control. Use the same identity/data contract and record build changes. Outcome vocabulary:

| Outcome | Meaning |
|---|---|
| Fixed within tested scope | Original invariant restored and allowed behavior preserved |
| Partially fixed | Some roles/routes/builds still violate the invariant |
| Not fixed | Same confirmed failure remains under comparable conditions |
| Inconclusive | Missing prerequisites, uncertain identity/build, or unavailable target prevents judgment |

A source patch proves intent; tests prove only the exercised slice; a deployment retest checks the deployed boundary. Do not collapse these into one "fixed" label.

### Audience-Specific Delivery

The executive summary names the supported risk, affected scope, confidence, decision, owner, and remaining uncertainty. Engineering gets exact prerequisites, source boundary, evidence, minimal reproduction, fix, and regression tests. Operations gets deployment/version verification, cache-policy monitoring, rollback/compatibility criteria, and approved retention/purge actions. Keep the facts and severity consistent across all three.

Deliver privately through the approved channel. An internal report, a bounty submission, and a public writeup may require different redaction and consent. Report closure does not automatically grant publication permission. Track report version, reviewer, action owner, due date, and retest record without overwriting original observations.

## Gotchas

- Screenshots are supplementary; text and state prerequisites make a result reproducible.
- A test that passes because the application always returns an error is not remediation. Preserve a positive control.
- A fixture's expected output is not an executed result. Keep author verification separate from the learner's completed exercises.

## Labs

### Independent Case and Setup

You receive an entirely synthetic evidence pack for a personal-preference response-policy issue. Review the report as if you had not collected the evidence. Reproduce the response semantics from the supplied model, verify evidence hashes, and inspect a redacted derivative. No live target, account, cache service, or other exercise is involved.

Create an empty disposable directory outside the vault with these **six files**. All contents are supplied. The hash manifest is generated locally by the included utility so no invented digest or execution result is presented as fact. The manifest is the seventh, generated artifact, not a missing input.

### File: scope.json

```json
{
  "case": "REP-01",
  "policy": "SYNTHETIC-R1",
  "authorized_activity": "offline fixture reproduction and report review only",
  "origin_label": "https://app.lab.test",
  "path": "/preferences",
  "method": "GET",
  "roles": ["member-A", "member-B", "anonymous"],
  "network_requests_allowed": 0,
  "contract": "Personal and authentication-error responses use no-store; valid preference bodies remain unchanged.",
  "case_date": "2026-11-03",
  "collector": "training-fixture-author; no real collection",
  "classification": "synthetic training material",
  "production_claims": "none",
  "publication": "exercise artifact only; no real disclosure authorization implied"
}
```

### File: case.py

```python
from copy import deepcopy

PROFILES = {
	"member-A": {"owner": "member-A", "view": "blue"},
	"member-B": {"owner": "member-B", "view": "green"},
}
SESSIONS = {"sid=fixture-A": "member-A", "sid=fixture-B": "member-B"}


def response(build, request, evidence_id):
	if build not in {"before", "fixed"}:
		raise ValueError("unknown build")
	if (request["method"], request["origin"], request["path"]) != (
		"GET", "https://app.lab.test", "/preferences"
	):
		raise ValueError("outside fixture scope")
	role = SESSIONS.get(request["headers"].get("Cookie"))
	headers = {"Content-Type": "application/json", "X-Request-ID": evidence_id}
	if role is None:
		headers["Cache-Control"] = "no-store"
		return {"status": 401, "headers": headers, "body": {"error": "authentication-required"}}
	headers["Cache-Control"] = "public, max-age=600" if build == "before" else "no-store"
	return {"status": 200, "headers": headers, "body": deepcopy(PROFILES[role])}


def redacted(records):
	derivative = deepcopy(records)
	for record in derivative:
		headers = record["request"]["headers"]
		if "Cookie" in headers:
			headers["Cookie"] = "[REDACTED]"
	return derivative
```

### File: evidence.json

```json
[
  {
	"id":"E1", "build":"before", "role":"member-A", "at":"2026-11-03T10:00:00Z", "provenance":"synthetic",
	"request":{"method":"GET","origin":"https://app.lab.test","path":"/preferences","headers":{"Accept":"application/json","Cookie":"sid=fixture-A"},"body":null},
	"response":{"status":200,"headers":{"Content-Type":"application/json","X-Request-ID":"E1","Cache-Control":"public, max-age=600"},"body":{"owner":"member-A","view":"blue"}}
  },
  {
	"id":"E2", "build":"before", "role":"member-B", "at":"2026-11-03T10:01:00Z", "provenance":"synthetic",
	"request":{"method":"GET","origin":"https://app.lab.test","path":"/preferences","headers":{"Accept":"application/json","Cookie":"sid=fixture-B"},"body":null},
	"response":{"status":200,"headers":{"Content-Type":"application/json","X-Request-ID":"E2","Cache-Control":"public, max-age=600"},"body":{"owner":"member-B","view":"green"}}
  },
  {
	"id":"E3", "build":"fixed", "role":"member-A", "at":"2026-11-03T11:00:00Z", "provenance":"synthetic",
	"request":{"method":"GET","origin":"https://app.lab.test","path":"/preferences","headers":{"Accept":"application/json","Cookie":"sid=fixture-A"},"body":null},
	"response":{"status":200,"headers":{"Content-Type":"application/json","X-Request-ID":"E3","Cache-Control":"no-store"},"body":{"owner":"member-A","view":"blue"}}
  },
  {
	"id":"E4", "build":"fixed", "role":"member-B", "at":"2026-11-03T11:01:00Z", "provenance":"synthetic",
	"request":{"method":"GET","origin":"https://app.lab.test","path":"/preferences","headers":{"Accept":"application/json","Cookie":"sid=fixture-B"},"body":null},
	"response":{"status":200,"headers":{"Content-Type":"application/json","X-Request-ID":"E4","Cache-Control":"no-store"},"body":{"owner":"member-B","view":"green"}}
  },
  {
	"id":"E5", "build":"fixed", "role":"anonymous", "at":"2026-11-03T11:02:00Z", "provenance":"synthetic",
	"request":{"method":"GET","origin":"https://app.lab.test","path":"/preferences","headers":{"Accept":"application/json"},"body":null},
	"response":{"status":401,"headers":{"Content-Type":"application/json","X-Request-ID":"E5","Cache-Control":"no-store"},"body":{"error":"authentication-required"}}
  }
]
```

### File: report.txt

```text
REP-01 | Personal preference responses violate the no-storage contract
Report revision: 1 | Case date: 2026-11-03 | Classification: SYNTHETIC
Author: training-fixture-author | Status: offline exercise, not submitted

EXECUTIVE SUMMARY
The supplied before-build model labels personal preference responses public
for 600 seconds, contrary to its stated no-storage contract. Two synthetic
member contexts show the same policy error. The fixed model changes the
directive to no-store while preserving legitimate preference reads.
No production system, real user, cache reuse, or data disclosure was tested.
Decision: accept as an informational hardening exercise; no numerical severity
or business-loss estimate is justified by this evidence alone.
Action owner: fictional Preferences service team.

SCOPE AND PREREQUISITES
SYNTHETIC-R1 permits offline reproduction of GET /preferences fixtures only.
app.lab.test is an origin label, not a target to contact. Network budget: zero.
Use Python 3.12 standard library with the six supplied files in one directory.
No browser, server, credentials, account, or prior exercise is required.
fixture-A and fixture-B are literal test labels mapped to member-A/member-B.
Every evidence timestamp is fictional case metadata, not an actual capture time.

REPRODUCTION
1. Read scope.json and inspect case.py::response. All processing is in memory.
2. Read E1 and E2 in evidence.json. Both return 200 and a member-specific body
   with Cache-Control: public, max-age=600. Expected policy is no-store.
3. Run: py -3.12 --version
4. Run: py -3.12 -m unittest -v test_example
5. Run: py -3.12 pack.py build
6. Run: py -3.12 pack.py verify
7. Record actual runtime version, test output, and manifest verification result.
The model's response is compared with every supplied response, not a manually
typed summary. The report remains a synthetic worked example even after tests.

EVIDENCE INDEX
E1: before / member-A / 10:00Z / 200 / public, max-age=600 / blue preference.
E2: before / member-B / 10:01Z / 200 / public, max-age=600 / green preference.
E3: fixed / member-A / 11:00Z / 200 / no-store / same body as E1.
E4: fixed / member-B / 11:01Z / 200 / no-store / same body as E2.
E5: fixed / anonymous / 11:02Z / 401 / no-store / authentication-required.
The evidence JSON contains complete normalized application-layer records;
it is not a TCP capture and makes no claim about HTTP framing or TLS.
manifest.json records locally computed SHA-256 values for the six input files.
It detects byte changes relative to that manifest, not authenticity.

ROOT CAUSE AND IMPACT
In case.py::response, the before-build success branch chooses a public cache
policy for personal data. The authentication-error branch already uses no-store.
This violates the owner contract. Actual disclosure would depend on intermediary
configuration, cache keys, storage, and reuse; none was exercised or observed.
No account crossover, unauthorized read, or real personal data is demonstrated.
Severity rationale: informational hardening pending a separately authorized
deployment assessment. A CVSS score/vector is intentionally not asserted.

REMEDIATION
Use no-store at the response-policy boundary for these personal responses.
Retain normal authentication and successful reads. Verify deployed intermediary
rules do not override the policy. no-cache and private are not equivalent to
no-store. Previously stored responses require owner-approved cache invalidation
and review; changing the header alone does not remove existing copies.

RETEST AND POSITIVE CONTROLS
The supplied fixed fixtures E3/E4 preserve status 200 and the complete original
bodies while replacing the cache directive. E5 preserves anonymous rejection.
Expected outcome: fixed within this model's response-policy scope.
Six test methods are expected to pass; execution by the author is NOT claimed.
Actual deployment retest: not performed. Browser/cache behavior: unverified.
Missing access to a deployment would be inconclusive, not proof of remediation.

HANDLING AND DISCLOSURE
All identities, requests, bodies, times, and builds are synthetic. Restricted
original/derivative handling is practiced using test labels only. The redactor
preserves identity aliases and body facts while replacing Cookie values in a
deep-copied derivative. It is not a general-purpose secret scanner.
No report was submitted or published and no real program's consent is implied.
Keep actual execution evidence separately; do not overwrite the supplied case
history. Delete disposable artifacts after review under the exercise policy.

OPERATIONAL HANDOFF
For a real authorized rollout, service owners would verify effective response
headers, intermediary configuration, and allowed-user behavior on the intended
build. A rollback must not silently restore the public-cache directive.
These are proposed deployment checks, not work performed in this exercise.
```

### File: pack.py

```python
import hashlib
import json
import sys
from pathlib import Path

FILES = ("scope.json", "case.py", "evidence.json", "report.txt", "pack.py", "test_example.py")


def manifest(root):
	return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
			for name in FILES}


def verify(root, expected):
	return set(expected) == set(FILES) and manifest(root) == expected


def main():
	root = Path(__file__).parent
	output = root / "manifest.json"
	if sys.argv[1:] == ["build"]:
		if output.exists():
			raise SystemExit("manifest already exists; preserve it before rebuilding")
		output.write_text(json.dumps(manifest(root), indent=2) + "\n", encoding="utf-8")
		print("manifest created; source authenticity not established")
	elif sys.argv[1:] == ["verify"]:
		expected = json.loads(output.read_text(encoding="utf-8"))
		if not verify(root, expected):
			raise SystemExit("FAIL: evidence pack differs from manifest")
		print("PASS: six input files match manifest")
	else:
		raise SystemExit("usage: py -3.12 pack.py build|verify")


if __name__ == "__main__":
	main()
```

### File: test_example.py

```python
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from case import redacted, response
from pack import FILES, manifest, verify

ROOT = Path(__file__).parent
EVIDENCE = json.loads((ROOT / "evidence.json").read_text(encoding="utf-8"))
SCOPE = json.loads((ROOT / "scope.json").read_text(encoding="utf-8"))


class ReportingTests(unittest.TestCase):
	def test_complete_reproduction(self):
		self.assertEqual([record["id"] for record in EVIDENCE], ["E1", "E2", "E3", "E4", "E5"])
		for record in EVIDENCE:
			with self.subTest(evidence=record["id"]):
				self.assertEqual(response(record["build"], record["request"], record["id"]),
								 record["response"])
				self.assertEqual(record["provenance"], "synthetic")

	def test_before_and_fixed_contract(self):
		for before, fixed in ((EVIDENCE[0], EVIDENCE[2]), (EVIDENCE[1], EVIDENCE[3])):
			self.assertEqual(before["response"]["headers"]["Cache-Control"], "public, max-age=600")
			self.assertEqual(fixed["response"]["headers"]["Cache-Control"], "no-store")
			self.assertEqual(before["response"]["body"], fixed["response"]["body"])
			self.assertEqual(fixed["response"]["status"], 200)

	def test_anonymous_control(self):
		control = EVIDENCE[4]["response"]
		self.assertEqual(control["status"], 401)
		self.assertEqual(control["headers"]["Cache-Control"], "no-store")
		self.assertNotIn("owner", control["body"])

	def test_redaction_preserves_original_and_facts(self):
		derivative = redacted(EVIDENCE)
		self.assertEqual(derivative[0]["request"]["headers"]["Cookie"], "[REDACTED]")
		self.assertEqual(EVIDENCE[0]["request"]["headers"]["Cookie"], "sid=fixture-A")
		for original, changed in zip(EVIDENCE, derivative):
			self.assertEqual(original["response"], changed["response"])
			self.assertEqual(original["role"], changed["role"])

	def test_manifest_detects_tampering(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			for name in FILES:
				shutil.copyfile(ROOT / name, root / name)
			expected = manifest(root)
			self.assertTrue(verify(root, expected))
			target = root / "report.txt"
			target.write_bytes(target.read_bytes() + b"\nchanged\n")
			self.assertFalse(verify(root, expected))

	def test_scope_and_report_limits(self):
		self.assertEqual(SCOPE["network_requests_allowed"], 0)
		report = (ROOT / "report.txt").read_text(encoding="utf-8")
		for label in ("E1:", "E2:", "E3:", "E4:", "E5:", "not performed", "NOT claimed"):
			self.assertIn(label, report)
		outside = dict(EVIDENCE[0]["request"], origin="https://vendor.test")
		with self.assertRaises(ValueError):
			response("fixed", outside, "outside")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Commands

1. Read only the completed report first. List its prerequisites, supported claim, and explicit unknowns. Then verify that all cited artifacts are present and sufficient.
2. In the disposable directory, follow the report's commands:

```powershell
py -3.12 --version
py -3.12 -m unittest -v test_example
py -3.12 pack.py build
py -3.12 pack.py verify
```

3. Review the six-test result and manifest result. The tampering test changes a temporary copy only; it does not alter the evidence pack. Keep the actual version/output alongside the pack as learner evidence, clearly separate from case timestamps.
4. Review the redaction test's derivative policy: Cookie is removed while role and response facts remain. Explain why a real export also needs URL/body/header/metadata review.
5. Give a fresh reader this note and the six files; require reproduction without account access or undocumented steps. No communication with an agent is a lab prerequisite.

### Hints

The before and fixed bodies must match. A 401 instead of a personal response would not prove the fix preserved legitimate behavior. The manifest hashes exact file bytes, so CRLF/LF conversion after manifest creation is a real integrity difference. A hash mismatch says bytes changed, not why or who changed them.

### Solution and Expected Results

Six tests are expected to pass, and manifest verification should print `PASS: six input files match manifest`. These are expected results, not author-executed output. The tests regenerate all five responses in process and compare them to the complete supplied records. E3/E4 correct cache policy while preserving bodies; E5 preserves anonymous rejection. The temporary tamper is detected.

The completed report is intentionally modest: a demonstrated policy mismatch in a model, not proven production disclosure. Its executive summary gives a decision, its technical body gives full reproduction, and its operational handoff identifies unperformed deployment work. That separation is the solution, not a missing exploitation step.

### Acceptance, Troubleshooting, and Cleanup

- [ ] Reproduce the complete synthetic evidence pack using only this note and Python 3.12.
- [ ] Verify integrity, redaction fidelity, and positive controls; explain what each check does not establish.
- [ ] Record actual runtime/test results and distinguish model retest from unperformed deployment validation.

Run all commands from this lab's own directory to avoid same-named test module collisions. Missing JSON files or trailing commas prevent loading; all required inputs are printed above. If the manifest already exists, verify it first; do not overwrite evidence to hide a mismatch. Preserve the old manifest before deliberately generating a new version. Use an existing Python 3.12 executable if `py` is unavailable; no third-party install is needed.

Cleanup: remove only the disposable directory, generated manifest, and `__pycache__` after retaining synthetic learning evidence. Temporary tamper-test copies clean themselves up. There is no server, user account, trust certificate, or remote artifact to delete.

Author validation: static review only; neither tests nor manifest generation ran. The evidence is complete **synthetic case data**, not a record of live assessment. Production cache behavior, authenticity of external evidence, generic secret detection, rendering, and execution remain unverified.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]

## References

- [OWASP WSTG Reporting](https://owasp.org/www-project-web-security-testing-guide/latest/5-Reporting/) - report structure; latest links may redirect during site changes.
- [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document) - metric meanings and explicit scoring assumptions.
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111) - public, private, no-cache, and no-store distinctions.
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) - assessment planning, evidence, and reporting.
- [Python 3.12 hashlib](https://docs.python.org/3.12/library/hashlib.html) and [unittest](https://docs.python.org/3.12/library/unittest.html) - local integrity and acceptance checks.
