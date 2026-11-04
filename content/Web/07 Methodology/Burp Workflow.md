---
title: "Burp Workflow"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Burp Workflow

> [!abstract] TL;DR
> Scope -> baseline -> one-variable change -> compare -> reproduce -> document -> clean up. Link [[Burp Suite]] for tool-specific operations.

> [!info] Agent scope
> Project scope; proxying; request replay; session handling; comparisons; evidence capture; link the shared Burp Suite note.

## Prerequisites

- HTTP, browser navigation versus API calls, session lifecycle, and [[Web Lab Setup]].
- [[Burp Suite]] is the shared tool reference. Record the actual edition/build when using Burp; UI locations and availability change.
- Required lab: Python 3.12 standard library only, entirely in-process and offline. Burp, a browser, a certificate authority, accounts, and a server are not required.

## Learn

```text
Teach me a rigorous Burp Suite assessment workflow, assuming HTTP and sessions.
Cover project scope versus network enforcement, dedicated browser/proxy trust,
HTTP history versus interception, Repeater destinations and redirects, unchanged
replay, one-variable comparisons, session jars/rules/macros, CSRF state, cache
and protocol confounders, and evidence export/redaction. Distinguish Community
and Professional capabilities and version-sensitive UI from stable principles.
Use a fully supplied offline synthetic request/response case with a harmless
display preference, expired session, legitimate second identity, and timestamps.
Show Python 3.12 standard-library tests for the experiment logic; do not require
Burp installation, servers, live requests, or external accounts. Explain what
an offline model cannot prove about TLS, browser policy, or Burp behavior.
Teach baseline/test/control sequencing, expected and actual request provenance,
failure diagnosis, cleanup, and evidence retention. No exploitation, bypass,
data theft, or live discovery. Cite public PortSwigger and protocol sources.
End with hard interpretation questions and worked answers. Teach here without
editing files or study status.
```

## Cheatsheet

### Establish the Experiment Boundary

Write a scope card before opening a project: approved scheme/host/port, paths, methods, accounts/roles, deployment, time window, request budget, prohibited actions, redirect policy, evidence retention, and emergency contact. Keep it with the project. Tool scope is a targeting/filtering feature, **not an egress firewall** or authorization document.

In a separately authorized local setup, use a dedicated browser profile or Burp's browser, a loopback-only proxy listener, and no unrelated tabs/extensions. Do not change corporate/system proxy or certificate trust for this exercise. If TLS interception is needed elsewhere, trust its CA only in the disposable profile; remove it afterward. The browser-to-proxy and proxy-to-server TLS connections are different connections. A successful interception is not proof of end-to-end TLS identity.

Do not enable automated auditing, crawling, extensions, live tasks, or external interaction services just because a host is in scope. Community provides manual tools such as Proxy and Repeater; automated Scanner and disk project capabilities are edition-dependent. Temporary projects require deliberate evidence exports before closing. Consult the current build's documentation for exact controls.

### Capture and Replay Procedure

| Stage | Concrete action | Required evidence / gate |
|---|---|---|
| Scope | Add exact origin and exclusions in Target scope; filter HTTP history | Inspect the actual destination; filtering does not stop unrelated traffic |
| Baseline | Keep interception off while navigating a permitted benign action | Capture method, URL, body, role label, time, response, and build |
| Isolate | Select the request in HTTP history and send to Repeater | Name tab `B0-member-A-blue`; confirm target scheme/host/port |
| Unchanged replay | Send exactly the captured request, with redirects not followed automatically | If response semantics change, diagnose state before modifying inputs |
| One-variable test | Duplicate baseline tab; change only `view=blue` to `view=green` | Expected delta: returned view, not owner/status/authorization |
| Control replay | Repeat baseline under the same known session state | Confirms whether drift, logout, cache, or deployment caused a difference |
| Compare | Send responses to Comparer; inspect raw and semantic differences | Keep raw artifacts and record exactly what was normalized |
| Close | Export minimal requests/responses and context; revoke lab sessions | Redact derivatives; clean up only lab-owned profile/trust/project |

Read-only operation is a business property, not merely a GET label. Do not replay payments, messages, file uploads, or other state-changing actions without explicit permission and a reset plan. An idempotency key is not a universal safety guarantee. Repeater is an HTTP client, not a browser: it does not establish browser CORS/SameSite behavior or execute JavaScript.

### Worked Request and Interpretation

Synthetic application-layer example, not a request to send to a live host:

```http
GET /preferences?view=blue HTTP/1.1
Host: app.lab.test
Cookie: sid=fixture-A
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
X-Request-ID: R1

{"owner":"member-A","view":"blue"}
```

Hypothesis H1: changing `view` changes the rendering preference only. Baseline B0 and unchanged B1 should agree on owner, view, status, and cache policy, while request IDs may differ. Test T1 changes view to green; control B2 restores blue. If T1 returns 401 after logout, H1 has not been tested under comparable conditions. Re-authenticate only through the approved normal flow in a real engagement; do not improvise around invalid sessions.

### Session State Is an Input

| State component | Failure mode | Control |
|---|---|---|
| Cookie jar | A later login silently changes the identity of replayed requests | Isolate profiles/projects or explicitly label and inspect each outgoing request |
| Session handling rule | A macro rewrites tokens/cookies before send | Record rule scope and action order; compare intended request to actual emitted request |
| CSRF token | Stale or single-use token causes an unrelated rejection | Capture fresh state through the normal application flow; record prerequisites |
| Logout/rotation | Baseline token becomes invalid during comparison | Repeat unchanged control and check identity before interpreting results |
| OAuth redirects | Replay omits browser navigation, nonce, or callback state | Treat complete protocol flow as prerequisite, not one reusable request |
| Cache validators | A 304 or cached body hides the intended origin response | Record `Age`, `ETag`, `Vary`, validators, and deployment; avoid assuming a cache hit is a fresh evaluation |

Scope session rules to the smallest tools and URLs needed. Disable irrelevant rules for a controlled experiment, document that choice, and verify actual requests. A macro can accidentally run a state-changing request or mix identities; never assume background automation preserves experimental isolation.

### Compare Without Erasing the Finding

First compare raw status, headers, body length/bytes, redirect target, and timings. Then compare a derivative with only demonstrated volatile fields removed. Keep owner/tenant, resource IDs, security decisions, cache directives, and errors. A byte diff shows *where* data changed; a semantic diff helps explain *why*. Response-time differences require repeated controlled measurements and a benign cause model, not a claim from one slow request.

HTTP/2 or HTTP/3 traffic may be represented in a text-oriented editor differently from actual wire framing. Record negotiated protocol and intermediary context; the visible request is not necessarily a byte-for-byte network capture. This note does not cover framing manipulation. Compressed bodies, charset conversion, automatic content-length handling, and redirects also affect exported views.

### Evidence Package

Use IDs `B0`, `B1`, `T1`, `B2`, `L1` for baseline, replay, test, control, and logged-out control. For each retain UTC time, build, role, experiment step, actual request/response, session-state label, and hypothesis. Export raw originals to restricted storage; create a derivative that replaces Cookie/Authorization/Set-Cookie values and identifiers consistently. Body and URL secrets need separate review. Hash raw and redacted versions separately; hashing is not anonymization. A screenshot supplements but does not replace reproducible text.

## Gotchas

- Intercept-on can make a page appear broken because a request is waiting; history can capture traffic with interception off.
- An in-scope hostname in the `Host` header does not guarantee Repeater's actual destination matches it. Verify the destination control independently.
- Restoring a saved request does not restore server-side state. Record session rotation, deployment, data reset, and cache context separately.

## Labs

### Case and Setup

The following in-process model stands in for a supplied capture sequence. It is not an HTTP server or a Burp emulator. All requests are Python dictionaries; `app.lab.test` is a label never resolved. Two synthetic session labels belong to member-A and member-B. The only operation reads a harmless preference. No account registration, external target, or installation is required.

In an empty disposable directory outside the vault, create the two complete files below. The reference solution is provided so the exercise can be completed without an agent. First predict B0/B1/T1/B2/L1 semantics, then run the checks.

### File: workflow.py

```python
from copy import deepcopy


class FixtureApplication:
	def __init__(self):
		self.sessions = {"fixture-A": "member-A", "fixture-B": "member-B"}
		self.sequence = 0

	def handle(self, request):
		self.sequence += 1
		headers = {"Content-Type": "application/json", "Cache-Control": "no-store",
				   "X-Request-ID": f"R{self.sequence}"}
		if (request["origin"], request["method"], request["path"]) != (
			"https://app.lab.test", "GET", "/preferences"
		):
			raise ValueError("outside fixture scope")
		owner = self.sessions.get(request["session"])
		if owner is None:
			return {"status": 401, "headers": headers, "body": {"error": "signed-out"}}
		if request["view"] not in {"blue", "green"}:
			return {"status": 400, "headers": headers, "body": {"error": "invalid-view"}}
		return {"status": 200, "headers": headers,
				"body": {"owner": owner, "view": request["view"]}}


def request(view="blue", session="fixture-A"):
	return {"origin": "https://app.lab.test", "method": "GET",
			"path": "/preferences", "session": session, "view": view}


def semantic(response):
	result = deepcopy(response)
	result["headers"].pop("X-Request-ID", None)
	return result


def compare(baseline, changed):
	if baseline["status"] != 200 or changed["status"] != 200:
		return "incomparable-state"
	if baseline["body"]["owner"] != changed["body"]["owner"]:
		return "incomparable-identity"
	return "same" if semantic(baseline) == semantic(changed) else "semantic-difference"


def redact(record):
	result = deepcopy(record)
	result["request"]["session"] = "[REDACTED]"
	return result


def experiment():
	app = FixtureApplication()
	records = []
	for label, outgoing in (("B0", request()), ("B1", request()),
							("T1", request("green")), ("B2", request())):
		records.append({"id": label, "identity": "member-A",
						"request": outgoing, "response": app.handle(outgoing)})
	del app.sessions["fixture-A"]
	outgoing = request("green")
	records.append({"id": "L1", "identity": "signed-out",
					"request": outgoing, "response": app.handle(outgoing)})
	return records
```

### File: test_example.py

```python
import json
import unittest
from workflow import FixtureApplication, compare, experiment, redact, request


class WorkflowTests(unittest.TestCase):
	def test_baseline_and_control(self):
		records = experiment()
		baseline = records[0]["response"]
		self.assertNotEqual(baseline, records[1]["response"])
		self.assertEqual(compare(baseline, records[1]["response"]), "same")
		self.assertEqual(compare(baseline, records[3]["response"]), "same")

	def test_single_variable(self):
		records = experiment()
		baseline, changed = records[0], records[2]
		differences = [key for key in baseline["request"]
					   if baseline["request"][key] != changed["request"][key]]
		self.assertEqual(differences, ["view"])
		self.assertEqual(compare(baseline["response"], changed["response"]),
						 "semantic-difference")
		self.assertEqual(changed["response"]["body"],
						 {"owner": "member-A", "view": "green"})

	def test_logout_is_not_parameter_effect(self):
		records = experiment()
		self.assertEqual(records[4]["response"]["status"], 401)
		self.assertEqual(compare(records[0]["response"], records[4]["response"]),
						 "incomparable-state")

	def test_identity_change(self):
		app = FixtureApplication()
		self.assertEqual(compare(app.handle(request()),
								 app.handle(request(session="fixture-B"))),
						 "incomparable-identity")

	def test_scope_and_validation(self):
		app = FixtureApplication()
		self.assertEqual(app.handle(request("purple"))["status"], 400)
		outgoing = request()
		outgoing["origin"] = "https://vendor.test"
		with self.assertRaises(ValueError):
			app.handle(outgoing)

	def test_redaction_does_not_change_original(self):
		original = experiment()[0]
		derivative = redact(original)
		self.assertEqual(derivative["request"]["session"], "[REDACTED]")
		self.assertEqual(original["request"]["session"], "fixture-A")
		self.assertEqual(derivative["response"], original["response"])


if __name__ == "__main__":
	print(json.dumps([redact(record) for record in experiment()], indent=2))
	unittest.main()
```

### Objectives and Commands

1. Label raw observations, one-variable change, positive control, and invalid-session control. Explain why request ID drift should not invalidate the baseline but identity drift should.
2. Run from this lab's directory:

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 -m unittest -v test_example
```

3. Use the printed redacted records to write this interpretation: "H1 is supported by T1 and B2 for member-A within the fixture; L1 is not comparable because session state changed." Record actual results separately from the supplied expectations.
4. Map each record to the Burp procedure above on paper. Do not send these synthetic requests anywhere. Optional tool familiarity may inspect already captured local artifacts in Burp without issuing requests, but is not required for completion.

### Hints

Same status alone is not same behavior. Keep the owner field in the comparison. The logout occurs before L1 but after B2. The redactor knows this fixture schema only; it is not a generic HTTP secret scrubber.

### Solution and Expected Results

B0/B1/B2 return 200, owner member-A, view blue, and `no-store`; T1 changes view to green only. L1 returns 401 with `signed-out`. Six tests are expected to pass. The raw baseline comparison differs due to `X-Request-ID`; the semantic comparison agrees. Switching to fixture-B is an incomparable identity, not a view-parameter effect.

The methodological failure is attributing every response difference to the edited parameter. The control is baseline-test-baseline sequencing plus identity/state checks. Retesting keeps valid view changes observable while rejecting session-confounded comparisons.

### Acceptance, Troubleshooting, and Cleanup

- [ ] Reproduce the five-record evidence sequence and the unchanged positive control.
- [ ] Detect logout and identity drift without interpreting either as a vulnerability.
- [ ] Preserve synthetic originals, inspect redacted derivatives, and record actual test results.

An import error means the two files are not in the same working directory or a different `workflow` module is being imported. Use a fresh directory, not the vault or another exercise directory. Substitute an installed Python 3.12 executable if `py` is unavailable. Delete only the disposable directory and `__pycache__` when finished. Nothing listens on a port; no proxy settings, CA certificates, or accounts were changed.

Author validation: static review only; no tests or Burp operations executed. This model does not validate network framing, real session middleware, TLS, browser policy, Burp session rules, or edition-specific UI.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]
- [[Burp Suite]]

## References

- [PortSwigger getting started](https://portswigger.net/burp/documentation/desktop/getting-started) - official scope, Proxy, and Repeater workflow.
- [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater) - manual replay and destination controls.
- [Burp session handling](https://portswigger.net/burp/documentation/desktop/settings/sessions) - rules, cookies, and macros; verify against the installed build.
- [Burp Comparer](https://portswigger.net/burp/documentation/desktop/tools/comparer) - raw comparisons.
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) - HTTP semantics; replay is not equivalent to browser execution.
