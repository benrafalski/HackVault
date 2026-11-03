---
title: "Content Discovery"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Content Discovery

> [!abstract] TL;DR
> Baseline first; bound concurrency and rate; retain method/status/length/redirect/context. Do not infer validity from status code alone.

> [!info] Agent scope
> Endpoint inventories; crawling; dictionaries; response baselines; authenticated coverage; rate limits and stop conditions.

## Prerequisites

- HTTP methods, URLs, redirects, cookies, and representations; [[Web Lab Setup]].
- Python 3.12 standard library for the complete offline exercise. No scanner, wordlist download, server, network, browser, or account is required.

## Learn

```text
Teach me evidence-based web content discovery at expert depth. Assume HTTP,
URL parsing, sessions, and basic Python. Explain inventories from navigation,
captured HTML, client bundles, API schemas, and owner route tables; bounded
crawling; curated dictionaries; method/origin/role/version coverage; and why
status, length, and timing alone are unreliable. Work through an offline case
with soft 404s, a SPA shell, login redirects, a legitimate member-only view,
nonce variation, a third-party link, and a 429 stop condition. Provide complete
Python 3.12 standard-library fixture processing and named regression tests.
Explain baseline selection, negative controls, normalization risks, pagination,
coverage denominators, rate budgets, and evidence provenance. No live target
discovery or scans, exploitation, bypasses, credentials, or external accounts.
Use only supplied synthetic captures; explain what remains unobserved. Discuss
tradeoffs and difficult classification examples with worked answers and public
primary sources. Teach here; do not request file edits or change study status.
```

## Cheatsheet

### Inventory Before Requests

The unit of coverage is a request context, not a path string:

```text
origin=https://app.lab.test:443
method=GET
path=/workspace
query_schema=none
representation=application/json
identity=synthetic-member-A
workflow_state=signed-in
deployment=fixture-v1
source=navigation:N2
```

Maintain candidate, observed, classified, blocked, and unobserved states. A URL in HTML is a candidate; a captured response is an observation; neither establishes a vulnerability. The server may expose routes absent from the UI, while a client route may never reach the server independently.

| Source | Extraction and value | Boundary |
|---|---|---|
| Captured HTML | Parse anchors/forms with an HTML parser; record base URL and method | Do not submit forms or follow third-party URLs |
| API schema | Record operation, parameters, security requirements, versions | Schema can be stale or intentionally incomplete |
| Client bundle | Record literal paths and the calling feature | String presence does not prove deployment or reachability |
| Owner route table | Compare expected handlers with captures | Include middleware, feature flags, and mounted prefixes |
| Small domain dictionary | Hypotheses from supplied vocabulary, e.g. `docs`, `status`, `archive` | No generic bulk wordlist or guessed sensitive filenames |

For offline crawling, resolve relative links against the captured document URL, remove fragments, and retain queries. Honor a captured `<base>` only after validating its destination. Bound depth, pages, and total candidates; repeated pagination and calendars can create an infinite graph. This lab parses one supplied page with no `<base>` and no script execution.

### Baselines and Classification

Take at least two supplied negative controls in the same role, representation, host, and deployment. Their difference reveals background variation. A control is not "known missing" merely because it looks random: obtain that fact from the synthetic fixture or owner route map.

| Response | Interpretation | Next offline decision |
|---|---|---|
| 200, same application shell as missing-path controls | Baseline-equivalent, not confirmed content | Compare documented semantic fields; retain raw response |
| 200, distinct page/content contract | Observed distinct response | Corroborate against navigation/schema; no security claim |
| 302 to `/login` | Session-gated or common gateway behavior | Compare member capture, never call this an absent route |
| 401/403 | Request denied in this context | Could be gateway-wide; do not infer object existence |
| 404/410 | Missing/removed in this context | Could deliberately conceal a protected resource |
| 405 | Method rejected | Record `Allow` if supplied; do not try unsafe methods |
| 429/503 | Throttling/availability stop signal | Stop queue; preserve `Retry-After`, do not accelerate retries |
| Cross-origin redirect | Scope boundary | Record destination but do not follow it |

Compare status, media type, redirect, semantic body, and identity together. Byte length is a triage feature, not an oracle. Compression, nonces, translated text, personalization, and shared error templates defeat simplistic filters. A `HEAD` response is not a substitute for observing a `GET` body. A `304` requires the relevant cached representation to interpret.

Canonicalize only known volatile fields in a derivative. For JSON, parse it and remove the documented `request_id`; do not regex away arbitrary numbers or all identifiers. Keep arrays ordered unless the schema explicitly says order is irrelevant. Never normalize away identity, authorization decisions, or resource ownership. Exact canonical equality can detect a known shell; fuzzy similarity can rank manual review but must not silently erase real content.

### Coverage and Experiment Ledger

Worked classification from the lab:

```text
GET /workspace, guest: 302 Location=/login -> login-redirect
GET /workspace, member: 200 {page:workspace, owner:member-A} -> distinct-response
GET /archive, guest: 200 {page:shell, request_id:n7} -> baseline-equivalent
GET /handoff, guest: 302 Location=https://vendor.test/help -> outside-scope
```

The member result is ordinary intended behavior, not an authorization defect. A useful role matrix retains guest and member rows rather than replacing the former with the latter. Store raw capture ID, capture time, session label, deployment, source route, expected outcome, observed outcome, and reason for each classification.

Coverage must name its denominator: "7 guest captures classified from 7 supplied cases; one member case observed" is defensible. "All endpoints tested" is not. Schema-only routes and missing role contexts remain unobserved; a test skip is not a pass. Prioritize routes by business importance and trust boundary, then by uncertainty, rather than raw path count.

### Budgets, Safety, and Evidence

An authorized online plan would specify origin/method allowlists, maximum total requests, per-origin rate, concurrency, timeout, retry ceiling, read-only assumptions, and stop contacts. Even GET can have side effects in poorly designed systems. Obtain owner confirmation instead of assuming method semantics guarantees safety. Do not infer that scope filtering prevents a browser, extension, redirect, or scanner from sending other traffic.

This exercise has a zero-network budget. Its dictionary selects existing captured records only; missing fixtures become `unobserved`, not network requests. Its stop simulation ends before processing any later queued item after a 429/503. For evidence, retain raw captures, documented normalization rules, their separate hashes, and the decision ledger. Remove session tokens and unrelated data from shareable derivatives; use synthetic identity labels that preserve the role distinction.

## Gotchas

- Authentication expiry can make many valid pages look like the same login page. Re-establish a control before interpreting a changed result.
- URL parsers parse, but do not enforce your security policy. Explicitly validate authority, credentials, port, and scheme. Do not decode encoded paths repeatedly or merge slash/case variants without server evidence.
- Automatic redirect following destroys the distinction between an original response and its destination. Retain each hop separately, with scope checked at the boundary.

## Labs

### Case and Complete Setup

Review a synthetic capture bundle for `https://app.lab.test`. The owner says `/missing-a` and `/missing-b` are absent; all unknown routes return a JSON shell. Only GET captures are supplied. Guest and member are fixture labels, not accounts. Build a route ledger without contacting any host.

Create an empty disposable directory outside the vault containing this one complete file. It embeds the HTML, dictionary, captures, classifier, and solution tests. Predict outcomes before inspecting the assertions. No server starts and no networking module is imported.

### File: test_example.py

```python
import json
import unittest
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

BASE = "https://app.lab.test/"
HTML = '<a href="/docs">Docs</a><a href="/workspace#top">Work</a>' \
	   '<a href="https://vendor.test/help">Help</a>'
DICTIONARY = ["/api/status", "/archive", "/unseen"]


def capture(status, body=None, location="", **headers):
	return {"status": status, "body": body, "location": location,
			"headers": {"content-type": "application/json", **headers}}


FIXTURES = {
	("guest", "/missing-a"): capture(200, {"page": "shell", "request_id": "n1"}),
	("guest", "/missing-b"): capture(200, {"page": "shell", "request_id": "n2"}),
	("guest", "/archive"): capture(200, {"page": "shell", "request_id": "n7"}),
	("guest", "/docs"): capture(200, {"page": "docs", "revision": 1}),
	("guest", "/api/status"): capture(200, {"state": "ready"}),
	("guest", "/workspace"): capture(302, location="/login"),
	("member", "/workspace"): capture(200, {"page": "workspace", "owner": "member-A"}),
	("guest", "/retired"): capture(404, {"error": "missing"}),
	("guest", "/handoff"): capture(302, location="https://vendor.test/help"),
	("guest", "/slow"): capture(429, {"error": "pause"}, **{"retry-after": "60"}),
}


def scoped_path(reference):
	parsed = urlsplit(urljoin(BASE, reference))
	if parsed.scheme != "https" or parsed.netloc != "app.lab.test":
		return None
	return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


class Links(HTMLParser):
	def __init__(self):
		super().__init__()
		self.references = []

	def handle_starttag(self, tag, attrs):
		if tag == "a":
			reference = dict(attrs).get("href")
			if reference is not None:
				self.references.append(reference)


def candidates():
	parser = Links()
	parser.feed(HTML)
	return sorted({path for reference in parser.references + DICTIONARY
				   if (path := scoped_path(reference)) is not None})


def fingerprint(response):
	body = response["body"]
	if isinstance(body, dict):
		body = {key: value for key, value in body.items() if key != "request_id"}
	return (response["status"], response["headers"]["content-type"],
			response["location"], json.dumps(body, sort_keys=True))


def classify(role, path):
	response = FIXTURES.get((role, path))
	if response is None:
		return "unobserved"
	if response["status"] in (429, 503):
		return "stop"
	if response["location"]:
		destination = scoped_path(response["location"])
		if destination is None:
			return "outside-scope"
		return "login-redirect" if destination == "/login" else "redirect-review"
	if response["status"] in (401, 403):
		return "denied-context"
	if response["status"] in (404, 410):
		return "missing-context"
	controls = [FIXTURES.get((role, path)) for path in ("/missing-a", "/missing-b")]
	if all(control is not None for control in controls):
		baseline = {fingerprint(control) for control in controls}
		if len(baseline) == 1 and fingerprint(response) in baseline:
			return "baseline-equivalent"
	if 200 <= response["status"] < 300:
		return "distinct-response" if role == "guest" else "observed-no-role-baseline"
	return "review"


def process_queue(paths):
	ledger = []
	for path in paths:
		decision = classify("guest", path)
		ledger.append((path, decision))
		if decision == "stop":
			break
	return ledger


class DiscoveryTests(unittest.TestCase):
	def test_inventory(self):
		self.assertEqual(candidates(),
						 ["/api/status", "/archive", "/docs", "/unseen", "/workspace"])
		self.assertIsNone(scoped_path("https://vendor.test/help"))
		self.assertIsNone(scoped_path("https://app.lab.test:444/docs"))

	def test_soft_404(self):
		self.assertNotEqual(FIXTURES[("guest", "/archive")]["body"],
							FIXTURES[("guest", "/missing-a")]["body"])
		self.assertEqual(classify("guest", "/archive"), "baseline-equivalent")
		self.assertEqual(classify("guest", "/docs"), "distinct-response")

	def test_role_coverage(self):
		self.assertEqual(classify("guest", "/workspace"), "login-redirect")
		self.assertEqual(classify("member", "/workspace"), "observed-no-role-baseline")
		self.assertEqual(classify("member", "/docs"), "unobserved")

	def test_boundary_and_absence(self):
		self.assertEqual(classify("guest", "/handoff"), "outside-scope")
		self.assertEqual(classify("guest", "/retired"), "missing-context")
		self.assertEqual(classify("guest", "/unseen"), "unobserved")

	def test_stop(self):
		self.assertEqual(process_queue(["/docs", "/slow", "/api/status"]),
						 [("/docs", "distinct-response"), ("/slow", "stop")])


if __name__ == "__main__":
	print(json.dumps(process_queue(candidates()), indent=2))
	unittest.main()
```

### Objectives and Commands

1. Extract the five scoped candidates; annotate the source of each (HTML or dictionary). Count `/unseen` as a coverage gap, not an absent endpoint.
2. Compare raw bodies of the two missing controls and `/archive`; identify exactly which normalization is justified.
3. Use the guest/member captures to explain ordinary session gating. There is no member negative-control capture, so the classifier explicitly refuses to assert a baseline comparison for that role.
4. Run the supplied solution and acceptance tests in the disposable directory:

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 -m unittest -v test_example
```

### Hints

An HTML fragment is not sent in an HTTP request. A third-party anchor must not enter the scoped queue. The dictionary is an inventory hypothesis source, not a request generator. Comparing controls across identities can erase genuine role-specific behavior.

### Solution and Expected Results

The five candidate decisions are `/api/status` distinct, `/archive` baseline-equivalent, `/docs` distinct, `/unseen` unobserved, and `/workspace` login-redirect. The explicit stop queue processes only `/docs` and `/slow`. Five tests should pass; none has been executed by the author.

The cheatsheet's member body demonstrates distinct content to a human reader, but the code deliberately labels it `observed-no-role-baseline`: a different guest body is not a substitute for a same-role negative control. This conservative distinction is useful when reporting incomplete evidence.

The naïve baseline accepts `/archive` because it is 200. The controlled classifier fixes that false positive while retaining `/docs` and `/api/status`. Retest acceptance requires both outcomes, so a blanket "discard all 200" filter cannot pass.

### Acceptance, Troubleshooting, and Cleanup

- [ ] Reproduce the five candidates and document the unobserved role/route cells.
- [ ] Distinguish the soft-404 shell, normal member content, and external redirect without network activity.
- [ ] Verify the queue stops at the supplied 429 and record actual test results.

Run in this lab's own directory to avoid importing another note's same-named test module. If Python 3.12 is installed without `py`, substitute its executable path. The parser is intentionally limited to supplied anchors; forms, scripts, pagination, and `<base>` behavior require additional captures, not guesses. Remove the disposable directory and `__pycache__` after retaining synthetic evidence. No account, proxy, or service needs cleanup.

Author validation: static review only. Automated results, rendered output, and general-purpose crawling behavior are unverified. The lab tests classification, not actual HTTP or browser behavior.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]

## References

- [OWASP information gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/) - inventory methodology; latest URLs may redirect as OWASP reorganizes its site.
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) - methods, status, redirects, representations.
- [RFC 6585: Additional HTTP Status Codes](https://www.rfc-editor.org/rfc/rfc6585) - 429 and rate-limit semantics.
- [Python 3.12 HTMLParser](https://docs.python.org/3.12/library/html.parser.html) and [URL parsing](https://docs.python.org/3.12/library/urllib.parse.html) - parsing does not itself enforce scope.
