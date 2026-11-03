---
title: "Burp Suite"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Burp Suite

> [!abstract] TL;DR
> Set scope, verify identity, capture baseline, change one variable, and preserve sanitized request/response evidence. See [[Burp Workflow]].

> [!info] Agent scope
> Proxy; Repeater; scope; sessions; request comparison; lab evidence; edition-specific features; links from Burp Workflow.

## Prerequisites

- Burp Suite Community or Professional desktop, a dedicated lab browser, and Python 3.12 (standard library only). Record the exact Burp build from Help/About and `py -3.12 --version`.
- Use only `http://127.0.0.1:8765` and a temporary directory for the files below. No account, external target, certificate installation, scanner, extension, or privileged shell is required.
- These instructions describe desktop UI concepts; labels can move between releases. Community supports this Proxy/Repeater/Comparer exercise. Do not assume Professional project persistence or scanner features exist in Community.

## Learn

```text
Teach me Burp Suite desktop at expert workflow depth using only a benign
HTTP service on 127.0.0.1. Assume I understand HTTP framing, cookies, origins,
TLS, and browser devtools but am new to Burp's state model. Establish the exact
edition/build and distinguish Community, Professional, and DAST capabilities.
Trace browser -> listener -> request history -> Repeater -> origin -> response.
Explain destination versus Host, scope versus routing versus history filters,
interception queues, upstream proxies, browser proxy bypass, TLS interception
and trust stores, HTTP/2 normalization, compression, and edited message framing.
Show a complete harmless GET/JSON baseline and a one-parameter comparison,
including stable identity and explicit session-cookie handling. Explain cookie
jar and session-handling rules, redirects, stale tokens, caching, and how they
confound comparisons. Teach Repeater tab groups/history and Comparer byte/word
diffs, then an evidence table with sensitive fields removed. Contrast transport
errors, application errors, and observations that do not establish a defect.
Give a complete Python 3.12 stdlib localhost fixture, deterministic checks,
manual acceptance criteria, teardown, and difficult questions with worked
answers. Use primary PortSwigger references. No scanner, exploit payloads,
external targets, credential capture, or global CA installation. Clearly label
version-dependent features and untested behavior. Teach here, not by editing
files or changing my study status.
```

## Cheatsheet

### Proxy, Scope, and Transport

| Surface | Concrete workflow | Interpretation and boundary |
|---|---|---|
| Listener | Settings -> Tools -> Proxy -> Proxy listeners; choose loopback and an unused port, normally 8080 | Listener port is not origin port 8765. Never expose an unauthenticated listener on all interfaces. |
| Browser | Proxy -> Intercept -> Open browser; set Intercept off for initial navigation | Burp's browser avoids many external-browser proxy bypass problems. A browser page loading does not prove it traversed Burp; require a history entry. |
| Scope | Target -> Scope: exact scheme `http`, host `127.0.0.1`, port `8765` | Scope is a tool-selection boundary, not a firewall. History filters hide rows; they do not prevent network access. |
| Proxy history | Filter by in-scope items; inspect method, URL, status, MIME type, time, and request/response | Keep baseline rows. A pending intercepted request has not necessarily reached the origin. |
| Repeater | Send a captured request to Repeater; verify target host/port/TLS, name the tab, send once | The editor's Host header and Repeater destination are separate controls. Leave both aligned here. |
| Comparer | Send two response bodies to Comparer, choose Words or Bytes | Compare decoded bodies or equivalent raw messages, not one of each. Date headers and encoding can create irrelevant differences. |

For HTTPS outside this HTTP-only exercise: Burp terminates client TLS and establishes a separate origin connection. The dedicated browser must trust the lab CA; trust in one browser does not prove OS-wide trust. Certificate pinning, mutual TLS, and upstream proxy configuration can prevent interception. Do not disable application protections to make capture work. Remove only lab-added trust after a permitted exercise; this lab adds none.

HTTP/2 pseudoheaders, HTTP/1.1 rendering, automatic Content-Length updates, decompression, and newline display may differ from bytes on the network. Record the negotiated protocol and whether evidence is raw or decoded. Do not treat a UI representation as a packet capture. Leave Repeater's automatic framing correction enabled for this exercise.

### Sessions and Controlled Comparisons

1. Establish an origin baseline and note the response's `Set-Cookie`. A cookie is scoped by domain/path, with Secure, HttpOnly, SameSite, and expiry controlling different browser behaviors.
2. Record the exact `Cookie` sent in each request. Repeater is not a browser: an explicit captured cookie may remain stale, and session-handling rules may replace it. Inspect the actual sent request and active rules, not just assumptions about the cookie jar.
3. Keep method, path, body, identity, headers, protocol, and server state fixed. Change only `color=blue` to `color=green` below. Disable automatic redirect following for this comparison so an intervening response is not hidden.
4. Compare status, parsed JSON fields, response headers, and timing separately. A length change alone proves neither authorization failure nor a vulnerability.
5. Replay the baseline after the variant. If it differs semantically, investigate state, caching, or session handling before attributing the result to the changed parameter.

Exact benign baseline (CRLF framing is managed by Burp):

```http
GET /inspect?color=blue HTTP/1.1
Host: 127.0.0.1:8765
Cookie: lab_session=learner
Accept: application/json
Connection: close

```

Expected semantic body: `{"color":"blue","identity":"learner","method":"GET"}`. JSON whitespace is not significant. Removing the cookie changes only `identity` to `guest`; this is a deliberately public echo service, not an authentication mechanism.

### Editions, Evidence, and Trust

| Capability | Constraint |
|---|---|
| Proxy, manual Repeater, Comparer | Sufficient for this lab in Community; UI details vary by desktop build. |
| Automated scanning | Professional/DAST licensing and workflows differ; unused here. Do not infer access from a screenshot or old tutorial. |
| Persistent disk projects | Check the edition's project options; Community sessions may be temporary. Export sanitized evidence before closing. |
| Extensions and session macros | Can read or transform traffic and make extra requests. Disable unnecessary extensions/rules; record enabled ones. |

Evidence should include tool build/edition, origin, timestamp, request identifier/tab, exact changed field, actual sent cookie (synthetic only), baseline/variant/retest status and JSON, and scope settings. Save a text transcription of this synthetic request and response; do not export unrelated browser traffic or project secrets. CA private keys and live session cookies never belong in the vault.

## Gotchas

- `localhost` and `127.0.0.1` are different cookie hosts and may route through different proxy bypass rules. Use the latter consistently.
- An origin connection refusal differs from a browser-to-proxy failure. Inspect listener state, destination, and history before changing settings.
- Scope filtering does not erase previously captured sensitive traffic. Use a fresh project/browser and close unrelated tabs.

## Labs

### Environment and Complete Files

Create an empty temporary lab directory and place the following single file there. It serves only a fixed route and returns synthetic data; it does not read files, authenticate real users, or contact other hosts. The tests use an ephemeral loopback port; the manual server uses 8765.

### File: test_example.py

```python
import argparse
import http.client
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
	def log_message(self, format_string, *args):
		pass

	def do_GET(self):
		url = urlsplit(self.path)
		if url.path != "/inspect":
			self.send_error(404)
			return
		values = parse_qs(url.query, keep_blank_values=True).get("color", ["blue"])
		if len(values) != 1 or values[0] not in {"blue", "green"}:
			self.send_error(400, "Use one color: blue or green")
			return
		cookie = SimpleCookie()
		cookie.load(self.headers.get("Cookie", ""))
		session = cookie.get("lab_session")
		identity = "learner" if session and session.value == "learner" else "guest"
		body = json.dumps({"color": values[0], "identity": identity,
						   "method": "GET"}, sort_keys=True).encode("utf-8")
		self.send_response(200)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.send_header("Set-Cookie", "lab_session=learner; Path=/; HttpOnly; SameSite=Lax")
		self.end_headers()
		self.wfile.write(body)


class ExampleTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
		cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
		cls.thread.start()

	@classmethod
	def tearDownClass(cls):
		cls.server.shutdown()
		cls.server.server_close()
		cls.thread.join()

	def request(self, path, cookie="lab_session=learner"):
		connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
		try:
			connection.request("GET", path, headers={"Cookie": cookie})
			response = connection.getresponse()
			return response.status, response.read()
		finally:
			connection.close()

	def test_baseline_and_variant(self):
		for color in ("blue", "green", "blue"):
			status, body = self.request("/inspect?color=" + color)
			self.assertEqual(status, 200)
			self.assertEqual(json.loads(body), {"color": color, "identity": "learner",
												"method": "GET"})

	def test_guest(self):
		status, body = self.request("/inspect", "")
		self.assertEqual(status, 200)
		self.assertEqual(json.loads(body)["identity"], "guest")

	def test_invalid_color(self):
		self.assertEqual(self.request("/inspect?color=red")[0], 400)

	def test_missing_route(self):
		self.assertEqual(self.request("/missing")[0], 404)


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--serve", action="store_true")
	options = parser.parse_args()
	if options.serve:
		with ThreadingHTTPServer(("127.0.0.1", 8765), Handler) as server:
			print("Lab origin: http://127.0.0.1:8765/inspect?color=blue", flush=True)
			try:
				server.serve_forever()
			except KeyboardInterrupt:
				pass
	else:
		unittest.main(argv=[__file__], verbosity=2)
```

### Objectives and Steps

Commands for the learner, not an author execution record:

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 test_example.py --serve
```

1. Require four passing fixture tests before starting the manual server. Keep that server in its own terminal.
2. Open a fresh Burp project, record edition/build, check its loopback listener, set exact origin scope, and keep Intercept off. Do not enable scanning or automatic requests.
3. Open Burp's browser and visit `http://127.0.0.1:8765/inspect?color=blue` twice. The first request should be guest; the second should send the newly issued cookie and be learner. A favicon 404 is unrelated.
4. Send the second GET to Repeater; record baseline JSON. Duplicate the tab, change only `blue` to `green`, and send. Use Comparer on the two bodies.
5. Remove the cookie from a separate copy; inspect guest output. Restore it and repeat the original baseline. Keep this identity experiment separate from the color experiment.
6. In scope settings, verify a different hostname/port would not match, without browsing to any external host. Record that scope is not network enforcement.

### Hints

- If no history appears, confirm the browser belongs to this Burp instance and the listener is enabled. If requests hang, check the Intercept queue.
- A guest result with the intended cookie requires inspecting the actual request and session-handling rules. Do not add a real account to solve it.

### Solution and Expected Results

The color variant preserves `identity=learner`, `method=GET`, and status 200; only `color` changes. Removing the cookie produces `identity=guest`, also status 200. Restoring the baseline reproduces the first semantic body. Date headers may differ; compare parsed fields. Rejecting red with 400 and a missing route with 404 proves the fixture's deliberately narrow surface, not a security finding.

### Verification, Troubleshooting, and Cleanup

Expected automated count: **4 unittest tests**. Manual gates: visible Proxy entry, correct Repeater destination, stable-cookie color comparison, separate guest comparison, and baseline retest. Record the exact request and the three JSON results; no screenshot alone substitutes for these values.

If 8765 or the proxy port is occupied, stop this exercise and choose an unused port consistently in server, scope, URL, and Repeater; do not terminate an unknown owner. Stop the origin with Ctrl+C, close the lab browser/project, remove synthetic exports and the temporary directory, and restore only proxy settings changed for this exercise. No CA cleanup is needed here.

Author validation: content review only, **not executed**. Burp UI labels, browser behavior, and the four tests require learner verification on the recorded build.

- [ ] Local Burp Suite exercise: Complete the localhost capture, stable-session color comparison, and baseline retest.
- [ ] Boundary check: Confirm exact-host/port scope and keep evidence limited to synthetic traffic.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]
- [[Burp Workflow]]

## References

- [Burp desktop documentation](https://portswigger.net/burp/documentation/desktop)
- [Proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy)
- [Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater)
- [Scope](https://portswigger.net/burp/documentation/desktop/getting-started/setting-target-scope)
- [Session handling](https://portswigger.net/burp/documentation/desktop/settings/sessions)
- [Comparer](https://portswigger.net/burp/documentation/desktop/tools/comparer)
