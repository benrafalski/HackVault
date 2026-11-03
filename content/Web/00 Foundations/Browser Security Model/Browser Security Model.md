---
title: "Browser Security Model"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[Browser Security Model Security]]"
updated: 2026-11-03
---
# Browser Security Model

> [!abstract] TL;DR
> Origin, site, credentials, resource loading, and script access are different boundaries. CORS controls selected cross-origin reads; it is neither authentication nor a general prohibition on cross-origin requests.

## Prerequisites

[[HTTP]], [[URLs and Encoding]], and [[TLS and PKI]]. Lab: Python 3.12+ and a current browser in a disposable profile. No external service or Python packages.

## Learn

```text
Teach me the browser security model with origins, schemeful sites and ambient
credentials as separate concepts. Explain SOP reads versus navigations/forms/
subresources, CORS simple and preflight requests, credential mode, caches and
opaque responses. Cover cookie Domain/Path/Secure/HttpOnly/SameSite, partitioning,
CSP directives/nonces, sandboxed frames, opaque origins, postMessage validation
and secure contexts. Provide a complete two-loopback-origin fixture with
benign data, exact browser observations and independent server-header tests.
Do not treat curl or Python clients as browser policy enforcement. Distinguish
standard rules from current browser defaults and privacy policies. Cite primary
specifications and MDN. Teach here without file edits or fabricated results;
finish with worked origin/site and request-versus-read questions.
```

## Cheatsheet

### Origin, Site, and Access

An origin is `(scheme, host, effective port)`. `https://app.example.test` and `https://api.example.test` are cross-origin but usually same-site. A schemeful site is scheme plus registrable domain (with public-suffix rules), or an appropriate host-based boundary for IP/localhost cases; ports are not part of site. Do not derive a registrable domain by taking the final two labels. Opaque origins, such as a sandboxed document without allow-same-origin, are not ordinary scheme/host tuples; serialization can be `null`.

| Browser action | Typical cross-origin behavior | Separate check |
|---|---|---|
| Top-level navigation | Generally permitted, subject to navigation policy | Does not grant opener DOM read access |
| Form submission | Can send cross-origin requests | Server must prevent unwanted authenticated mutations |
| Image/script/style loading | Often possible with type-specific rules | CSP, CORP, MIME checks and execution context |
| Fetch response read | SOP/CORS applies | Request may have reached server even when read is blocked |
| Cross-origin frame DOM | Restricted | `postMessage` is explicit communication, not shared DOM |
| Canvas pixel read after foreign image | Can be tainted without suitable CORS | Display permission differs from pixel read permission |

`fetch(..., {mode:"no-cors"})` yields an opaque response for cross-origin use: status 0 and unreadable content to script. It does not grant CORS permission. JavaScript controls cannot inspect every network error detail; DevTools and server logs provide different evidence.

### CORS and Credentials

For eligible simple requests, the browser may send first and check the response's Access-Control-Allow-Origin before exposing it. Non-safelisted methods/headers/content types normally require an OPTIONS preflight with Origin, Access-Control-Request-Method and possibly Access-Control-Request-Headers. A successful preflight authorizes a request shape, not user access to a resource. Preflight caching is distinct from ordinary HTTP caching.

Credentialed readable response example for one registered origin:

```http
Access-Control-Allow-Origin: https://app.example.test
Access-Control-Allow-Credentials: true
Vary: Origin
```

Use the exact origin, not `*`, when credentials are included. `fetch` defaults to same-origin credentials; cross-origin cookies require `credentials:"include"` and still obey cookie policy. `Access-Control-Expose-Headers` exposes selected non-safelisted response fields; Set-Cookie is never script-readable through fetch headers. A server reflecting any incoming Origin is not an allowlist. Cache varied responses with `Vary: Origin` to avoid mixing grants.

### Cookies and Other Controls

| Attribute/control | What it provides | What it does not provide |
|---|---|---|
| Host-only cookie (no Domain) | Restricts host matching | Port isolation; cookies are not port-scoped |
| Path | Selects matching request paths | A robust same-origin isolation boundary |
| Secure | Secure transport sending policy | Encryption after TLS termination |
| HttpOnly | Blocks document.cookie access | Prevention of script-initiated authenticated requests |
| SameSite=Lax/Strict | Restricts selected cross-site sending | Same-origin authorization or complete CSRF protection |
| SameSite=None; Secure | Allows cross-site eligibility | Guaranteed third-party cookie availability |
| Partitioned | Partitioned cookie state where supported | Universal cross-browser behavior |

Production cookie example: `Set-Cookie: __Host-session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax`. The `__Host-` prefix requires Secure, Path=/ and no Domain in supporting browsers. SameSite defaults and privacy restrictions vary; explicit attributes and browser/version testing matter. Different loopback ports are cross-origin but cookies for the same host can be shared, which the lab intentionally demonstrates.

CSP restricts loading/execution according to directives, not all data flow. `default-src` is a fallback for fetch directives; `base-uri`, `form-action` and `frame-ancestors` need explicit consideration. Nonces must be unpredictable per response; hashes cover exact inline bytes. `script-src 'self'` does not permit inline script. Report-Only reports without enforcing. Multiple policies intersect rather than one simply replacing another.

A sandboxed iframe starts with substantial restrictions; tokens relax specific capabilities. `allow-scripts` permits scripts; `allow-same-origin` retains the document's origin. Combining both on same-origin untrusted content can undermine the intended isolation. Use a separate origin for untrusted active content. For postMessage, send to an exact targetOrigin and verify both event.origin and expected event.source, then validate data schema.

Secure contexts require a trustworthy origin and ancestor context. HTTPS and certain loopback origins qualify; `window.isSecureContext` is the actual observable signal. Qualification does not grant every permission or bypass user consent. Browser privacy protections, mixed-content rules and permissions policies are additional independent gates.

## Gotchas

HTTP clients outside the browser do not enforce SOP/CORS. A denied CORS read is not proof of no server-side effect. Origin is not guaranteed on every request and `null` must not be universally trusted. Localhost exceptions should not become production cookie policy.

## Labs

### Environment and Complete Files

Save this file in a disposable directory. Unit tests use an ephemeral IPv4 loopback port and benign GETs. Manual mode binds only 127.0.0.1 ports 8765/8766 and serves synthetic text, no mutation endpoints. The lab cookie omits Secure solely for this HTTP loopback exercise; production needs HTTPS and Secure.

### File: test_example.py

```python
import http.client
import json
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


ORIGIN = "http://127.0.0.1:8765"
PAGE = b'''<!doctype html><meta charset="utf-8"><title>Origin lab</title>
<button id="run">Run observations</button><pre id="out"></pre>
<script src="/app.js"></script>'''
SCRIPT = br'''document.querySelector('#run').onclick = async () => {
  const lines = [];
  const base = 'http://127.0.0.1:8766';
  await fetch('/cookie');
  for (const path of ['/data', base + '/data', base + '/allowed']) {
	try {
	  const response = await fetch(path, {credentials: 'include'});
	  lines.push(path + ' => ' + await response.text());
	} catch (error) { lines.push(path + ' => browser blocked read'); }
  }
  lines.push('document.cookie=' + document.cookie);
  lines.push('secureContext=' + window.isSecureContext);
  document.querySelector('#out').textContent = lines.join('\n');
};'''


class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		path = urlsplit(self.path).path
		content_type = "application/json"
		body = json.dumps({"marker": "synthetic", "cookie_received":
						   "lab_marker=synthetic" in self.headers.get("Cookie", "")}).encode()
		if path == "/":
			body, content_type = PAGE, "text/html; charset=utf-8"
		elif path == "/app.js":
			body, content_type = SCRIPT, "text/javascript"
		self.send_response(200)
		self.send_header("Content-Type", content_type)
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		if path == "/cookie":
			self.send_header("Set-Cookie", "lab_marker=synthetic; Path=/; HttpOnly; SameSite=Lax")
		if path == "/allowed":
			self.send_header("Vary", "Origin")
			if self.headers.get("Origin") == ORIGIN:
				self.send_header("Access-Control-Allow-Origin", ORIGIN)
				self.send_header("Access-Control-Allow-Credentials", "true")
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, format, *args):
		pass


@contextmanager
def serve(port=0):
	server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
	worker = threading.Thread(target=server.serve_forever, daemon=True)
	worker.start()
	try:
		yield server.server_port
	finally:
		server.shutdown()
		server.server_close()
		worker.join(timeout=3)


class BrowserFixtureTests(unittest.TestCase):
	def test_header_contract(self):
		with serve() as port:
			for path, origin, expected in (("/data", ORIGIN, None),
											("/allowed", ORIGIN, ORIGIN),
											("/allowed", "http://127.0.0.1:9999", None)):
				connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
				try:
					connection.request("GET", path, headers={"Origin": origin})
					response = connection.getresponse()
					self.assertEqual(response.getheader("Access-Control-Allow-Origin"), expected)
					self.assertEqual(json.loads(response.read())["marker"], "synthetic")
				finally:
					connection.close()


if __name__ == "__main__":
	if sys.argv[1:] == ["--serve"]:
		with serve(8765), serve(8766):
			print("Open http://127.0.0.1:8765/ in a disposable browser profile; Ctrl+C stops.")
			try:
				threading.Event().wait()
			except KeyboardInterrupt:
				pass
	else:
		unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`. This verifies the server's CORS header contract only.
2. Run `python test_example.py --serve`; open `http://127.0.0.1:8765/` in a clean browser profile, open Network/Console, then select Run observations.
3. Compare same-origin `/data`, cross-origin `/data`, and cross-origin `/allowed`. Inspect Network to distinguish a completed request from an exposed response.
4. Inspect the lab cookie in browser storage, the rendered document.cookie line, and `cookie_received` in the allowed response. Compare `window.isSecureContext` with the HTTP loopback origin.

### Hints

Use exactly 127.0.0.1, not localhost, or the allowlisted origin differs. Same host with different ports is cross-origin but does not partition cookies by port. DevTools can inspect HttpOnly cookies even though page script cannot.

### Solution and Expected Results

Expected unit result: one test with three cases passes. Expected browser result: same-origin read succeeds, cross-origin `/data` read fails, and `/allowed` succeeds with explicit credentialed CORS. The failed read can still appear as a successful server response in Network. The synthetic HttpOnly cookie is absent from document.cookie but sent to matching host/path; it can be sent across these ports. Modern browsers normally classify loopback as trustworthy; record the actual isSecureContext value and version. No preflight is required for these simple GETs.

### Verification, Troubleshooting, and Cleanup

Not executed during authoring; browser enforcement remains unverified. Optional unit runner: `python -m pytest -q test_example.py`. Occupied ports: stop only your previous fixture or choose two unused ports and update ORIGIN, SCRIPT and manual binds together. Privacy tools/extensions can alter observations; use a clean profile. Ctrl+C stops both servers; clear the lab cookie/site data and delete the test directory/profile. Do not change global proxy, VPN or trust settings.

- [ ] Record request-versus-read evidence from both origins.
- [ ] Explain cookie visibility, origin/site and secure-context distinctions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[CORS Misconfiguration]]
- [[CSRF]]
- [[XSS]]
- [[Clickjacking]]
- [[Browser Security Model Security]]

## References

- [MDN same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
- [Fetch Standard: CORS](https://fetch.spec.whatwg.org/)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [Secure Contexts specification](https://w3c.github.io/webappsec-secure-contexts/)
