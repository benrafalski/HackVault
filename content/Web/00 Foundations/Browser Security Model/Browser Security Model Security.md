---
title: "Browser Security Model Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[Browser Security Model]]"
updated: 2026-11-03
---
# Browser Security Model Security

> [!abstract] TL;DR
> Enforce each boundary where it belongs: server authorization and CSRF controls for actions, CORS for browser reads, cookie attributes for credential handling, CSP for resource execution, and frame/message policies for embedding and communication.

## Attack Surface

Same-site subdomains may be cross-origin and differently trusted. Browsers automatically attach eligible cookies, allow some cross-origin sends, and isolate many reads. An application that equates CORS failure with request prevention or trusts every same-site actor is missing an independent control.

## Learn

```text
Teach me browser-boundary defense using synthetic data only. Explain origin
versus schemeful site, CORS allowlists/credentials/cache variation, independent
CSRF and authorization decisions, cookie prefix/attribute limits, CSP enforcing
versus report-only policies, sandbox tokens, frame-ancestors, postMessage and
secure-context restrictions. Give a complete benign loopback CSP hardening lab:
baseline marker, fixed policy, retained approved script, header tests and manual
browser evidence. Add offline policy tests for CORS and action authorization,
not credential theft, exploitation or bypass. Explain supported-browser/version
differences and what a non-browser unit test cannot prove. Cite primary sources;
teach here, do not edit files or fabricate results. End with worked decisions.
```

## Cheatsheet

### Independent Controls

| Risk | Required control | Common false assurance |
|---|---|---|
| Cross-origin script reads | Exact registered Origin allowlist; explicit credential policy | Reflecting any Origin or accepting all `null` origins |
| Unwanted authenticated action | Per-action authorization plus CSRF defense for cookie-authenticated mutations | Assuming CORS blocks simple forms/requests |
| Session cookie disclosure | HTTPS, Secure, HttpOnly, narrow host scope | Assuming HttpOnly prevents authenticated actions by script |
| Cross-site credential sending | Explicit SameSite plus action policy | Treating same-site as same-origin |
| Unwanted script execution | Contextual output handling and tested CSP | CSP as a substitute for safe DOM/template APIs |
| Unwanted embedding | CSP frame-ancestors; compatible legacy policy if needed | frame-src, which controls frames loaded by your page instead |
| Untrusted embedded activity | Separate origin and minimal iframe sandbox grants | Combining powerful sandbox tokens without origin analysis |

For cookie-authenticated mutations, validate authorization, request method, a session-bound unpredictable CSRF token and appropriate Origin/Referer or Fetch Metadata signals under an explicit compatibility policy. These signals complement each other; non-browser clients can supply Origin. Fetch Metadata is not authentication. SameSite is defense in depth, including browser-specific defaults and top-level navigation exceptions. Do not put CSRF tokens in URLs or logs.

### Concrete Response Policy

For a small static application with external same-origin scripts and no forms/frames:

```http
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

This is a starting contract, not universal policy. Required CDNs, images, fonts, forms and API destinations need deliberate directives. Avoid broadening script-src with unsafe-inline just to silence errors. A nonce policy permits exact response-authorized script elements; generate a new unpredictable nonce per response and propagate it safely. CSP hashes require exact script bytes. Strict-dynamic changes trust propagation for supported browsers; test actual browser versions before adopting it.

`frame-ancestors` must be delivered in an HTTP policy header; a meta tag does not enforce it. Report-Only does not block. Multiple CSP headers apply together and can unexpectedly make a legitimate resource fail. CSP reports are untrusted telemetry and can contain URLs; redact and rate-limit collection.

Production session cookie:

```http
Set-Cookie: __Host-session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/
```

No Domain means host-only, but cookies still lack port isolation. SameSite=None requires Secure in modern browsers and does not override third-party-cookie restrictions. Partitioned cookies and newer prefixes/features need browser compatibility checks; do not infer availability from HTTPS alone.

### Frames, Messages, and Secure Contexts

Prefer separate origins for untrusted documents. Start iframe sandbox with no permissions; add only requirements. Same-origin content with both allow-scripts and allow-same-origin can undermine sandbox assumptions. For postMessage, use an exact targetOrigin, compare event.origin and event.source against expected values, validate a small schema and ignore unknown operations. Origin `null` covers multiple opaque-origin situations and is not a unique trusted identity.

Secure context qualification is necessary for many APIs but does not replace permissions, consent, SOP or authorization. Mixed content may be blocked or upgraded depending on resource type/browser. Loopback exceptions are for development, not evidence that plaintext remote HTTP is secure. Navigation, resource display, and response/DOM reading are separate capabilities.

## Detection and Defense

Track server action denials, CORS grant decisions, CSRF failures, unexpected embedding, CSP violations and cookie attribute drift. Browser extensions and privacy tools can cause legitimate blocks; retain browser version and a clean-profile reproduction. No server header assertion alone proves that a browser enforced CSP or SameSite. Use both configuration tests and manual/browser automation evidence, without real accounts or secrets.

## Labs

### Environment and Complete Files

Python 3.12+, current browser and a disposable profile. No packages. Unit tests use an ephemeral loopback port; optional manual mode binds 127.0.0.1:8770. Two pages contain the same benign inline marker and approved external script. The hardened page prohibits inline execution but retains the external script. There are no forms, accounts or mutation endpoints.

### File: test_example.py

```python
import http.client
import secrets
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


POLICY = ("default-src 'none'; script-src 'self'; base-uri 'none'; "
		  "object-src 'none'; form-action 'none'; frame-ancestors 'none'")
PAGE = b'''<!doctype html><meta charset="utf-8"><title>CSP policy lab</title>
<p id="inline">inline: not run</p><p id="external">external: not run</p>
<script>document.getElementById('inline').textContent = 'inline: ran';</script>
<script src="/approved.js"></script>'''
APPROVED = b"document.getElementById('external').textContent = 'external: ran';"


def cors_origin(origin):
	return origin if origin == "https://app.example.test" else None


def action_allowed(role, origin, token, expected):
	return (role == "editor" and origin == "https://app.example.test"
			and bool(expected) and secrets.compare_digest(token, expected))


class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path not in {"/baseline", "/hardened", "/approved.js"}:
			self.send_error(404)
			return
		script = self.path == "/approved.js"
		body = APPROVED if script else PAGE
		self.send_response(200)
		self.send_header("Content-Type", "text/javascript" if script else "text/html; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.send_header("X-Content-Type-Options", "nosniff")
		if self.path == "/hardened":
			self.send_header("Content-Security-Policy", POLICY)
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


class BrowserPolicyTests(unittest.TestCase):
	def test_header_baseline_and_fix(self):
		with serve() as port:
			for path, policy in (("/baseline", None), ("/hardened", POLICY)):
				connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
				try:
					connection.request("GET", path)
					response = connection.getresponse()
					self.assertEqual(response.getheader("Content-Security-Policy"), policy)
					self.assertEqual(response.read(), PAGE)
				finally:
					connection.close()

	def test_cors_is_not_action_authorization(self):
		origin = "https://app.example.test"
		self.assertEqual(cors_origin(origin), origin)
		self.assertIsNone(cors_origin("null"))
		self.assertIsNone(cors_origin("https://other.example.test"))
		self.assertTrue(action_allowed("editor", origin, "synthetic", "synthetic"))
		self.assertFalse(action_allowed("reader", origin, "synthetic", "synthetic"))
		self.assertFalse(action_allowed("editor", origin, "missing", "synthetic"))
		self.assertFalse(action_allowed("editor", "https://other.example.test",
										"synthetic", "synthetic"))


if __name__ == "__main__":
	if sys.argv[1:] == ["--serve"]:
		with serve(8770):
			print("Open http://127.0.0.1:8770/baseline and /hardened; Ctrl+C stops.")
			try:
				threading.Event().wait()
			except KeyboardInterrupt:
				pass
	else:
		unittest.main()
```

### Objectives and Baseline

1. Run `python -m unittest -v test_example`. The tests verify server output and a synthetic policy function, not browser execution.
2. Run `python test_example.py --serve`; visit `/baseline` then `/hardened` at the printed loopback origin in a clean browser profile.
3. Record both text markers and Console/Network evidence. The page content is identical; only the enforcing header changes.
4. Explain why a CORS grant in the offline test does not grant the reader role permission to perform an editor action.

### Hints

`script-src 'self'` permits `/approved.js` but not inline script. The test token is a synthetic constant, not an example of production token generation or session binding. The policy function assumes typed ASCII token inputs; a real API validates schema first.

### Solution and Fixed Retest

Expected unit result: two tests pass. Baseline browser page shows both markers ran. Hardened page shows `inline: not run` and `external: ran`; Console reports the blocked inline script and Network shows the external script loaded. This is a hardening comparison using harmless local code, not an injection exercise. Authorized editor with matching synthetic token passes; a CORS-allowed reader still fails authorization. Revisit the hardened page after changes and confirm the permitted external script remains functional.

### Verification, Troubleshooting, and Cleanup

Author did not execute tests or open a browser. Optional runner: `python -m pytest -q test_example.py`. If markers do not differ, inspect the actual CSP response header, path and clean-profile extensions; Report-Only would not enforce. If the port is occupied, choose an unused port in manual mode and use its URL. Ctrl+C stops the server; delete the disposable profile/site data, file and caches. No trust store or global browser setting is changed.

- [ ] Record benign baseline and hardened browser markers.
- [ ] Distinguish CORS, CSRF, authorization, cookie and CSP controls.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[CORS Misconfiguration]]
- [[CSRF]]
- [[XSS]]
- [[Clickjacking]]
- [[Browser Security Model]]

## References

- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [Fetch Standard](https://fetch.spec.whatwg.org/)
- [HTML sandboxing](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
