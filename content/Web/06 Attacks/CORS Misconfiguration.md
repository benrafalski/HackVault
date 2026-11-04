---
title: "CORS Misconfiguration"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# CORS Misconfiguration

> [!abstract] TL;DR
> A CORS misconfiguration grants an unintended origin permission to read a response through browser script, potentially with ambient credentials.

> [!info] Agent scope
> Origin reflection; credentialed reads; null origin; allowlist parsing; preflight; distinction from CSRF and server-side access control.

## Learn

```text
Teach CORS misconfiguration at expert depth, assuming origins, HTTP headers,
fetch, sessions, and shared caches. Trace the Fetch CORS protocol: safelisted
requests, preflight, actual response, credentials mode, exposed headers, and
preflight caching. Distinguish sending a request from reading its response.
Explain origin reflection, null/opaque origins, exact serialized-origin lists,
scheme/port differences, credential rules, and Vary interactions. Separate
browser CORS policy from server authentication, authorization, and CSRF.
Review a secure header builder with synthetic allowed/denied origins and method
and header validation. Explain browser-only claims an offline test cannot prove.
Cite the Fetch Standard and framework documentation; give review questions and
answers. No exploit pages, bypasses, data theft, scanning, or chained attacks.
Teach rather than author files; do not invent executions or measurements.
```

## Cheatsheet

> [!important] Defensive scope
> This is a header-construction and policy-review lab, not a cross-origin data access demonstration. All origins use reserved example names; no requests are sent.

### Mechanism and Prerequisites

CORS governs when a browser exposes a cross-origin response to script. A harmful grant requires an unintended origin, a response worth protecting, and appropriate authority/credential behavior. Intentionally public data may legitimately use `Access-Control-Allow-Origin: *` without credentials. A server returning a permissive header is not by itself proof of private data exposure.

| Decision | Correct rule | Common mistaken inference |
|---|---|---|
| Origin grant | One exact allowed serialized origin, or `*` for appropriate public resources | A comma-separated origin list is not the response syntax |
| Credentials | Explicit origin plus `Access-Control-Allow-Credentials: true` when needed | `*` does not authorize credentialed response reads |
| Preflight | Validate requested method and non-safelisted header names | OPTIONS success does not authorize the actual operation |
| Actual response | Include the applicable CORS headers independently | Preflight headers alone do not make a response readable |
| Cache variation | Merge `Origin` into existing `Vary` when response depends on it | Replacing `Vary` can lose content-negotiation dimensions |
| `null` Origin | Deny unless a narrowly justified design requires it | It is a serialized opaque origin, not a trusted local identity |

An origin is a scheme/host/port tuple, not a URL path. Maintain reviewed serialized strings rather than substring or registrable-domain matching. Account for default port serialization in configuration. Do not parse a supplied Origin as a general URL and silently accept extra components. A missing Origin is a different request category, not permission to grant all origins.

### Worked Response and Limits

For a permitted credentialed caller:

```http
Access-Control-Allow-Origin: https://ui.example
Access-Control-Allow-Credentials: true
Vary: Accept-Encoding, Origin
Cache-Control: private, no-store
```

Only expose response headers required by the client with `Access-Control-Expose-Headers`; this does not expose protected cookie headers. Preflight requests generally do not carry the user's credentials, so placing ordinary session authentication ahead of all OPTIONS handling can break valid browsers. The actual request must still be authenticated and authorized. Keep preflight max-age short enough for policy changes; browser caps and preflight-cache behavior differ by version.

Evidence: record Origin, method, requested header names, returned grant, credential mode, cache policy, and actual browser visibility. Redact tokens and response bodies. A nonbrowser HTTP client does not enforce CORS. A denied browser read does not prove a write was prevented. A trusted origin compromised by script remains trusted by this policy.

## Defense

Centralize the origin list, use minimal methods and headers, and apply policy consistently to errors as well as successful responses. Keep server authorization and CSRF controls separate. Avoid broad credentials permissions merely to solve a frontend error. Test CDN and application header composition after upgrades; multiple conflicting CORS layers can produce invalid responses.

## Labs

### Environment and Objectives

Python 3.12 stdlib, one file, no browser/server/packages. Review a proposal that echoes any Origin and allows all request headers. The supplied replacement constructs only approved grants and preserves cache variation. The names and preflight metadata below are the complete synthetic dataset.

### File: test_example.py

```python
import unittest


ALLOWED_ORIGINS = {"https://ui.example"}
ALLOWED_METHODS = {"GET", "POST"}
ALLOWED_HEADERS = {"content-type", "x-csrf-token"}


def cors_headers(origin, requested_method=None, requested_headers=()):
	result = {"Vary": "Accept-Encoding, Origin", "Cache-Control": "private, no-store"}
	if origin not in ALLOWED_ORIGINS:
		return result
	if requested_method is not None:
		if requested_method not in ALLOWED_METHODS:
			raise PermissionError("method")
		names = {name.lower() for name in requested_headers}
		if not names <= ALLOWED_HEADERS:
			raise PermissionError("headers")
		result["Access-Control-Allow-Methods"] = requested_method
		if names:
			result["Access-Control-Allow-Headers"] = ", ".join(sorted(names))
		result["Access-Control-Max-Age"] = "300"
	result["Access-Control-Allow-Origin"] = origin
	result["Access-Control-Allow-Credentials"] = "true"
	return result


class CorsTests(unittest.TestCase):
	def test_actual_response(self):
		headers = cors_headers("https://ui.example")
		self.assertEqual(headers["Access-Control-Allow-Origin"], "https://ui.example")
		self.assertNotIn("Access-Control-Allow-Methods", headers)
		self.assertIn("Accept-Encoding", headers["Vary"])

	def test_denied_origins(self):
		for origin in [None, "null", "http://ui.example", "https://other.example",
					   "https://ui.example:8443"]:
			with self.subTest(origin=origin):
				headers = cors_headers(origin)
				self.assertNotIn("Access-Control-Allow-Origin", headers)
				self.assertNotIn("Access-Control-Allow-Credentials", headers)
				self.assertIn("Origin", headers["Vary"])

	def test_preflight(self):
		headers = cors_headers("https://ui.example", "POST", ["X-CSRF-Token"])
		self.assertEqual(headers["Access-Control-Allow-Headers"], "x-csrf-token")
		self.assertEqual(headers["Access-Control-Allow-Methods"], "POST")

	def test_rejected_capabilities(self):
		with self.assertRaises(PermissionError):
			cors_headers("https://ui.example", "DELETE")
		with self.assertRaises(PermissionError):
			cors_headers("https://ui.example", "POST", ["X-Admin-Mode"])


if __name__ == "__main__":
	unittest.main()
```

### Commands and Hints

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on non-Windows systems. Hint: distinguish the actual response branch from the preflight branch. Does denial still preserve `Vary`? Does any branch grant a wildcard with credentials?

### Separate Solution, Expected Observations, and Cleanup

Expected: four tests pass; only the configured HTTPS origin receives a grant; denied origins get neither credential nor origin permission; supported preflight headers are normalized. The code assumes a framework has already parsed header names as strings. It is not a server authorization gate and is not a general HTTP parser.

Run from the directory containing the file. Do not name it `unittest.py`. Remove that disposable directory after review; there is no external state. Tests were not run during authoring. Actual browser Fetch enforcement, OPTIONS routing, and CDN behavior remain integration checks, not claims established here.

- [ ] Local CORS Misconfiguration exercise: Review the exact-origin and preflight policy.
- [ ] Boundary check: Run secure grant/denial and cache-variation regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Fetch Standard: CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [RFC 9111: HTTP caching](https://www.rfc-editor.org/rfc/rfc9111)
- [Starlette CORSMiddleware documentation](https://www.starlette.io/middleware/#corsmiddleware)
