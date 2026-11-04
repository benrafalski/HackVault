---
title: "Clickjacking"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Clickjacking

> [!abstract] TL;DR
> Clickjacking overlays or disguises a framed trusted interface so a user activates a control under a false visual context.

> [!info] Agent scope
> Frame-based UI redress; framing prerequisites; overlay variants; frame-ancestors; X-Frame-Options; lab evidence.

## Learn

```text
Teach clickjacking as a UI integrity failure, assuming frames, origins, cookies,
and HTTP response headers. Explain frameability, usable credentials, meaningful
actions, and user interaction as separate prerequisites. Discuss overlay,
multi-step, and drag/drop redress conceptually without construction instructions.
Compare CSP frame-ancestors, frame-src, X-Frame-Options, report-only policies,
all-ancestor checks, nested frames, and meta versus response delivery. Explain
SameSite and confirmation limits, legitimate embedding, legacy compatibility,
and why frame-busting scripts are not equivalent to browser enforcement.
Review a secure route-to-response-policy implementation and synthetic deployment
evidence. Include acceptance criteria and primary sources; ask review questions
with answers. No deceptive UI, exploit pages, bypasses, data theft, or live tests.
Teach, do not edit files or claim unexecuted browser checks succeeded.
```

## Cheatsheet

> [!important] Defensive scope
> This page reviews headers and synthetic incident records. There are no overlays, deceptive interactions, or live framing demonstrations.

### Mechanism and Prerequisites

The security boundary is the relationship between the user-visible context and the origin receiving an interaction. A page may be embeddable without a meaningful security impact: the relevant action, identity state, and interaction must also be available. Cookie restrictions can reduce authenticated frame usability but are not an embedding policy. Multi-step and drag/drop variants differ in interaction requirements, not in the need to protect UI integrity.

| Policy | Meaning | Important limitation |
|---|---|---|
| `frame-ancestors 'none'` | No ancestor may embed this response | Must be an enforced HTTP CSP response header |
| `frame-ancestors 'self'` | Every ancestor must match the page's origin | Same-origin embedding is intentionally allowed |
| Explicit ancestor origins | Permit reviewed embedding applications | All ancestors must qualify; trust their entire origin |
| `frame-src` | Controls frames loaded by this page | Does not control who embeds this page |
| `X-Frame-Options: DENY` | Legacy no-framing protection | Cannot express a modern multi-origin allowlist |
| `X-Frame-Options: SAMEORIGIN` | Legacy same-origin policy | Align with CSP and test supported legacy clients |

`frame-ancestors` does not fall back to `default-src` and is not supported through a meta CSP element. Report-only is observational, not enforcement. `ALLOW-FROM` is obsolete and not a portable solution. In CSP-capable browsers, an enforced `frame-ancestors` policy takes precedence over X-Frame-Options; old clients vary. Avoid conflicting policies and document the supported browser set rather than promising universal behavior.

### Worked Configuration and Evidence

Response fragment for pages that must never be embedded:

```http
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'
X-Frame-Options: DENY
```

Deliver on the final HTML response, including error/login paths and alternate hosts. A proxy may overwrite or omit headers on errors; configuration presence alone is insufficient. Multiple CSP headers are jointly enforced, not combined as a union of permissions. Route-specific embedding exceptions should be narrowly scoped and should not contain privileged account controls.

Useful evidence: final response URL and status, enforced versus report-only header name, ancestor origins, browser version, whether credentials were available, and whether a meaningful control could function. A screenshot of an empty frame alone cannot distinguish policy blocking from network or cookie failure. No header-only fixture proves browser behavior.

## Defense

Default to no embedding, allow same-origin or partner embedding only when required, and keep sensitive operations behind clear confirmation or reauthentication. Frame-busting JavaScript is not a robust replacement for response policy. CSRF tokens do not stop a user interacting with a legitimate framed application; they address a different boundary.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no services or browser automation. Review a synthetic deployment where `/account` has only report-only policy and `/error` has no framing policy. Decide which records need remediation; then test a secure response builder for all listed routes and statuses. This is a configuration review, not a browser simulator.

### File: test_example.py

```python
import unittest


EVIDENCE = [
	{"route": "/account", "status": 200, "delivery": "report-only"},
	{"route": "/error", "status": 500, "delivery": "absent"},
	{"route": "/help", "status": 200, "delivery": "enforced"},
]


def remediation_routes(records):
	return [record["route"] for record in records
			if record["delivery"] != "enforced"]


def response_headers(route, status):
	if route not in {"/account", "/error", "/help"}:
		raise ValueError("unknown route")
	if status not in {200, 401, 403, 404, 500}:
		raise ValueError("unsupported fixture status")
	return {
		"Content-Type": "text/html; charset=utf-8",
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
		"X-Frame-Options": "DENY",
	}


class FramingTests(unittest.TestCase):
	def test_incident_review(self):
		self.assertEqual(remediation_routes(EVIDENCE), ["/account", "/error"])

	def test_every_html_response(self):
		for route in ["/account", "/error", "/help"]:
			for status in [200, 401, 403, 404, 500]:
				with self.subTest(route=route, status=status):
					headers = response_headers(route, status)
					policy = headers["Content-Security-Policy"]
					self.assertIn("frame-ancestors 'none'", policy.split("; "))
					self.assertEqual(headers["X-Frame-Options"], "DENY")
					self.assertNotIn("Content-Security-Policy-Report-Only", headers)

	def test_unknown_route(self):
		with self.assertRaises(ValueError):
			response_headers("/unreviewed", 200)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: a correct directive in the wrong header is still not enforcement. Check error responses independently of successful responses.

Solution: both account and error routes require an enforced response policy; the secure builder applies it across the fixture status matrix. Expected: three tests pass, with fifteen route/status subcases. These assertions validate construction, not actual delivery through an intermediary or a browser's all-ancestor checks.

### Verification, Troubleshooting, and Cleanup

Authoring was static; no tests/browser checks ran. Work in the directory containing the named file. No external fixtures or dependencies are required. If adapting into an application, check that its exception middleware and proxy preserve these headers; do not broaden permissions merely to silence a browser error. Remove the disposable exercise directory afterward.

- [ ] Local Clickjacking exercise: Review synthetic framing-policy deployment evidence.
- [ ] Boundary check: Run secure response-header coverage regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [CSP Level 3: frame-ancestors](https://www.w3.org/TR/CSP3/#directive-frame-ancestors)
- [RFC 7034: X-Frame-Options](https://www.rfc-editor.org/rfc/rfc7034)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
