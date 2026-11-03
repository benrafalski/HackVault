---
title: "HTTP/1.1 Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[HTTP]]"
updated: 2026-11-03
---
# HTTP/1.1 Security

> [!abstract] TL;DR
> Every hop must agree on framing, authority, and request identity. Reject ambiguity before reuse or translation, constrain public authorities, and derive sensitive absolute URLs from trusted configuration.

## Attack Surface

Clients control methods, request targets, most fields and content. Proxies add routing and identity metadata, pool connections, and sometimes cache responses. A backend must know which hop supplied trusted fields; neither a private source IP nor an established connection grants end-user authorization.

## Learn

```text
Teach me defensive HTTP/1.1 engineering from parsed request to proxy/origin
behavior. Explain framing disagreement, duplicate fields, Host/authority trust,
forwarded headers, method authorization, redirect credential policy, cache
boundaries, body/time limits and persistent-connection error handling. Supply
strict ingress policy, trusted-origin construction and regression tests using
synthetic parsed metadata only. Show baseline policy failure, a fix and retained
legitimate behavior, without exploit payloads or network desynchronization.
Distinguish RFC rules from stricter application policy and version-dependent
proxy defaults. Cover logs, false positives and error response decisions.
Use primary sources; teach here without editing files or inventing test results.
```

## Cheatsheet

### Framing and Translation Contract

| Ingress condition | Defensive action | Reason |
|---|---|---|
| Transfer-Encoding plus Content-Length | Reject and close under strict policy | Do not forward two competing length interpretations |
| Conflicting or malformed lengths | Reject before dispatch | No trustworthy next-message boundary |
| Repeated identical lengths | RFC has constrained recovery rules; strict API can reject all repeats | Document stricter policy and test all hops |
| Invalid field syntax / obsolete folding | Reject or handle only as prescribed by RFC | Do not normalize differently at edge and origin |
| Incomplete body / timeout | Abort; do not return uncertain connection to pool | Remaining bytes may belong to failed request |
| Unsupported transfer coding | Reject appropriately | Do not assume an unimplemented decoder is safe |

Use maintained server/proxy parsers. Application middleware sees already-parsed metadata and cannot repair bytes the edge interpreted differently. Enforce body and header limits at the earliest capable layer, plus total deadline and concurrency budget; Content-Length limits alone miss streamed bodies and decompression expansion. Close or reset the affected connection/stream after framing errors according to the protocol implementation.

### Identity, Methods, and Headers

An allowlist should match the parsed authority including permitted port policy. Sensitive URLs should use a configured base such as `https://app.example.test`, not arbitrary Host or X-Forwarded-Host. In a multiple-tenant service, map a validated tenant authority to registered configuration before generating links. Duplicate Host fields are not a tenant selection mechanism.

Forwarded identity is trusted only if the immediate peer is a configured proxy, direct backend access is constrained, and the proxy strips/overwrites inbound claims. A chain's right/left entry interpretation must match the proxy topology. Never authorize a user solely from X-Forwarded-For. Remove hop-specific Connection fields and all nominated fields before forwarding; do not blindly copy header dictionaries.

| Application decision | Correct boundary |
|---|---|
| Method permitted | Explicit route-method mapping; 405 with Allow for unsupported methods |
| Identity authenticated | 401 and suitable challenge where applicable |
| Action authorized | Resource/action check on each request; 403 or deliberate 404 concealment |
| HEAD handling | Same access checks as GET, no response body |
| Cacheable response | Explicit public/private/no-store policy and correct Vary |
| Redirect destination | Approved scheme/authority or controlled local target; limit hops |

307/308 preserve a request body; a redirect is therefore also a data-disclosure and replay decision. 301/302 behavior for POST is historically variable; 303 is the deliberate retrieve-result pattern. Do not replay Authorization to a different authority. Safe/idempotent methods describe semantics, not permissions; a DELETE needs authorization even if repeating it changes nothing further.

Concrete configured-origin fragment:

```python
from urllib.parse import urlencode
PUBLIC_ORIGIN = "https://app.example.test"
status_url = PUBLIC_ORIGIN + "/status?" + urlencode({"ticket": "synthetic-17"})
```

For user-specific sensitive responses, `Cache-Control: no-store` prevents storage by conforming caches; it does not erase logs or screenshots. `Vary: Origin` is required when cacheable CORS responses vary by origin. `Set-Cookie` needs its own handling and must not be blindly folded.

## Detection and Defense

Correlate trusted edge request IDs with origin IDs, method, normalized route, status, body-byte counts, parser rejection reason and timeout stage. Do not log raw Authorization, cookies or full sensitive queries. Repeated 400s can be buggy clients, probes or proxy mismatch; compare firmware/client versions and edge/origin counts. Monitor configuration drift and supported security updates, not only obvious error spikes. Shared technique notes provide broader context without being required by this lab.

## Labs

### Environment and Complete Files

Python 3.12+, standard library; offline metadata only. This intentionally narrow API accepts GET/HEAD/POST, explicit approved authority, no transfer coding, and at most one decimal length up to 4096. It is not a wire parser or a general HTTP conformance implementation.

### File: test_example.py

```python
import unittest
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True)
class Request:
	method: str = "GET"
	authority: str = "app.example.test"
	lengths: tuple = ()
	transfer_codings: tuple = ()


def admissible(request):
	if request.method not in {"GET", "HEAD", "POST"}:
		return False
	if request.authority != "app.example.test":
		return False
	if request.transfer_codings or len(request.lengths) > 1:
		return False
	if request.lengths:
		length = request.lengths[0]
		if not isinstance(length, str) or not length.isascii() or not length.isdecimal():
			return False
		if len(length) > 4 or int(length) > 4096:
			return False
	return True


def link(ticket):
	return "https://app.example.test/status?" + urlencode({"ticket": ticket})


class HTTPPolicyTests(unittest.TestCase):
	def test_authority_baseline_and_fix(self):
		incoming = Request(authority="other.example.test")
		baseline = "https://" + incoming.authority + "/status"
		self.assertEqual(baseline, "https://other.example.test/status")
		self.assertFalse(admissible(incoming))
		self.assertEqual(link("synthetic 17"),
						 "https://app.example.test/status?ticket=synthetic+17")
		self.assertTrue(admissible(Request()))

	def test_framing_policy(self):
		self.assertTrue(admissible(Request(method="POST", lengths=("4096",))))
		for request in (Request(lengths=("4097",)), Request(lengths=("2", "2")),
						Request(lengths=("-1",)), Request(lengths=("2",),
						transfer_codings=("chunked",)), Request(method="DELETE")):
			with self.subTest(request=request):
				self.assertFalse(admissible(request))

	def test_head_retains_authorization(self):
		grants = {("reader", "GET"), ("reader", "HEAD")}
		self.assertIn(("reader", "HEAD"), grants)
		self.assertNotIn(("anonymous", "HEAD"), grants)
		self.assertNotIn(("reader", "POST"), grants)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run `python -m unittest -v test_example`; explain why host-derived output is unsafe as a trust policy even with syntactically valid text.
2. Identify which rejections are a deliberately strict API profile rather than universally invalid HTTP.
3. Temporarily remove the authority condition; the negative assertion must fail. Restore it and retest.
4. Add a permitted zero-length POST and a rejected nondecimal length case without constructing or sending malformed HTTP bytes.

### Hints

Repeated identical Content-Length rejection and rejection of all transfer coding are stricter than general protocol support. A model's authority is already parsed and canonicalized; real parsers must establish that invariant first.

### Solution and Fixed Retest

Expected: three tests pass. The configured-origin link stays on `app.example.test`, allowed traffic remains accepted, ambiguous metadata is rejected, and HEAD does not become an authorization exception. The authority mutation fails the existing negative assertion. Deployment evidence must additionally come from the real edge parser/configuration and correlation of accepted request metadata across hops; this lab does not certify those components.

### Verification, Troubleshooting, and Cleanup

No commands executed by the author. Optional pytest: `python -m pytest -q test_example.py`. No service or privileged operation is needed. A failing strict-policy case may reflect an intentional business change; update the contract and edge configuration together, not just the assertion. Delete the lab directory and caches.

- [ ] Record authority and framing baseline/fixed policy results.
- [ ] Explain authorization, redirects and connection-reuse error handling.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Request Smuggling]]
- [[Host Header Attacks]]
- [[HTTP]]

## References

- [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
- [HTTP/1.1 parsing and security, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
- [HTTP caching, RFC 9111](https://www.rfc-editor.org/rfc/rfc9111)
