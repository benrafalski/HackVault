---
title: "Reverse Proxies CDN and WAF Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Reverse Proxies CDN and WAF]]"
updated: 2026-11-03
---
# Reverse Proxies CDN and WAF Security

> [!abstract] TL;DR
> Origin bypass, spoofed forwarding headers, parsing disagreement, and overconfidence in WAF rules can defeat edge controls.

> [!info] Agent scope
> Security of: Proxy chains; forwarded headers; CDN origins; WAF policy; routing; TLS termination; trust boundaries; origin access controls. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Origin bypass, spoofed forwarding headers, parsing disagreement, and overconfidence in WAF rules can defeat edge controls.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive reverse-proxy, CDN and WAF engineering at expert depth.
Assume HTTP and TLS knowledge. Map trust from public authority and client
connection through forwarded facts, origin TLS verification, origin identity,
router and application authorization. Explain configuration failures without
exploit or bypass instructions. Use NGINX OSS 1.28 reference semantics and
explicitly distinguish provider WAF/CDN features. Show concrete safe configs,
certificate and rule lifetimes, body-inspection limits, cache boundaries,
timeouts, logging and fail-open/fail-closed tradeoffs. Supply a complete offline
baseline/fix lab with harmless synthetic requests and retained allowed traffic.
Use primary sources; no real endpoints, credentials, public listeners, host
policy changes or file editing. Do not claim fixtures verify TLS or a live WAF.
```

## Cheatsheet

### Root Causes and Defensive Boundaries

The immediate TCP peer is transport evidence; a forwarding field is a claim. Only a configured trusted proxy may supply that claim, and the proxy must normalize it before forwarding. Trust-all CIDRs, fixed hop counts across variable-length paths and client-controlled external host/scheme are design defects. Application sessions remain responsible for user identity; address-based controls alone are insufficient.

| Baseline design defect | Concrete fix | What still needs proof |
|---|---|---|
| Origin accepts every network source | Private connectivity or scoped ingress plus authenticated CDN-origin path | The allowed identity belongs to your distribution, not just the provider |
| HTTPS upstream without verification | Enable chain/name verification and appropriate SNI | Trust store, renewal, expiry monitoring and reload work |
| Edge appends arbitrary incoming identity | Overwrite at first trust boundary; accept from known downstream peers only | Every alternate traffic path follows the same contract |
| All bodies assumed fully inspected | Route/body limits; explicit oversized-body action; allowlisted media types | Product inspection limits vary by integration and managed-rule version |
| Rule exclusions applied globally | Narrow method/path/content-type exclusions with owner and expiration | Legitimate requests still work and excluded paths have app defenses |
| Edge-only authentication | Origin independently requires the intended proxy path and app authorization | Cached responses do not accidentally cross identity boundaries |

Do not treat WAF availability as application authorization. For high-risk routes, reject requests if required validation cannot complete; document any availability-driven fail-open decision explicitly. A WAF `count`/logging mode records matches but does not block. Rate limits need an identified aggregation key and distributed semantics; a per-process limit is not a global account quota.

### Real Configuration Fragments

NGINX OSS 1.28 location fragment for a proxy directly serving a known public authority. It is intentionally not a complete server or required exercise:

```nginx
proxy_set_header Host origin.internal;
proxy_set_header X-Forwarded-Host lab.example;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header Forwarded "";
proxy_ssl_server_name on;
proxy_ssl_name origin.internal;
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/nginx/origin-ca.pem;
proxy_pass https://origin.internal;
proxy_next_upstream off;
```

If another TLS terminator precedes this proxy, `$scheme` describes the local connection, not necessarily the browser connection. Use a documented trusted-hop configuration instead of substituting an unverified header. The fixed host names prevent arbitrary routing, but actual name resolution and origin certificates must be provided separately. The optional NGINX real-IP module changes `$remote_addr`; review its trusted source list before relying on this fragment.

Origin-side mTLS server fragment, requiring a managed client CA and separate ordinary server certificate/key:

```nginx
ssl_client_certificate /etc/nginx/approved-edge-ca.pem;
ssl_verify_client on;
ssl_verify_depth 2;
```

Trusting a CA accepts its valid client certificates according to the configured verification path; dedicate issuance to the intended edge identities or add supported identity constraints. Do not assume a shared provider CA identifies only your account. Plan short certificate lifetimes, overlapping rotation, revocation handling and safe reloads. A request header cannot establish mTLS identity; it must come from the verified handshake. No certificates or real secret material are included in this lab.

### Request and Policy Review

Define the expected method, authority, route, media type and maximum decoded body size at the application, then align intermediary limits. Reject malformed or ambiguous framing at supported parsers without constructing ambiguous-message exercises. Avoid broad path rewrites or decoding twice. Caching rules must key all representation inputs or exclude personalized traffic entirely. Do not use `Set-Cookie` presence or file extensions as the sole classification rule.

Pin or explicitly track rule-set versions, NGINX packages/modules and container images; verify publisher/build provenance and rebuild for security updates. A reverse proxy's configuration parser, TLS library and optional modules all contribute to the patch surface. A digest or signed package is evidence of origin/bytes, not assurance that the configuration is correct.

## Detection and Defense

Correlate a freshly generated edge request ID with origin route/status, handshake identity, WAF rule/version/action, request-size classification, cache decision and timings. Sanitize log fields and exclude credentials, cookies and bodies. Alert on origin traffic without the intended authenticated edge, unexpected upstream certificate failures, sudden rule-disable changes or audit gaps. A rise in WAF matches may reflect a changed client or new rule; preserve a synthetic allowed-request regression set before blocking broadly. Retain configuration revision and rollout/rollback evidence.

## Labs

### Environment and Complete Files

Python 3.12 standard library, no packages, service, network or credentials. Create an empty directory with this one file. It combines static configuration review with an offline decision function. `peer_verified` is preverified synthetic input, **not TLS validation**, and this function is not a WAF/provider simulator. The weak baseline is reviewed, never deployed.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {"origin_auth": False, "verify_upstream_tls": False,
			"overwrite_forwarding": False, "waf_mode": "count", "max_body": 16384}
REQUEST = {"peer_verified": True, "edge_identity": "lab-edge",
		   "host": "lab.example", "method": "POST", "path": "/reports",
		   "content_type": "application/json", "body": b'{"report":"synthetic"}'}


def findings(config):
	result = {name for name in ("origin_auth", "verify_upstream_tls", "overwrite_forwarding")
			  if config.get(name) is not True}
	if config.get("waf_mode") != "enforce":
		result.add("waf_mode")
	if config.get("max_body") != 16384:
		result.add("max_body")
	return result


def hardened():
	return dict(BASELINE, origin_auth=True, verify_upstream_tls=True,
				overwrite_forwarding=True, waf_mode="enforce")


def accept(config, request):
	if findings(config):
		return False
	return (request.get("peer_verified") is True
			and request.get("edge_identity") == "lab-edge"
			and request.get("host") == "lab.example"
			and request.get("method") == "POST"
			and request.get("path") == "/reports"
			and request.get("content_type") == "application/json"
			and len(request["body"]) <= config["max_body"])


class OriginContractTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(findings(BASELINE), {"origin_auth", "verify_upstream_tls",
											"overwrite_forwarding", "waf_mode"})
		self.assertEqual(findings(hardened()), set())
		self.assertTrue(accept(hardened(), REQUEST))

	def test_identity_required(self):
		for field, value in [("peer_verified", False), ("edge_identity", "other-edge")]:
			with self.subTest(field=field):
				self.assertFalse(accept(hardened(), dict(REQUEST, **{field: value})))

	def test_route_contract(self):
		for field, value in [("host", "other.example"), ("path", "/other"),
							 ("method", "GET"), ("content_type", "text/plain")]:
			with self.subTest(field=field):
				self.assertFalse(accept(hardened(), dict(REQUEST, **{field: value})))

	def test_size_and_missing_control(self):
		self.assertTrue(accept(hardened(), dict(REQUEST, body=b"x" * 16384)))
		self.assertFalse(accept(hardened(), dict(REQUEST, body=b"x" * 16385)))
		config = copy.deepcopy(hardened())
		del config["verify_upstream_tls"]
		self.assertFalse(accept(config, REQUEST))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

Run `python -m unittest -v test_example`. Identify the four baseline design failures. Apply `hardened()` through the identical reviewer and retain acceptance of the intended synthetic report. Require rejection for missing verified identity, unapproved route/media type and oversized bodies. No external traffic or bypass experiment is involved.

### Hints

The reviewer checks configuration intent; the request function checks an assumed preverified context. Neither produces evidence that a CA validated a certificate or that a managed WAF inspected a body. The byte-size tests do not parse JSON; schema and authorization belong to the origin application.

### Solution and Fixed Retest

Four tests should pass. The fixed design requires origin authentication, upstream verification, normalized forwarding and enforcing mode. The known report remains accepted; each changed contract dimension is denied. Exactly 16,384 bytes fits the fixture size contract, 16,385 does not. A real rollout additionally verifies chain/name validation, edge identity, WAF oversize behavior, application validation and direct-origin restrictions in an authorized environment.

### Verification, Troubleshooting, and Cleanup

No package or certificate setup is missing from this offline exercise. Restore the embedded fixtures to reset; delete its directory and `__pycache__` to clean up. Author validation was static only, with no tests, provider requests or proxy services run. Historical runtime milestones below are preserved but not fulfilled by this model.

### User-Owned Milestones

- [ ] Local Reverse Proxies CDN and WAF exercise: Place a local proxy before a toy app and record the method, authority, path, and client identity seen at each hop. Try direct-origin access and forged forwarding headers.
- [ ] Boundary check: Reach the lab origin directly and verify its network/authentication policy blocks bypass. Send a fake forwarded scheme from an untrusted client and confirm it is not accepted.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Request Smuggling]]
- [[Host Header Attacks]]
- [[Cache Poisoning and Deception]]
- [[Reverse Proxies CDN and WAF]]

## References

- [NGINX upstream TLS and proxy settings](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [NGINX client certificate verification](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
- [NGINX trusted address handling](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [AWS WAF oversized components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)
- [CloudFront origin restrictions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/restrict-access-to-load-balancer.html)
