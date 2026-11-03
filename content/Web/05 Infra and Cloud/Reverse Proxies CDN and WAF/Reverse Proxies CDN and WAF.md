---
title: "Reverse Proxies CDN and WAF"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Reverse Proxies CDN and WAF Security]]"
updated: 2026-11-03
---
# Reverse Proxies CDN and WAF

> [!abstract] TL;DR
> Define trusted hops, canonical authority, origin access policy, and edge/origin timeouts. Compare parsing and caching decisions end to end.

> [!info] Agent scope
> Proxy chains; forwarded headers; CDN origins; WAF policy; routing; TLS termination; trust boundaries; origin access controls.

## Prerequisites

- HTTP authority, TLS, IP routing and application authorization; [[Web Lab Setup]].
- Required lab: Python 3.12 standard library, offline. Reference configuration uses NGINX OSS 1.28 HTTP directives, not an installed service or a promise of current security-patch status.

## Learn

```text
Teach me reverse proxies, CDNs and WAFs at expert engineering depth. Assume
HTTP, TLS and IP routing. Trace client-to-edge-to-origin authority, TLS SNI,
upstream verification, forwarded identity, path transformation, buffering,
timeouts, retries, cache keys and WAF inspection. Explain NGINX OSS 1.28
configuration semantics and distinguish vendor CDN/WAF behavior. Supply exact
configuration fragments and a complete offline request-transformation lab
with synthetic inputs, expected output and negative regression tests. Cover
trusted-hop algorithms, origin access controls, client certificates, certificate
rotation, WebSockets, large bodies, streaming and observability. Explain why
filtering is not application authorization. Use primary references; no public
listeners, real credentials, exploitation or host network policy changes.
Teach in this conversation, without file editing or invented execution evidence.
```

## Cheatsheet

### Follow Every Connection

```text
client --TLS A--> CDN/WAF --TLS B + origin authentication--> reverse proxy --> app
		 public authority     upstream SNI / origin authority         application identity
```

Each TLS session has its own peer identity, certificate chain, expiration and trust store. HTTPS at the browser does not prove encrypted or authenticated origin transport. Verify the origin certificate against its intended DNS name; sending `Host` does not itself configure TLS SNI. Authenticate the allowed CDN path with a supported private origin mechanism or mTLS and restrict reachability. Shared CDN IP ranges alone identify provider infrastructure, not your distribution. An origin secret header has rotation, logging and disclosure risks and is not equivalent to mTLS.

| Decision | Required contract | Failure mode |
|---|---|---|
| Authority | Allowlisted public host; fixed internal authority | Arbitrary client Host influences routing or generated links |
| Client address | Trust immediate peer first, then a documented chain algorithm | A user-supplied forwarding field is treated as authenticated identity |
| Scheme | Set by the trusted TLS termination point | Redirect loops or incorrect cookie/security decisions |
| Path | One documented prefix/normalization policy | Different WAF, cache and router interpretations |
| Bodies | Explicit maximum, media type, buffering/streaming policy | Proxy accepts more than origin can safely process |
| Timeouts | Total application deadline plus connect/read/write budgets | Read timeout is mistaken for total request deadline |
| Retries | Retry only operations safe under uncertain completion | A request commits upstream but a retry repeats its side effect |

At a directly exposed edge, overwrite forwarding headers from connection facts. Within multiple trusted hops, walk address information from the known peer toward earlier hops until reaching the first untrusted address; a fixed trusted-hop count fails when traffic can take different-length paths. Configure trusted CIDRs explicitly and keep them current. RFC 7239 `Forwarded` syntax includes quoting and IPv6; do not parse it with a naive comma split in production. Forwarded IP is useful evidence and rate-limit input, not user authentication.

### Complete Loopback Proxy Configuration

This reference `nginx.conf` is syntactically complete for NGINX OSS 1.28 with normal HTTP/proxy modules. It needs an independently supplied origin at `127.0.0.1:18081` to serve requests and writable paths relative to its chosen prefix; it is **not the required lab**. It starts no service in this revision. Both listener and upstream are loopback; HTTP here is explicitly local, not a deployment TLS design.

```nginx
worker_processes 1;
pid nginx.pid;
error_log error.log warn;
events { worker_connections 128; }
http {
	access_log off;
	server {
		listen 127.0.0.1:18080 default_server;
		server_name _;
		return 400;
	}
	server {
		listen 127.0.0.1:18080;
		server_name lab.example;
		client_max_body_size 16k;
		client_body_timeout 5s;
		client_header_timeout 5s;
		location /api/ {
			proxy_pass http://127.0.0.1:18081/;
			proxy_http_version 1.1;
			proxy_set_header Host origin.internal;
			proxy_set_header X-Forwarded-Host lab.example;
			proxy_set_header X-Forwarded-Proto $scheme;
			proxy_set_header X-Forwarded-For $remote_addr;
			proxy_set_header Forwarded "";
			proxy_set_header Connection "";
			proxy_connect_timeout 2s;
			proxy_read_timeout 5s;
			proxy_send_timeout 5s;
			proxy_next_upstream off;
			proxy_cache off;
		}
		location / { return 404; }
	}
}
```

Here `/api/report?year=2026` maps to `/report?year=2026`: the URI component `/` in `proxy_pass` replaces the matched location prefix. Without that URI component, forwarding semantics differ; regex/named locations and rewrites introduce additional rules. This fragment does not adopt arbitrary upstream addresses from request data. `proxy_read_timeout` bounds inactivity between upstream reads, not total completion time. Buffering defaults can spill to temporary disk; choose disk quotas, request-size limits and streaming settings deliberately.

Optional inspection commands for an already installed binary, not a setup requirement: `nginx -V` reports version/build modules; `nginx -t -p <absolute-lab-directory> -c nginx.conf` checks syntax and referenced files without starting a service. Do not use a system-wide config path. No execution is asserted here.

For a real encrypted origin, the following **location fragment** needs an actual CA bundle and DNS/service configuration:

```nginx
proxy_pass https://origin.internal;
proxy_ssl_server_name on;
proxy_ssl_name origin.internal;
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/nginx/origin-ca.pem;
proxy_ssl_verify_depth 3;
```

NGINX upstream certificate verification is not enabled just by choosing an `https://` URL. Certificate rotation must maintain overlapping trust while reloading/restarting relevant processes and renewing connections. Do not disable verification to fix expiry or name mismatch.

### CDN and WAF Operations

CDN cacheability, key dimensions, TTL, purge scope and stale serving are deployment contracts; origin response headers alone may be overridden by edge rules. Prefer immutable versioned public assets and no shared storage for personalized responses. WAF rules inspect only supported protocols, encodings, body sizes and content types. Document oversize behavior and rule exclusions per route, then measure false positives with harmless expected requests. Managed-rule version changes require staged evaluation; a rule label or status code is not proof of application correctness.

WebSocket upgrades need explicit hop-by-hop `Upgrade`/`Connection` forwarding and compatible timeouts; the ordinary API config above intentionally does not support them. SSE/streaming needs buffering and idle-timeout review. HTTP/2 or HTTP/3 at the edge can become HTTP/1.1 upstream: keep parsers patched and reject ambiguous framing at every boundary rather than treating translation as transparent. Logs should correlate edge-generated request ID, selected route/upstream, status, timing and cache/WAF decision without recording credentials or bodies.

## Gotchas

`$proxy_add_x_forwarded_for` appends to an incoming field; it is not automatically suitable at an untrusted edge. Trust only known proxies and do not infer client identity from the leftmost value. A WAF block proves only a specific policy decision; the origin still needs authorization and parser correctness.

## Labs

### Environment and Complete Files

Python 3.12 standard library only. Create an empty directory and the one file below. No listener, NGINX, DNS, certificates or account is required. The in-process edge function transforms a deliberately narrow set of already parsed request fields. It is not an HTTP parser, proxy implementation, CDN, TLS validator or WAF product.

### File: test_example.py

```python
import unittest
from urllib.parse import urlsplit


def forward(peer, authority, target, incoming, tls):
	if authority != "lab.example":
		raise ValueError("unapproved authority")
	parsed = urlsplit(target)
	if parsed.scheme or parsed.netloc or parsed.fragment:
		raise ValueError("origin-form target required")
	if not parsed.path.startswith("/api/"):
		raise ValueError("no route")
	if "%" in parsed.path or "\\" in parsed.path or ".." in parsed.path.split("/"):
		raise ValueError("outside lab path grammar")
	path = parsed.path[len("/api"):]
	if parsed.query:
		path += "?" + parsed.query
	headers = {"host": "origin.internal", "x-forwarded-host": "lab.example",
			   "x-forwarded-proto": "https" if tls else "http",
			   "x-forwarded-for": peer}
	if "accept" in incoming:
		headers["accept"] = incoming["accept"]
	return {"target": path, "headers": headers}


class ProxyContractTests(unittest.TestCase):
	def test_route_and_query(self):
		result = forward("192.0.2.10", "lab.example", "/api/report?year=2026", {}, True)
		self.assertEqual(result["target"], "/report?year=2026")
		self.assertEqual(result["headers"]["host"], "origin.internal")

	def test_connection_facts_replace_client_fields(self):
		incoming = {"x-forwarded-for": "synthetic", "x-forwarded-proto": "other",
					"forwarded": "synthetic", "accept": "application/json"}
		headers = forward("192.0.2.10", "lab.example", "/api/report", incoming, True)["headers"]
		self.assertEqual(headers["x-forwarded-for"], "192.0.2.10")
		self.assertEqual(headers["x-forwarded-proto"], "https")
		self.assertNotIn("forwarded", headers)
		self.assertEqual(headers["accept"], "application/json")

	def test_unknown_host_and_route(self):
		for authority, path in [("other.example", "/api/report"), ("lab.example", "/other")]:
			with self.subTest(authority=authority, path=path), self.assertRaises(ValueError):
				forward("192.0.2.10", authority, path, {}, True)

	def test_scheme_tracks_connection(self):
		headers = forward("192.0.2.10", "lab.example", "/api/report", {}, False)["headers"]
		self.assertEqual(headers["x-forwarded-proto"], "http")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

Run `python -m unittest -v test_example`. Predict the upstream target and four generated headers. Compare HTTPS and HTTP connection facts with the same input fields. Require unknown host/route rejection and preservation of `Accept`. The documentation-only address is never contacted.

### Hints

Only the selected fields are copied. The fixture accepts already normalized lowercase header names and a trusted connection peer argument; these are caller preconditions, not claims about raw network input. Its deliberately restricted path grammar is not a general URL normalization recommendation.

### Solution and Expected Results

Four tests should pass. The route strips `/api`, preserves the query, selects the fixed origin authority and overwrites forwarding identity using connection facts. Arbitrary incoming forwarding strings are not propagated. Changing `tls` changes the forwarded scheme; no certificate is validated by this boolean. Real deployment additionally requires origin authentication, routing, correct parsing, TLS verification and end-to-end observation.

### Verification, Troubleshooting, and Cleanup

Use this page's file in its own directory. A missing module means the working directory is wrong. Restore the printed function to reset and remove the file/`__pycache__` to clean up. No runtime configuration, HTTP service, TLS handshake or tests were executed during authoring. The historical runtime milestones below remain uncompleted and are not instructions to test real origins.

### User-Owned Milestones

- [ ] Local Reverse Proxies CDN and WAF exercise: Place a local proxy before a toy app and record the method, authority, path, and client identity seen at each hop. Try direct-origin access and forged forwarding headers.
- [ ] Boundary check: Reach the lab origin directly and verify its network/authentication policy blocks bypass. Send a fake forwarded scheme from an untrusted client and confirm it is not accepted.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Request Smuggling]]
- [[Host Header Attacks]]
- [[Cache Poisoning and Deception]]
- [[Reverse Proxies CDN and WAF Security]]

## References

- [NGINX HTTP proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [NGINX real IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [NGINX WebSocket proxying](https://nginx.org/en/docs/http/websocket.html)
- [RFC 7239 Forwarded](https://www.rfc-editor.org/rfc/rfc7239)
- [CloudFront origin access restriction](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/restrict-access-to-load-balancer.html)
