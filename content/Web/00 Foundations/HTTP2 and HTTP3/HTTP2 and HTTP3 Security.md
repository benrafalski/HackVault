---
title: "HTTP/2 and HTTP/3 Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[HTTP2 and HTTP3]]"
updated: 2026-11-03
---
# HTTP/2 and HTTP/3 Security

> [!abstract] TL;DR
> Multiplexing moves resource accounting from connections to streams and decoded work. Patch the protocol stack, bound compression and stream state, and validate authority/content invariants before translating to another HTTP version.

## Attack Surface

H2 shares TCP and HPACK state across streams; H3 shares QUIC connection limits and QPACK state while giving streams independent delivery. Edge-origin translation introduces a second parser. Stream cancellation, decompressed fields, control streams and queued application work need limits beyond a TCP connection count.

## Learn

```text
Teach me HTTP/2 and HTTP/3 defensive design assuming HTTP semantics. Cover
stream state, HPACK/QPACK context and decoded limits, pseudo-field validation,
H1 translation, ALPN and alternate-service identity, QUIC connection migration,
0-RTT replay policy, cancellation and work accounting. Give exact configuration
examples with supported-version qualifications and a synthetic offline budget
and translation-invariant lab. Establish a permissive baseline as data, tighten
it and show permitted requests still pass. Do not generate malformed network
traffic, resets, floods or bypass exercises. Distinguish model results from a
patched server's behavior. Explain telemetry and false positives and cite RFCs.
Teach in this conversation without editing files or inventing verification.
```

## Cheatsheet

### Invariants at the Edge

| Boundary | Invariant | Failure handling |
|---|---|---|
| Decoded field section | Lowercase names, pseudo-fields before ordinary fields, required/unique pseudo-fields | Reject malformed request before dispatch |
| Authority | Validated `:authority` and any Host are consistent under chosen policy | Never let downgrade choose a different authority |
| Framing | DATA octet total agrees with Content-Length if present | Reject/reset; do not synthesize misleading H1 framing |
| Hop metadata | No Connection fields or Transfer-Encoding; TE only `trailers` | Remove/reject according to protocol, not generic copying |
| Compression | Bounded table state and decoded field bytes/count | Compression errors can be connection-scoped |
| Stream lifecycle | Legal transitions and bounded admitted work | Preserve distinction between stream and connection errors |

CONNECT and extended CONNECT have different pseudo-field rules; do not apply a normal GET validator universally. A field block can be small when compressed but large when decoded. HPACK table capacity does not bound total decoded bytes or CPU. QPACK blocked-stream limits bound dynamic-table waiting, but an application queue still needs its own admission policy.

### Resource Budgets

Limit concurrent active streams, new-stream rate, decoded field bytes/count, body bytes, connection lifetime/idle time, field completion time, total request time and queued work per authenticated principal. Cancellation must release resources but should not erase already-consumed cost from rate accounting. Flow control bounds DATA delivery, not all parsing, compression or application work. Limit both per-connection and aggregate principal/IP budgets; NAT makes IP a coarse identity and QUIC migration makes tuple-based state fragile.

| Metric | Why it matters | False-positive context |
|---|---|---|
| New/active/completed/cancelled streams | Work may greatly exceed connection count | Browsers cancel navigation/subresources normally |
| Decoded versus encoded field size | Compression changes work ratio | Repeated large legitimate metadata |
| QPACK blocked streams and duration | Dependency stalls | Loss or small configured table during normal startup |
| CPU/queue latency versus DATA bytes | Header/control work can dominate | Cold caches, certificate operations |
| QUIC loss/fallback/migration | Availability and identity observation | Wi-Fi/mobile path changes, UDP restrictions |

Use maintained vendor security updates. HTTP/2 Rapid Reset disclosures demonstrated why concurrent-stream settings alone do not account for all work; no traffic reproduction is needed to audit patch level and rate-limit design. H3 is not immune to resource exhaustion merely because it uses another transport. Verify vendor advisories for the exact build rather than assuming a protocol version is a patch level.

### Concrete Configuration and Translation

NGINX 1.25.1+ syntax fragment for an HTTPS H2 server with certificates configured elsewhere:

```nginx
listen 443 ssl;
http2 on;
http2_max_concurrent_streams 64;
client_header_timeout 10s;
client_body_timeout 10s;
client_max_body_size 1m;
large_client_header_buffers 4 8k;
```

Earlier builds use `listen 443 ssl http2`; verify installed documentation. These settings are illustrative budgets, not universal safe values. Body timeout is between reads, not a complete request deadline. Deprecated H2-specific header-size directives should not be copied from old guides. H3 requires an appropriately built QUIC module and TLS library; its stream controls and deployment maturity vary by product/version. Do not assume the H2 directive limits H3.

Log inbound protocol and upstream protocol independently. An H2/H3 frontend with an H1 backend must reconstruct one unambiguous method/target/authority/body representation. Reject disagreements before pooling the backend connection. For public URLs, use configured origins. Keep certificate validation for Alt-Svc origin identity; an alternate host/port does not create a new authorization grant. TLS 1.3 early data is replayable: disallow it for mutations unless the application contract explicitly handles replay.

## Detection and Defense

Correlate stream/request IDs, normalized authority/path, rejected-field reasons, bytes, cancellation timing, queue admission and backend status. Do not log raw credentials or compressed header blocks. Alert on budget breaches and anomalous work ratios with normal browser cancellation baselines. Quarantine failing connections through the implementation's error handling, not a custom byte patcher. Confirm valid requests still work after narrowing limits.

## Labs

### Environment and Complete Files

Python 3.12+, stdlib only. The lab evaluates synthetic decoded requests and work counters; it sends no traffic and implements neither HPACK nor QPACK. The field-byte metric below is an application UTF-8 byte budget, not the RFC SETTINGS accounting formula.

### File: test_example.py

```python
import unittest
from dataclasses import dataclass


def normal_get(fields):
	pseudo = {}
	ordinary_seen = False
	decoded_bytes = 0
	for name, value in fields:
		decoded_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8"))
		if name != name.lower() or any(char in name + value for char in "\r\n\x00"):
			return False
		if name.startswith(":"):
			if ordinary_seen or name in pseudo:
				return False
			pseudo[name] = value
		else:
			ordinary_seen = True
			if name in {"connection", "transfer-encoding", "host"}:
				return False
			if name == "te" and value != "trailers":
				return False
	return (pseudo == {":method": "GET", ":scheme": "https",
					   ":authority": "app.example.test", ":path": "/status"}
			and decoded_bytes <= 1024 and len(fields) <= 16)


@dataclass
class Budget:
	started: int = 0
	active: int = 0

	def admit(self):
		if self.started >= 3 or self.active >= 2:
			return False
		self.started += 1
		self.active += 1
		return True

	def finish(self):
		if self.active <= 0:
			raise ValueError("no active work")
		self.active -= 1


FIELDS = [(":method", "GET"), (":scheme", "https"),
		  (":authority", "app.example.test"), (":path", "/status")]


class ProtocolPolicyTests(unittest.TestCase):
	def test_valid_and_order(self):
		self.assertTrue(normal_get(FIELDS + [("accept", "text/plain")]))
		self.assertFalse(normal_get([("accept", "text/plain")] + FIELDS))
		self.assertFalse(normal_get(FIELDS + [(":path", "/status")]))

	def test_translation_and_size(self):
		self.assertFalse(normal_get(FIELDS + [("host", "other.example.test")]))
		self.assertFalse(normal_get(FIELDS + [("x-note", "a" * 1025)]))
		self.assertTrue(normal_get(FIELDS + [("te", "trailers")]))

	def test_cancellation_keeps_cost(self):
		budget = Budget()
		self.assertTrue(budget.admit())
		self.assertTrue(budget.admit())
		self.assertFalse(budget.admit())
		budget.finish()
		self.assertTrue(budget.admit())
		budget.finish()
		self.assertFalse(budget.admit())
		self.assertEqual((budget.started, budget.active), (3, 1))
		baseline_concurrency_only = budget.active < 2
		self.assertTrue(baseline_concurrency_only)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run `python -m unittest -v test_example`. Explain why the concurrency-only baseline allows another admission after cumulative work reaches the window budget.
2. Change `finish()` to decrement `started` too; observe the regression test fail, then restore it.
3. Explain why this fixed-route GET profile rejects Host entirely even though broader protocol handling can permit consistent Host metadata.
4. Add an accepted small ordinary field and a rejected uppercase field case. Keep all data offline.

### Hints

Active concurrency and cumulative work per interval are different dimensions. A real time-window limiter needs a clock/window reset, fairness, and distributed enforcement; this model deliberately represents one fixed interval.

### Solution and Fixed Retest

Expected: three tests pass. Allowed GET fields survive, late/duplicate pseudo-fields and excess decoded size fail. Three total admissions exhaust the interval even after a cancellation; one request remains active at the end. Decrementing cumulative cost on finish incorrectly admits another request and fails the assertion. This proves a policy invariant, not resistance of any network implementation.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring; optional pytest command is `python -m pytest -q test_example.py`. No packages, servers, load generation or firewall changes. A real rollout requires build/advisory review and bounded legitimate-client acceptance checks on both edge and origin. Remove the directory and caches after recording results.

- [ ] Explain decoded limits, compression state and translation invariants.
- [ ] Record concurrency-only baseline and cumulative-budget fixed behavior.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Request Smuggling]]
- [[HTTP2 and HTTP3]]

## References

- [HTTP/2 security considerations, RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- [HTTP/3 security considerations, RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)
- [NGINX HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html)
- [QPACK, RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)
