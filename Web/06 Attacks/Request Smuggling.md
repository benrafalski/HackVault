---
title: "Request Smuggling"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Request Smuggling

> [!abstract] TL;DR
> Request smuggling exploits disagreement between HTTP parsers about request boundaries or translated message structure on a shared connection.

> [!info] Agent scope
> HTTP framing disagreements; frontend/backend parsing; HTTP/2 downgrades; isolated lab verification; parser alignment.

## Learn

```text
Teach request smuggling as disagreement over message boundaries across HTTP
parsers. Assume HTTP/1.1 framing, HTTP/2 streams, proxies, and connection reuse.
Explain Content-Length, transfer coding, body completeness, frontend/backend
normalization, shared connections, and HTTP/2-to-HTTP/1.1 translation conceptually.
Distinguish protocol requirements from a stricter deployment rejection policy.
Review semantic parser summaries and safe rejection/connection-disposal decisions,
not raw requests. Explain stream reset versus closing a connection, request-ID
correlation, retry ambiguity, parser versions, and why edge HTTP/2 is insufficient.
Use an offline policy/incident exercise with synthetic evidence and primary RFCs.
No framing payloads, ambiguous wire examples, parser bypasses, live probes,
cross-user effects, scanning, or chains. Include limitations and review questions
with answers. Teach, do not edit files or claim live verification occurred.
```

## Cheatsheet

> [!important] Defensive scope
> Only framing-policy review and synthetic log reconciliation are provided. There are no raw HTTP messages, ambiguous encodings, probes, or operational smuggling payloads. No proxies or services are started.

### Root Cause and Prerequisites

Every hop must agree on where a message starts and ends, which authority it targets, and which metadata survives translation. Disagreement can leave bytes or state interpreted differently by a downstream parser. Shared persistent connections can extend consequences beyond the current request; exact connection pooling, routing, and parser behavior matter. A timeout alone does not demonstrate desynchronization.

| Surface | Required invariant | Defensive response |
|---|---|---|
| HTTP/1.1 length metadata | One unambiguous supported framing interpretation | Reject malformed/conflicting forms before forwarding |
| Transfer coding | Supported semantics and complete body | Decode/forward according to one reviewed policy |
| Body completeness | Declared framing agrees with received body | Fail closed; do not reuse uncertain HTTP/1.1 state |
| HTTP/2 translation | Stream data and emitted HTTP/1.1 length agree | Generate downstream framing from validated state |
| Connection metadata | Hop-specific fields handled at each boundary | Do not blindly forward connection-specific metadata |
| Error/retry | Rejected data cannot become another message | Dispose of affected state and control retries |

RFC 9112 defines HTTP/1.1 framing precedence and error handling. A deployment can adopt stricter rejection, such as rejecting all duplicate length declarations rather than normalizing identical values. Document this as a local policy, not an assertion that the RFC always mandates that choice. Intermediaries and origins must agree; a lenient origin can undermine assumptions made at an edge.

### HTTP/2 and Version Details

HTTP/2 uses stream framing, but translation to HTTP/1.1 reintroduces textual framing decisions. A Content-Length field, when present, must match content length; connection-specific fields are prohibited subject to the protocol's defined exceptions. Do not copy field syntax or calculate lengths from a different representation than the bytes sent downstream. HTTP/3 similarly does not certify every intermediary's downstream parser.

Patch and inventory the actual edge, WAF, proxy, application server, and protocol-conversion versions. Product names alone are not compatibility evidence. An HTTP/1.1 framing error often requires closing the affected connection; an HTTP/2 error may be stream-scoped or connection-scoped depending on the violation. Use the protocol implementation's documented rules, not a universal close-everything heuristic.

### Buffered Forwarding Configuration

**Fragment / prerequisites:** NGINX HTTP proxy module, a maintained release, and an operator-defined `reviewed_origin` upstream. Place this location inside the intended `server` block; it is not a complete configuration or a portable parser-policy language.

```nginx
location / {
	proxy_request_buffering on;
	proxy_http_version 1.1;
	proxy_pass http://reviewed_origin;
}
```

**Interpretation:** Explicit request buffering makes NGINX read the entire request body before sending it upstream. The HTTP/1.1 directive selects the upstream protocol; it does not enable stricter parsing. Buffering is a body-completeness control, not proof of parser agreement: require supported parser rejection of invalid/conflicting framing, document any stricter duplicate-length policy separately, and verify affected HTTP/1.1 state is closed rather than pooled after framing errors. Do not invent a header rewrite as a substitute for parser validation.

**Limits / false positives:** buffering adds latency and can spill bodies to temporary storage; body-size limits, timeouts, disk pressure, and client disconnects can explain failures without desynchronization. This fragment does not configure HTTP/2 error handling or implement the lab's stricter semantic policy. Installed-version behavior and inherited configuration remain unverified.

### Evidence and Defense Limits

Correlate edge-generated request IDs, stream IDs, upstream connection IDs, forwarded request counts, origin receipt counts, and rejection categories. Do not accept client-supplied correlation IDs as authoritative. Retries, caching, fan-out, and health checks can legitimately change counts, so reconciliation needs known routing semantics. Log metadata, not request bodies.

Header filters or a WAF signature do not establish parser agreement. Disabling reuse can reduce some cross-request effects but is not a root-cause fix. Request normalization must be applied once, consistently, and before security/routing decisions that rely on it.

## Defense

Use maintained strict parsers, minimize protocol conversions, reject uncertain framing, and align edge/origin policies. Test vendor-provided conformance cases in dedicated environments under separate authorization. After errors, never return an uncertain connection to a shared pool. Keep retry behavior explicit for non-idempotent operations.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no network, parser, proxy, or dependencies. The fixtures are semantic summaries from a hypothetical parser audit, not serialized requests. Review a proposed policy that forwards records even when the parsers disagree. The replacement must reject and retire affected HTTP/1.1 connection state.

### File: test_example.py

```python
from dataclasses import dataclass, replace
from collections import Counter
import unittest


@dataclass(frozen=True)
class FramingReview:
	length_fields: int = 1
	transfer_coding: bool = False
	parser_agreement: bool = True
	body_complete: bool = True
	downstream_length_matches: bool = True
	forbidden_connection_metadata: bool = False


def h1_forwarding_decision(review):
	uncertain = (
		review.length_fields not in (0, 1)
		or (review.length_fields > 0 and review.transfer_coding)
		or not review.parser_agreement
		or not review.body_complete
		or not review.downstream_length_matches
		or review.forbidden_connection_metadata
	)
	return ("reject", "retire-connection") if uncertain else ("forward", "eligible-for-reuse")


def unmatched_requests(edge_forwarded, origin_received):
	expected = Counter(edge_forwarded)
	observed = Counter(origin_received)
	return dict(expected - observed), dict(observed - expected)


class FramingPolicyTests(unittest.TestCase):
	def test_reviewed_normal_case(self):
		self.assertEqual(h1_forwarding_decision(FramingReview()),
						 ("forward", "eligible-for-reuse"))

	def test_uncertainty_never_forwards(self):
		baseline = FramingReview()
		changes = [{"length_fields": 2}, {"transfer_coding": True},
				   {"parser_agreement": False}, {"body_complete": False},
				   {"downstream_length_matches": False},
				   {"forbidden_connection_metadata": True}]
		for change in changes:
			with self.subTest(change=change):
				self.assertEqual(h1_forwarding_decision(replace(baseline, **change)),
								 ("reject", "retire-connection"))

	def test_synthetic_incident_reconciliation(self):
		missing, extra = unmatched_requests(["edge-1", "edge-2"], ["edge-1", "origin-unknown"])
		self.assertEqual(missing, {"edge-2": 1})
		self.assertEqual(extra, {"origin-unknown": 1})
		self.assertEqual(unmatched_requests(["edge-1"], ["edge-1"]), ({}, {}))


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: the summary's `parser_agreement` is supplied evidence, not something the code can discover. Why must connection disposal accompany rejection in this HTTP/1.1 policy?

Solution: any uncertainty prevents forwarding and reuse. Expected: three tests pass; six semantic failure categories reject, and log reconciliation identifies one missing and one unexpected receipt. Those counts require investigation; they are not proof of request smuggling. The fixture assumes one-to-one routing with no retries/cache/fan-out and does not implement a protocol parser.

### Verification, Troubleshooting, and Cleanup

No tests or live protocol checks ran during authoring. Run beside the named file; no setup is needed. A policy test cannot certify installed parsers, HTTP/2 error handling, or wire-level alignment. Remove the disposable exercise directory afterward. Raw request construction is intentionally outside this exercise.

- [ ] Local Request Smuggling exercise: Review semantic framing and connection-lifecycle policy.
- [ ] Boundary check: Run offline rejection and request-count reconciliation tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 9112: HTTP/1.1 message framing](https://www.rfc-editor.org/rfc/rfc9112)
- [RFC 9113: HTTP/2 malformed messages](https://www.rfc-editor.org/rfc/rfc9113)
- [RFC 9110: HTTP semantics and intermediaries](https://www.rfc-editor.org/rfc/rfc9110)
