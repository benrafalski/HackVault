---
title: "HTTP Caching"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[HTTP Caching Security]]"
updated: 2026-11-03
---
# HTTP Caching

> [!abstract] TL;DR
> Separate public immutable assets from personalized responses. Document key inputs, TTL, Vary, purge behavior, and no-store decisions.

> [!info] Agent scope
> Cache keys; freshness; validation; Vary; shared versus private caches; authentication interactions; intermediary behavior.

## Prerequisites

- HTTP request/response semantics, representation headers and authentication; [[Web Lab Setup]].
- Required exercise: Python 3.12 standard library only. Protocol baseline: RFC 9111 (HTTP caching), RFC 9110 (semantics), RFC 5861 (stale extensions), RFC 8246 (`immutable`). Vendor overrides require separate verification.

## Learn

```text
Teach me HTTP caching at expert protocol and deployment depth. Assume HTTP
and application authentication. Use RFC 9111/9110 semantics, identifying CDN
and browser differences. Derive cache keys and Vary matching, corrected age,
freshness, validators and 304 metadata merging. Explain private/shared caches,
Authorization and cookies, no-cache versus no-store, s-maxage, must-revalidate,
immutable, stale extensions, redirects/errors, unsafe-method invalidation,
purges and versioned assets. Provide exact request/response exchanges and a
complete Python 3.12 offline cache lab with fake time, language variants,
ETags, stale validation, changed representations and private-response tests.
Label simplifications and show tradeoffs, failure diagnosis and primary sources.
No public listener, real credentials or exploitation. Teach here; no file edits.
```

## Cheatsheet

### Storage, Selection, Freshness, Validation

A cache first decides whether it may store a response, then whether a stored representation matches the request, then whether it may reuse it now. These are separate decisions. The primary key includes request method and target URI; practical caches usually concentrate on GET. Scheme, authority, path and query can distinguish resources. Do not remove query fields or normalize paths unless the origin's representation contract guarantees equivalence. A fragment is not sent in an HTTP request.

`Vary` lists request header fields used to select representations, not response headers. Field names are case-insensitive; value normalization is field-specific. An absent header is distinct from a present nonmatching value. `Vary: *` never matches for reuse without validation. High-cardinality values, especially cookies or raw user agents, can make caching ineffective and complicate privacy. Prefer an explicit, low-cardinality normalized variant where the CDN and origin share the same contract.

| Response directive | Effect | Common confusion |
|---|---|---|
| `max-age=60` | Freshness lifetime 60 seconds | Starts from corrected age, not simply browser arrival |
| `s-maxage=60` | Shared-cache lifetime override; also carries proxy-revalidate semantics | Does not set browser lifetime |
| `private` | Shared cache must not store unqualified private response | Browser may still store; not equivalent to no-store |
| `no-cache` | Store is possible; validate before reuse | Not a prohibition on storage |
| `no-store` | Do not store this request/response under compliant cache rules | Does not reliably purge older entries or all application-held copies |
| `must-revalidate` | Once stale, successful validation required; cannot serve disconnected stale result | Does not demand validation while fresh |
| `immutable` | Fresh representation expected not to change | Requires content-addressed/versioned URLs; no perpetual lifetime |
| `stale-while-revalidate=N` | Permits limited stale use while refreshing | Not suitable where stale authorization/personal data would violate policy |
| `stale-if-error=N` | Permits limited stale fallback for qualifying errors | Not permission to ignore must-revalidate or privacy restrictions |

`Expires` can supply freshness when overriding Cache-Control lifetimes are absent; `Date` anchors it. Invalid/conflicting freshness fields should be handled conservatively. Some statuses allow heuristic caching when explicit lifetime is absent, including redirects and certain errors; declare policies rather than relying on guesswork. `Set-Cookie` alone does not universally prohibit caching. Responses to requests with `Authorization` have shared-reuse restrictions, with explicit exceptions such as `public`, `s-maxage` and `must-revalidate`; do not use those directives for personalized responses casually.

### Age Calculation

Using seconds and timestamps from RFC 9111:

```text
apparent_age = max(0, response_time - date_value)
response_delay = response_time - request_time
corrected_age_value = age_value + response_delay
corrected_initial_age = max(apparent_age, corrected_age_value)
resident_time = now - response_time
current_age = corrected_initial_age + resident_time
fresh iff freshness_lifetime > current_age
```

Example: request at 100, response at 102, `Date=99`, `Age=10`. Apparent age is 3, corrected age is 12. At time 120 the current age is 30. A `max-age=30` response is already stale at that equality boundary. `Age` is accumulated age, not a hop count; intermediaries must not reset it to make old content look fresh. Clock skew and invalid fields need conservative handling.

### Worked Validation Exchange

```http
GET /catalog HTTP/1.1
Host: lab.example
Accept-Language: en

HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 12:00:00 GMT
Cache-Control: public, max-age=30
Vary: Accept-Language
ETag: "catalog-en-v1"
Content-Type: text/plain
Content-Length: 7

book:10
```

After the entry becomes stale:

```http
GET /catalog HTTP/1.1
Host: lab.example
Accept-Language: en
If-None-Match: "catalog-en-v1"

HTTP/1.1 304 Not Modified
Date: Tue, 03 Nov 2026 12:01:00 GMT
Cache-Control: public, max-age=30
Vary: Accept-Language
ETag: "catalog-en-v1"
```

A 304 has no content body; a cache updates appropriate stored metadata and reuses the saved representation body. It is not a redirect. `If-None-Match` takes precedence over `If-Modified-Since` when both apply; GET/HEAD use weak comparison for `If-None-Match`. Strong validators identify byte-equivalent representations and matter for range combination and `If-Range`; weak tags do not establish that equivalence. Compression/content negotiation must align validators and `Vary`; do not accidentally assign one strong ETag to different encoded bytes.

### Deployment Patterns and Lifetime

```http
Cache-Control: public, max-age=31536000, immutable
```

Use that only for versioned public assets such as a content-hashed bundle whose URL is never reused. For sensitive dynamic content:

```http
Cache-Control: private, no-store
```

Apply the private rule to success, errors and redirects on the sensitive route, not only its happy path. A compliant browser cache, service worker, application memory and back/forward navigation are distinct storage mechanisms. Logout needs server-side session invalidation and an application retention design, not just one cache header.

Successful unsafe requests can invalidate the target URI in caches they pass through, but do not invalidate every collection/derived view at every CDN. Purge operations are provider-specific, propagate asynchronously and may omit variants or negative entries. Versioned resource names avoid many purge races but increase retained storage. Decide stale/error behavior explicitly and use request coalescing to avoid many simultaneous refreshes. Observe `Age`, validators, cache status, selected variant and origin requests; provider HIT/MISS headers are diagnostics, not standardized authorization evidence.

## Gotchas

Do not treat URL suffixes as content classification, or a cache MISS as proof that no other layer stores the response. A user-specific ETag can itself disclose identity or support unwanted tracking even if response bodies are small.

## Labs

### Environment and Complete Files

Python 3.12 standard library in an empty directory; one file, embedded data, no server or requests. Run `python -m unittest -v test_example`. This is a working in-memory cache for exactly two routes and two language variants, with a fake clock and ETag revalidation. It deliberately omits general Cache-Control parsing, age propagation, ranges, concurrency and real intermediary behavior.

### File: test_example.py

```python
import hashlib
import unittest


class Origin:
	def __init__(self):
		self.bodies = {"en": b"book:10", "fr": b"livre:10"}
		self.calls = 0

	def get(self, language, validator=None):
		self.calls += 1
		body = self.bodies[language]
		tag = '"' + hashlib.sha256(body).hexdigest() + '"'
		headers = {"etag": tag, "cache-control": "public, max-age=30",
				   "vary": "accept-language"}
		return (304, headers, b"") if validator == tag else (200, headers, body)


class Cache:
	def __init__(self, origin):
		self.origin = origin
		self.entries = {}

	def get(self, path, language, now, user=None):
		if path == "/account":
			if user not in {"alice", "bob"}:
				raise ValueError("synthetic user required")
			return ("private:" + user).encode(), "BYPASS"
		if path != "/catalog" or language not in {"en", "fr"}:
			raise ValueError("outside fixture contract")
		key = ("GET", "https", "lab.example", path, language)
		entry = self.entries.get(key)
		if entry and now - entry["stored"] < 30:
			return entry["body"], "HIT"
		status, headers, body = self.origin.get(language, entry["etag"] if entry else None)
		if status == 304:
			entry.update(stored=now, etag=headers["etag"])
			return entry["body"], "REVALIDATED"
		self.entries[key] = {"body": body, "etag": headers["etag"], "stored": now}
		return body, "MISS"


class CacheTests(unittest.TestCase):
	def setUp(self):
		self.origin = Origin()
		self.cache = Cache(self.origin)

	def test_freshness_boundary_and_304(self):
		self.assertEqual(self.cache.get("/catalog", "en", 0), (b"book:10", "MISS"))
		self.assertEqual(self.cache.get("/catalog", "en", 29), (b"book:10", "HIT"))
		self.assertEqual(self.cache.get("/catalog", "en", 30), (b"book:10", "REVALIDATED"))
		self.assertEqual(self.origin.calls, 2)

	def test_variants(self):
		self.assertEqual(self.cache.get("/catalog", "en", 0)[0], b"book:10")
		self.assertEqual(self.cache.get("/catalog", "fr", 1)[0], b"livre:10")
		self.assertEqual(len(self.cache.entries), 2)

	def test_changed_body(self):
		self.cache.get("/catalog", "en", 0)
		self.origin.bodies["en"] = b"book:11"
		self.assertEqual(self.cache.get("/catalog", "en", 29)[0], b"book:10")
		self.assertEqual(self.cache.get("/catalog", "en", 30), (b"book:11", "MISS"))

	def test_private_route_never_stored(self):
		for user in ("alice", "bob", "alice"):
			self.assertEqual(self.cache.get("/account", "en", 0, user),
							 (("private:" + user).encode(), "BYPASS"))
		self.assertEqual(self.cache.entries, {})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

Predict the result at times 0, 29 and 30 before running four tests. Change the origin bytes while the old entry is still fresh, then compare fresh reuse with stale revalidation. Request both languages and both synthetic accounts. Explain why the catalog deliberately serves its old fresh body until its lifetime expires but the account route never stores anything.

### Hints

`now` is monotonic fixture time in seconds, not wall-clock HTTP `Date`. The model starts with zero initial age and only supports the printed policy; hard-coded 30 seconds must not become a general cache implementation. The account user is test data, not authentication.

### Solution and Expected Results

Four tests should pass. Initial catalog fetch is MISS; time 29 is HIT; time 30 is stale and receives a bodyless 304, yielding REVALIDATED with the stored body. Changed origin content instead produces a fresh 200/MISS at time 30. English/French occupy separate entries. Account requests return their own synthetic marker and leave the cache empty. This demonstrates actual in-memory reuse and validation, not live RFC conformance.

### Verification, Troubleshooting, and Cleanup

No external clock, HTTP package or data file is required. Run from this page's directory; each test creates fresh state. Delete the file and `__pycache__` for cleanup. Author review was static only; no tests or CDN/browser observations were executed. Runtime milestones below remain separate and uncompleted.

### User-Owned Milestones

- [ ] Local HTTP Caching exercise: Serve a public versioned response with an ETag and a private user response. Observe fresh hits, revalidation, and account switching through a local shared cache.
- [ ] Boundary check: Vary a harmless request header that changes the origin response and verify it is either keyed or never shared. Check that two synthetic users never receive each other's private content.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Cache Poisoning and Deception]]
- [[HTTP Caching Security]]

## References

- [RFC 9111 HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111)
- [RFC 9110 HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 5861 stale controls](https://www.rfc-editor.org/rfc/rfc5861)
- [RFC 8246 immutable](https://www.rfc-editor.org/rfc/rfc8246)
