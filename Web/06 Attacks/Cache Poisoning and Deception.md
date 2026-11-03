---
title: "Cache Poisoning and Deception"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Cache Poisoning and Deception

> [!abstract] TL;DR
> Cache poisoning stores an attacker-influenced response for others; cache deception stores a private response under a key or policy that makes it reusable unexpectedly.

> [!info] Agent scope
> Unkeyed input; cache keys; normalization; poison versus private-response caching; cacheability rules; lab isolation.

## Learn

```text
Teach cache poisoning and cache deception as distinct shared-representation
failures. Assume HTTP caching, routes, authentication, and reverse proxies.
Trace eligibility, normalized key, response variation, Vary, freshness, validation,
and reuse. Distinguish attacker-influenced public representation from accidental
private-response storage. Explain unkeyed inputs, authority/path normalization,
extension-based rules, cookies/Authorization, Set-Cookie, no-store/private/no-cache,
and purge/versioning tradeoffs without contamination techniques or payloads.
Review a secure synthetic cache implementation with locale-aware keys and explicit
private bypass. Provide complete safe tests, evidence interpretation, primary
RFC/vendor sources, and questions/answers. No live CDN changes, private-data
retrieval, bypasses, scanning, or chains. Do not edit files or invent test passes.
```

## Cheatsheet

> [!important] Defensive scope
> This lab exercises an in-memory cache containing only synthetic public labels and synthetic account names. No shared service is contacted or contaminated.

### Two Failure Modes

Poisoning requires response influence that is not represented correctly in the reuse decision; deception requires a private response to be classified as shareable. Both need storage and later reuse. Reflection in an uncached response is not cache poisoning. A filename-like URL is not evidence that the route serves public static content.

| Decision | Required invariant | Limitation |
|---|---|---|
| Eligibility | Only reviewed public routes enter shared storage | URL suffix heuristics do not know application sensitivity |
| Key | Includes every permitted representation-changing input | Adding unbounded headers can create cardinality/availability problems |
| Normalization | Cache and origin agree on resource identity | Independent decoding/canonicalization can diverge |
| Variation | `Vary` matches response negotiation | CDNs can override or constrain Vary support |
| Identity | Private/authenticated responses are not shared by accident | A user-keyed cache still needs authorization and invalidation |
| Freshness | Age, max-age, validation, and stale policy are explicit | Long TTLs amplify a wrong decision |

`Cache-Control: no-store` prohibits storage by compliant caches; `private` prohibits shared caching but permits private caches; `no-cache` permits storage but requires validation before reuse. These are not synonyms. Set-Cookie does not by itself universally prohibit caching. RFC 9111 restricts shared reuse of responses to requests carrying Authorization unless explicit conditions permit it; product/CDN rules can differ and must be inspected. This lab adopts a stricter authenticated-request bypass.

### Worked Response Contracts

```http
Cache-Control: public, max-age=60
Vary: Accept-Language
```

Use only for genuinely public negotiated content. Private account responses instead use:

```http
Cache-Control: private, no-store
```

Do not reflect arbitrary request headers into public output. If a business-required variant is finite, normalize it to a reviewed enum and include it in the key. If it is identity-specific, avoid shared storage or use an explicitly isolated authenticated cache design. Normalize path and authority once with the routing contract; do not let an extension rule override the application's privacy classification.

### Evidence, Versions, and Recovery

Record cache key dimensions (redacted), route classification, status, Age/cache-status metadata, TTL, origin response policy, and whether a second eligible request reused the representation. A cache miss or a changing cache-buster does not test reuse. Product-specific cache-status headers are diagnostic, not standardized guarantees.

The Python 3.12 fixture is an application cache, not an RFC-complete proxy. Real CDNs may apply custom keys, query filtering, cookie rules, stale serving, or regional tiers. Inventory those settings and versions. After fixing policy, purge affected entries and account for downstream/browser caches; changing the origin header does not retroactively erase every cached copy.

## Defense

Default dynamic authenticated routes to private/no-store, explicitly approve public caching, and align keys with allowed variation. Restrict untrusted authority/forwarding influence. Test routing and cache rules together after changes, including error responses. Maintain a scoped purge procedure and monitor private-route cache hits without logging private response bodies.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no cache service or network. Review a proposal that keys only on path and caches every response. The replacement recognizes exact public routes, keys on finite locale, tracks freshness with an injected clock, and bypasses shared storage for account/identity requests.

### File: test_example.py

```python
import unittest


class PublicCache:
	def __init__(self):
		self.entries = {}
		self.origin_calls = 0

	def get(self, route, language, user=None, now=0):
		if route not in {"/catalog", "/account"} or language not in {"en", "fr"}:
			raise ValueError("route or representation")
		if route == "/account":
			if user is None:
				raise PermissionError("authentication required")
			self.origin_calls += 1
			return f"Account for {user}", "private, no-store", "BYPASS"
		if user is not None:
			self.origin_calls += 1
			return f"Catalog {language}", "private, no-store", "BYPASS"
		key = ("https://shop.example", route, language)
		entry = self.entries.get(key)
		if entry is not None and now < entry[0]:
			return entry[1], "public, max-age=60", "HIT"
		self.origin_calls += 1
		body = {"en": "Public catalog", "fr": "Catalogue public"}[language]
		self.entries[key] = (now + 60, body)
		return body, "public, max-age=60", "MISS"


class CacheTests(unittest.TestCase):
	def test_variants_and_reuse(self):
		cache = PublicCache()
		english = cache.get("/catalog", "en")
		french = cache.get("/catalog", "fr")
		self.assertNotEqual(english[0], french[0])
		self.assertEqual(cache.get("/catalog", "en", now=1)[2], "HIT")
		self.assertEqual(cache.origin_calls, 2)

	def test_private_never_enters_shared_store(self):
		cache = PublicCache()
		first = cache.get("/account", "en", user="Ada")
		second = cache.get("/account", "en", user="Grace")
		self.assertNotEqual(first[0], second[0])
		self.assertEqual(first[1:], ("private, no-store", "BYPASS"))
		cache.get("/catalog", "en", user="Ada")
		self.assertEqual(cache.entries, {})

	def test_expiry_and_exact_routes(self):
		cache = PublicCache()
		cache.get("/catalog", "en", now=0)
		self.assertEqual(cache.get("/catalog", "en", now=60)[2], "MISS")
		with self.assertRaises(ValueError):
			cache.get("/unreviewed", "en")
		with self.assertRaises(PermissionError):
			cache.get("/account", "en")


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: separate cache eligibility from key composition. A perfect key does not make an unreviewed route public.

Solution: only anonymous catalog representations enter storage; locale is part of the key and expiry is deterministic. Expected: three tests pass, public repeats hit, locale variants remain distinct, private requests leave shared storage empty, and expiry triggers a miss. The fixture does not emit HTTP `Vary`; its return values are application metadata, so a real HTTP adapter must supply the documented headers.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. The injected `now` avoids sleeps and clock flakiness; use a monotonic clock for real elapsed-time logic. Run beside the named file. No external data or packages are needed; remove the disposable directory afterward. CDN normalization, revalidation, multi-tier purge, and browser behavior remain unverified.

- [ ] Local Cache Poisoning and Deception exercise: Review eligibility, key, and privacy rules.
- [ ] Boundary check: Run safe variant, identity-bypass, reuse, and expiry tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 9111: HTTP caching](https://www.rfc-editor.org/rfc/rfc9111)
- [RFC 9110: Vary](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5)
- [Cloudflare cache keys](https://developers.cloudflare.com/cache/how-to/cache-keys/)
