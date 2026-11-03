---
title: "HTTP Caching Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[HTTP Caching]]"
updated: 2026-11-03
---
# HTTP Caching Security

> [!abstract] TL;DR
> Unkeyed attacker input can poison a shared response; path/policy confusion can cache one user's private response for another.

> [!info] Agent scope
> Security of: Cache keys; freshness; validation; Vary; shared versus private caches; authentication interactions; intermediary behavior. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unkeyed attacker input can poison a shared response; path/policy confusion can cache one user's private response for another.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive shared HTTP cache design at expert depth, assuming RFC
9110/9111 and authentication fundamentals. Explain response-dependency versus
key completeness, private/shared storage, Authorization and cookies, Vary,
freshness/304 merging, negative caching, stale controls and purge lifetimes.
Show concrete safe policies, reverse-proxy cache gates and an independent
offline baseline/fix lab using only synthetic account and language markers.
Require positive public-cache reuse and negative personalized-storage tests.
Explain real CDN overrides and unsupported fixture semantics, diagnosis and
false positives. No exploitation, cache poisoning procedure, credential access,
network service or host policy changes. Use primary sources; teach here without
editing files or claiming unperformed tests.
```

## Cheatsheet

### Key Completeness and Storage Eligibility

For every response input, decide: include it in the key using origin-equivalent semantics, remove it before the origin so it cannot change the response, or disallow shared storage. Inputs include method, scheme, authority, path/query, selected representation headers and application identity. Merely adding every incoming header produces unbounded key cardinality and is not a good design. Use public route allowlists with deliberate variant contracts; keep sensitive routes out of shared caches.

| Design defect | Defensive policy | Edge case |
|---|---|---|
| Personalized route uses shared TTL | `Cache-Control: private, no-store`; edge bypass and no storage | Error/redirect responses must inherit the private policy |
| Language changes body but not key | `Vary: Accept-Language` plus matching edge configuration | CDN may normalize or omit `Vary`; verify actual behavior |
| All static-looking paths cached | Classify by explicit route contract, not suffix | Application routers can produce dynamic bodies at many paths |
| Cookies assumed to disable caching | Explicit request/response storage gates | `Set-Cookie` is not a universal RFC no-store signal |
| Authentication removed from consideration | Bypass requests carrying credentials unless a reviewed public contract applies | RFC shared-cache exceptions must not accidentally expose personalized content |
| Long stale window on private data | Never share/store it; narrow public stale allowances | Logout does not revoke already delivered browser copies |
| Purge assumed instantaneous | Versioned public URLs and verified provider invalidation | Variants, regions and negative cached responses may differ |

`private` prohibits shared storage, not private browser storage. `no-cache` allows storage but requires validation before reuse. `no-store` is the strongest ordinary HTTP storage directive, but cannot erase arbitrary prior copies. Authorization remains an origin responsibility on revalidation: a 304 still confirms reuse of a representation. Reusing an ETag or stale body across user identities can violate privacy even without a new 200 body. `Vary: Cookie` is generally not a substitute for excluding personalized responses from shared storage.

### Concrete Response Contracts

Public, low-cardinality negotiated catalog:

```http
Cache-Control: public, max-age=30, s-maxage=60
Vary: Accept-Language, Accept-Encoding
ETag: "catalog-en-identity-v3"
```

The strong tag must correspond to the actual selected encoded bytes; a compressed variant needs an appropriate validator. For account responses, including authentication errors and redirects:

```http
Cache-Control: private, no-store
```

Do not attach a shared TTL to the private route in a CDN override. Authentication failures containing useful private context should not be negatively cached. For immutable public assets, a content-derived URL and long lifetime is appropriate only if publication never rewrites those bytes under the same name.

### NGINX Storage and Lookup Gates

NGINX OSS 1.28 reference fragment, requiring a separately configured upstream named `origin`, cache zone `public_cache`, and reviewed route. No service is launched and this is not required for the lab:

```nginx
# http context
map $http_authorization $has_auth { default 1; "" 0; }
map $http_cookie $has_cookie { default 1; "" 0; }

# exact public location inside server context
location = /catalog {
	proxy_pass http://origin;
	proxy_cache public_cache;
	proxy_cache_key "$scheme|$host|$request_uri";
	proxy_cache_bypass $has_auth $has_cookie;
	proxy_no_cache $has_auth $has_cookie $upstream_http_set_cookie;
}
```

The first gate avoids **reading** an existing shared entry; the second avoids **writing** a response. Both matter. This conservative policy bypasses all cookie-bearing requests, which can reduce hit rate. NGINX normally processes response Cache-Control, Set-Cookie and Vary for cache decisions; do not use `proxy_ignore_headers` to discard them without a narrowly reviewed reason. Keying host is not host validation: enforce allowed authorities separately. GET/HEAD handling, normalized URI use and vendor behavior must be checked against the actual deployment.

This fragment is not a complete policy for public catalog content: the origin must still emit its reviewed variant headers, TTL and no personalized values. A cache zone merely stores data; it does not enforce business classification. Keep cache storage, purge credentials and rule-change authority separate from normal application read access.

## Detection and Defense

Record synthetic response marker, route classification, selected variant, cache status, age, origin request ID and configuration revision. Never log real cookies or authorization values to explain a hit. Review changes to key composition, header overrides, TTL/stale rules, route matchers and purge access. A cache HIT on a public catalog is expected; a HIT on a no-store account route is actionable. A MISS is inconclusive because another cache layer may have served the content. Use known synthetic identities and inspect every relevant layer independently.

## Labs

### Environment and Complete Files

Python 3.12 standard library only, one empty directory and the one file below. All data is embedded and synthetic; no HTTP requests or external cache. This is a concrete allowlisted in-memory cache plus a design-contract reviewer. It does not parse general HTTP headers, simulate browser storage or implement full RFC/provider cache semantics. Unsafe baseline intent is only inspected, never used to serve another user's data.

### File: test_example.py

```python
import unittest

BASELINE = {"key_language": False, "exclude_identity": False, "honor_no_store": False}


def findings(config):
	return {name for name in BASELINE if config.get(name) is not True}


def fixed():
	return {name: True for name in BASELINE}


class SharedCache:
	def __init__(self, config):
		if findings(config):
			raise ValueError("unapproved cache contract")
		self.entries = {}

	def request(self, path, language="en", user=None, cookie=False,
				no_store=False, set_cookie=False):
		if language not in {"en", "fr"}:
			raise ValueError("unknown language")
		if path == "/account":
			if user not in {"alice", "bob"}:
				return b"sign-in-required", "BYPASS"
			return ("account:" + user).encode(), "BYPASS"
		if path != "/catalog":
			return b"not-found", "BYPASS"
		body = {"en": b"public-book", "fr": b"public-livre"}[language]
		key = ("https", "lab.example", path, language)
		if user is not None or cookie or no_store:
			return body, "BYPASS"
		if key in self.entries:
			return self.entries[key], "HIT"
		if not set_cookie:
			self.entries[key] = body
		return body, "MISS"


class CachePrivacyTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(findings(BASELINE), set(BASELINE))
		with self.assertRaises(ValueError):
			SharedCache(BASELINE)
		self.assertEqual(findings(fixed()), set())

	def test_public_reuse_and_variant_separation(self):
		cache = SharedCache(fixed())
		self.assertEqual(cache.request("/catalog"), (b"public-book", "MISS"))
		self.assertEqual(cache.request("/catalog"), (b"public-book", "HIT"))
		self.assertEqual(cache.request("/catalog", "fr"), (b"public-livre", "MISS"))

	def test_accounts_not_stored(self):
		cache = SharedCache(fixed())
		for user in ("alice", "bob", "alice"):
			self.assertEqual(cache.request("/account", user=user),
							 (("account:" + user).encode(), "BYPASS"))
		self.assertEqual(cache.entries, {})

	def test_credentials_and_no_store_skip_existing_hit(self):
		cache = SharedCache(fixed())
		cache.request("/catalog")
		for option in ({"user": "alice"}, {"cookie": True}, {"no_store": True}):
			self.assertEqual(cache.request("/catalog", **option)[1], "BYPASS")

	def test_response_cookie_and_unknown_route_not_stored(self):
		cache = SharedCache(fixed())
		self.assertEqual(cache.request("/catalog", set_cookie=True)[1], "MISS")
		self.assertEqual(cache.request("/unknown")[1], "BYPASS")
		self.assertEqual(cache.entries, {})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

Run `python -m unittest -v test_example`. Identify the three baseline policy defects and explain why the cache refuses initialization until fixed. Retest the same contract after `fixed()`. Verify public reuse remains enabled, language variants remain distinct, both synthetic accounts always bypass, and credential/no-store requests skip an existing entry.

### Hints

The `no_store` argument is a trusted fixture decision that excludes both lookup and storage, not a complete parser for request/response directives. `set_cookie` represents a newly fetched origin response, so it only applies on a MISS. A cached hit makes no origin call and cannot predict a future origin header. Production policies must prevent sensitive content from becoming a shared entry in the first place.

### Solution and Fixed Retest

Five tests should pass. The fix requires language keying, identity exclusion and storage restrictions before constructing the cache. Public English content transitions MISS to HIT; French remains a separate MISS. Each account gets its own synthetic marker without storage, credential/no-store traffic bypasses a warm cache, and a response cookie prevents storing a new public response. Unknown routes are never cached. No private-data disclosure or poisoning experiment is performed.

### Verification, Troubleshooting, and Cleanup

Each test creates a fresh cache, so there is no external purge step. If results differ, compare the copied flags and key tuple before interpreting the failure. Restore the printed fixture to reset, then delete the directory and `__pycache__`. Tests, browsers, proxies and CDNs were not run during authoring. Historical runtime milestones below remain uncompleted.

### User-Owned Milestones

- [ ] Local HTTP Caching exercise: Serve a public versioned response with an ETag and a private user response. Observe fresh hits, revalidation, and account switching through a local shared cache.
- [ ] Boundary check: Vary a harmless request header that changes the origin response and verify it is either keyed or never shared. Check that two synthetic users never receive each other's private content.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Cache Poisoning and Deception]]
- [[HTTP Caching]]

## References

- [RFC 9111 HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111)
- [RFC 9110 conditional requests](https://www.rfc-editor.org/rfc/rfc9110)
- [NGINX cache directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [CloudFront cache keys](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-the-cache-key.html)
