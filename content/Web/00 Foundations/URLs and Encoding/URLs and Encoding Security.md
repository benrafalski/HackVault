---
title: "URLs and Encoding Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[URLs and Encoding]]"
updated: 2026-11-03
---
# URLs and Encoding Security

> [!abstract] TL;DR
> Validate the structured value the final consumer will use, not a different textual representation. For a finite set of destinations or routes, identifiers mapped to configured URLs are safer and simpler than accepting arbitrary URLs.

## Attack Surface

URLs cross browser, proxy, framework, HTTP-client and sometimes filesystem parsers. Each has its own normalization rules. Raw controls, credentials, port syntax, duplicate query keys, Unicode host processing and repeat decoding can undermine an otherwise reasonable allowlist if validation and use disagree.

## Learn

```text
Teach me defensive URL handling with browser and backend parser boundaries.
Cover raw versus parsed validation, scheme/host/port allowlists, percent bytes,
strict UTF-8, form plus/duplicate keys, Unicode and IDNA profiles, relative URL
resolution, normalization ownership and context-specific output escaping.
Give a narrow configured-destination policy and independent offline tests using
synthetic harmless URLs. Compare an overly broad scheme-only policy with the
fixed structured check; preserve allowed destinations. Explain why this does
not solve DNS/redirect/network policy for an arbitrary outbound client. Do not
provide bypass, traversal, scanning or outbound exploitation exercises. Include
version differences, logs, primary sources and worked answers. Teach here,
without file edits or fabricated execution results.
```

## Cheatsheet

### Validation Order and Contracts

1. Set a size bound and reject raw controls before a parser silently strips them.
2. Parse using the same library/profile used by the consumer; catch errors including property-access errors such as invalid ports.
3. Validate scheme, userinfo prohibition, exact hostname, effective port and route/query policy independently.
4. Decode the intended component once, using strict byte/charset handling; normalize only as explicitly defined for that identifier.
5. Validate semantic values, then construct the final URL from validated fields or a configured mapping. Do not re-decode downstream.

| Decision | Unsafe shortcut | Correct boundary |
|---|---|---|
| Approved destination | Any `https` URL accepted | Exact parsed authority and port policy |
| Query singleton | Silently take first/last duplicated value | Parse ordered pairs, require exactly one |
| Label normalization | Decode repeatedly until text looks familiar | One owning decoder and strict semantic grammar |
| IDN comparison | Mix browser UTS 46 and another IDNA profile | Pin one profile or use fixed ASCII hostname inventory |
| Relative redirect | Treat arbitrary reference as appended path | Controlled local route identifiers or parsed same-origin check |
| Output into HTML | URL encoding alone | DOM URL property or proper attribute escaping plus URL policy |

Encoding is not validation. A valid URL can be disallowed by policy; a parser accepting input does not make it safe. Python `urlsplit` differs from WHATWG browser parsing and is not a validator. Python 3.12 strips leading C0 controls/spaces; pre-parse rejection prevents lost evidence. Browser `new URL()` may normalize a default port away. Compare effective port to 443 for HTTPS, not raw string presence alone.

### Narrow Construction Examples

Finite documentation destination mapping (complete fragment):

```python
DESTINATIONS = {
	"guide": "https://docs.example.test/docs/guide",
	"start": "https://docs.example.test/docs/start",
}
destination = DESTINATIONS["guide"]
```

Form parsing with a singleton requirement (fragment):

```python
from urllib.parse import parse_qsl
pairs = parse_qsl("view=compact", keep_blank_values=True, max_num_fields=16,
				  encoding="utf-8", errors="strict")
views = [value for key, value in pairs if key == "view"]
if len(views) != 1 or views[0] not in {"compact", "full"}:
	raise ValueError("invalid view")
```

`errors="strict"` catches invalid decoded UTF-8, not every malformed `%` sequence; validate triplets separately if the input contract requires it. NFC can unify canonically equivalent labels; NFKC can erase meaningful distinctions. Preserve original bytes separately where signatures or forensics require them, but redact sensitive values. Never normalize passwords, tokens or signed text without the protocol's explicit rule.

### Limits of a URL Check

A lexical host allowlist does not establish where a network connection goes. A general outbound client also needs resolved-address policy, redirect revalidation, bounded schemes/protocols, connection-time enforcement, TLS identity checks, timeouts and response-size limits. This note's lab deliberately makes no requests and does not implement such a client. Filesystem access needs separate path containment and race-safe access primitives; URL path validation alone is insufficient. Shared technique notes describe those domains without being prerequisites for this exercise.

## Detection and Defense

Log rejected decision categories, request ID, selected route and normalized authority, not full credentials or query values. Compare edge and application normalized route telemetry when diagnosing differences. Internationalized names, legacy encodings and legitimate duplicate-list query parameters are possible false positives: fix the contract deliberately rather than weakening a generic global filter. Reject unsupported forms early and return a clear 400-style validation response in an API.

## Labs

### Environment and Complete Files

Python 3.12+, stdlib. Synthetic URLs only; no DNS or HTTP calls. Policy intentionally permits two exact HTTPS documentation routes and no query/fragment/userinfo. Encoded paths are unnecessary for this finite interface and are rejected rather than decoded.

### File: test_example.py

```python
import unittest
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def approved_url(raw):
	if not isinstance(raw, str) or len(raw) > 512 or not raw.isascii():
		raise ValueError("unsupported input")
	if any(ord(char) <= 32 or ord(char) == 127 for char in raw) or "\\" in raw:
		raise ValueError("raw syntax")
	parts = urlsplit(raw)
	if (parts.scheme != "https" or parts.username is not None
			or parts.password is not None or parts.hostname != "docs.example.test"
			or parts.port not in (None, 443)):
		raise ValueError("authority policy")
	if parts.path not in {"/docs/guide", "/docs/start"} or parts.query or parts.fragment:
		raise ValueError("route policy")
	return urlunsplit(("https", "docs.example.test", parts.path, "", ""))


def view_parameter(query):
	pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=8,
					  encoding="utf-8", errors="strict")
	if len(pairs) != 1 or pairs[0][0] != "view" or pairs[0][1] not in {"compact", "full"}:
		raise ValueError("one supported view required")
	return pairs[0][1]


class URLPolicyTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		unlisted = "https://other.example.test/docs/guide"
		baseline_scheme_only = urlsplit(unlisted).scheme == "https"
		self.assertTrue(baseline_scheme_only)
		with self.assertRaises(ValueError):
			approved_url(unlisted)
		self.assertEqual(approved_url("https://DOCS.example.test:443/docs/guide"),
						 "https://docs.example.test/docs/guide")

	def test_rejected_components(self):
		for raw in ("http://docs.example.test/docs/guide",
					"https://docs.example.test:8443/docs/guide",
					"https://docs.example.test/docs/unknown",
					"https://docs.example.test/docs/guide#part",
					" https://docs.example.test/docs/guide"):
			with self.subTest(raw=raw), self.assertRaises(ValueError):
				approved_url(raw)

	def test_query_cardinality(self):
		self.assertEqual(view_parameter("view=compact"), "compact")
		with self.assertRaises(ValueError):
			view_parameter("view=compact&view=full")
		with self.assertRaises(ValueError):
			view_parameter("view=")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run `python -m unittest -v test_example`; compare the scheme-only baseline and structured destination policy.
2. Remove the hostname condition temporarily; the baseline/fix test must fail, then restore it.
3. Explain why explicit 443 normalizes away, but 8443 is rejected; why duplicate `view` values are rejected even though both individual values are recognized.
4. Add a positive `/docs/start` test and an invalid-port negative test; catch ValueError at the call boundary.

### Hints

The final URL is reconstructed from approved values, not the original authority text. `.port` is an operation that can fail. The policy's ASCII/path restrictions are business constraints, not claims about all legal URLs.

### Solution and Fixed Retest

Expected: three tests pass. The unlisted HTTPS host passes the weak baseline but fails the fixed policy; uppercase approved host plus default port becomes the canonical approved URL. Other port, scheme, route, fragment and raw whitespace fail. Exactly one supported `view` survives. No redirects, addresses or external resources are accessed.

### Verification, Troubleshooting, and Cleanup

Author execution prohibited; optional pytest command: `python -m pytest -q test_example.py`. No packages required for unittest. A new accepted destination requires an explicit policy change and matching positive/negative tests. Delete the lab directory and caches; no external state changed.

- [ ] Record broad-baseline and narrow-policy results.
- [ ] Explain decoding, Unicode and downstream-consumer boundaries.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Path Traversal]]
- [[SSRF]]
- [[URLs and Encoding]]

## References

- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [Python URL parsing security](https://docs.python.org/3.12/library/urllib.parse.html#url-parsing-security)
- [Unicode IDNA compatibility processing](https://unicode.org/reports/tr46/)
