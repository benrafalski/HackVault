---
title: "URLs and Encoding"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[URLs and Encoding Security]]"
updated: 2026-11-03
---
# URLs and Encoding

> [!abstract] TL;DR
> Percent encoding encodes bytes within a component, not a whole trust decision. URL parsing, UTF-8 decoding, form parsing, Unicode normalization and output escaping are distinct operations with distinct grammars.

## Prerequisites

HTTP request targets and Unicode code points versus encoded bytes. Lab: Python 3.12+ standard library. Browser-console examples use the current WHATWG URL API and need no network.

## Learn

```text
Teach me URLs and encoding at parser-boundary depth. Explain scheme, authority,
userinfo, host/IP literals, port, path segments, query and fragment; relative
resolution and special-scheme WHATWG parsing versus RFC-oriented libraries.
Work through percent bytes, UTF-8, reserved/unreserved characters, form plus
conversion, repeated query keys, Unicode NFC/NFKC and IDNA. Compare JavaScript
URL/URLSearchParams with Python 3.12 urllib.parse without assuming identical
validation. Give complete offline round-trip and strict-decoding tests and
exact expected representations at each boundary. Explain encoding for URL
components versus HTML/JS/SQL/shell contexts. Cite standards and version changes.
Teach here, do not edit files or claim execution; end with worked examples.
```

## Cheatsheet

### Components and Relative Resolution

For `https://example.test:8443/a/b?q=one+two&tag=x&tag=y#part`, scheme is `https`, host `example.test`, port 8443, path `/a/b`, query is the text after `?`, and fragment is `part`. A query is not intrinsically a dictionary; key/value form interpretation belongs to the consumer. Repeated keys and their order can matter. Userinfo is a separate authority component, not part of the hostname, and should normally be excluded from application URLs. IPv6 literals need brackets in serialized authority, for example `https://[::1]:8443/`.

Fragments are processed client-side and are absent from ordinary HTTP request targets. A relative reference depends on a base: `new URL("next", "https://example.test/a/")` becomes `/a/next`; with base `/a` it becomes `/next`. A leading slash replaces the path; a full absolute reference can replace the origin. Do not treat general URL resolution as safe path concatenation.

Browser fragment, complete console expressions:

```javascript
const target = new URL("https://example.test/a%2Fb?q=a+b&tag=x&tag=y#part");
console.log(target.pathname);
console.log(target.searchParams.get("q"));
console.log(target.searchParams.getAll("tag"));
console.log(target.hash);
console.log(new URL("https://EXAMPLE.test:443/").origin);
```

Expected values in order: `/a%2Fb`, `a b`, `["x", "y"]`, `#part`, and `https://example.test`. These expressions parse values only; they make no requests.

### Encoding Decisions

| Task | JavaScript | Python 3.12 | Important boundary |
|---|---|---|---|
| Single path segment | `encodeURIComponent(value)` | `quote(value, safe="")` | Never encode the complete URL as one segment |
| Form/query pairs | `new URLSearchParams(pairs)` | `urlencode(pairs)` | Space becomes `+`; literal plus becomes `%2B` |
| Repeated form keys | `.append`, `.getAll` | `parse_qsl`, tuple list | Do not silently drop all but one value |
| Percent bytes | Component-specific decoding | `unquote_to_bytes` | Bytes first; then strict selected charset |
| Form decode | `URLSearchParams` | `parse_qsl` / `unquote_plus` | `+` is space here, not in an arbitrary path |

`unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`. Reserved characters such as `/`, `?`, `#`, `&`, `=` have structural roles; decoding them too early can change component boundaries. `%C3%A9` represents two UTF-8 bytes for one code point. `%2F` is an encoded slash; whether a routing layer preserves it or treats it as a separator is a server/framework policy. Do not decode an entire URL before parsing components. Percent hex case is insensitive, but path case generally is not.

`encodeURI` preserves structural delimiters and is not interchangeable with `encodeURIComponent`. Neither performs HTML escaping; assigning a URL to a DOM property and inserting a quoted HTML attribute are different output contexts. JavaScript component encoding can throw for lone surrogate code units. Python's default unquote text behavior can replace invalid UTF-8 unless `errors="strict"` is selected; strict text decoding alone still does not reject every malformed percent triplet.

### Unicode and Normalization

NFC composes canonically equivalent sequences, such as `e` plus combining acute versus precomposed accented e. NFKC additionally folds compatibility distinctions and can change identifier meaning. Choose a policy at identifier creation and lookup; do not silently normalize secrets or signatures. Hostnames use IDNA ASCII labels where applicable; Python's built-in `idna` codec and browser UTS 46 processing are not interchangeable for all inputs. Record the exact library/profile for internationalized identity policy. ASCII-only host allowlists can avoid this ambiguity for a small fixed destination set.

WHATWG URL serialization normalizes special-scheme hosts, default ports and path components. Python `urlsplit` is a splitter, not a full browser-equivalent validator; it can accept values a consumer handles differently. Python 3.10 strips ASCII newline/tab and Python 3.12 strips leading WHATWG C0 controls/spaces during parsing, so validate forbidden raw controls before parsing when preservation/rejection matters. Accessing `.port` can itself raise `ValueError` for an invalid port. Python 3.10+ query parsing defaults to `&` as separator, rather than automatically treating `;` the same way.

### Boundary Checklist

Parse structure with the consumer-compatible parser; decode only the relevant component once; decode bytes using the required charset; normalize only under the data contract; validate the resulting semantic value; serialize through the same abstraction. Log the route/key selected, not sensitive full query strings. Signature protocols must define the exact canonical byte representation rather than hashing whichever serialization a library happens to emit.

## Gotchas

`URLSearchParams` may reserialize query escaping differently even if semantics stay the same. `dict(parse_qsl(...))` loses duplicates. `%20` and `+` are equivalent only in a form-decoding context. A safe URL component is not safe shell or SQL syntax.

## Labs

### Environment and Complete Files

Python 3.12+, no dependencies/network. Fixtures compare real stdlib parsing/encoding and a strict single-component decoder. It is not a browser parser or proxy normalization test.

### File: test_example.py

```python
import re
import unicodedata
import unittest
from urllib.parse import parse_qsl, quote, unquote, unquote_to_bytes, urlencode, urlsplit


def strict_component(value):
	if re.search(r"%(?![0-9A-Fa-f]{2})", value):
		raise ValueError("bad percent triplet")
	return unquote_to_bytes(value).decode("utf-8", errors="strict")


class EncodingTests(unittest.TestCase):
	def test_components(self):
		parsed = urlsplit("https://example.test:8443/a%2Fb?q=a+b#part")
		self.assertEqual((parsed.scheme, parsed.hostname, parsed.port),
						 ("https", "example.test", 8443))
		self.assertEqual(parsed.path, "/a%2Fb")
		self.assertEqual(parsed.fragment, "part")
		request_target = parsed.path + "?" + parsed.query
		self.assertEqual(request_target, "/a%2Fb?q=a+b")

	def test_form_roundtrip(self):
		pairs = [("q", "a+b c"), ("tag", "x"), ("tag", "y"), ("empty", "")]
		encoded = urlencode(pairs)
		self.assertEqual(encoded, "q=a%2Bb+c&tag=x&tag=y&empty=")
		self.assertEqual(parse_qsl(encoded, keep_blank_values=True), pairs)
		self.assertEqual(unquote("a+b"), "a+b")

	def test_unicode_bytes(self):
		word = "caf\u00e9"
		self.assertEqual(quote(word, safe=""), "caf%C3%A9")
		self.assertEqual(strict_component("caf%C3%A9"), word)
		self.assertEqual(unicodedata.normalize("NFC", "cafe\u0301"), word)
		self.assertEqual(len(word.encode("utf-8")), 5)

	def test_decode_once_and_errors(self):
		self.assertEqual(strict_component("label%2520one"), "label%20one")
		with self.assertRaises(ValueError):
			strict_component("label%GG")
		with self.assertRaises(UnicodeDecodeError):
			strict_component("%FF")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`. Write raw, parsed, decoded and serialized forms for each input.
2. Remove `keep_blank_values=True`; confirm the round-trip test fails, then restore it.
3. Decode `label%2520one` once and explain why a second decode would violate this component contract.
4. Optionally run the browser console expressions; compare preserved pathname with decoded form values without contacting the named host.

### Hints

Percent decoding and form decoding differ. UnicodeDecodeError is a kind of UnicodeError/ValueError, but the explicit exception identifies the charset boundary. Duplicate keys require a sequence representation.

### Solution and Expected Results

Expected: four tests pass. Fragment is excluded from `/a%2Fb?q=a+b`; the form round-trip preserves a literal plus, space, both tags and the empty value. Accented e occupies two UTF-8 bytes; the word occupies five. Single decoding preserves `%20` as literal text in the encoded-percent example. These are Python results; browser equality must be assessed separately for policy-sensitive inputs.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional `python -m pytest -q test_example.py` requires pytest. Preserve Python Unicode escapes exactly. No host files, routes or servers change; remove the disposable directory and bytecode caches.

- [ ] Record byte, character, form and component representations.
- [ ] Explain decoder ownership and cross-parser limitations.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Path Traversal]]
- [[SSRF]]
- [[URLs and Encoding Security]]

## References

- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [URI generic syntax, RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
- [Python urllib.parse](https://docs.python.org/3.12/library/urllib.parse.html)
- [Unicode normalization](https://unicode.org/reports/tr15/)
