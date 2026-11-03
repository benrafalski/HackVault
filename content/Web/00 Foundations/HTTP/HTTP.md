---
title: "HTTP/1.1"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[HTTP Security]]"
updated: 2026-11-03
---
# HTTP/1.1

> [!abstract] TL;DR
> HTTP semantics describe what a message means; framing determines where it ends. Reusing an HTTP/1.1 connection is safe only when both sides agree on the end of every message and consume or discard it correctly.

## Prerequisites

TCP byte streams, URL authority/path, and UTF-8 bytes. Lab: Python 3.12+ standard library, no server or external service. See [[Web Lab Setup]] for capture hygiene.

## Learn

```text
Teach me HTTP/1.1 at wire and application depth. Assume TCP and basic URLs.
Trace request-target forms, Host, CRLF fields, body-length precedence, chunked
coding/trailers, HEAD and no-body statuses, interim responses and connection
reuse. Explain safe/idempotent methods, conditional requests, status decisions,
representation versus transfer metadata, redirects and intermediaries. Give
worked octet counts, exact curl commands and an offline real-parser lab with
positive and truncated-body tests. Explain why one recv is not one request,
why a redirect can alter method/authority, and how proxies remove hop fields.
Use RFC 9110/9111/9112 and explicit Python version distinctions. Teach here,
not by editing files; do not generate exploit requests or claim unrun tests.
End with worked boundary and retry questions.
```

## Cheatsheet

### Message Anatomy and Framing

An origin request has `METHOD SP request-target SP HTTP/1.1 CRLF`, fields, a blank CRLF, and an optional body. Example bytes below use CRLF at every displayed line ending; the body is exactly five ASCII bytes with no extra newline:

```http
POST /messages?mode=preview HTTP/1.1
Host: example.test
Content-Type: text/plain; charset=utf-8
Content-Length: 5

hello
```

Origin-form is path/query; absolute-form is commonly used with explicit HTTP proxies; authority-form belongs to CONNECT; asterisk-form is used by server-wide OPTIONS. URL fragments are never sent in the request target. HTTP/1.1 requires Host. Field names are case-insensitive, but values have field-specific grammars. Preserve repeated fields where their specification requires it: `Set-Cookie` is not a comma-joined list field.

| Situation | Body delimitation |
|---|---|
| Response to HEAD; 1xx, 204 or 304 | No message body regardless of a representation length field |
| Successful CONNECT response | Following bytes belong to the tunnel, not another ordinary response body |
| Final transfer coding is chunked | Hex chunk size, chunk bytes, CRLF; zero chunk then trailers/end |
| Valid Content-Length, no transfer coding | Exactly that many octets |
| Request with neither framing field | No request body |
| Response otherwise allowed a body but no length | Read to connection close; cannot safely reuse that connection |

Transfer-Encoding takes precedence under the protocol's parsing rules, but conflicting framing is a security error and should be rejected at a strict ingress. Do not write an ad hoc production parser. An incomplete length-delimited response is an error, not a shorter successful representation. Content-Length counts encoded bytes: `len("caf\u00e9".encode("utf-8"))` is five, not four. Content-Encoding such as gzip describes representation coding; Transfer-Encoding chunked frames transport and is removed by a receiving hop.

Chunked body representing `hello`:

```text
5\r\nhello\r\n0\r\n\r\n
```

Trailer fields arrive after content and cannot retroactively decide routing or authentication. Applications and proxies differ in trailer support; never rely on them for checks that must precede body processing.

### Methods, Conditions, and Status

| Operation | Semantics | Retry caution |
|---|---|---|
| GET / HEAD | Safe and idempotent; HEAD returns metadata without body | Avoid state-changing handlers; caches/prefetchers may invoke them |
| PUT | Replace target state; idempotent intent | Responses can differ; concurrent writers need preconditions |
| DELETE | Idempotent intent | A second call may return 404 without violating idempotence |
| POST | Resource-specific processing | Do not blindly retry after unknown outcome; explicit idempotency contract |
| PATCH | Partial update; not inherently idempotent | Depends on patch operations and preconditions |

`If-None-Match` with GET/HEAD supports 304 reuse; `If-Match` with a current ETag can prevent lost updates and return 412 on mismatch. 201 indicates creation and commonly provides Location; 202 means accepted, not completed; 204 has no content. 400 is malformed request, 401 requires an authentication challenge, 403 refuses access, 404 can intentionally conceal existence, 405 includes Allow, 409 signals state conflict, 415 unsupported media, 429 rate limiting, 502 bad upstream response, 503 temporary unavailability, 504 upstream timeout. Status and application result must both be interpreted: a JSON error inside 200 is still a successful HTTP status.

### Reuse, Redirects, and Intermediaries

HTTP/1.1 persistence is default unless closure is signaled/required. Drain the body before reusing a connection; pipelined responses must retain request order and therefore suffer application head-of-line blocking. A connection is not a user session. Pooling, cookies and authorization are separate state.

| Redirect | Method rule | Decision |
|---|---|---|
| 301 / 302 | Historical clients may turn POST into GET | Do not rely on preserving a mutation |
| 303 | Follow with retrieval, normally GET | Useful after POST to a result resource |
| 307 / 308 | Preserve method and body | Revalidate destination, replayability and credential policy |

Location can be relative; resolve against the response URL. Limit redirect count; do not forward sensitive authorization across origins automatically. A proxy may route, cache, transform and translate protocol versions. Connection and fields named by its tokens are hop-specific and must not blindly reach the next hop. Via describes intermediaries; Forwarded/X-Forwarded fields require an explicit trusted-proxy policy. Caches need correct Vary, freshness and authorization handling, not merely a 200 status.

Read-only diagnostics for an already-running authorized loopback service:

```sh
curl --http1.1 -i http://127.0.0.1:8000/
curl --http1.1 -I http://127.0.0.1:8000/
curl --http1.1 -v --max-time 5 http://127.0.0.1:8000/
```

`-I` sends HEAD; `-i` prints response fields; `-v` can expose request credentials. These commands are not needed for the offline lab.

## Gotchas

JSON can be any JSON value, not only an object. A 304 has no body but refers to a cached representation. A HEAD Content-Length can describe the corresponding GET representation and is not permission to read those bytes. HTTP/1.0 persistence rules differ; Python's basic HTTP server defaults are not production HTTP policy.

## Labs

### Environment and Complete Files

Python 3.12+, no dependencies/network. Python's real `http.client.HTTPResponse` parses byte fixtures through a file-like socket adapter. This tests that client parser, not a reverse proxy or TCP segmentation.

### File: test_example.py

```python
import http.client
import io
import unittest


class ByteSocket:
	def __init__(self, data):
		self.data = data

	def makefile(self, mode):
		return io.BytesIO(self.data)


def response(data, method="GET"):
	parsed = http.client.HTTPResponse(ByteSocket(data), method=method)
	parsed.begin()
	return parsed


class HTTPTests(unittest.TestCase):
	def test_octet_length_and_reuse(self):
		body = "caf\u00e9".encode("utf-8")
		wire = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
				b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + body)
		with response(wire) as parsed:
			self.assertFalse(parsed.will_close)
			self.assertEqual(parsed.read().decode("utf-8"), "caf\u00e9")

	def test_chunked(self):
		wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
				b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n")
		with response(wire) as parsed:
			self.assertTrue(parsed.chunked)
			self.assertEqual(parsed.read(), b"hello")

	def test_head_and_redirect(self):
		with response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n", "HEAD") as parsed:
			self.assertEqual(parsed.read(), b"")
		with response(b"HTTP/1.1 303 See Other\r\nLocation: /result\r\n"
					  b"Content-Length: 0\r\n\r\n") as parsed:
			self.assertEqual(parsed.status, 303)
			self.assertEqual(parsed.getheader("Location"), "/result")
			self.assertEqual(parsed.read(), b"")

	def test_truncated_body(self):
		with response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi") as parsed:
			with self.assertRaises(http.client.IncompleteRead) as caught:
				parsed.read()
			self.assertEqual(caught.exception.partial, b"hi")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`; map the body boundary in each fixture.
2. Change the UTF-8 Content-Length from 5 to 4; observe decode failure, then restore 5. This remains an offline fixture.
3. Explain why HEAD succeeds without 99 bytes and why the parser exposes Location without following it.
4. Compare chunk payload bytes with chunk framing bytes; compute the actual decoded representation length.

### Hints

Read metadata before consuming content. Redirect following belongs to a higher-level client. HTTPResponse handles framing but does not implement application authentication or every strict edge policy.

### Solution and Expected Results

Expected: four tests pass. UTF-8 body is five octets; chunked content decodes to `hello`; HEAD content is empty; redirect remains 303; truncated length raises IncompleteRead with partial `hi`. Changing the length to four cuts a UTF-8 sequence. `will_close=False` describes framing eligibility for reuse, not an actual reused network connection in this lab.

### Verification, Troubleshooting, and Cleanup

Author did not run these commands. Optional `python -m pytest -q test_example.py` requires pytest. Preserve literal `\r\n` escapes; a text editor converting them to actual multiline strings breaks Python syntax. Delete the lab directory and caches; no sockets or services were created.

- [ ] Explain message boundaries and HEAD without a network dependency.
- [ ] Distinguish redirect, retry, and persistent-connection decisions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Request Smuggling]]
- [[Host Header Attacks]]
- [[HTTP Security]]

## References

- [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
- [HTTP/1.1 framing, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
- [HTTP caching, RFC 9111](https://www.rfc-editor.org/rfc/rfc9111)
- [Python HTTP client](https://docs.python.org/3.12/library/http.client.html)
