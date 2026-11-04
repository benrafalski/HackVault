---
title: "HTTP/2 and HTTP/3"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[HTTP2 and HTTP3 Security]]"
updated: 2026-11-03
---
# HTTP/2 and HTTP/3

> [!abstract] TL;DR
> HTTP/2 multiplexes framed streams over one ordered TCP byte stream. HTTP/3 maps HTTP to QUIC streams, removing TCP cross-stream delivery blocking but retaining congestion, flow-control, and application dependencies.

## Prerequisites

[[HTTP]], [[TCP and IP]], and [[TLS and PKI]]. Python 3.12+ suffices for the offline wire-format lab. It does not negotiate or implement either protocol.

## Learn

```text
Teach me HTTP/2 and HTTP/3 from bytes to operational behavior. Explain H2's
preface, nine-byte frame header, stream lifecycle, SETTINGS, stream/connection
flow control, HPACK tables and CONTINUATION ordering. Contrast QUIC packet,
connection and stream identities, TLS 1.3, loss recovery, migration, H3 control
streams, variable-length integers and QPACK blocking. Cover ALPN, Alt-Svc,
HTTPS DNS records, fallback, pseudo-headers, trailers and H1 translation.
Give worked byte examples, an offline framing lab, and exact diagnostics with
build-feature checks. Distinguish protocol capability from client support and
client-edge from edge-origin transport. Cite RFCs 9113/9114/9000/7541/9204.
Teach here without file edits; do not claim a codec exercise demonstrates real
multiplexing, speed or resilience. Finish with worked design tradeoffs.
```

## Cheatsheet

### HTTP/2

TLS deployments negotiate ALPN `h2`; cleartext/prior-knowledge support is client-specific, and browsers normally use TLS. The client connection preface begins `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, then SETTINGS. Both peers exchange settings; ACK acknowledges receipt, not agreement to arbitrary invalid values.

Every frame has length (24 bits), type (8), flags (8), reserved bit plus stream ID (31), then payload. Stream zero is for connection-level control. Client-initiated bidirectional request streams use odd positive IDs, increasing without reuse. HEADERS opens or continues a message's fields; DATA carries content; END_STREAM closes one direction. END_HEADERS terminates a field block and is distinct from END_STREAM. A HEADERS field block split into CONTINUATION frames must remain contiguous on that connection until END_HEADERS.

| Frame | Role / constraint |
|---|---|
| SETTINGS | Connection parameters, stream 0; ACK has empty payload |
| HEADERS / CONTINUATION | HPACK block; pseudo-fields precede ordinary fields |
| DATA | Stream body; flow-controlled at connection and stream levels |
| WINDOW_UPDATE | Positive flow-control increment; does not raise application queue capacity |
| RST_STREAM | Terminates one stream; does not close whole connection |
| GOAWAY | Connection shutdown with last processed stream context; retry still depends on semantics |
| PING | Connection liveness/RTT aid; not proof of application health |

Initial DATA flow-control windows are 65,535 bytes; SETTINGS_INITIAL_WINDOW_SIZE adjusts stream windows, not the connection window directly. Default max frame payload is 16,384, adjustable within protocol bounds. Header blocks are not DATA-window controlled, so separate decoded-header limits are necessary. Prioritization support varies; RFC 9218 replaces assumptions about older priority-tree behavior in many deployments.

HPACK has a static table and a per-connection dynamic table. Indexed representations save repeated strings; literals can add entries or request never-indexed handling. `82` alone is the indexed field `:method: GET` (static index 2); it is a fragment, not a complete request. Table size bounds compressed state, not the total decoded field-section size. Huffman encoding is a fixed code, not encryption. A decoder error can corrupt shared compression state and require connection failure.

### HTTP/3 and QUIC

QUIC uses UDP but provides encrypted, reliable ordered delivery within each stream. Stream independence means loss affecting one stream need not stall delivery on another; shared congestion control, connection-level flow control and application dependencies remain. QUIC integrates TLS 1.3 handshake messages without the TLS record layer. Connection IDs can survive address changes; a five-tuple is not a permanent connection identity. Migration/path validation are protocol features, not permission to change application identity.

Each H3 request uses a client-initiated bidirectional QUIC stream. Unidirectional control, QPACK encoder, and QPACK decoder streams carry connection state; these critical streams are not ordinary requests. H3 frames use QUIC variable-length integers for type and payload length, not H2's fixed nine-byte header. Stream IDs live in QUIC, not in each H3 frame.

QPACK separates table updates from field sections. Required Insert Count and Base identify dynamic dependencies; a field section may block until its referenced inserts arrive. SETTINGS_QPACK_BLOCKED_STREAMS and dynamic-table capacity bound this behavior. Static/literal representations can avoid dynamic dependencies at a bandwidth cost. QPACK is not HPACK over UDP.

### Semantics, Negotiation, and Translation

| Property | H2 | H3 |
|---|---|---|
| Transport / ALPN | TCP + TLS, `h2` | QUIC + TLS 1.3, `h3` |
| Field compression | HPACK | QPACK |
| End of message | END_STREAM flag | End of QUIC sending direction |
| Loss scope | TCP delivery can block all streams | Reliable delivery independently ordered per stream |
| Flow control | HTTP/2 DATA windows | QUIC stream/connection limits |
| Discovery | TLS ALPN / configured prior knowledge | Alt-Svc, HTTPS RR or configured knowledge |

Normal requests carry `:method`, `:scheme`, `:authority`, `:path`; CONNECT variants have different rules. Names are lowercase; Connection and Transfer-Encoding are not valid ordinary H2/H3 fields, and `te` is limited to `trailers`. Content-Length, if sent, remains an assertion about content octets, not message framing. Intermediaries must validate it against actual content before safely translating to H1. Preserve authority/path semantics and remove hop-specific fields rather than copying all fields blindly.

`Alt-Svc: h3=":443"; ma=3600` advertises an alternative for the same origin; the alternate endpoint still needs valid origin authentication. Failed QUIC can fall back to TCP depending on client policy and timing. An HTTPS URL alone proves neither H2 nor H3. A browser's protocol column reports its connection to the edge, not the proxy's backend connection.

Optional commands for an already-approved endpoint; not required by the lab:

```sh
curl --version
curl --http2 -I https://example.com/
curl --http3-only -I https://example.com/
```

Feature availability depends on curl build and TLS/QUIC libraries, not version number alone. `--http3-only` requires a sufficiently recent HTTP3-enabled build (introduced in curl 7.88.0); unlike fallback-capable modes, it requires H3. Record negotiated protocol rather than inferring it from a requested flag. Do not disable shared-host UDP or the corporate VPN to test fallback.

## Gotchas

Many streams do not imply many independent congestion windows. Server push is a protocol capability with limited/removed browser support, not a default optimization. Connection coalescing requires identity/origin rules; shared IP alone is insufficient. Real implementations should use maintained protocol libraries, not the educational codec below.

## Labs

### Environment and Complete Files

Python 3.12+, stdlib. This decodes a bounded H2 frame and implements actual QUIC integer encoding rules. No network, HPACK/QPACK implementation or throughput model is included.

### File: test_example.py

```python
import unittest


def h2_frame(kind, flags, stream, payload):
	if not 0 <= stream < 2**31 or len(payload) >= 2**24:
		raise ValueError("frame bounds")
	return (len(payload).to_bytes(3, "big") + bytes((kind, flags))
			+ stream.to_bytes(4, "big") + payload)


def parse_h2(data):
	if len(data) < 9:
		raise ValueError("short header")
	length = int.from_bytes(data[:3], "big")
	if len(data) != 9 + length:
		raise ValueError("length mismatch")
	return data[3], data[4], int.from_bytes(data[5:9], "big") & 0x7fffffff, data[9:]


def quic_integer(value):
	if not 0 <= value < 2**62:
		raise ValueError("integer bounds")
	for size, prefix in ((1, 0), (2, 1), (4, 2), (8, 3)):
		if value < 2 ** (size * 8 - 2):
			return (value | prefix << (size * 8 - 2)).to_bytes(size, "big")


def read_quic_integer(data):
	if not data:
		raise ValueError("missing integer")
	size = 1 << (data[0] >> 6)
	if len(data) < size:
		raise ValueError("truncated integer")
	return int.from_bytes(data[:size], "big") & ((1 << (size * 8 - 2)) - 1), size


class FramingTests(unittest.TestCase):
	def test_settings_and_data(self):
		self.assertEqual(h2_frame(4, 0, 0, b"").hex(), "000000040000000000")
		self.assertEqual(parse_h2(h2_frame(0, 1, 3, b"ok")), (0, 1, 3, b"ok"))
		with self.assertRaises(ValueError):
			parse_h2(h2_frame(0, 1, 3, b"ok")[:-1])

	def test_varint_boundaries(self):
		for value in (0, 63, 64, 16383, 16384, 2**30, 2**62 - 1):
			encoded = quic_integer(value)
			self.assertEqual(read_quic_integer(encoded), (value, len(encoded)))
		self.assertEqual(quic_integer(64).hex(), "4040")
		with self.assertRaises(ValueError):
			read_quic_integer(b"\x40")

	def test_h3_data_frame(self):
		frame = quic_integer(0) + quic_integer(2) + b"ok"
		kind, first = read_quic_integer(frame)
		length, second = read_quic_integer(frame[first:])
		self.assertEqual((kind, length, frame[first + second:]), (0, 2, b"ok"))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`; annotate the empty SETTINGS frame's nine bytes.
2. Compare H2 DATA stream 3 with H3 DATA: locate where the stream ID is supplied in each protocol.
3. Change the expected encoding of 64 to `0040`; observe failure, then restore `4040`.
4. Explain why DATA bytes alone are not a complete valid HTTP exchange; preceding request fields and connection state are absent.

### Hints

The high two bits encode integer width, not integer value. H2's reserved stream-ID bit is ignored on receipt. The H2 codec checks byte shape only, not type-specific semantic legality.

### Solution and Expected Results

Expected: three tests pass. Empty SETTINGS is `000000040000000000`; QUIC 64 is `4040`; H3 DATA is `00026f6b`. The H2 DATA payload is associated with stream 3 in its header, while H3's enclosing QUIC stream supplies that identity. These results validate wire encodings, not a working HTTP/2/3 stack, TLS negotiation, fallback, or performance.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional runner: `python -m pytest -q test_example.py` with pytest installed. No third-party HTTP stack or network is required. Truncated-integer failures are intentional. Delete the lab directory and caches.

- [ ] Decode H2 frames and QUIC integers and explain compression dependencies.
- [ ] Distinguish negotiated protocol, transport behavior and intermediary translation.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Request Smuggling]]
- [[HTTP2 and HTTP3 Security]]

## References

- [HTTP/2, RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- [HTTP/3, RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)
- [QUIC transport, RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- [HPACK, RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
- [QPACK, RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)
