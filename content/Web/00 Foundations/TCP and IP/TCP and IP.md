---
title: "TCP/IP"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[TCP and IP Security]]"
updated: 2026-11-03
---
# TCP/IP

> [!abstract] TL;DR
> IP forwards packets; TCP supplies an ordered byte stream, not messages. Diagnose routing, transport, TLS, and application behavior separately. A successful connect is not proof of application health or authorization.

## Prerequisites

- Binary/hexadecimal notation, bytes versus characters, and a terminal.
- The complete lab uses Python 3.12, its standard library, and loopback only. No administrator rights, VM, external endpoint, or third-party package is required.

## Learn

```text
Teach me TCP/IP as an experienced programmer needing packet-level diagnostics.
Cover IPv4/IPv6 addressing, CIDR, longest-prefix routing, next hops, ARP/neighbor
discovery, MTU/PMTUD, TCP handshake/state, sequence spaces, ACKs, retransmission,
flow versus congestion control, half-close, ports, and UDP. Derive exact sequence
examples including SYN/FIN consumption. Connect socket APIs to packets and OS
state. Explain partial reads/writes, framing, buffering, Nagle/delayed ACK,
keepalive, TIME_WAIT, NAT, proxies, and capture-offload artifacts.
Use complete bounded loopback programs and synthetic captures, expected results,
tests, and diagnosis trees. Compare refusal, timeout, reset, EOF, TLS failure,
and application rejection. Distinguish standards from OS defaults. Cite RFC
9293, RFC 8200, and socket documentation. End with difficult questions and
worked answers. Teach here; do not edit files or study status. Do not scan or
capture other systems.
```

## Cheatsheet

### Addressing and Forwarding

| Decision | Mechanism | Diagnostic consequence |
|---|---|---|
| Is the destination local? | Interface addresses and routing table | An address on another interface is not necessarily on-link |
| Which route wins? | Longest matching prefix; metric/policy breaks further ties | A `/24` beats a `/16` even if the latter has a lower metric |
| Which Ethernet destination? | Neighbor resolution for the next hop | For an off-link destination, the router's MAC is used |
| Can this packet fit? | Path MTU and transport packetization | IPv6 routers do not fragment; blocking required ICMP messages can break PMTUD |
| Which socket receives? | Transport and local/remote endpoint tuple | TCP port 53 and UDP port 53 are different endpoints |

`192.0.2.130/26` belongs to `192.0.2.128/26`; the mask is `255.255.255.192`. That documentation subnet contains 64 addresses. For conventional IPv4 multi-access `/26` use, the network and broadcast addresses are not host assignments; `/31` point-to-point links follow different rules. IPv6 has no broadcast; link-local destinations may require an interface/zone identifier.

RFC 1918 IPv4 ranges are specifically `10/8`, `172.16/12`, and `192.168/16`. Do not equate every library's `is_private` property with that exact list: special-purpose classifications and library versions matter. Private addressing is neither encryption nor authentication.

### TCP Lifecycle and Accounting

```text
client SYN seq=1000             -> server
client                         <- SYN,ACK seq=7000 ack=1001
client ACK seq=1001 ack=7001    -> server
client data seq=1001 len=5     -> server
client                         <- ACK ack=1006
client FIN seq=1006            -> server
client                         <- ACK ack=1007
```

SYN and FIN each consume one sequence number. A pure ACK consumes none. ACK 1006 cumulatively acknowledges bytes before 1006, not packet number 1006. Sequence arithmetic wraps modulo 2^32; ordinary integer comparisons fail near wraparound. SACK reports additional received ranges without replacing the cumulative ACK.

| State/observation | Meaning | Do not infer |
|---|---|---|
| LISTEN | Passive endpoint accepting connections | Application workers are healthy |
| SYN-SENT | Active open awaiting a valid response | A firewall definitely caused the wait |
| ESTABLISHED | Both sequence spaces established | Authentication or application success |
| CLOSE-WAIT | Peer sent FIN; local sending side has not closed | A need to reduce TIME_WAIT settings |
| TIME-WAIT | Final close bookkeeping, usually at the active closer | A leaked live application socket by itself |
| RST | Abort/refusal under applicable state rules | A complete application response |
| `recv()` returns empty bytes | Orderly EOF after queued bytes | A zero-length application frame |

`shutdown(SHUT_WR)` sends EOF in one direction while preserving reads. `close()` releases the application's socket reference; wire behavior also depends on queued data, errors, and linger configuration. A process crash is not a clean application protocol.

### Flow, Congestion, and Framing

- **Flow control:** the receiver advertises receive-window capacity. Zero window can mean its application is not draining data.
- **Congestion control:** the sender limits outstanding data using its congestion algorithm. Congestion window and advertised receive window are distinct.
- **Retransmission:** loss recovery uses ACK evidence and timers. One capture cannot necessarily identify which device dropped the original packet.
- **Backpressure:** bounded application queues and write deadlines prevent unbounded memory growth. A per-read timeout is not an end-to-end operation deadline.
- **Framing:** use length prefixes, escaped delimiters, fixed-size records, or a standard protocol. One `send()` does not correspond to one `recv()`.
- **Writes:** `send()` can write fewer bytes than supplied. Python `sendall()` loops until completion or error; an error does not reveal how much the peer application consumed.
- **Latency:** Nagle and delayed ACK can interact with tiny writes. Measure before using TCP_NODELAY; it cannot fix a missing application delimiter.
- **Keepalive:** TCP probes detect some stale connections; they do not prove application responsiveness or replace deadlines.

UDP preserves datagram boundaries but supplies no built-in acknowledgment, retransmission, ordering, or peer authentication. An undersized receive buffer can truncate a datagram; its discarded suffix does not arrive on the next read. A connected UDP socket sets a default peer/filtering behavior, not a TCP-style handshake. QUIC adds transport behavior over UDP; raw UDP does not inherit those guarantees.

### Diagnosis and Capture

Read-only commands for a disposable lab, not a reason to enumerate unrelated networks:

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,RouteMetric
Get-NetIPConfiguration
```

Linux equivalents are `ss -lntp`, `ip route get 192.0.2.1`, and `ip address`. The route query shows a local forwarding decision without contacting the documentation address.

| Failure | Discriminating evidence | Next boundary |
|---|---|---|
| Name lookup fails | Compare name with a known local address | Resolver/search suffix, not handshake |
| Immediate refusal | No listener or explicit rejection | Bind address, port, address family |
| Connect timeout | No usable handshake response before deadline | Route, filtering, peer, return path; evidence needed |
| TLS failure after connect | Alert/certificate error after transport establishment | Trust, hostname, protocol, client certificate |
| Request hangs | Last successful protocol step and deadline | Framing, queues, upstream dependencies |
| Reset after connect | Reset timing relative to bytes/close | Process failure, proxy policy, protocol mismatch |

Optional capture: in a disposable lab with Wireshark/Npcap already installed, select the loopback interface, run the exercise, and filter `tcp.port == <printed-port>`, replacing the placeholder with the reported number. Inspect SYN/SYN-ACK/ACK, Follow TCP Stream, the client's FIN, response bytes, and close. Stop immediately afterward. Capture permissions and driver installation are separate prerequisites; do not elevate or alter corporate interfaces. Checksum offload and packet coalescing can make host captures differ from on-wire packets. The standard-library lab is complete without capture tooling.

## Gotchas

An ephemeral source port is not a user identity. NAT rewrites tuples; a terminating proxy creates another connection and sequence space. IPv4 loopback binding does not create an IPv6 listener. IPv6 wildcard dual-stack behavior depends on OS/socket configuration. Retries after ambiguous failures can duplicate application operations; use an application idempotency design where necessary.

## Labs

### Environment and Objectives

Use a new empty directory and Python 3.12. There are no external dependencies. The file below contains the implementation and tests.

1. Predict which route wins for `192.0.2.130`.
2. Predict how many framed messages the synthetic stream contains and whether two-byte reads can reconstruct them.
3. Explain why the server can reply after the client half-closes.
4. Distinguish an empty framed message from transport EOF and a truncated frame.

### File: test_tcp.py

```python
import ipaddress
import socket
import struct
import unittest


class Decoder:
	def __init__(self, maximum=64):
		self.maximum = maximum
		self.buffer = bytearray()

	def feed(self, chunk):
		self.buffer.extend(chunk)
		messages = []
		while len(self.buffer) >= 4:
			length = struct.unpack("!I", self.buffer[:4])[0]
			if length > self.maximum:
				raise ValueError("frame exceeds configured maximum")
			if len(self.buffer) < 4 + length:
				break
			messages.append(bytes(self.buffer[4:4 + length]))
			del self.buffer[:4 + length]
		return messages

	def finish(self):
		if self.buffer:
			raise EOFError("truncated frame")


def encode(message):
	return struct.pack("!I", len(message)) + message


def select_route(address, routes):
	destination = ipaddress.ip_address(address)
	matching = [ipaddress.ip_network(route) for route in routes
				if destination in ipaddress.ip_network(route)]
	return str(max(matching, key=lambda route: route.prefixlen))


class TransportTests(unittest.TestCase):
	def test_longest_prefix(self):
		routes = ["0.0.0.0/0", "192.0.2.0/24", "192.0.2.128/26"]
		self.assertEqual(select_route("192.0.2.130", routes), "192.0.2.128/26")

	def test_fragmentation_and_coalescing(self):
		wire = encode(b"alpha") + encode(b"") + encode(b"beta")
		decoder = Decoder()
		messages = []
		for offset in range(0, len(wire), 2):
			messages.extend(decoder.feed(wire[offset:offset + 2]))
		decoder.finish()
		self.assertEqual(messages, [b"alpha", b"", b"beta"])
		self.assertEqual(Decoder().feed(wire), messages)

	def test_invalid_length_and_truncation(self):
		with self.assertRaises(ValueError):
			Decoder().feed(struct.pack("!I", 65))
		decoder = Decoder()
		decoder.feed(encode(b"alpha")[:-1])
		with self.assertRaises(EOFError):
			decoder.finish()

	def test_loopback_half_close(self):
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
			listener.settimeout(3)
			listener.bind(("127.0.0.1", 0))
			listener.listen(1)
			address = listener.getsockname()
			print(f"loopback port: {address[1]}")
			with socket.create_connection(address, timeout=3) as client:
				connection, peer = listener.accept()
				with connection:
					connection.settimeout(3)
					client.sendall(encode(b"alpha") + encode(b"beta"))
					client.shutdown(socket.SHUT_WR)
					decoder = Decoder()
					messages = []
					while True:
						chunk = connection.recv(2)
						if not chunk:
							break
						messages.extend(decoder.feed(chunk))
					decoder.finish()
					self.assertEqual(messages, [b"alpha", b"beta"])
					self.assertEqual(peer[0], "127.0.0.1")
					connection.sendall(b"K")
					self.assertEqual(client.recv(1), b"K")


if __name__ == "__main__":
	unittest.main(verbosity=2)
```

### Run and Hints

```powershell
py -3.12 --version
py -3.12 test_tcp.py
```

On Linux use `python3.12 test_tcp.py`. No service stays running. The selected port changes each run.

Hints: count length-prefix bytes separately from payload bytes; a FIN ends only one direction; the route calculation chooses prefix length, not array order. The framing tests force application read sizes, not actual packet sizes.

### Solution and Expected Results

Four tests should pass. The route is `192.0.2.128/26`; the synthetic stream contains `alpha`, an empty message, and `beta`. The live TCP exchange contains two messages and returns `K` after the client's sending direction has closed. EOF with buffered incomplete data is an error. A header advertising 65 bytes is rejected before that body is accepted.

The decoder is an instructional component, not a production server: callers must bound read sizes, enforce an overall deadline, close after protocol errors, control connection counts, and design authenticated application messages. The route helper intentionally omits metrics, policy routing, source selection, and multipath.

### Verification, Troubleshooting, and Cleanup

- A bind/connect permission error can indicate endpoint-security policy; do not disable it. Run the pure tests independently with `py -3.12 -m unittest test_tcp.TransportTests.test_fragmentation_and_coalescing test_tcp.TransportTests.test_longest_prefix`.
- A timeout is a failed check, not an expected success. Keep the traceback and Python version.
- Context managers close all sockets. Delete only the newly created exercise directory when finished. No route, firewall, or system configuration changes.
- [ ] Record the selected route, decoded messages, and half-close result.
- [ ] Explain which additional evidence a packet capture would supply.
- [ ] Record observed versions and checks; do not infer production readiness from four tests.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[TCP and IP Security]]
- [[DNS]]
- [[TLS and PKI]]
- [[HTTP]]

## References

- [RFC 9293: TCP](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 8200: IPv6](https://www.rfc-editor.org/rfc/rfc8200)
- [RFC 768: UDP](https://www.rfc-editor.org/rfc/rfc768)
- [Python socket documentation](https://docs.python.org/3.12/library/socket.html)
- [Python ipaddress documentation](https://docs.python.org/3.12/library/ipaddress.html)
