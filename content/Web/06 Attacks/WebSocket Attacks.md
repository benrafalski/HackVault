---
title: "WebSocket Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# WebSocket Attacks

> [!abstract] TL;DR
> WebSocket attacks exploit cross-origin handshake trust, stale connection identity, or unsafe interpretation and authorization of messages after connection establishment.

> [!info] Agent scope
> Cross-site WebSocket hijacking; handshake identity; origin checks; message injection; per-message authorization.

## Learn

```text
Teach WebSocket application security across handshake and connection lifetime.
Assume HTTP upgrade, WebSocket frames, cookies, origins, JSON messages, and async
servers. Explain cross-site WebSocket hijacking prerequisites without a client
attack page. Distinguish Origin validation, session identity, CORS, frame masking,
TLS, subprotocol selection, message schema, and per-resource authorization.
Trace subscriptions, publish actions, expiry/revocation, role changes, backpressure,
message/decompression limits, and output rendering. Review an offline application
handler with synthetic sessions and safe positive/negative tests. State what it
cannot prove about RFC framing or deployed proxy limits. Cite primary standards
and runtime docs; give review questions with answers. No live sockets, injection
payloads, theft, bypasses, scanning, or chains. Do not edit files or invent passes.
```

## Cheatsheet

> [!important] Defensive scope
> This lab tests application-level handshake metadata and message processing in memory. It opens no sockets and supplies no cross-site connection page or frame payloads.

### Handshake Is Only the Beginning

Cross-site WebSocket hijacking requires a browser-originated connection carrying useful ambient credentials and a server that accepts an unintended origin. WebSocket is not protected by ordinary Fetch CORS middleware in the same way as HTTP fetch responses. Validate the browser Origin explicitly and authenticate independently. Nonbrowser clients can supply Origin themselves, so it is not an identity credential.

| Layer | Required control | Limitation |
|---|---|---|
| TLS/upgrade | `wss`, reviewed proxy upgrade routing, supported subprotocol | Encryption does not authorize the peer |
| Browser Origin | Exact approved origin; explicit missing/null policy | Does not authenticate arbitrary clients |
| Session | Valid identity at connection establishment | Long-lived connections can outlive that identity |
| Message | Bounded bytes, strict schema, known operation | A valid JSON message can still be unauthorized |
| Resource | Check actor/action/resource on each operation | Subscription permission can change after subscription |
| Delivery | Revalidate recipients as required; bound queues | A broadcast cache can mix identities |

RFC 6455 masking is a protocol requirement, not confidentiality or proof of a trusted browser. Libraries should handle fragmentation, control frames, masking, and UTF-8 validation; application code should not hand-roll framing. HTTP/2 extended CONNECT uses a different transport path than HTTP/1.1 Upgrade and needs separately reviewed infrastructure support.

### Message and Lifecycle Boundaries

Treat every message as a new untrusted input. Never evaluate message text or use it directly as HTML, SQL, commands, or routing authority. Use a closed operation schema and explicit server-derived identity. A successful handshake does not authorize every room, topic, or object. Store authorization context carefully and re-check revocation, expiry, tenant, and permissions for subsequent work.

Decide what happens on logout, role removal, and session expiry: close connections, stop subscriptions, or reauthenticate through a designed protocol. Checking only at the next client message does not stop unsolicited server pushes to a revoked subscriber; push delivery needs its own revocation policy. Use short revalidation intervals or event-driven disconnects where appropriate.

Bound message size after reassembly and, if enabled, decompression; frame size alone is insufficient. Bound queue depth, per-identity rates, connection counts, and idle lifetime. Compression can trade bandwidth for memory/CPU and additional confidentiality considerations. Backpressure must not silently accumulate unbounded messages.

### Versions and Evidence

The Python 3.12 fixture is a pure application handler, not a WebSocket library. Production library limits and defaults change by version; explicitly configure message size, queue, ping/timeout, and compression. Record connection ID, origin decision, authenticated subject reference, operation/resource, denial category, and close reason without session tokens or full message content. An accepted handshake is not evidence that a forbidden message succeeded.

## Defense

Apply origin and identity checks before accepting a browser connection, then schema and resource authorization per message. Revalidate ongoing subscriptions and stop delivery on revocation. Keep output data-only and enforce bounded work/queues. Do not assume HTTP middleware automatically covers upgrade and message paths.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no WebSocket package/server/network. Review a proposal that checks a session only once and trusts room names thereafter. The secure handler re-reads current session state and checks each room operation. All messages and identities are synthetic; the injected clock avoids waiting.

### File: test_example.py

```python
import json
import unittest


def unique_fields(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise ValueError("duplicate message field")
		result[key] = value
	return result


class Connection:
	def __init__(self, origin, session_id, sessions, rooms, now):
		if origin != "https://chat.example":
			raise PermissionError("origin")
		self.session_id = session_id
		self.sessions = sessions
		self.rooms = rooms
		self.closed = False
		self.subscriptions = set()
		self.queue = []
		self.identity(now)

	def identity(self, now):
		session = self.sessions.get(self.session_id)
		if self.closed or session is None or session["revoked"] or now >= session["expires"]:
			self.closed = True
			self.subscriptions.clear()
			raise PermissionError("session no longer valid")
		return session["user"]

	def message(self, raw, now):
		user = self.identity(now)
		if type(raw) is not str or len(raw.encode("utf-8")) > 512:
			raise ValueError("message size")
		data = json.loads(raw, object_pairs_hook=unique_fields)
		if type(data) is not dict or set(data) != {"op", "room"}:
			raise ValueError("message schema")
		if data["op"] != "subscribe" or type(data["room"]) is not str:
			raise ValueError("operation")
		if self.rooms.get(data["room"]) != user:
			raise PermissionError("room authorization")
		if len(self.queue) >= 2:
			raise ValueError("queue full")
		self.subscriptions.add(data["room"])
		self.queue.append({"event": "subscribed", "room": data["room"]})


class SocketApplicationTests(unittest.TestCase):
	def setUp(self):
		self.sessions = {"session-a": {"user": "ada", "expires": 100, "revoked": False}}
		self.rooms = {"room-a": "ada", "room-b": "grace"}

	def connection(self):
		return Connection("https://chat.example", "session-a", self.sessions, self.rooms, 0)

	def test_origin_and_per_message_authorization(self):
		with self.assertRaises(PermissionError):
			Connection("https://other.example", "session-a", self.sessions, self.rooms, 0)
		connection = self.connection()
		connection.message('{"op":"subscribe","room":"room-a"}', 1)
		with self.assertRaises(PermissionError):
			connection.message('{"op":"subscribe","room":"room-b"}', 2)
		self.assertEqual(connection.subscriptions, {"room-a"})
		self.assertEqual(len(connection.queue), 1)

	def test_revocation_and_expiry(self):
		connection = self.connection()
		connection.message('{"op":"subscribe","room":"room-a"}', 1)
		self.sessions["session-a"]["revoked"] = True
		with self.assertRaises(PermissionError):
			connection.message('{"op":"subscribe","room":"room-a"}', 2)
		self.assertTrue(connection.closed)
		self.assertEqual(connection.subscriptions, set())
		self.sessions["session-a"]["revoked"] = False
		with self.assertRaises(PermissionError):
			self.connection().message('{"op":"subscribe","room":"room-a"}', 100)

	def test_schema_and_bounded_queue(self):
		connection = self.connection()
		with self.assertRaises(ValueError):
			connection.message('{"op":"subscribe","room":"room-a","extra":1}', 1)
		with self.assertRaises(ValueError):
			connection.message("A" * 513, 1)
		for now in [1, 2]:
			connection.message('{"op":"subscribe","room":"room-a"}', now)
		with self.assertRaises(ValueError):
			connection.message('{"op":"subscribe","room":"room-a"}', 3)
		self.assertEqual(len(connection.queue), 2)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: the shared session table is read again for each message. Why must a real push-delivery loop also check revocation even when the client sends nothing?

Solution: Origin gates browser context; live session state supplies identity; room policy precedes subscription/queue changes. Expected: three tests pass, denied rooms add no subscription, revoked/expired sessions close logically, and the queue never exceeds two entries. There is no network close frame or delivery loop; those are explicitly outside this application-layer fixture.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file; no browser cookies or server are needed. Logical close state is not a claim about a socket library's close handshake. Remove the disposable exercise directory afterward. Framing, proxy upgrade routing, compression, rate limiting, and push revocation require integration validation.

- [ ] Local WebSocket Attacks exercise: Review handshake and ongoing message authority.
- [ ] Boundary check: Run secure origin, resource, revocation, schema, and queue tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 6455: WebSocket protocol](https://www.rfc-editor.org/rfc/rfc6455)
- [RFC 8441: WebSockets over HTTP/2](https://www.rfc-editor.org/rfc/rfc8441)
- [WHATWG WebSockets](https://websockets.spec.whatwg.org/)
- [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
