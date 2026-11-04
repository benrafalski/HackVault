---
title: "Sessions and Cookies"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[Sessions and Cookies Security]]"
updated: 2026-11-03
---
# Sessions and Cookies

> [!abstract] TL;DR
> Use Secure and HttpOnly, an appropriate SameSite policy, narrow scope, and server-side expiry. Prefer __Host- cookie naming when its requirements fit.

> [!info] Agent scope
> Session lifecycle; cookie attributes; session identifiers; rotation; fixation; logout; CSRF relationship.

## Prerequisites

- HTTP request/response headers, TLS termination, origins versus sites, Python 3.12.
- [[Web Lab Setup]]; the lab uses only local memory, synthetic users, and standard-library tests.

## Learn

```text
Teach me browser cookies and server sessions at expert engineering depth. Assume
HTTP, TLS, origins/sites and basic Python. Trace anonymous state, authentication,
identifier rotation, elevation, idle/absolute timeout, logout and account-wide
revocation. Explain cookie matching, Secure/HttpOnly/SameSite, host-only versus
Domain, __Host- prefixes, expiry, duplicate names, and cross-site identity callbacks.
Contrast opaque server sessions with signed client state: integrity is not secrecy,
authentication is not authorization, and signatures do not provide revocation.
Work through exact HTTP headers and a complete tested session store with injected
time, CSRF binding and concurrent logout behavior. Explain transaction boundaries,
distributed stores, cache lag, key rotation and session-version checks. Separate
browser-enforced properties from backend tests; do not pretend a cookie parser is
a browser. Use RFC/MDN/OWASP primary guidance, identify version-sensitive behavior,
and finish with hard design questions and worked answers. Teach here, without
editing files or marking study progress. Use only synthetic defensive examples.
```

## Cheatsheet

### Wire Flow and Authority

1. The server may allocate an anonymous session for CSRF or a cart. Never adopt an arbitrary supplied identifier as a new authenticated session.
2. Verify login credentials and any required second factor. Atomically create a fresh identifier, carry forward only approved anonymous data, and invalidate the predecessor. Rotate again on privilege elevation.
3. Return a cookie. On later requests, parse the cookie strictly, look up live server state, enforce expiry and account/session version, then authorize the particular action and object.
4. On logout, invalidate authority in the store before clearing the cookie. On password reset or account disable, revoke all affected sessions or increment a checked account epoch.

```http
HTTP/1.1 200 OK
Set-Cookie: __Host-session=<opaque-random-value>; Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store

GET /account HTTP/1.1
Host: app.example.test
Cookie: __Host-session=<opaque-random-value>
```

The cookie contains neither roles nor passwords. `secrets.token_urlsafe(32)` generates 256 random bits before encoding. A server may store a SHA-256 digest of this high-entropy identifier to reduce disclosure from a read-only store leak; this is not password hashing. Never put identifiers in URLs, analytics, exception messages or logs.

| Attribute | Actual effect | Important limit |
|---|---|---|
| `Secure` | Restricts cookie delivery to secure transport, subject to browser localhost handling | TLS must extend across trusted termination boundaries; not encryption at rest |
| `HttpOnly` | Prevents ordinary script reads through `document.cookie` | Scripts can still send same-origin authenticated requests |
| No `Domain` | Host-only delivery | Prefer over sharing credentials with every subdomain |
| `Path=/` | Request-path matching | Not an access-control boundary between applications |
| `SameSite=Strict` | Strong cross-site sending restriction | Can disrupt incoming links and federated flows |
| `SameSite=Lax` | Permits some top-level safe-method cross-site navigation | Not a substitute for CSRF protection; GET must not mutate |
| `SameSite=None; Secure` | Enables cross-site cookie use where browser policy permits | Third-party-cookie restrictions can still block it |
| `Max-Age` / `Expires` | Client persistence; Max-Age takes precedence when both apply | Server expiry remains authoritative; session restore may retain session cookies |
| `__Host-` | Supporting browsers require Secure, Path=/, and no Domain | Backend must still parse and validate; do not rely on every client enforcing prefixes |

Deletion must use the same name and matching Domain/Path scope, with `Max-Age=0`; clearing one cookie does not revoke a copied session. Reject ambiguous duplicate session-cookie names at the framework boundary instead of choosing whichever parser value is convenient.

### Time, State and Deployment

An idle deadline is extended by accepted activity; an absolute deadline is fixed at creation. Use server time, not client time. Enforce both on every authorization path, including WebSocket message/session renewal paths. A background cleanup job frees storage but is not the expiry control. Rotation should not silently extend an absolute login lifetime unless a fresh authentication policy permits it.

| Design | Benefit | Cost or failure mode |
|---|---|---|
| Opaque server session | Immediate centrally enforced revocation; small cookie | Store availability and latency; replica lag can resurrect revoked authority |
| Signed client session | No lookup for integrity | Visible claims, cookie-size limits, stale roles, difficult revocation |
| Encrypted client session | Confidentiality plus integrity with authenticated encryption | Still needs expiry, replay policy and revocation; key compromise affects many sessions |
| Account epoch in session | Efficient account-wide revocation | Every use must compare current epoch, with a stated cache staleness bound |

CSRF tokens bind a state-changing request to the session/browser transaction; they are not the session credential. For cookie-authenticated mutations, check a session-bound unpredictable token and exact trusted Origin where the application can require it. Handle missing Origin explicitly. SameSite uses site semantics, not origin semantics: sibling origins may still be same-site. CORS controls response visibility, not whether all state-changing requests can be sent.

At a reverse proxy, trust forwarded scheme/host only from configured proxies. Generate absolute URLs from configured public origins. Treat authenticated pages as private and usually `no-store`; a correct session check cannot repair a shared-cache leak. Login returns a fresh session only after the entire authentication policy succeeds.

## Gotchas

- Rotating on every request creates parallel-request races; rotate at trust transitions and define whether any predecessor grace period is acceptable.
- Do not bind sessions rigidly to IP addresses: mobile networks and proxies change them. Use anomalies as signals, not proof of identity.
- A local application logout, an identity-provider logout, and refresh-token revocation are distinct operations.

## Labs

### Environment and Complete Files

Python 3.12, standard library only. Put the following complete file in a new disposable directory. No server, network, real credentials or sibling-note files are needed. This is a real in-memory session implementation, not a browser simulator: it tests identifier/state lifecycle and header construction, not browser cookie enforcement, durable persistence or distributed races. Time is injected for deterministic boundary checks; the store is single-threaded.

### File: test_sessions.py

```python
import secrets
import unittest
from dataclasses import dataclass
from http.cookies import SimpleCookie


@dataclass
class Session:
	user: str | None
	role: str
	created: int
	touched: int
	csrf: str


class Store:
	def __init__(self):
		self.rows = {}

	def issue(self, now, user=None, role="anonymous", created=None):
		token = secrets.token_urlsafe(32)
		self.rows[token] = Session(user, role, now if created is None else created,
								   now, secrets.token_urlsafe(32))
		return token

	def require(self, token, now):
		row = self.rows.get(token)
		if row is None:
			raise PermissionError("session")
		if now < row.touched or now - row.touched >= 300 or now - row.created >= 3600:
			self.rows.pop(token, None)
			raise PermissionError("expired")
		row.touched = now
		return row

	def rotate(self, token, now, user, role):
		old = self.require(token, now)
		fresh = self.issue(now, user, role, old.created)
		del self.rows[token]
		return fresh

	def logout(self, token):
		self.rows.pop(token, None)


def cookie(token, clear=False):
	jar = SimpleCookie()
	jar["__Host-session"] = token
	item = jar["__Host-session"]
	item["path"] = "/"
	item["secure"] = True
	item["httponly"] = True
	item["samesite"] = "Lax"
	if clear:
		item["max-age"] = 0
	return jar.output(header="").strip()


class SessionTests(unittest.TestCase):
	def test_login_elevation_logout(self):
		store = Store()
		anonymous = store.issue(0)
		logged_in = store.rotate(anonymous, 10, "alice", "reader")
		self.assertNotEqual(anonymous, logged_in)
		with self.assertRaises(PermissionError):
			store.require(anonymous, 11)
		self.assertEqual(store.require(logged_in, 11).user, "alice")
		elevated = store.rotate(logged_in, 20, "alice", "editor")
		with self.assertRaises(PermissionError):
			store.require(logged_in, 21)
		self.assertEqual(store.require(elevated, 21).role, "editor")
		store.logout(elevated)
		with self.assertRaises(PermissionError):
			store.require(elevated, 22)

	def test_deadlines(self):
		store = Store()
		token = store.issue(0)
		store.require(token, 299)
		with self.assertRaises(PermissionError):
			store.require(token, 599)
		token = store.issue(0)
		for now in range(200, 3600, 200):
			store.require(token, now)
		with self.assertRaises(PermissionError):
			store.require(token, 3600)

	def test_headers(self):
		header = cookie("synthetic")
		parsed = SimpleCookie()
		parsed.load(header)
		item = parsed["__Host-session"]
		self.assertTrue(item["secure"])
		self.assertTrue(item["httponly"])
		self.assertEqual(item["path"], "/")
		self.assertEqual(item["domain"], "")
		self.assertEqual(item["samesite"], "Lax")
		self.assertIn("Max-Age=0", cookie("", clear=True))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

Run `py -3.12 -m unittest -v test_sessions`. Trace the three different identifiers without printing their values. Identify which state survives a rotation and why the CSRF token does not. Explain why the authenticated-user argument to `rotate` must come from verified credentials, never a request body. Check expiry exactly at each deadline.

### Hints

`created` survives rotation; `touched` changes on use. A cookie header is delivery metadata, whereas the dictionary entry is authority. Deleting only the header cannot satisfy the logout test.

### Solution and Expected Results

The supplied implementation is the reference solution. Expected: three tests pass; prelogin and pre-elevation identifiers fail; a live session returns Alice; logout removes authority; idle and absolute boundaries reject at equality. These are expected results, not an execution report. Production storage must make rotation, authorization and logout races explicit using transactions or conditional writes.

### Verification, Troubleshooting, and Cleanup

If imports fail, check Python 3.12 and the filename; do not name it `http.py` or `secrets.py`. A browser acceptance test remains separate: on an HTTPS test deployment inspect Set-Cookie, cross-site navigation, a POST callback, deletion scope, and server-side logout. No such deployment is required or provided here. Delete the disposable directory and `__pycache__`; no persistent session data is written. Author execution: not performed.

- [ ] Local Sessions and Cookies exercise: Implement a synthetic login/logout flow and observe cookie attributes and identifier rotation. Verify the old identifier fails after logout and after privilege elevation.
- [ ] Boundary check: Set a prelogin synthetic identifier and confirm login rotates it. Replay the old session after logout and require rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[CSRF]]
- [[Sessions and Cookies Security]]

## References

- [RFC 6265: cookie storage and matching](https://www.rfc-editor.org/rfc/rfc6265)
- [MDN Set-Cookie: current browser attributes and prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
