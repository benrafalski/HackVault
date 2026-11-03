---
title: "Sessions and Cookies Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[Sessions and Cookies]]"
updated: 2026-11-03
---
# Sessions and Cookies Security

> [!abstract] TL;DR
> Session fixation, stolen tokens, weak invalidation, and missing CSRF protection let a valid session be used outside its intended workflow.

> [!info] Agent scope
> Security of: Session lifecycle; cookie attributes; session identifiers; rotation; fixation; logout; CSRF relationship. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

The browser, TLS terminator, cookie parser, session store, CSRF middleware, authorization service and caches each enforce a different boundary. A valid identifier authenticates session possession, not permission to change another user's object. Account recovery and privilege changes must revoke or rotate the same authority that ordinary requests consume.

## Learn

```text
Teach me defensive session and cookie security. Assume HTTP, browser origins and
basic transactions. Trace fixation risk conceptually, cookie scope, login/elevation
rotation, timeout, account epochs, logout races, CSRF and same-site sibling risks.
Distinguish a valid signature/session from current authorization. Explain exact
verification order and fail-closed behavior across a distributed session store.
Give secure code, cookie headers and synthetic rejection tests for wrong origin,
missing CSRF proof, stale session, wrong owner and expiration, with positive controls.
Cover duplicate cookies, trusted proxies, cache controls, session restore, OIDC POST
callbacks and separate local/IdP logout. Use primary sources; do not provide theft,
forgery, bypass or exploit walkthroughs. Include detection without logging secrets,
operational tradeoffs, full independent lab files and worked answers. Teach in this
conversation, not by editing notes or marking completion. Do not invent test results.
```

## Cheatsheet

### Root Causes and Verification Order

| Failure mechanism | Preconditions and consequence | Concrete control |
|---|---|---|
| Identity transition reuses anonymous authority | A pre-authentication identifier remains authoritative after login | Allocate a fresh random identifier; atomically invalidate predecessor |
| Logout only removes a browser cookie | Server accepts the old identifier until its TTL | Revoke server state first; delete correctly scoped cookie second |
| Ambient cookie authenticates a mutation | Browser attaches credential without proof of request intent | Session-bound CSRF token, exact Origin policy, safe GET semantics |
| Signed cookie contains stale role | Integrity check succeeds after role removal | Check live account epoch/permissions or accept a documented short staleness bound |
| Revocation read from lagging replica | Old authority remains visible | Route security decisions to consistent storage; fail closed on uncertainty |
| Parser chooses one of duplicate cookie names | Intermediaries/framework disagree | Reject ambiguity and remove broad Domain-scoped legacy cookies |

For a mutation: enforce transport and request limits; parse one session credential; retrieve live state; check absolute/idle deadline and account status; validate CSRF and Origin; load the resource and apply object/function authorization; commit the mutation under a concurrency policy consistent with revocation. Do not update idle time for rejected authentication attempts. Whether a CSRF-rejected but authenticated request counts as activity is a documented policy choice.

```http
POST /profile HTTP/1.1
Host: app.example.test
Origin: https://app.example.test
Cookie: __Host-session=<current-session>
X-CSRF-Token: <session-bound-value>
Content-Type: application/json

{"display_name":"Synthetic Alice"}
```

The fixed response is permitted only for an authenticated current session and an authorized profile. Missing CSRF proof is a 403-class rejection; missing/expired authentication normally yields 401 or an explicit login redirect appropriate to the UI. Do not convert an API error into a cached HTML login page. Check Origin by parsed exact scheme/host/port or a canonical exact allowlist, not substring matching. For clients without Origin, require a separately defined authenticated non-browser path; do not silently disable the check.

### Cookie and Lifecycle Policy

Use `__Host-session=...; Secure; HttpOnly; Path=/; SameSite=Lax` for a typical first-party application. Lax is not sufficient for cross-site POST federation callbacks: use a narrowly scoped, short-lived correlation mechanism designed by the federation library, not a global SameSite relaxation. Strict may break expected inbound navigation. None requires Secure and remains subject to browser third-party-cookie restrictions.

CSRF proof must be bound to the session and compared safely. A synchronizer token stored in server state avoids trusting an unrelated cookie value. Rotate it when the session changes. HttpOnly cannot stop authenticated same-origin requests initiated by compromised script; XSS prevention is still necessary. Path cannot isolate mutually untrusted applications on one origin.

Logout is idempotent. High-risk account actions require recent authentication and revoke competing sessions according to policy. For signed sessions, rotate signing keys with a bounded overlap, but use an epoch/revocation store if individual invalidation is required. Emergency removal of a compromised key must override cache TTLs. Never accept an unknown key as a reason to skip verification.

## Detection and Defense

Log event type, pseudonymous account ID, request correlation ID, revocation reason and aggregate rejection counts. Do not log Cookie, Set-Cookie, CSRF tokens or full request bodies from authentication endpoints. A one-way keyed audit identifier may correlate session events without storing the credential. Mobile IP changes and parallel tabs are common benign anomalies; neither proves compromise. Test store outage behavior and cache isolation as well as happy-path login. Metrics should distinguish expired state, CSRF rejection and authorization denial internally without revealing account existence externally.

## Labs

### Environment and Complete Files

Python 3.12 with standard-library SQLite and unittest. This complete local authorization transaction uses real SQLite locking and conditional session state, with no HTTP server. Synthetic inputs represent already-parsed requests; browser behavior, TLS and multi-node replication are explicitly outside this test. Store a session digest rather than a bearer value. The mutation and logout serialize on the same connection/transaction boundary; a production concurrent implementation needs separate connections and a tested isolation policy.

### File: test_session_security.py

```python
import hashlib
import hmac
import secrets
import sqlite3
import unittest


class Service:
	def __init__(self):
		self.db = sqlite3.connect(":memory:")
		self.db.executescript("""
			CREATE TABLE sessions (digest TEXT PRIMARY KEY, user TEXT,
								   csrf TEXT, expires INTEGER);
			CREATE TABLE profiles (user TEXT PRIMARY KEY, label TEXT);
			INSERT INTO profiles VALUES ('alice', 'Alice'), ('bob', 'Bob');
		""")

	@staticmethod
	def digest(token):
		return hashlib.sha256(token.encode("ascii")).hexdigest()

	def login(self, now):
		token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		with self.db:
			self.db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
							(self.digest(token), "alice", csrf, now + 600))
		return token, csrf

	def update(self, token, csrf, origin, owner, label, now):
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			row = self.db.execute(
				"SELECT user, csrf, expires FROM sessions WHERE digest = ?",
				(self.digest(token),)).fetchone()
			if row is None or now >= row[2]:
				raise PermissionError("authentication")
			if origin != "https://app.example.test":
				raise PermissionError("origin")
			if not isinstance(csrf, str) or not hmac.compare_digest(
					csrf.encode("utf-8"), row[1].encode("utf-8")):
				raise PermissionError("csrf")
			if owner != row[0]:
				raise PermissionError("authorization")
			self.db.execute("UPDATE profiles SET label = ? WHERE user = ?",
							(label, owner))

	def logout(self, token):
		with self.db:
			self.db.execute("DELETE FROM sessions WHERE digest = ?",
							(self.digest(token),))


class SecurityTests(unittest.TestCase):
	def setUp(self):
		self.service = Service()
		self.token, self.csrf = self.service.login(100)
		self.addCleanup(self.service.db.close)

	def request(self, **changes):
		values = dict(token=self.token, csrf=self.csrf,
					  origin="https://app.example.test", owner="alice",
					  label="Updated", now=101)
		values.update(changes)
		return self.service.update(**values)

	def test_positive_and_negative_controls(self):
		self.request()
		for changes in ({"csrf": ""}, {"origin": "https://other.example.test"},
						{"owner": "bob"}, {"now": 700}, {"token": "unknown"}):
			with self.subTest(changes=changes):
				with self.assertRaises(PermissionError):
					self.request(**changes)
		self.assertEqual(self.service.db.execute(
			"SELECT label FROM profiles WHERE user = 'bob'").fetchone()[0], "Bob")
		self.request(label="Still allowed")

	def test_revocation_is_authoritative(self):
		self.service.logout(self.token)
		self.service.logout(self.token)
		with self.assertRaises(PermissionError):
			self.request()
		fresh, proof = self.service.login(102)
		self.request(token=fresh, csrf=proof, now=103)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

Run `py -3.12 -m unittest -v test_session_security`. Baseline: a valid Alice request updates Alice. Negative fixtures vary one policy input at a time; they are not crafted bypass messages. Verify Bob is unchanged and that a valid request still succeeds after rejected requests. Trace how exceptions roll back the transaction.

### Hints

Authentication precedes ownership checking. `BEGIN IMMEDIATE` establishes a write transaction before the read/decision/write sequence. Revocation and the mutation must use a consistent authority store; clearing a cookie is not part of this database decision.

### Solution and Fixed Retest

The supplied secure implementation is the fix/reference. Expected: two tests pass, five invalid input cases reject, Bob remains unchanged, the old session fails after logout and a newly established session works. A baseline implementation that only checked session existence would fail the negative cases; that failure mechanism is described without shipping an insecure endpoint. Rerun this identical suite after storage or middleware changes.

### Verification, Troubleshooting, and Cleanup

No tests were run by the author. All state is in memory; delete the file and `__pycache__` when finished. Do not reuse the hardcoded subject selection as a real login handler: the lab begins after authentication. In production, add idle/absolute expiry, account epoch, login rotation, strict input schemas and concurrent multi-connection tests. A SQLite transaction test does not certify Redis or distributed cache semantics. If transaction errors appear, ensure the supplied methods are not wrapped in an additional transaction.

- [ ] Local Sessions and Cookies exercise: Implement a synthetic login/logout flow and observe cookie attributes and identifier rotation. Verify the old identifier fails after logout and after privilege elevation.
- [ ] Boundary check: Set a prelogin synthetic identifier and confirm login rotates it. Replay the old session after logout and require rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[CSRF]]
- [[Sessions and Cookies]]

## References

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html)
