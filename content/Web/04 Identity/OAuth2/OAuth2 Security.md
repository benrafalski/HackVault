---
title: "OAuth 2.0 Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[OAuth2]]"
updated: 2026-11-03
---
# OAuth 2.0 Security

> [!abstract] TL;DR
> Redirect mistakes, missing correlation/PKCE, token leakage, and unsafe account linking can bind access to the wrong client or user.

> [!info] Agent scope
> Security of: Actors; authorization code with PKCE; scopes; state; redirect validation; access and refresh tokens; client types. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Registration, browser correlation, AS selection, authorization-code redemption, token custody, refresh families and resource authorization all require independent controls. A client secret does not repair a misbound callback. PKCE does not grant resource ownership. An access token is not a standardized assertion of user login.

## Learn

```text
Teach defensive OAuth 2.0 engineering. Explain redirect, state, PKCE, issuer binding,
client authentication, consent, audience/scope and refresh-token trust boundaries.
Describe failure mechanisms conceptually without credential stealing or bypass
walkthroughs. Show secure request validation order, exact public/confidential client
flows, storage/rotation/revocation lifecycle and synthetic negative regression tests.
Use a real OAuth client parser and real transactional refresh-token storage in a
standalone lab; label missing HTTP/browser and provider layers. Include fixed
redirect/state tests, PKCE known-answer validation, client binding, expiry, refresh
reuse detection and positive controls. Discuss retry/concurrency tradeoffs, sender
constraints, BFF versus SPA custody, incident response and secret-free telemetry.
Use RFC 9700/7636/9207 and library docs. Teach here without editing files, changing
progress or inventing execution results. End with difficult questions and answers.
```

## Cheatsheet

### Verification Matrix

| Stage | Required checks | Failure mechanism if omitted |
|---|---|---|
| Client registration | Exact redirects, permitted grant/response types, client type/auth method | Credentials or responses can be delivered outside intended client registration |
| Authorization request | Trusted AS, fresh state/verifier, S256, narrow scopes, browser binding | Transaction can be associated with the wrong browser or AS |
| Callback | One value per security parameter, exact callback, state/session/deadline, issuer binding, error handling | Cross-transaction results can create incorrect local state |
| Code exchange | Fixed token endpoint, registered client auth, code/client/redirect/PKCE/expiry | A code can be accepted outside its intended exchange context |
| API request | Token validity, resource audience, granted scope, live object policy | An authentic token is overinterpreted as universal authority |
| Refresh | Client/grant binding, expiry, narrowed scope, atomic rotation and reuse response | Long-lived grant remains reusable after replacement or revocation |

At authorization, invalid redirect registration is a local error at the AS, not a redirect to the supplied URI. At redemption, compare with the redirect bound to this code, not merely any registered redirect. `state` must be generated independently and associated with the initiating browser; an arbitrary state returned unchanged is not sufficient. Store the AS/issuer with the transaction and use RFC 9207 or an equivalent supported mix-up defense. Validate correlation even on error callbacks.

### Token Custody and Lifetime

Keep refresh tokens out of browser-accessible storage when a backend design is available. A backend session needs Secure/HttpOnly cookies and CSRF protection. A SPA remains public and must address script compromise, CORS, token lifetimes and refresh-token policy; embedding a secret changes none of those facts. Client secrets and private keys require controlled storage and rotation, separate from user passwords.

For refresh rotation, persist family ID, account/grant, client, scope, absolute expiry, current token digest and used-token history. Atomically mark the old token used and issue/store its successor. If a previously used token is presented, revoke the family according to policy and require fresh authorization. Legitimate concurrent tabs can trigger the same signal: serialize refreshes at the client and define a bounded retry policy rather than silently permitting replay. Retain enough history to recognize reuse until the family cannot be used.

Sender-constrained tokens (DPoP or mTLS) reduce usefulness of a token without its key, but require proof validation, key binding and replay controls. They do not prove consent, audience or object ownership by themselves. Refresh revocation and local logout do not necessarily revoke every existing JWT access token; use introspection/current-state checks or explicitly accept the short residual lifetime.

### Secure Request Shape

```http
POST /token HTTP/1.1
Host: as.example.test
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=lab-client&refresh_token=<current-family-token>
```

This example is for a public client whose provider policy permits refresh grants; confidential clients additionally authenticate using their registered method. A successful response rotates the token according to policy; a rejected expired/reused/wrong-client grant returns `invalid_grant` without revealing which credential exists. No debug page may echo token bodies.

## Detection and Defense

Monitor callback mismatch counts, unexpected AS/redirect combinations, invalid grants, refresh-family reuse and consent changes. Log client ID, configured issuer, reason code and pseudonymous family/request ID, never code, verifier, token or Authorization header. Validate provider changes against a negative test matrix. Do not interpret every invalid grant as an incident: expired tabs, user cancellation and concurrent refresh are normal causes. Do not auto-link accounts by email returned from an arbitrary OAuth API; use a supported identity protocol and explicit authenticated linking.

## Labs

### Environment and Complete Files

Python 3.12, standard-library SQLite, and OAuthlib. The version range targets documented 3.x APIs but has not been installed/tested here. This exercise runs the real OAuthlib callback parser, the actual RFC 7636 S256 function/known-answer vector, and a real refresh-family state transaction. It is not an AS/token endpoint implementation and does not simulate consent or network behavior. All fixtures are local and synthetic.

### File: requirements.txt

```text
oauthlib>=3.2,<4
```

### File: test_oauth_security.py

```python
import base64
import hashlib
import json
import secrets
import sqlite3
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError


CLIENT = "lab-client"
CALLBACK = "https://client.example.test/callback"


def challenge(verifier):
	return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def callback_code(uri, expected_state):
	parsed = urlsplit(uri)
	expected = urlsplit(CALLBACK)
	if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, expected.path) or parsed.fragment:
		raise ValueError("callback target")
	query = parse_qs(parsed.query, keep_blank_values=True)
	if any(len(values) != 1 for values in query.values()):
		raise ValueError("duplicate parameter")
	result = WebApplicationClient(CLIENT).parse_request_uri_response(uri, state=expected_state)
	return result["code"]


class RefreshStore:
	def __init__(self):
		self.db = sqlite3.connect(":memory:")
		self.db.executescript("""
			CREATE TABLE families (id TEXT PRIMARY KEY, client TEXT, expires INTEGER, revoked INTEGER);
			CREATE TABLE tokens (digest TEXT PRIMARY KEY, family TEXT, used INTEGER);
		""")

	@staticmethod
	def digest(token):
		return hashlib.sha256(token.encode("ascii")).hexdigest()

	def start(self, now):
		family, token = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
		with self.db:
			self.db.execute("INSERT INTO families VALUES (?, ?, ?, 0)", (family, CLIENT, now + 600))
			self.db.execute("INSERT INTO tokens VALUES (?, ?, 0)", (self.digest(token), family))
		return token

	def rotate(self, token, client, now):
		replacement = None
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			row = self.db.execute("""SELECT families.id, client, expires, revoked, used
				FROM tokens JOIN families ON tokens.family = families.id WHERE digest = ?""",
				(self.digest(token),)).fetchone()
			if row and row[1] == client and now < row[2] and not row[3]:
				if row[4]:
					self.db.execute("UPDATE families SET revoked = 1 WHERE id = ?", (row[0],))
				else:
					replacement = secrets.token_urlsafe(32)
					self.db.execute("UPDATE tokens SET used = 1 WHERE digest = ?", (self.digest(token),))
					self.db.execute("INSERT INTO tokens VALUES (?, ?, 0)",
									(self.digest(replacement), row[0]))
		if replacement is None:
			raise PermissionError("invalid_grant")
		return replacement


class OAuthSecurityTests(unittest.TestCase):
	def test_callback_and_pkce(self):
		state = secrets.token_urlsafe(32)
		uri = CALLBACK + "?" + urlencode({"code": "synthetic-code", "state": state})
		self.assertEqual(callback_code(uri, state), "synthetic-code")
		with self.assertRaises(MismatchingStateError):
			callback_code(uri, "different-transaction")
		with self.assertRaises(ValueError):
			callback_code(uri + "&code=duplicate", state)
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		self.assertEqual(challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
		self.assertNotEqual(challenge("x" * 43), challenge(verifier))

	def test_refresh_rotation_and_reuse(self):
		store = RefreshStore()
		self.addCleanup(store.db.close)
		original = store.start(100)
		with self.assertRaises(PermissionError):
			store.rotate(original, "other-client", 101)
		current = store.rotate(original, CLIENT, 102)
		with self.assertRaises(PermissionError):
			store.rotate(original, CLIENT, 103)
		with self.assertRaises(PermissionError):
			store.rotate(current, CLIENT, 104)
		fresh = store.start(200)
		self.assertIsInstance(store.rotate(fresh, CLIENT, 201), str)
		expired = store.start(300)
		with self.assertRaises(PermissionError):
			store.rotate(expired, CLIENT, 900)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_oauth_security
```

Baseline is an accepted correlated callback and one valid refresh rotation. Negative fixtures cover mismatched state, duplicate callback parameters, wrong client, used predecessor and expiry. Explain why reuse revocation must commit even though the operation returns an error.

### Hints

The exception is raised after the transaction exits: raising it inside the transaction would roll back the family revocation. A failed wrong-client attempt does not consume a valid token. The PKCE vector proves transformation correctness only; an AS must still compare the supplied verifier against the challenge bound to the code.

### Solution and Fixed Retest

Expected: two tests pass. Correct callback and PKCE vector succeed; state/duplicates fail; original token rotates once; reuse revokes its successor; a new family works; equality with expiry rejects. The reference fix is strict callback parsing plus atomic family state changes, not merely token randomness. Repeat the same tests after storage changes.

### Verification, Troubleshooting, and Cleanup

Not executed here. The callback helper assumes expected state came from a live, browser-bound, one-use transaction; that web-session layer is not supplied. The refresh store omits scopes, account status, inactivity expiry and HTTP admission controls; it implements the tested lifecycle slice, not a deployable provider. Integration still needs issuer-response binding, PKCE redemption, multi-connection race tests and resource audience checks. Delete the disposable directory/venv/caches; SQLite is in memory.

- [ ] Local OAuth2 exercise: Connect a local client to a test authorization server using code plus PKCE. Record authorization, callback, token exchange, and API access with synthetic users.
- [ ] Boundary check: Alter state and use the wrong PKCE verifier in the local flow; both must fail. Verify a token for another API is rejected by the resource server.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[OAuth Attacks]]
- [[OAuth2]]

## References

- [RFC 9700: OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 7636: PKCE and Appendix B vector](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9207: issuer identification](https://www.rfc-editor.org/rfc/rfc9207)
- [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [OAuthlib WebApplicationClient](https://oauthlib.readthedocs.io/en/latest/oauth2/clients/webapplicationclient.html)
