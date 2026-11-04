---
title: "OpenID Connect Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[OpenID Connect]]"
updated: 2026-11-03
---
# OpenID Connect Security

> [!abstract] TL;DR
> Issuer mix-up, ID/access-token confusion, nonce/correlation gaps, and email-only account linking can create incorrect login sessions.

> [!info] Agent scope
> Security of: OIDC over OAuth; ID tokens; discovery; nonce; issuer and audience validation; userinfo; session relationships. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

The RP trusts a configured OP to authenticate a subject under a defined assurance policy. Discovery, callback correlation, ID-token keys/claims, UserInfo, account mapping and local session issuance must all preserve that same transaction and issuer. An email address is not a globally authoritative account key.

## Learn

```text
Teach defensive OpenID Connect integration at expert depth. Assume OAuth code+PKCE
and JWT. Explain issuer mix-up, discovery/JWKS trust, audience/azp, nonce/state,
ID/access-token confusion, UserInfo subject consistency, max_age/auth_time and
email-only linking risks as mechanisms, without exploit or bypass recipes.
Provide a secure ordered verifier and a standalone lab with real signed ID tokens,
transaction-bound nonce, wrong issuer/client rejection and explicit recent-session
account linking with database uniqueness. Show positive controls, safe negative
fixtures, key/session lifecycle, logout limits, detection and failure recovery.
Separate OP assertions from local authorization and email verification from account
ownership. Cite Core/Discovery and library docs, qualify versions and untested
integration boundaries, and end with worked questions. Teach here; no file edits
or study-status changes, no invented execution results.
```

## Cheatsheet

### Binding Failures and Fixed Policy

| Boundary | Root cause | Verification/fix |
|---|---|---|
| Issuer selection | Callback or unverified token chooses OP/endpoints | Store selected trusted issuer in transaction; exact discovery/ID-token issuer match |
| Key discovery | Any advertised key/URL becomes trusted | Trusted issuer metadata, controlled JWKS fetch, algorithm/key constraints |
| Token purpose | A signed token is treated as login regardless of context | Dedicated ID-token validator with client audience and transaction nonce |
| Browser transaction | State exists but is not bound to browser/use/deadline | One-use server-side transaction with state, nonce, verifier, issuer and action |
| UserInfo | Profile data silently changes subject | Require UserInfo `sub` equal verified ID-token `sub` |
| Account linking | Email equality implies account ownership | Explicit authenticated linking, recent reauthentication, unique issuer+subject binding |
| Step-up | UI or `amr` text is interpreted as adequate assurance | Enforce documented OP assurance semantics and `auth_time` server-side |

Process callback parameters once with duplicate/size controls; validate transaction and expected issuer; exchange the code only at the recorded token endpoint; verify ID-token signature, required claims, exact issuer, client audience/authorized party, time and nonce; enforce requested authentication assurance; verify UserInfo subject if used; map identity; then rotate/create the RP session. An OAuth authorization success without a valid ID token cannot complete this OIDC login.

Discovery is configuration with security impact. Allowlist issuers/tenants, prevent unbounded arbitrary fetches, verify TLS and exact returned issuer, and keep signing-algorithm policy independent of untrusted input. An OP can legitimately host endpoints on different origins; approve the metadata relationship instead of inventing a universal same-host rule. Cache by issuer with size/time/refresh limits. On outage, do not accept new unknown keys; handle previously trusted keys under a stated cache validity policy.

### Account Linking and Claims

Persist identities with a uniqueness constraint on `(issuer, subject)` referencing an internal immutable account ID. The same email at two OPs can denote different people or different assurance policies. Even `email_verified=true` does not prove control of an existing local account. Do not merge automatically. Require a live authenticated target account, recent authentication, explicit user intent, CSRF/callback binding and fresh verification of the identity being linked. Reject an identity already linked elsewhere; record and notify link/unlink changes.

When linking, the target internal account and action belong in the initiating server-side transaction, not in callback query values. Prevent removing the last viable authenticator without a recovery plan. Pairwise subject/sector changes and issuer migrations require controlled remapping, not a fallback to email matching.

`acr` values express authentication context under an agreement; `amr` reports methods. Neither is a universal boolean for MFA. `auth_time` is when user authentication occurred; token `iat` is issuance time. A freshly refreshed ID token can describe an old authentication event. For sensitive actions, request and check freshness and supported assurance, then independently authorize the action.

### Sessions, Logout and Errors

Create a fresh local session after successful login, preserve only intended prelogin state, and enforce account-disable/role changes under local policy. RP logout clears local authority; OP logout and refresh revocation are separate. A back-channel logout token has a distinct claim/event profile and replay requirements; never route it through a generic ID-token login endpoint. Registered post-logout redirects and state still need validation.

Externally return a generic failed-login/link outcome. Internally classify issuer, signature, audience, nonce, freshness, UserInfo and uniqueness failures. Redact codes, tokens, verifier, nonce, cookies and sensitive identity attributes. Clock drift and stale tabs are routine explanations for some failures; account-link changes warrant durable audit independent of login success metrics.

## Detection and Defense

Test each configured OP independently with valid login, wrong client, wrong issuer, missing/incorrect nonce, stale authentication and existing-identity link cases. Include key rollover and disabled-account tests in deployment validation. Retain only the identity attributes the application needs. API authorization must not rely solely on OP group claims without clear tenant mapping, freshness and entitlement policy.

## Labs

### Environment and Complete Files

Python 3.12, SQLite and PyJWT with cryptography. Version range is an unexecuted compatibility target using documented APIs. This lab creates real signed ID-token fixtures and exercises a local linking transaction. It starts after a trusted code exchange: no OP endpoints, browser or token exchange are simulated. The fixture session is server-owned test state, not user-supplied JSON. A production adapter must derive it from a verified live session.

### File: requirements.txt

```text
PyJWT[crypto]>=2.10,<3
```

### File: test_oidc_security.py

```python
import secrets
import sqlite3
import time
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER = "https://login.example.test"
CLIENT = "link-client"


class Linker:
	def __init__(self, public_key):
		self.key = public_key
		self.pending = {}
		self.db = sqlite3.connect(":memory:")
		self.db.execute("CREATE TABLE identities (issuer TEXT, subject TEXT, account TEXT, PRIMARY KEY (issuer, subject))")

	def begin(self, session, now, confirmed):
		if not confirmed or not session.get("active") or not 0 <= now - session["auth_time"] <= 300:
			raise PermissionError("recent authenticated intent required")
		state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		self.pending[state] = dict(session=session["id"], account=session["account"],
								   deadline=now + 120, nonce=nonce)
		return state, nonce

	def finish(self, session, state, token, now):
		transaction = self.pending.get(state)
		if not transaction or not session.get("active") or transaction["session"] != session["id"]:
			raise PermissionError("session binding")
		if transaction["account"] != session["account"] or now >= transaction["deadline"]:
			raise PermissionError("transaction")
		if not 0 <= now - session["auth_time"] <= 300:
			raise PermissionError("stale local authentication")
		del self.pending[state]
		if not isinstance(token, str) or len(token) > 8192:
			raise PermissionError("size")
		header = jwt.get_unverified_header(token)
		if header != {"alg": "RS256", "typ": "JWT"}:
			raise PermissionError("header profile")
		claims = jwt.decode(token, self.key, algorithms=["RS256"], issuer=ISSUER,
			audience=CLIENT, options={"require": ["iss", "sub", "aud", "iat", "exp", "nonce"]})
		if claims["aud"] != CLIENT or claims.get("azp", CLIENT) != CLIENT:
			raise PermissionError("client profile")
		if claims["nonce"] != transaction["nonce"]:
			raise PermissionError("nonce")
		if not isinstance(claims["sub"], str) or not claims["sub"]:
			raise PermissionError("subject")
		if any(type(claims[field]) is not int for field in ("iat", "exp")):
			raise PermissionError("time type")
		if not 0 <= now - claims["iat"] <= 300 or not claims["iat"] < claims["exp"] <= claims["iat"] + 600:
			raise PermissionError("time policy")
		with self.db:
			self.db.execute("INSERT INTO identities VALUES (?, ?, ?)",
							(claims["iss"], claims["sub"], transaction["account"]))
		return transaction["account"]


class LinkingTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def setUp(self):
		self.now = int(time.time())
		self.linker = Linker(self.private.public_key())
		self.addCleanup(self.linker.db.close)
		self.session = dict(id="server-session-a", account="account-a", active=True, auth_time=self.now - 10)

	def issue(self, nonce, **changes):
		claims = dict(iss=ISSUER, sub="subject-a", aud=CLIENT, iat=self.now - 1,
					  exp=self.now + 120, nonce=nonce, email="same@example.test", email_verified=True)
		claims.update(changes)
		return jwt.encode(claims, self.private, algorithm="RS256")

	def test_explicit_link_and_uniqueness(self):
		with self.assertRaises(PermissionError):
			self.linker.begin(self.session, self.now, confirmed=False)
		state, nonce = self.linker.begin(self.session, self.now, confirmed=True)
		self.assertEqual(self.linker.finish(self.session, state, self.issue(nonce), self.now), "account-a")
		second = dict(self.session, id="server-session-b", account="account-b")
		state, nonce = self.linker.begin(second, self.now, confirmed=True)
		with self.assertRaises(sqlite3.IntegrityError):
			self.linker.finish(second, state, self.issue(nonce), self.now)
		state, nonce = self.linker.begin(second, self.now, confirmed=True)
		self.assertEqual(self.linker.finish(second, state, self.issue(nonce, sub="subject-b"), self.now), "account-b")

	def test_wrong_context(self):
		for changes in ({"iss": "https://second.example.test"}, {"aud": "other-client"},
						{"nonce": "other-transaction"}):
			state, nonce = self.linker.begin(self.session, self.now, confirmed=True)
			token = self.issue(nonce, **changes) if "nonce" not in changes else self.issue(changes["nonce"])
			with self.assertRaises((jwt.InvalidTokenError, PermissionError)):
				self.linker.finish(self.session, state, token, self.now)
		stale = dict(self.session, auth_time=self.now - 301)
		with self.assertRaises(PermissionError):
			self.linker.begin(stale, self.now, confirmed=True)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_oidc_security
```

Observe that two subjects with identical verified email can remain two accounts, while one issuer/subject cannot be linked twice. Verify that link intent and recent local authentication are required before the new OP identity is accepted. The second-issuer fixture is deliberately signed by the lab key to isolate the issuer check; this is not a real second provider integration.

### Hints

Email is not used in the insertion key. The uniqueness constraint is the last line of defense against concurrent linking decisions. Production must convert integrity errors into a generic user-facing conflict without disclosing which other account owns the identity.

### Solution and Fixed Retest

Expected: two tests pass. Unconfirmed/stale linking and three wrong token contexts fail. A valid identity links to account A, duplicate identity linkage fails, and a distinct subject with the same email links to account B. The supplied implementation is the reference fix. Retest after identity-schema or provider-configuration changes.

### Verification, Troubleshooting, and Cleanup

Not executed here. The lab's single-audience profile is intentionally stricter than general Core. It does not cover UserInfo, remote JWKS, OP assurance/reauthentication, web CSRF, account-disable races or logout. Production must make transaction consumption/session checks and identity insertion consistent across workers. Delete directory/venv/caches; SQLite and keys are memory-only.

- [ ] Local OpenID Connect exercise: Use a test OIDC provider and local relying party. Inspect the verified issuer/subject pair, then test wrong audience and nonce mismatch.
- [ ] Boundary check: Present a valid ID token from a second test issuer or client and require rejection. Confirm account linking requires a verified existing session and explicit policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[OAuth Attacks]]
- [[JWT Attacks]]
- [[OpenID Connect]]

## References

- [OpenID Connect Core: ID-token validation and subjects](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [RFC 9700: OAuth security context](https://www.rfc-editor.org/rfc/rfc9700)
- [PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html)
