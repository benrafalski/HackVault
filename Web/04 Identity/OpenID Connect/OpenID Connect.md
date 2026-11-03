---
title: "OpenID Connect"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[OpenID Connect Security]]"
updated: 2026-11-03
---
# OpenID Connect

> [!abstract] TL;DR
> Identify accounts by stable issuer plus subject, not mutable email alone. Keep discovery tied to trusted issuers and use a maintained OIDC client.

> [!info] Agent scope
> OIDC over OAuth; ID tokens; discovery; nonce; issuer and audience validation; userinfo; session relationships.

## Prerequisites

- Authorization code with PKCE, JWT verification, browser sessions and [[Web Lab Setup]].
- Python 3.12 for the self-contained relying-party validation lab.

## Learn

```text
Teach OpenID Connect at expert relying-party engineering depth. Assume OAuth
code+PKCE, JWT and browser sessions. Trace discovery, authorization with openid,
state/nonce/verifier storage, code exchange, ID-token validation, UserInfo and local
session creation. Explain issuer equality, JWKS trust, aud/azp, exp/iat, nonce,
auth_time/max_age, acr/amr and at_hash/c_hash where the flow requires them.
Distinguish ID/access/refresh tokens and OP/RP sessions. Use stable issuer+subject
identity, pairwise subjects and explicit account linking rather than mutable email.
Give real signed-token verification code, synthetic rejection tests, exact files,
dependencies and commands; label any unimplemented browser/provider layer. Cover
key rollover, discovery cache/outage, logout, refresh and reauthentication tradeoffs.
Use OIDC Core/Discovery/logout specs and library docs, no invented results or bypass
walkthroughs. Finish with difficult worked questions. Teach here, not file edits.
```

## Cheatsheet

### OAuth Plus an Identity Assertion

OIDC adds the `openid` scope, an ID token, identity claims and discovery rules to OAuth. The OpenID Provider (OP) authenticates the user; the Relying Party (RP) validates the authentication result for its registered client. The access token is for a resource such as UserInfo; the ID token is for the RP and must not be used as an API bearer credential. A refresh token is an AS grant capability, not a local browser session.

1. Start with a trusted issuer configured or selected through an allowlisted tenant policy. Obtain its discovery document over verified HTTPS. The returned `issuer` must exactly equal the expected issuer; metadata is not trusted simply because it parses as JSON.
2. Record a browser-bound, expiring, one-use transaction: issuer, client ID, exact redirect, state, nonce, PKCE verifier, requested authentication policy and intended post-login action.
3. Navigate to the configured authorization endpoint with `response_type=code`, `scope=openid ...`, state, nonce and S256 challenge. The OP authenticates and authorizes according to policy.
4. Validate callback correlation and issuer binding, then redeem the code at the transaction's fixed token endpoint with client authentication where required and the stored verifier.
5. Validate the returned ID token using the expected issuer's trusted keys and registered algorithm policy. Check all contextual claims below before creating a local session.
6. Optionally call UserInfo using the access token; require its `sub` to exactly equal the verified ID-token subject. Create/rotate the RP session using the stable `(iss, sub)` mapping and current account policy.

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: login.example.test

GET /authorize?response_type=code&client_id=rp-lab&scope=openid%20profile&redirect_uri=https%3A%2F%2Frp.example.test%2Fcallback&state=<state>&nonce=<nonce>&code_challenge=<S256>&code_challenge_method=S256 HTTP/1.1
Host: login.example.test

GET /userinfo HTTP/1.1
Host: login.example.test
Authorization: Bearer <access-token>
```

For issuers with path components, follow the OIDC Discovery construction rules, not an assumed URL convention from a different metadata standard. Discovery fields include `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, supported response types/subject types/ID-token signing algorithms and optional UserInfo/logout endpoints. Restrict fetched destinations and redirects, bound response sizes/timeouts, and cache under the issuer. Do not blindly enable every advertised algorithm.

### ID-Token Verification Order

| Check | Requirement and meaning |
|---|---|
| Signature/key/algorithm | Trusted OP key and registered accepted algorithm; `kid` only selects within this OP's keys |
| `iss` | Exact expected OP identifier, not normalized by ad hoc slash removal |
| `aud` | Contains this client ID; not the API audience |
| `azp` | For multiple audiences, check authorized party per Core; this RP's strict policy requires it to equal client ID. If present with one audience, validate it too |
| `exp`, `iat` | Required by Core; expiration and issue-time plausibility under bounded skew/age policy |
| `sub` | Nonempty stable subject, namespaced by issuer; not email/display name |
| `nonce` | If sent, require exact returned value bound to this transaction; consume transaction once |
| `auth_time` | Required when requested via `max_age` or as an essential claim; enforce requested recency |
| `acr`, `amr` | Authentication context/method information with issuer-specific semantics; do not infer assurance from an arbitrary string |
| `at_hash`, `c_hash` | Hash binding depends on response flow and algorithm; enforce where required by that flow/profile |

In code flow an `at_hash` may be present in the token-endpoint ID token; for the lab policy it is required and checked. With RS256, it is base64url without padding of the leftmost half of SHA-256 over the ASCII access token. This computation is not universal for every signing algorithm. Hybrid/front-channel responses have additional requirements; prefer a maintained OIDC client rather than adapting code-flow checks to another flow.

`state`, `nonce` and PKCE protect different associations: browser callback transaction, ID-token authentication transaction and code redemption. Do not omit a binding because another random string is present. The lab enforces nonce on every transaction as a local policy, even though its protocol requirement depends on flow/request.

### Identity and Session Lifecycle

Public versus pairwise subjects determine whether an OP exposes the same subject across RPs/sectors. Preserve the issuer namespace and sector configuration during migrations; a subject change needs a verified migration strategy. Email may change or be recycled, and `email_verified=true` is a claim under that OP's policy, not universal account-linking authority.

The OP login session, RP cookie session, access-token lifetime and refresh grant have separate clocks. ID-token expiration constrains acceptance of the assertion; it does not automatically end an already established RP session unless the RP chooses that policy. Refreshing tokens is not necessarily fresh user authentication: `auth_time` can remain old. Request recent authentication for sensitive actions and verify the resulting claims.

Logout can clear the RP session, revoke a refresh grant, initiate OP logout and/or receive front/back-channel notifications. These are separate operations. Validate registered post-logout redirects and logout-message profiles; a back-channel logout token is not an ordinary ID token. Key rotation follows the OP's trusted JWKS with bounded cache/overlap; unknown keys and discovery failures never disable signature checking.

## Gotchas

- ID-token `aud` is the client ID, while an access token's intended resource is different.
- `prompt=login` and `max_age` express different requests; verify returned authentication recency rather than trusting UI behavior.
- A browser silently failing to send a SameSite cookie at a callback is a correlation/deployment problem, not a reason to accept missing state.

## Labs

### Environment and Complete Files

Python 3.12 and PyJWT's crypto extra. The documented 2.x API is used; the dependency range is a compatibility target not an executed lockfile. This lab verifies real RS256 ID tokens and an actual `at_hash`, plus UserInfo and transaction bindings. It is the RP validation slice of code flow, not a running OP, browser redirect flow, discovery fetcher or OAuth token endpoint. All keys and data are generated locally.

### File: requirements.txt

```text
PyJWT[crypto]>=2.10,<3
```

### File: test_oidc.py

```python
import base64
import hashlib
import hmac
import secrets
import time
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER = "https://login.example.test"
CLIENT = "rp-lab"


def access_hash(access_token):
	digest = hashlib.sha256(access_token.encode("ascii")).digest()
	return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")


class RelyingParty:
	def __init__(self, public_key):
		self.public_key = public_key
		self.pending = {}

	def begin(self, browser):
		state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		self.pending[state] = dict(browser=browser, nonce=nonce, deadline=time.time() + 300)
		return state, nonce

	def finish(self, browser, state, id_token, access_token, userinfo):
		transaction = self.pending.get(state)
		if not transaction or transaction["browser"] != browser or time.time() >= transaction["deadline"]:
			raise PermissionError("transaction")
		del self.pending[state]
		header = jwt.get_unverified_header(id_token)
		if header.get("alg") != "RS256" or header.get("crit"):
			raise PermissionError("algorithm profile")
		claims = jwt.decode(id_token, self.public_key, algorithms=["RS256"],
			issuer=ISSUER, audience=CLIENT,
			options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "at_hash"]})
		audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
		if len(audience) > 1 and claims.get("azp") != CLIENT:
			raise PermissionError("authorized party")
		if "azp" in claims and claims["azp"] != CLIENT:
			raise PermissionError("authorized party")
		if not isinstance(claims["nonce"], str) or not hmac.compare_digest(
				claims["nonce"].encode(), transaction["nonce"].encode()):
			raise PermissionError("nonce")
		now = int(time.time())
		if any(type(claims[field]) is not int for field in ("iat", "exp", "auth_time")):
			raise PermissionError("time type")
		if not 0 <= now - claims["auth_time"] <= 300 or not 0 <= now - claims["iat"] <= 300:
			raise PermissionError("authentication age")
		if not claims["iat"] < claims["exp"] <= claims["iat"] + 600:
			raise PermissionError("lifetime")
		if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(
				claims["at_hash"].encode(), access_hash(access_token).encode()):
			raise PermissionError("access-token binding")
		if not isinstance(claims["sub"], str) or not claims["sub"] or userinfo.get("sub") != claims["sub"]:
			raise PermissionError("subject binding")
		return claims["iss"], claims["sub"]


class OidcTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def fixture(self, changes=None):
		rp = RelyingParty(self.private.public_key())
		state, nonce = rp.begin("browser-a")
		access = secrets.token_urlsafe(32)
		now = int(time.time())
		claims = dict(iss=ISSUER, sub="subject-123", aud=CLIENT, iat=now - 1,
					  exp=now + 120, auth_time=now - 10, nonce=nonce, at_hash=access_hash(access))
		claims.update(changes or {})
		token = jwt.encode(claims, self.private, algorithm="RS256")
		return rp, state, token, access

	def test_identity_and_one_use(self):
		rp, state, token, access = self.fixture()
		self.assertEqual(rp.finish("browser-a", state, token, access, {"sub": "subject-123"}),
						 (ISSUER, "subject-123"))
		with self.assertRaises(PermissionError):
			rp.finish("browser-a", state, token, access, {"sub": "subject-123"})

	def test_claim_and_userinfo_binding(self):
		for changes in ({"aud": "other-client"}, {"nonce": "other-transaction"},
						{"aud": [CLIENT, "other"], "azp": "other"},
						{"auth_time": int(time.time()) - 1000}):
			rp, state, token, access = self.fixture(changes)
			with self.assertRaises((jwt.InvalidTokenError, PermissionError)):
				rp.finish("browser-a", state, token, access, {"sub": "subject-123"})
		rp, state, token, access = self.fixture()
		with self.assertRaises(PermissionError):
			rp.finish("browser-a", state, token, access, {"sub": "different-subject"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_oidc
```

Trace an RP's immutable expected issuer/client against the returned claims. Identify where the nonce is consumed and why UserInfo cannot replace the verified subject. Explain the stricter local lifetime, authentication-age and `at_hash` policies rather than mislabeling them universal OIDC requirements.

### Hints

All claim fixtures are signed by the local issuer. The wrong audience still fails. A failed completion consumes a matched transaction in this fail-closed lab policy; restart login rather than retrying an ambiguous transaction.

### Solution and Expected Results

Expected: two tests pass. Successful identity is `(https://login.example.test, subject-123)`. Repeated completion, four invalid claim contexts and mismatched UserInfo reject. The supplied validator is the reference solution for this narrow profile. In production, transaction consumption and session creation need atomic shared storage, bounded input parsing and a maintained OIDC client's complete protocol handling.

### Verification, Troubleshooting, and Cleanup

Not executed here. Correct clock errors rather than disabling expiry. Do not use the single in-memory key as a JWKS rotation implementation. No browser, OP discovery, TLS, code exchange or logout integration is exercised. Delete the directory/venv/caches; all credentials and transactions are ephemeral.

- [ ] Local OpenID Connect exercise: Use a test OIDC provider and local relying party. Inspect the verified issuer/subject pair, then test wrong audience and nonce mismatch.
- [ ] Boundary check: Present a valid ID token from a second test issuer or client and require rejection. Confirm account linking requires a verified existing session and explicit policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[OAuth Attacks]]
- [[JWT Attacks]]
- [[OpenID Connect Security]]

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [PyJWT OIDC hash example and API](https://pyjwt.readthedocs.io/en/stable/usage.html)
