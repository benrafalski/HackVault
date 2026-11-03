---
title: "JWT Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[JWT]]"
updated: 2026-11-03
---
# JWT Security

> [!abstract] TL;DR
> Signature bypass, algorithm/key confusion, and missing claim checks allow a token valid somewhere else or for another purpose to be accepted here.

> [!info] Agent scope
> Security of: JOSE; JWS versus JWE; claims; signing; verification; key distribution; expiry and revocation; algorithm and audience constraints. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

The JOSE parser, algorithm/key configuration, issuer registry, JWKS transport/cache, time policy, token-purpose mapping and resource authorizer are independent trust boundaries. Token possession is a bearer credential; even a correctly signed token may belong to another application, tenant, time interval or purpose.

## Learn

```text
Teach defensive JWT/JOSE verification at expert depth. Explain how algorithm/key
ambiguity, wrong issuer/audience, omitted required claims, token substitution,
stale revocation and unsafe key discovery cause incorrect trust, conceptually only.
Give a fixed validation pipeline and real cryptographic regression tests using a
local synthetic issuer: permitted access, wrong purpose/audience, missing expiry,
expired token, unsupported header policy, revoked ID and wrong resource owner.
Cover JWS versus JWE guarantees, nested token verification, JWKS rotation/outages,
critical headers, duplicate claims, maximum lifetime, clock skew and key compromise.
Explain why authentication differs from authorization and jti is not automatic
replay prevention. Use RFC 8725 and library docs; no theft, forgery or bypass recipe.
Include complete files/dependencies/commands, diagnostics without raw tokens,
worked answers and unverified limits. Teach here; do not edit files or study status.
```

## Cheatsheet

### Fixed Validation Pipeline

1. Select the expected token profile from the endpoint, not from claims. Bound token/header size and accepted serialization; reject malformed input and ambiguous parsing.
2. Resolve a key only from the configured issuer trust set. Treat `kid` as an opaque bounded selector. Reject unknown or duplicate IDs; never resolve arbitrary header URLs/files. Constrain JWKS refreshes, redirects and network destinations.
3. Enforce algorithm and key type/use. Do not mix HMAC and asymmetric algorithms in one generic verifier. Reject unsupported critical headers; encrypted tokens need authenticated decryption and the profile's sender-authentication checks.
4. Verify cryptography before trusting claims. Require exact issuer, intended audience, mandatory claim presence and types, valid time interval and maximum lifetime. Apply only bounded clock leeway.
5. Validate purpose/type and any profile-specific claims; an ID token is not an API access token. Check current account/session status and revocation policy.
6. Authorize the requested action and resource using trusted identity and live policy. An `admin` string is not a substitute for tenant/object checks.

| Mechanism | Failure condition | Regression/control |
|---|---|---|
| Algorithm/key mismatch | Verifier accepts input-selected trust semantics | One configured algorithm family and compatible trusted key |
| Token substitution | Same issuer signs different kinds of tokens | Distinct audience and explicit type/purpose checks |
| Missing expiry | Library validates time only when present | Require `exp` and enforce maximum lifetime |
| JWKS key confusion | Keys selected outside issuer namespace | Cache key by issuer and key ID; reject duplicates; controlled refresh |
| Stale privilege/revocation | Self-contained claims outlive policy changes | Epoch/denylist/introspection or explicit short staleness budget |
| Overbroad audience | Valid token for another service accepted | Exact API audience/profile; no wildcard matching |

### Keys, Sessions and Revocation

Public verification keys are not secrets, but their authenticity matters. Pin trusted discovery configuration, TLS verification and issuer matching. Key rollover needs an overlap for already-issued tokens; compromised keys must be removed immediately with cache invalidation. Do not preserve acceptance of an unknown key merely because discovery is unavailable. A cached known key may be used only within an explicitly bounded stale policy, with compromise overrides.

HMAC verification keys also grant signing capability, so distributing one to every microservice expands the signing trust domain. Prefer asymmetric verification for separated services. JWE hides claims from nonrecipients but does not erase bearer replay or authorize resource access. Never put passwords or unnecessary personal data in either representation.

`jti` revocation entries should be namespaced by issuer and retained until the token cannot be accepted including skew. Access tokens normally allow repeated API requests; one-use replay semantics belong to specific artifacts, not every JWT. Refresh-family revocation and local browser logout may leave issued access tokens valid until expiry unless the resource server checks current state.

### Response and Evidence

Return a generic invalid-token response for invalid authentication; use authorization-denied for a valid identity missing permission. Internally classify signature, issuer, audience, time, type and revoked-session failures. Never log the full Authorization header or decoded sensitive payload. An unknown `kid` burst may indicate stale caches or malformed traffic; confirm issuer deployment timing before assuming malicious behavior.

## Detection and Defense

Maintain a per-profile validation test matrix and run it whenever the library, issuer configuration or key cache changes. Test known-key availability during JWKS outage and emergency retirement separately. Compare clocks and monitor skew. Track aggregate failure reasons and pseudonymous request IDs without token content. A validated subject still needs a tenant/ownership lookup; evaluate permissions after account disable or role changes according to a documented consistency budget.

## Labs

### Environment and Complete Files

Python 3.12 and PyJWT with cryptography. Official APIs were checked; the version range below is an unexecuted compatibility target, not a resolved lockfile. No other note or server is required. The fixture issuer creates real RSA signatures for deliberately different policy cases. No token modification or bypass implementation is supplied.

### File: requirements.txt

```text
PyJWT[crypto]>=2.10,<3
```

### File: test_jwt_security.py

```python
import secrets
import time
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER = "https://issuer.example.test"
AUDIENCE = "urn:lab:documents"


class ResourceServer:
	def __init__(self, public_key):
		self.public_key = public_key
		self.revoked = set()

	def read(self, token, owner):
		if not isinstance(token, str) or len(token) > 8192:
			raise PermissionError("token size")
		try:
			header = jwt.get_unverified_header(token)
			if header != {"alg": "RS256", "typ": "at+jwt", "kid": "lab"}:
				raise PermissionError("header policy")
			claims = jwt.decode(token, self.public_key, algorithms=["RS256"],
				issuer=ISSUER, audience=AUDIENCE,
				options={"require": ["iss", "aud", "sub", "exp", "iat", "jti"]})
		except jwt.InvalidTokenError as error:
			raise PermissionError("invalid credential") from error
		if type(claims["iat"]) is not int or type(claims["exp"]) is not int:
			raise PermissionError("time type")
		if not 0 < claims["exp"] - claims["iat"] <= 300:
			raise PermissionError("lifetime")
		if not isinstance(claims["jti"], str) or not claims["jti"]:
			raise PermissionError("token id")
		if (ISSUER, claims["jti"]) in self.revoked:
			raise PermissionError("revoked")
		if claims.get("scope") != "documents:read" or claims["sub"] != owner:
			raise PermissionError("authorization")
		return "synthetic document"


class PolicyTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	def setUp(self):
		self.api = ResourceServer(self.private.public_key())

	def issue(self, changes=None, omit=(), typ="at+jwt"):
		now = int(time.time())
		claims = dict(iss=ISSUER, aud=AUDIENCE, sub="alice", iat=now - 1,
					  exp=now + 120, jti=secrets.token_urlsafe(16), scope="documents:read")
		claims.update(changes or {})
		for field in omit:
			claims.pop(field)
		token = jwt.encode(claims, self.private, algorithm="RS256",
						   headers={"kid": "lab", "typ": typ})
		return token, claims

	def test_policy_matrix(self):
		valid, unused = self.issue()
		self.assertEqual(self.api.read(valid, "alice"), "synthetic document")
		fixtures = [self.issue({"aud": "urn:lab:other"}), self.issue(omit=("exp",)),
					self.issue(typ="JWT"), self.issue({"scope": "documents:write"}),
					self.issue({"exp": int(time.time()) - 1})]
		for token, unused in fixtures:
			with self.assertRaises(PermissionError):
				self.api.read(token, "alice")
		with self.assertRaises(PermissionError):
			self.api.read(valid, "bob")
		self.assertEqual(self.api.read(valid, "alice"), "synthetic document")

	def test_revocation(self):
		token, claims = self.issue()
		self.api.read(token, "alice")
		self.api.revoked.add((ISSUER, claims["jti"]))
		with self.assertRaises(PermissionError):
			self.api.read(token, "alice")
		fresh, unused = self.issue()
		self.assertEqual(self.api.read(fresh, "alice"), "synthetic document")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_jwt_security
```

Record which layer rejects each trusted-issuer fixture. Show that valid repeat reads are permitted, a valid token cannot read Bob's object, and revocation affects only the intended token. This is a local resource-authorization function, not an HTTP stack or a complete JWT profile implementation.

### Hints

The missing-claim fixture is signed correctly. It fails because the endpoint requires expiry. `scope` is deliberately a single exact value in this narrow profile; real OAuth scope lists require tokenization and subset checks, not substring matching.

### Solution and Fixed Retest

Expected: two tests pass. Five invalid profiles and the wrong owner reject; an allowed read still works; a revoked identifier fails and a fresh one works. The supplied pipeline is the reference fix. A signature-only baseline would accept inappropriate claim profiles; no insecure server is included. Retest the same fixtures after configuration changes.

### Verification, Troubleshooting, and Cleanup

Not executed here. The revocation set is ephemeral and single-process; production needs shared bounded storage and expiry cleanup. There is no remote JWKS, multi-tenant registry, duplicate-JSON rejection test, HTTP bearer parser or live account epoch in this exercise. Those integration gates remain explicit. Remove the disposable directory/venv/caches; all generated keys disappear with the process. Preserve the historical study checkboxes below without treating their wording as an instruction to perform token manipulation.

- [ ] Local JWT exercise: Issue short-lived tokens from a local test issuer and verify them in a separate API. Test wrong audience, expired time, changed signature, and unsupported algorithm.
- [ ] Boundary check: Present a correctly signed token for a different synthetic audience and require rejection. Modify one claim without resigning and confirm verification fails.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[JWT Attacks]]
- [[JWT]]

## References

- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9068: access-token validation](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 7517: JWK](https://www.rfc-editor.org/rfc/rfc7517)
- [PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html)
