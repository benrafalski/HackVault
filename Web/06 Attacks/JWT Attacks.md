---
title: "JWT Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# JWT Attacks

> [!abstract] TL;DR
> JWT attacks target acceptance rules: cryptographic verification, key selection, algorithm policy, and claims that bind a token to its intended context.

> [!info] Agent scope
> Algorithm confusion; signature verification; key selection; claim checks; token substitution; rotation and revocation gaps.

## Learn

```text
Teach JWT acceptance failures at expert depth. Assume JSON, base64url, MACs,
signatures, issuer/audience, and OAuth/OIDC. Distinguish JWS/JWE, decoding from
verification, algorithm confusion, signature integrity, key identity, and claim
policy. Explain fixed algorithm families, trusted key maps/JWKS, kid lookup,
token purpose/type, NumericDate checks, subject, rotation, revocation, and replay.
Review a maintained-library verifier with offline synthetic signed fixtures and
negative claim/key/algorithm tests, never forging or brute-forcing tokens. Explain
why an accepted token still needs object authorization. Cite RFC 8725, RFC 7519,
RFC 9068, and PyJWT docs; specify version assumptions and questions/answers.
No theft, bypass payloads, key attacks, RCE, scanning, or chains. Teach rather
than edit files; do not invent test results or claim the fixture is a full issuer.
```

## Cheatsheet

> [!important] Defensive scope
> The lab issues and verifies only synthetic local test tokens with an explicitly public fixture key. No raw tokens are printed, forged, collected, or sent anywhere.

### Acceptance Is a Pipeline

A JWT is a claims representation, not proof of identity by itself. JWS provides integrity/authentication under a key; JWE encrypts and authenticates under its profile. Base64url is encoding, not secrecy. Unverified headers may guide a constrained key lookup, but claims must not influence authorization until cryptographic and policy validation finish.

| Check | Trusted input | Limitation |
|---|---|---|
| Algorithm | Verifier configuration, fixed family | Never derive allowed algorithms from the token |
| Key | Issuer-bound local map or configured JWKS | `kid` is a selector, not a filename/URL or trust anchor |
| Signature/MAC | Maintained JOSE implementation | Authentic claims may still target another context |
| Issuer/audience | Expected service configuration | A valid ID token is not automatically an access token |
| Purpose/type | Explicit token profile and mutually exclusive rules | A generic `typ` value alone is not authorization |
| Time | Required exp/iat/nbf with bounded skew | Presence and semantic validity are separate checks |
| Subject/scope | Profile schema plus application policy | A valid subject cannot access every object |
| Revocation | Session/token version or bounded denylist | Expiration alone leaves a replay window |

Algorithm confusion results from mixing incompatible key/algorithm assumptions. Keep symmetric MAC keys and asymmetric verification keys in separate verifier profiles. Reject unsupported critical headers; do not follow token-supplied key locations. TLS-protected JWKS still needs an expected issuer/endpoint and an availability/rotation strategy.

### Rotation, Revocation, and Evidence

Publish new keys before issuing tokens with them; retain old verification keys only for the intended overlap period. Bound JWKS refreshes on unknown key IDs so arbitrary IDs cannot create unbounded outbound work. Emergency key removal can invalidate many users; plan operational impact. Short token lifetimes reduce exposure but increase refresh traffic. Revocation checks add state and consistency costs; use them where required rather than claiming JWTs are automatically logout-aware.

Log verifier profile, issuer alias, failure category, and key ID after bounded parsing; never raw tokens or unnecessary claims. An invalid-signature event is not evidence that a valid token was accepted. A correctly signed token with the wrong audience is still a rejection case.

### Library and Profile Details

The Python 3.12 lab pins PyJWT 2.10.1 and uses HS256 only for an offline fixture. The shared fixture key is not production key management; every real verifier with an HMAC key can also mint tokens. PyJWT `require` checks claim presence; explicit validation and type policy remain necessary. The lab uses an access-purpose profile inspired by RFC 9068 but does not claim full RFC 9068 conformance or implement an authorization server.

## Defense

Configure algorithms, issuer, audience, key source, token purpose, and required claims independently of input. Bound token/header size, reject unknown profile fields where appropriate, and validate before constructing an application principal. Apply object/function authorization afterward. Patch JOSE libraries and regression-test acceptance rules after upgrades or key rotation.

## Labs

### Environment and Complete Files

Python 3.12 and PyJWT 2.10.1; no crypto extra is required for HS256. No network during tests. Review a proposal that trusts decoded claims and a token-selected algorithm. The replacement uses a fixed verifier profile. All claims, IDs, and keys below are synthetic.

### File: requirements.txt

```text
PyJWT==2.10.1
```

### File: test_example.py

```python
import time
import unittest
import jwt


FIXTURE_KEY = b"public-training-only-key-not-for-production-2026"
KEYS = {"training-v1": FIXTURE_KEY}
ISSUER = "https://issuer.example"
AUDIENCE = "training-api"


def mint_fixture(overrides=None, algorithm="HS256", key=FIXTURE_KEY, kid="training-v1"):
	now = int(time.time())
	claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "ada", "iat": now,
			  "nbf": now, "exp": now + 300, "jti": "fixture-1", "token_use": "access"}
	claims.update(overrides or {})
	return jwt.encode(claims, key, algorithm=algorithm, headers={"typ": "at+jwt", "kid": kid})


def verify(token, revoked=frozenset()):
	if type(token) is not str or len(token) > 4096:
		raise ValueError("token size")
	header = jwt.get_unverified_header(token)
	if set(header) != {"alg", "typ", "kid"}:
		raise ValueError("header profile")
	if header["alg"] != "HS256" or header["typ"] != "at+jwt":
		raise ValueError("algorithm or type")
	if type(header["kid"]) is not str or header["kid"] not in KEYS:
		raise ValueError("key selection")
	claims = jwt.decode(token, KEYS[header["kid"]], algorithms=["HS256"],
						issuer=ISSUER, audience=AUDIENCE,
						options={"require": ["iss", "aud", "sub", "iat", "nbf", "exp",
											 "jti", "token_use"]})
	if any(type(claims[name]) is not int for name in ["iat", "nbf", "exp"]):
		raise ValueError("time claim types")
	if claims["exp"] <= claims["iat"] or claims["exp"] - claims["iat"] > 300:
		raise ValueError("lifetime")
	if claims["token_use"] != "access" or type(claims["sub"]) is not str or not claims["sub"]:
		raise ValueError("purpose or subject")
	if type(claims["jti"]) is not str or claims["jti"] in revoked:
		raise ValueError("revocation")
	return claims["sub"]


def authorize_owner(principal, owner):
	if principal != owner:
		raise PermissionError("object owner")


class JwtTests(unittest.TestCase):
	def test_valid_fixture(self):
		self.assertEqual(verify(mint_fixture()), "ada")

	def test_claim_policy(self):
		for change in [{"aud": "other-api"}, {"iss": "https://other.example"},
					   {"exp": int(time.time()) - 60}, {"token_use": "identity"}]:
			with self.subTest(change=change), self.assertRaises((ValueError, jwt.InvalidTokenError)):
				verify(mint_fixture(change))

	def test_algorithm_key_and_signature_policy(self):
		tokens = [mint_fixture(algorithm="HS512"), mint_fixture(kid="unlisted"),
				  mint_fixture(key=b"different-public-fixture-key-for-signature-test")]
		for token in tokens:
			with self.assertRaises((ValueError, jwt.InvalidTokenError)):
				verify(token)

	def test_revocation_and_object_boundary(self):
		token = mint_fixture()
		with self.assertRaises(ValueError):
			verify(token, revoked={"fixture-1"})
		principal = verify(token)
		self.assertEqual(principal, "ada")
		authorize_owner(principal, "ada")
		with self.assertRaises(PermissionError):
			authorize_owner(principal, "grace")


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest -v test_example
```

On POSIX use `python3.12` and `.venv/bin/python`. Setup requires an approved package source; tests are offline. Hint: a valid signature with the wrong purpose must fail. Why is header inspection permitted only for a closed local lookup?

Solution: configuration selects one algorithm/key family, library verification checks integrity and standard claims, and explicit policy enforces lifetime, purpose, and revocation. Expected: four tests pass. The separate owner gate permits the synthetic principal's own object and denies another owner. A service must invoke that gate before reading/mutating data and extend it for tenant, action, and field policies; a valid JWT alone does not grant those permissions.

### Verification, Troubleshooting, and Cleanup

No installation or tests ran during authoring. Use the venv interpreter and do not name a file `jwt.py`. An incorrect system clock can affect time checks; inspect clock configuration rather than disabling expiry validation. Remove the disposable directory and venv afterward. Asymmetric keys, JWKS refresh, JWE, durable revocation, and production token profiles remain outside the executable fixture but within the review guidance above.

- [ ] Local JWT Attacks exercise: Review fixed verifier and token-purpose policy.
- [ ] Boundary check: Run secure signature, algorithm, key, claim, and revocation tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 7519: JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 9068: JWT access token profile](https://www.rfc-editor.org/rfc/rfc9068)
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/2.10.1/api.html)
