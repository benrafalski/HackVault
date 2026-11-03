---
title: "JWT"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[JWT Security]]"
updated: 2026-11-03
---
# JWT

> [!abstract] TL;DR
> Decode for inspection; verify before trust. Validate iss, aud, exp/nbf as applicable and distinguish access tokens from ID tokens.

> [!info] Agent scope
> JOSE; JWS versus JWE; claims; signing; verification; key distribution; expiry and revocation; algorithm and audience constraints.

## Prerequisites

- JSON, base64url, public-key signatures, HTTP bearer credentials, UTC time and [[Web Lab Setup]].
- Python 3.12 for the lab. JWT is a format, not a login protocol or authorization policy.

## Learn

```text
Teach JWT and JOSE at expert engineering depth. Assume JSON, HTTP, public-key
cryptography and UTC. Explain JWS compact signing input, JWE five-part encryption,
JWK/JWKS fields, nested tokens, NumericDate, issuer/subject/audience and token typing.
Trace verification in order: bounded parse, trusted issuer/key policy, fixed algorithm,
signature, mandatory claims, times, purpose, revocation and resource authorization.
Build real asymmetric signing/verifying code with a published public JWK and tests
for wrong audience, expiry, untrusted key, missing claims and wrong token purpose.
Explain key rotation, JWKS caching/outages, refresh versus access tokens, revocation,
clock skew, duplicate claims and differences between RFC 7519 and an application
profile. Use primary RFC/library documentation; do not invent versions or results.
Use only synthetic defensive fixtures, no forgery or bypass walkthroughs. Finish
with difficult worked questions. Teach here without editing files or study status.
```

## Cheatsheet

### JOSE Representations

| Object | Compact representation | What it establishes |
|---|---|---|
| JWS | `base64url(protected).base64url(payload).base64url(signature)` | Integrity/authenticity under an accepted key and algorithm; no secrecy |
| JWE | `protected.encrypted_key.iv.ciphertext.tag` | Authenticated encryption for a recipient under `alg` key management and `enc` content encryption |
| JWT | JSON claims carried by JWS or JWE | Claim vocabulary; application profiles define acceptance |
| Nested JWT | Commonly sign then encrypt, with `cty: JWT` | Recipient must verify both layers and inner claims; successful decryption alone is not sender identity |

JWS signs the ASCII concatenation of the first two encoded segments with a literal dot. Do not decode/re-serialize JSON before verifying: whitespace/order changes alter bytes. Base64url is not encryption. A JWE encrypted with a recipient's public key can be produced by anyone who knows that key; require authenticated sender semantics where needed. PyJWT in this lab implements JWS/JWT, not JWE.

### Headers, Claims and Policy

| Field | Meaning | Required validation |
|---|---|---|
| `alg` | JOSE algorithm identifier | Match deployment allowlist and key type; never let input choose trust policy |
| `kid` | Key-selection hint | Lookup only inside the configured issuer's accepted key set; not a URL or path |
| `typ` | Explicit token type | Separate access, ID and other token validators; RFC 9068 uses `at+jwt` |
| `crit` | Extensions that must be understood | Reject unsupported critical processing; do not silently ignore |
| `iss` | Issuer identifier | Exact configured value, including slash/case semantics |
| `sub` | Subject identifier in issuer namespace | Use `(iss, sub)`; not mutable email as global identity |
| `aud` | Intended recipients, string or array | This verifier must be an intended recipient; enforce narrower application profile if required |
| `exp` / `nbf` | Exclusive expiry / inclusive not-before | NumericDate seconds, not milliseconds; bounded measured clock leeway |
| `iat` | Issuance time | Validate type/plausibility and maximum age/lifetime if required |
| `jti` | Unique token identifier | Does nothing by itself; use a store for revocation or one-use replay policy |

RFC 7519 does not universally require every registered claim. A profile must require what it depends on; validating `exp` only when present is not equivalent to requiring expiration. The lab defines a narrow local access-token profile, not full RFC 9068 conformance. Booleans are not acceptable numeric timestamps in that profile even though Python treats them as integers.

### Trust and Key Distribution

For RSA public JWKs, `kty=RSA`, `n` and `e` encode the modulus/exponent as unsigned base64url integers. `kid`, `use=sig`, `key_ops=[verify]` and `alg=RS256` constrain selection but do not make an arbitrary JWK trustworthy. EC keys use `crv/x/y`; OKP keys use `crv/x`. Never publish private members such as RSA `d` or HMAC `k`.

Configure the issuer and JWKS URL through trusted configuration/discovery. An unverified header can only select among that established trust, not introduce a new source. Bound document size, keys, redirects, network timeouts and refresh frequency. On unknown `kid`, at most one controlled refresh may help rotation; repeated misses must not create unbounded outbound traffic. Reject duplicates/ambiguity. A certificate in `x5c` does not automatically make its chain trusted or prove it matches `n/e`.

Publish a new verification key before signing with it. Keep the old public key for the maximum accepted old-token lifetime plus permitted skew, then retire it. A compromised key requires emergency removal and cache invalidation; ordinary overlap is inappropriate. HMAC places signing authority in every verifier, whereas asymmetric keys permit verify-only resource servers.

### Time and Revocation

Short-lived access tokens bound stale authority, not immediate revocation. Options are a `jti` denylist until `exp`, live account/session epoch checks, introspection or short lifetimes with a stated staleness budget. Refresh tokens represent longer-lived grants and need separate rotation/revocation. Bearer access tokens are normally reusable until expiry: do not mark every `jti` consumed unless the protocol intentionally specifies one-use semantics. A resource server must still evaluate scopes, ownership and current account policy.

```http
GET /reports/42 HTTP/1.1
Host: api.example.test
Authorization: Bearer <access-token>
```

Use TLS; avoid URLs and raw token logs. Authentication failure is generally 401 with appropriate Bearer challenge; a valid identity lacking permission is generally 403. Token payloads should contain the minimum information required, because JWS claims are readable to holders and often intermediaries that terminate TLS.

## Gotchas

- Successful JSON decoding is not signature verification. Successful signature verification is not claim validation. Neither grants arbitrary resource access.
- Generic parsers may accept duplicate JSON members differently. Use a library/profile with understood behavior and reject ambiguity at security boundaries.
- Clock leeway enlarges the actual acceptance interval; it is not a remedy for large clock drift.

## Labs

### Environment and Complete Files

Python 3.12. The PyJWT 2.x API was checked against official documentation; this range is an intended compatibility constraint, not a tested lockfile or claim that every release is supported. The crypto extra installs cryptography for RSA. Resolve, validate and record exact installed versions before reuse. No HTTP/network service is needed: the local issuer and resource verifier exchange real compact JWS bytes and a real public JWK in process.

### File: requirements.txt

```text
PyJWT[crypto]>=2.10,<3
```

### File: test_jwt.py

```python
import json
import time
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


ISSUER = "https://issuer.example.test"
AUDIENCE = "urn:lab:reports"


def verify(token, public_jwk):
	if not isinstance(token, str) or len(token) > 8192:
		raise ValueError("token size")
	header = jwt.get_unverified_header(token)
	if header != {"alg": "RS256", "typ": "at+jwt", "kid": "lab-1"}:
		raise ValueError("header profile")
	key = jwt.PyJWK.from_dict(public_jwk).key
	claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
						audience=AUDIENCE, leeway=0,
						options={"require": ["iss", "sub", "aud", "exp", "iat", "nbf"]})
	for field in ("exp", "iat", "nbf"):
		if type(claims[field]) is not int:
			raise ValueError("timestamp type")
	if not claims["iat"] <= claims["nbf"] < claims["exp"] <= claims["iat"] + 300:
		raise ValueError("lifetime")
	if not isinstance(claims["sub"], str) or not claims["sub"]:
		raise ValueError("subject")
	return claims


class JwtTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private.public_key()))
		cls.jwk.update(kid="lab-1", use="sig", alg="RS256", key_ops=["verify"])

	def issue(self, **changes):
		now = int(time.time())
		claims = dict(iss=ISSUER, sub="alice", aud=AUDIENCE,
					  iat=now - 1, nbf=now - 1, exp=now + 120)
		claims.update(changes)
		return jwt.encode(claims, self.private, algorithm="RS256",
						  headers={"kid": "lab-1", "typ": "at+jwt"})

	def test_round_trip(self):
		self.assertNotIn("d", self.jwk)
		self.assertEqual(verify(self.issue(), self.jwk)["sub"], "alice")

	def test_claim_rejections(self):
		now = int(time.time())
		fixtures = ({"aud": "urn:lab:other"}, {"iss": "https://other.example.test"},
					{"iat": now - 100, "nbf": now - 100, "exp": now - 1},
					{"nbf": now + 60}, {"exp": now + 3600})
		for changes in fixtures:
			with self.subTest(changes=changes):
				with self.assertRaises((jwt.InvalidTokenError, ValueError)):
					verify(self.issue(**changes), self.jwk)

	def test_wrong_trust_key(self):
		other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		wrong_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(other.public_key()))
		with self.assertRaises(jwt.InvalidSignatureError):
			verify(self.issue(), wrong_jwk)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_jwt
.venv\Scripts\python -m pip freeze
```

Trace the public JWK conversion and identify what the verifier never receives: the private key. Inspect the header/profile rules and distinguish the claim-policy failure cases from an invalid signature. Use the fixed lab issuer, not any live token or production key.

### Hints

Every negative claim fixture is deliberately issued by the trusted local issuer; its signature is valid but its use here is not. A wrong trusted-key configuration is tested without modifying token bytes. Strict header equality is an intentionally narrow lab profile, not a universal JWT requirement.

### Solution and Expected Results

Expected: three tests pass, five invalid claim profiles reject, and a wrong public key causes signature verification failure. The round-trip is permitted. The supplied validator is the reference solution; it has no network JWKS cache, revocation store or object authorization, so it is not a complete API authentication middleware.

### Verification, Troubleshooting, and Cleanup

No execution performed. Ensure the package is `PyJWT`, not the unrelated `jwt` package. Future-time failures may indicate a bad system clock; do not disable time validation to mask them. Generated private keys live only in process memory; delete the disposable directory/venv/caches. The legacy study checklist below is preserved; the supplied exercise uses safe negative fixtures rather than a claim-editing walkthrough.

- [ ] Local JWT exercise: Issue short-lived tokens from a local test issuer and verify them in a separate API. Test wrong audience, expired time, changed signature, and unsupported algorithm.
- [ ] Boundary check: Present a correctly signed token for a different synthetic audience and require rejection. Modify one claim without resigning and confirm verification fails.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[JWT Attacks]]
- [[JWT Security]]

## References

- [RFC 7519: JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7515: JWS](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7516: JWE](https://www.rfc-editor.org/rfc/rfc7516)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9068: JWT access-token profile](https://www.rfc-editor.org/rfc/rfc9068)
- [PyJWT usage](https://pyjwt.readthedocs.io/en/stable/usage.html)
