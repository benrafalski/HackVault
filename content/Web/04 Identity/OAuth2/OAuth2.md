---
title: "OAuth 2.0"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[OAuth2 Security]]"
updated: 2026-11-03
---
# OAuth 2.0

> [!abstract] TL;DR
> Use maintained protocol libraries, code+PKCE, exact redirects, bounded scopes, and correlation checks. Use OIDC when authenticated user identity is required.

> [!info] Agent scope
> Actors; authorization code with PKCE; scopes; state; redirect validation; access and refresh tokens; client types.

## Prerequisites

- HTTP redirects/form encoding, TLS, browser sessions, Python 3.12 and [[Web Lab Setup]].
- OAuth delegates API access. Use OIDC for standardized authenticated user identity.

## Learn

```text
Teach OAuth 2.0 at expert protocol and implementation depth. Assume HTTP, TLS and
browser sessions. Trace resource owner, client, authorization server and resource
server through authorization code with S256 PKCE, state, consent, callback, token
exchange and API authorization. Explain exact fields, public/confidential clients,
redirect registration, issuer binding, client authentication, scope versus audience,
opaque/JWT access tokens, refresh rotation, revocation and sender constraints.
Contrast user delegation with client credentials; explain why OAuth alone is not
login, and why implicit/password grants are not modern recommendations. Give a
complete library-backed local protocol lab with positive and synthetic rejection
tests, not an invented dictionary protocol. Label missing browser/consent/deployment
layers. Use RFC 6749/7636/9700 and library docs, no fabricated versions/results,
credential theft or bypass walkthroughs. Finish with worked design questions.
Teach here, without editing notes or study completion.
```

## Cheatsheet

### Actors and Code Flow

The resource owner authorizes a client to access resources at a resource server (RS); the authorization server (AS) authenticates the owner, records consent/policy and issues grants. The client ID identifies a registration, not a secret. A public browser/native client cannot keep a distributed secret confidential. A confidential backend can authenticate at the token endpoint using its registered method; PKCE still protects the code exchange and is not replaced by a client secret.

1. Client creates fresh `state` and a 43-128 character high-entropy verifier, stores them with browser/session binding, expected issuer, redirect URI and deadline.
2. Client sends authorization request with `response_type=code`, client ID, exact redirect, scopes, state and `code_challenge=BASE64URL(SHA256(ASCII(verifier)))`, without padding, and method `S256`.
3. AS checks registration/redirect before redirecting anywhere, authenticates the owner and obtains policy/consent. It binds a short-lived single-use code to client, redirect, owner, granted scopes and PKCE challenge.
4. Client receives callback, validates transaction/browser/state and expected issuer where supported, then consumes the transaction. An OAuth error response also needs correlation; do not exchange an absent code.
5. Client POSTs the code, exact original redirect, verifier and required client authentication to the fixed trusted token endpoint. AS verifies all bindings and consumes the code atomically with token issuance.
6. Client sends the access token to the intended RS. RS verifies current token validity, audience/resource and scope, then object/function authorization. A successful grant is not a generic login assertion.

```http
GET /authorize?response_type=code&client_id=lab-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=notes%3Aread&state=<random-state>&code_challenge=<S256-value>&code_challenge_method=S256 HTTP/1.1
Host: as.example.test

HTTP/1.1 302 Found
Location: https://client.example.test/callback?code=<one-use-code>&state=<same-state>

POST /token HTTP/1.1
Host: as.example.test
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=lab-client&code=<code>&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&code_verifier=<original-verifier>
```

The token response is JSON containing `access_token`, `token_type`, typically `expires_in`, granted `scope` when required, and optionally `refresh_token`; use `Cache-Control: no-store` and `Pragma: no-cache`. A confidential client's authentication is omitted from this public-client example intentionally. Never transmit a browser/native embedded client secret as proof of confidentiality.

### Independent Bindings

| Value | Binds what | Does not establish |
|---|---|---|
| `state` | Callback to initiating browser transaction | Token validity or owner identity by itself |
| PKCE verifier | Code redemption to initiating client instance | Client confidentiality, user authentication or object permission |
| Redirect URI | Delivery target registered for client and bound to code | Safe arbitrary post-login navigation |
| Scope | Granted operation categories | Which API is recipient or ownership of every object |
| Audience/resource | Intended RS | Every operation at that RS |
| Client authentication | Registered confidential client at token endpoint | User authentication |

Use exact registered redirect matching, with protocol-defined native loopback-port exceptions only where applicable. No wildcard hosts or open redirectors. Bind the token exchange to the originally selected AS; do not choose its endpoint from an unverified response. Multi-AS clients need mix-up defenses such as authorization-response issuer identification (RFC 9207) or distinct callback routes with stored issuer binding.

### Tokens and Lifecycle

Opaque access tokens require authoritative lookup/introspection. JWT access tokens require the AS's key/profile plus claims and current-state policy. OAuth does not require JWTs. Bearer tokens authorize their holder; use TLS and header transport, never URLs/logs. DPoP or mTLS sender constraints add proof-of-possession checks but do not replace audience, scope or request authorization.

Refresh tokens go only to the AS, not the RS. Bind them to client and grant, preserve or narrow scope, rotate atomically and detect reuse or use sender-constrained tokens according to current guidance. Reuse handling must account for legitimate concurrent refresh/retry, without silently accepting an unlimited predecessor grace period. Set inactivity and absolute grant lifetimes. Revocation of the refresh grant may not instantly invalidate existing self-contained access tokens; state that residual interval.

Prefer code+PKCE for interactive clients. Client credentials grants represent the client itself, not an end user; use workload identity/registered authentication and narrow service permissions. RFC 9700 rejects the resource-owner-password grant as a modern design, and discourages front-channel access-token issuance. Device authorization is a separate protocol for limited-input devices, not a reason to collect passwords in a client.

## Gotchas

- CORS is not client authentication. A browser can be allowed to call a token endpoint while remaining a public client.
- Persist the granted scope, not blindly the requested scope. Treat scope strings as space-delimited tokens, not substrings.
- A backend-for-frontend can keep tokens out of JavaScript but introduces cookie/CSRF/session responsibilities.

## Labs

### Environment and Complete Files

Python 3.12 and OAuthlib 3.x. APIs were checked in official documentation; the range is an unexecuted compatibility target, not a verified lockfile. This is a real OAuthlib authorization-code/PKCE exchange through its HTTP-message API, without sockets. The AS owner authentication/consent is a pre-established synthetic fixture (`alice`); no login UI, TLS, browser cookie handling or production persistence is provided. Only code grants are enabled; refresh tokens are deliberately not issued.

### File: requirements.txt

```text
oauthlib>=3.2,<4
```

### File: test_oauth.py

```python
import base64
import hashlib
import json
import secrets
import time
import unittest
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
from oauthlib.oauth2 import RequestValidator, WebApplicationClient, WebApplicationServer


CLIENT = "lab-client"
REDIRECT = "https://client.example.test/callback"
AUTHORIZE = "https://as.example.test/authorize"
TOKEN = "https://as.example.test/token"
RESOURCE = "https://api.example.test/notes"


class Validator(RequestValidator):
	def __init__(self):
		self.codes, self.tokens = {}, {}

	def validate_client_id(self, client_id, request, *args, **kwargs):
		if client_id != CLIENT:
			return False
		request.client = SimpleNamespace(client_id=CLIENT)
		return True

	def client_authentication_required(self, request, *args, **kwargs):
		return False

	def authenticate_client_id(self, client_id, request, *args, **kwargs):
		return self.validate_client_id(client_id, request)

	def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
		return client_id == CLIENT and redirect_uri == REDIRECT

	def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
		return REDIRECT

	def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
		return response_type == "code" and request.code_challenge_method == "S256"

	def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
		return grant_type == "authorization_code"

	def is_pkce_required(self, client_id, request):
		return True

	def get_default_scopes(self, client_id, request, *args, **kwargs):
		return ["notes:read"]

	def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
		return set(scopes) <= {"notes:read"}

	def save_authorization_code(self, client_id, code, request, *args, **kwargs):
		self.codes[code["code"]] = dict(client=client_id, redirect=request.redirect_uri,
			user=request.user, scopes=list(request.scopes), expires=time.time() + 60,
			challenge=request.code_challenge, method=request.code_challenge_method)

	def validate_code(self, client_id, code, client, request, *args, **kwargs):
		row = self.codes.get(code)
		if not row or row["client"] != client_id or time.time() >= row["expires"]:
			return False
		request.user, request.scopes = row["user"], row["scopes"]
		request.code_challenge, request.code_challenge_method = row["challenge"], row["method"]
		return True

	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
		return self.codes[code]["redirect"] == redirect_uri

	def get_code_challenge(self, code, request):
		return self.codes[code]["challenge"]

	def get_code_challenge_method(self, code, request):
		return self.codes[code]["method"]

	def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
		self.codes.pop(code, None)

	def save_bearer_token(self, token, request, *args, **kwargs):
		token.pop("refresh_token", None)
		self.tokens[token["access_token"]] = dict(user=request.user,
			scopes=set(request.scopes), expires=time.time() + token["expires_in"])

	def validate_bearer_token(self, token, scopes, request):
		row = self.tokens.get(token)
		if not row or time.time() >= row["expires"] or request.uri != RESOURCE:
			return False
		if not set(scopes or []) <= row["scopes"]:
			return False
		request.user = row["user"]
		return True


class OAuthTests(unittest.TestCase):
	def test_code_pkce_and_resource(self):
		validator = Validator()
		server = WebApplicationServer(validator, token_expires_in=120)
		client = WebApplicationClient(CLIENT)
		verifier, state = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
		uri = client.prepare_request_uri(AUTHORIZE, redirect_uri=REDIRECT,
			scope=["notes:read"], state=state, code_challenge=challenge, code_challenge_method="S256")
		headers, body, status = server.create_authorization_response(
			uri, scopes=["notes:read"], credentials={"user": "alice"})
		self.assertEqual(status, 302)
		callback = client.parse_request_uri_response(headers["Location"], state=state)
		code = callback["code"]
		fields = dict(grant_type="authorization_code", client_id=CLIENT,
					  redirect_uri=REDIRECT, code=code, code_verifier=verifier)
		headers, body, status = server.create_token_response(TOKEN, http_method="POST",
			body=urlencode(fields), headers={"Content-Type": "application/x-www-form-urlencoded"})
		self.assertEqual(status, 200)
		token = json.loads(body)
		self.assertEqual(token["token_type"], "Bearer")
		self.assertNotIn("refresh_token", token)
		valid, request = server.verify_request(RESOURCE,
			headers={"Authorization": "Bearer " + token["access_token"]}, scopes=["notes:read"])
		self.assertTrue(valid)
		self.assertEqual(request.user, "alice")
		valid, request = server.verify_request(RESOURCE,
			headers={"Authorization": "Bearer " + token["access_token"]}, scopes=["notes:write"])
		self.assertFalse(valid)
		headers, body, status = server.create_token_response(TOKEN, http_method="POST", body=urlencode(fields))
		self.assertEqual(status, 400)
		self.assertEqual(json.loads(body)["error"], "invalid_grant")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_oauth
```

Follow the actual URI, form body, response headers/status and JSON in the debugger using synthetic data only. Trace the challenge from authorization request into persisted code metadata and its verification during exchange. Explain why the resource's scope check does not imply ownership of every note.

### Hints

OAuthlib handles message parsing and PKCE, but the validator owns persistence, registration, expiry and scope policy. The fixture accepts one exact resource URL to model a single RS boundary. It is not a general URL-routing or audience strategy.

### Solution and Expected Results

Expected: one end-to-end test passes with authorization 302, token 200, permitted `notes:read`, rejected `notes:write`, and 400 `invalid_grant` on repeated code redemption. Tokens and codes are randomly generated, so their values are not fixed outputs. The supplied validator is the reference lab solution.

### Verification, Troubleshooting, and Cleanup

Not executed here. A missing validator hook indicates a library/API compatibility issue, not permission to return True for every check. Production must implement transactional single-use redemption across workers; this serial in-memory fixture does not establish race safety. No browser consent/session, network TLS, refresh grant or full identity-provider integration is tested. Remove the directory/venv/caches; all grants disappear when the process exits.

- [ ] Local OAuth2 exercise: Connect a local client to a test authorization server using code plus PKCE. Record authorization, callback, token exchange, and API access with synthetic users.
- [ ] Boundary check: Alter state and use the wrong PKCE verifier in the local flow; both must fail. Verify a token for another API is rejected by the resource server.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[OAuth Attacks]]
- [[OAuth2 Security]]

## References

- [RFC 6749: OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9700: OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 9207: authorization response issuer](https://www.rfc-editor.org/rfc/rfc9207)
- [OAuthlib RequestValidator API](https://oauthlib.readthedocs.io/en/latest/oauth2/validator.html)
