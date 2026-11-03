---
title: "OAuth Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# OAuth Attacks

> [!abstract] TL;DR
> OAuth attacks exploit mismatched client, redirect, user-session, issuer, or token binding rather than a single universal token format weakness.

> [!info] Agent scope
> Redirect validation; state and PKCE mistakes; code and token handling; consent; account linking; issuer mix-up conditions.

## Learn

```text
Teach OAuth failure modes as lost bindings between browser session, client,
authorization server, redirect URI, code, verifier, resource, and user intent.
Assume OAuth authorization code flow, TLS, sessions, and OIDC basics. Explain
exact redirect matching, state, PKCE S256, one-time codes, issuer mix-up conditions,
token audience/purpose, consent, refresh tokens, and account linking. Distinguish
client checks from authorization-server checks and OAuth authorization from OIDC
authentication. Review offline callback correlation and PKCE regressions plus
explicit linking approval. Explain what these tests do not prove about tokens,
redirect transport, discovery, or a provider. Cite RFC 9700, RFC 7636, RFC 9207,
and OIDC Core; include difficult questions with answers. No interception, token
theft, bypasses, live providers, scanning, or chains. Do not edit files or invent
test results.
```

## Cheatsheet

> [!important] Defensive scope
> Only offline binding checks with synthetic identifiers are performed. No authorization URL, provider request, real code/token, or credential is used.

### Bindings and Owners

OAuth failures are not one universal token weakness. A missing binding must reach a meaningful grant, session, or account-linking decision. A valid provider response can still belong to a different client, issuer, session, or resource. OAuth authorizes access; OIDC adds identity assertions and validation rules.

| Binding | Owner/check | Limitation |
|---|---|---|
| Redirect URI | Authorization server exact registered matching, with specified native-app exceptions | A trusted redirect endpoint must not become an arbitrary redirector |
| Browser transaction | Client stores unpredictable state bound to initiating session | State does not verify token audience or signatures |
| Code-to-client instance | PKCE S256 challenge at authorization, verifier at token endpoint | PKCE does not decide which local account may be linked |
| Code use | Server binds client/redirect and atomically consumes code | Client callback deduplication alone is insufficient |
| Issuer | Client binds expected issuer and endpoints; checks response issuer where supported | TLS to the wrong legitimate issuer is still the wrong issuer |
| Resource/purpose | Resource server validates audience, scope, token type | An ID token is not automatically an API access token |
| Account linking | Reauthenticate existing account and explicitly approve new identity | Matching email strings alone is not ownership proof |

Use authorization code with PKCE S256 for public clients and as recommended protection for confidential clients. Generate verifiers with cryptographic randomness and RFC 7636 syntax/length; never hardcode production verifiers. Do not fall back silently to weaker methods. Store transaction state server-side or in a properly protected session and expire it. Bind callback error handling too, so an unrelated response cannot reset another flow.

### Issuer, Consent, and Token Handling

Mix-up conditions arise when a client works with multiple authorization servers but fails to bind the response and token endpoint to the initiating issuer. RFC 9207 supplies an authorization-response issuer identifier; use maintained issuer-aware libraries. Discovery metadata and key endpoints must come from configured trust, not arbitrary response fields.

Consent should show the real client and minimum scopes. Incremental authorization must not silently expand prior grants. Access tokens belong to their resource; ID tokens require issuer/audience/signature/time checks and nonce validation when used in the initiating flow. Refresh tokens require protected storage, restricted lifetime, and rotation or sender constraints according to client/provider policy. Do not log codes, verifiers, or raw tokens; record correlation IDs and failure categories.

Account linking is a sensitive local state change: require a freshly authenticated existing account, verify the external identity as `(issuer, subject)`, require deliberate linking intent, and prevent one external identity from being silently reassigned. Unlink and recovery policies need equivalent care.

### Versions and Defense Limits

RFC 9700 (2025) is the OAuth 2.0 Security Best Current Practice; do not treat older implicit/password-flow examples as current recommendations. Provider implementations and library defaults differ. State, PKCE, nonce, issuer, and audience have overlapping security goals but are not interchangeable. The fixture implements only selected checks with stdlib hashing, not an OAuth client/server.

## Defense

Use maintained protocol libraries with explicit issuer/client/redirect configuration, PKCE, transaction correlation, and full token validation. Minimize scopes and keep provider credentials out of browsers. Make one-time state/code consumption atomic and enforce expiry. Require explicit authenticated account linking and audit grant changes without secrets.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no provider/network/packages. Review a proposal that accepts any callback with a code. The replacement separates client callback correlation from server-side code redemption. Fixed strings below are synthetic fixtures, not production entropy or credentials. Account linking is an additional independent policy check.

### File: test_example.py

```python
import base64
import hashlib
import hmac
import unittest


def challenge(verifier):
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	if type(verifier) is not str or not 43 <= len(verifier) <= 128:
		raise ValueError("verifier length")
	if any(character not in alphabet for character in verifier):
		raise ValueError("verifier alphabet")
	digest = hashlib.sha256(verifier.encode("ascii")).digest()
	return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def accept_callback(pending, session, state, issuer):
	if pending["used"] or (session, state, issuer) != (
			pending["session"], pending["state"], pending["issuer"]):
		raise PermissionError("callback binding")
	pending["used"] = True


def redeem_synthetic_code(grant, client, redirect, verifier):
	if grant["used"] or (client, redirect) != (grant["client"], grant["redirect"]):
		raise PermissionError("grant binding")
	if not hmac.compare_digest(challenge(verifier), grant["challenge"]):
		raise PermissionError("PKCE mismatch")
	grant["used"] = True
	return "synthetic-grant-accepted"


def approve_link(current_user, intended_user, reauthenticated, explicit_approval):
	if current_user != intended_user or not reauthenticated or not explicit_approval:
		raise PermissionError("link intent")


class OAuthBindingTests(unittest.TestCase):
	def setUp(self):
		self.pending = {"session": "session-a", "state": "state-a",
						"issuer": "https://identity.example", "used": False}
		self.verifier = "A" * 43
		self.grant = {"client": "training-client", "redirect": "https://app.example/callback",
					  "challenge": challenge(self.verifier), "used": False}

	def test_client_correlation_and_single_use(self):
		for session, state, issuer in [
				("session-b", "state-a", "https://identity.example"),
				("session-a", "state-b", "https://identity.example"),
				("session-a", "state-a", "https://other.example")]:
			with self.assertRaises(PermissionError):
				accept_callback(self.pending, session, state, issuer)
			self.assertFalse(self.pending["used"])
		accept_callback(self.pending, "session-a", "state-a", "https://identity.example")
		with self.assertRaises(PermissionError):
			accept_callback(self.pending, "session-a", "state-a", "https://identity.example")

	def test_server_code_binding(self):
		for client, redirect, verifier in [
				("other-client", self.grant["redirect"], self.verifier),
				(self.grant["client"], "https://app.example/other", self.verifier),
				(self.grant["client"], self.grant["redirect"], "B" * 43)]:
			with self.assertRaises(PermissionError):
				redeem_synthetic_code(self.grant, client, redirect, verifier)
			self.assertFalse(self.grant["used"])
		redeem_synthetic_code(self.grant, self.grant["client"], self.grant["redirect"], self.verifier)
		with self.assertRaises(PermissionError):
			redeem_synthetic_code(self.grant, self.grant["client"], self.grant["redirect"], self.verifier)

	def test_linking_requires_existing_account_intent(self):
		approve_link("ada", "ada", True, True)
		for args in [("ada", "grace", True, True), ("ada", "ada", False, True),
					 ("ada", "ada", True, False)]:
			with self.assertRaises(PermissionError):
				approve_link(*args)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: which function belongs at the client and which at the authorization server? Why does a successful PKCE comparison not authorize account linking?

Solution: each role checks its own binding before consuming state. Expected: three tests pass; mismatches do not consume pending state/grants; accepted records become single-use; linking requires the same current account and both approval conditions. These in-memory updates are not concurrency-safe production code. Expiry, cryptographic entropy, token validation, verified external identity, and durable atomic consumption belong to a real library-backed integration.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file; no identity-provider registration is needed. The repeated verifier characters intentionally make a reproducible fixture, not a recommended secret. Remove the disposable exercise directory; no grants, accounts, or network state exist outside the process.

- [ ] Local OAuth Attacks exercise: Review client/server and account-linking bindings.
- [ ] Boundary check: Run offline correlation, PKCE, single-use, and approval tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9207: authorization server issuer identification](https://www.rfc-editor.org/rfc/rfc9207)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
