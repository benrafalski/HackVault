---
title: "MFA and WebAuthn/Passkeys"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[MFA and WebAuthn Security]]"
updated: 2026-11-03
---
# MFA and WebAuthn/Passkeys

> [!abstract] TL;DR
> Validate challenge, origin, RP ID, signature, and required user verification. Treat recovery and new-factor enrollment as sensitive authenticated operations.

> [!info] Agent scope
> Authentication factors; TOTP; recovery; WebAuthn registration and assertion; relying-party IDs; passkeys; phishing resistance.

## Prerequisites

- Browser secure contexts, origins, public-key signatures, sessions, Python 3.12 and [[Web Lab Setup]].
- The browser lab needs a current browser with WebAuthn and a user-verifying platform authenticator or security key. A disposable browser virtual authenticator is an alternative, not proof of hardware assurance.

## Learn

```text
Teach MFA, TOTP and WebAuthn/passkeys at expert engineering depth. Assume HTTP,
browser origins, sessions and public-key cryptography. Separate knowledge, possession
and inherence; explain when local PIN/biometric user verification makes a cryptographic
authenticator multi-factor and why two passwords do not. Derive TOTP moving counters,
digits/window/drift, rate budgets, one-use steps and seed/recovery custody.
Trace WebAuthn create/get through clientDataJSON, attestationObject, authenticatorData,
RP ID hash, flags, COSE public keys, signature base and credential/account binding.
Explain RP ID versus origin, user presence versus verification, attestation trust,
discoverable credentials, userHandle, sync/backup flags, counter limits and phishing
resistance. Give complete runnable browser and Python verifier files with real
authenticator operations, positive controls and safe rejection tests; never fake
authentication using a dictionary of booleans. Cover enrollment, challenge consumption,
session/step-up, recovery, loss, device replacement and privacy tradeoffs. Cite W3C,
FIDO, RFC 6238, NIST and library docs; distinguish unverified browser/hardware behavior.
No theft, forgery or bypass walkthroughs. End with worked questions. Teach here,
without editing notes or study progress or inventing execution results.
```

## Cheatsheet

### Factor and Recovery Decisions

| Mechanism | Evidence | Important boundary |
|---|---|---|
| Password/PIN sent to server | Knowledge of a shared secret | Two knowledge secrets are not independent factors |
| TOTP | Possession of a shared seed at an accepted time step | Code is phishable; server seed disclosure enables reproduction |
| SMS/voice | Access to a delivery channel | Telecom/account-recovery risks; not phishing-resistant |
| WebAuthn with UP only | Credential use plus user presence | A touch is not identity verification |
| WebAuthn with required UV | Credential use plus local verification such as PIN/biometric | Evaluate authenticator assurance and recovery/sync policy, not just UI wording |
| Recovery code | Possession of a one-use high-entropy secret | Explicit recovery workflow, not an automatic equivalent of recent strong authentication |

A passkey is a FIDO credential used through WebAuthn/CTAP, not a standardized promise that a key is hardware-bound. Synced credentials improve availability across devices but introduce sync-provider/recovery trust. Device-bound credentials can meet different custody requirements. Biometric templates normally stay on the authenticator; the RP receives the UV result, not a fingerprint or PIN.

Enroll new factors only after appropriate recent authentication and explicit intent, then confirm possession before activation. Notify factor changes independently. Allow multiple authenticators under policy, protect removal of the last usable factor and provide a recovery path whose assurance is explicitly stated. Password reset must not silently disable MFA. Recovery should revoke relevant sessions, issue a restricted recovery state and require deliberate re-enrollment; it must not automatically satisfy an unrelated high-risk step-up.

### TOTP Mechanics

RFC 6238 computes HOTP using counter `floor((UnixTime - T0) / X)`, commonly `T0=0`, `X=30 seconds`. HMAC over the 8-byte big-endian counter is dynamically truncated and reduced modulo `10^digits`, then zero-padded. Algorithm, step and digits are enrollment parameters, not inferred from whatever the client sends. SHA-1 remains specified for HOTP/TOTP; that keyed construction is distinct from accepting SHA-1 digital signatures.

Store a cryptographically random seed encrypted under a separately controlled key: a hash cannot support future verification. Treat the provisioning URI/QR as a credential. Activate only after confirmation, show it only in the authenticated enrollment context, and never put it in analytics/logs. Libraries such as PyOTP implement the algorithm; the application supplies storage, throttling and one-use semantics. A narrow `[-1, 0, +1]` step window increases guessing opportunities and must be justified by clock/drift requirements. Record the matched step atomically and reject steps already accepted. Bound attempts per account, source and system before verification. Do not silently enlarge the window when clocks drift.

### Registration: Inputs, Bytes and Storage

1. Server binds a random challenge (at least 16 unpredictable bytes; use 32), deadline, ceremony type and immutable account/user handle to a live authenticated enrollment transaction. Generate a fresh challenge per attempt.
2. `navigator.credentials.create({publicKey: ...})` receives `rp.id/name`, `user.id/name/displayName`, challenge, allowed COSE algorithms, `excludeCredentials`, attestation preference and authenticator selection. Binary values must be ArrayBuffers, not base64 strings.
3. Browser checks secure context and RP ID eligibility. The authenticator creates a credential. `clientDataJSON` contains type `webauthn.create`, challenge, origin and cross-origin context. `attestationObject` is CBOR with format, authenticator data and attestation statement.
4. Server verifies expected challenge, exact allowed origin, expected RP ID hash, UP/required UV, accepted algorithm and supported attestation policy using a maintained library. It does not merely decode CBOR.
5. Atomically claim the challenge, reject duplicate credential IDs and store credential ID, COSE public key, immutable account handle, counter, transport hints and backup/device properties. Transport hints help routing but are not proof of authenticator type.

Attestation conveys authenticator provenance under a trust policy; `attestation="none"` avoids demanding that provenance and reduces privacy/interoperability costs. Successfully parsing an attestation certificate does not establish a trusted hardware model. Enterprise attestation requires an explicit deployment/privacy policy and trusted metadata; do not infer assurance from AAGUID alone.

### Assertion Verification Order

| Input/check | Required handling |
|---|---|
| Credential ID/type | Resolve a registered active credential; require public-key type and account ownership |
| Transaction | Same browser/account/action, fresh deadline, correct ceremony, one-use challenge |
| `clientDataJSON` | Exact received bytes are hashed; verify `webauthn.get`, challenge, origin and allowed cross-origin/top-origin policy |
| `authenticatorData` | First 32 bytes RP ID hash, flags byte, four-byte counter; parse extensions through a library |
| RP ID hash | SHA-256 of configured RP ID, not arbitrary supplied host or origin |
| Flags | UP required; UV required for this policy; validate backup eligibility/state consistency |
| Signature | Verify over `authenticatorData || SHA256(clientDataJSON)` using stored public key/algorithm |
| `userHandle` | When present, match stored immutable user ID and credential ownership; discoverable login must resolve this safely |
| Counter | Apply supported library/authenticator policy; increasing counters are a signal, not universal replay prevention |
| Commit | Atomically consume challenge and update credential state; only then grant session/step-up authority |

The RP ID is a domain identifier without scheme/port, normally the origin's host or an eligible registrable suffix. An origin includes scheme, host and effective port. `localhost` and `http://localhost:8765` are therefore different kinds of values. Broad parent-domain RP IDs increase the domain's trust surface; approve each origin independently. Do not treat suffix matching on an arbitrary URL as origin verification. Related-origin requests and embedded contexts are version-sensitive features requiring explicit policy, not defaults to assume.

The signature covers client-data hash, which binds challenge and origin. This is the basis of phishing resistance when the browser/authenticator and RP checks behave correctly: credentials are scoped to the RP, not reusable passwords typed into arbitrary sites. It does not stop compromised same-origin script from acting through a live session, authorize arbitrary transactions, or secure a weak recovery channel.

### Passkeys, Sessions and Failure Decisions

Discoverable credentials allow account selection without a username/allow-list; non-discoverable flows usually identify the account first and supply credential IDs. `user.id` should be opaque, stable and at most 64 bytes, not an email address. Synced passkeys may have zero or nonmonotonic cross-device counters; challenge freshness and one-use storage remain mandatory even with counters. Backup eligibility (BE) describes whether backup is possible, backup state (BS) current backup status; neither alone proves hardware custody.

Request `userVerification="required"` **and** enforce it server-side. `preferred` can complete without UV. After success rotate/create the application session under local policy; store a server-owned authentication time/method for step-up. A client-supplied `mfa=true` or hidden button is not authorization. Bind high-risk step-up to the intended action/account, with a short deadline and one-use policy where appropriate.

## Gotchas

- Registration is not proof of control of a preexisting account; the enrollment transaction supplies that authority.
- WebAuthn `timeout` is a client hint. The server must enforce its own deadline.
- Changing RP ID can strand existing credentials. Changing only port changes the origin policy but not RP ID; migration still needs deliberate configuration.
- Credential removal on the RP does not necessarily remove the authenticator's local/synced record, and deleting browser cookies does not revoke a passkey.

## Labs

### Environment and Complete Files

Python 3.12, `webauthn` 2.x and a current browser with WebAuthn JSON conversion methods (`parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON`, credential `toJSON`). Dependency range is an **unexecuted compatibility target**, not a lockfile; record resolved versions. The following four files are sufficient in a new disposable directory. This uses a real browser/authenticator and real server verification, not a protocol simulator. No Node tooling, CDN or sibling files are required.

The loopback-only server deliberately starts with a synthetic enrolled-account context for each browser cookie; it has **no password login or real account recovery** and must never be exposed on a network. Enrollment is permitted once for that fixture. It demonstrates ceremony verification, not production account authentication/session management. Browser credential storage may outlive the Python process. Use a disposable virtual authenticator or remove the test credential afterward.

### File: requirements.txt

```text
webauthn>=2,<3
```

### File: lab.py

```python
import json
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers import options_to_json, base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import AuthenticatorSelectionCriteria
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, ResidentKeyRequirement
from webauthn.helpers.structs import UserVerificationRequirement


RP_ID, ORIGIN = "localhost", "http://localhost:8765"


class Ceremony:
	def __init__(self):
		self.user_id = secrets.token_bytes(32)
		self.credential = None
		self.pending = None

	def begin(self, kind, now):
		if kind == "register" and self.credential is None:
			options = generate_registration_options(rp_id=RP_ID, rp_name="Disposable W4 Lab",
				user_id=self.user_id, user_name="synthetic-alice",
				authenticator_selection=AuthenticatorSelectionCriteria(
					resident_key=ResidentKeyRequirement.REQUIRED,
					user_verification=UserVerificationRequirement.REQUIRED))
		elif kind == "authenticate" and self.credential is not None:
			options = generate_authentication_options(rp_id=RP_ID,
				allow_credentials=[PublicKeyCredentialDescriptor(id=self.credential.credential_id)],
				user_verification=UserVerificationRequirement.REQUIRED)
		else:
			raise ValueError("ceremony unavailable")
		self.pending = (kind, options.challenge, now + 120)
		return json.loads(options_to_json(options))

	def finish(self, kind, response, now):
		pending, self.pending = self.pending, None
		if pending is None or pending[0] != kind or now >= pending[2]:
			raise ValueError("no live ceremony")
		challenge = pending[1]
		if kind == "register":
			verified = verify_registration_response(credential=response,
				expected_challenge=challenge, expected_rp_id=RP_ID,
				expected_origin=ORIGIN, require_user_verification=True)
			if self.credential is not None:
				raise ValueError("already enrolled")
			self.credential = verified
			return {"result": "registered", "user_verified": verified.user_verified}
		if self.credential is None or base64url_to_bytes(response["id"]) != self.credential.credential_id:
			raise ValueError("unknown credential")
		user_handle = response["response"].get("userHandle")
		if user_handle is not None and base64url_to_bytes(user_handle) != self.user_id:
			raise ValueError("user handle")
		arguments = dict(credential=response, expected_challenge=challenge, expected_rp_id=RP_ID,
			expected_origin=ORIGIN, credential_public_key=self.credential.credential_public_key,
			credential_current_sign_count=self.credential.sign_count, require_user_verification=True)
		for changed in ({"expected_origin": "https://different.example.test"},
						{"expected_challenge": secrets.token_bytes(32)}):
			try:
				verify_authentication_response(**(arguments | changed))
			except InvalidAuthenticationResponse:
				pass
			else:
				raise RuntimeError("negative context check unexpectedly accepted")
		verified = verify_authentication_response(**arguments)
		self.credential.sign_count = verified.new_sign_count
		self.credential.credential_backed_up = verified.credential_backed_up
		return {"result": "authenticated", "negative_context_checks": 2,
			"user_verified": verified.user_verified}


SESSIONS = {}


class Handler(BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		pass

	def send(self, status, value, cookie=None, html=False):
		data = value if html else json.dumps(value).encode()
		self.send_response(status)
		self.send_header("Content-Type", "text/html; charset=utf-8" if html else "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.send_header("Cache-Control", "no-store")
		self.send_header("X-Content-Type-Options", "nosniff")
		self.send_header("Referrer-Policy", "no-referrer")
		if cookie:
			self.send_header("Set-Cookie", "lab=" + cookie + "; Path=/; HttpOnly; SameSite=Strict")
		self.end_headers()
		self.wfile.write(data)

	def session(self):
		jar = SimpleCookie()
		jar.load(self.headers.get("Cookie", ""))
		item = jar.get("lab")
		return SESSIONS.get(item.value) if item else None

	def do_GET(self):
		if self.headers.get("Host") != "localhost:8765" or self.path != "/":
			return self.send(404, {"error": "route"})
		context, cookie = self.session(), None
		if context is None:
			if len(SESSIONS) >= 16:
				return self.send(503, {"error": "restart disposable lab"})
			cookie = secrets.token_urlsafe(32)
			SESSIONS[cookie] = Ceremony()
		self.send(200, Path(__file__).with_name("index.html").read_bytes(), cookie, html=True)

	def do_POST(self):
		if self.headers.get("Host") != "localhost:8765" or self.headers.get("Origin") != ORIGIN:
			return self.send(403, {"error": "origin"})
		context = self.session()
		if context is None:
			return self.send(403, {"error": "browser context"})
		try:
			length = int(self.headers.get("Content-Length", "0"))
			if not 0 < length <= 65536 or self.headers.get("Content-Type") != "application/json":
				raise ValueError("body")
			data = json.loads(self.rfile.read(length))
			if self.path == "/begin":
				result = context.begin(data["kind"], time.time())
			elif self.path == "/finish":
				result = context.finish(data["kind"], data["credential"], time.time())
			else:
				return self.send(404, {"error": "route"})
		except Exception as error:
			print("rejected:", type(error).__name__)
			return self.send(400, {"error": "ceremony rejected; begin again"})
		self.send(200, result)


if __name__ == "__main__":
	print("Disposable WebAuthn lab: " + ORIGIN + "/")
	HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
```

### File: index.html

```html
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Disposable WebAuthn Lab</title>
<h1>WebAuthn Lab</h1>
<button id="register" type="button">Register</button>
<button id="authenticate" type="button">Authenticate</button>
<button id="replay" type="button">Check consumed challenge</button>
<pre id="result" aria-live="polite"></pre>
<script>
let lastCompletion = null;
const output = document.querySelector("#result");
async function post(path, body) {
  const response = await fetch(path, {
	method: "POST", headers: {"Content-Type": "application/json"},
	body: JSON.stringify(body), credentials: "same-origin"
  });
  const value = await response.json();
  if (!response.ok) throw new Error(response.status + " " + value.error);
  return value;
}
async function run(kind) {
  const options = await post("/begin", {kind});
  let credential;
  if (kind === "register") {
	credential = await navigator.credentials.create({
	  publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)
	});
  } else {
	credential = await navigator.credentials.get({
	  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)
	});
  }
  if (!credential) throw new Error("No credential returned");
  const completion = {kind, credential: credential.toJSON()};
  const result = await post("/finish", completion);
  lastCompletion = completion;
  output.textContent = JSON.stringify(result, null, 2);
}
for (const kind of ["register", "authenticate"]) {
  document.getElementById(kind).onclick = async () => {
	try { await run(kind); }
	catch (error) { output.textContent = error.message; }
  };
}
document.getElementById("replay").onclick = async () => {
  if (!lastCompletion) { output.textContent = "Complete a ceremony first"; return; }
  try {
	await post("/finish", lastCompletion);
	output.textContent = "FAIL: consumed challenge accepted";
  } catch (error) { output.textContent = "Expected rejection: " + error.message; }
};
</script>
</html>
```

### File: test_example.py

```python
import unittest
from lab import Ceremony


class TransactionTests(unittest.TestCase):
	def test_registration_options_and_expiry(self):
		context = Ceremony()
		first = context.begin("register", 100)
		self.assertEqual(first["rp"]["id"], "localhost")
		self.assertEqual(first["authenticatorSelection"]["userVerification"], "required")
		second = context.begin("register", 101)
		self.assertNotEqual(first["challenge"], second["challenge"])
		with self.assertRaises(ValueError):
			context.finish("register", {}, 221)
		self.assertIsNone(context.pending)
		self.assertIsNone(context.credential)

	def test_no_pre_enrollment_authentication(self):
		context = Ceremony()
		with self.assertRaises(ValueError):
			context.begin("authenticate", 100)
		with self.assertRaises(ValueError):
			context.finish("authenticate", {}, 100)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_example
.venv\Scripts\python -m pip freeze
.venv\Scripts\python lab.py
```

The last command is a **reader/parent-run step**, not an author-executed server. Open `http://localhost:8765/`, not the IP address or an HTML file URL. Loopback localhost is treated as a potentially trustworthy origin by supporting browsers; ordinary deployed HTTP is not acceptable. The lab cookie intentionally omits Secure only for this loopback HTTP exercise; production requires HTTPS and secure cookie/session policy.

1. For a virtual authenticator in Chromium DevTools, open More tools > WebAuthn, enable the environment and add CTAP2 with resident-key and user-verification support. Enable user verification. Keep this environment open; menu names may vary. Alternatively use a real test authenticator with a PIN/biometric. Never enter real service credentials.
2. Select Register and complete the browser prompt. Then Authenticate. The server verifies the actual response twice with deliberately wrong expected context, then with the correct context. Only the correct verification may succeed.
3. Select Check consumed challenge after successful authentication. Expect rejection, then Authenticate again and require success with a fresh challenge.
4. Inspect the options and library calls without copying credential responses into logs. Explain RP ID versus origin, UV, challenge expiry and credential/account association. Do not claim the unittest-only run exercised an authenticator.

### Hints

The browser JSON conversion methods handle ArrayBuffer/base64url conversion. Missing methods require a compatible current browser, not skipping validation. A click cancellation is not a failed cryptographic check. The response is unchanged for the wrong-origin/challenge tests; only the verifier's expected context changes. `pending` is consumed before verification, so any failed completion must start over.

### Solution and Expected Results

Expected unit result: **two tests pass**, covering option policy and transaction gates only. Expected browser result: `registered` with `user_verified: true`, then `authenticated` with `negative_context_checks: 2` and `user_verified: true`. Repeated completion returns HTTP 400; new authentication succeeds. These are acceptance criteria, **not observed output**. A virtual authenticator validates integration logic but cannot certify physical security, sync-provider custody or biometric assurance.

### Verification, Troubleshooting, and Cleanup

Not installed, executed or browser-tested here. Parent validation owns all run steps. `NotAllowedError` commonly means cancellation, timeout, missing matching credential or UV unavailable. `SecurityError` commonly indicates wrong origin/RP ID or insecure context. Missing browser JSON APIs require an updated supported browser. Rejections should expose only exception class, not clientData or keys. Port 8765 must be free; changing it requires changing ORIGIN and both Host checks consistently. Do not bind to `0.0.0.0`.

Stop with Ctrl+C, remove the disposable authenticator/test passkey from its manager, clear localhost site data, and delete the directory/venv/caches. All server state is memory-only; restarting loses enrollment and invalidates outstanding transactions. Production gaps: durable shared challenge/credential storage, concurrent consumption, real login/enrollment authorization, recovery, rate limiting, attestation trust policy, cross-origin embedding policy, secure session issuance and account-wide revocation. None is claimed by this lab. The original study checkboxes remain unchanged.

- [ ] Local MFA and WebAuthn exercise: Register a test passkey in a local HTTPS/localhost relying party and authenticate with a fresh challenge. Verify replay and wrong-origin attempts fail; document recovery behavior separately.
- [ ] Boundary check: Replay an old synthetic assertion and call a step-up-protected operation without completing the factor. Require server-side rejection in both cases.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[MFA and WebAuthn Security]]

## References

- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [FIDO passkeys](https://fidoalliance.org/passkeys/)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [py_webauthn registration](https://duo-labs.github.io/py_webauthn/registration.html)
- [py_webauthn authentication](https://duo-labs.github.io/py_webauthn/authentication.html)
- [Chrome DevTools virtual authenticators](https://developer.chrome.com/docs/devtools/webauthn)
