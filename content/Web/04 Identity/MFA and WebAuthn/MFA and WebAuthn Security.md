---
title: "MFA and WebAuthn/Passkeys Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[MFA and WebAuthn]]"
updated: 2026-11-03
---
# MFA and WebAuthn/Passkeys Security

> [!abstract] TL;DR
> Weak recovery, missing challenge/origin validation, or step-up enforced only in the UI can bypass an otherwise strong factor.

> [!info] Agent scope
> Security of: Authentication factors; TOTP; recovery; WebAuthn registration and assertion; relying-party IDs; passkeys; phishing resistance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Factor enrollment, authenticator custody, browser ceremony, server verification, session issuance, step-up and recovery are separate security decisions. A correct signature cannot repair enrollment into the wrong account. Phishing-resistant WebAuthn does not make TOTP/email recovery equally resistant, or make a stolen application session harmless. Evaluate the weakest permitted route to equivalent authority.

## Learn

```text
Teach defensive MFA and WebAuthn/passkey engineering at expert depth. Assume sessions,
HTTP origins, cryptographic signatures and transactional storage. Trace enrollment,
challenge generation/consumption, credential ownership, exact origin/RP ID validation,
UP/UV flags, signatures, counters, backup state, session rotation and action-bound
step-up. Explain phishing resistance and its limits, synced versus device-bound keys,
attestation trust and version-sensitive cross-origin features. Cover TOTP seed custody,
time windows, matched-step replay prevention, atomic rate budgets and recovery codes.
Give secure library calls, concrete failure decisions and an independent complete
SQLite/PyOTP test lab for actual TOTP verification, expiry, replay, throttling,
recovery/re-enrollment and revocation with positive controls. Do not equate state-unit
tests with a real WebAuthn ceremony; define browser/hardware integration gates.
Explain root causes without theft, forgery, exploit payloads or bypass walkthroughs.
Use W3C/FIDO/NIST/RFC/library sources, no invented execution results. End with worked
design questions. Teach in this conversation, not file edits or study-state changes.
```

## Cheatsheet

### Trust Boundaries and Failure Decisions

| Boundary | Root cause | Required rejection/control |
|---|---|---|
| Enrollment | Credential added using account ID from request rather than current authorized account | Recent authenticated intent, CSRF, account/action-bound challenge, possession confirmation |
| Ceremony | Challenge reused, expired or not bound to browser/action | Unpredictable short-lived server state, atomic consume, restart on failed completion |
| Origin/RP ID | Client-selected domain or permissive string matching | Exact configured origin list, eligible configured RP ID, library hash verification |
| Credential ownership | A valid key is treated as authority for any account | Stored credential ID -> immutable account mapping; verify userHandle when present |
| UP versus UV | A touch or requested UV is treated as verified identity | Require UV in options and in server verification; enforce UP too |
| Signature/counter | Parsed client data or counter change replaces signature checking | Verify actual signature over authenticator data plus client-data hash; one-use challenge regardless of counters |
| Step-up | UI hides operation but server accepts ordinary session | Server-owned action/account/session-bound proof with recent authentication and deadline |
| TOTP | Accepted code reused in same window or unlimited attempts | Atomic matched-step record and cheap bounded admission before verification |
| Recovery | Recovery grants all privileges or silently removes MFA | One-use restricted capability, notifications, session revocation and explicit re-enrollment |

Two passwords are one factor type. A PIN unlocking a cryptographic authenticator is different: local verification plus possession can be multi-factor under the assurance policy. Do not infer this from product branding or an arbitrary client field. Synced passkeys can be phishing-resistant without being hardware-bound; enterprise custody requirements need explicit authenticator/attestation and recovery policies.

### WebAuthn Verification and State Order

1. Select the transaction using server-owned browser/session state. Bound JSON/body sizes, reject duplicate security parameters, check expected ceremony, account/action, deadline and current account/credential epoch.
2. Resolve a registered active credential ID within this account. For discoverable login, resolve the immutable user handle and credential together; do not accept a handle as a standalone credential. Registration must reject credentials already bound to another account.
3. Use a maintained library to check `clientDataJSON.type`, original challenge, exact origin and cross-origin policy. Hash original client-data bytes, not a JSON reserialization. Require the RP ID hash of the configured RP ID.
4. Require UP and the application's UV policy. Validate algorithm/COSE key, extensions and BE/BS consistency; verify the signature over `authenticatorData || SHA256(clientDataJSON)`. Attestation validation on registration is a separate provenance decision, not a substitute for account authorization.
5. Apply supported counter policy and record credential properties. Some authenticators keep zero counters and synchronized credentials can complicate monotonicity. A clone signal needs investigation and appropriate policy; counter zero is not permission to skip signatures/challenges.
6. Atomically claim the live transaction, recheck account/credential state, update counters and create the session/step-up proof. On a lost race or revoked credential, deny. No failed path may leave a partially elevated session.

The following **verifier adapter fragment** uses documented py_webauthn 2.x APIs. Its inputs come from bounded parsed JSON and trusted storage; it deliberately does not implement the transaction, registration or HTTP layer. The independent lab below does not depend on this fragment or package.

```python
from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes


def verify_assertion(response, *, challenge, expected_origin, rp_id,
					 credential_id, user_id, public_key, sign_count):
	if base64url_to_bytes(response["id"]) != credential_id:
		raise PermissionError("credential ownership")
	handle = response["response"].get("userHandle")
	if handle is not None and base64url_to_bytes(handle) != user_id:
		raise PermissionError("user binding")
	return verify_authentication_response(
		credential=response, expected_challenge=challenge,
		expected_origin=expected_origin, expected_rp_id=rp_id,
		credential_public_key=public_key,
		credential_current_sign_count=sign_count,
		require_user_verification=True,
	)
```

For deployment, verify the chosen library/version also enforces the intended `crossOrigin`/`topOrigin` and extension policies; do not assume the adapter covers new Level 3 features automatically. Reject unsupported embedded/related-origin flows. Origin includes scheme and port; RP ID does not. Bind proxy-derived URLs to configured public origins, not arbitrary forwarded headers. The adapter's return value alone must not mutate privilege before atomic state checks.

### TOTP, Recovery and Step-Up

Use a vetted TOTP library with fixed enrolled algorithm, digits and period. Check ASCII digit length before comparison, use time-aware verification and a narrow documented step window. Record the **matched counter**, not a client timestamp. With a drift window, a monotonic last-step policy may reject legitimate out-of-order attempts; that availability tradeoff is preferable to silently accepting repeated codes. Use an atomic replay record and bounded account/network/global limits; rate limits and OTP replay state must survive worker changes. Fixed windows are easy to teach but permit boundary bursts, so production commonly uses sliding windows/token buckets and bounded storage.

TOTP seeds must remain recoverable to the verifier, so encrypt them under managed keys with versioned rotation and restricted decrypt access. A seed hash is not a verifier. Provisioning QR codes and URIs are credentials. Do not send them to remote QR generators. Require confirmation before enabling a new seed, keep the old factor active until replacement is confirmed under policy, then revoke obsolete credentials/sessions. Backup restoration must not restore stale last-step or revoked-session authority.

Generate high-entropy recovery codes, display once in an authenticated context and store digests. Consume a code atomically; throttle attempts and avoid disclosing which code/account exists. A recovery capability should authorize only recovery operations, not money movement, export or administrator actions. Recovery notifications, delay/approval for high-assurance accounts and independent helpdesk identity proofing require a documented policy. Knowledge questions are not an equivalent factor.

Bind step-up to session, immutable account, credential/account epoch, canonical action and important action parameters. For example, an authorization for `export:alice` must not authorize `factor-remove:alice` or a different user's export. Store authentication method/time and expire the proof independently of the session. For one-use authorization, consume the proof in the same transaction as the protected mutation or durable outbox event. A queued job must revalidate authority where its threat model requires it.

### Regression and Incident Decisions

| Test | Expected decision | What it does not prove |
|---|---|---|
| Valid registered authenticator, fresh challenge, required UV | Accept and update state once | Account was safely enrolled or device meets a hardware assurance level |
| Same genuine assertion, wrong configured expected challenge/origin | Reject before elevation | Browser implementation is uncompromised |
| Consumed challenge or removed credential | Reject | All distributed caches have propagated revocation |
| Old TOTP step, correct current code after three admitted attempts | Reject replay/throttle respectively | Resistance to high-volume distributed guessing |
| Recovery code reused, or recovery handle used as ordinary session | Reject | Recovery delivery/helpdesk process is trustworthy |
| Correct fresh factor after negative cases | Accept appropriate action | Unrelated actions are authorized |

## Detection and Defense

Audit enrollment/removal/recovery, credential epoch changes, step-up action class and verification result with pseudonymous account/request IDs. Never log OTP seeds/codes, recovery capabilities, attestation dumps, client-data responses or session cookies. Alert on repeated recovery, unexpected factor replacement and UV-policy failures; distinguish cancellation/unsupported authenticator from signature failure. Counter anomalies can reflect authenticators/synchronization and are not standalone proof of compromise. Require out-of-band notifications and audited administrative recovery; rate limiting must not become indefinite unauthenticated account lockout.

On credential loss/compromise, revoke the credential and applicable sessions/step-up grants, invalidate recovery artifacts according to policy, and require controlled re-enrollment. On TOTP database exposure, seed secrecy may be lost even if passwords remain hashed; plan seed replacement and session revocation. Test revocation from the actual authority store, not merely UI removal.

## Labs

### Environment and Complete Files

Python 3.12, standard-library SQLite/unittest and PyOTP 2.9.0, a release documented by the project. Installation and execution are **unverified**. Create the two files below in a new disposable directory. No browser, server, mail service, real user or companion page is needed. This lab performs actual RFC TOTP computations and transactional authorization/recovery. It **does not implement or simulate WebAuthn authentication**; browser/cryptographic WebAuthn checks remain separate integration gates described above.

`password_verified_session` is a test fixture boundary standing in for a completed first-factor check, not a password endpoint. All code generation is by the synthetic owner's authenticator fixture. The public RFC seed is intentionally stored in memory only; production must use encrypted seed storage. The recovery capability is a separate table/type and cannot serve as an ordinary session.

### File: requirements.txt

```text
pyotp==2.9.0
```

### File: test_example.py

```python
import base64
import hashlib
import re
import secrets
import sqlite3
import unittest
import pyotp


SEED = base64.b32encode(b"12345678901234567890").decode("ascii")


def digest(value):
	if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", value):
		raise PermissionError("capability")
	return hashlib.sha256(value.encode("ascii")).hexdigest()


def match_step(seed, code, now, previous):
	if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
		raise PermissionError("factor")
	step = now // 30
	if step <= previous or not pyotp.TOTP(seed).verify(code, for_time=now, valid_window=0):
		raise PermissionError("factor")
	return step


class Authority:
	def __init__(self):
		self.db = sqlite3.connect(":memory:")
		self.db.executescript("""
			CREATE TABLE account (id TEXT PRIMARY KEY, seed TEXT, epoch INTEGER, last_step INTEGER);
			CREATE TABLE sessions (digest TEXT PRIMARY KEY, epoch INTEGER, expires INTEGER);
			CREATE TABLE grants (digest TEXT PRIMARY KEY, session TEXT, action TEXT, epoch INTEGER, expires INTEGER);
			CREATE TABLE attempts (kind TEXT, window INTEGER, count INTEGER, PRIMARY KEY (kind, window));
			CREATE TABLE recovery_codes (digest TEXT PRIMARY KEY);
			CREATE TABLE recovery (digest TEXT PRIMARY KEY, epoch INTEGER, expires INTEGER);
			CREATE TABLE events (action TEXT);
		""")
		self.fixture_codes = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
		with self.db:
			self.db.execute("INSERT INTO account VALUES ('alice', ?, 0, -1)", (SEED,))
			self.db.executemany("INSERT INTO recovery_codes VALUES (?)",
				[(digest(code),) for code in self.fixture_codes])

	def admit(self, kind, now):
		window = now // 60
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			self.db.execute("DELETE FROM attempts WHERE window < ?", (window,))
			self.db.execute("INSERT OR IGNORE INTO attempts VALUES (?, ?, 0)", (kind, window))
			row = self.db.execute("SELECT count FROM attempts WHERE kind = ? AND window = ?",
				(kind, window)).fetchone()
			if row[0] >= 3:
				raise PermissionError("rate")
			self.db.execute("UPDATE attempts SET count = count + 1 WHERE kind = ? AND window = ?",
				(kind, window))

	def password_verified_session(self, now):
		token = secrets.token_urlsafe(32)
		with self.db:
			self.db.execute("INSERT INTO sessions SELECT ?, epoch, ? FROM account WHERE id = 'alice'",
				(digest(token), now + 600))
		return token

	def require_session(self, session, now):
		row = self.db.execute("""SELECT account.seed, account.epoch, account.last_step
			FROM sessions JOIN account ON sessions.epoch = account.epoch
			WHERE sessions.digest = ? AND sessions.expires > ? AND account.id = 'alice'""",
			(digest(session), now)).fetchone()
		if row is None:
			raise PermissionError("session")
		return row

	def step_up(self, session, code, action, now):
		if action != "export:alice":
			raise PermissionError("unsupported action")
		self.admit("totp", now)
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			seed, epoch, previous = self.require_session(session, now)
			step = match_step(seed, code, now, previous)
			self.db.execute("UPDATE account SET last_step = ? WHERE id = 'alice'", (step,))
			grant = secrets.token_urlsafe(32)
			self.db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
				(digest(grant), digest(session), action, epoch, now + 60))
		return grant

	def perform(self, session, grant, action, now):
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			unused_seed, epoch, unused_step = self.require_session(session, now)
			deleted = self.db.execute("""DELETE FROM grants WHERE digest = ? AND session = ?
				AND action = ? AND epoch = ? AND expires > ?""",
				(digest(grant), digest(session), action, epoch, now))
			if deleted.rowcount != 1:
				raise PermissionError("step-up required")
			self.db.execute("INSERT INTO events VALUES (?)", (action,))
		return "queued synthetic export"

	def recover(self, code, now):
		self.admit("recovery", now)
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			deleted = self.db.execute("DELETE FROM recovery_codes WHERE digest = ?", (digest(code),))
			if deleted.rowcount != 1:
				raise PermissionError("recovery")
			self.db.execute("UPDATE account SET epoch = epoch + 1 WHERE id = 'alice'")
			self.db.execute("DELETE FROM sessions")
			self.db.execute("DELETE FROM grants")
			self.db.execute("DELETE FROM recovery")
			token = secrets.token_urlsafe(32)
			self.db.execute("INSERT INTO recovery SELECT ?, epoch, ? FROM account WHERE id = 'alice'",
				(digest(token), now + 300))
		return token

	def enroll_replacement(self, recovery, seed, code, now):
		self.admit("enrollment", now)
		if not isinstance(seed, str) or not re.fullmatch(r"[A-Z2-7]{32}", seed):
			raise ValueError("seed policy")
		step = match_step(seed, code, now, -1)
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			deleted = self.db.execute("""DELETE FROM recovery WHERE digest = ? AND expires > ?
				AND epoch = (SELECT epoch FROM account WHERE id = 'alice')""", (digest(recovery), now))
			if deleted.rowcount != 1:
				raise PermissionError("recovery authority")
			self.db.execute("UPDATE account SET seed = ?, last_step = ?, epoch = epoch + 1 WHERE id = 'alice'",
				(seed, step))
			self.db.execute("DELETE FROM sessions")
			self.db.execute("DELETE FROM grants")
			self.db.execute("DELETE FROM recovery_codes")
		return "replacement confirmed; normal login required"


class MfaSecurityTests(unittest.TestCase):
	def setUp(self):
		self.authority = Authority()
		self.addCleanup(self.authority.db.close)

	def test_rfc_vector(self):
		token = pyotp.TOTP(SEED, digits=8, digest=hashlib.sha1)
		self.assertEqual(token.at(59), "94287082")
		self.assertEqual(token.at(1111111109), "07081804")

	def test_action_binding_replay_and_positive_control(self):
		session = self.authority.password_verified_session(60)
		with self.assertRaises(PermissionError):
			self.authority.perform(session, secrets.token_urlsafe(32), "export:alice", 60)
		code = pyotp.TOTP(SEED).at(60)
		grant = self.authority.step_up(session, code, "export:alice", 60)
		with self.assertRaises(PermissionError):
			self.authority.perform(session, grant, "export:bob", 61)
		self.assertEqual(self.authority.perform(session, grant, "export:alice", 61), "queued synthetic export")
		with self.assertRaises(PermissionError):
			self.authority.perform(session, grant, "export:alice", 62)
		with self.assertRaises(PermissionError):
			self.authority.step_up(session, code, "export:alice", 62)
		fresh = self.authority.step_up(session, pyotp.TOTP(SEED).at(90), "export:alice", 90)
		self.authority.perform(session, fresh, "export:alice", 91)
		self.assertEqual(self.authority.db.execute("SELECT count(*) FROM events").fetchone()[0], 2)

	def test_admission_survives_failed_verification(self):
		session = self.authority.password_verified_session(60)
		for unused in range(3):
			with self.assertRaises(PermissionError):
				self.authority.step_up(session, "not-an-otp", "export:alice", 60)
		with self.assertRaises(PermissionError):
			self.authority.step_up(session, pyotp.TOTP(SEED).at(61), "export:alice", 61)
		self.authority.step_up(session, pyotp.TOTP(SEED).at(120), "export:alice", 120)

	def test_recovery_revocation_and_reenrollment(self):
		session = self.authority.password_verified_session(100)
		grant = self.authority.step_up(session, pyotp.TOTP(SEED).at(100), "export:alice", 100)
		code = self.authority.fixture_codes[0]
		recovery = self.authority.recover(code, 101)
		with self.assertRaises(PermissionError):
			self.authority.recover(code, 102)
		with self.assertRaises(PermissionError):
			self.authority.perform(session, grant, "export:alice", 102)
		with self.assertRaises(PermissionError):
			self.authority.step_up(recovery, pyotp.TOTP(SEED).at(102), "export:alice", 102)
		seed = pyotp.random_base32()
		result = self.authority.enroll_replacement(recovery, seed, pyotp.TOTP(seed).at(102), 102)
		self.assertEqual(result, "replacement confirmed; normal login required")
		with self.assertRaises(PermissionError):
			self.authority.enroll_replacement(recovery, seed, pyotp.TOTP(seed).at(103), 103)
		fresh = self.authority.password_verified_session(120)
		self.authority.step_up(fresh, pyotp.TOTP(seed).at(120), "export:alice", 120)

	def test_exclusive_deadlines(self):
		session = self.authority.password_verified_session(60)
		grant = self.authority.step_up(session, pyotp.TOTP(SEED).at(60), "export:alice", 60)
		with self.assertRaises(PermissionError):
			self.authority.perform(session, grant, "export:alice", 120)
		with self.assertRaises(PermissionError):
			self.authority.step_up(session, pyotp.TOTP(SEED).at(660), "export:alice", 660)
		recovery = self.authority.recover(self.authority.fixture_codes[0], 700)
		seed = pyotp.random_base32()
		with self.assertRaises(PermissionError):
			self.authority.enroll_replacement(recovery, seed, pyotp.TOTP(seed).at(1000), 1000)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_example
.venv\Scripts\python -m pip freeze
```

Follow the RFC vector into actual library verification, then trace factor acceptance into a single action-bound grant. Confirm no protected event is inserted for a missing factor, wrong action, consumed proof or expired state. Establish that correct verification still works after rejection and after controlled recovery/re-enrollment. No guessing traffic, phone enrollment or real secret is needed. Injected seconds are synthetic server times; users never choose the production clock.

### Hints

The rate counter commits **before** the verification transaction, so a failed OTP cannot roll back its own admission count. Matching a TOTP and updating `last_step` occur in one write transaction. Recovery increments the epoch and deletes sessions/grants; it returns a separately typed capability with only re-enrollment authority. Confirmation consumes its step so it cannot immediately serve again as step-up proof.

### Solution and Fixed Retest

The supplied implementation is the secure reference for this single-account slice. Expected: **five tests pass**; RFC outputs are `94287082` and `07081804`; only two allowed export events exist in the action-binding test; repeated OTP/proof/recovery and deadline equality reject; three failed admissions block the next correct code in that minute; next-window verification succeeds. Old sessions fail after recovery, replacement requires possession confirmation, and a fresh first-factor session plus the new seed can step up. These are expected results, not author observations. Retest the identical suite after storage/limiter changes.

### Verification, Troubleshooting, and Cleanup

Not executed here. The lab is serial and single-account: no distributed limiter, concurrency measurement, HTTP CSRF, email delivery, encrypted seed custody, durable session service or WebAuthn verification is claimed. A production TOTP fallback must not satisfy an operation explicitly requiring phishing-resistant assurance. The `events` table represents a durable queued action, not an actual data export. Fresh recovery codes would need to be issued through an authenticated post-recovery workflow; none are silently generated here.

If the vector fails, verify algorithm, digits, period and exact public seed rather than widening windows. Later tests intentionally use six digits. Do not change injected times to wall-clock sleeps. SQLite transaction errors usually indicate an unintended outer transaction. Delete the directory/venv/caches; database state and recovery codes are memory-only. WebAuthn acceptance still requires an actual registered test authenticator, correct/incorrect expected context, consumed challenge, required UV and revoked credential checks in a separately authorized integration run. The historical study checklist below is preserved, not certified complete.

- [ ] Local MFA and WebAuthn exercise: Register a test passkey in a local HTTPS/localhost relying party and authenticate with a fresh challenge. Verify replay and wrong-origin attempts fail; document recovery behavior separately.
- [ ] Boundary check: Replay an old synthetic assertion and call a step-up-protected operation without completing the factor. Require server-side rejection in both cases.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[MFA and WebAuthn]]

## References

- [W3C WebAuthn verification algorithms](https://www.w3.org/TR/webauthn-3/)
- [RFC 6238 and test vectors](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 4226 security requirements](https://www.rfc-editor.org/rfc/rfc4226)
- [PyOTP API and application security requirements](https://pyauth.github.io/pyotp/)
- [py_webauthn authentication verification](https://duo-labs.github.io/py_webauthn/authentication.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
