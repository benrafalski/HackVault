---
title: "Password Storage Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[Password Storage]]"
updated: 2026-11-03
---
# Password Storage Security

> [!abstract] TL;DR
> Fast or unsalted hashes, exposed reset tokens, weak recovery, and unlimited online attempts can defeat otherwise correct authentication.

> [!info] Agent scope
> Security of: Password hashing; salts; Argon2id and alternatives; work factors; verification; upgrades; reset flows; rate limits. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Credential enrollment, hash storage, verification workers, reset delivery, account lookup, MFA recovery and session revocation form one lifecycle. Strong hashing only addresses offline guessing cost; it does not make online verification unlimited or recovery trustworthy.

## Learn

```text
Teach defensive password-storage and recovery engineering at expert depth. Cover
Argon2id costs, salts, pepper custody, legacy upgrades, malformed hash handling,
credential-version races, constant-time library verification and bounded input.
Explain why online throttling, unknown-user handling, recovery and session revocation
remain necessary. Trace a single-use reset from generation through delivery, digest
storage, exact expiry, atomic consumption, password replacement and session epoch.
Provide a complete local synthetic SQLite regression lab with positive controls,
reused/expired token rejection and bounded attempts; no cracking, theft or bypass
walkthroughs. Explain reset-request flooding, denial-of-service tradeoffs and logs
without secrets. Cite primary standards/library docs, distinguish measured from
unverified claims and finish with worked design questions. Teach here; no file edits
or study-status changes, and no fabricated execution results.
```

## Cheatsheet

### Failure Mechanisms and Hardening

| Boundary | Unsafe assumption | Fixed policy and evidence |
|---|---|---|
| Stored hash | A salt makes a fast hash expensive | Use a password KDF; inspect algorithm/cost metadata, benchmark deployment capacity |
| Verification | Matching credentials are enough | Check disabled state, credential epoch and MFA before creating a session |
| Rehash | Last writer wins is harmless | Compare-and-swap; concurrent reset wins; restart authentication if version changes |
| Online attempts | Expensive KDF is a rate limiter | Enforce cheap account/network/global budgets before hashing and bound worker concurrency |
| Reset | A random-looking token can be reused until expiry | Store digest, purpose, account and deadline; consume once in same transaction as change |
| Recovery | Password reset also proves a second factor | Keep MFA recovery a separately protected workflow with notifications and audit |
| Error handling | Different public messages help users debug | Generic account/login/reset responses; differentiated internal event codes |

Argon2id costs must be bounded by application policy for enrolled records. A malformed or unexpectedly costly database record is an operations/security incident; do not let an arbitrary user-provided PHC string drive expensive work. Passwords are secrets even on failed login: redact before access/error tracing and avoid persistent debug dumps.

### Reset Protocol and Verification Order

1. Accept a normalized account identifier under a documented identity policy. Rate-limit request and delivery independently; return the same public response whether the account exists.
2. Generate `secrets.token_urlsafe(32)`; store SHA-256 of the token, account, purpose, expiry and use state. Hashing is appropriate here because the token has high entropy, unlike a human password.
3. Deliver only through the established recovery channel. Construct the URL from a fixed public base; use HTTPS, `Referrer-Policy: no-referrer`, no third-party page resources and no token-bearing analytics.
4. GET displays a form but must not consume the token: mail scanners may prefetch links. The actual change is a CSRF-protected POST. Validate new-password policy and compute its hash under a bounded resource budget.
5. In one transaction check token purpose, digest, account and `now < expires`; consume it; replace the hash; increment credential/session epoch; revoke other reset capabilities. Roll back all changes on failure.
6. Notify the user, require a fresh normal login and preserve MFA requirements. Do not include passwords or reset tokens in notifications.

```http
POST /password-reset/complete HTTP/1.1
Host: app.example.test
Content-Type: application/json
Cache-Control: no-store

{"token":"<synthetic-capability>","new_password":"<synthetic-new-password>"}
```

This wire shape is illustrative, not a supplied server. An invalid, expired or reused token receives the same generic failure class; successful change invalidates sessions according to policy. For multiple concurrent reset requests, explicitly decide whether issuing a new token invalidates old ones; account-wide invalidation on successful reset is mandatory in the lab policy.

### Limits and Tradeoffs

An indefinite account lockout lets unauthenticated traffic deny service; short cooldowns, exponential delays, risk signals and recovery are preferable to an unbounded hard lock. IP-only limits penalize shared networks and miss distributed traffic. Unknown accounts need a comparable KDF path but also consume the global budget. Pepper rotation is not merely key replacement: active users can be migrated after verification, while inactive users may need reset. Keep old pepper versions only for a bounded migration period.

## Detection and Defense

Measure rejection rates, hashing queue depth, latency, reset delivery volume, password-change events and revoked session counts. Correlate by pseudonymous account/request IDs, never raw passwords, hashes or reset tokens. Alert on corrupt verifier records and unexpected work-factor changes. A successful reset followed by login from a new environment merits risk evaluation, not automatic proof of compromise. Backup restoration must not accidentally restore old valid reset capabilities or session epochs.

## Labs

### Environment and Complete Files

Python 3.12; Argon2 package version is documentation-verified, not locally installed/tested. This lab uses real hashing and SQLite transactions, synthetic users, no mail and no HTTP. The reset token is returned directly to the test to stand in for delivery; this is not a production delivery mechanism. The login limiter is a bounded single-process fixture, not a distributed limiter.

### File: requirements.txt

```text
argon2-cffi==25.1.0
```

### File: test_password_security.py

```python
import hashlib
import secrets
import sqlite3
import unittest
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError


HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID)
OLD = "synthetic old password with several words"
NEW = "synthetic replacement with different words"


class Accounts:
	def __init__(self):
		self.db = sqlite3.connect(":memory:")
		self.db.executescript("""
			CREATE TABLE accounts (id TEXT PRIMARY KEY, hash TEXT, epoch INTEGER);
			CREATE TABLE resets (digest TEXT PRIMARY KEY, account TEXT, expires INTEGER);
		""")
		with self.db:
			self.db.execute("INSERT INTO accounts VALUES ('alice', ?, 0)",
							(HASHER.hash(OLD),))
		self.dummy = HASHER.hash("synthetic unused account placeholder")
		self.attempts = {}

	def login(self, account, candidate, now):
		bucket = (account, now // 60)
		count = self.attempts.get(bucket, 0)
		if count >= 3:
			return False
		self.attempts[bucket] = count + 1
		if not isinstance(candidate, str) or not 1 <= len(candidate.encode()) <= 1024:
			return False
		row = self.db.execute("SELECT hash FROM accounts WHERE id = ?", (account,)).fetchone()
		try:
			HASHER.verify(row[0] if row else self.dummy, candidate)
		except (VerificationError, InvalidHashError):
			return False
		return row is not None

	def issue_reset(self, now):
		token = secrets.token_urlsafe(32)
		digest = hashlib.sha256(token.encode("ascii")).hexdigest()
		with self.db:
			self.db.execute("INSERT INTO resets VALUES (?, 'alice', ?)", (digest, now + 600))
		return token

	def reset(self, token, password, now):
		if not isinstance(password, str) or not 15 <= len(password) or len(password.encode()) > 1024:
			raise ValueError("password policy")
		digest = hashlib.sha256(token.encode("ascii")).hexdigest()
		replacement = HASHER.hash(password)
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			row = self.db.execute(
				"SELECT account FROM resets WHERE digest = ? AND expires > ?",
				(digest, now)).fetchone()
			if row is None:
				raise PermissionError("reset rejected")
			self.db.execute("UPDATE accounts SET hash = ?, epoch = epoch + 1 WHERE id = ?",
							(replacement, row[0]))
			self.db.execute("DELETE FROM resets WHERE account = ?", (row[0],))


class RecoveryTests(unittest.TestCase):
	def setUp(self):
		self.accounts = Accounts()
		self.addCleanup(self.accounts.db.close)

	def test_single_use_and_account_epoch(self):
		first = self.accounts.issue_reset(100)
		other = self.accounts.issue_reset(101)
		self.accounts.reset(first, NEW, 102)
		for token in (first, other):
			with self.assertRaises(PermissionError):
				self.accounts.reset(token, OLD, 103)
		self.assertEqual(self.accounts.db.execute(
			"SELECT epoch FROM accounts WHERE id = 'alice'").fetchone()[0], 1)
		self.assertFalse(self.accounts.login("alice", OLD, 120))
		self.assertTrue(self.accounts.login("alice", NEW, 120))

	def test_exact_expiry_and_rate_limit(self):
		token = self.accounts.issue_reset(100)
		with self.assertRaises(PermissionError):
			self.accounts.reset(token, NEW, 700)
		for unused in range(3):
			self.assertFalse(self.accounts.login("alice", "wrong", 10))
		self.assertFalse(self.accounts.login("alice", OLD, 10))
		self.assertTrue(self.accounts.login("alice", OLD, 60))
		self.assertFalse(self.accounts.login("unknown", OLD, 60))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_password_security
```

Establish that the old password works in the fresh account, then follow the provided reset tests. Inspect the transaction: deletion of all reset tokens and the epoch increment must commit together. The schema contains only password hashes and reset digests, not plaintext credentials. No actual session service is included; its required contract is to compare the stored current epoch on each use.

### Hints

Expiry is exclusive. A new valid password must not make an already consumed token valid again. A per-minute window is intentionally simple and permits bursts around boundaries; production should use a tested rolling/token-bucket design and bounded counter storage.

### Solution and Fixed Retest

Expected: two tests pass, both outstanding reset tokens fail after one succeeds, epoch becomes one, the old password fails and the new one succeeds. The exact-expiry reset fails; a correct login is throttled after three attempts and succeeds in the next window. This demonstrates availability tradeoffs without running guessing traffic. The reference fix is atomic consumption/replacement plus bounded admission, not merely a longer token. Rerun the same tests after changing the schema or reset handler.

### Verification, Troubleshooting, and Cleanup

Not executed here. The reset function hashes before the authoritative transaction to keep the transaction short; a production endpoint must add cheap token-shape checks, an optional preliminary lookup and rate/concurrency limits before that work, while still rechecking under lock. This suite does not test email delivery, CSRF, parallel connections, account-disable races or actual session revocation. Delete the disposable directory, `.venv` and caches; the database exists only in memory.

- [ ] Local Password Storage exercise: Hash the same synthetic password twice and confirm different stored encodings both verify. Increase the configured cost and test upgrade-on-login without logging the password.
- [ ] Boundary check: Verify wrong passwords fail consistently and reset tokens are single-use and expire. Use only synthetic credentials and a small bounded test set.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[Password Storage]]

## References

- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [argon2-cffi API](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
