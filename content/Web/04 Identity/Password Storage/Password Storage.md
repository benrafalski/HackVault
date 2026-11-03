---
title: "Password Storage"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[Password Storage Security]]"
updated: 2026-11-03
---
# Password Storage

> [!abstract] TL;DR
> Use library hash/verify APIs; never fast hashes alone or reversible encryption for ordinary password verification. Store algorithm and cost metadata with the hash.

> [!info] Agent scope
> Password hashing; salts; Argon2id and alternatives; work factors; verification; upgrades; reset flows; rate limits.

## Prerequisites

- Python 3.12, byte encodings, database transactions, and [[Web Lab Setup]].
- Passwords in this note are public synthetic fixtures, never usable account credentials.

## Learn

```text
Teach me password storage and verification at expert depth. Assume Python, UTF-8
and database transactions. Explain Argon2id memory/time/parallelism parameters,
salt generation, PHC encodings, constant-time library verification, scrypt,
PBKDF2 and legacy bcrypt tradeoffs. Separate offline resistance from online limits.
Work through a complete Argon2 login and compare-and-swap rehash implementation,
Unicode/length policy, unknown-account timing, corrupted hashes, concurrency,
parameter migration and capacity budgeting. Cover peppers, compromise response,
single-use expiring reset tokens, session revocation and MFA recovery interaction.
Give runnable synthetic tests, exact dependencies/commands, expected results and
operational failure diagnosis, not password-cracking or bypass instructions.
Use RFC 9106, NIST and library/OWASP documentation; distinguish guidance from
measured tuning and never invent benchmarks. Finish with difficult worked questions.
Teach here without editing files or changing study completion.
```

## Cheatsheet

### Stored Representation and Verification Order

```text
$argon2id$v=19$m=65536,t=3,p=4$<encoded-salt>$<encoded-derived-hash>
 algorithm version   KiB     passes lanes
```

The PHC string stores algorithm, version, costs, salt and verifier. It is not encrypted password material. The salt is public and independently random for each record; two hashes of the same password should differ. Do not manually choose a salt when the library already generates one. UTF-8 encoding and any normalization are part of the credential contract: apply the same documented rule at enrollment and verification, never trim, silently truncate or change normalization during migration.

1. Apply cheap input size/type limits and online throttling before expensive hashing. Accept long passwords within a documented byte ceiling; the lab uses 1024 UTF-8 bytes.
2. Load an account hash through parameterized storage access. Use a precomputed dummy hash for an unknown account so that the main expensive operation is still performed. Uniform wording alone does not remove all timing distinctions.
3. Use the library's `verify(stored, candidate)`; mismatch is an expected result, malformed hash is an integrity/operations event. Never compare newly generated salted encodings as strings.
4. On success, check policy/disabled state and required additional factors. Rehash only after successful verification if parameters are obsolete. Update with compare-and-swap so a concurrent password reset is not overwritten.
5. Establish a fresh session only after full authentication succeeds. Authorization remains a separate resource-level decision.

### Algorithm and Work-Factor Decisions

| Choice | Where it fits | Costs and caveats |
|---|---|---|
| Argon2id | Preferred general-purpose memory-hard password KDF | Memory per concurrent hash plus CPU and lanes; benchmark inside actual limits |
| scrypt | Memory-hard alternative when Argon2id unavailable | `N`, `r`, `p` and implementation memory ceilings must be explicit |
| PBKDF2-HMAC-SHA256 | Environments requiring compatible approved primitives | CPU-hard, not memory-hard; use current guidance and measured iteration policy |
| bcrypt | Legacy compatibility/migration | Traditional 72-byte input limit and library-dependent overflow behavior; not a new default |
| Plain SHA-256 or encryption | Not ordinary password storage | Fast hashing lacks work factor; encryption makes recovery possible and concentrates risk in a key |

OWASP gives an Argon2id minimum configuration of 19 MiB, two iterations and one lane; RFC 9106 also describes much larger profiles, including a 64 MiB/three-pass profile. These are policy starting points, not proof of capacity or an immutable universal optimum. The fetched argon2-cffi documentation uses 64 MiB, three passes and four lanes by default. Explicit parameters avoid unreviewed policy changes when defaults evolve.

Approximate resident hashing budget is concurrent verifications times memory per hash, plus process overhead. Eight 64 MiB jobs already require about 512 MiB for their working memory. Bound concurrency and queues, measure p95/p99 latency under load, and apply per-account plus network/global budgets. Do not reduce work factors dynamically under load in a way that changes newly enrolled credentials without review.

### Upgrade, Pepper and Recovery Lifecycle

Keep algorithm/cost metadata with each hash so old and new records can coexist. Successful legacy verification supplies the plaintext transiently for a new hash; inactive accounts require a reset or continued legacy verification until policy retires them. Rehash failures must not erase the old hash. Parameter downgrades require an explicit policy exception, not merely `check_needs_rehash` returning true.

A pepper is a secret stored outside the database, ideally in a managed secret service/HSM. Version it. Loss can lock users out; compromise usually requires password resets because stored password hashes alone cannot be transformed into fresh peppered verifiers. Do not improvise incompatible prehash encodings or concatenate low-entropy secrets.

Reset tokens are high-entropy bearer capabilities, not passwords: generate at least 32 random bytes, store a digest, bind purpose/account and expiry, consume atomically with the password update, then revoke relevant sessions and other reset tokens. Build reset URLs from a configured public origin, not request Host. Send generic responses for known/unknown accounts, prevent referrer/token logging, and do not automatically log in after reset. Resetting a password should not silently disable MFA.

## Gotchas

- Database write access can replace credential records; password hashing does not protect a fully compromised authentication service.
- Salt reuse is not fixed by a pepper. A pepper does not replace rate limiting or MFA.
- Password policy and reset policy are part of the authentication boundary, not just form validation.

## Labs

### Environment and Complete Files

Python 3.12 and argon2-cffi. The version below is visible in the official documentation fetched for this note; installation and execution have not been verified here. Each hash uses 64 MiB, so run this small suite serially. Create both files in an empty disposable directory; it needs no database server or other note.

### File: requirements.txt

```text
argon2-cffi==25.1.0
```

### File: test_passwords.py

```python
import unittest
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError


CURRENT = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
						 hash_len=32, salt_len=16, type=Type.ID)
LEGACY = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4,
						hash_len=32, salt_len=16, type=Type.ID)
PASSWORD = "synthetic violet river lantern 2026"


def acceptable(candidate):
	return isinstance(candidate, str) and 1 <= len(candidate.encode("utf-8")) <= 1024


def verify_and_upgrade(rows, user, candidate, dummy, before_update=lambda: None):
	if not acceptable(candidate):
		return False
	previous = rows.get(user)
	stored = previous if previous is not None else dummy
	try:
		CURRENT.verify(stored, candidate)
	except (VerificationError, InvalidHashError):
		return False
	if previous is None:
		return False
	if CURRENT.check_needs_rehash(previous):
		upgraded = CURRENT.hash(candidate)
		before_update()
		if rows.get(user) != previous:
			return False
		rows[user] = upgraded
	return True


class PasswordTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.dummy = CURRENT.hash("synthetic unknown-account placeholder")

	def test_salts_and_verification(self):
		first, second = CURRENT.hash(PASSWORD), CURRENT.hash(PASSWORD)
		self.assertNotEqual(first, second)
		self.assertTrue(CURRENT.verify(first, PASSWORD))
		self.assertTrue(CURRENT.verify(second, PASSWORD))
		self.assertFalse(verify_and_upgrade({"alice": first}, "alice", "wrong", self.dummy))
		self.assertFalse(verify_and_upgrade({}, "missing", PASSWORD, self.dummy))

	def test_upgrade(self):
		rows = {"alice": LEGACY.hash(PASSWORD)}
		self.assertTrue(CURRENT.check_needs_rehash(rows["alice"]))
		self.assertTrue(verify_and_upgrade(rows, "alice", PASSWORD, self.dummy))
		self.assertFalse(CURRENT.check_needs_rehash(rows["alice"]))
		self.assertTrue(CURRENT.verify(rows["alice"], PASSWORD))

	def test_reset_wins_over_rehash(self):
		rows = {"alice": LEGACY.hash(PASSWORD)}
		reset_hash = CURRENT.hash("synthetic replacement password")
		def reset():
			rows["alice"] = reset_hash
		self.assertFalse(verify_and_upgrade(rows, "alice", PASSWORD, self.dummy, reset))
		self.assertEqual(rows["alice"], reset_hash)

	def test_bounds_and_corrupt_record(self):
		self.assertFalse(acceptable("x" * 1025))
		self.assertFalse(acceptable(None))
		self.assertFalse(verify_and_upgrade({"alice": "corrupt"}, "alice",
											PASSWORD, self.dummy))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_passwords
```

Identify algorithm/cost fields without printing passwords. Verify different salts, wrong-password rejection, upgrade-on-success and the simulated reset/rehash interleaving. The implementation uses real Argon2id; only persistence and the concurrent scheduler are modeled by a dictionary and a hook. In a database, replace the comparison/write with `UPDATE accounts SET password_hash = ? WHERE id = ? AND password_hash = ?` and require one affected row, in a transaction with credential-version checks.

### Hints

Verification recomputes using the parameters stored in the old record. `check_needs_rehash` answers whether the record matches the configured hasher, not whether the password was correct. A reset that wins the race must remain authoritative.

### Solution and Expected Results

The printed code is the reference solution. Expected: four tests pass; salts differ; legacy cost changes from `t=2` to `t=3` after verification; a concurrent replacement is preserved; malformed records and oversize inputs fail closed. No timings are claimed. For a production login, make the final authentication decision contingent on unchanged credential/account version even when no rehash is needed.

### Verification, Troubleshooting, and Cleanup

If the native wheel cannot be installed for your platform, consult argon2-cffi's installation guide rather than substituting a fast hash. Swapping or resource failures indicate insufficient memory/concurrency budget, not evidence that authentication should skip verification. Record the resolved environment with `python -m pip freeze` after validation. Delete the disposable directory, including `.venv` and `__pycache__`. Author execution: not performed.

- [ ] Local Password Storage exercise: Hash the same synthetic password twice and confirm different stored encodings both verify. Increase the configured cost and test upgrade-on-login without logging the password.
- [ ] Boundary check: Verify wrong passwords fail consistently and reset tokens are single-use and expire. Use only synthetic credentials and a small bounded test set.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[Password Storage Security]]

## References

- [argon2-cffi high-level API and example](https://argon2-cffi.readthedocs.io/en/stable/howto.html)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
