---
title: "Python Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Python]]"
updated: 2026-11-03
---
# Python Security

> [!abstract] TL;DR
> eval, untrusted pickle, unsafe YAML loading, shell=True with data, and attacker-controlled import paths can execute unintended code.

> [!info] Agent scope
> Security of: Python runtime; environments and dependencies; modules; exceptions; async; web server interfaces; input and serialization boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- eval, untrusted pickle, unsafe YAML loading, shell=True with data, and attacker-controlled import paths can execute unintended code.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Python backend security on CPython 3.12-3.14. Assume Python,
HTTP and basic SQL. Explain data-to-code boundaries in imports, packaging,
subprocesses, eval, pickle and YAML; distinguish parsing from schema validation.
Cover size/depth limits, strict JSON, path resolution and filesystem races,
secret handling, exception/log disclosure, async cancellation, transactions and
owner-scoped database operations. Give safe fixed implementations and complete
unittest regressions using synthetic identities and literal data only. Explain
why venv and the GIL are not security boundaries. No exploitation, privilege
escalation, evasion or bypass demonstrations. Use primary public sources and
explicit version assumptions. Teach here; do not edit files or claim execution.
```

## Cheatsheet

### Root Causes and Safer APIs

| Boundary | Unsafe design (review only) | Defensible choice |
|---|---|---|
| Object reconstruction | `pickle.loads(request_body)` trusts an executable object format | JSON with byte/shape/type limits; never use pickle for untrusted input. Signing does not make arbitrary third-party pickles safe. |
| Expression evaluation | `eval(user_text)` crosses from data to Python execution | Enumerated operations mapped to fixed functions; no user-supplied code. `literal_eval` still needs resource limits and is not a general untrusted-input sandbox. |
| YAML | General object-capable loader | Maintained library safe loader plus schema, size and nesting limits. The standard library has no YAML loader. |
| Process launch | Concatenated command with `shell=True` | Fixed executable, argument list, `shell=False`, timeout, controlled environment. Validate arguments for the called program, not only shell characters. |
| Dependencies/imports | Unreviewed build scripts, writable import roots, ambiguous package sources | Isolated venv, reviewed pins/hashes, trusted index, read-only deployed code. `python -I` isolates user paths for suitable entry points. |
| Files | Path string prefix check | Resolve against an allowed root and use `Path.is_relative_to` (3.9+), with OS-level safe-open handling if directories can be modified concurrently. Resolution alone has a TOCTOU window. |
| Authorization | `SELECT ... WHERE id=?` for a private object | Add owner/tenant predicate from verified identity and return only public columns. SQL parameter binding prevents structural injection, not ownership mistakes. |

### Cleanup, Transactions and Error Boundaries

The SQLite connection context commits/rolls back but does not close the connection; use `contextlib.closing` or explicit `close`. Starting with Python 3.12, `sqlite3` exposes `autocommit`; older `isolation_level` recipes and defaults differ. Choose behavior explicitly in production and do not assume a transaction protects changes made on another connection.

Authenticate at a framework boundary and pass a typed principal to services. A caller-supplied username is not evidence of identity. Cancellation must unwind database/resource contexts; suppressing `CancelledError` can keep expensive work alive after disconnect. Threads and child processes are not automatically terminated when an awaiting task is cancelled.

For passwords use an established password hashing library, not `hashlib.sha256` alone. Use `secrets` for tokens and `hmac.compare_digest` for appropriate constant-time comparisons. Limit error output and logging before interpolation; never log raw session material. JSON encoding is not HTML escaping, and safe subprocess arguments are not safe file paths automatically.

## Detection and Defense

Track bounded validation-failure counts, unexpected child-process launches, dependency/lockfile drift and authorization denials. Record interpreter/package origins at startup without exposing secrets. Treat audit hooks as observability, not a sandbox against malicious Python already running in-process. Distinguish client mistakes from sustained anomalies before alerting.

## Labs

- [ ] Local Python exercise: Create a virtual environment and a small JSON-processing function with explicit validation and tests for empty, malformed, and oversized input. Confirm dependencies resolve from the intended environment.
- [ ] Boundary check: Pass a harmless shell-metacharacter string through subprocess with an argument list and shell disabled. Verify it stays data and no additional command runs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. CPython 3.12-3.14, standard library only. Create an empty directory, run `py -3.12 -m venv .venv`; all commands below use `.\.venv\Scripts\python.exe` (POSIX `.venv/bin/python`). This exercise validates a synthetic ledger policy and literal argument transport; it runs no shell command constructed from input.

### File: example.py

```python
import json
import sqlite3
import subprocess
import sys


def database():
	connection = sqlite3.connect(":memory:")
	connection.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, owner TEXT, cents INTEGER)")
	connection.execute("INSERT INTO ledger VALUES (1, 'alice', 500)")
	connection.commit()
	return connection


def adjust(connection, principal, record_id, delta):
	if principal not in {"alice", "bob"}:
		return 401
	if type(delta) is not int or not -100 <= delta <= 100:
		return 400
	with connection:
		result = connection.execute(
			"UPDATE ledger SET cents = cents + ? WHERE id = ? AND owner = ? AND cents + ? >= 0",
			(delta, record_id, principal, delta))
		return 200 if result.rowcount == 1 else 404


def echo_literal(value):
	if type(value) is not str or len(value) > 80:
		raise ValueError("invalid marker")
	result = subprocess.run(
		[sys.executable, "-I", "-c", "import json,sys; print(json.dumps(sys.argv[1]))", value],
		shell=False, check=True, capture_output=True, text=True, timeout=5)
	return json.loads(result.stdout)


if __name__ == "__main__":
	connection = database()
	try:
		print(adjust(connection, "alice", 1, 25))
		print(connection.execute("SELECT cents FROM ledger WHERE id=1").fetchone()[0])
		print(echo_literal("synthetic ; & marker"))
	finally:
		connection.close()
```

### File: test_example.py

```python
import unittest
from example import adjust, database, echo_literal


class BoundaryTests(unittest.TestCase):
	def setUp(self):
		self.connection = database()
		self.addCleanup(self.connection.close)

	def test_policy_and_atomic_write(self):
		self.assertEqual(adjust(self.connection, None, 1, 25), 401)
		self.assertEqual(adjust(self.connection, "bob", 1, 25), 404)
		self.assertEqual(adjust(self.connection, "alice", 1, True), 400)
		self.assertEqual(self.connection.execute("SELECT cents FROM ledger").fetchone()[0], 500)
		self.assertEqual(adjust(self.connection, "alice", 1, 25), 200)
		self.assertEqual(self.connection.execute("SELECT cents FROM ledger").fetchone()[0], 525)

	def test_literal_transport(self):
		marker = "synthetic ; & marker"
		self.assertEqual(echo_literal(marker), marker)
		with self.assertRaises(ValueError):
			echo_literal("x" * 81)


if __name__ == "__main__":
	unittest.main()
```

### Objectives, Baseline and Hints

Run `.\.venv\Scripts\python.exe example.py`, then `.\.venv\Scripts\python.exe -m unittest -v`. Baseline is a 500-cent Alice record. Verify denied/invalid calls leave 500 unchanged and the permitted adjustment produces 525. The marker contains punctuation but no additional command; it must round-trip exactly as data. Hint: the owner predicate belongs in the UPDATE, and Python's bool/int relationship requires an exact type check.

### Solution and Fixed Retest

The complete solution couples policy and mutation in one parameterized statement, bounds the adjustment and fixes the child executable/code. Expected program lines: `200`, `525`, `synthetic ; & marker`; expected suite: two passing tests. Re-run unchanged after replacing the persistence or process adapter. The test's principal is supplied by trusted test code, not a production authentication mechanism. No vulnerable executable variant is needed for these negative regressions.

### Troubleshooting and Reset

A subprocess timeout may indicate endpoint protection or interpreter startup constraints; do not disable corporate controls. Confirm `sys.executable` points to the chosen interpreter. SQLite in-memory state is per connection, so another connection does not see these rows. Every run reseeds; no files or child processes remain after normal completion. Delete only the disposable directory/venv to clean up. Multi-connection contention and framework authentication are not measured by this unit lab.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Python]]

## References

- [Security considerations](https://docs.python.org/3/library/security_warnings.html)
- [subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [sqlite3 transactions](https://docs.python.org/3/library/sqlite3.html#transaction-control)
- [pickle warning](https://docs.python.org/3/library/pickle.html)
