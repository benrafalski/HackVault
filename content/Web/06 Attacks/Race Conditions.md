---
title: "Race Conditions"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Race Conditions

> [!abstract] TL;DR
> A race condition occurs when concurrent operations observe or mutate shared state in an ordering that violates an intended invariant.

> [!info] Agent scope
> TOCTOU; concurrent state transitions; transaction isolation; lab synchronization; atomic updates; idempotency.

## Learn

```text
Teach race conditions as failures of atomicity and ordering across shared state.
Assume threads, transactions, locks, and database isolation. Explain TOCTOU,
lost updates, write skew, duplicate effects, optimistic versions, unique
constraints, compare-and-swap updates, and idempotency. Distinguish process locks
from database coordination and distributed leases/fencing. Analyze isolation
guarantees in SQLite versus a multi-writer server database; discuss retries,
deadlocks, rollback, and external effects. Review a secure one-unit reservation
with two bounded local workers, a barrier, separate connections, and durable
effect records. Explain why finite tests do not prove all schedules. Cite primary
docs and give review questions with answers. No live request bursts, unsafe
baseline, bypasses, theft, scanning, or chains; do not author files or invent passes.
```

## Cheatsheet

> [!important] Defensive scope
> The lab tests only an atomic secure implementation using two local database workers. It creates no HTTP traffic, vulnerable race demonstration, or load test.

### Root Cause and Invariants

TOCTOU separates a decision from the action that relies on it. If relevant state changes between them, the action can violate the decision's assumptions. Lost updates, duplicate redemptions, and partially visible workflows are different concurrency failures. Meaningful evidence is the final invariant and committed effect count, not close timestamps or response latency alone.

| Mechanism | Suitable invariant | Limitation |
|---|---|---|
| Conditional update | A single row changes only if current state permits | Multi-row predicates may need stronger isolation |
| Unique constraint | One durable record per logical key | Choosing the correct key and handling conflicts still matter |
| Optimistic version | Write only if version has not changed | Retry must re-evaluate business assumptions |
| Row/range locks | Serialize conflicting transactions | Deadlocks and lock scope depend on database/indexing |
| Serializable isolation | Equivalent committed serial execution | Applications must handle serialization failures/retry |
| Idempotency record | Same intent returns the same committed outcome | Not a substitute for capacity/authorization constraints |

A transaction does not automatically make every read-then-write serializable. Snapshot isolation may still allow write skew across multiple rows. An in-process lock coordinates only participants sharing that lock; multiple workers/hosts may ignore it. A distributed lease may expire while work continues; fencing tokens can help a resource reject stale owners, but only if the resource enforces them.

### Worked Atomic Transition

The fixture uses `UPDATE inventory SET remaining = remaining - 1 WHERE remaining > 0` inside the same transaction as the idempotency/effect record. `BEGIN IMMEDIATE` acquires SQLite's write reservation before checking replay state. The effect record and decrement commit together, so a failed insert or exception rolls back the decrement. A retry of the winning key is reported as replay, not a second reservation.

SQLite permits one writer at a time; it does not emulate PostgreSQL/MySQL row-level lock behavior. The Python 3.12 fixture uses explicit transaction initiation and a five-second busy timeout. Each worker owns a separate connection; `check_same_thread=False` is unnecessary. The barrier synchronizes entry, not an unsafe internal window. No arbitrary sleeps are needed.

### Evidence and Tradeoffs

Record transaction/key IDs, affected-row count, conflict/retry category, final stock, and number of committed effects. Avoid logging customer data. A bounded test passing is regression evidence, not proof over every schedule, crash, or database engine. External effects need an outbox/idempotent receiver; committing a database row cannot roll back an already sent external action.

## Defense

Place the invariant in a database constraint or atomic transition when possible. Choose isolation for the whole predicate, not a single endpoint. Define bounded retries for known transient conflicts and never blindly retry non-idempotent external effects. Monitor duplicate logical effects and failed transitions; correctness must survive process restarts and multiple instances.

## Labs

### Environment and Objectives

Python 3.12 stdlib including SQLite and threads; one file, local temporary database, no network/packages. Review a proposed separate check/decrement sequence without running it. The secure replacement must permit one committed reservation, reject the other, and return a replay for the winner's repeated key.

### File: test_example.py

```python
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import sqlite3
import unittest


def initialize(path):
	with closing(sqlite3.connect(path)) as database, database:
		database.execute("CREATE TABLE inventory (id INTEGER PRIMARY KEY, "
						 "remaining INTEGER NOT NULL CHECK (remaining >= 0))")
		database.execute("CREATE TABLE effects (intent TEXT PRIMARY KEY)")
		database.execute("INSERT INTO inventory VALUES (1, 1)")


def reserve(path, intent, barrier=None):
	if barrier is not None:
		barrier.wait(timeout=5)
	with closing(sqlite3.connect(path, timeout=5)) as database, database:
		database.execute("BEGIN IMMEDIATE")
		if database.execute("SELECT 1 FROM effects WHERE intent = ?", (intent,)).fetchone():
			return "replay"
		changed = database.execute(
			"UPDATE inventory SET remaining = remaining - 1 "
			"WHERE id = 1 AND remaining > 0"
		).rowcount
		if changed != 1:
			return "unavailable"
		database.execute("INSERT INTO effects VALUES (?)", (intent,))
		return "created"


class AtomicityTests(unittest.TestCase):
	def test_two_workers_one_effect_and_replay(self):
		with TemporaryDirectory() as directory:
			path = str(Path(directory) / "fixture.db")
			initialize(path)
			barrier = Barrier(2)
			with ThreadPoolExecutor(max_workers=2) as workers:
				pending = {key: workers.submit(reserve, path, key, barrier)
						   for key in ["intent-a", "intent-b"]}
				results = {key: future.result(timeout=10) for key, future in pending.items()}
			self.assertEqual(sorted(results.values()), ["created", "unavailable"])
			winner = next(key for key, result in results.items() if result == "created")
			self.assertEqual(reserve(path, winner), "replay")
			with closing(sqlite3.connect(path)) as database:
				self.assertEqual(database.execute("SELECT remaining FROM inventory").fetchone()[0], 0)
				self.assertEqual(database.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)

	def test_rollback_restores_capacity(self):
		with TemporaryDirectory() as directory:
			path = str(Path(directory) / "fixture.db")
			initialize(path)
			with closing(sqlite3.connect(path)) as database:
				with self.assertRaises(RuntimeError):
					with database:
						database.execute("UPDATE inventory SET remaining = 0 WHERE id = 1")
						raise RuntimeError("synthetic failure before commit")
				self.assertEqual(database.execute("SELECT remaining FROM inventory").fetchone()[0], 1)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: what happens if the effect insert fails after the decrement? Why is the replay lookup inside the write transaction?

Solution: write coordination and the conditional update serialize the inventory change; the effect record commits with it. Expected: two tests pass, exactly one worker creates an effect, winner identity is nondeterministic, replay leaves one effect, and rollback restores capacity. There is no unsafe baseline, and no claim that repeated execution proves every schedule.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Use a normal local temporary filesystem, not a network share. A barrier timeout means a worker did not arrive; a database lock timeout is a test/environment failure, not expected success. Do not remove timeouts or increase worker count to turn this into a stress test. Connections close before temporary cleanup. Remove the disposable exercise directory afterward. Cross-database isolation, crash recovery, and external effects remain unverified.

- [ ] Local Race Conditions exercise: Review the atomic invariant and effect transaction.
- [ ] Boundary check: Run bounded secure concurrency, replay, and rollback tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [SQLite isolation](https://www.sqlite.org/isolation.html)
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html)
- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
- [Python sqlite3 transaction control](https://docs.python.org/3.12/library/sqlite3.html#transaction-control)
