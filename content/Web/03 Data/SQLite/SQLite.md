---
title: "SQLite"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[SQLite Security]]"
updated: 2026-11-03
---
# SQLite

> [!abstract] TL;DR
> Use bound parameters and explicit transactions. Protect the database, WAL/journal, and backup files together; disable unnecessary extension loading.

> [!info] Agent scope
> Embedded database model; files and locking; SQL; transactions; parameter binding; extensions; application file permissions.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me SQLite as an embedded web-application database, assuming SQL and Python.
Explain pager/files, rollback journals versus WAL, one-writer concurrency, busy
timeouts, checkpoints, BEGIN modes, snapshots, constraints and parameter binding.
Use Python 3.12+ sqlite3 with explicit transaction ownership; distinguish Python
version from linked SQLite version and autocommit API changes. Cover backup API,
STRICT tables, foreign-key enabling, extensions, URI modes and OS file permissions.
Provide complete stdlib-only tests for rollback, literal values and a competing
writer. Discuss network filesystems and scaling boundaries. Use SQLite/Python
primary sources, worked failures and review questions. Teach without editing
files or claiming execution; no confidential or offensive fixtures.
```

## Cheatsheet

### Embedded Engine and Files

SQLite executes inside the caller process; it has no daemon, authenticated database users or GRANT statements. Whoever can read the database file may read its contents with another program. Protect the containing directory, main database, `-wal`, `-shm`, rollback journals and backups together. File encryption is not a default SQLite feature.

Rollback journaling saves original pages before modification. WAL appends committed changes and lets readers retain older snapshots while one writer proceeds. WAL does not provide multiple simultaneous writers. Long readers can delay checkpoints and grow WAL; an aggressive checkpoint can increase latency. Do not copy only the main file during an active WAL workload: use the backup API or an appropriately coordinated snapshot.

### SQL and Transaction Choices

```sql
PRAGMA foreign_keys=ON;
CREATE TABLE account(id INTEGER PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance>=0));
BEGIN IMMEDIATE;
UPDATE account SET balance=balance-5 WHERE id=1 AND balance>=5;
COMMIT;
```

Require exactly one changed row before accepting the debit. `BEGIN DEFERRED` postpones acquisition of the writer lock; upgrading an old read snapshot can fail. `BEGIN IMMEDIATE` acquires the write transaction early, reducing surprise at the cost of blocking competing writers sooner. A busy timeout waits for some lock conflicts, not every stale-snapshot condition; retry the whole idempotent transaction, not just its last statement.

SQLite type affinity is not rigid typing. `STRICT` tables require SQLite 3.37+ and support a restricted type vocabulary; use `INTEGER` smallest units rather than assuming a DECIMAL declaration enforces exact currency semantics. CHECK with NULL may pass unless NOT NULL is also present. Enable `PRAGMA foreign_keys=ON` for every connection, outside an active transaction. Index referencing foreign-key columns when access/deletion patterns need them.

### Python Binding and Lifecycle

```python
import sqlite3

connection = sqlite3.connect(":memory:", isolation_level=None)
try:
	connection.execute("CREATE TABLE note(id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
	connection.execute("BEGIN")
	connection.execute("INSERT INTO note(label) VALUES (?)", ("O'Reilly",))
	connection.execute("ROLLBACK")
finally:
	connection.close()
```

`?` and named parameters bind values, never identifiers. Pass a one-item tuple with its trailing comma. `executescript()` accepts a SQL script, not parameter bindings, and has transaction behavior different from repeated `execute()` under legacy transaction control. Use it only for static trusted schema scripts.

Python 3.12 introduced `autocommit`; the examples deliberately use `isolation_level=None` with explicit SQL and the legacy default transaction-control mode. Do not add `autocommit=False` without revisiting BEGIN/COMMIT ownership. A connection context manager manages transactions, not connection closure. Do not share connections across threads casually; removing `check_same_thread` does not design concurrency for you.

### Deployment Decisions

Use local storage with correct locking; WAL relies on same-host shared memory and is unsuitable for ordinary network-filesystem deployment. Keep extension loading disabled; builds differ in whether it is available. `mode=ro` prevents writes through that connection, not other processes; `immutable=1` assumes the file cannot change and is unsafe when it can. Inspect `sqlite3.sqlite_version`, not only `python --version`.

## Gotchas

Deleting a row does not guarantee immediate removal of all recoverable bytes from every database artifact or backup.

## Labs

### Environment and Complete Files

Python 3.12+ with stdlib `sqlite3`, linked SQLite 3.37+ for STRICT. No packages, network or service. **Printed tests have not been executed during authoring.** Save the complete file in an empty directory; all databases live in a temporary directory removed after the run.

### File: test_example.py

```python
import pathlib
import sqlite3
import tempfile
import unittest


class SQLiteMechanisms(unittest.TestCase):
	def test_transactions_and_writer_lock(self):
		self.assertGreaterEqual(sqlite3.sqlite_version_info, (3, 37, 0))
		with tempfile.TemporaryDirectory() as directory:
			path = pathlib.Path(directory) / "lab.db"
			first = sqlite3.connect(path, isolation_level=None, timeout=0.05)
			second = sqlite3.connect(path, isolation_level=None, timeout=0.05)
			backup = sqlite3.connect(":memory:")
			try:
				self.assertEqual(first.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
				first.execute("PRAGMA foreign_keys=ON")
				second.execute("PRAGMA foreign_keys=ON")
				first.execute("CREATE TABLE note(id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE) STRICT")
				first.execute("INSERT INTO note VALUES (?, ?)", (1, "seed"))
				first.execute("BEGIN IMMEDIATE")
				first.execute("INSERT INTO note VALUES (?, ?)", (2, "O'Reilly"))
				self.assertEqual(first.execute("SELECT label FROM note WHERE id=?", (2,)).fetchone()[0], "O'Reilly")
				self.assertEqual(second.execute("SELECT count(*) FROM note").fetchone()[0], 1)
				with self.assertRaises(sqlite3.OperationalError) as failure:
					second.execute("BEGIN IMMEDIATE")
				self.assertEqual(failure.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
				first.execute("ROLLBACK")
				second.execute("BEGIN IMMEDIATE")
				second.execute("INSERT INTO note VALUES (?, ?)", (3, "committed"))
				second.execute("COMMIT")
				self.assertEqual(first.execute("SELECT id FROM note ORDER BY id").fetchall(), [(1,), (3,)])
				with self.assertRaises(sqlite3.IntegrityError):
					first.execute("INSERT INTO note VALUES (?, ?)", (4, "seed"))
				first.backup(backup)
				self.assertEqual(backup.execute("SELECT count(*) FROM note").fetchone()[0], 2)
				print("SQLite", sqlite3.sqlite_version, "backup rows=2")
			finally:
				backup.close()
				second.close()
				first.close()


if __name__ == "__main__":
	unittest.main()
```

```powershell
python --version
python test_example.py -v
```

### Objectives and Hints

Predict visibility before rollback, explain why a WAL reader succeeds while another writer fails, and explain why the backup contains the committed row but not the rolled-back row. Hint: the two connections are independent even though this deterministic test schedules them on one thread.

### Solution and Expected Results

One test passes. The second connection sees only the committed seed while the first holds its write transaction; its competing BEGIN raises SQLITE_BUSY. After rollback, the second writer commits id `3`. Final IDs are `1,3`, and the backup contains two rows. A failed unique insertion does not add a third row.

### Troubleshooting and Cleanup

Unsupported STRICT syntax indicates an old linked engine. A failure to enter WAL suggests filesystem/build constraints. `SQLITE_LOCKED` is not interchangeable with SQLITE_BUSY and merits a separate diagnosis. Temporary files are cleaned automatically after connections close; no host ACLs change. OS-identity separation is outside this stdlib test: inspect the service account's actual directory/file ACLs separately before deployment, and keep the original boundary-study checkbox incomplete until that check is performed.

- [ ] Local SQLite exercise: Create a temporary database, perform a transaction with rollback, and query a quote-containing value using parameters. Inspect file permissions and test a second writer's behavior.
- [ ] Boundary check: Run the app under a restricted local identity and verify it cannot open an unrelated database file. Confirm malformed values remain data in a prepared query.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[SQLite Security]]

## References

- [WAL](https://www.sqlite.org/wal.html)
- [Transactions](https://www.sqlite.org/lang_transaction.html)
- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html)
- [Online backup](https://www.sqlite.org/backup.html)
