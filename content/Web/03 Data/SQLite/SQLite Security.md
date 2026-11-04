---
title: "SQLite Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[SQLite]]"
updated: 2026-11-03
---
# SQLite Security

> [!abstract] TL;DR
> Unsafe SQL or readable database artifacts can expose application data even when no network database listener exists.

> [!info] Agent scope
> Security of: Embedded database model; files and locking; SQL; transactions; parameter binding; extensions; application file permissions. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsafe SQL or readable database artifacts can expose application data even when no network database listener exists.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me SQLite defensive security assuming Python and SQL. Trace untrusted
values, application SQL, embedded engine, extension/native code and OS files as
separate trust boundaries. Cover parameter binding, fixed query shapes, authorizer
callbacks, progress budgets, setlimit, trusted_schema, URI read-only connections,
WAL/backups and service-account ACLs. Explain why these are not server GRANTs or
a sandbox against arbitrary Python execution. Provide stdlib-only synthetic
baseline/fix/regression tests with positive reads and denied writes/attachments.
Use harmless fixtures, public SQLite/Python references and exact version caveats;
no injection exploitation or file theft. Teach here without edits or invented runs.
```

## Cheatsheet

### Boundaries and Safe Construction

SQLite has no authenticated database role system. Parameter binding protects grammar, while application code supplies row authorization. A connection authorizer can deny operations for that connection; a process with filesystem access can open another connection without it. Neither `PRAGMA query_only=ON` nor a URI `mode=ro` is an OS permission boundary.

```python
def find_note(connection, tenant_id, label):
	if not isinstance(label, str) or len(label) > 80:
		raise ValueError("label must be at most 80 characters")
	return connection.execute(
		"SELECT id FROM note WHERE tenant_id=? AND label=? LIMIT 20",
		(tenant_id, label),
	).fetchall()
```

Fragment prerequisite: `note(id,tenant_id,label)` and a trusted authenticated `tenant_id`. Do not concatenate label values, accept arbitrary sort expressions, or send untrusted strings to `executescript`. Bound `LIKE` patterns still interpret `%` and `_`; literal substring semantics require explicit escaping and `ESCAPE` handling.

### File and Engine Hardening

| Surface | Defense and limitation |
|---|---|
| Main DB, WAL, SHM, journals | Dedicated service directory with inherited ACLs restricted to that service and operators; directory creation rights matter as much as the main file. |
| Backups | Use backup API; encrypt/protect copies independently. Row deletion and VACUUM do not erase all backups or storage snapshots. |
| Native extensions | Do not enable loading. Availability varies by SQLite build; application-defined functions are also code capabilities. |
| Untrusted schema | `PRAGMA trusted_schema=OFF` reduces schema-triggered use of unsafe functions; version/build behavior must be checked. |
| SQL resource use | Set SQL/value/variable limits, progress callbacks and outer request deadlines; no single setting caps every allocation or native function. |
| Attachments | Deny ATTACH through an authorizer and use fixed database paths; do not trust a user-controlled URI. |

Python 3.11+ exposes `Connection.setlimit`; 3.12+ also exposes some `setconfig` functionality depending on linked SQLite. Do not assume a constant/API exists merely because the Python executable is new. A progress handler interrupts VM work but is not a hard wall-clock limit around arbitrary Python callbacks. Prepared-statement caching affects when authorization runs; configure policy before preparing statements and avoid live policy mutation on shared connections.

For deployment, inspect actual service identities and inherited ACLs (`Get-Acl -LiteralPath <dedicated-directory>` on Windows). A file marked read-only is not equivalent to denying access to another identity. Do not grant broad directory traversal/read permissions merely to solve a startup error. The lab below does not modify or validate host ACLs.

## Detection and Defense

Log denied operation categories, bounded-query failures and unexpected schema migrations, not raw user values. Audit file access/backup jobs through OS controls. Trace callbacks can expose parameters and should not be enabled indiscriminately in production. A SQLITE_BUSY spike is usually contention; distinguish it from deliberate budget exhaustion or repeated policy denial.

## Labs

### Environment and Complete Files

Python 3.12+ with SQLite 3.37+; stdlib only. All synthetic files are temporary. **Not executed during authoring.** Baseline shows a writable connection violates a report-only policy; fixed tests install restrictions before any app query. No arbitrary SQL input endpoint is supplied.

### File: test_example.py

```python
import pathlib
import sqlite3
import tempfile
import unittest


def report_authorizer(action, first, second, database, source):
	allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
	return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


class SQLitePolicy(unittest.TestCase):
	def test_baseline_and_fixed_policy(self):
		with tempfile.TemporaryDirectory() as directory:
			path = pathlib.Path(directory) / "fixture.db"
			admin = sqlite3.connect(path, isolation_level=None)
			try:
				admin.execute("CREATE TABLE note(id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
				admin.execute("INSERT INTO note VALUES (?, ?)", (1, "O'Reilly"))
				admin.execute("BEGIN")
				admin.execute("UPDATE note SET label=? WHERE id=?", ("temporary", 1))
				self.assertEqual(admin.execute("SELECT label FROM note").fetchone()[0], "temporary")
				admin.execute("ROLLBACK")
			finally:
				admin.close()
			report = sqlite3.connect(path, isolation_level=None, cached_statements=0)
			try:
				report.execute("PRAGMA trusted_schema=OFF")
				report.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
				report.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
				report.set_authorizer(report_authorizer)
				self.assertEqual(report.execute("SELECT id FROM note WHERE label=?", ("O'Reilly",)).fetchall(), [(1,)])
				for statement in (
					"UPDATE note SET label='temporary' WHERE id=1",
					"ATTACH DATABASE ':memory:' AS extra",
				):
					with self.assertRaises(sqlite3.DatabaseError) as denied:
						report.execute(statement)
					self.assertEqual(denied.exception.sqlite_errorcode, sqlite3.SQLITE_AUTH)
				self.assertEqual(report.execute("SELECT label FROM note").fetchone()[0], "O'Reilly")
			finally:
				report.close()
			readonly = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
			try:
				with self.assertRaises(sqlite3.OperationalError) as denied:
					readonly.execute("UPDATE note SET label='temporary'")
				self.assertEqual(denied.exception.sqlite_errorcode, sqlite3.SQLITE_READONLY)
			finally:
				readonly.close()

	def test_work_budget(self):
		connection = sqlite3.connect(":memory:")
		try:
			connection.set_progress_handler(lambda: 1, 100)
			with self.assertRaises(sqlite3.OperationalError) as stopped:
				connection.execute(
					"WITH RECURSIVE numbers(value) AS (VALUES(1) UNION ALL "
					"SELECT value+1 FROM numbers WHERE value<10000) SELECT sum(value) FROM numbers"
				).fetchone()
			self.assertEqual(stopped.exception.sqlite_errorcode, sqlite3.SQLITE_INTERRUPT)
			connection.set_progress_handler(None, 0)
			self.assertEqual(connection.execute("SELECT 1").fetchone(), (1,))
		finally:
			connection.close()


if __name__ == "__main__":
	print("SQLite", sqlite3.sqlite_version)
	unittest.main()
```

```powershell
python --version
python test_example.py -v
```

### Objectives and Hints

Identify which boundary stops UPDATE, ATTACH, disk writes and excessive VM work. Explain why the unrestricted bootstrap connection must not be handed to the report subsystem. Hint: the authorizer uses a deliberately narrow allowlist, not a purported comprehensive SQL sandbox.

### Solution and Expected Results

Two tests pass. Baseline UPDATE succeeds but rolls back. The same UPDATE and an in-memory ATTACH are denied with SQLITE_AUTH after policy installation; permitted bound SELECT still returns id `1`. A separate read-only URI rejects writes with SQLITE_READONLY. The bounded recursive fixture is interrupted, and removing its budget handler restores a trivial read. Exact error codes avoid mistaking unrelated failures for successful enforcement.

### Troubleshooting and Cleanup

An authorization failure on an intended query means the allowlist needs an explicit reviewed capability, not a global allow. Platform-specific extended error codes may need inspection before comparison for other fixtures. Connections close and temporary files disappear automatically. No extension is loaded and no host ACL is changed. Real cross-identity file denial, encrypted backup policy and endpoint time budgets remain deployment validation requirements; these tests intentionally do not claim to prove them.

- [ ] Local SQLite exercise: Create a temporary database, perform a transaction with rollback, and query a quote-containing value using parameters. Inspect file permissions and test a second writer's behavior.
- [ ] Boundary check: Run the app under a restricted local identity and verify it cannot open an unrelated database file. Confirm malformed values remain data in a prepared query.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[SQLite]]

## References

- [SQLite security guidance](https://www.sqlite.org/security.html)
- [Runtime limits](https://www.sqlite.org/limits.html)
- [Authorizer API](https://www.sqlite.org/c3ref/set_authorizer.html)
- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html)
