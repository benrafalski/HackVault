---
title: "SQL Injection"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# SQL Injection

> [!abstract] TL;DR
> SQL injection occurs when untrusted data changes a query's syntax instead of remaining a bound value.

> [!info] Agent scope
> Query construction boundaries; in-band and blind variants; database-specific conditions; parameterization; identifier allowlists.

## Learn

```text
Teach SQL injection as a query-construction and database-authority failure at
expert depth. Assume SQL joins, HTTP request handling, and transaction basics.
Trace request parsing through ORM/raw SQL, driver binding, database parsing,
execution, and response mapping. Distinguish values from identifiers and SQL
structure; cover stored dynamic SQL, second-order input, LIKE semantics, and
prepared statements versus emulated preparation. Explain in-band result/error
and blind boolean/time evidence conceptually, without probes or payloads.
Compare SQLite, PostgreSQL, MySQL, and SQL Server driver semantics and privileges.
Work through secure parameter binding, fixed query templates, identifier maps,
tenant predicates, safe errors, and regression tests with ordinary synthetic
records. Explain what each control cannot prove, including ORM escape hatches.
Use public vendor documentation. Ask difficult review questions with answers.
Only defensive code review and hardening: no exploitation, bypasses, extraction,
shells, RCE, scanning, or chains. Do not edit files or claim tests were run.
```

## Cheatsheet

> [!important] Defensive scope
> This page reviews query boundaries and tests secure implementations. It contains no operational injection payloads or live exploitation exercise.

### Mechanism and Prerequisites

The dangerous transition is **data becoming SQL grammar** before the database parses a statement. A controllable HTTP field is insufficient by itself: it must reach a structurally constructed query. Stored values remain untrusted when later used to construct reports or administrative queries. A database's permissions constrain impact, but do not repair the boundary.

| Boundary | Secure construction | Limitation |
|---|---|---|
| Equality/range values | Driver placeholders and separately supplied values | Does not authorize the selected rows |
| Table, column, sort direction | Map a small public enum to fixed SQL fragments | Placeholders cannot normally represent identifiers |
| Variable list | One placeholder per validated element; cap count | Binding one comma-separated string is not a list |
| Search patterns | Bind the pattern; define literal versus wildcard search | Binding preserves SQL grammar, not literal LIKE semantics |
| Stored procedures/raw ORM APIs | Bind inside every dynamic SQL boundary | Procedure/ORM branding does not imply safety |
| Tenant scope | Derive tenant from authenticated server context | A client-supplied tenant is not an authority |

In-band variants expose results or database errors; blind variants expose a correlated difference in behavior or duration. These describe observation channels, not universally available capabilities. An error may be ordinary bad input. A slow query may be a missing index. Establish root cause through query construction and controlled secure regressions, not timing speculation.

### Driver and Version Details

Python 3.12 `sqlite3` supports `?` and named value placeholders; `execute()` accepts one statement, but this alone does not make string-built statements safe. `executescript()` is for trusted scripts and has no value-binding API. Transaction configuration changed in Python 3.12 with the `autocommit` parameter; the lab uses a connection context to commit setup and closes explicitly.

PostgreSQL's server protocol uses positional parameters; Psycopg's Python interface uses `%s` placeholders passed with a separate sequence, not Python interpolation. MySQL placeholder and server/emulated preparation behavior depends on the connector and configuration; check that exact driver. SQL Server applications should use typed parameters; dynamic SQL in stored procedures needs its own parameterization. Identifier quoting APIs are vendor-specific and do not replace an application allowlist.

### Worked Secure Query

The complete lab below binds both the tenant and name and chooses the ORDER BY column from a closed map. Apostrophes in ordinary names are valid data. Do not sanitize them away. Log the query template identifier, duration, error category, and affected-row count; avoid raw parameter values or session identifiers. A stable query template is useful evidence but does not prove a correct authorization predicate.

## Defense

Use parameter APIs on every execution path, including exports and background jobs. Give application roles only required operations on required schemas; separate migration identities. Restrict database file/network capabilities and public error detail. Review raw query escape hatches and generated SQL after framework upgrades. WAF signatures and string escaping are not a substitute for grammar/data separation. Retain business authorization and result-size limits even after binding is correct.

## Labs

### Environment and Objectives

Independent defensive hardening exercise: Python 3.12, standard library only, no database service or network. In a disposable directory create the single file below. All rows are synthetic and the database is in memory. Review a proposed design that interpolates names and accepts an arbitrary sort expression; identify why those two boundaries require different fixes without implementing the proposal.

Objectives: preserve legitimate punctuation, constrain query structure, enforce a server-selected tenant, and reject unknown sort choices. The secure implementation is included so the challenge does not require an agent or an unsafe baseline.

### File: test_example.py

```python
import sqlite3
import unittest


SORT_COLUMNS = {"name": "name", "id": "id"}


def find_people(database, tenant, name, sort="name"):
	if type(tenant) is not str or type(name) is not str:
		raise ValueError("scalar values required")
	if type(sort) is not str or sort not in SORT_COLUMNS:
		raise ValueError("unknown sort")
	column = SORT_COLUMNS[sort]
	statement = (
		"SELECT id, name FROM people WHERE tenant = ? AND name = ? "
		f"ORDER BY {column}"
	)
	return database.execute(statement, (tenant, name)).fetchall()


class QueryTests(unittest.TestCase):
	def setUp(self):
		self.database = sqlite3.connect(":memory:")
		self.addCleanup(self.database.close)
		with self.database:
			self.database.execute(
				"CREATE TABLE people (id INTEGER PRIMARY KEY, "
				"tenant TEXT NOT NULL, name TEXT NOT NULL)"
			)
			self.database.executemany(
				"INSERT INTO people VALUES (?, ?, ?)",
				[(1, "north", "O'Neil"), (2, "south", "O'Neil"),
				 (3, "north", "Ada")],
			)

	def test_literal_name_and_tenant(self):
		self.assertEqual(find_people(self.database, "north", "O'Neil"),
						 [(1, "O'Neil")])

	def test_other_tenant_and_missing_name(self):
		self.assertEqual(find_people(self.database, "south", "Ada"), [])
		self.assertEqual(find_people(self.database, "north", "Unknown"), [])

	def test_fixed_structure(self):
		self.assertEqual(find_people(self.database, "north", "Ada", "id"),
						 [(3, "Ada")])
		with self.assertRaises(ValueError):
			find_people(self.database, "north", "Ada", "popularity")

	def test_types_and_unchanged_data(self):
		with self.assertRaises(ValueError):
			find_people(self.database, "north", ["Ada"])
		count = self.database.execute("SELECT COUNT(*) FROM people").fetchone()[0]
		self.assertEqual(count, 3)


if __name__ == "__main__":
	unittest.main()
```

### Commands and Hints

```powershell
py -3.12 -m unittest -v test_example
```

On non-Windows systems use `python3.12` instead of `py -3.12`. Hint: compare the f-string's only variable with the separate bound tuple. Which values are trusted code? Why would binding a column name produce a value rather than a new identifier? Why must the tenant come from outside the request body?

### Separate Solution and Expected Observations

The only interpolated fragment comes from `SORT_COLUMNS`; neither the name nor tenant reaches SQL text. Expected: four tests succeed, the north query returns only row 1, the alternate tenant cannot see Ada, and unknown sorts fail before execution. These are expected results, not a reported run. A complete application must additionally authenticate the tenant and authorize the operation; this function assumes that boundary has already supplied the tenant.

### Verification, Troubleshooting, and Cleanup

Review every `execute` call for separate values. No external dependencies or fixture files are missing. If Python cannot import `test_example`, run from the directory containing the file. If SQLite is unavailable in a custom Python build, use a standard CPython 3.12 build. The in-memory database disappears on close; remove only this disposable exercise directory afterward. No commands or tests were executed during authoring.

- [ ] Local SQL Injection exercise: Review the query-construction proposal and explain both fixes.
- [ ] Boundary check: Run the secure literal-value, sort-map, and tenant regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python 3.12 sqlite3: placeholders and transaction control](https://docs.python.org/3.12/library/sqlite3.html)
- [PostgreSQL PREPARE](https://www.postgresql.org/docs/current/sql-prepare.html)
- [Psycopg 3 parameter passing](https://www.psycopg.org/psycopg3/docs/basic/params.html)
- [MySQL prepared statements](https://dev.mysql.com/doc/refman/8.4/en/sql-prepared-statements.html)
- [SQL Server SQL injection guidance](https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-injection)
