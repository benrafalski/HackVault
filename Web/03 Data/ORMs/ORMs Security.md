---
title: "ORMs Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[ORMs]]"
updated: 2026-11-03
---
# ORMs Security

> [!abstract] TL;DR
> Raw-query concatenation, tenant-filter bypass, and mass assignment can defeat the apparent safety of object-oriented persistence.

> [!info] Agent scope
> Security of: Object mapping; query translation; migrations; relationships; raw-query escape hatches; mass assignment; transaction boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Raw-query concatenation, tenant-filter bypass, and mass assignment can defeat the apparent safety of object-oriented persistence.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me ORM security using SQLAlchemy 2.0 and real SQLite, assuming Python/SQL.
Trace request DTOs, authenticated tenant context, entity state, query translation,
bulk/raw escape hatches and database permissions. Explain mass assignment,
explicit response projection, identity-map reuse, global-filter limitations,
optimistic concurrency, migrations and rollback after flush errors. Provide a
synthetic baseline/fix test for an unexpected harmless internal field, plus
parameterized ordinary/bulk/raw paths with tenant predicates. No privilege
escalation, injection exploitation or data-theft walkthroughs. Include negative
and positive tests, resource limits and primary sources. Teach here without
editing or inventing evidence.
```

## Cheatsheet

### What the ORM Does Not Authorize

Expression APIs usually bind scalar values. They do not decide whether a caller owns a row, may modify a property, or may observe a response field. An unsafe pattern is iterating over arbitrary JSON keys and calling `setattr(entity, key, value)`. Use an explicit write DTO and explicit assignments; reject unexpected fields rather than silently accepting a new mapped field after a schema upgrade.

```python
def parse_title(payload):
	if not isinstance(payload, dict) or set(payload) != {"title"}:
		raise ValueError("only title is writable")
	title = payload["title"]
	if not isinstance(title, str) or not 1 <= len(title) <= 80:
		raise ValueError("invalid title")
	return title
```

The authenticated tenant belongs outside this DTO. Response serialization must likewise project allowed fields rather than exposing `__dict__` or every mapped column. ORM relationships can accidentally serialize other objects or trigger unbounded queries.

### Equivalent Policy Across Paths

| Path | Required review |
|---|---|
| Entity SELECT + attribute update | Filter by tenant and ID before loading; identity-map hits are not new authorization checks. |
| Bulk UPDATE/DELETE | Include tenant in the SQL predicate, bound affected-row expectation, and explicit allowed values. |
| Raw `text()` SQL | Bind values and reproduce the same authorization predicate; string interpolation is not ORM protection. |
| Global query filters | Helpful defaults, not a universal boundary; raw paths and explicit bypass APIs may omit them. |
| Hooks / validators | Often not invoked by bulk operations; enforce critical invariants in the database too. |
| Migration runner | Separate elevated identity; never run destructive autogeneration automatically at app startup. |

For concurrent edits, use a version column and conditional UPDATE (`id`, `tenant`, expected version); require one affected row. Object-version helpers may not cover multirow bulk operations. Request-scoped sessions prevent tenant context leaking through cached entities. A failed flush must roll back before the Session returns to service.

Cap page size, relationship depth and number of fields; use eager loading or projections to avoid attacker-amplifiable N+1. SQL timeouts, pool budgets and HTTP deadlines serve different purposes. SQLite fixtures cannot certify PostgreSQL/SQL Server role enforcement, RLS or isolation semantics.

## Detection and Defense

Record query counts/latency, row counts for mutations, policy rejection categories and migration events. Avoid logging sensitive parameters. Inspect generated SQL for missing predicates, not merely whether it contains placeholders. Test the actual runtime identity on the production engine as a separate gate; an in-memory SQLite test has no server roles.

## Labs

### Environment and Complete Files

Python 3.12+, SQLite and SQLAlchemy `>=2.0,<2.1`; record installed versions. **Unexecuted authoring fixture.** Baseline changes only a harmless synthetic `internal_note` inside a rollback and shows that broad assignment fails the rejection contract. No privileged role is changed.

### File: requirements.txt

```text
SQLAlchemy>=2.0,<2.1
```

### File: test_example.py

```python
import sys
import unittest
from sqlalchemy import String, create_engine, select, text, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

BASELINE = "--baseline" in sys.argv
if BASELINE:
	sys.argv.remove("--baseline")


class Base(DeclarativeBase):
	pass


class Document(Base):
	__tablename__ = "document"
	id: Mapped[int] = mapped_column(primary_key=True)
	tenant: Mapped[int]
	title: Mapped[str] = mapped_column(String(80))
	internal_note: Mapped[str] = mapped_column(String(80))


def apply_title(document, payload):
	if BASELINE:
		for field, value in payload.items():
			setattr(document, field, value)
		return
	if not isinstance(payload, dict) or set(payload) != {"title"}:
		raise ValueError("only title is writable")
	if not isinstance(payload["title"], str) or not 1 <= len(payload["title"]) <= 80:
		raise ValueError("invalid title")
	document.title = payload["title"]


class ORMPolicy(unittest.TestCase):
	def setUp(self):
		self.engine = create_engine("sqlite://")
		Base.metadata.create_all(self.engine)
		with Session(self.engine) as session, session.begin():
			session.add_all([
				Document(id=1, tenant=7, title="first", internal_note="fixture"),
				Document(id=2, tenant=8, title="second", internal_note="fixture"),
			])

	def tearDown(self):
		self.engine.dispose()

	def test_reject_unexpected_fields(self):
		with Session(self.engine) as session:
			document = session.scalar(select(Document).where(Document.id == 1, Document.tenant == 7))
			with self.assertRaises(ValueError):
				apply_title(document, {"title": "allowed", "internal_note": "temporary"})
			session.rollback()

	def test_scoped_paths(self):
		with Session(self.engine) as session, session.begin():
			document = session.scalar(select(Document).where(Document.id == 1, Document.tenant == 7))
			apply_title(document, {"title": "O'Reilly"})
		with Session(self.engine) as session, session.begin():
			result = session.execute(update(Document).where(Document.id == 2, Document.tenant == 7).values(title="no change"))
			self.assertEqual(result.rowcount, 0)
			result = session.execute(update(Document).where(Document.id == 1, Document.tenant == 7).values(title="approved"))
			self.assertEqual(result.rowcount, 1)
			rows = session.execute(text("SELECT id,title FROM document WHERE tenant=:tenant AND id=:id"), {"tenant": 7, "id": 2}).all()
			self.assertEqual(rows, [])
			own = session.execute(text("SELECT id,title FROM document WHERE tenant=:tenant"), {"tenant": 7}).all()
			self.assertEqual(own, [(1, "approved")])
		with Session(self.engine) as session:
			self.assertEqual(session.get(Document, 2).title, "second")


if __name__ == "__main__":
	unittest.main()
```

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python test_example.py --baseline -v
.\.venv\Scripts\python test_example.py -v
```

### Objectives and Hints

Require rejection of the unexpected field while preserving allowed updates. Explain why all three query styles carry an explicit trusted tenant. Hint: parameterization and authorization are different assertions; zero matched rows on a scoped foreign-ID update is the intended result.

### Solution and Expected Results

Baseline has one intentional failing test (`ValueError not raised`); the default fixed implementation passes both tests. The fixed path accepts `O'Reilly`, the own-tenant bulk update changes one row, the foreign-ID update changes zero, and scoped raw read returns no foreign row. Final bootstrap verification confirms tenant 8's synthetic title remains `second`.

### Troubleshooting and Cleanup

Failure to import SQLAlchemy means use the virtual environment interpreter. A global Session can contaminate results; each test creates a fresh real database. These are service-layer contract calls, not HTTP end-to-end tests, and `tenant=7` represents an already authenticated identity. In-memory databases are disposed after each test; remove only the lab-local virtual environment when finished. Production-engine grant and migration checks remain unexecuted requirements.

- [ ] Local ORMs exercise: Implement a parent/child query and compare lazy loading with explicit projection. Capture query counts, then test rollback and an update limited to approved fields.
- [ ] Boundary check: Send an unexpected synthetic role/owner field in an update and verify rejection. Compare ordinary and bulk/raw paths for the same tenant constraint.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[SQL Injection]]
- [[Broken Access Control and IDOR]]
- [[ORMs]]

## References

- [SQLAlchemy ORM DML](https://docs.sqlalchemy.org/en/20/orm/queryguide/dml.html)
- [SQLAlchemy version counters](https://docs.sqlalchemy.org/en/20/orm/versioning.html)
- [OWASP mass assignment guidance](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
