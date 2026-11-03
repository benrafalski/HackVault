---
title: "Broken Access Control and IDOR"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Broken Access Control and IDOR

> [!abstract] TL;DR
> Broken access control lets a caller perform an object, function, or tenant-scoped operation that the server should deny; IDOR is a common identifier-based manifestation.

> [!info] Agent scope
> Object and function authorization; tenant boundaries; identifier substitution; role matrices; deny-by-default checks.

## Learn

```text
Teach broken access control and IDOR as server-side policy failures. Assume
authentication, SQL, HTTP routes, and multi-tenant data models. Distinguish object,
function, property, horizontal, vertical, and tenant authorization. Trace every
identifier location, including nested/bulk routes and background jobs. Build an
actor/object/action matrix with deny-by-default rules and tenant-scoped admins.
Review scoped SQL reads and atomic writes/deletes, field projection, ownership
immutability, soft deletion, caches, and policy revocation. Explain UUID limits,
404/403 tradeoffs, and why status alone does not establish state protection.
Use only synthetic records and secure implementation regressions; no live ID
substitution, enumeration, theft, bypasses, scanning, or chains. Cite primary
authorization guidance and give difficult review questions with answers. Teach,
do not author files or fabricate test results.
```

## Cheatsheet

> [!important] Defensive scope
> The lab tests authorized and denied operations directly against an in-memory synthetic database. It contains no endpoint enumeration or real-account access exercise.

### Policy Is a Relation

Authentication supplies an actor, not permission to every object. The authorization decision depends on actor, tenant, object, action, field, and sometimes current state. IDOR is the identifier-based manifestation of a missing or incorrect object check; opaque identifiers reduce guessing but do not enforce policy.

| Actor relative to object | Read | Rename | Delete |
|---|---|---|---|
| Owner in same tenant | Allow | Allow | Deny in this product |
| Peer member in same tenant | Deny | Deny | Deny |
| Administrator in same tenant | Allow | Allow | Allow |
| Administrator in another tenant | Deny | Deny | Deny |
| Unknown role/unauthenticated | Deny | Deny | Deny |

This matrix is a product rule, not a universal role model. Derive actor identity, role, and tenant from a trusted session or verified identity provider; never accept them from an object-update body. An administrative role may be tenant-local, not global. Object ownership does not imply permission to change ownership, tenant, billing fields, or every nested relationship.

### Enforcement Patterns

For reads, scope the database query before materializing unauthorized data. For writes, include authorization predicates in the mutation or hold appropriate locks; checking an object then updating it separately can race with ownership/state changes. Validate parent-child relationships, not just that each identifier exists. Bulk operations need per-object policy and a defined all-or-nothing or partial-success contract. Background jobs must preserve/re-evaluate the relevant actor authority rather than inherit unrestricted worker authority by accident.

Project only permitted fields; allowing a row does not authorize every column. Scope caches and data loaders to actor/tenant where representations vary. Policy changes and revocation need cache invalidation or short lifetimes. Database row-level security can add protection, but session context, privileged roles, and connection pooling must be configured correctly.

Returning 404 for inaccessible objects can reduce existence disclosure; returning 403 may improve legitimate diagnostics. Keep behavior consistent and consider timing and error detail. Neither status proves absence of mutation. Log decision reason, action, object ID, actor/tenant reference, and policy version without private object content.

### Scoped Read Reference

**Fragment / prerequisites:** SQLite named-parameter SQL for the lab's `documents` schema. The caller must first authenticate and allowlist the `read` action; bind `:actor_id`, `:tenant_id`, and `:role` from trusted server-side identity, and `:object_id` from the requested identifier. Pass a parameter mapping to the database driver, never interpolate values.

```sql
SELECT id, title
FROM documents
WHERE id = :object_id
	AND tenant = :tenant_id
	AND :role IN ('member', 'admin')
	AND (owner = :actor_id OR :role = 'admin');
```

**Interpretation:** A tenant-local admin still needs the tenant predicate. Return only the projected fields; no row means absent or inaccessible, not permission to retry an unscoped query. This read does not authorize a later write. **False-positive caveat:** denied reads can reflect deleted records or stale tenant membership, not attempted abuse; diagnose with internal decision logs without exposing object existence.

### Version and Worked Code Notes

The Python 3.12/SQLite fixture below uses bound values and an allowlisted action branch. Role checks precede the query; tenant and owner conditions remain in every operation. This is application authorization, not SQLite built-in row-level security. Framework decorators often cover function access but cannot infer object ownership automatically.

## Defense

Centralize policy at a layer reached by all entry points. Deny unknown actions/roles, protect immutable security fields, and make mutation authorization atomic. Regression-test the complete matrix after route/schema changes. Keep administrative capabilities explicit and narrowly scoped; do not rely on UI controls or ID entropy.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, in-memory SQLite, no service. All actors and records are synthetic. Review a proposal that checks only whether the user is logged in. Use the matrix above to explain each predicate in the replacement and verify denied writes leave state unchanged.

### File: test_example.py

```python
from dataclasses import dataclass
import sqlite3
import unittest


@dataclass(frozen=True)
class Actor:
	user: str
	tenant: str
	role: str


def operate(database, actor, action, object_id, title=None):
	if actor.role not in {"member", "admin"} or action not in {"read", "rename", "delete"}:
		raise PermissionError("policy")
	if action == "delete" and actor.role != "admin":
		raise PermissionError("function")
	where = "id = ? AND tenant = ? AND (owner = ? OR ? = 'admin')"
	values = (object_id, actor.tenant, actor.user, actor.role)
	if action == "read":
		row = database.execute("SELECT id, title FROM documents WHERE " + where,
							   values).fetchone()
		if row is None:
			raise PermissionError("object")
		return row
	if action == "rename":
		if type(title) is not str or not 1 <= len(title) <= 80:
			raise ValueError("title")
		statement = "UPDATE documents SET title = ? WHERE " + where
		values = (title,) + values
	else:
		statement = "DELETE FROM documents WHERE " + where
	with database:
		changed = database.execute(statement, values).rowcount
		if changed != 1:
			raise PermissionError("object")


class AuthorizationTests(unittest.TestCase):
	def setUp(self):
		self.database = sqlite3.connect(":memory:")
		self.addCleanup(self.database.close)
		self.database.execute("CREATE TABLE documents "
							  "(id INTEGER PRIMARY KEY, tenant TEXT, owner TEXT, title TEXT)")
		with self.database:
			self.database.execute("INSERT INTO documents VALUES (?, ?, ?, ?)",
								  (1, "north", "ada", "Draft"))

	def test_owner_allowed_operations(self):
		owner = Actor("ada", "north", "member")
		operate(self.database, owner, "rename", 1, "Reviewed")
		self.assertEqual(operate(self.database, owner, "read", 1), (1, "Reviewed"))

	def test_denial_matrix_preserves_state(self):
		actors = [Actor("grace", "north", "member"), Actor("admin", "south", "admin"),
				  Actor("ada", "north", "unknown")]
		for actor in actors:
			for action in ["read", "rename", "delete"]:
				with self.subTest(actor=actor, action=action), self.assertRaises(PermissionError):
					operate(self.database, actor, action, 1, "Changed")
		self.assertEqual(self.database.execute("SELECT title FROM documents").fetchall(),
						 [("Draft",)])

	def test_function_and_tenant_admin(self):
		with self.assertRaises(PermissionError):
			operate(self.database, Actor("ada", "north", "member"), "delete", 1)
		operate(self.database, Actor("admin", "north", "admin"), "delete", 1)
		self.assertEqual(self.database.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 0)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: the tenant predicate must apply even when the role is admin. Read the parentheses in the WHERE clause and explain why they matter.

Solution: action policy gates the function and SQL predicates gate the object. Expected: three tests pass; the owner can rename/read, nine denied matrix operations preserve the record, and only the same-tenant admin can delete. `Actor` is a trusted fixture, not an authentication implementation. Nested/bulk routes and field-level product policies must call equivalent enforcement in an actual application.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file; SQLite ships with standard CPython. Close occurs through unittest cleanup and the database is memory-only. Remove the disposable exercise directory. A successful suite establishes only the printed matrix and implementation, not every route in a larger app.

- [ ] Local Broken Access Control and IDOR exercise: Review the actor/object/action matrix.
- [ ] Boundary check: Run scoped reads, atomic writes, and no-mutation denial tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP API object-level authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
