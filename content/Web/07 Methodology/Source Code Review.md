---
title: "Source Code Review"
aliases: []
tags: [web, w7]
domain: web
phase: "W7"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Source Code Review

> [!abstract] TL;DR
> Record source -> transformations -> policy -> sink, including identity and version assumptions. Verify fixes with the smallest failing behavior test.

> [!info] Agent scope
> Entry points; data flow; trust boundaries; authorization; dangerous sinks; configuration; dependency review; targeted tests.

## Prerequisites

- Request lifecycles, authentication versus authorization, SQL parameter binding, and Python exceptions; [[Web Lab Setup]].
- Python 3.12 with its standard-library `sqlite3` module. No third-party dependencies, service, account, network access, package installer, or vulnerability scanner is needed.

## Learn

```text
Teach me security-focused source review at expert engineering depth. Assume
Python, SQL, HTTP, and authentication basics. Begin at a concrete entry point
and trace parsing, transformations, trusted identity, tenant/object/function
authorization, database mutation, serialization, logging, and error handling.
Explain forward/backward dataflow, control-flow dominance, framework middleware,
background workers, configuration precedence, dependency reachability, and
the difference between a suspicious sink and a demonstrated defect. Use a safe
Python 3.12 stdlib SQLite hardening case: ownership checks stay present; improve
schema validation, bounded text handling, and atomic owner-scoped updates.
Provide full fixtures, positive and negative regression tests, review evidence,
and remediation reasoning without exploitation, bypass instructions, payloads,
or access to third-party data. Discuss transactions, race assumptions, principal
trust, Unicode length policy, deployment limits, and what unit tests cannot
establish. Cite public primary sources and include difficult review questions
with worked answers. Teach here without file-writing requests or status edits.
```

## Cheatsheet

### Review One Behavior End to End

Start with an invariant: "Only an authenticated owner in the same tenant can rename a document; the resulting title is bounded nonblank text; rejected operations do not mutate data." This gives the review a falsifiable target and a cheap regression test.

| Step | Evidence to locate | Question |
|---|---|---|
| Entry | Route, job consumer, import function, CLI handler | Which inputs are untrusted and how large can they be? |
| Identity | Authentication middleware and principal construction | Is identity established by trusted code, or copied from request fields? |
| Transform | Parser, coercion, normalization, deserialization | Are types and validation semantics preserved? |
| Policy | Role, tenant, object ownership, workflow checks | Does every path to the operation enforce the relevant policy? |
| Sink | DB mutation, file write, process invocation, outbound request, template | Which invariant must hold before this operation? |
| Output | DTO serialization, errors, audit event | Are only intended fields exposed, and can rejection be distinguished operationally? |

Trace forward from the input to understand transformations; trace backward from the sink to find all callers. A check must dominate the sensitive operation on every relevant control path. An unused helper, a UI-only restriction, or a check applied after mutation does not establish that. For async jobs, carry a server-issued identity/reference and re-evaluate time-sensitive permissions; do not assume authorization at enqueue time is sufficient forever.

### Concrete Review Evidence

Example for the lab's `rename_document`:

```text
Entry: rename_document(connection, principal, document_id, payload)
Untrusted: document_id, payload['title']; payload cannot choose owner or tenant
Trusted prerequisite: Principal produced by authentication adapter (not supplied here)
Transform: exact object fields -> string type -> strip outer whitespace -> 1..80 code points
Policy/sink: UPDATE ... WHERE id=? AND owner=? AND tenant=?
Outcome: one updated row or generic 404; no unauthorized object data returned
Evidence: owner-positive, other-owner-denied, other-tenant-denied, unchanged-row tests
Limit: direct unit calls cannot prove an HTTP adapter constructs Principal safely
```

Record file/symbol, revision, line range in the review artifact, route/caller, violated invariant, preconditions, observed test, fix, and residual uncertainty. Separate confirmed defects from questions and hardening recommendations. A static analyzer or text search gives leads, not proof of reachability or impact.

### Dangerous Sinks and Safe Alternatives

| Boundary | Review for | Safer design / residual risk |
|---|---|---|
| SQL | String-built statements, dynamic identifiers, broad updates | Bind values; allowlist identifiers; include ownership in mutation predicate. Binding alone is not authorization |
| Object binding | User-controlled owner/role/tenant fields | Explicit input DTO; reject unknown fields rather than silently granting meaning |
| File output | Arbitrary caller paths, symlink assumptions | Server-owned IDs and storage roots; filesystem permissions remain necessary |
| Process launch | User input selecting commands/options | Prefer a library API; fixed executable and structured arguments when unavoidable |
| Templates | Mixing untrusted text with template source | Treat input as data with context-appropriate escaping |
| Parsing | Object construction, permissive formats, unbounded collections | Data-only schemas, size/depth limits, explicit types |
| Network client | Unrestricted destinations or redirects | Narrow approved destination policy and egress controls; no fetching in this lab |
| Logging | Full bodies, tokens, personal data, untrusted multiline messages | Structured minimal events with stable IDs and access/retention controls |

This is a hardening checklist, not an instruction to exercise dangerous sinks. Review declarations together with actual runtime configuration and all call sites.

### Authorization and Atomicity

Authentication proves a principal; authorization permits a particular operation on a resource. Tenant membership is not necessarily ownership; ownership is not necessarily permission to administer. Distinguish object, function, and workflow-state policies. Avoid trusting an incoming header or payload field as identity merely because its name is `user_id`.

The fixed lab update binds values and predicates on `(id, owner, tenant)` in **one SQL statement**. This prevents a read-check-write gap for those predicates. It does not solve every concurrent workflow invariant: revision checks, quotas, related rows, or external effects may require optimistic concurrency, transactions, locks, or an outbox. State which invariants the transaction actually protects.

Returning generic 404 for absent and inaccessible records limits existence disclosure. A 403 can be clearer when existence is already public; choose deliberately and test consistency. A negative test must assert both rejection **and unchanged persisted state**. A positive control prevents a fix that simply denies all updates from looking successful.

### Validation and Configuration Tradeoffs

Reject unknown input fields when silently ignoring them would hide client errors or invite future mass assignment. Validate types before normalization; in Python `bool` is an `int` subclass, so `type(value) is int` deliberately rejects boolean IDs. Define whether text limits count Unicode code points, UTF-8 bytes, or grapheme clusters. The lab uses code points and permits internal spaces; it is not a display-width or storage-byte guarantee.

Validate at the owning boundary and retain database constraints as defense in depth. In a real HTTP adapter, also cap raw body size before parsing, choose explicit accepted content types, return generic client errors, and avoid debug tracebacks. The supplied in-process function receives an already parsed small object and does not implement transport limits.

Review config precedence: secure source defaults can be overridden by environment, deployment templates, feature flags, debug mode, proxy trust, test fixtures, or exception handlers. Record the effective value and where it came from. Review migrations, schema constraints, scheduled jobs, and administrative endpoints, not just normal request handlers.

### Dependency Review With Reachability

Capture runtime and transitive versions, lockfile/provenance, update policy, bundled native libraries, and build/runtime differences. An advisory's affected range is necessary but not sufficient: inspect platform, feature flags, vulnerable API reachability, and deployment. Conversely, absence of an advisory does not prove safety. Never run unknown project install hooks just to review a manifest.

The lab has zero third-party Python distributions, but Python and its linked SQLite still need supported security updates. The provided command records the actual SQLite version; stdlib membership is not a security certification. No package or advisory scan is claimed here.

## Gotchas

- Unit-test fixtures can accidentally bypass production authentication/middleware. Document that boundary rather than crediting untested controls.
- A frozen dataclass prevents ordinary attribute reassignment, not forged identity. The trust boundary is who constructs it.
- A minimal fix belongs where policy is enforced; duplicating partial checks across callers creates drift. Do not remove existing authorization to make an exercise fail.

## Labs

### Case and Environment

Review a synthetic document rename service. Baseline v1 already restricts the mutation to the owner and tenant and binds SQL values. Its hardening gap is accepting whitespace-only and excessively long titles. The supplied fixed v2 adds exact schema and bounded normalization. Neither version exposes a network endpoint; no exploit or authorization omission is introduced.

Create an empty disposable directory outside the vault with these two files. All identities and documents are seeded in memory on every test. Use Python 3.12 with `sqlite3`; no installation commands or external account are required. The baseline and reference fix are both complete so the reader need not invent implementation details.

### File: review_case.py

```python
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
	user_id: str
	tenant_id: str


class Rejected(Exception):
	def __init__(self, status, code):
		super().__init__(code)
		self.status = status
		self.code = code


def seed():
	connection = sqlite3.connect(":memory:")
	connection.execute(
		"CREATE TABLE documents (id INTEGER PRIMARY KEY, "
		"owner TEXT NOT NULL, tenant TEXT NOT NULL, title TEXT NOT NULL)"
	)
	connection.executemany("INSERT INTO documents VALUES (?, ?, ?, ?)", [
		(1, "alice", "red", "Planning"),
		(2, "bob", "red", "Checklist"),
		(3, "alice", "blue", "Notes"),
	])
	connection.commit()
	return connection


def store_title(connection, principal, document_id, title):
	if principal is None:
		raise Rejected(401, "authentication-required")
	with connection:
		cursor = connection.execute(
			"UPDATE documents SET title=? WHERE id=? AND owner=? AND tenant=?",
			(title, document_id, principal.user_id, principal.tenant_id),
		)
		if cursor.rowcount != 1:
			raise Rejected(404, "not-found")
	return {"id": document_id, "title": title}


def rename_baseline(connection, principal, document_id, payload):
	if principal is None:
		raise Rejected(401, "authentication-required")
	if type(document_id) is not int or document_id <= 0:
		raise Rejected(400, "invalid-id")
	if type(payload) is not dict or set(payload) != {"title"}:
		raise Rejected(400, "invalid-fields")
	title = payload["title"]
	if type(title) is not str or not title:
		raise Rejected(400, "invalid-title")
	return store_title(connection, principal, document_id, title)


def rename_document(connection, principal, document_id, payload):
	if principal is None:
		raise Rejected(401, "authentication-required")
	if type(document_id) is not int or document_id <= 0:
		raise Rejected(400, "invalid-id")
	if type(payload) is not dict or set(payload) != {"title"}:
		raise Rejected(400, "invalid-fields")
	title = payload["title"]
	if type(title) is not str:
		raise Rejected(400, "invalid-title")
	title = title.strip()
	if not 1 <= len(title) <= 80 or any(ord(char) < 32 or ord(char) == 127 for char in title):
		raise Rejected(400, "invalid-title")
	return store_title(connection, principal, document_id, title)
```

The shared storage function enforces ownership in both versions. It is an internal helper, not an exposed handler; a real module should keep its call sites narrowly controlled so callers cannot omit input policy. The lab forbids ASCII control characters after trimming; this is a stated title policy, not comprehensive Unicode sanitization.

### File: test_example.py

```python
import sqlite3
import unittest
from review_case import Principal, Rejected, rename_baseline, rename_document, seed


class ReviewTests(unittest.TestCase):
	def setUp(self):
		self.connection = seed()
		self.addCleanup(self.connection.close)
		self.alice = Principal("alice", "red")

	def titles(self):
		return self.connection.execute("SELECT id, title FROM documents ORDER BY id").fetchall()

	def assert_rejected_unchanged(self, status, principal, document_id, payload):
		before = self.titles()
		with self.assertRaises(Rejected) as caught:
			rename_document(self.connection, principal, document_id, payload)
		self.assertEqual(caught.exception.status, status)
		self.assertEqual(self.titles(), before)

	def test_baseline_and_hardening(self):
		result = rename_baseline(self.connection, self.alice, 1, {"title": "   "})
		self.assertEqual(result["title"], "   ")
		self.assert_rejected_unchanged(400, self.alice, 1, {"title": "   "})

	def test_owner_positive_control(self):
		result = rename_document(self.connection, self.alice, 1, {"title": "  Revised  "})
		self.assertEqual(result, {"id": 1, "title": "Revised"})
		self.assertEqual(self.titles(), [(1, "Revised"), (2, "Checklist"), (3, "Notes")])

	def test_owner_boundary(self):
		self.assert_rejected_unchanged(404, self.alice, 2, {"title": "Revised"})

	def test_tenant_boundary(self):
		self.assert_rejected_unchanged(404, self.alice, 3, {"title": "Revised"})

	def test_authentication_and_missing_record(self):
		self.assert_rejected_unchanged(401, None, 1, {"title": "Revised"})
		self.assert_rejected_unchanged(404, self.alice, 99, {"title": "Revised"})

	def test_schema_and_types(self):
		for payload in ({}, {"title": 7}, {"title": "Revised", "owner": "alice"}, []):
			with self.subTest(payload=payload):
				self.assert_rejected_unchanged(400, self.alice, 1, payload)
		self.assert_rejected_unchanged(400, self.alice, True, {"title": "Revised"})

	def test_length_and_control_policy(self):
		self.assert_rejected_unchanged(400, self.alice, 1, {"title": "A" * 81})
		self.assert_rejected_unchanged(400, self.alice, 1, {"title": "Two\nLines"})
		result = rename_document(self.connection, self.alice, 1, {"title": "A" * 80})
		self.assertEqual(len(result["title"]), 80)


if __name__ == "__main__":
	print("linked SQLite", sqlite3.sqlite_version)
	unittest.main()
```

### Objectives and Commands

1. Trace the function boundary through normalization and SQL mutation. Mark identity as trusted input and explain where an HTTP adapter would have to establish that trust.
2. Record finding CR-01: "Baseline accepts blank titles; harden normalized title policy." Classify it as a data-integrity hardening issue, not demonstrated cross-user access.
3. Predict the whitespace contrast and all denial/positive-control outcomes. Run:

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 -m unittest -v test_example
```

4. Preserve actual Python/SQLite versions, test output, reviewed symbols, and the invariant above as the review evidence. No database file remains because every test uses an in-memory connection.

### Hints

Look for the three predicates in the same UPDATE, not a prior read. Parameter binding and authorization answer different questions. Rejecting invalid input is insufficient if an earlier mutation already happened; inspect the unchanged-row assertions. A test that demonstrates the baseline accepts whitespace should pass as a characterization test, not appear as an unexplained broken suite.

### Solution and Expected Results

Seven test methods are expected to pass. Baseline accepts a whitespace title; fixed v2 rejects it. A legitimate rename trims outer whitespace and updates only row 1. Other-owner row 2, other-tenant row 3, and missing row 99 yield generic 404; absent principal yields 401. Wrong fields/types, boolean ID, 81-character title, and embedded newline yield 400 with rows unchanged. An 80-character title succeeds.

Review conclusion: ownership checks were present and remain intact. The concrete change is strict normalized title policy. Do not claim that cross-tenant access was possible in the baseline. The same SQL predicate provides the ownership boundary in both versions, and the tests check denial plus preserved allowed behavior.

### Acceptance, Troubleshooting, and Cleanup

- [ ] Produce the input-to-policy-to-sink trace and identify the missing production adapter boundary.
- [ ] Confirm safe baseline characterization, fixed rejection, and legitimate-owner success.
- [ ] Record the exact runtime versions and tests actually run without changing study status.

If imports fail, keep both files in the same fresh directory. If `sqlite3` is unavailable, the interpreter distribution lacks that optional build component; use an existing Python 3.12 distribution with SQLite support. No package install is part of the exercise. Delete the disposable directory and `__pycache__` after retaining synthetic evidence.

Author validation: static review only; tests not executed. No production HTTP integration, multi-connection concurrency, migrations, deployment config, advisory scanning, or full Unicode policy was verified.

## Related

- [[Web Roadmap#W7 Methodology|W7 Methodology]]

## References

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/) - review methodology.
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) - deny-by-default and authorization placement.
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) - syntax and semantic policy.
- [Python 3.12 sqlite3](https://docs.python.org/3.12/library/sqlite3.html) - placeholders, transactions, and runtime version.
- [SQLite UPDATE](https://www.sqlite.org/lang_update.html) - mutation predicates; a single statement is not every application's transaction strategy.
