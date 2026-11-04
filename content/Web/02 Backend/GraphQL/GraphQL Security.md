---
title: "GraphQL Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[GraphQL]]"
updated: 2026-11-03
---
# GraphQL Security

> [!abstract] TL;DR
> Resolver authorization gaps, cross-request cache reuse, and unbounded query complexity can leak data or exhaust backend resources.

> [!info] Agent scope
> Security of: Schemas; resolvers; queries and mutations; variables; introspection; batching; authorization; query cost controls. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Resolver authorization gaps, cross-request cache reuse, and unbounded query complexity can leak data or exhaust backend resources.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach GraphQL defensive design at expert depth, assuming schema/resolver and HTTP
knowledge. Trace verified identity into request context, loaders, direct object
lookup, nested relationships, mutations and subscriptions. Explain field versus
object policy, null propagation and error redaction. Compare open-query weighted
cost analysis with persisted-operation admission; include variable cardinality,
aliases, fragment expansion, batching, response limits and database deadlines.
Show complete graphql-core regression fixtures with two synthetic identities,
a harmless over-restrictive baseline, a concrete fix and positive controls.
Cover request-local loader caches, mutation invalidation, introspection tradeoffs,
and safe telemetry. Cite GraphQL specifications and implementation docs. Do not
provide exploitation payloads, production targeting or bypass walkthroughs.
```

## Cheatsheet

### Trust Boundaries

| Surface | Root cause | Control |
|---|---|---|
| Root and relationship fields | Policy only on one entry path | Shared authorized repository operation, including list filters |
| Mutations | Schema validation mistaken for business permission | Action and object policy, writable-field allowlists, transaction |
| Loaders | Global cache keyed only by object ID | Request-scoped loader bound to identity; invalidate after writes |
| Aliases/fragments | Counting HTTP requests or raw field tokens | Expanded execution-aware cost, variable bounds, deadlines |
| Lists | Pagination argument accepted without cap | Validate min/max before database access; bound output |
| Errors | Internal exception details exposed | Stable external code/message, correlation ID, private diagnostics |
| Introspection | Hidden schema treated as security | Independent authorization; explicitly decide tooling exposure |

A root resolver returning an object does not authorize every field on it. Sensitive nested fields need policy too; default dictionary/attribute resolvers otherwise expose any declared schema field. Filter lists before pagination and counts. Use the same rule for global-node lookup, relationships, exports and background work. Batch loaders must preserve input-key order; missing and denied results need deliberate treatment.

### Admission and Cost

For open queries, parse with a byte/token ceiling, validate, select the operation, coerce variables, expand fragments with cycle protection, and estimate weighted work including list cardinality. A flat depth limit misses wide trees; AST node counts miss repeated fragment use and runtime fan-out. Bound database work and response bytes even after admission. Cancellation must reach downstream I/O; aborting response serialization does not cancel a running SQL query.

Persisted operations are a different policy: accept only registered documents, with defined variable shapes and budgets. Automatic persisted-query registration is not an allowlist if arbitrary clients can register new documents. The lab registry has one read-only operation and no upload, mutation, HTTP-array batching or free-form query endpoint. Its simple cost formula is valid only for this known shape, not a generic analyzer.

### Detection and Defense

Measure admitted cost, operation identifier, principal surrogate, resolver/database latency, row count, error code and cancellation outcome. Do not routinely log full variables or query literals. Check partial responses, not just HTTP status. A nullable denial preserves siblings; a non-null denial can propagate to `data: null`. This availability choice should not expose object existence through detailed error text. Cookie transport also needs CSRF defenses; restricting introspection does not provide them.

## Detection and Defense

Apply object/field policies, request-scoped batching, pagination and complexity limits, and production error redaction. Log operation names, cost, denials, and resolver latency.

## Labs

### Persisted Read With Shared Policy

**Requirements:** Python 3.12, graphql-core 3.2.6, pytest 8.3.5. Empty temporary directory, one file, inline fixtures. In-process execution only; all runtime results **unverified**. `actor` is trusted test context after authentication, not an accepted client identity field.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install graphql-core==3.2.6 pytest==8.3.5
.venv\Scripts\python -m pytest -q test_graphql_policy.py
```

**Objective:** admit bounded work, use one policy on direct and relationship access, and repair an availability regression without relaxing ownership. **Hint:** budget counts the selected projection as well as root lookup.

### File: test_graphql_policy.py

```python
import pytest
from graphql import GraphQLError, build_schema, graphql_sync


DOCUMENTS = {"read-v1": '''query Read($id: ID!, $limit: Int!) {
	direct: note(id: $id) { id text }
	me { notes(limit: $limit) { id text } }
}'''}


def build_gateway(budget):
	schema = build_schema('''
		type Note { id: ID!, text: String! }
		type User { notes(limit: Int!): [Note!]! }
		type Query { note(id: ID!): Note, me: User! }
	''')
	records = {"1": dict(id="1", owner="alice", text="alpha"),
			   "2": dict(id="2", owner="bob", text="beta")}

	def load(note_id, actor):
		record = records.get(note_id)
		return record if record and record["owner"] == actor else None

	def direct(parent, info, id):
		record = load(id, info.context["actor"])
		if record is None:
			raise GraphQLError("not available", extensions={"code": "NOT_AVAILABLE"})
		return record

	def listing(parent, info, limit):
		if not 1 <= limit <= 2:
			raise GraphQLError("invalid limit")
		visible = [load(note_id, info.context["actor"]) for note_id in records]
		return [record for record in visible if record is not None][:limit]

	schema.get_type("Query").fields["note"].resolve = direct
	schema.get_type("Query").fields["me"].resolve = lambda parent, info: {}
	schema.get_type("User").fields["notes"].resolve = listing

	def execute(operation, variables, actor):
		if actor not in {"alice", "bob"}:
			raise ValueError("identity required")
		if operation not in DOCUMENTS:
			raise ValueError("operation not registered")
		if not isinstance(variables, dict) or set(variables) != {"id", "limit"}:
			raise ValueError("invalid variables")
		limit = variables["limit"]
		if type(limit) is not int or not 1 <= limit <= 2:
			raise ValueError("invalid limit")
		if not isinstance(variables["id"], str) or len(variables["id"]) > 16:
			raise ValueError("invalid id")
		if 5 + 2 * limit > budget:
			raise ValueError("cost exceeds budget")
		return graphql_sync(schema, DOCUMENTS[operation], variable_values=variables,
							context_value={"actor": actor})

	return execute


def test_admission_and_policy():
	variables = {"id": "1", "limit": 1}
	baseline = build_gateway(6)
	with pytest.raises(ValueError, match="cost"):
		baseline("read-v1", variables, "alice")
	execute = build_gateway(7)
	own = execute("read-v1", variables, "alice")
	assert own.errors is None
	assert own.data["direct"] == {"id": "1", "text": "alpha"}
	assert own.data["me"]["notes"] == [{"id": "1", "text": "alpha"}]
	foreign = execute("read-v1", {"id": "2", "limit": 1}, "alice")
	assert foreign.data["direct"] is None
	assert foreign.errors[0].extensions["code"] == "NOT_AVAILABLE"
	assert foreign.data["me"]["notes"] == [{"id": "1", "text": "alpha"}]
	bob = execute("read-v1", {"id": "2", "limit": 1}, "bob")
	assert bob.data["direct"]["text"] == "beta"
	with pytest.raises(ValueError, match="cost"):
		execute("read-v1", {"id": "1", "limit": 2}, "alice")
	with pytest.raises(ValueError, match="registered"):
		execute("unknown", variables, "alice")
	with pytest.raises(ValueError, match="limit"):
		execute("read-v1", {"id": "1", "limit": True}, "alice")
```

### Solution and Acceptance

Raise the baseline budget from 6 to 7, the minimum for the known one-item projection. Expected: one passing test; ordinary own reads resume, two-item requests remain over budget, direct foreign reads return null/error and relationships omit foreign records. Bob's subsequent request proves identity is not retained from Alice. No global loader/cache exists in this fixture.

Troubleshooting: install `graphql-core` rather than `graphql`; rejected admission raises `ValueError` before execution, whereas resolver denial is in `ExecutionResult.errors`. Reset by recreating the gateway. Cleanup: remove the temporary environment/files. Transport authentication, open-query analysis, database deadlines and distributed quotas require separate integration checks.

- [ ] Local GraphQL exercise: Build a small schema with users and owned notes. Query nested fields, repeat fields with aliases, and test a denied object through every available relationship.
- [ ] Boundary check: Reach another synthetic user's note both directly and through a parent relationship; require identical denial. Submit a bounded over-budget query and verify controlled rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[GraphQL Attacks]]
- [[GraphQL]]

## References

- [Official documentation or primary training reference](https://graphql.org/learn/security/)
