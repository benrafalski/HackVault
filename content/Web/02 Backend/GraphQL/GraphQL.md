---
title: "GraphQL"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[GraphQL Security]]"
updated: 2026-11-03
---
# GraphQL

> [!abstract] TL;DR
> Authorize in data access/resolvers, validate inputs, bound depth and cost, and scope loaders per request/identity. Introspection controls do not replace authorization.

> [!info] Agent scope
> Schemas; resolvers; queries and mutations; variables; introspection; batching; authorization; query cost controls.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach GraphQL execution and API design at expert depth. Assume JSON, HTTP, Python
and database knowledge. Trace lexing/parsing, schema validation, operation selection,
variable coercion, resolver execution, completion and null propagation. Explain
input/output types, nullability, lists, enums, aliases, fragments, directives,
queries, mutations, introspection and schema evolution. Use graphql-core 3.2
examples with actual schema execution. Contrast serial root mutation fields with
transactions and query concurrency. Show request-scoped batching and identity-aware
caches, ownership checks on direct and relationship paths, depth versus weighted
cost, pagination bounds and deadlines. Give complete small tests and ask me to
predict data/errors/resolver calls. Separate the GraphQL language from HTTP
transport conventions. Cite the specification and library docs; no exploit payloads.
```

## Cheatsheet

### Execution Contract

`source -> AST -> schema validation -> operation selection -> variable coercion -> resolve -> complete -> data/errors`. Syntax/type errors precede execution. A resolver receives a parent value, field arguments and request context; context should hold an already-verified principal and request-local loaders. A schema describes allowed shapes, not ownership or business rules.

| Construct | Meaning | Failure/decision |
|---|---|---|
| `String` / `String!` | Nullable / non-null | Non-null failure propagates to nearest nullable ancestor |
| `[Note!]!` | Non-null list of non-null notes | One failed item can null the entire list and propagate further |
| `ID!` variable | Required opaque identifier input | Not proof of authorization; string/numeric input coercion differs from domain validation |
| Alias | Response key distinct from field name | Two aliases can execute a resolver twice |
| Fragment | Reusable selection | Cost analysis must account for expansion, cycles and type conditions |
| Mutation | Root fields execute serially | Nested fields are not a transaction; previous side effects may survive an error |
| Introspection | Schema metadata through `__schema`, `__type` | Hiding it is not an access policy; `__typename` is distinct |

Variables keep data out of query text but do not validate URL destinations, SQL semantics or ownership. Custom scalars need explicit parse/serialize rules. The default field resolver can read dictionary keys/attributes; deliberately choose which fields enter the schema. Adding required input fields breaks old clients; adding enum values can break exhaustive generated-client switches.

### Batching, Caching and Cost

Resolver N+1: one list query plus one owner query per item. A request-scoped DataLoader groups keys and returns results in exactly input-key order, including missing entries. Identity belongs in the loader scope or key; never share a user-specific cache across requests by ID alone. Clear/update request caches after mutations. HTTP array batching, loader batching and repeated aliased selections are different mechanisms.

Depth alone misses wide aliases and large lists. Model work as `field_weight + bounded_cardinality * child_cost`, including variable values and fragment expansion. Validate list limits in resolvers even with preflight cost analysis. Add maximum source bytes/tokens, operation count, response bytes, database deadline, and concurrency controls. Reject unsupported transport batching explicitly. A persisted-operation registry can bound the document set but still requires variable limits and authorization.

### Errors and Transport

An execution result can contain both `data` and `errors`; an HTTP `200` alone is not success. Error `path` uses response aliases and list indices. Validation errors have no executed data. Redact internal exception messages, retain a correlation ID, and log internal detail separately. The lab executes in process and does not claim HTTP status/media-type compliance. Production adapters must define GET/POST behavior, operation-name selection, content negotiation, authentication, and CSRF handling for cookie credentials.

## Gotchas

HTTP 200 may contain GraphQL errors alongside partial data. Disabling introspection does not make an otherwise exposed schema safe.

## Labs

### Real Schema Execution

**Requirements:** Python 3.12, graphql-core 3.2.6, pytest 8.3.5. Empty temporary directory; only the following file. The library version tracks GraphQL.js 16-era APIs, not every draft specification feature. No server/database required. Execution is **unverified**.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install graphql-core==3.2.6 pytest==8.3.5
.venv\Scripts\python -m pytest -q test_graphql_contract.py
```

**Objective:** predict variable rejection, alias results, mutation ordering, relationship filtering and introspection. **Hint:** inspect the nullable root `note` versus the non-null `notes` list.

### File: test_graphql_contract.py

```python
from graphql import GraphQLError, build_schema, graphql_sync


def make_schema():
	schema = build_schema('''
		type Note { id: ID!, text: String! }
		type User { id: ID!, notes(limit: Int! = 2): [Note!]! }
		type Query { me: User!, note(id: ID!): Note }
		type Mutation { rename(id: ID!, text: String!): Note }
	''')
	notes = {"1": dict(id="1", owner="alice", text="alpha"),
			 "2": dict(id="2", owner="bob", text="beta")}

	def owned(note_id, actor):
		note = notes.get(note_id)
		if note is None or note["owner"] != actor:
			raise GraphQLError("not available")
		return note

	def get_note(parent, info, id):
		return owned(id, info.context["actor"])

	def user_notes(parent, info, limit):
		if not 1 <= limit <= 2:
			raise GraphQLError("limit must be 1..2")
		return [note for note in notes.values()
				if note["owner"] == info.context["actor"] == parent["id"]][:limit]

	def rename(parent, info, id, text):
		note = owned(id, info.context["actor"])
		if not 1 <= len(text) <= 40:
			raise GraphQLError("text must be 1..40 characters")
		note["text"] = text
		return note

	schema.get_type("Query").fields["me"].resolve = lambda parent, info: {
		"id": info.context["actor"]}
	schema.get_type("Query").fields["note"].resolve = get_note
	schema.get_type("User").fields["notes"].resolve = user_notes
	schema.get_type("Mutation").fields["rename"].resolve = rename
	return schema


def test_execution():
	schema = make_schema()

	def run(source, variables=None):
		return graphql_sync(schema, source, variable_values=variables,
							context_value={"actor": "alice"})

	result = run('query Read($id: ID!) { note(id: $id) { id text } }', {"id": "1"})
	assert result.errors is None
	assert result.data == {"note": {"id": "1", "text": "alpha"}}
	invalid = run('query Read($id: ID!) { note(id: $id) { id } }', {})
	assert invalid.data is None and invalid.errors
	partial = run('{ own: note(id:"1") { text } other: note(id:"2") { text } }')
	assert partial.data == {"own": {"text": "alpha"}, "other": None}
	assert partial.errors[0].path == ["other"]
	assert run('{ me { notes { id } } }').data == {"me": {"notes": [{"id": "1"}]}}
	changed = run('mutation { first: rename(id:"1", text:"one") { text } '
				  'second: rename(id:"1", text:"two") { text } }')
	assert changed.data == {"first": {"text": "one"}, "second": {"text": "two"}}
	assert run('{ note(id:"1") { text } }').data["note"]["text"] == "two"
	assert run('{ __schema { queryType { name } } }').data == {
		"__schema": {"queryType": {"name": "Query"}}}
	overflow = run('{ me { notes(limit:3) { id } } }')
	assert overflow.data is None and overflow.errors
```

### Solution and Acceptance

Expected: one passing test. Required-variable failure occurs before resolvers; the foreign nullable root is null with an error; list output contains only Alice's note. Serial root mutations produce `one`, then `two`; this is not rollback semantics. The invalid limit bubbles through non-null `notes` and `me`, leaving `data` null. Repair an intentionally over-restrictive limit ceiling of 1 back to 2 and repeat the normal list request to confirm availability.

Troubleshooting: install `graphql-core`, not an unrelated package named `graphql`. The schema is fresh per test; context is per execution. Cleanup: remove the temporary directory/environment. HTTP adapter, TLS, database batching and production cost enforcement are not validated by this lab.

- [ ] Local GraphQL exercise: Build a small schema with users and owned notes. Query nested fields, repeat fields with aliases, and test a denied object through every available relationship.
- [ ] Boundary check: Reach another synthetic user's note both directly and through a parent relationship; require identical denial. Submit a bounded over-budget query and verify controlled rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[GraphQL Attacks]]
- [[GraphQL Security]]

## References

- [GraphQL execution](https://graphql.org/learn/execution/)
- [GraphQL specification](https://spec.graphql.org/October2021/)
- [GraphQL-core documentation](https://graphql-core-3.readthedocs.io/en/stable/)
- [GraphQL security and demand control](https://graphql.org/learn/security/)
