---
title: "GraphQL Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# GraphQL Attacks

> [!abstract] TL;DR
> GraphQL attack paths arise from resolver-level authorization gaps and client-controlled query structure that can amplify backend work.

> [!info] Agent scope
> Resolver authorization; batching; aliases; introspection exposure; query cost; mutation and object access checks.

## Learn

```text
Teach GraphQL security as resolver authorization plus control of client-selected
work. Assume schemas, queries/mutations, variables, resolvers, and authentication.
Trace validation, execution, nested/direct object access, field projection,
aliases, fragments, batching, DataLoader caches, introspection, and partial errors.
Explain cost versus depth, list cardinality, per-operation and aggregate budgets,
mutation authorization, and why hiding a schema is not an access-control fix.
Review a real local GraphQL schema with a shared authorization helper and a small
persisted-operation registry; provide secure execution tests using synthetic data.
State registry limitations and what a general cost analyzer would need. Cite the
GraphQL spec and graphql-core docs, give questions/answers, and specify versions.
No enumeration, expensive-query payloads, theft, bypasses, scanning, or chains.
Do not edit files or claim unexecuted tests passed.
```

## Cheatsheet

> [!important] Defensive scope
> The lab executes only a closed registry of ordinary local operations against synthetic records. There is no HTTP server, schema enumeration, or resource-exhaustion query.

### Execution and Authorization

GraphQL validation checks that an operation conforms to the schema; it does not decide whether the caller may access a record. Root, nested, mutation, and global-node paths may reach the same object. Policy must follow the object/action, not only the first root resolver. Authentication at one endpoint does not authorize every field reachable from it.

| Surface | Required check | Limitation |
|---|---|---|
| Object resolver | Actor/tenant/object/action | Knowing a node ID is not permission |
| Nested relationship | Parent-child relation and child policy | Authorizing the parent alone can be insufficient |
| Mutation | Object and field update permission before effect | Schema type validation does not authorize a write |
| DataLoader/cache | Scope by request/identity or correctly keyed policy context | Global loaders can mix users' results |
| Aliases/batching | Account for every executed operation/field | One HTTP request can perform many backend actions |
| Introspection | Product exposure decision | Disabling it does not repair resolver authorization |

GraphQL responses can contain both `data` and `errors`; HTTP 200 does not imply full success. Nullability determines how errors propagate. Review whether denied fields expose partial metadata or internal exceptions. Mutations execute top-level fields serially within one operation, but that is not a cross-request transaction or authorization mechanism.

### Cost, Registry, and Tradeoffs

Depth alone misses wide alias sets and large lists. Cost analysis must account for selected fields, expanded fragments, directives/variables, list cardinality, resolver weights, and repeated/batched operations. Bound page sizes and aggregate cost per identity as well as per operation. Limit parsing bytes/tokens, execution time, backend queries, and response size.

A closed persisted-operation registry can sharply reduce structural freedom for a controlled client. Bind IDs to reviewed immutable documents and validate variables; an operation name supplied by the caller is not the same as a registry ID. Automatic persisted-query registration is not an allowlist if arbitrary users can register documents. Versioning the registry increases release coordination but simplifies cost review.

The fixture uses fixed scalar-returning operations with declared costs, not a general static analyzer. Aliases in one reviewed operation still pass through the same object policy. Batch limits apply before any execution to avoid partial side effects. An introspection operation is absent from the exposed registry, but the schema itself is not treated as secret.

### Versions and Evidence

Python 3.12 with graphql-core 3.2.6 supplies real schema parsing and execution. Pin library versions because minor graphql-core releases can track upstream GraphQL.js behavior changes. Framework HTTP adapters add separate parsing, authentication, batching, and error policies. Record operation registry ID/hash, cost, resolver denial category, and backend query counts without variable values or private results.

## Defense

Enforce shared object policy in every resolver/data-access path, authorize mutations before writing, and constrain field exposure. Use a reviewed registry where practical, otherwise a real cost analyzer plus runtime limits. Scope caches and errors correctly. Keep introspection policy separate from authorization and complexity controls.

## Labs

### Environment and Complete Files

Python 3.12 with graphql-core 3.2.6. No server, database, or network during tests. Review a proposal that protects only the direct resolver and accepts arbitrary client documents. The replacement centralizes policy and exposes three reviewed operations, with a bounded batch budget.

### File: requirements.txt

```text
graphql-core==3.2.6
```

### File: test_example.py

```python
import unittest
from graphql import GraphQLError, build_schema, graphql_sync


SCHEMA = build_schema("""
	type Document { id: ID!, title: String! }
	type Viewer { document(id: ID!): Document }
	type Query { document(id: ID!): Document, viewer: Viewer! }
	type Mutation { rename(id: ID!, title: String!): Document }
""")
OPERATIONS = {
	"read": (1, "query Read($id: ID!) { document(id: $id) { id title } }"),
	"paths": (3, "query Paths($id: ID!) { first: document(id: $id) { id } "
				  "second: document(id: $id) { id } viewer { document(id: $id) { id } } }"),
	"rename": (2, "mutation Rename($id: ID!, $title: String!) { "
				   "rename(id: $id, title: $title) { id title } }"),
}


def authorized_document(info, object_id):
	document = info.context["documents"].get(object_id)
	if document is None or document["owner"] != info.context["user"]:
		raise GraphQLError("Not permitted")
	return document


def resolve_document(source, info, id):
	return authorized_document(info, id)


def rename_document(source, info, id, title):
	document = authorized_document(info, id)
	if not 1 <= len(title) <= 80:
		raise GraphQLError("Invalid title")
	document["title"] = title
	return document


SCHEMA.type_map["Query"].fields["document"].resolve = resolve_document
SCHEMA.type_map["Query"].fields["viewer"].resolve = lambda source, info: {}
SCHEMA.type_map["Viewer"].fields["document"].resolve = resolve_document
SCHEMA.type_map["Mutation"].fields["rename"].resolve = rename_document


def execute_batch(context, requests):
	if not 1 <= len(requests) <= 2:
		raise ValueError("batch size")
	if any(operation not in OPERATIONS for operation, variables in requests):
		raise ValueError("unknown operation")
	if sum(OPERATIONS[operation][0] for operation, variables in requests) > 3:
		raise ValueError("aggregate cost")
	return [graphql_sync(SCHEMA, OPERATIONS[operation][1], context_value=context,
						 variable_values=variables)
			for operation, variables in requests]


class GraphqlTests(unittest.TestCase):
	def setUp(self):
		self.context = {"user": "ada", "documents": {
			"1": {"id": "1", "owner": "ada", "title": "Ada draft"},
			"2": {"id": "2", "owner": "grace", "title": "Grace draft"}}}

	def test_allowed_read_and_mutation(self):
		results = execute_batch(self.context, [("read", {"id": "1"}),
				   ("rename", {"id": "1", "title": "Reviewed"})])
		self.assertTrue(all(result.errors is None for result in results))
		self.assertEqual(self.context["documents"]["1"]["title"], "Reviewed")

	def test_direct_alias_and_nested_denial(self):
		result = execute_batch(self.context, [("paths", {"id": "2"})])[0]
		self.assertEqual(len(result.errors), 3)
		self.assertEqual(result.data, {"first": None, "second": None,
									   "viewer": {"document": None}})

	def test_denied_mutation_and_budget(self):
		result = execute_batch(self.context, [("rename", {"id": "2", "title": "Changed"})])[0]
		self.assertIsNotNone(result.errors)
		self.assertEqual(self.context["documents"]["2"]["title"], "Grace draft")
		with self.assertRaises(ValueError):
			execute_batch(self.context, [("paths", {"id": "1"}), ("read", {"id": "1"})])
		with self.assertRaises(ValueError):
			execute_batch(self.context, [("unregistered", {})])


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest -v test_example
```

On POSIX use `python3.12` and `.venv/bin/python`. Setup needs an approved package source. Hint: each alias is an execution path; inspect partial `data` as well as `errors`. Why is the batch budget checked before executing its first operation?

Solution: the same authorization helper protects root, nested, and mutation paths; the registry removes arbitrary document structure and prechecks aggregate work. Expected: three tests pass, three denied read paths return null with errors, denied mutation preserves the record, and over-budget/unknown operations never execute. This cost model is valid only for the fixed tiny registry, not general GraphQL or list-heavy schemas.

### Verification, Troubleshooting, and Cleanup

No installation/tests ran during authoring. Use the venv interpreter and avoid a local `graphql.py`. GraphQL returns execution errors in a result object; do not expect every denial to raise a Python exception. Remove the disposable directory/venv afterward. HTTP transport, multi-tenant identity, DataLoader isolation, general cost analysis, and production database atomicity remain integration requirements.

- [ ] Local GraphQL Attacks exercise: Review resolver policy and a closed operation registry.
- [ ] Boundary check: Run actual GraphQL execution, mutation-denial, and budget tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [GraphQL specification](https://spec.graphql.org/)
- [GraphQL authorization guidance](https://graphql.org/learn/authorization/)
- [GraphQL security guidance](https://graphql.org/learn/security/)
- [graphql-core 3 documentation](https://graphql-core-3.readthedocs.io/en/stable/)
