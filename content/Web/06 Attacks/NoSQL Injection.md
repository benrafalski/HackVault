---
title: "NoSQL Injection"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# NoSQL Injection

> [!abstract] TL;DR
> NoSQL injection lets attacker data become query operators, expressions, or structural fragments rather than validated values.

> [!info] Agent scope
> Operator and syntax injection; query object construction; type confusion; input schema enforcement.

## Learn

```text
Teach NoSQL injection as loss of ownership over query structure. Assume JSON,
HTTP parsing, document storage, and basic MongoDB filters. Distinguish operator
injection, string-expression construction, and scalar/object type confusion.
Trace duplicate keys, nested input, schema validation, query construction,
aggregation stages, database permissions, and result authorization. Compare
MongoDB query documents with Elasticsearch DSL without treating NoSQL as one
language. Explain explicit equality construction, server-owned tenant clauses,
strict schemas, bounded values, and why character removal is insufficient.
Use secure query-builder tests and ordinary synthetic records, not query payloads
or login demonstrations. Cover MongoDB version-sensitive scripting features,
evidence limits, and defense tradeoffs with primary sources and review questions.
No bypasses, theft, RCE, scanning, or chains; do not edit files or invent results.
```

## Cheatsheet

> [!important] Defensive scope
> The lab constructs safe filters and inspects calls to a fake collection. It does not execute attacker-controlled operators or connect to a database.

### Query Structure Is Authority

SQL placeholders are not the only data/code boundary. A document database query is a tree: field names, operators, stages, projections, and sort choices are structural instructions. Serializing an untrusted request object to JSON does not make that tree safe to execute. The application must own the structure and admit only validated values.

| Failure family | Prerequisite | Secure alternative |
|---|---|---|
| Operator injection | Caller controls query document nodes | Construct a fixed filter from scalar values |
| Syntax injection | Caller enters a string evaluated as an expression | Use a documented data query API; disable unneeded scripting |
| Type confusion | Parser accepts arrays/objects where scalar expected | Strict type checks before any driver call |
| Aggregation misuse | Caller chooses stages or field expressions | Fixed reviewed pipelines with bounded parameters |
| Tenant override | Client fields merged with trusted query scope | Derive tenant from authenticated context; never merge whole body |

Secure MongoDB filter fragment, with values already validated:

```python
filter_document = {"tenant": {"$eq": authenticated_tenant},
				   "display_name": {"$eq": validated_name}}
projection = {"_id": 0, "display_name": 1}
```

The operators above are fixed application code, not input. A user-supplied regular expression is another language and resource boundary; equality is preferable when the product requires exact matching. Escaping characters without a schema cannot establish ownership of a nested query tree.

### Versions, Evidence, and Limits

MongoDB 8.0 deprecates server-side JavaScript features such as `$where`, `$function`, and `$accumulator`; deprecation does not mean every deployment has disabled them. Confirm server version, feature use, and configuration. Database validation enforces stored document shape, not necessarily safe query input. MongoDB authentication and collection roles limit authority but do not validate application filters.

Elasticsearch DSL, Redis commands, and MongoDB filters are different APIs. Do not copy a MongoDB mitigation into another system without tracing its actual interpreter. ORM/ODM casting may coerce types; evaluate strictness in the installed version. Log rejected field names/types and query template IDs, not user records or authentication data. A driver error establishes malformed input, not a proven authorization failure.

## Defense

Accept a closed request schema, reject duplicate JSON fields and unknown properties, cap input sizes, and construct the driver request explicitly. Keep projection, tenant scope, and permitted operations server-owned. Enforce object authorization independently. Disable unused scripting, constrain query duration/result size, and test that rejected input never invokes the collection API.

## Labs

### Environment and Objectives

Python 3.12 stdlib only. All data is in one file; no MongoDB, packages, services, or network. Review a proposal that merges the request body into a filter. The replacement accepts only `name`, then creates fixed equality nodes. Tests observe the exact driver call and verify early rejection, not database semantics.

### File: test_example.py

```python
import json
import unittest
from unittest.mock import Mock


def unique_fields(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise ValueError("duplicate field")
		result[key] = value
	return result


def lookup(collection, authenticated_tenant, body):
	if type(body) is not str or len(body) > 1024:
		raise ValueError("body size")
	document = json.loads(body, object_pairs_hook=unique_fields)
	if type(document) is not dict or set(document) != {"name"}:
		raise ValueError("request fields")
	name = document["name"]
	if type(name) is not str or not 1 <= len(name) <= 80:
		raise ValueError("name must be a bounded scalar")
	if type(authenticated_tenant) is not str or not authenticated_tenant:
		raise ValueError("trusted tenant required")
	query = {"tenant": {"$eq": authenticated_tenant}, "display_name": {"$eq": name}}
	return collection.find_one(query, {"_id": 0, "display_name": 1})


class QueryShapeTests(unittest.TestCase):
	def setUp(self):
		self.collection = Mock()
		self.collection.find_one.return_value = {"display_name": "Ada"}

	def test_scalar_query(self):
		self.assertEqual(lookup(self.collection, "north", '{"name":"Ada"}'),
						 {"display_name": "Ada"})
		self.collection.find_one.assert_called_once_with(
			{"tenant": {"$eq": "north"}, "display_name": {"$eq": "Ada"}},
			{"_id": 0, "display_name": 1},
		)

	def test_reject_before_driver(self):
		bodies = ['{"name":[]}', '{"name":{"label":"Ada"}}',
				  '{"name":"Ada","tenant":"south"}',
				  '{"name":"Ada","name":"Grace"}', '{"name":null}']
		for body in bodies:
			with self.subTest(body=body), self.assertRaises(ValueError):
				lookup(self.collection, "north", body)
		self.collection.find_one.assert_not_called()

	def test_legitimate_punctuation(self):
		lookup(self.collection, "north", json.dumps({"name": "O'Neil"}))
		query = self.collection.find_one.call_args.args[0]
		self.assertEqual(query["display_name"], {"$eq": "O'Neil"})


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: the mock is an observation point, not an emulated database. Which keys can the caller choose in the final query? What happens before the first collection method call?

Solution: strict JSON shape keeps caller input in a scalar equality value; the server supplies tenant and projection. Expected: three tests pass, five invalid documents make no driver call, and punctuation remains intact. No database authorization, query planner, collation, or ODM behavior is established by these tests.

### Verification, Troubleshooting, and Cleanup

Not executed during authoring. Run in the file's directory and avoid filenames `json.py` or `unittest.py`. No installation is needed. A real collection test should use the deployed driver/server version and synthetic fixtures, but is outside this offline lab. Remove the disposable directory afterward.

- [ ] Local NoSQL Injection exercise: Review request schema and fixed query structure.
- [ ] Boundary check: Verify invalid shapes never call the collection API.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [MongoDB equality query operator](https://www.mongodb.com/docs/manual/reference/operator/query/eq/)
- [MongoDB server-side JavaScript](https://www.mongodb.com/docs/manual/core/server-side-javascript/)
- [MongoDB schema validation](https://www.mongodb.com/docs/manual/core/schema-validation/)
- [Python JSON decoder behavior](https://docs.python.org/3.12/library/json.html)
