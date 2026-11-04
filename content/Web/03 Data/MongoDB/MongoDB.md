---
title: "MongoDB"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[MongoDB Security]]"
updated: 2026-11-03
---
# MongoDB

> [!abstract] TL;DR
> Construct query objects explicitly; do not merge arbitrary request JSON into filters. Validate both types and allowed operators.

> [!info] Agent scope
> Documents and collections; query operators; aggregation; indexes; authentication; application query construction.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me MongoDB 8.0 application engineering assuming JSON, indexes and HTTP.
Explain BSON types, documents, embedding versus references, collection validators,
query operators, aggregation stages, compound/multikey indexes and explain plans.
Trace authentication database, roles, explicit typed query construction, atomic
updates, read/write concerns and replica-set transaction requirements. Work through
a complete authenticated local schema/seed/query lab, including malformed types,
query cost and a conditional inventory update. Contrast standalone limitations
with transaction retry semantics. Use public primary sources and version caveats;
teach here with worked answers, not file edits or fabricated execution evidence.
```

## Cheatsheet

### Documents, Types, and Atomicity

BSON distinguishes strings, dates, ObjectIds, int32/int64, doubles and Decimal128. An ObjectId and its textual representation are not interchangeable. Store instants as BSON Date and exact decimal quantities as Decimal128 or appropriate integer units. Validation is still necessary in a flexible-schema system; `validationAction: "error"` rejects invalid writes, while `warn` only observes them.

Embed data that is bounded and updated atomically together. References avoid unbounded document growth but require additional queries or `$lookup`. Documents have a 16 MiB BSON size limit; arrays that grow forever eventually hurt size, index and update behavior. A single-document conditional update is atomic:

```javascript
db.inventory.updateOne(
	{_id: "book", available: {$gte: 1}},
	{$inc: {available: -1}}
);
```

Require `matchedCount===1`; a preceding read and unconditional decrement is not equivalent. `updateMany` is not an all-or-nothing transaction across documents. Multi-document transactions require a replica set or sharded deployment, not a standalone server. Use the driver's transaction helper with bounded retry handling; do not repeat external side effects inside retryable callbacks. Set transaction-level concerns deliberately and understand ambiguous commit outcomes/idempotency.

### Queries, Indexes, and Aggregation

```javascript
db.orders.find({tenant: 7, state: "open"}, {_id: 1, total: 1})
	.sort({createdAt: -1, _id: -1}).limit(20).maxTimeMS(1000);
db.orders.createIndex({tenant: 1, state: 1, createdAt: -1, _id: -1});
db.orders.aggregate([
	{$match: {tenant: 7}},
	{$group: {_id: "$state", total: {$sum: "$total"}}},
	{$sort: {_id: 1}}
], {maxTimeMS: 1000, allowDiskUse: false});
```

Fragment fields must exist with consistent types. Put selective `$match` early; the optimizer may reorder some stages but cannot turn every pipeline into an indexed lookup. Equality/sort/range index design depends on query selectivity and ordering. Inspect `explain("executionStats")`, especially keys/documents examined versus rows returned; it actually executes work. A scan on a tiny fixture is normal.

Array indexes become multikey and have compound-index constraints. A compound unique index can enforce tenant-local names; missing/null values and partial index filters change uniqueness behavior. Collation affects equality/sort and must match relevant index use. `{field:null}` can match null or missing; distinguish with `$exists` when that matters.

### Application Boundary and Operations

Construct filters from validated scalars, never merge arbitrary request JSON or accept a request-supplied pipeline. `$set` only approved fields. A projection reduces fields but is not row authorization. Limit page size, query time, aggregation disk use and connection pools. Large `skip` pagination becomes expensive; prefer a deterministic keyset cursor with a unique tie-breaker.

Users authenticate in an `authSource` database; their roles may grant actions elsewhere. Restrict roles to named collections and separate admin credentials. Remote connections need certificate/hostname verification and network policy. A majority write concern improves replicated durability but is not a substitute for backups; read preference and read concern determine what a client may observe. MongoDB 8.0 deprecates server-side JavaScript features; ordinary queries should not need them.

## Gotchas

NoSQL does not mean no injection. Sanitizing a few character sequences is not a substitute for constructing a typed query.

## Labs

### Environment and Complete Files

PowerShell, Docker Linux containers and official `mongo:8.0`, which includes mongosh. Record image digest and `db.version()`. **Not executed here.** Standalone authentication is enabled through bootstrap environment variables; no ports or host directories are exposed. This lab intentionally validates single-document atomicity, not replicated durability.

### File: setup.js
```javascript
const shop = db.getSiblingDB("shop");
shop.createCollection("inventory", {
	validator: {$jsonSchema: {
		bsonType: "object", required: ["_id", "available", "label"],
		properties: {
			_id: {bsonType: "string"}, available: {bsonType: "int", minimum: 0},
			label: {bsonType: "string", maxLength: 80}
		}
	}}, validationLevel: "strict", validationAction: "error"
});
shop.inventory.insertMany([
	{_id: "book", available: Int32(3), label: "O'Reilly"},
	{_id: "pen", available: Int32(0), label: "synthetic"}
]);
shop.inventory.createIndex({label: 1}, {unique: true});
shop.createCollection("operator_only");
shop.operator_only.insertOne({_id: 1, label: "fixture"});
shop.createRole({role: "inventoryApp", privileges: [
	{resource: {db: "shop", collection: "inventory"}, actions: ["find", "insert", "update"]}
], roles: []});
shop.createUser({user: "app", pwd: "App-lab-only-80!", roles: ["inventoryApp"]});
```

### File: test.js
```javascript
const shop = db.getSiblingDB("shop");
function check(condition, message) { if (!condition) throw new Error(message); }
function failsCode(operation, code) {
	let actual;
	try { operation(); } catch (error) { actual = error.code; }
	check(actual === code, `expected code ${code}, got ${actual}`);
}
function findLabel(label) {
	if (typeof label !== "string" || label.length > 80) throw new TypeError("label");
	return shop.inventory.find({label}, {_id: 1}).limit(20).maxTimeMS(1000).toArray();
}
check(findLabel("O'Reilly")[0]._id === "book", "literal round trip");
let rejected = false;
try { findLabel({unexpected: "object"}); } catch (error) { rejected = error instanceof TypeError; }
check(rejected, "scalar validation");
failsCode(() => shop.inventory.insertOne({_id: "bad", available: "three", label: "bad"}), 121);
check(shop.inventory.updateOne({_id: "book", available: {$gte: 1}}, {$inc: {available: Int32(-1)}}).matchedCount === 1, "reserve");
check(shop.inventory.updateOne({_id: "pen", available: {$gte: 1}}, {$inc: {available: Int32(-1)}}).matchedCount === 0, "empty stock");
const totals = shop.inventory.aggregate([{$group: {_id: null, total: {$sum: "$available"}}}], {maxTimeMS: 1000}).toArray();
check(totals[0].total === 2, "aggregation");
failsCode(() => shop.operator_only.findOne({}), 13);
const session = db.getMongo().startSession();
try {
	session.startTransaction();
	failsCode(() => session.getDatabase("shop").inventory.findOne({_id: "book"}), 20);
} finally {
	session.endSession();
}
printjson(shop.inventory.find({label: "O'Reilly"}).explain("executionStats"));
print("PASS: schema, literal, atomic update, role and standalone transaction boundary");
```

```powershell
docker run --name w3-mongo-tech -d -e MONGO_INITDB_ROOT_USERNAME=operator -e MONGO_INITDB_ROOT_PASSWORD=Admin-lab-only-80! mongo:8.0
docker exec w3-mongo-tech mongosh --quiet -u operator -p Admin-lab-only-80! --authenticationDatabase admin --eval 'db.runCommand({ping:1})'
docker cp setup.js w3-mongo-tech:/tmp/setup.js
docker cp test.js w3-mongo-tech:/tmp/test.js
docker exec w3-mongo-tech mongosh --quiet -u operator -p Admin-lab-only-80! --authenticationDatabase admin --file /tmp/setup.js
docker exec w3-mongo-tech mongosh --quiet -u app -p App-lab-only-80! --authenticationDatabase shop --file /tmp/test.js
```

### Objectives, Hints, and Solution

Retry readiness manually. Predict validator code 121, authorization code 13 and unsupported-transaction code 20. Explain why atomic decrement needs no multi-document transaction. Expected: stock becomes two, empty stock is unchanged, and all checks pass. Hint: authentication database is `shop` for app, `admin` for bootstrap. Do not change authSource just to suppress an authorization error.

### Troubleshooting and Cleanup

The test mutates stock and is intended for a fresh fixture; recreate the container to repeat. A changed engine error code warrants inspection, not accepting every failure. Replica-set transaction success and TLS are unexecuted deployment requirements, not results of this standalone lab. Cleanup only the lab container and anonymous data volumes:

```powershell
docker rm -f -v w3-mongo-tech
```

- [ ] Local MongoDB exercise: Create a collection with a schema validator and limited user. Query by a validated scalar field, add an index, and test malformed types and unauthorized collections.
- [ ] Boundary check: Send an object where the API expects a username string and verify schema rejection before querying. Confirm the app user cannot read an unrelated collection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[NoSQL Injection]]
- [[MongoDB Security]]

## References

- [Schema validation](https://www.mongodb.com/docs/manual/core/schema-validation/)
- [Atomicity and transactions](https://www.mongodb.com/docs/manual/core/write-operations-atomicity/)
- [Compound indexes](https://www.mongodb.com/docs/manual/core/indexes/index-types/index-compound/)
