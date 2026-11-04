---
title: "MongoDB Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[MongoDB]]"
updated: 2026-11-03
---
# MongoDB Security

> [!abstract] TL;DR
> Operator injection and overbroad service privileges can bypass intended filters or expose entire collections.

> [!info] Agent scope
> Security of: Documents and collections; query operators; aggregation; indexes; authentication; application query construction. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Operator injection and overbroad service privileges can bypass intended filters or expose entire collections.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive MongoDB 8.0 security assuming JSON, indexes and web identity.
Distinguish scalar data from query operators and aggregation stages; explain
typed input validation, explicit filters/projections, trusted tenant predicates,
collection validators and narrow roles. Cover authSource, TLS, network exposure,
query budgets, regex cost, pagination and server-side JavaScript deprecation.
Build an authenticated synthetic read-only policy lab with an excessive-update
baseline, least-privilege fix, denied collection test and allowed scalar read.
No operator exploitation, data theft or escalation. Include exact fixtures,
primary sources, failure diagnoses and version caveats; teach without edits or
fabricated execution results.
```

## Cheatsheet

### Query Shape Is Code

Passing `request.body` directly to `find()` lets the client choose query structure. A scalar field and an object are not interchangeable, even when both parse as JSON. Validate type, length, allowed keys and numeric bounds before constructing a new filter. Do not recursively strip a few special characters and assume the remaining structure is authorized.

```javascript
function accountFilter(authenticatedTenant, body) {
	if (!body || Array.isArray(body) || typeof body !== "object" ||
			Object.keys(body).some(key => key !== "username") ||
			typeof body.username !== "string" ||
			body.username.length < 1 || body.username.length > 80) {
		throw new TypeError("username string required");
	}
	return {tenant: authenticatedTenant, username: body.username};
}
```

The tenant is injected by trusted server context. Never spread a later client object over that filter. Use explicit `$set` fields for updates; forbid client-selected pipelines, collection names and projection fields. A collection validator protects stored documents, not the shape or authorization of read filters. MongoDB collection roles do not provide general per-document tenant isolation.

### Role and Resource Controls

Custom roles can grant only `find` on one named collection. Built-in `read` spans a database; `readWrite` includes mutation capabilities unnecessary for a reporting service. Avoid `root`, user administration, `bypassDocumentValidation` and cluster administration in app credentials. Rotate credentials separately from bootstrap secrets; specify the correct authentication database.

Use verified TLS and firewall rules for real remote connections. Do not treat authentication as a reason to expose a broker/database port publicly. Cap `limit`, `maxTimeMS`, page size, body size and concurrent cursors. Restrict regex input or use fixed equality searches; an index and maxTimeMS do not make every regex cheap. `$lookup` and large sorts can amplify work even for authorized input. `allowDiskUse:false` bounds spill behavior but may cause legitimate queries to fail; measure and index appropriately.

Read/write concerns govern consistency/durability, not tenant authorization. Transactions require replica sets/sharded clusters and cannot repair missing filters. MongoDB 8.0 deprecates server-side JavaScript functions such as `$where`/`$function`; new application query APIs should not expose them at all. Never give users direct query consoles over application credentials.

## Detection and Defense

Record validation rejection categories, authorization failures (code 13), slow queries and examined/returned document ratios. A syntax error, network timeout or empty cursor is not proof of correct authorization. Profile selectively because profiler/log data can contain sensitive filters. Database auditing availability depends on deployment/edition; application policy logs remain necessary. Review role definitions and network exposure after migrations.

## Labs

### Environment and Complete Files

PowerShell, Docker Linux containers, `mongo:8.0` and bundled mongosh. Record resolved digest/version. **Not executed here.** No port publication or host mounts. The baseline uses a no-match UPDATE, so it demonstrates an excessive capability without modifying any record.

### File: setup.js
```javascript
const appdb = db.getSiblingDB("appdb");
appdb.createCollection("users", {
	validator: {$jsonSchema: {bsonType: "object", required: ["tenant", "username"], properties: {
		tenant: {bsonType: "int"}, username: {bsonType: "string", maxLength: 80}
	}}}, validationAction: "error"
});
appdb.users.insertMany([
	{_id: 1, tenant: Int32(7), username: "O'Reilly"},
	{_id: 2, tenant: Int32(8), username: "other fixture"}
]);
appdb.users.createIndex({tenant: 1, username: 1}, {unique: true});
appdb.createCollection("operator_only");
appdb.operator_only.insertOne({_id: 1, label: "synthetic"});
appdb.createRole({role: "reporter", privileges: [
	{resource: {db: "appdb", collection: "users"}, actions: ["find", "update"]}
], roles: []});
appdb.createUser({user: "app", pwd: "App-lab-only-80!", roles: ["reporter"]});
```

### File: test.js
```javascript
const appdb = db.getSiblingDB("appdb");
function check(condition, message) { if (!condition) throw new Error(message); }
let queries = 0;
function lookup(body) {
	if (!body || Array.isArray(body) || typeof body !== "object" ||
			Object.keys(body).some(key => key !== "username") ||
			typeof body.username !== "string" || body.username.length < 1 || body.username.length > 80) {
		throw new TypeError("username string required");
	}
	queries += 1;
	return appdb.users.find({tenant: 7, username: body.username}, {_id: 1, username: 1})
		.limit(10).maxTimeMS(1000).toArray();
}
for (const body of [{username: {unexpected: "object"}}, {username: "valid", tenant: 8}]) {
	let rejected = false;
	try { lookup(body); } catch (error) { rejected = error instanceof TypeError; }
	check(rejected, "input shape must fail");
}
check(queries === 0, "reject before querying");
const rows = lookup({username: "O'Reilly"});
check(rows.length === 1 && rows[0]._id === 1, "allowed literal read");
let forbiddenCollection;
try { appdb.operator_only.findOne({}); } catch (error) { forbiddenCollection = error.code; }
check(forbiddenCollection === 13, "unrelated collection denial");
let updateCode;
try {
	appdb.users.updateOne({_id: "nonexistent-fixture"}, {$set: {username: "no mutation"}});
} catch (error) { updateCode = error.code; }
check(updateCode === 13, "reporter must not have update capability");
print("PASS: validation, allowed read, collection and mutation denials");
```

### File: fix.js
```javascript
db.getSiblingDB("appdb").updateRole("reporter", {privileges: [
	{resource: {db: "appdb", collection: "users"}, actions: ["find"]}
]});
```

### Baseline, Hints, and Solution

```powershell
docker run --name w3-mongo-sec -d -e MONGO_INITDB_ROOT_USERNAME=operator -e MONGO_INITDB_ROOT_PASSWORD=Admin-lab-only-80! mongo:8.0
docker exec w3-mongo-sec mongosh --quiet -u operator -p Admin-lab-only-80! --authenticationDatabase admin --eval 'db.runCommand({ping:1})'
docker cp setup.js w3-mongo-sec:/tmp/setup.js
docker cp test.js w3-mongo-sec:/tmp/test.js
docker cp fix.js w3-mongo-sec:/tmp/fix.js
docker exec w3-mongo-sec mongosh --quiet -u operator -p Admin-lab-only-80! --authenticationDatabase admin --file /tmp/setup.js
docker exec w3-mongo-sec mongosh --quiet -u app -p App-lab-only-80! --authenticationDatabase appdb --file /tmp/test.js
docker exec w3-mongo-sec mongosh --quiet -u operator -p Admin-lab-only-80! --authenticationDatabase admin --file /tmp/fix.js
docker exec w3-mongo-sec mongosh --quiet -u app -p App-lab-only-80! --authenticationDatabase appdb --file /tmp/test.js
```

Retry readiness manually. Baseline fails the last assertion because UPDATE is permitted even with zero matches. Fixed run succeeds with code 13 for both forbidden actions while the same literal read still works. Hint: zero matched rows is not a permission denial. The app can read both tenants if trusted query construction is bypassed; this lab does not claim per-document database authorization.

### Troubleshooting and Cleanup

Inspect `$LASTEXITCODE` and actual error codes. Wrong authSource or startup refusal is not successful enforcement. Use a fresh app connection for retest, and do not weaken roles to work around an initialization mistake. Cleanup only the fixture:

```powershell
docker rm -f -v w3-mongo-sec
```

- [ ] Local MongoDB exercise: Create a collection with a schema validator and limited user. Query by a validated scalar field, add an index, and test malformed types and unauthorized collections.
- [ ] Boundary check: Send an object where the API expects a username string and verify schema rejection before querying. Confirm the app user cannot read an unrelated collection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[NoSQL Injection]]
- [[MongoDB]]

## References

- [Security checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
- [User-defined roles](https://www.mongodb.com/docs/manual/core/security-user-defined-roles/)
- [Schema validation](https://www.mongodb.com/docs/manual/core/schema-validation/)
