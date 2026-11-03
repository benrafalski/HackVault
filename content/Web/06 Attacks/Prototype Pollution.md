---
title: "Prototype Pollution"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Prototype Pollution

> [!abstract] TL;DR
> Prototype pollution lets untrusted property paths mutate shared prototype state, changing later lookups in code that did not receive the original input.

> [!info] Agent scope
> Prototype mutation; unsafe merge and path APIs; client/server sources and sinks; property ownership checks; safe dictionaries.

## Learn

```text
Teach prototype pollution using JavaScript's actual property model. Assume JSON,
objects, prototypes, descriptors, and Node/browser runtimes. Explain own versus
inherited properties, getters/setters, unsafe recursive merging/path setters,
prototype mutation sources, and later security-sensitive sinks conceptually.
Contrast Object.hasOwn, Object.keys, Map, null-prototype objects, explicit defaults,
schema validation, and freeze limitations. Discuss client and server impact
without pollution payloads or gadget chains. Review a strict JSON settings reader
and run native Node tests that reject unknown keys without mutating prototypes.
Include version details, primary ECMAScript/Node references, and review questions
with answers. No bypasses, RCE, theft, scanning, or live exploitation. Do not edit
files or claim unexecuted tests passed.
```

## Cheatsheet

> [!important] Defensive scope
> The lab never mutates a prototype or implements an unsafe merge. It tests a secure settings reader against ordinary JSON values and unknown fields.

### Property Lookup and Authority

JavaScript reads may walk the prototype chain when an own property is absent. A shared prototype mutation can therefore change behavior in objects that never received the original input. A source must reach a mutation operation, and a later sink must use the changed property in a meaningful way. A suspicious key alone is not proof of mutation; mutation alone is not proof of every claimed impact.

Client sources include parsed messages, settings, and URL-derived state; server sources include JSON/configuration merges and path APIs. Sinks include defaults, feature gates, template options, and downstream library configuration. Exact library versions and call paths determine whether those lookups exist. The secure approach is to remove uncontrolled structural merging and make security-relevant defaults explicit.

| API/design | Benefit | Limitation |
|---|---|---|
| `Object.hasOwn(obj, key)` | Tests ownership without trusting an instance method | Does not validate the property's value |
| `Object.keys(obj)` | Enumerates own enumerable string keys | Does not itself make copying or nested merging safe |
| `Map` | Separates dictionary entries from object properties | Consumers must continue using Map APIs |
| `Object.create(null)` | Removes inherited defaults for a dictionary | Nested objects and conversion back to ordinary objects need review |
| Closed schema | Rejects structural keys not in the contract | Generic deep merge later can reintroduce risk |
| `Object.freeze` | Prevents changes to the frozen object itself | Shallow; not universal protection of an object graph |

`__proto__`, `constructor`, and `prototype` deserve review in structural APIs, but a denylist is not a substitute for a schema. `JSON.parse` creates data; later assignment/merge/path operations determine whether special property semantics become relevant. Treat arbitrary live JavaScript objects differently from parsed JSON because accessors can run on property access.

### Versions and Evidence

`Object.hasOwn` is an ES2022 API, available in the Node 22 runtime used here. Node's `--disable-proto` option addresses the legacy accessor only; it is defense in depth, not a complete prototype safety guarantee. Node's built-in `node:test` and strict assertions require no npm dependencies in this lab.

Record entry format, merge/path utility and version, destination object, ownership checks, and later property reads. Review options at sinks even when the source has been patched. Avoid claiming browser or process compromise from a parser error or unexpected property name. The lab snapshots prototype descriptors solely to assert that secure parsing leaves them unchanged.

## Defense

Prefer explicit field mapping over generic recursive merging. Validate parsed data, use safe dictionaries, initialize defaults, and require own properties for security decisions. Patch dependencies and inspect how they consume options. Do not accept caller-controlled property paths unless a product requirement and a narrow validated grammar justify them.

## Labs

### Environment and Objectives

Node.js 22.x, built-in modules only. No npm install, browser, services, or Python approximation of JavaScript. One `.mjs` file with inline synthetic settings. Review a proposal that recursively merges arbitrary settings into shared defaults; replace it with a closed schema and a null-prototype result.

### File: test_example.mjs

```javascript
import test from "node:test";
import assert from "node:assert/strict";

function readSettings(raw) {
	if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > 1024) {
		throw new TypeError("bounded JSON text required");
	}
	const parsed = JSON.parse(raw);
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new TypeError("object required");
	}
	const allowed = new Set(["theme", "pageSize"]);
	if (Object.keys(parsed).some((key) => !allowed.has(key))) {
		throw new TypeError("unknown setting");
	}
	const result = Object.create(null);
	result.theme = "light";
	result.pageSize = 20;
	if (Object.hasOwn(parsed, "theme")) {
		if (!["light", "dark"].includes(parsed.theme)) throw new TypeError("theme");
		result.theme = parsed.theme;
	}
	if (Object.hasOwn(parsed, "pageSize")) {
		if (!Number.isInteger(parsed.pageSize) || parsed.pageSize < 1 || parsed.pageSize > 50) {
			throw new TypeError("page size");
		}
		result.pageSize = parsed.pageSize;
	}
	return Object.freeze(result);
}

test("known settings and explicit defaults", () => {
	const result = readSettings('{"theme":"dark"}');
	assert.equal(result.theme, "dark");
	assert.equal(result.pageSize, 20);
	assert.equal(Object.getPrototypeOf(result), null);
	assert.equal(Object.hasOwn(result, "pageSize"), true);
	assert.equal(Object.isFrozen(result), true);
});

test("unknown and non-scalar values are rejected", () => {
	for (const raw of ['{"extra":true}', '{"theme":{"label":"dark"}}',
		'{"pageSize":true}', '{"pageSize":51}', '[]', 'null']) {
		assert.throws(() => readSettings(raw), TypeError);
	}
});

test("secure reads leave shared prototypes unchanged", () => {
	const before = Object.getOwnPropertyDescriptors(Object.prototype);
	readSettings('{"pageSize":10}');
	assert.throws(() => readSettings('{"unreviewed":"value"}'), TypeError);
	assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), before);
	assert.equal(Object.hasOwn({}, "theme"), false);
});
```

### Commands, Hints, and Separate Solution

```powershell
node --test test_example.mjs
```

Hint: the result's default values are own properties. Why should a security-sensitive consumer still avoid treating a missing property as permission? Why is accepting parsed JSON narrower than accepting any JavaScript object?

Solution: there is no recursive merge or path setter, only two explicit assignments after validation. Expected: three Node tests pass, defaults are stable, and the shared prototype descriptors remain unchanged. No prototype mutation is demonstrated. JSON duplicate fields retain JavaScript's last-value semantics here; if signed/canonical JSON requires duplicate rejection, use a reviewed parser with that feature rather than claiming this reader provides it.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Node 22 must already be available; no package manifest is needed for `.mjs`. A missing `node:test` indicates an unsupported runtime. Remove the disposable directory after review. The suite does not establish safety of third-party merge utilities, browser sinks, or nested object schemas.

- [ ] Local Prototype Pollution exercise: Review strict mapping and property ownership.
- [ ] Boundary check: Run native JavaScript no-mutation and settings regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [ECMAScript Object.hasOwn](https://tc39.es/ecma262/#sec-object.hasown)
- [ECMAScript Object.create](https://tc39.es/ecma262/#sec-object.create)
- [Node 22 test runner](https://nodejs.org/docs/latest-v22.x/api/test.html)
- [Node CLI disable-proto option](https://nodejs.org/docs/latest-v22.x/api/cli.html#--disable-protomode)
