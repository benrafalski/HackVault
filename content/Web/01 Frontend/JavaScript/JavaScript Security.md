---
title: "JavaScript Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[JavaScript]]"
updated: 2026-11-03
---
# JavaScript Security

> [!abstract] TL;DR
> eval-like execution, unsafe DOM sinks, prototype mutation, and coercion-based validation allow data to influence code or policy.

> [!info] Agent scope
> Security of: Types and coercion; scope and closures; prototypes; modules; promises; event loop; errors; runtime versus source semantics. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- eval-like execution, unsafe DOM sinks, prototype mutation, and coercion-based validation allow data to influence code or policy.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive JavaScript security at runtime depth. I know closures,
prototypes, ES modules, promises and the event loop. Explain data-to-code and
data-to-policy boundaries, coercion errors, own versus inherited properties,
generic merge risks, getters/proxies, shallow copies, asynchronous failures and
dependency authority. Show explicit runtime schemas, safe projection, bounded
input processing and text-only rendering. Use complete Node assertion labs
with synthetic JSON, inert unexpected keys, positive/negative tests and
prototype-invariant checks. Do not supply exploitation, bypass, credential
access or offensive payloads. Distinguish language guarantees, host behavior,
client validation and server authorization. Use TC39/Node/WHATWG primary
sources; teach here without editing files or claiming execution.
```

## Cheatsheet

### Root Causes and Defensive Decisions

| Boundary | Failure mechanism | Concrete control |
|---|---|---|
| JSON to record | Parsing checks grammar, not keys/types/ranges | Decode to unknown data, exact-key validation, fresh projected record |
| Text to number | Implicit conversion accepts unintended forms | Require a number and finite integer range, or define a separate string grammar |
| External keys to object | Property lookup/assignment can interact with prototypes | Fixed field projection; Map/null-prototype dictionaries where appropriate |
| Text to executable source | Dynamic evaluation grants code authority | Dispatch through a fixed operation map, never compile input |
| Data to DOM | HTML sinks interpret grammar | Text nodes and independently validated URLs |
| Promise to state | Rejection/race leaves partial or stale state | Await ownership, cleanup, request identities and cancellation |

`Object.hasOwn()` distinguishes inherited properties but does not validate the property's value. `Object.keys()` is useful for JSON-derived objects because JSON cannot contain symbol keys or accessors; for arbitrary in-process objects that assumption is false. A getter or proxy can execute during inspection. These labs accept JSON text, not arbitrary hostile JavaScript objects, and bound its length before parsing. A production HTTP service must bound encoded bytes before decoding as well.

Avoid generic recursive merges for externally controlled configuration. A denylist of prototype-sensitive keys is incomplete if permitted fields can still alter policy. Prefer an exact schema and construct the return value explicitly. `Object.assign()` and object spread differ in destination setter behavior, but neither establishes authorization or deep immutability. `Object.freeze()` protects only one level; use an immutable domain representation or controlled updates rather than assuming deep freeze.

### Worked Boundary Fragments

```js
// Fragment: no source compilation and no inherited operation lookup.
const operations = new Map([
	['sum', (left, right) => left + right],
	['max', (left, right) => Math.max(left, right)]
]);
function calculate(operation, left, right) {
	if (!operations.has(operation) || !Number.isFinite(left) || !Number.isFinite(right)) {
		throw new TypeError('Invalid calculation');
	}
	return operations.get(operation)(left, right);
}
```

Use native `JSON.parse`, not eval-like parsing. Avoid logging entire rejected values: messages may carry confidential application data or unbounded content. Report error categories and a correlation identifier. Rejected promises are not ordinary synchronous throws at the call site; every detached operation needs an explicit error owner. Do not retry validation/authorization failures; retries belong to transient operations with idempotency guarantees.

Client code and configuration are visible and modifiable by the user. Closures, minification, private class fields, and frozen objects are not server security boundaries. ES module scope prevents accidental global bindings, not a malicious dependency's access to host APIs. Review dependencies and lockfiles, restrict build credentials, and treat source maps as deployable artifacts. Node and browsers differ in ambient capabilities; the same module may have much broader filesystem/network authority in Node.

## Detection and Defense

Search owned code for dynamic evaluation, arbitrary-key recursive merges, unsafe DOM sinks, implicit numeric comparisons and floating promises. Test wrong types, extra keys, empty strings, absent fields and boundary values. Compare prototype descriptors around a test to detect accidental global mutation, while recognizing that this does not prove all objects are unchanged. Keep error telemetry bounded, and repeat tests against production artifacts when transforms or polyfills differ.

## Labs

### Environment and Complete Files

Supported Node LTS (Node 22+ sufficient), no dependencies or server. Create a disposable `js-policy-lab` with one complete file below. All data is embedded synthetic JSON; there are no dangerous property-name fixtures or code-execution payloads.

### File: policy.mjs

```js
import assert from 'node:assert/strict';

function baseline(text) {
	const value = JSON.parse(text);
	return { ...value, quantity: Number(value.quantity) };
}
function decodeOrder(text) {
	if (typeof text !== 'string' || text.length > 512) throw new TypeError('size');
	const value = JSON.parse(text);
	if (value === null || typeof value !== 'object' || Array.isArray(value)) {
		throw new TypeError('object');
	}
	const allowed = new Set(['label', 'quantity']);
	const keys = Object.keys(value);
	if (keys.length !== 2 || keys.some(key => !allowed.has(key)) ||
			!Object.hasOwn(value, 'label') || !Object.hasOwn(value, 'quantity')) {
		throw new TypeError('keys');
	}
	if (typeof value.label !== 'string' || value.label.length < 1 || value.label.length > 40) {
		throw new TypeError('label');
	}
	if (typeof value.quantity !== 'number' || !Number.isSafeInteger(value.quantity) ||
			value.quantity < 1 || value.quantity > 10) throw new TypeError('quantity');
	return Object.freeze({ label: value.label, quantity: value.quantity });
}

const prototypeBefore = Object.getOwnPropertyDescriptors(Object.prototype);
const approved = '{"label":"LAB-7","quantity":2}';
const wrongType = '{"label":"LAB-7","quantity":"2"}';
const extraKey = '{"label":"LAB-7","quantity":2,"color":"blue"}';
assert.equal(baseline(wrongType).quantity, 2);
assert.equal(baseline(extraKey).color, 'blue');
assert.deepEqual(decodeOrder(approved), {label: 'LAB-7', quantity: 2});
for (const fixture of [wrongType, extraKey, 'null', '[]', '{}',
	'{"label":"LAB-7","quantity":0}', '{"label":"LAB-7","quantity":11}',
	'{"label":"LAB-7","quantity":1.5}', '{"label":"","quantity":2}']) {
	assert.throws(() => decodeOrder(fixture), TypeError);
}
assert.throws(() => decodeOrder('{'), SyntaxError);
assert.throws(() => decodeOrder(' '.repeat(513)), TypeError);
const frozen = decodeOrder(approved);
assert.throws(() => { frozen.quantity = 9; }, TypeError);
assert.equal(frozen.quantity, 2);
assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), prototypeBefore);
console.log('PASS baseline observed; policy rejects malformed data; valid order retained');
```

### Objectives and Baseline

Run `node --version`, then `node policy.mjs`. Explain why the baseline silently accepts a numeric string and carries an unrelated key. Identify every check that prevents those changes in the fixed path. The operation has no server or persistence; it demonstrates a decoder suitable for invocation at a real service boundary, not a claim of server authorization.

### Hints

Coercion and unknown-key preservation are separate defects. Fix both before constructing the domain object. `Object.freeze` is useful here because the returned fields are primitives, but it does not validate input.

### Solution and Fixed Retest

The solution is `decodeOrder`: length gate, parse, object check, exact keys, field checks, projection, freeze. Expected output is one PASS line and exit zero. The same wrong-type and extra-key fixtures that baseline accepts must throw in the fixed path; the approved fixture remains quantity 2 and label LAB-7. Remove the quantity type guard temporarily while leaving integer checks: numeric strings should still fail because `Number.isSafeInteger` is noncoercing. This demonstrates complementary checks, not permission to normalize arbitrary types.

### Verification, Troubleshooting, and Cleanup

SyntaxError for malformed JSON is intentionally distinct from schema TypeError. Failure of the mutation assertion means the file was not executed as ESM/strict code or the return was no longer frozen. The prototype descriptor assertion detects only changes during this process; it is not a general security scanner. Record runtime and output, then delete only the disposable directory. This revision did not execute commands or tests.

- [ ] Local JavaScript exercise: Log synchronous statements, a resolved promise, and a zero-delay timer; predict and verify their order. Add a rejected promise and handle it explicitly.
- [ ] Boundary check: Pass a marker and unexpected object keys through a toy merge/validation routine. Confirm schema rejection and that Object.prototype remains unchanged.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Prototype Pollution]]
- [[JavaScript]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide)
- [ECMAScript object operations](https://tc39.es/ecma262/#sec-object-objects)
- [Node assertions](https://nodejs.org/api/assert.html)
