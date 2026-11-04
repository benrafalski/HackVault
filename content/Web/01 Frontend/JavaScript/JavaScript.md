---
title: "JavaScript"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[JavaScript Security]]"
updated: 2026-11-03
---
# JavaScript

> [!abstract] TL;DR
> Use Object.hasOwn(obj, key) for own-property checks; await with try/catch for expected failures. JSON.parse parses JSON but does not validate an application's schema.

> [!info] Agent scope
> Types and coercion; scope and closures; prototypes; modules; promises; event loop; errors; runtime versus source semantics.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me JavaScript at expert runtime depth, assuming basic programming and HTML.
Cover primitive/reference semantics, coercion and equality algorithms, numeric
limits, lexical environments and closures, this binding, prototypes/descriptors,
ES modules and cycles, promises/async functions, host event loops and errors.
Trace values, bindings, stack frames and scheduled jobs in worked programs.
Distinguish ECMAScript guarantees from browser and Node host behavior, source
syntax from emitted code, concurrency from CPU parallelism, and parsing from
schema validation. Give complete .mjs labs and native assertions for closures,
prototype lookup, live imports, scheduling, rejection handling and cleanup.
Use TC39, WHATWG and Node primary sources. Include debugging questions with
worked answers; teach here without editing files or inventing test results.
```

## Cheatsheet

### Values and Conversion

Primitives are undefined, null, boolean, string, symbol, number, and bigint. Objects have identity; functions are callable objects. Assignment copies a value, including an object reference, not a deep object graph. `const` prevents reassignment of a binding, not mutation of the referenced object. `Object.freeze()` is shallow.

| Expression / API | Consequence |
|---|---|
| `Boolean('false')` | `true`; nonempty text is truthy |
| `Number('')` | `0`; validate syntax before accepting numeric text |
| `Number.isFinite(value)` | No coercion; rejects strings, NaN and infinities |
| `Object.is(NaN, NaN)` | `true`, unlike `===`; also distinguishes signed zeros |
| `value ?? fallback` | Falls back only for null/undefined, preserving `0`, `false`, `''` |
| `value || fallback` | Falls back for every falsy value |
| `JSON.stringify({value: undefined})` | Omits the property; arrays serialize such entries as null |

Number uses binary64; integers beyond `Number.MAX_SAFE_INTEGER` cannot all be distinguished. Use integer minor currency units within a checked range or a decimal library for appropriate accounting rules. BigInt cannot mix implicitly with Number arithmetic and is not JSON-serializable without an explicit wire convention. `==` applies conversion rules; prefer `===` and explicit input parsing when defining a contract.

### Environments, Objects, and Modules

`let` and `const` are block scoped and unavailable in their temporal dead zone before initialization. `var` is function scoped; a loop using it shares one binding among closures. Closures retain bindings, not snapshots, and can keep referenced data alive. Ordinary function `this` depends on the call expression; arrows capture lexical `this`. Extracting an object method loses its receiver unless bound.

Property reads search own properties then the prototype chain; getters may execute. `in` includes inherited properties; `Object.hasOwn()` does not. `Object.keys()` enumerates own enumerable string keys; `Reflect.ownKeys()` also includes nonenumerable and symbol keys. Spread and assignment are shallow and can invoke source getters. Use `Map` for dynamic keys without object-prototype semantics.

ES modules have strict semantics, lexical module scope and live import bindings. Resolution and fetching are host responsibilities. Static dependencies are linked before evaluation; cycles can expose uninitialized bindings. Top-level await delays dependent module evaluation. Node `.mjs` is ESM regardless of a nearby package type; `.cjs` is CommonJS. Browsers need supported URLs or import maps for bare specifiers. Do not equate bundler resolution with native runtime resolution.

### Scheduling and Error Ownership

JavaScript on one event loop runs a job to completion. Browser tasks include events/timers; promise reactions and `queueMicrotask()` use microtasks drained at checkpoints before the next task. A timer delay is a minimum eligibility delay, not a deadline or priority guarantee. Rendering opportunities are host decisions; `await Promise.resolve()` does not guarantee a paint and repeatedly queuing microtasks can starve it. Use workers for independent CPU work.

An async function executes synchronously until suspension and always returns a promise. `await` resumes through promise jobs; it does not block the process. A synchronous `try/catch` around a call without awaiting its result cannot catch a later rejection. `Promise.all()` preserves input result order, rejects on one failure, and does not cancel other operations. Use `allSettled()` for independent outcomes, bounded concurrency for large workloads, and AbortSignal where the underlying operation supports cancellation.

```js
// Fragment: ownership of both success and failure is explicit.
async function loadJSON(url, signal) {
	const response = await fetch(url, { signal });
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	return response.json();
}
```

JSON parsing returns values, not application-validated records. Preserve error causes when translating failures; avoid a `finally` return that overrides the original result/error. Node has additional scheduling machinery such as `process.nextTick` and event-loop phases; do not generalize a browser ordering diagram to all Node/CommonJS/ESM situations. Source maps help correlate generated code, but the executed artifact determines behavior.

## Gotchas

Async does not mean parallel CPU execution. TypeScript annotations disappear at runtime and cannot replace JavaScript input validation.

## Labs

### Environment and Complete Files

Use a supported Node LTS with ESM, `node:assert/strict`, `Object.hasOwn`, and top-level await (Node 22 or newer is sufficient for these APIs). No packages, package manifest, server, or external data. Create a disposable `javascript-runtime-lab` directory containing both files. Record `node --version`; author execution is deferred.

### File: counter.mjs

```js
export let total = 0;
export function increment() { total += 1; }
export function makeCounter(start) {
	let current = start;
	return () => ++current;
}
```

### File: lab.mjs

```js
import assert from 'node:assert/strict';
import { total, increment, makeCounter } from './counter.mjs';

assert.equal(total, 0);
increment();
assert.equal(total, 1);
const first = makeCounter(10);
const second = makeCounter(10);
assert.deepEqual([first(), first(), second()], [11, 12, 11]);

const prototype = { category: 'synthetic' };
const record = Object.create(prototype);
record.id = 'DEMO-7';
assert.equal('category' in record, true);
assert.equal(Object.hasOwn(record, 'category'), false);
assert.deepEqual(Object.keys(record), ['id']);
assert.equal(Boolean('false'), true);
assert.equal(Number(''), 0);
assert.equal(Number.isFinite('7'), false);

const events = [];
const timerDone = new Promise(resolve => {
	setTimeout(() => { events.push('timer'); resolve(); }, 0);
});
events.push('sync-start');
const reaction = Promise.resolve().then(() => events.push('promise'));
queueMicrotask(() => events.push('microtask'));
events.push('sync-end');
await reaction;
await timerDone;
assert.deepEqual(events, ['sync-start', 'sync-end', 'promise', 'microtask', 'timer']);

async function expectedFailure() { throw new Error('synthetic failure'); }
await assert.rejects(expectedFailure, /synthetic failure/);
const outcomes = await Promise.allSettled([Promise.resolve(7), expectedFailure()]);
assert.deepEqual(outcomes.map(outcome => outcome.status), ['fulfilled', 'rejected']);
console.log(events.join(' -> '));
console.log('PASS modules, closures, prototypes, conversion, scheduling, errors');
```

### Objectives and Steps

Run `node lab.mjs` in the lab directory. Predict every assertion and the event order before running. Explain why the two counters do not share state, why the imported total changes without reassignment in the importer, and why an inherited category is not an own key. Inspect the emitted event sequence without treating timer latency as measured evidence.

### Hints

Promise reaction registration and `queueMicrotask()` happen before either callback runs. The timer callback cannot run during synchronous module evaluation. An async throw becomes a rejected promise, which `assert.rejects` consumes.

### Solution and Expected Results

Expected first line: `sync-start -> sync-end -> promise -> microtask -> timer`; second line begins PASS and exit status is zero. Each `makeCounter()` invocation creates a distinct lexical environment. The imported total is a live binding. Prototype lookup finds category, while own-key enumeration does not. Rejections are owned by `assert.rejects` and `allSettled`, so no unhandled-rejection warning is expected.

For a local regression exercise, replace `let current = start` with a single module-level shared counter and observe the counter assertion fail; restore per-call state and rerun. Do not add a real network call or time-based assertion.

### Verification, Troubleshooting, and Cleanup

Missing-module errors usually mean a missing `.mjs` extension or wrong working directory. Repeated execution should have identical output because each process starts with fresh module state. A process that stays alive indicates an extra open handle not present in the printed program. Remove only the two-file lab directory after recording your Node version and observations. No tests were run during note authoring.

- [ ] Local JavaScript exercise: Log synchronous statements, a resolved promise, and a zero-delay timer; predict and verify their order. Add a rejected promise and handle it explicitly.
- [ ] Boundary check: Pass a marker and unexpected object keys through a toy merge/validation routine. Confirm schema rejection and that Object.prototype remains unchanged.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Prototype Pollution]]
- [[JavaScript Security]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide)
- [ECMAScript specification](https://tc39.es/ecma262/)
- [HTML event loops](https://html.spec.whatwg.org/multipage/webappapis.html#event-loops)
- [Node ECMAScript modules](https://nodejs.org/api/esm.html)
