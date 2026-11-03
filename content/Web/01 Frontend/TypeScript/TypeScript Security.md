---
title: "TypeScript Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[TypeScript]]"
updated: 2026-11-03
---
# TypeScript Security

> [!abstract] TL;DR
> Casting untrusted input to a trusted interface hides missing validation while giving downstream code false confidence.

> [!info] Agent scope
> Security of: Type system; narrowing; generics; compiler options; emitted JavaScript; compile-time types versus runtime input validation. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Casting untrusted input to a trusted interface hides missing validation while giving downstream code false confidence.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me TypeScript security as defensive boundary design. I know JavaScript,
strict TypeScript and HTTP. Explain type erasure, any/assertions, incorrect type
predicates, structural excess properties, brands, readonly, generated clients,
compiler emit and runtime schema drift. Show complete server-side validation
of unknown JSON, exact keys, number ranges, body limits and error mapping.
Separate syntax/type validation, domain invariants and authorization. Supply
an independent loopback HTTP lab using synthetic requests with positive and
negative tests, compiler checks, expected responses and cleanup. No exploit,
bypass, credential access or offensive procedures. Use TypeScript and Node
primary sources. Teach here without editing files or inventing executed tests.
```

## Cheatsheet

### Compile-Time Trust Is Not Runtime Evidence

`const order = JSON.parse(text) as Order` emits the parse but no assertion. Likewise a generic `fetchJSON<Order>()` can merely promise a shape without checking it. A `.d.ts` declaration describes what a library claims, not necessarily what it returns. Generated client types cannot force arbitrary HTTP callers to obey the schema.

| Tool | Useful guarantee | Not guaranteed |
|---|---|---|
| `strict` / unknown | Checked code must narrow uncertain values | That the narrowing implementation is correct |
| `satisfies` | Static expression compatibility | External data validation |
| Brand / opaque ID | Prevents accidental mixing in checked code | Identity ownership or authorization |
| readonly / Readonly | Restricts typed mutation through that view | Deep runtime immutability or other aliases |
| noEmitOnError | Blocks emission by this tsc invocation | That another transpiler checks types or stale output is deleted |
| Schema parser | Validates the rules it implements | Tenant membership, freshness, resource ownership |

At an HTTP boundary: bound bytes, decode JSON, validate object shape and exact keys, validate primitives/ranges, construct a domain value, then authorize the action against server-owned identity. Do not accept client fields for server-owned privileges or prices. For large schemas use a maintained schema library and derive types from schemas where possible; still test coercion/default/unknown-key behavior explicitly.

A user-defined type predicate is trusted by the compiler even if it checks too little. Prefer returning a fresh validated value instead of narrowing a mutable arbitrary object. An assertion function that throws is only as good as its runtime checks. `as unknown as Trusted` is a review signal, not a conversion. Typed errors should be normalized at the HTTP edge without exposing request bodies or stack traces.

### Emission and Deployment

The lab uses TypeScript 5.0+ syntax and explicit options to avoid changing defaults. Native Node type stripping, Babel, and bundlers may remove types without running the checker; enforce a distinct check gate. `target` and `lib` do not supply runtime APIs. Align module resolution with deployment, inspect emitted imports, and ensure the service executes the newly built artifact. Source maps improve diagnosis but may expose original source and embedded configuration if published indiscriminately.

Unsafe assertion fragment, shown only to explain missing validation:

```ts
type Order = {quantity: number};
const unchecked = JSON.parse('{"quantity":"2"}') as Order;
// unchecked.quantity remains a string at runtime; no conversion occurred.
```

The complete lab below replaces that assertion with a decoder and exercises actual HTTP requests, without relying on a typed client.

## Detection and Defense

Review exported decoders, assertions, `any`, suppression comments and generated-code assumptions. Include tests for strings instead of numbers, arrays/null, missing fields, unknown fields, fractions and bounds. Treat malformed JSON separately from valid JSON with invalid shape. Keep validation errors stable and nonsensitive; track categories and status counts. This synthetic public calculation endpoint has no identity or persistence, so it must not be copied as an authenticated business service without adding authorization and operational limits.

## Labs

### Environment and Complete Files

Supported Node LTS (22+ sufficient for built-in fetch/test), npm and TypeScript 5.0+. Create `typescript-boundary-lab` with these five files. Dependencies are resolved by the install command and recorded exactly; no arbitrary patch pin is assumed. The test owns a short-lived loopback listener on an OS-assigned port and closes it. These commands are for later execution, not executed during authoring.

### File: package.json

```json
{"name":"typescript-boundary-lab","private":true,"type":"module",
 "scripts":{"check":"tsc --noEmit","build":"tsc","test":"node --test test.mjs"}}
```

### File: tsconfig.json

```json
{"compilerOptions":{"target":"ES2022","module":"NodeNext",
 "moduleResolution":"NodeNext","lib":["ES2022"],"types":[],"strict":true,
 "noUncheckedIndexedAccess":true,"exactOptionalPropertyTypes":true,
 "verbatimModuleSyntax":true,"noEmitOnError":true,"rootDir":"src","outDir":"dist"},
 "include":["src/**/*.ts"]}
```

### File: src/order.ts

```ts
export type Order = Readonly<{quantity: number}>;
export function decodeOrder(value: unknown): Order {
	if (value === null || typeof value !== 'object' || Array.isArray(value) ||
			!('quantity' in value) || !Object.hasOwn(value, 'quantity') ||
			Object.keys(value).length !== 1) throw new TypeError('shape');
	const quantity = value.quantity;
	if (typeof quantity !== 'number' || !Number.isSafeInteger(quantity) ||
			quantity < 1 || quantity > 10) throw new TypeError('quantity');
	return Object.freeze({quantity});
}
```

### File: server.mjs

```js
import { createServer } from 'node:http';
import { decodeOrder } from './dist/order.js';

export function makeServer() {
	return createServer(async (request, response) => {
		function send(status, value) {
			response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
			response.end(JSON.stringify(value));
		}
		if (request.url !== '/quote') { send(404, {error: 'not_found'}); return; }
		if (request.method !== 'POST') {
			response.setHeader('Allow', 'POST'); send(405, {error: 'method'}); return;
		}
		if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
			send(415, {error: 'media_type'}); return;
		}
		const chunks = [];
		let size = 0;
		try {
			for await (const chunk of request) {
				size += chunk.length;
				if (size <= 1024) chunks.push(chunk);
			}
			if (size > 1024) { send(413, {error: 'size'}); return; }
			const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
			const order = decodeOrder(value);
			send(200, {quantity: order.quantity, totalCents: order.quantity * 125});
		} catch (error) {
			send(error instanceof SyntaxError ? 400 : 422, {error: 'invalid_input'});
		}
	});
}
```

This tiny harness drains excess body bytes without retaining them so its 413 response is deterministic. A production service also needs early transport limits/timeouts; the harness is not a general hardened HTTP server.

### File: test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { makeServer } from './server.mjs';

test('runtime boundary independent of client types', async () => {
	const unchecked = JSON.parse('{"quantity":"2"}');
	assert.equal(typeof unchecked.quantity, 'string');
	const server = makeServer();
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	const url = `http://127.0.0.1:${server.address().port}/quote`;
	try {
		for (const [body, status] of [
			['{"quantity":2}', 200], ['{"quantity":"2"}', 422],
			['{"quantity":0}', 422], ['{"quantity":11}', 422],
			['{"quantity":1.5}', 422], ['{"quantity":2,"color":"blue"}', 422],
			['null', 422], ['[]', 422], ['{}', 422], ['{', 400], [' '.repeat(1025), 413]
		]) {
			const response = await fetch(url, {method: 'POST',
				headers: {'Content-Type': 'application/json'}, body});
			assert.equal(response.status, status, body.slice(0, 60));
			const result = await response.json();
			if (status === 200) assert.deepEqual(result, {quantity: 2, totalCents: 250});
		}
		assert.equal((await fetch(url)).status, 405);
		assert.equal((await fetch(url, {method: 'POST', body: '2'})).status, 415);
	} finally {
		await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
	}
});
```

### Objectives, Commands, and Hints

```powershell
npm install --save-dev --save-exact typescript
npx tsc --version
node --version
npm run check
npm run build
npm test
```

Predict every status before running. Explain why the string fixture still has a string after parsing, why 400 differs from 422, and why an extra inert color is rejected. Hint: the test client is plain JavaScript and sends literal JSON; no TypeScript compiler can enforce its request shape.

### Solution and Fixed Retest

The fix is the emitted `decodeOrder()` call at the HTTP boundary. The valid fixture returns `200 {"quantity":2,"totalCents":250}`; wrong type/shape/range returns 422, broken JSON 400, large body 413, wrong method 405 and wrong media type 415. Expected Node test summary: one passing test, zero failures. Static checking should exit zero. The first assertion records the unsafe assumption without exposing a vulnerable server route. Repeating the same fixtures through the decoder establishes both rejection and permitted behavior.

### Verification, Troubleshooting, and Cleanup

Missing dist means build did not complete; never rely on stale emitted files. An address problem should not require choosing a fixed port because port zero is intentional. Test failure before finally may require closing a leftover process, but the normal path closes its listener. Record lockfile/compiler/runtime, then remove only the disposable directory. No install, server, compiler or test was run by this revision.

- [ ] Local TypeScript exercise: Define a discriminated result type and handle every case. Parse malformed JSON into unknown and validate it before use; confirm both compiler exhaustiveness and runtime rejection.
- [ ] Boundary check: Send a string where the API expects a numeric quantity despite the client's type definitions. Verify the server rejects it without relying on the client compiler.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[TypeScript]]

## References

- [Official documentation or primary training reference](https://www.typescriptlang.org/docs/handbook/intro.html)
- [TypeScript compiler reference](https://www.typescriptlang.org/tsconfig/)
- [Node HTTP](https://nodejs.org/api/http.html)
- [Node test runner](https://nodejs.org/api/test.html)
