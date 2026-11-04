---
title: "Node.js and Express"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Nodejs and Express Security]]"
updated: 2026-11-03
---
# Node.js and Express

> [!abstract] TL;DR
> Keep parsing, authentication, authorization, business logic, and error mapping explicit. Use a nonprivileged runtime identity and production error responses without stack traces.

> [!info] Agent scope
> Node runtime; event loop; Express middleware; routing; parsing; error handling; proxy trust; process configuration.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Node.js 24 LTS and Express 5 assuming JavaScript promises, HTTP and SQL.
Trace an HTTP request through libuv, middleware, parsing, routing, awaited work,
response completion and error middleware. Distinguish microtasks, nextTick,
timers, the worker pool and worker_threads; explain event-loop starvation and
backpressure. Compare ESM/CommonJS, Express 4/5 async errors and path syntax,
configuration loading, proxy trust, graceful shutdown and multi-process state.
Work through schema validation, transactional service calls and authentication
versus per-object authorization. Supply complete programs, expected results and
regression tests; explain headers-sent errors and cancellation limitations.
Use public Node/Express primary sources. Distinguish measured from predicted
results. Teach here, without editing files or assuming access to any vault.
```

## Cheatsheet

### Runtime and Request Lifecycle

JavaScript executes on one event-loop thread per isolate. Socket readiness is generally handled by OS polling; filesystem operations, some DNS operations, crypto and compression can use libuv's worker pool. `async` does not move JavaScript computation to that pool. Use `worker_threads` for CPU work, with bounded queues and explicit message ownership. Separate processes have separate heaps and connection pools.

Promise continuations and `process.nextTick` callbacks run before the loop resumes I/O; recursive scheduling can starve it. Since Node 20/libuv 1.45 timers run after poll rather than both before and after. Never derive correctness from a race between zero-delay timers and `setImmediate`. Stream `pipeline` propagates errors and handles backpressure; `res.write()` returning false means wait for drain, not append unbounded buffers.

| Boundary | Mechanism and failure mode |
|---|---|
| Modules | `"type":"module"` selects ESM for `.js`; relative ESM imports include extensions. CommonJS uses `require` and `.cjs`. Module-level mutable state is shared within a process, not across replicas. |
| Middleware | Registration order is execution order. Each path must respond, call `next()`, or forward an error exactly once. Parsers run before consumers; error middleware has four parameters and follows routes. |
| Parsing | `express.json` checks media type, decodes JSON and enforces a byte limit. It does not validate field types, ownership or allowed properties. Parsed input is untrusted. |
| Routing | Express 5 uses newer path matching: named wildcards and braces for optional segments; do not copy Express 4 string-pattern routes blindly. Query parsing defaults also differ; choose `simple` explicitly when flat keys suffice. |
| Async errors | Express 5 forwards rejected promises returned by handlers. Express 4 needs a wrapper or explicit `catch(next)`. Detached timers and promises are outside that contract. |
| Errors | Map known parser/validation errors to 4xx. Log internal failures server-side and return a stable 500 shape. After headers are sent, delegate to Express's default handler rather than trying another JSON response. |

### State, Transactions and Identity

A promise chain is not a transaction. Acquire one database connection, begin, perform all dependent statements on it, commit or roll back, then release in `finally`. Never hold a transaction while waiting for an external payment API. Use a unique idempotency key and an outbox for committed side effects. An in-memory `Map` survives only until process exit and cannot coordinate replicas.

Authenticate before private routes, derive the principal from verified credentials, and constrain object queries by both identifier and principal/tenant. CORS is a browser read policy, not authorization. Cookie-based identity requires CSRF protection for state changes; bearer tokens require signature, issuer, audience and lifetime verification.

### Process and Proxy Configuration

Read `process.env` at startup, parse ports as integers, reject missing secrets, and avoid returning environment values. `NODE_ENV=production` changes framework defaults; it does not secure routes. Start directly with `node`, not a development reload tool. On shutdown stop accepting requests, allow a bounded drain, then close database pools; forced termination needs an external deadline.

`app.set('trust proxy', false)` ignores forwarded identity claims. Behind a real reverse proxy, trust explicit proxy addresses/subnets and require that proxy to overwrite forwarded headers. A numeric hop count is unsafe when different-length ingress paths exist. `req.ip`, `req.protocol`, redirects, secure-cookie decisions and rate limits all depend on this setting.

## Gotchas

Hiding a route in the UI does not protect it. An async API does not make synchronous CPU work nonblocking.

## Labs

- [ ] Local Nodejs and Express exercise: Build GET and POST routes for synthetic notes with a bounded JSON parser, schema validation, and a final error handler. Verify malformed JSON, missing fields, and unknown IDs produce deliberate 4xx responses.
- [ ] Boundary check: Call another synthetic user's note ID directly and send a forged X-Forwarded-For header. Verify resource denial and that untrusted headers cannot alter a security decision.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted example. Use Node.js 24 LTS (latest security patch), npm 11, and Express 5.1.0 in a new disposable directory. This is a fixed teaching pin, not a claim that it is the latest secure release. Installation produces a lockfile; retain it when recording a run. No database or credentials are required.

### File: package.json

```json
{"private":true,"type":"module","scripts":{"start":"node server.js","test":"node --test"},"dependencies":{"express":"5.1.0"}}
```

### File: app.js

```javascript
import express from 'express';

export function createApp() {
	const app = express();
	const notes = new Map();
	let sequence = 0;
	app.disable('x-powered-by');
	app.set('trust proxy', false);
	app.set('query parser', 'simple');
	app.use(express.json({ limit: '2kb' }));
	app.post('/notes', (req, res) => {
		const body = req.body;
		if (!body || Object.keys(body).some(key => key !== 'text') ||
				typeof body.text !== 'string' || !body.text.trim() || body.text.length > 80) {
			return res.status(400).json({ error: 'invalid_note' });
		}
		const note = { id: String(++sequence), text: body.text.trim() };
		notes.set(note.id, note);
		return res.location(`/notes/${note.id}`).status(201).json(note);
	});
	app.get('/notes/:id', (req, res) => {
		const note = notes.get(req.params.id);
		return note ? res.json(note) : res.status(404).json({ error: 'not_found' });
	});
	app.get('/failure', async () => {
		await Promise.resolve();
		throw new Error('synthetic internal failure');
	});
	app.use((req, res) => res.status(404).json({ error: 'not_found' }));
	app.use((error, req, res, next) => {
		if (res.headersSent) return next(error);
		const status = error.type === 'entity.too.large' ? 413
			: error.type === 'entity.parse.failed' ? 400 : 500;
		return res.status(status).json({ error: status === 500 ? 'internal' : 'invalid_body' });
	});
	return app;
}
```

### File: server.js

```javascript
import { createApp } from './app.js';
const server = createApp().listen(3000, '127.0.0.1');
server.requestTimeout = 15000;
server.headersTimeout = 10000;
for (const signal of ['SIGINT', 'SIGTERM']) {
	process.once(signal, () => server.close());
}
```

### File: app.test.js

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createApp } from './app.js';

test('parser, route and rejected handler lifecycle', async () => {
	const server = createApp().listen(0, '127.0.0.1');
	await once(server, 'listening');
	const base = `http://127.0.0.1:${server.address().port}`;
	try {
		const created = await fetch(`${base}/notes`, {
			method: 'POST', headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ text: 'first' })
		});
		assert.equal(created.status, 201);
		assert.equal(created.headers.get('location'), '/notes/1');
		assert.deepEqual(await created.json(), { id: '1', text: 'first' });
		const read = await fetch(`${base}/notes/1`);
		assert.equal((await read.json()).text, 'first');
		for (const [body, expected] of [['{', 400], ['{}', 400],
			[JSON.stringify({ text: 'x'.repeat(3000) }), 413]]) {
			const response = await fetch(`${base}/notes`, {
				method: 'POST', headers: { 'Content-Type': 'application/json' }, body
			});
			assert.equal(response.status, expected);
			await response.text();
		}
		const missing = await fetch(`${base}/notes/999`);
		assert.equal(missing.status, 404);
		await missing.text();
		const failed = await fetch(`${base}/failure`);
		assert.equal(failed.status, 500);
		assert.deepEqual(await failed.json(), { error: 'internal' });
	} finally {
		await new Promise(resolve => server.close(resolve));
	}
});
```

### Objectives and Steps

Run `npm install`, `npm test`, then `npm start`. In another terminal run `curl.exe -i http://127.0.0.1:3000/notes/999` on Windows (`curl` elsewhere). Trace why malformed JSON never reaches the route and why `/failure` reaches error middleware. The checklist's authorization boundary is implemented independently in [[Nodejs and Express Security]].

### Hints

The parser calls the error path before routing. Returning a promise lets Express 5 observe a rejection; creating a detached promise does not. A missing resource is an expected branch, not an exception.

### Solution and Expected Results

The supplied implementation is the solution: parser before routes, error middleware last, stable public messages. Expected test result: one passing test with creation 201, malformed/schema errors 400, large body 413, missing ID 404, rejected async handler 500. These are predictions, not recorded output. No authorization is claimed for this technology-only service.

### Troubleshooting and Reset

`Cannot use import` means the package module setting is missing. A hanging response usually means neither `next` nor a response was reached. `EADDRINUSE`: stop the prior local server; tests use an ephemeral port. Stop with Ctrl+C; restarting clears the in-memory notes. Delete only this disposable directory to remove dependencies. This process-local store has no durability or transactional concurrency guarantee across workers.

## Related


- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Prototype Pollution]]
- [[Command Injection]]
- [[Nodejs and Express Security]]

## References

- [Node event loop](https://nodejs.org/en/learn/asynchronous-work/event-loop-timers-and-nexttick)
- [Express 5 migration](https://expressjs.com/en/guide/migrating-5.html)
- [Express error handling](https://expressjs.com/en/guide/error-handling.html)
- [Express behind proxies](https://expressjs.com/en/guide/behind-proxies.html)
