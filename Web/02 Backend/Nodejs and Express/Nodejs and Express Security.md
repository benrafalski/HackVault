---
title: "Node.js and Express Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Nodejs and Express]]"
updated: 2026-11-03
---
# Node.js and Express Security

> [!abstract] TL;DR
> Unsafe object merging, shell construction, overtrusted forwarded headers, and missing object authorization turn untrusted request data into server authority.

> [!info] Agent scope
> Security of: Node runtime; event loop; Express middleware; routing; parsing; error handling; proxy trust; process configuration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsafe object merging, shell construction, overtrusted forwarded headers, and missing object authorization turn untrusted request data into server authority.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Node.js 24 / Express 5 security given promises, HTTP and SQL.
Trace trust from bytes through parsers, identity verification, owner-constrained
queries, response serialization and logging. Explain prototype-bearing objects,
unsafe merges, shell/eval sinks, async error propagation, event-loop resource
limits, sessions/CSRF, proxy trust, environment secrets and dependency integrity.
Compare Express 4/5 defaults and reverse-proxy topology assumptions. Use code
review examples, fixed code and local negative regression tests with synthetic
principals only. Cover atomic authorization/mutation, detection and false
positives. Do not demonstrate exploitation, bypass, credential theft or evasion.
Use official public sources and distinguish unexecuted expectations from evidence.
Teach the subject in this conversation, not through file-edit instructions.
```

## Cheatsheet

### Boundaries and Concrete Controls

| Root cause | Defensive implementation | Evidence and limits |
|---|---|---|
| Request fields become authority | Construct `{text: body.text}` explicitly; reject unknown keys. Never merge arbitrary input into configuration or session objects. | Count schema rejections by route, not by raw body. Validation must also cover nested objects. |
| Object lookup ignores owner | Query `WHERE id = $1 AND owner_id = $2`; derive owner from verified identity. | Non-owner and nonexistent IDs can both return 404. A role check alone does not establish ownership. |
| Read/check/write race | Put owner predicate in the update itself and check affected rows; use a transaction for multi-row invariants. | A check in one request followed by an unrestricted update later is not atomic. |
| Proxy-supplied identity | Keep `trust proxy` false for direct deployments; configure trusted subnet predicates behind controlled ingress. | Address/protocol fields are network metadata, not authenticated user identity. Topology changes need retesting. |
| Shell/code sink | Prefer library APIs; if a child process is necessary, fixed executable plus allowlisted argument array and `shell:false`. Never evaluate input as code. | An argument array still permits dangerous program options unless values are constrained. |
| Resource exhaustion | Limit bodies, timeouts, concurrency, pagination and expensive work. Use worker threads for bounded CPU tasks. | Body size does not cap JSON nesting cost, database work or regex complexity. |
| Session confusion | Rotate session ID after login; server-side session store, Secure/HttpOnly/SameSite cookies, CSRF token for writes. | Express core supplies no complete session/auth system. A signed cookie is not encrypted. |

### Review Pattern: Unsafe Versus Fixed

Unsafe review fragment: `await notes.update(req.params.id, req.body)` mixes resource selection and arbitrary persistence fields without an owner constraint. Fixed SQL-shaped fragment:

```javascript
const result = await connection.query(
	'UPDATE notes SET text = $1 WHERE id = $2 AND owner_id = $3 RETURNING id, text',
	[validatedText, req.params.id, verifiedPrincipal.id]
);
```

This is a fragment, not a complete database program. Parameter binding protects SQL structure; the owner predicate enforces policy; selecting output columns prevents accidental field disclosure. None substitutes for the others. Never return `error.stack` or log authorization headers. Express 5 catches returned async rejections, not failures from detached background work.

## Detection and Defense

Log bounded correlation IDs, route templates, status and policy decision reason internally. Distinguish expected 404 concealment from internal authorization errors. Alert on sustained validation/denial rates and abnormal event-loop delay, accounting for client bugs and legitimate load. Audit dependencies and lockfile changes; run under a nonprivileged OS identity. Removing `X-Powered-By` reduces a hint, not an underlying vulnerability. Use production error handling and no development inspector on public interfaces.

## Labs

- [ ] Local Nodejs and Express exercise: Build GET and POST routes for synthetic notes with a bounded JSON parser, schema validation, and a final error handler. Verify malformed JSON, missing fields, and unknown IDs produce deliberate 4xx responses.
- [ ] Boundary check: Call another synthetic user's note ID directly and send a forged X-Forwarded-For header. Verify resource denial and that untrusted headers cannot alter a security decision.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted, loopback-only defensive regression lab. Node.js 24 LTS, npm 11, Express 5.1.0. The principal is injected by test code or fixed server startup, never by a request header; this is not a production authentication scheme. All records and users are synthetic.

### File: package.json

```json
{"private":true,"type":"module","scripts":{"test":"node --test","start":"node server.js"},"dependencies":{"express":"5.1.0"}}
```

### File: app.js

```javascript
import express from 'express';
export function createApp(principal = null) {
	const app = express();
	const notes = new Map([['1', { owner: 'alice', text: 'synthetic' }]]);
	app.disable('x-powered-by');
	app.set('trust proxy', false);
	app.use(express.json({ limit: '1kb' }));
	app.use((req, res, next) => {
		if (!principal) return res.status(401).json({ error: 'authentication_required' });
		res.locals.principal = principal;
		next();
	});
	app.patch('/notes/:id', (req, res) => {
		const note = notes.get(req.params.id);
		if (!note || note.owner !== res.locals.principal) {
			return res.status(404).json({ error: 'not_found' });
		}
		const body = req.body;
		if (!body || Object.keys(body).length !== 1 ||
				typeof body.text !== 'string' || !body.text.trim() || body.text.length > 80) {
			return res.status(400).json({ error: 'invalid_note' });
		}
		note.text = body.text;
		return res.json({ text: note.text });
	});
	app.use((req, res) => res.status(404).json({ error: 'not_found' }));
	app.use((error, req, res, next) => {
		if (res.headersSent) return next(error);
		const status = error.type === 'entity.too.large' ? 413
			: error.type === 'entity.parse.failed' ? 400 : 500;
		return res.status(status).json({ error: 'request_failed' });
	});
	return app;
}
```

### File: server.js

```javascript
import { createApp } from './app.js';
createApp('alice').listen(3001, '127.0.0.1');
```

### File: policy.test.js

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createApp } from './app.js';

test('owner policy and field allowlist', async () => {
	for (const [principal, body, expected] of [
		[null, { text: 'new' }, 401], ['bob', { text: 'new' }, 404],
		['alice', { text: 'new', owner: 'bob' }, 400],
		['alice', { text: 'new' }, 200]
	]) {
		const server = createApp(principal).listen(0, '127.0.0.1');
		await once(server, 'listening');
		try {
			const response = await fetch(`http://127.0.0.1:${server.address().port}/notes/1`, {
				method: 'PATCH', headers: { 'Content-Type': 'application/json',
					'X-Forwarded-For': '192.0.2.10' }, body: JSON.stringify(body)
			});
			assert.equal(response.status, expected);
			const result = await response.json();
			assert.equal(Object.hasOwn(result, 'owner'), false);
			if (expected === 200) assert.deepEqual(result, { text: 'new' });
		} finally {
			await new Promise(resolve => server.close(resolve));
		}
	}
});
```

### Objectives, Baseline and Hints

Run `npm install`, `npm test`, then `npm start`. Baseline: the fixed Alice process can update its synthetic note. Save `{"text":"reviewed"}` as a local body file and call `curl.exe -i -X PATCH http://127.0.0.1:3001/notes/1 -H "Content-Type: application/json" --data-binary "@body.json"`. The expected response is 200 with only `text`.

Explain why the test harness must select the principal outside HTTP and why a forwarded address cannot grant ownership. Identify the owner predicate and the input/output field allowlists. Hint: request validation and authorization are separate gates, and all mutation is synchronous in this in-memory model.

### Solution and Fixed Retest

The complete files implement the hardening: deny absent identity, conceal non-owned objects, accept only text, serialize only text, ignore forwarded identity claims. Run the same suite after any middleware or repository refactor. Expected: one passing test exercising 401, 404, 400 and 200. No vulnerable server or exploit is supplied. Production replacement must atomically constrain database mutations; the synchronous `Map` example does not model distributed races.

### Troubleshooting and Reset

If the valid request returns 400, confirm JSON media type and exactly one text field. The manual server is deliberately fixed to Alice; Bob/anonymous cases exist only in the test harness. Tests bind ephemeral ports. Stop the manual process with Ctrl+C; restart restores the single seed. Remove the disposable directory to clean dependencies. Authentication cryptography, CSRF and a real proxy deployment remain reference topics, not validated integrations.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Prototype Pollution]]
- [[Command Injection]]
- [[Nodejs and Express]]

## References

- [Express production security](https://expressjs.com/en/advanced/best-practice-security.html)
- [Proxy trust](https://expressjs.com/en/guide/behind-proxies.html)
- [Node security best practices](https://nodejs.org/en/learn/getting-started/security-best-practices)
