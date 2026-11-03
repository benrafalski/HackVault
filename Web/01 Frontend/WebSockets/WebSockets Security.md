---
title: "WebSockets Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[WebSockets]]"
updated: 2026-11-03
---
# WebSockets Security

> [!abstract] TL;DR
> Validate browser Origin before upgrade, authenticate independently, and authorize every message against current session state. Bound resources before parsing. A valid handshake does not grant permanent authority.

> [!info] Agent scope
> Security of: Upgrade handshake; frames; browser API; origin validation; authentication lifecycle; per-message authorization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Upgrade path, Origin, cookie/session resolution, subprotocol, frame size/compression, JSON schema, action/resource authorization, subscriptions and connection lifetime are separate boundaries. Labs use only loopback, an explicitly synthetic Alice session and harmless status text; no real authentication service or account data.

## Learn

```text
Teach defensive WebSocket engineering at expert depth for browsers and Node/ws.
Assume HTTP, cookies and async JavaScript. Separate Origin from authentication,
handshake authorization from message authorization, and session expiry from TCP
lifetime. Explain subprotocol negotiation, parsing/decompression bounds, rate and
queue controls, heartbeat, logout/revocation, subscription fan-out and proxy TLS.
Use only a loopback synthetic-session fixture. Compare a pure weak authorization
function with the fixed network policy; test wrong Origin, missing session,
wrong room, invalid JSON, permitted messages, expiry and revocation. Include all
files, commands, observable evidence, regression checks and cleanup. Use primary
sources and state limits. No operational exploitation, credential collection,
bypass or real targets. Teach here without file edits or fabricated test results.
```

## Cheatsheet

### Boundary Decisions

| Stage | Required decision | Failure mode |
|---|---|---|
| HTTP upgrade | Exact route and browser Origin allowlist; validate subprotocol | Accepting unexpected browser contexts |
| Identity | Server-side session/token lookup with expiry/revocation | Trusting origin or payload user ID as identity |
| Message decode | Wire/decompressed size cap, text/binary policy, parse error handling | Excess allocation or connection/process errors |
| Operation | Exact schema and current resource permission | Assuming every room/action is permitted after login |
| Subscription | Authorize subscription and future deliveries | A previously allowed subscription outliving permission |
| Lifetime | Periodic expiry, event-driven revocation, per-message recheck | Idle sockets retaining expired authority |
| Capacity | Global/user/IP connection caps, rate, queue and fan-out bounds | One authorized client exhausting resources |

Origin checking applies to the browser security model; a Node client can set Origin. CORS headers and preflight rules are not a replacement. Cookies may be sent according to SameSite/third-party rules; SameSite is a useful additional constraint, not your complete Origin policy. Cookie scope does not include port, so two localhost ports are not separate cookie stores.

Browser `WebSocket` cannot set arbitrary request headers. Cookie-based sessions require normal web session defenses; application-layer first-message authentication needs a short unauthenticated deadline and must not permit operations before success. Avoid long-lived tokens in query strings or subprotocol names. Production uses `wss:`, Secure/HttpOnly cookies where appropriate and trusted proxy configuration; loopback HTTP examples are intentionally not deployable authentication systems.

### Weak Versus Fixed Authorization

```javascript
const weakAllowsRoom = session => Boolean(session);
const allowsRoom = (session, room, now) =>
	Boolean(session && session.expires > now && session.user === room);
```

These are policy fragments. The fixed version also needs fresh server-side session lookup, strict schema validation and a real permission model when ownership is not sufficient. Never accept `user: 'alice'` in a message as authentication. Reject or re-evaluate subscriptions after role/resource changes; a connection-scoped snapshot alone is stale.

### Error and Resource Policy

With `ws`, set `maxPayload` explicitly and decide whether to negotiate permessage-deflate. The lab disables compression, eliminating that resource variable. Close code 1009 denotes excessive message size, 1008 a policy failure. Do not send reserved observation codes such as 1006. Malformed JSON can be rejected without closing if bounded; repeated invalid input should consume the rate budget. Browser error detail is deliberately limited: preserve server evidence without logging session tokens or message bodies.

## Detection and Defense

Log bounded event types: upgrade denial reason, opaque connection ID, synthetic/internal principal ID, action, resource category, rate-limit event, bytes/queue counts, expiry and close code. Do not log cookie/header dumps or complete messages. Distinguish network idle failures from authorization failures. Test with both a browser (real Origin/cookie behavior) and a controlled Node client (precise negative inputs); neither substitutes for the other.

## Labs

### Environment and Complete Files

Use Node 22.x/npm 10.x, `ws` 8.22.1 and a current browser; port 8841 must be free. Create all files in an empty disposable directory. Official npm metadata identifies this pin as a compatible 8.x advisory fix for the former 8.18.3 pin; review current advisories before reuse. The session endpoint deliberately issues a 30-second synthetic Alice identity without login and must remain loopback-only.

### File: package.json

```json
{
	"name": "ws-policy-lab",
	"version": "1.0.0",
	"private": true,
	"type": "module",
	"dependencies": {"ws": "8.22.1"}
}
```

### File: server.mjs

```javascript
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {WebSocketServer, WebSocket} from 'ws';
const origin = 'http://127.0.0.1:8841';
const html = readFileSync(new URL('./index.html', import.meta.url));
const sessions = new Map();
const tokenOf = request => (request.headers.cookie || '').split(';')
	.map(part => part.trim()).find(part => part.startsWith('lab_session='))?.slice(12);
const current = token => {
	const session = sessions.get(token);
	return session && session.expires > Date.now() ? session : null;
};
const sockets = new WebSocketServer({noServer: true, maxPayload: 4096, perMessageDeflate: false});
const server = http.createServer((request, response) => {
	response.setHeader('Cache-Control', 'no-store');
	if (request.method === 'GET' && request.url === '/') {
		response.writeHead(200, {'Content-Type': 'text/html'});
		return response.end(html);
	}
	if (request.method !== 'POST' || request.headers.origin !== origin) {
		response.writeHead(403); return response.end();
	}
	if (request.url === '/session') {
		const token = randomUUID();
		sessions.set(token, {user: 'alice', expires: Date.now() + 30000});
		response.setHeader('Set-Cookie', `lab_session=${token}; HttpOnly; SameSite=Strict; Path=/`);
		return response.end('Synthetic Alice session: 30 seconds');
	}
	if (request.url === '/logout') {
		const token = tokenOf(request);
		sessions.delete(token);
		for (const client of sockets.clients) {
			if (client.token === token) client.close(1008, 'session revoked');
		}
		response.setHeader('Set-Cookie', 'lab_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/');
		return response.end('Revoked');
	}
	response.writeHead(404); response.end();
});
server.on('upgrade', (request, socket, head) => {
	let status = 0;
	if (request.url !== '/socket' || request.headers.origin !== origin ||
			request.headers['sec-websocket-protocol'] !== 'lab.v1') status = 403;
	else if (!current(tokenOf(request))) status = 401;
	if (status) {
		console.log('upgrade-denied', status);
		socket.end(`HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
		return;
	}
	sockets.handleUpgrade(request, socket, head, client => {
		client.token = tokenOf(request);
		sockets.emit('connection', client);
	});
});
sockets.on('connection', client => {
	let count = 0;
	let windowStart = Date.now();
	client.on('error', () => console.log('socket-error'));
	const reply = value => {
		if (client.readyState !== WebSocket.OPEN) return;
		if (client.bufferedAmount > 65536) return client.close(1008, 'slow consumer');
		client.send(JSON.stringify(value));
	};
	client.on('message', (bytes, binary) => {
		const session = current(client.token);
		if (!session) return client.close(1008, 'session expired');
		if (Date.now() - windowStart >= 1000) { count = 0; windowStart = Date.now(); }
		if (++count > 20) return client.close(1008, 'rate limit');
		if (binary) return reply({error: 'text required'});
		let data;
		try { data = JSON.parse(bytes.toString()); }
		catch { return reply({error: 'invalid JSON'}); }
		if (!data || Object.keys(data).sort().join(',') !== 'room,type' ||
				data.type !== 'subscribe' || typeof data.room !== 'string' || data.room.length > 32) {
			return reply({error: 'schema'});
		}
		if (data.room !== session.user) {
			console.log('message-denied', session.user, 'room');
			return reply({error: 'forbidden room'});
		}
		reply({type: 'snapshot', room: session.user, value: 'synthetic status only'});
	});
});
setInterval(() => {
	for (const [token, session] of sessions) {
		if (session.expires <= Date.now()) sessions.delete(token);
	}
	for (const client of sockets.clients) {
		if (!current(client.token)) client.close(1008, 'session expired');
	}
}, 1000).unref();
server.listen(8841, '127.0.0.1', () => console.log(origin));
```

### File: index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>WebSocket session policy</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>Synthetic session policy</h1>
<button id="session">Issue Alice session</button>
<button id="connect">Connect</button>
<button id="own">Alice snapshot</button>
<button id="other">Bob snapshot</button>
<button id="logout">Revoke</button>
<pre id="log" aria-live="polite"></pre>
<script>
const log = text => document.querySelector('#log').textContent += text + '\n';
let socket;
async function post(path) {
	try { log(await (await fetch(path, {method: 'POST'})).text()); }
	catch (error) { log(error.message); }
}
document.querySelector('#session').onclick = () => post('/session');
document.querySelector('#logout').onclick = () => post('/logout');
document.querySelector('#connect').onclick = () => {
	if (socket && socket.readyState < 2) return log('Already connecting/open');
	socket = new WebSocket('ws://127.0.0.1:8841/socket', 'lab.v1');
	socket.onopen = () => log('OPEN');
	socket.onmessage = event => log(event.data);
	socket.onerror = () => log('ERROR: see Network/server');
	socket.onclose = event => log('CLOSE ' + event.code + ' ' + event.reason);
};
function subscribe(room) {
	if (socket?.readyState !== WebSocket.OPEN) return log('Not open');
	socket.send(JSON.stringify({type: 'subscribe', room}));
}
document.querySelector('#own').onclick = () => subscribe('alice');
document.querySelector('#other').onclick = () => subscribe('bob');
</script>
```

### File: checks.mjs

```javascript
import assert from 'node:assert/strict';
import {once} from 'node:events';
import WebSocket from 'ws';
const origin = 'http://127.0.0.1:8841';
function connect(senderOrigin, cookie = '') {
	return new Promise((resolve, reject) => {
		const socket = new WebSocket('ws://127.0.0.1:8841/socket', 'lab.v1', {
			origin: senderOrigin, headers: {Cookie: cookie}, handshakeTimeout: 2000
		});
		socket.on('error', reject);
		socket.once('open', () => resolve(socket));
	});
}
const weakAllowsRoom = session => Boolean(session);
assert.equal(weakAllowsRoom({user: 'alice'}, 'bob'), true);
await assert.rejects(connect('http://127.0.0.1:8842'), /403/);
await assert.rejects(connect(origin), /401/);
const issued = await fetch(origin + '/session', {method: 'POST', headers: {Origin: origin}});
assert.equal(issued.status, 200);
const cookie = issued.headers.get('set-cookie').split(';')[0];
const socket = await connect(origin, cookie);
async function exchange(text) {
	const next = once(socket, 'message', {signal: AbortSignal.timeout(2000)});
	socket.send(text);
	const [bytes] = await next;
	return JSON.parse(bytes.toString());
}
assert.deepEqual(await exchange('{'), {error: 'invalid JSON'});
assert.deepEqual(await exchange(JSON.stringify({type: 'subscribe', room: 'bob'})), {error: 'forbidden room'});
assert.equal((await exchange(JSON.stringify({type: 'subscribe', room: 'alice'}))).room, 'alice');
const closed = once(socket, 'close', {signal: AbortSignal.timeout(2000)});
await fetch(origin + '/logout', {method: 'POST', headers: {Origin: origin, Cookie: cookie}});
assert.equal((await closed)[0], 1008);
await assert.rejects(connect(origin, cookie), /401/);
console.log('PASS baseline discrepancy, handshake, message, allowed action, revocation');
```

### Objectives and Baseline

```powershell
npm install --ignore-scripts --no-audit --no-fund
node server.mjs
```

In a second terminal in the same directory: `node checks.mjs`. The first assertion demonstrates that the pure weak rule would approve Bob's room. The running service always uses the fixed rule; it has no insecure network mode. Open `http://127.0.0.1:8841/`, issue a session, connect, request Alice, request Bob, request Alice again, then revoke.

### Hints

The Node client deliberately supplies Origin to test the guard, demonstrating why Origin alone cannot authenticate it. The browser supplies its own Origin. The synthetic cookie is generated per session and is not a real credential. Revocation must affect an already open socket, not only new connections.

### Solution and Fixed Retest

Expected automated result: the final PASS line with no assertion failures. Browser: Alice snapshot accepted, Bob denied without a snapshot, Alice still accepted, revoke closes with 1008. Issue a new session and reconnect, then leave idle for at least 31 seconds: closure should be 1008 for expiry. For a real browser second-origin check, serve this directory using Python 3.11+ with `python -m http.server 8842 --bind 127.0.0.1`, open `/index.html` there and click Connect; require upgrade 403, not OPEN. Do not click session buttons on that static origin.

### Verification, Troubleshooting, and Cleanup

Validated 2026-11-03 with Node 22.23.4/npm 10.9.9: exact complete files extracted to a disposable directory, printed install passed with `ws` 8.22.1, server syntax/startup and exact HTML delivery passed on loopback, and unchanged `node checks.mjs` passed baseline discrepancy, handshake denials (403/401), malformed JSON, forbidden room, allowed action and revocation; server stopped. Official npm metadata selected 8.22.1 as a non-major fix. A separate disposable baseline audit of the same former 8.18.3 pin reported one high-severity vulnerable package with two advisories: [memory disclosure](https://github.com/advisories/GHSA-58qx-3vcg-4xpx) (moderate, affected 8.x <8.20.1) and [memory exhaustion](https://github.com/advisories/GHSA-96hv-2xvq-fx4p) (high, affected 8.x <8.21.0). This patched lab's independent `npm audit --json` exited 0 with zero reported vulnerabilities at all severities; this is a point-in-time dependency check, not a security guarantee.

Browser Origin/cookie policy, UI/rendering, browser allowed/denied/revocation sequence and idle expiry were not tested in this pass; Node-supplied headers do not verify browser policy. Run the browser and expiry steps above separately. A 401 after waiting is expected expiry: issue a fresh synthetic session. No OPEN after session issuance: verify exact hostname and cookie in DevTools without copying it elsewhere. The fixture omits distributed session storage, fleet-wide revocation and global connection quotas; production needs those controls. Stop only lab servers, clear only the `lab_session` cookie on this dedicated loopback host/profile, close tabs and delete the lab directory. Never clear unrelated site data.

- [ ] Local WebSockets exercise: Build a loopback echo service with a maintained WebSocket library. Send JSON messages, malformed input, and a clean close; record connection and message-level outcomes.
- [ ] Boundary check: Open the lab socket from a second origin and require handshake rejection. On an authorized connection, request another synthetic user's subscription and require message-level denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[WebSocket Attacks]]
- [[WebSockets]]

## References

- [RFC 6455 security considerations](https://www.rfc-editor.org/rfc/rfc6455#section-10)
- [WHATWG WebSockets](https://websockets.spec.whatwg.org/)
- [ws authentication and server options](https://github.com/websockets/ws)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
