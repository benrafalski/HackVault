---
title: "WebSockets"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[WebSockets Security]]"
updated: 2026-11-03
---
# WebSockets

> [!abstract] TL;DR
> WebSocket is an ordered, bidirectional message transport, not an authorization or reconnect protocol. Separate upgrade acceptance, message framing, application validation, queue limits and connection lifetime.

> [!info] Agent scope
> Upgrade handshake; frames; browser API; origin validation; authentication lifecycle; per-message authorization.

## Prerequisites

- HTTP, origins, async JavaScript and JSON. Node.js 22.x, npm 10.x and a current browser for the lab.
- Lab dependency: `ws` 8.22.1, selected from official npm metadata as a compatible 8.x advisory fix for the former 8.18.3 pin. Review current advisories before reuse. No real accounts or credentials.

## Learn

```text
Teach WebSockets at expert engineering depth, assuming HTTP and async JavaScript.
Trace an HTTP/1.1 upgrade through key/accept calculation, negotiated subprotocol,
masked frames, fragmentation, UTF-8 validation, control frames and close handshake.
Distinguish browser messages from frames and HTTP/2 extended CONNECT from H1.
Explain readyState, binaryType, bufferedAmount, ping/pong, queue/rate limits,
compression tradeoffs, proxy idle timeouts and reconnect/resume/idempotency.
Separately cover Origin checks, browser authentication constraints, session
expiry, revocation and per-message authorization. Give complete benign loopback
Node/ws and browser implementations, exact test inputs, visible output, negative
checks, cleanup and primary sources. State versions and what was not executed.
Do not teach exploitation or edit files/study status. End with worked questions.
```

## Cheatsheet

### Handshake and Frames

Representative HTTP/1.1 handshake (illustration; browsers construct this):

```http
GET /socket HTTP/1.1
Host: 127.0.0.1:8831
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: http://127.0.0.1:8831
Sec-WebSocket-Protocol: lab.v1

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: lab.v1
```

The accept value is Base64(SHA-1(key string + RFC GUID)); it proves handshake agreement, not user authentication. Use a library, not hand-written frame parsing. HTTP/2 extended CONNECT is a different negotiation path; deployment support depends on browser, proxy and server.

Client-to-server frames are masked; masking is not encryption. A frame includes FIN/opcode, length, optional masking key and payload. Text/binary messages may span multiple frames. Control frames (close, ping, pong) have small payload limits, cannot be fragmented and can occur between fragments. A browser `message` event delivers a complete application message, not each wire frame. `wss:` adds TLS transport confidentiality and server authentication.

### Browser API and Limits

| API/state | Meaning or risk |
|---|---|
| `new WebSocket(url, ['lab.v1'])` | Begins connection; constructor cannot set arbitrary Authorization headers |
| `readyState` | CONNECTING=0, OPEN=1, CLOSING=2, CLOSED=3 |
| `send(string)` | Text message; sending while CONNECTING throws |
| `send(ArrayBuffer/Blob/typedArray)` | Binary message; receiver chooses interpretation |
| `binaryType = 'arraybuffer'` | Binary events expose ArrayBuffer instead of default Blob |
| `bufferedAmount` | Bytes queued by `send`; not peer receipt or application acknowledgement |
| `error` | Limited browser detail; use server logs/Network panel for handshake status |
| `close(code, reason)` | Browser application codes: 1000 or 3000-4999; reason at most 123 UTF-8 bytes |

Browsers do not expose protocol ping/pong methods. A server library can send ping and observe pong; application heartbeats are a separate protocol. Standard WebSocket has no stream-style backpressure API. Limit queued bytes, message size, messages per interval, subscriptions and connection count. An application acknowledgement is needed to know an operation was processed.

### Lifecycle and Decision Table

| Condition | Decision |
|---|---|
| Open connection, bounded queue | Send validated message |
| Queue too large | Pause producer or close slow connection; never grow memory indefinitely |
| Missing pong/idle timeout | Terminate dead peer; reconnect with bounded exponential delay and jitter |
| Reconnect after unknown result | Use server-issued sequence/resume state and idempotent request IDs |
| Expired/revoked session | Reauthorize or close; handshake success does not extend session validity |
| New room/action | Recheck permission from server identity, not payload owner field |
| Compression | Negotiate deliberately; assess CPU/memory and sensitive-data compression risks |

1000 is normal closure; 1008 indicates policy violation; 1009 indicates message too large. 1006 is a local abnormal-close observation, never a transmitted close code. A TCP disconnect may prevent the peer receiving a close reason. Proxies must support upgrading and appropriate idle timeouts; do not assume normal HTTP request timeouts fit a long-lived channel.

Origin is a browser cross-site boundary, not authentication: nonbrowser clients can choose it. CORS response headers do not implement WebSocket Origin checks. Browser cookies may accompany the handshake under browser cookie rules; validate the session separately. Avoid credentials in URLs or subprotocol names because infrastructure may log them.

## Gotchas

- A browser socket from an HTTPS page generally needs `wss:`; the loopback HTTP example is not production TLS configuration.
- Fragment and decompressed message sizes must be bounded by the library, not just by JSON field checks after allocation.
- Reconnect does not restore subscriptions or guarantee exactly-once operations.

## Labs

### Environment and Complete Files

Create an empty disposable directory, Node 22.x/npm 10.x, free port 8831, current browser. Install only the pinned dependency below; no global installation or network configuration changes. This fixture assigns every accepted connection the synthetic principal `alice`; it demonstrates policy, not real authentication.

### File: package.json

```json
{
	"name": "ws-mechanics-lab",
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
import {WebSocketServer, WebSocket} from 'ws';
const origin = 'http://127.0.0.1:8831';
const html = readFileSync(new URL('./index.html', import.meta.url));
const server = http.createServer((request, response) => {
	response.writeHead(request.url === '/' ? 200 : 404, {'Content-Type': 'text/html'});
	response.end(request.url === '/' ? html : 'Not found');
});
const sockets = new WebSocketServer({noServer: true, maxPayload: 4096, perMessageDeflate: false});
server.on('upgrade', (request, socket, head) => {
	if (request.url !== '/socket' || request.headers.origin !== origin ||
			request.headers['sec-websocket-protocol'] !== 'lab.v1') {
		socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
		return;
	}
	sockets.handleUpgrade(request, socket, head, client => sockets.emit('connection', client));
});
sockets.on('connection', client => {
	client.alive = true;
	client.on('pong', () => { client.alive = true; });
	client.on('error', error => console.log('socket error', error.code));
	const reply = value => {
		if (client.readyState !== WebSocket.OPEN) return;
		if (client.bufferedAmount > 65536) return client.close(1008, 'slow consumer');
		client.send(JSON.stringify(value));
	};
	client.on('message', (bytes, binary) => {
		if (binary) return reply({error: 'text required'});
		let data;
		try { data = JSON.parse(bytes.toString()); }
		catch { return reply({error: 'invalid JSON'}); }
		if (!data || data.type !== 'echo' || typeof data.text !== 'string' ||
				data.text.length > 128 || typeof data.room !== 'string') {
			return reply({error: 'schema'});
		}
		if (data.room !== 'alice') return reply({error: 'forbidden room'});
		reply({type: 'echo', room: 'alice', text: data.text});
	});
});
const heartbeat = setInterval(() => {
	for (const client of sockets.clients) {
		if (!client.alive) { client.terminate(); continue; }
		client.alive = false;
		client.ping();
	}
}, 15000);
heartbeat.unref();
server.listen(8831, '127.0.0.1', () => console.log(origin));
```

### File: index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>WebSocket mechanics</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>WebSocket mechanics</h1>
<button id="connect">Connect</button>
<button id="valid">Echo</button>
<button id="invalid">Malformed JSON</button>
<button id="other">Other room</button>
<button id="close">Close</button>
<pre id="log" aria-live="polite"></pre>
<script>
let socket;
const log = text => document.querySelector('#log').textContent += text + '\n';
document.querySelector('#connect').onclick = () => {
	if (socket && socket.readyState < 2) return log('Already connecting/open');
	socket = new WebSocket('ws://127.0.0.1:8831/socket', 'lab.v1');
	socket.onopen = () => log('OPEN protocol=' + socket.protocol);
	socket.onmessage = event => log('MESSAGE ' + event.data);
	socket.onerror = () => log('ERROR: inspect server/Network evidence');
	socket.onclose = event => log('CLOSE ' + event.code + ' clean=' + event.wasClean);
};
function send(value) {
	if (socket?.readyState !== WebSocket.OPEN) return log('Not open');
	if (socket.bufferedAmount > 65536) return log('Queue full');
	socket.send(value);
	log('QUEUED ' + socket.bufferedAmount);
}
document.querySelector('#valid').onclick = () => send(JSON.stringify({type: 'echo', room: 'alice', text: 'hello'}));
document.querySelector('#invalid').onclick = () => send('{');
document.querySelector('#other').onclick = () => send(JSON.stringify({type: 'echo', room: 'bob', text: 'hello'}));
document.querySelector('#close').onclick = () => socket?.close(1000, 'done');
</script>
```

### Objectives and Steps

```powershell
npm install --ignore-scripts --no-audit --no-fund
node server.mjs
```

Open `http://127.0.0.1:8831/`. Click Connect, Echo, Malformed JSON, Other room, Echo, Close, in order, waiting for each response. Inspect the handshake and messages in DevTools Network. For a second-origin test, start `python -m http.server 8832 --bind 127.0.0.1` in another terminal in this same directory (Python 3.11+ optional prerequisite), open `http://127.0.0.1:8832/index.html`, and click Connect.

### Hints

The page's JavaScript always connects to 8831, so serving it on 8832 changes the browser Origin while leaving the destination unchanged. Browser error events hide the HTTP rejection detail; the Network panel supplies it.

### Solution and Expected Results

First origin: OPEN with `lab.v1`; echo JSON with `hello`; `invalid JSON`; `forbidden room`; successful echo again; clean close code 1000. Second origin: no OPEN, handshake 403 in Network, error/abnormal close may be reported by the browser. The immediate QUEUED reading includes the nonempty data just sent in that task; after the event loop/network drains it can return to zero. Neither value proves application receipt. Idle healthy clients remain open because browser protocol handling automatically answers pings.

### Verification, Troubleshooting, and Cleanup

Validated 2026-11-03 with Node 22.23.4/npm 10.9.9: exact complete files extracted to a disposable directory, printed install passed with `ws` 8.22.1, server syntax/startup and HTTP delivery of the exact HTML passed on loopback; server stopped. Official npm metadata selected 8.22.1 as a non-major fix. The former 8.18.3 dependency audit reported one high-severity vulnerable package with two advisories: [memory disclosure](https://github.com/advisories/GHSA-58qx-3vcg-4xpx) (moderate, affected 8.x <8.20.1) and [memory exhaustion](https://github.com/advisories/GHSA-96hv-2xvq-fx4p) (high, affected 8.x <8.21.0). The patched lab's `npm audit --json` exited 0 with zero reported vulnerabilities at all severities; this is a point-in-time dependency check, not a security guarantee.

Browser UI, handshake/Origin behavior, echo/denial/close sequence, heartbeat and rendering were not tested in this pass. Run all browser steps above before claiming those outcomes. Keep the generated lock for repeat runs using `npm ci --ignore-scripts`. Port conflict: use a different coordinated pair and update literals; never stop someone else's service. Stop only lab servers with Ctrl+C, close tabs and delete the disposable directory. There is no persisted session state.

- [ ] Local WebSockets exercise: Build a loopback echo service with a maintained WebSocket library. Send JSON messages, malformed input, and a clean close; record connection and message-level outcomes.
- [ ] Boundary check: Open the lab socket from a second origin and require handshake rejection. On an authorized connection, request another synthetic user's subscription and require message-level denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[WebSocket Attacks]]
- [[WebSockets Security]]

## References

- [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)
- [RFC 8441: HTTP/2 bootstrap](https://www.rfc-editor.org/rfc/rfc8441)
- [WHATWG WebSockets](https://websockets.spec.whatwg.org/)
- [Browser WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
- [ws documentation and examples](https://github.com/websockets/ws)
