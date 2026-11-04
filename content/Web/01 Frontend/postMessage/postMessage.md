---
title: "postMessage"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[postMessage Security]]"
updated: 2026-11-03
---
# postMessage

> [!abstract] TL;DR
> `postMessage` delivers structured data to another window asynchronously. An exact `targetOrigin` restricts delivery; the receiver independently validates origin, window identity, schema and operation. Transferable buffers move ownership rather than merely copying bytes.

> [!info] Agent scope
> Window messaging; targetOrigin; sender validation; structured clone; iframe and popup trust boundaries.

## Prerequisites

- Browser event handlers, origins (scheme/host/port), DOM references and JavaScript objects.
- Current Chromium or Firefox and Python 3.11+ for a loopback-only static server. No npm dependencies or browser permissions are needed. Do not use `file:` URLs.

## Learn

```text
Teach window postMessage at expert browser-engineering depth. Assume JavaScript,
DOM events and same-origin policy. Explain WindowProxy, asynchronous delivery,
targetOrigin versus MessageEvent.origin/source, navigation races, iframe/popup
lifetimes and opaque origins. Work through structured clone, transferable
ArrayBuffers, MessageChannel capabilities, SharedArrayBuffer isolation, versioned
schemas, request IDs, bounded pending requests, timeouts and safe rendering.
Give complete two-origin examples with visible success and rejection evidence,
exact startup commands and negative checks. Cover popup blocking, COOP, sandbox,
DataCloneError and messageerror. Use primary sources and distinguish defaults
from policy choices. Use synthetic data only, no exploitation or bypass. Teach
in chat, not file edits; do not claim unrun tests passed. End with worked questions.
```

## Cheatsheet

### Delivery and Identity

```javascript
otherWindow.postMessage({v: 1, type: 'ping', id: 7}, 'https://widget.example');
```

This is a fragment, not a complete protocol. `otherWindow` must be a window reference obtained from an iframe or popup. Cross-origin DOM access remains restricted; messaging grants no general DOM access. The caller returns before the target handles the event. Delivery is not an acknowledgement, durable queue or guarantee that a listener exists.

| Value | Meaning | Not sufficient for |
|---|---|---|
| `targetOrigin` | Destination origin allowed at delivery time; scheme, host and port matter | Authenticating replies |
| `event.origin` | Sender origin when `postMessage` was called | Identifying which of several same-origin windows sent it |
| `event.source` | Sender WindowProxy | Proving that window has not navigated since sending |
| Payload identity fields | Application claims | Authentication without independent binding |
| Request ID | Correlates pending operations | Permission or freshness by itself |

Use the full explicit origin, never a URL path, hostname substring or user-supplied payload origin. An omitted/default `targetOrigin` is not a general cross-origin transport setting; always specify it in cross-origin examples. `"*"` permits any destination origin. Opaque-origin documents, including some sandboxed frames, serialize their origin as `"null"`; that shared string cannot uniquely authenticate them. Do not use such contexts for sensitive window protocols.

### Clone and Transfer

| Value | Behavior |
|---|---|
| Plain object, array, Map, Set, typed array | Structured clone copies supported data; object identity is not shared |
| Function or DOM node | Not cloneable; sending can synchronously throw `DataCloneError` |
| Custom class object | Do not depend on prototype/method preservation; define a data schema |
| ArrayBuffer in transfer list | Sender buffer is detached; receiver owns the bytes |
| MessagePort | Transfer grants a communication capability; close it when done |
| SharedArrayBuffer | Shared memory, not transfer; requires applicable cross-origin isolation/security conditions |

```javascript
const buffer = new Uint8Array([10, 20, 30]).buffer;
otherWindow.postMessage({v: 1, type: 'bytes', buffer}, expectedOrigin, [buffer]);
console.log(buffer.byteLength);
```

Expected sender byte length after successful transfer: zero. A transferable must also be reachable in the payload if the receiver is to use it. Structured clone does not validate permitted fields, action names, lengths or ranges. Catch send-time exceptions; separately handle receiver `messageerror` for deserialization failures.

### Protocol and Lifecycle Decisions

Register listeners before sending. Use a ready exchange or a load event plus timeout; an iframe `load` alone is not evidence that the remote application is ready. Correlate replies to currently pending IDs, cap pending requests, reject duplicate/late replies, and clear timers on navigation/close. Use `textContent` for data, not HTML parsing or dynamic evaluation.

For a popup, open it from a user gesture, check a null result (blocked popup), and account for COOP or `noopener` severing opener relationships. Keep an exact expected reference and origin. For a `MessageChannel`, authenticate the initial window exchange before handing over a port; later port messages do not provide the same window-origin authentication surface, so possession of the port is authority.

## Gotchas

- A browser delivering the event is not evidence that the application should accept it.
- Parent and child can be mutually untrusted even when embedding is permitted. CSP `frame-ancestors` and iframe sandboxing govern other boundaries, not message authorization.
- `localhost` and `127.0.0.1`, or two different ports, are different origins. Keep all lab URLs exact.

## Labs

### Environment and Complete Files

Create an empty disposable directory with the two files below. Ports 8811, 8812 and optional 8813 must be free; do not stop existing services. If changing ports, change every origin literal consistently. All bytes are synthetic.

### File: parent.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Message ownership lab</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
iframe { display: block; width: min(100%, 36rem); height: 14rem; box-sizing: border-box; }
</style>
<h1>Parent 8811</h1>
<button id="send" disabled>Transfer three bytes</button>
<pre id="log" aria-live="polite"></pre>
<iframe id="child" title="Byte processor" src="http://127.0.0.1:8812/child.html"></iframe>
<script>
const origin = 'http://127.0.0.1:8812';
const frame = document.querySelector('#child');
const button = document.querySelector('#send');
const log = text => document.querySelector('#log').textContent += text + '\n';
let sequence = 0;
let pending = null;
addEventListener('message', event => {
	if (event.origin !== origin || event.source !== frame.contentWindow) {
		log('REJECT sender');
		return;
	}
	const data = event.data;
	if (!data || data.v !== 1) return log('REJECT version');
	if (data.type === 'ready') {
		button.disabled = false;
		return log('READY expected child');
	}
	if (data.type !== 'sum' || !pending || data.id !== pending.id ||
			!Number.isInteger(data.value) || data.value < 0 || data.value > 765) {
		return log('REJECT response');
	}
	clearTimeout(pending.timer);
	pending = null;
	button.disabled = false;
	log('SUM ' + data.value);
});
button.onclick = () => {
	button.disabled = true;
	const id = ++sequence;
	pending = {id, timer: setTimeout(() => {
		pending = null;
		button.disabled = false;
		log('TIMEOUT');
	}, 2000)};
	const buffer = new Uint8Array([10, 20, 30]).buffer;
	try {
		frame.contentWindow.postMessage({v: 1, type: 'bytes', id, buffer}, origin, [buffer]);
		log('SENDER byteLength=' + buffer.byteLength);
	} catch (error) {
		clearTimeout(pending.timer);
		pending = null;
		button.disabled = false;
		log(error.name);
	}
};
frame.addEventListener('load', () => {
	frame.contentWindow.postMessage({v: 1, type: 'hello'}, origin);
});
addEventListener('messageerror', () => log('DESERIALIZATION ERROR'));
</script>
```

### File: child.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Byte processor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h2>Child</h2>
<button id="diagnostic">Send diagnostic ready</button>
<pre id="log" aria-live="polite"></pre>
<script>
const parentOrigin = 'http://127.0.0.1:8811';
const log = text => document.querySelector('#log').textContent += text + '\n';
const ready = () => parent.postMessage({v: 1, type: 'ready'}, parentOrigin);
document.querySelector('#diagnostic').onclick = ready;
addEventListener('message', event => {
	if (event.origin !== parentOrigin || event.source !== parent) return log('REJECT sender');
	const data = event.data;
	if (!data || data.v !== 1) return log('REJECT version');
	if (data.type === 'hello') return ready();
	if (data.type !== 'bytes' || !Number.isSafeInteger(data.id) ||
			!(data.buffer instanceof ArrayBuffer) || data.buffer.byteLength !== 3) {
		return log('REJECT schema');
	}
	const value = new Uint8Array(data.buffer).reduce((sum, byte) => sum + byte, 0);
	log('RECEIVED 3 bytes; sum=' + value);
	parent.postMessage({v: 1, type: 'sum', id: data.id, value}, parentOrigin);
});
</script>
```

### Objectives and Steps

In two separate terminals in the disposable directory:

```powershell
python -m http.server 8811 --bind 127.0.0.1
```

```powershell
python -m http.server 8812 --bind 127.0.0.1
```

Open `http://127.0.0.1:8811/parent.html`. Click Transfer. Observe sender ownership and the child's sum. Repeat to prove the pending slot clears. For a harmless third-origin check, serve the same directory on 8813 in a third terminal, use browser Elements to change only the iframe `src` to `http://127.0.0.1:8813/child.html`, then click the child's diagnostic button. The parent's expected-origin literal remains 8812.

### Hints

The wrong-origin frame still has the same `contentWindow` reference relationship; origin validation must independently reject it. A blocked hello delivery is silent, so the child's diagnostic button makes rejection observable.

### Solution and Expected Results

Normal: `READY expected child`, `SENDER byteLength=0`, `SUM 60`; child displays `RECEIVED 3 bytes; sum=60`. Third-origin diagnostic: parent displays `REJECT sender`, never a new accepted ready response. Restore the iframe URL by reloading the parent; normal operation must return.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring; parent must check all browser observations and narrow/mobile readability. If no ready message, click the child's diagnostic button and check exact origins, server status and iframe errors. Do not loosen validation to `*`. If the port is occupied, choose a coordinated unused trio instead of terminating its owner. Stop only these servers with Ctrl+C, close lab tabs and delete the disposable directory. No persistent browser registrations or permissions were created.

- [ ] Local postMessage exercise: Create a parent and iframe on different loopback origins. Exchange a versioned message with an explicit targetOrigin and verify origin/source checks before updating text.
- [ ] Boundary check: Send a valid-looking message from an unexpected third lab origin. The receiver must ignore it and leave state unchanged; capture a diagnostic rejection without including sensitive data.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[postMessage Security]]

## References

- [HTML cross-document messaging specification](https://html.spec.whatwg.org/multipage/web-messaging.html#crossDocumentMessages)
- [Window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [Structured clone algorithm](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Structured_clone_algorithm)
- [Transferable objects](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Transferable_objects)
