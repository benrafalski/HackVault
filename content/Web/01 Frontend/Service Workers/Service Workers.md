---
title: "Service Workers"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[Service Workers Security]]"
updated: 2026-11-03
---
# Service Workers

> [!abstract] TL;DR
> A registration selects clients by origin and path scope; an active worker controls fetch policy for those clients. Installation, activation and control are distinct. Cache Storage is explicit application-managed storage, not the HTTP cache.

> [!info] Agent scope
> Registration and scope; lifecycle; fetch interception; cache APIs; update behavior; secure contexts.

## Prerequisites

- Promises, Fetch/Response streams, HTTP caching and origins. Current Chromium or Firefox, Python 3.11+ and a fresh disposable browser profile.
- Free loopback port 8851. Use only `/sw-tech/` in this lab; do not register a worker on an existing site. Loopback HTTP is normally potentially trustworthy; arbitrary LAN HTTP is not.

## Learn

```text
Teach service workers at expert browser-engineering depth. Assume promises,
Fetch streams, HTTP caching and origins. Explain registration URL/scope limits,
secure contexts, installing/waiting/active states versus client control, update
checks, updateViaCache, skipWaiting and clients.claim. Trace fetch dispatch,
respondWith/waitUntil timing, cloning streams, Cache Storage keys and matching,
cache-first/network-first/stale-while-revalidate, eviction and offline failures.
Give a complete visible loopback app with narrow scope, explicit update consent,
versioned cache cleanup and exact offline/update acceptance tests. Explain why
scope is not a cache namespace/security boundary and why authenticated responses
need a separate policy. Use primary sources, no existing-site changes, no
persistence/evasion techniques, no file edits or fabricated execution claims.
End with difficult questions and worked answers.
```

## Cheatsheet

### Registration, Lifecycle, and Control

| State/action | Actual meaning |
|---|---|
| `register('/app/sw.js', {scope: '/app/'})` | Creates/updates a registration; does not immediately control the calling page |
| `install` | Prepare a complete new cache; rejecting `waitUntil` fails installation |
| `waiting` | New worker installed while an old active worker still has clients |
| `activate` | Transition to active; migrate/delete only caches owned by this app |
| `navigator.serviceWorker.controller` | Worker currently controlling this document, possibly null |
| `navigator.serviceWorker.ready` | Resolves when an associated registration has an active worker; not proof this document is controlled |
| `skipWaiting()` | Requests early activation; can mix old page code and new fetch policy |
| `clients.claim()` | Lets an active worker take eligible uncontrolled clients; does not replace a data migration plan |
| `unregister()` | Removes registration for future use; existing controlled documents may continue until unloaded |

Script and registration are same-origin. Default maximum scope is the script's directory; `Service-Worker-Allowed` can authorize a broader scope but is intentionally unnecessary here. Most-specific matching registration wins. Secure-context availability does not require a separate user permission prompt for ordinary registration; notifications/push and other capabilities have additional requirements. Registration can still fail due to policy, storage mode, MIME, script errors or unsupported contexts.

The browser can stop a worker between events; globals are not durable state. Workers have no DOM. Use Cache Storage/IndexedDB for appropriate durable data, with eviction/error handling. Do not rely on a worker remaining alive as a timer service.

### Fetch and Storage

Call `event.respondWith(promise)` synchronously inside the event handler. Put asynchronous work inside that promise. `waitUntil` extends an event's useful lifetime for completion; it does not guarantee infinite execution. Request and response bodies are streams: clone before consuming a body twice.

```javascript
const response = await fetch(request);
if (response.ok && response.type === 'basic') {
	await cache.put(request, response.clone());
}
return response;
```

This fragment is safe only after an explicit public-resource allowlist. Cache API does not automatically implement HTTP freshness or obey `Cache-Control: no-store`; your code must choose what to store. `cache.put` can store responses that `cache.addAll` would reject. `addAll` fetches resources and rejects for failed/non-successful members, making it useful for install readiness. Cache matching uses request URL/method and applicable Vary semantics; ignoring search or Vary can collapse distinct representations. Avoid those options without a specific proof.

| Strategy | Good fit | Failure mode |
|---|---|---|
| Cache first | Versioned immutable public assets | Stale resources without version/update discipline |
| Network first | Public data needing freshness plus offline fallback | Latency/offline detection; stale fallback may need labeling |
| Stale while revalidate | Public content tolerating bounded staleness | Background failure invisible unless reported |
| Network only | Personalized, authorization-sensitive operations | Offline denial must be explicit, not another user's cached content |

Scope selects controlled clients, not a same-path-only fetch firewall: their subresource requests can trigger the worker outside the scope path or cross-origin. Filter URL, method, origin and response before applying a strategy. Cache names are origin-wide, not per registration; use an application prefix and never delete every cache on an origin.

### Updates

Keep the worker URL stable and change its bytes/version. `registration.update()` requests a check; `updateViaCache: 'none'` avoids HTTP-cache reuse for the script/import checks, not Cache Storage use. A waiting worker normally activates after old controlled clients are gone; reload alone can preserve the old lifecycle. Prompt for adoption, activate deliberately, and reload on controller change if code/cache formats require alignment. Deleting caches while an old page still needs them can break that page even when activation is intentional.

## Gotchas

- Storage can be evicted; offline availability is not an unlimited durability guarantee.
- DevTools bypass/update-on-reload toggles change behavior. Disable them when testing the normal lifecycle.
- Clearing HTTP cache does not necessarily remove registrations or Cache Storage.

## Labs

### Environment and Complete Files

Create an empty disposable root with subdirectory `sw-tech/`. Use a fresh browser profile so the loopback origin has no unrelated registrations. Put `server.py` in the root and the three browser files in `sw-tech/`. Do not put these in an existing web application. Header-selected account names below are synthetic fixture identities, not authentication.

### File: server.py

```python
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
FILES = {
	"/sw-tech/index.html": ("sw-tech/index.html", "text/html; charset=utf-8"),
	"/sw-tech/sw.js": ("sw-tech/sw.js", "text/javascript; charset=utf-8"),
	"/sw-tech/data.txt": ("sw-tech/data.txt", "text/plain; charset=utf-8"),
}

class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		path = urlsplit(self.path).path
		if path == "/sw-tech/profile":
			user = self.headers.get("X-Lab-User", "none")
			status = 200 if user in {"alice", "bob"} else 401
			data = {"user": user} if status == 200 else {"error": "signed out"}
			body, media_type = json.dumps(data).encode(), "application/json"
		elif path in FILES:
			filename, media_type = FILES[path]
			body, status = (ROOT / filename).read_bytes(), 200
		else:
			body, media_type, status = b"Not found", "text/plain", 404
		self.send_response(status)
		self.send_header("Content-Type", media_type)
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body)

if __name__ == "__main__":
	print("http://127.0.0.1:8851/sw-tech/index.html", flush=True)
	ThreadingHTTPServer(("127.0.0.1", 8851), Handler).serve_forever()
```

### File: sw-tech/data.txt

```text
Public fixture version 1
```

### File: sw-tech/sw.js

```javascript
const VERSION = 'v1';
const PREFIX = 'hv-w1-sw-tech-';
const CACHE = PREFIX + VERSION;
const ASSETS = ['/sw-tech/index.html', '/sw-tech/data.txt'];
self.addEventListener('install', event => {
	event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS)));
});
self.addEventListener('activate', event => {
	event.waitUntil(caches.keys().then(keys => Promise.all(keys
		.filter(key => key.startsWith(PREFIX) && key !== CACHE)
		.map(key => caches.delete(key)))));
});
self.addEventListener('message', event => {
	if (event.data?.type === 'ACTIVATE_LAB_UPDATE') event.waitUntil(self.skipWaiting());
});
self.addEventListener('fetch', event => {
	const url = new URL(event.request.url);
	if (event.request.method !== 'GET' || url.origin !== self.location.origin ||
			url.search || !ASSETS.includes(url.pathname)) return;
	event.respondWith((async () => {
		const cache = await caches.open(CACHE);
		const response = await cache.match(event.request) || await fetch(event.request);
		const headers = new Headers(response.headers);
		headers.set('X-Lab-Cache', VERSION);
		return new Response(response.body, {status: response.status, headers});
	})());
});
```

### File: sw-tech/index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Scoped offline lifecycle</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>Scoped offline lifecycle</h1>
<button id="register">Register</button>
<button id="read">Read public fixture</button>
<button id="update">Check update</button>
<button id="activate">Adopt waiting update</button>
<button id="status">Status</button>
<button id="cleanup">Unregister and clean lab caches</button>
<label>Synthetic account <select id="account">
	<option value="none">Signed out</option><option>alice</option><option>bob</option>
</select></label>
<button id="profile">Read network-only profile</button>
<p>Profile: <output id="profile-state">none</output></p>
<pre id="log" aria-live="polite"></pre>
<script>
const scope = new URL('/sw-tech/', location.origin).href;
const prefix = 'hv-w1-sw-tech-';
const log = text => document.querySelector('#log').textContent += text + '\n';
const account = document.querySelector('#account');
const profileState = document.querySelector('#profile-state');
let generation = 0;
account.onchange = () => { generation++; profileState.textContent = 'none'; };
async function registration() {
	const registrations = await navigator.serviceWorker.getRegistrations();
	return registrations.find(item => item.scope === scope);
}
function run(action) {
	return () => action().catch(error => log(error.name + ': ' + error.message));
}
document.querySelector('#profile').onclick = run(async () => {
	const requestedGeneration = generation;
	profileState.textContent = 'none';
	const response = await fetch('./profile', {
		cache: 'no-store', credentials: 'omit', headers: {'X-Lab-User': account.value}
	});
	const data = await response.json();
	if (requestedGeneration !== generation) return log('DISCARD old-account response');
	if (response.ok) profileState.textContent = data.user;
	log('PROFILE ' + response.status + ' ' + JSON.stringify(data));
});
document.querySelector('#register').onclick = run(async () => {
	const item = await navigator.serviceWorker.register('./sw.js', {
		scope: './', updateViaCache: 'none'
	});
	item.addEventListener('updatefound', () => {
		const worker = item.installing;
		worker?.addEventListener('statechange', () => log('WORKER ' + worker.state));
	});
	log('REGISTERED; inspect Status, then reload after activation');
});
document.querySelector('#read').onclick = run(async () => {
	const response = await fetch('./data.txt');
	log('DATA ' + (await response.text()).trim() + '; worker=' + response.headers.get('X-Lab-Cache'));
});
document.querySelector('#status').onclick = run(async () => {
	const item = await registration();
	log(JSON.stringify({controlled: Boolean(navigator.serviceWorker.controller),
		active: item?.active?.state, waiting: item?.waiting?.state,
		caches: (await caches.keys()).filter(key => key.startsWith(prefix))}));
});
document.querySelector('#update').onclick = run(async () => {
	const item = await registration();
	if (!item) return log('Register first');
	await item.update();
	log('UPDATE check requested; inspect Status after installation');
});
document.querySelector('#activate').onclick = run(async () => {
	const item = await registration();
	if (!item?.waiting) return log('No waiting update');
	item.waiting.postMessage({type: 'ACTIVATE_LAB_UPDATE'});
});
navigator.serviceWorker.addEventListener('controllerchange', () => location.reload());
document.querySelector('#cleanup').onclick = run(async () => {
	const item = await registration();
	if (item) await item.unregister();
	for (const key of await caches.keys()) {
		if (key.startsWith(prefix)) await caches.delete(key);
	}
	log('LAB registration/cache removed. Close all lab tabs now.');
});
</script>
```

### Objectives and Steps

From the disposable root:

```powershell
python server.py
```

1. Open `http://127.0.0.1:8851/sw-tech/index.html`, click Register, then Status until active is `activated`. Reload once to become controlled. Read must report version 1 and worker `v1`.
2. Stop only this lab server, then Read and reload the exact URL. Both should work from the installed public cache. Restart the same server before updating.
3. Change the data text to `Public fixture version 2` and change only `VERSION` in the worker to `v2`. Click Check update, then Status after installation. Keep the old page open: waiting should be `installed`, while Read still returns v1.
4. Click Adopt waiting update. After controller change/reload, Read must show version 2/worker v2; Status should list only the v2 lab cache.
5. With server running, select Alice, then Bob, then Signed out, reading the profile each time. Expect 200 Alice, 200 Bob, then 401 with display `none`. Stop the server, choose either account and read again: fetch must fail and display remain `none`, while public fixture reads still work. In DevTools Cache Storage confirm only index/data URLs exist, never `/sw-tech/profile`. Restart the server and verify Bob reads successfully again.

### Hints

Initial activation does not automatically claim the already open page; the reload is intentional. A changed data file alone does not force the worker's byte-comparison update. Use the exact `/index.html` URL: this minimal allowlist does not include directory redirects or query-string variants.

### Solution and Expected Results

Expected transitions: uncontrolled -> registered active but possibly still uncontrolled -> controlled v1 -> offline v1 -> v2 waiting with active v1 -> explicitly adopted v2. The waiting phase demonstrates compatibility protection, not an update failure. The worker does not claim unrelated clients or intercept unlisted resources.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must check offline reload, waiting/adoption, cache deletion and registration scope in DevTools. If installation fails, verify all three files and JS MIME type; inspect worker console. If v2 activates immediately, the old worker had no controlled clients or DevTools altered lifecycle behavior.

Cleanup: restart server if needed, click cleanup, close every `/sw-tech/` tab, then inspect this dedicated profile's registration list to confirm the exact scope is gone and only `hv-w1-sw-tech-*` caches were removed. Stop the lab server and delete the disposable directory/profile. Do not use global clear-site-data or unregister unrelated workers. The account fixture uses the same profile URL for both users; its exclusion from the public allowlist is what prevents shared offline reuse.

- [ ] Local Service Workers exercise: Add offline caching to a local app, then publish a new cache version. Verify online, offline, reload, and update behavior; delete old caches during controlled activation.
- [ ] Boundary check: Log in as two synthetic users in the lab and confirm user-specific responses never appear from a shared offline cache after logout or account switching.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Service Workers Security]]

## References

- [Service Workers specification](https://w3c.github.io/ServiceWorker/)
- [ServiceWorkerContainer.register](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerContainer/register)
- [Cache API](https://developer.mozilla.org/en-US/docs/Web/API/Cache)
- [Service worker lifecycle](https://web.dev/articles/service-worker-lifecycle)
- [Secure contexts](https://w3c.github.io/webappsec-secure-contexts/)
