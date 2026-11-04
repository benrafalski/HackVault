---
title: "Service Workers Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[Service Workers]]"
updated: 2026-11-03
---
# Service Workers Security

> [!abstract] TL;DR
> Cache only explicitly public resources. Registration scope is not a storage partition, and HTTP `no-store` alone does not prevent Cache Storage writes. Test logout, account switching, offline denial and scoped cleanup together.

> [!info] Agent scope
> Security of: Registration and scope; lifecycle; fetch interception; cache APIs; update behavior; secure contexts. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Worker script delivery, scope headers, update lifecycle, controlled-client fetches, origin-wide caches, worker messages and session transitions. Only defensive validation is demonstrated here; there is no persistence/evasion technique or modification of an existing site.

## Learn

```text
Teach defensive service-worker and cache design at expert depth. Assume Fetch,
HTTP caching, browser origins and promises. Explain script/scope trust, secure
contexts, controlled-client fetch dispatch, Cache Storage versus HTTP cache,
request keys/Vary, opaque responses, update races, quota/eviction and cleanup.
Focus on preventing personalized data from crossing logout/account boundaries.
Compare a harmless URL-only cache model with a fixed public-resource allowlist
and network-only private endpoint. Supply a complete loopback browser/server lab
with synthetic Alice/Bob sessions, offline denial, stale UI prevention, exact
scope/cache inspection, hints, worked results and cleanup. Explain why no-store,
unregister and closing one tab are not complete controls. Use primary sources.
No persistence, evasion, exploitation, existing-site edits or fabricated results.
Teach here, not file edits; end with difficult questions and worked answers.
```

## Cheatsheet

### Root Causes and Boundaries

| Assumption | Reality | Defensive rule |
|---|---|---|
| Cache is scoped to the worker | Cache Storage is origin-wide | Unique application prefix; delete only owned names |
| `no-store` prevents all storage | Cache API does not enforce HTTP freshness/cache directives for you | Explicit public-resource allowlist before any `put` |
| Different login means different cache | Cache keys do not automatically include current account | Network-only personalized responses by default |
| URL path scope limits every intercepted URL | Scope selects clients; their fetches can be outside that path | Filter method, origin, exact URL and response type |
| Unregister immediately removes all effects | Controlled pages and caches can remain | Unregister exact scope, remove owned caches, close controlled tabs |
| Secure context means script is approved | HTTPS protects transport, not application trust | Trusted deploy path, reviewed worker bytes, controlled updates |

A URL-only cache can reuse `/profile` across accounts if identity travels in cookies or other unkeyed state. Cache matching can consider `Vary`, but do not assume servers always emit a complete safe key or deliberately use `ignoreVary`. Cache API permits explicit storage even when the response says no-store. Never fall back to another user's successful response after a 401/403 or network failure.

### Concrete Fixed Policy

```javascript
const publicPaths = new Set(['/app/index.html', '/app/logo.png']);
const url = new URL(request.url);
const mayCache = request.method === 'GET' && url.origin === self.location.origin &&
	!url.search && publicPaths.has(url.pathname);
```

This fragment is the start of a policy, not proof the listed resources are public. Verify that even the HTML shell is not personalized. Restrict writes to successful same-origin responses of expected type. Treat redirects, error pages, query variants and opaque cross-origin responses explicitly. Request `cache: 'no-store'` controls the HTTP cache, not arbitrary Cache API writes; use both network-only routing and the correct HTTP headers.

Logout should clear in-memory UI and pending work as well as revoke server sessions. An old in-flight response can arrive after an account switch: bind it to a generation/account and discard late results. If private offline storage is genuinely required, define its threat model, account partitioning, expiry and logout deletion explicitly; browser code and local storage do not become a secure secret vault by encrypting with a key stored alongside the data.

### Update and Permission Boundaries

Registration normally needs a secure context but no ordinary user permission prompt. Scope cannot normally exceed the worker script directory without `Service-Worker-Allowed`. Do not broaden that header without a justified need. CSP `worker-src` can constrain worker creation; script hosting and update policy must still be trusted. Avoid automatic `skipWaiting`/`clients.claim` when existing pages have incompatible state. Service worker global variables can disappear between events; keep authorization authoritative on the server.

## Detection and Defense

Inventory exact registration scope/script URL and release version, observe update failures, and inspect cache names/keys for personalized endpoints. Log bounded route/status/cache-decision counters, not response bodies or tokens. Test with two synthetic identities, logout, denied authorization, network failure, worker update, storage eviction and late response arrival. A worker can mask a network outage with a cached 200, so verify response provenance and actual cache keys, not just status.

## Labs

### Environment and Complete Files

Python 3.11+ standard library, current Chromium/Firefox, fresh disposable browser profile, free port 8861. Create a disposable root with `server.py` and subdirectory `sw-security/` containing the other files. The header-selected identities are fixtures, not authentication. No real data, credentials or external dependencies.

### File: server.py

```python
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
FILES = {
		"/sw-security/index.html": ("sw-security/index.html", "text/html; charset=utf-8"),
		"/sw-security/sw.js": ("sw-security/sw.js", "text/javascript; charset=utf-8"),
		"/sw-security/public.txt": ("sw-security/public.txt", "text/plain; charset=utf-8"),
}

class Handler(BaseHTTPRequestHandler):
		def do_GET(self):
				path = urlsplit(self.path).path
				if path == "/sw-security/profile":
						user = self.headers.get("X-Lab-User", "none")
						status = 200 if user in {"alice", "bob"} else 401
						data = {"user": user, "label": f"synthetic {user} profile"} if status == 200 else {"error": "signed out"}
						body = json.dumps(data).encode()
						media_type = "application/json"
				elif path in FILES:
						filename, media_type = FILES[path]
						body = (ROOT / filename).read_bytes()
						status = 200
				else:
						body, media_type, status = b"Not found", "text/plain", 404
				self.send_response(status)
				self.send_header("Content-Type", media_type)
				self.send_header("Content-Length", str(len(body)))
				self.send_header("Cache-Control", "no-store")
				self.end_headers()
				self.wfile.write(body)

if __name__ == "__main__":
		print("http://127.0.0.1:8861/sw-security/index.html", flush=True)
		ThreadingHTTPServer(("127.0.0.1", 8861), Handler).serve_forever()
```

### File: sw-security/public.txt

```text
Public offline fixture
```

### File: sw-security/sw.js

```javascript
const PREFIX = 'hv-w1-sw-security-';
const CACHE = PREFIX + 'v1';
const PUBLIC = ['/sw-security/index.html', '/sw-security/public.txt'];
self.addEventListener('install', event => {
	event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(PUBLIC)));
});
self.addEventListener('activate', event => {
	event.waitUntil(caches.keys().then(keys => Promise.all(keys
		.filter(key => key.startsWith(PREFIX) && key !== CACHE)
		.map(key => caches.delete(key)))));
});
self.addEventListener('fetch', event => {
	const url = new URL(event.request.url);
	if (url.origin !== self.location.origin || event.request.method !== 'GET') return;
	if (url.pathname === '/sw-security/profile') {
		event.respondWith(fetch(event.request, {cache: 'no-store'}).catch(() =>
			new Response(JSON.stringify({error: 'private data unavailable offline'}), {
				status: 503, headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
			})));
		return;
	}
	if (url.search || !PUBLIC.includes(url.pathname)) return;
	event.respondWith(caches.open(CACHE).then(async cache =>
		await cache.match(event.request) || fetch(event.request)));
});
```

### File: sw-security/index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Private-response cache policy</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>Private-response cache policy</h1>
<button id="register">Register</button>
<label>Synthetic account <select id="account">
	<option value="none">Signed out</option><option>alice</option><option>bob</option>
</select></label>
<button id="profile">Read profile</button>
<button id="public">Read public fixture</button>
<button id="baseline">Run weak cache model</button>
<button id="audit">Audit lab cache keys</button>
<button id="cleanup">Clean lab registration and caches</button>
<p>Current profile: <output id="state">none</output></p>
<pre id="log" aria-live="polite"></pre>
<script>
const prefix = 'hv-w1-sw-security-';
const scope = new URL('/sw-security/', location.origin).href;
const account = document.querySelector('#account');
const state = document.querySelector('#state');
const log = text => document.querySelector('#log').textContent += text + '\n';
let generation = 0;
const run = action => () => action().catch(error => log(error.name + ': ' + error.message));
account.onchange = () => { generation++; state.textContent = 'none'; };
document.querySelector('#register').onclick = run(async () => {
	await navigator.serviceWorker.register('./sw.js', {scope: './', updateViaCache: 'none'});
	await navigator.serviceWorker.ready;
	log('ACTIVE; reload once to control this page');
});
document.querySelector('#profile').onclick = run(async () => {
	const requestGeneration = generation;
	const user = account.value;
	state.textContent = 'loading';
	const response = await fetch('./profile', {
		cache: 'no-store', credentials: 'omit', headers: {'X-Lab-User': user}
	});
	const data = await response.json();
	if (generation !== requestGeneration || user !== account.value) return log('DISCARD old-account response');
	state.textContent = response.ok ? data.label : 'none';
	log(response.status + ' ' + JSON.stringify(data));
});
document.querySelector('#public').onclick = run(async () => log(await (await fetch('./public.txt')).text()));
document.querySelector('#baseline').onclick = () => {
	const model = new Map([['/profile', {user: 'alice'}]]);
	const requestedUser = 'bob';
	const returnedUser = model.get('/profile').user;
	log('MODEL ONLY: requested=' + requestedUser + ' returned=' + returnedUser);
};
document.querySelector('#audit').onclick = run(async () => {
	for (const key of await caches.keys()) {
		if (!key.startsWith(prefix)) continue;
		const requests = await (await caches.open(key)).keys();
		const paths = requests.map(request => new URL(request.url).pathname);
		const safe = paths.every(path => ['/sw-security/index.html', '/sw-security/public.txt'].includes(path));
		log((safe ? 'PASS ' : 'FAIL ') + key + ' ' + JSON.stringify(paths));
	}
	log('CONTROLLED ' + Boolean(navigator.serviceWorker.controller));
});
document.querySelector('#cleanup').onclick = run(async () => {
	for (const registration of await navigator.serviceWorker.getRegistrations()) {
		if (registration.scope === scope) await registration.unregister();
	}
	for (const key of await caches.keys()) {
		if (key.startsWith(prefix)) await caches.delete(key);
	}
	generation++; state.textContent = 'none';
	log('CLEANED exact scope/cache prefix; close all lab tabs');
});
</script>
```

### Objectives and Baseline

Run `python server.py` from the disposable root and open its printed URL. Register, wait for ACTIVE, then reload. Run weak cache model: it must report requested Bob but returned Alice. This is a pure in-memory baseline, not an unsafe worker mode or a stored private response.

Choose Alice and read profile, then Bob and read profile, then Signed out and read profile. Audit cache keys. Stop this lab server with Ctrl+C while keeping the controlled page open, then repeat Alice/Bob/profile and public reads. The worker must not convert offline failure into a previous successful profile.

### Hints

HTTP 401 is a fulfilled fetch response, not a network exception; it should remain 401. Only a transport failure produces the lab's 503 JSON fallback. Both the worker's route policy and page's account-generation check matter: correct caches do not alone prevent stale in-memory UI.

### Solution and Fixed Retest

| Check | Expected outcome |
|---|---|
| Weak model | `requested=bob returned=alice` demonstrates the flawed key |
| Online Alice/Bob | 200 with only the selected account's synthetic label |
| Signed out | 401 and displayed profile `none` |
| Offline profile, either account | 503 `private data unavailable offline`; display `none` |
| Offline public fixture | `Public offline fixture` still readable |
| Cache audit | Only index/public paths, no profile URL, CONTROLLED true |
| Restart server and read Bob | 200 Bob again; permitted behavior survives |

Use Network throttling to delay a profile response, then switch accounts before it arrives: old-account response must be discarded and not repopulate the display. This is a manual race check, not a timing guarantee from a normal fast run.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must execute every matrix row and race check, inspect exact scope/cache keys and verify browser rendering. If offline fetch throws instead of returning 503, the page likely lacks a controller: restart, register, wait and reload. An empty cache audit is not proof of correct installation; require both listed public entries and CONTROLLED true.

Cleanup while the page is available: click Clean, close all `/sw-security/` tabs, inspect that exact registration/cache prefix is gone, stop only this server and delete the disposable directory/profile. Do not clear an entire browser profile containing unrelated sites or unregister other scopes. The lab has no actual login or persisted credentials; production must replace the fixture identity header with server authentication.

- [ ] Local Service Workers exercise: Add offline caching to a local app, then publish a new cache version. Verify online, offline, reload, and update behavior; delete old caches during controlled activation.
- [ ] Boundary check: Log in as two synthetic users in the lab and confirm user-specific responses never appear from a shared offline cache after logout or account switching.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Service Workers]]

## References

- [Service Workers specification](https://w3c.github.io/ServiceWorker/)
- [Cache API and HTTP-cache differences](https://developer.mozilla.org/en-US/docs/Web/API/Cache)
- [ServiceWorkerRegistration.unregister](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/unregister)
- [ServiceWorkerContainer.register and scope](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerContainer/register)
- [CSP worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src)
