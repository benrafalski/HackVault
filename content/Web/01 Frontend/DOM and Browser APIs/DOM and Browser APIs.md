---
title: "DOM and Browser APIs"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[DOM and Browser APIs Security]]"
updated: 2026-11-03
---
# DOM and Browser APIs

> [!abstract] TL;DR
> Use createElement/textContent for untrusted text; check response.ok; keep long-lived secrets out of script-readable storage when the architecture allows it.

> [!info] Agent scope
> DOM construction and mutation; event propagation; fetch; storage; navigation; sources and sinks; permissions.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me DOM and browser APIs at expert implementation depth. I know HTML,
JavaScript and HTTP. Cover live document construction/mutation, node identity,
collections, event capture/target/bubbling, default actions and delegation,
shadow boundaries, fetch streams/status/CORS/abort, request races, storage
scope/lifetime/quotas, history versus navigation, sources/sinks and permissions.
Trace an actual fetch-backed list through loading, success, empty and failure
states. Provide complete browser files, synthetic JSON, local HTTP commands,
DOM assertions and DevTools observations. Explain stale responses, detached
listeners, storage failures and secure-context/user-activation requirements.
Separate browser-version support from specification guarantees. Use WHATWG
and W3C primary sources. Teach here without editing files or inventing tests.
```

## Cheatsheet

### DOM Identity and Event Dispatch

DOM nodes are objects with identity, ownership and parentage. Appending an existing node moves it; cloning produces different nodes and does not copy listeners registered with `addEventListener`. `replaceChildren()` clears old children and can discard focus/selection. Use stable nodes for ongoing editing and explicit focus restoration when deleting the focused item. A DocumentFragment groups construction without making text safe by itself; the chosen insertion APIs determine interpretation.

`querySelectorAll()` returns a static NodeList; many collections such as `children` are live. Mutating a live collection while indexing forward can skip elements. `textContent` does not force the layout-aware rendered-text calculation associated with `innerText`. `innerHTML` parses; it is not an efficient equivalent to every DOM operation or a text setter.

Event path: capture ancestors, target, then bubble ancestors if the event bubbles. `target` is the originating/retargeted element, `currentTarget` is the listener's element. Shadow DOM can retarget events; `composedPath()` exposes the permitted composed path, not necessarily closed-root internals. `preventDefault()` cancels a cancelable default action, while propagation controls affect listener dispatch. Passive listeners cannot cancel defaults. `stopPropagation()` does not stop other listeners on the same node; `stopImmediatePropagation()` does.

Delegation fragment with an ownership check:

```js
list.addEventListener('click', event => {
	if (!(event.target instanceof Element)) return;
	const button = event.target.closest('button[data-id]');
	if (!button || !list.contains(button)) return;
	selectRecord(button.dataset.id);
});
```

### Fetch and Concurrent Work

| Observation | Interpretation / required action |
|---|---|
| fetch resolves with 404 | HTTP exchange succeeded; inspect `ok`/`status` before parsing |
| fetch rejects | Network, abort, CORS or another fetch-level failure; not an HTTP status |
| `response.json()` rejects | Body may be malformed or not JSON; status checks do not validate schema |
| body already consumed | Response stream is normally single-use; clone before consumption if necessary |
| old response replaces new data | Cancellation/request-generation ownership is missing |
| `mode: 'no-cors'` produces opaque response | Not a way to make another origin's JSON readable |

AbortController cancels supported local work; it does not roll back a server operation already accepted. Use a generation number as well when stale completion must never commit state. Credential mode controls credentials on fetch; default is same-origin. CORS is a browser read-sharing policy, not authentication or CSRF protection. Never manually set a multipart boundary when the browser creates a FormData body.

### Storage, Navigation, Permissions

localStorage is synchronous, string-only, origin-scoped storage; JSON parsing and quota/security exceptions still need handling. sessionStorage is scoped additionally by top-level browsing context and survives reloads. IndexedDB is asynchronous and transactional, suitable for structured larger data. None is automatically confidential from authorized scripts on that origin. Partitioning, private browsing and eviction policies affect availability. The storage event notifies other relevant documents, not the document that made the write.

`history.pushState()` changes same-origin session history without fetching a new document and does not itself emit popstate. Back/Forward traversals can emit popstate; update route state accordingly. `location.assign()` navigates; `replace()` removes the current history entry. Validate destinations and serialize query values using URL/URLSearchParams.

Many powerful APIs require a secure context, permission and/or transient user activation. A Permissions API query does not request the capability, and support varies per permission name/browser. Feature-detect and handle rejection. Querying availability on page load is different from prompting for access; initiate a permission request only from a meaningful user action. Permissions Policy can further restrict an embedded context even if the user previously granted access.

## Gotchas

Catching a fetch exception does not handle ordinary HTTP 4xx/5xx responses. Client-side route guards do not protect server data.

## Labs

### Environment and Complete Files

Current Chromium/Firefox and Python 3.12+ for a stdlib static HTTP server. No npm dependencies. Create a disposable `dom-list-lab` containing the three files below. The server serves only synthetic fixtures and must bind to loopback. Do not open the page as a file URL: that does not reproduce same-origin fetch/storage semantics.

### File: records.json

```json
[{"id":"a","label":"Ada"},{"id":"b","label":"Lin"}]
```

### File: empty.json

```json
[]
```

### File: index.html

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>DOM list lab</title></head>
<body><main><h1>Records</h1>
<nav aria-label="Fixtures"><button data-file="records.json">Load records</button>
<button data-file="empty.json">Load empty</button>
<button data-file="missing.json">Load missing</button></nav>
<p id="status" role="status">Idle</p><ul id="list"></ul>
<output id="selected"></output><pre id="checks"></pre>
</main><script>
const list = document.querySelector('#list');
const status = document.querySelector('#status');
let generation = 0;
let active;
function render(records) {
	const fragment = document.createDocumentFragment();
	for (const record of records) {
		const item = document.createElement('li');
		const button = document.createElement('button');
		button.dataset.id = record.id;
		button.textContent = record.label;
		item.append(button); fragment.append(item);
	}
	list.replaceChildren(fragment);
}
async function load(file) {
	const mine = ++generation;
	active?.abort(); active = new AbortController();
	status.textContent = 'Loading'; render([]);
	document.querySelector('#selected').textContent = '';
	try {
		const response = await fetch(file, {signal: active.signal, cache: 'no-store'});
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const records = await response.json();
		if (!Array.isArray(records) || records.length > 100 || records.some(record =>
			!record || typeof record.id !== 'string' || typeof record.label !== 'string')) {
			throw new Error('Invalid records');
		}
		if (mine !== generation) return;
		render(records); status.textContent = records.length ? 'Ready' : 'Empty';
		document.querySelector('#checks').textContent =
			list.children.length === records.length ? 'PASS row count' : 'FAIL row count';
	} catch (error) {
		if (mine !== generation) return;
		status.textContent = error.name === 'AbortError' ? 'Cancelled' : error.message;
		document.querySelector('#checks').textContent =
			list.children.length === 0 ? 'PASS no stale rows' : 'FAIL stale rows';
	}
}
document.querySelector('nav').addEventListener('click', event => {
	const button = event.target instanceof Element ? event.target.closest('button[data-file]') : null;
	if (button) load(button.dataset.file);
});
list.addEventListener('click', event => {
	const button = event.target instanceof Element ? event.target.closest('button[data-id]') : null;
	if (!button || !list.contains(button)) return;
	document.querySelector('#selected').textContent = `Selected ${button.dataset.id}`;
	const url = new URL(location.href); url.searchParams.set('selected', button.dataset.id);
	history.replaceState(null, '', url);
	try { sessionStorage.setItem('hv-dom-selected', button.dataset.id); }
	catch { document.querySelector('#selected').textContent += ' (storage unavailable)'; }
});
addEventListener('pagehide', () => active?.abort());
</script></body></html>
```

### Objectives and Commands

```powershell
python --version
python -m http.server 8765 --bind 127.0.0.1
```

Run in the lab directory and open `http://127.0.0.1:8765/`. Use another unused port if needed; do not terminate someone else's server. Load each fixture and inspect status, row count and Network. Select Lin and inspect query/sessionStorage. Throttle the browser network, click Load records then Load empty quickly, and verify only the latest operation owns the result.

### Hints

The missing fixture produces an HTTP response, not a rejected fetch. Parsing the server's HTML error page as JSON would hide the useful 404. The generation guard remains useful even when an operation cannot be canceled in time.

### Solution and Expected Results

Records: Ready, two buttons, PASS row count. Empty: Empty, zero rows, PASS row count. Missing: HTTP 404, zero rows, PASS no stale rows. Selecting Lin displays Selected b and changes the query to `selected=b` without another document request. A later empty load must leave zero rows even if an earlier load completes afterward. Browser abort timing is nondeterministic; assert final ownership, not a fixed sequence of Network rows.

### Verification, Troubleshooting, and Cleanup

Use keyboard activation and inspect accessible names. A file-origin fetch failure means the page was not served over HTTP. A 404 for records usually means wrong working directory/case. Storage rejection is handled as degraded functionality, not a crash. Remove only `hv-dom-selected` via DevTools, close the tab, stop your server with Ctrl+C, and delete the lab directory. No commands or browser tests were executed by this revision.

- [ ] Local DOM and Browser APIs exercise: Build a local list with event delegation and fetch-backed loading. Add explicit loading, error, and empty states; verify a 404 does not masquerade as a network exception.
- [ ] Boundary check: Put `<b>LAB</b>` in a query parameter and show it in the page using textContent. Confirm literal rendering and no extra elements in the DOM.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Prototype Pollution]]
- [[DOM and Browser APIs Security]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model)
- [DOM Standard](https://dom.spec.whatwg.org/)
- [Fetch Standard](https://fetch.spec.whatwg.org/)
- [HTML Web Storage](https://html.spec.whatwg.org/multipage/webstorage.html)
- [Permissions specification](https://www.w3.org/TR/permissions/)
