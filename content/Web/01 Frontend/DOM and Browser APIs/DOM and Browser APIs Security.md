---
title: "DOM and Browser APIs Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[DOM and Browser APIs]]"
updated: 2026-11-03
---
# DOM and Browser APIs Security

> [!abstract] TL;DR
> Attacker-controlled URLs, storage entries, or messages reaching HTML or navigation sinks can produce DOM XSS or unsafe redirects.

> [!info] Agent scope
> Security of: DOM construction and mutation; event propagation; fetch; storage; navigation; sources and sinks; permissions. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Attacker-controlled URLs, storage entries, or messages reaching HTML or navigation sinks can produce DOM XSS or unsafe redirects.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive DOM/browser API security. I know HTML, JavaScript and HTTP.
Trace URL, storage, network and message inputs into text, HTML, navigation,
resource and permission sinks. Explain origin checks, URL parsing, query
multiplicity, storage lifetime, fetch credentials/CORS, race ownership, event
delegation and the limits of user activation or isTrusted. Show safe text-node
construction, exact route policy, storage validation and cleanup, CSP/Trusted
Types defense in depth, and server-side authorization requirements. Supply
complete local labs using inert synthetic fixtures and DOM assertions, with
positive behavior and rejection tests. No exploitation, bypass or credential
access. Use WHATWG/W3C primary sources and browser-version distinctions.
Teach here without editing files or claiming unperformed execution.
```

## Cheatsheet

### Source-to-Sink Review

| Source | Trust mistake | Fixed boundary |
|---|---|---|
| Query/hash | Treat decoded URL text as markup or trusted navigation | Cardinality/length validation, textContent, explicit route map |
| local/session storage | Treat stored JSON as already trusted | Parse and schema-check on every load; version and namespace records |
| API response | Trust a successful HTTP status as schema proof | Check status, media/schema and application invariants |
| Cross-context message | Trust only a data field claiming an origin | Verify browser-supplied origin and expected source window, then schema |
| Event target | Act on any matching nested element | Verify delegation root and owned identifier; authorize on server |
| Permission state | Treat a browser grant as business permission | Check feature/context/user intent and service authorization separately |

Text nodes are safe for text because they do not invoke an HTML parser. An attribute setter only avoids markup interpolation; URL-valued attributes still need policy. DOMParser, template elements and detached documents are not general sanitizers. A detached tree may become active when moved into a live context. Keep rich HTML support explicit and use a maintained sanitizer when required, not a regex filter.

### Navigation and Fetch Policy

Parse using a trusted base; compare canonical URL origin/protocol and reject credentials. For product navigation, a fixed route identifier map is often simpler than accepting arbitrary URLs. `startsWith()` is not an origin check. URL encoding preserves a component's syntax; it does not authorize a destination. Query parameters may repeat; decide whether duplicates are valid before selecting one. Fragments are not sent in HTTP requests but remain untrusted input to client code.

```js
// Fragment: fixed application routes, no arbitrary URL accepted.
const routes = new Map([['home', '/'], ['help', '/help']]);
function routeFor(identifier) {
	if (typeof identifier !== 'string' || !routes.has(identifier)) return null;
	return routes.get(identifier);
}
```

Credentialed fetch can have state-changing effects regardless of whether the response becomes readable; CORS is not an authorization layer. Do not use `no-cors` to resolve a read error. Same-origin scripts can access script-readable storage, so origin separation and dependency trust matter. HttpOnly cookies prevent direct script reads of cookie values but do not prevent an authorized-origin script from causing authenticated requests; CSRF and application authorization still matter.

Use AbortController and request identities to prevent stale results from committing into the wrong view. Abort is not transactional rollback. Clear user-specific state on identity changes; avoid caching responses across principals without a correctly keyed cache policy. Do not put secrets in query strings or browser bundles.

### Permissions and Policy Limits

User activation and `event.isTrusted` are browser interaction facts, not user identity or authorization. Powerful APIs can be blocked by secure-context requirements, user denial, embedding policy or unsupported permission names. Handle denial without retry loops or deceptive prompts. Permissions Policy headers can disable unused capabilities, for example `Permissions-Policy: camera=(), microphone=(), geolocation=()` on an HTTP-served page that needs none.

CSP limits approved resource/execution sources, while Trusted Types can constrain selected string-to-DOM sinks in supporting browsers. Neither repairs an application that turns every string into a trusted value. Roll out with reporting, verify actual enforcement per browser, and keep direct DOM assertions in tests. DOM clobbering risks also favor explicit references from query APIs over reliance on named properties of window/document.

## Detection and Defense

Inventory parsing/navigation sinks, storage readers, message handlers and permission requests. Record bounded rejection categories without raw sensitive URLs. Inspect DOM structure rather than merely absence of console errors. Test approved routes, empty/multiple/oversized values, stale state and storage failure. A passing text-rendering test does not certify every sink or server endpoint.

## Labs

### Environment and Complete Files

Current desktop browser; Python 3.12+ only for a loopback static server so storage and history use a stable HTTP origin. Create a disposable `dom-policy-lab` with the single complete file below. All destinations are display-only; no navigation or permissions are requested.

### File: index.html

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>DOM source policy</title></head>
<body><main><h1>Query rendering</h1><p id="text"></p>
<output id="destination"></output><pre id="tests" role="status"></pre>
</main><script>
const routes = new Map([['home', '/'], ['help', '/help']]);
function readInput(search) {
	const params = new URLSearchParams(search);
	const labels = params.getAll('label');
	const next = params.getAll('next');
	if (labels.length !== 1 || labels[0].length > 80 || next.length !== 1 ||
			!routes.has(next[0])) throw new TypeError('query');
	return {label: labels[0], destination: routes.get(next[0])};
}
function render(input) {
	document.querySelector('#text').textContent = input.label;
	document.querySelector('#destination').textContent = input.destination;
}
const fixture = new URLSearchParams({label: '<b>LAB</b>', next: 'help'}).toString();
const baseline = new URLSearchParams('next=elsewhere').get('next');
const checks = [['unvalidated baseline accepts unknown token', baseline === 'elsewhere']];
function check(name, ok) { checks.push([name, ok]); }
function rejected(search) {
	try { readInput(search); return false; } catch { return true; }
}
const approved = readInput(fixture);
render(approved);
check('text preserved', document.querySelector('#text').textContent === '<b>LAB</b>');
check('no parsed elements', document.querySelector('#text').children.length === 0);
check('approved route retained', approved.destination === '/help');
check('unknown route rejected', rejected('label=LAB&next=elsewhere'));
check('duplicate label rejected', rejected('label=A&label=B&next=help'));
check('duplicate route rejected', rejected('label=A&next=help&next=home'));
check('long text rejected', rejected(new URLSearchParams({label:'A'.repeat(81),next:'home'})));
check('missing field rejected', rejected('label=LAB'));
try {
	sessionStorage.setItem('hv-dom-policy', JSON.stringify({label:'LAB', next:'help'}));
	const saved = JSON.parse(sessionStorage.getItem('hv-dom-policy'));
	check('stored data revalidated', readInput(new URLSearchParams(saved)).destination === '/help');
	sessionStorage.removeItem('hv-dom-policy');
} catch { checks.push(['storage unavailable: UI remains functional', true]); }
try { render(readInput(location.search || fixture)); }
catch { document.querySelector('#text').textContent = 'Rejected query'; }
document.querySelector('#tests').textContent = checks.map(([name, ok]) =>
	`${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n');
if (checks.some(([, ok]) => !ok)) throw new Error('DOM policy regression');
</script></body></html>
```

### Objectives and Commands

```powershell
python -m http.server 8766 --bind 127.0.0.1
```

Open `http://127.0.0.1:8766/?label=%3Cb%3ELAB%3C%2Fb%3E&next=help`. Inspect the text node and displayed `/help` path. Repeat with `?label=LAB&next=elsewhere` and with `?label=A&label=B&next=help`. No route is actually followed. Choose another unused port if necessary.

### Hints

URLSearchParams decodes the text; decoding is not sanitization. The fixture's angle brackets remain literal because the rendering API creates text. Read all values before deciding whether a scalar parameter is valid.

### Solution and Fixed Retest

The weak baseline merely reads an unknown route token. `readInput()` rejects it before any render/navigation; the same approved label and help identifier still work. Ten PASS lines are expected, with either a storage-revalidated line or an explicit storage-unavailable line. Approved query displays literal `<b>LAB</b>` with zero child elements. Invalid queries display Rejected query; they do not create a navigation. The source-to-sink fix is exact input policy plus text-only output, not merely URL encoding.

### Verification, Troubleshooting, and Cleanup

If the address bar loses encoding visually, inspect the decoded value rather than assuming it changed semantics. Storage availability is environment-dependent and does not affect the rendering assertions. CSP/Trusted Types response enforcement and permission dialogs are reference topics, not claimed executed checks in this lab. Remove only `hv-dom-policy` if an interrupted run left it, close the tab, stop your server and remove the disposable directory. Author execution was deferred.

- [ ] Local DOM and Browser APIs exercise: Build a local list with event delegation and fetch-backed loading. Add explicit loading, error, and empty states; verify a 404 does not masquerade as a network exception.
- [ ] Boundary check: Put `<b>LAB</b>` in a query parameter and show it in the page using textContent. Confirm literal rendering and no extra elements in the DOM.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Prototype Pollution]]
- [[DOM and Browser APIs]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model)
- [URL Standard](https://url.spec.whatwg.org/)
- [DOM Standard](https://dom.spec.whatwg.org/)
- [W3C Trusted Types](https://www.w3.org/TR/trusted-types/)
- [Permissions Policy](https://www.w3.org/TR/permissions-policy-1/)
