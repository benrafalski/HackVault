---
title: "React Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[React]]"
updated: 2026-11-03
---
# React Security

> [!abstract] TL;DR
> dangerouslySetInnerHTML, untrusted navigation targets, or authorization enforced only by hidden components expose data or execution paths.

> [!info] Agent scope
> Security of: Components; state and effects; rendering; routing; server/client boundaries; escaping and dangerous HTML APIs. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- dangerouslySetInnerHTML, untrusted navigation targets, or authorization enforced only by hidden components expose data or execution paths.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive React security at framework/runtime depth. I know React
state/effects, routing, HTTP and SSR. Explain escaped text, raw HTML props,
untrusted prop spreads, URL/style policies, hydration, server/client module
graphs, Server Functions, client route guards, async identity changes and
request-scoped server state. Show complete real React rendering tests and
independent server authorization tests with synthetic identities, positive
cases and denials. Distinguish React 18/19 and framework-specific behavior;
do not equate server execution with authorization. No exploit payloads,
bypass, credential access or offensive steps. Use React and Node primary
sources. Teach here without editing files or claiming unperformed execution.
```

## Cheatsheet

### Rendering Boundaries

Ordinary string children become text: JSX `<p>{label}</p>` is equivalent in meaning to `createElement('p', null, label)`. React DOM escapes text during server rendering and uses text semantics in the browser. `dangerouslySetInnerHTML={{__html: value}}` explicitly opts into HTML parsing. Use it only when rich content is a genuine requirement and a maintained sanitizer/strict trust contract supplies the value. Do not write a regex sanitizer or assume React's normal escaping applies to that prop.

| Surface | Correct decision |
|---|---|
| Labels/descriptions | Ordinary string children; never markup for text-only fields |
| URLs | Parse and enforce destinations before assigning href/src or navigating |
| External prop objects | Select known safe props; do not spread arbitrary records onto host components |
| User style preferences | Map bounded tokens to reviewed styles/classes |
| SSR state serialization | Use framework-supported serializers and escape the actual embedding context |
| Hydration mismatch | Fix nondeterministic/server-client divergent output, not blanket suppression |

An HTML-safe string is not automatically a safe URL or CSS value. React versions have changed how particular dangerous URL schemes and DOM properties are handled; keep an application policy independent of those defenses. Refs, third-party widgets and direct DOM mutation can bypass React's ordinary rendering path. Review them as separate sinks.

### Server/Client Authority

Hiding a button, returning null, checking context roles, or redirecting a route affects UI only. Every API handler or Server Function must authenticate, validate and authorize the requested resource/action. A client-provided user ID/role cannot be its own proof. Test the service without mounting the UI. Server Components reduce some client code but any serialized props/output are client-visible; do not serialize secrets or import server-only modules through a client dependency graph.

SSR is not the same as Server Components, and this lab uses ordinary static SSR, not an RSC framework. Framework-specific Server Function transports, caches and serialization require framework-specific tests. Shared module-level mutable data on a server can cross requests; allocate principal-specific state per request. Cache keys must include the actual authorization context when caching private data. Client identity changes should invalidate pending work and clear user-specific state; canceling a request is not a server-side rollback.

### Concrete Safe Component Fragment

```jsx
function Summary({title, mayEdit}) {
	return <section><h2>{title}</h2>
		{mayEdit && <button type="button">Edit</button>}
	</section>;
}
```

`mayEdit` here is a display hint, never service authority. A service must derive its own decision from a trusted identity and server-owned record. CSP and Trusted Types can constrain some unsafe escape hatches, but support/integration varies; they do not prove that the authorization or HTML policy is correct.

## Detection and Defense

Inventory raw HTML, arbitrary prop spreading, refs/widgets, server serialization and client-visible environment variables. Test literal markers structurally (text plus absence of extra elements), not just no console errors. Keep direct denied/allowed service tests, unknown-role tests, and stale-request tests. Never use real credentials in fixtures. Update React/framework packages together where required and inspect resolved dependency versions rather than assuming the source syntax identifies the deployed runtime.

## Labs

### Environment and Complete Files

Supported Node LTS (22+ sufficient), npm, matching React/react-dom 18+ packages. Create `react-policy-lab` with all four files below. The lab uses React's actual server renderer and a temporary loopback HTTP listener. `createElement` avoids needing a JSX compiler while executing the same element model. No browser, bundler or external API is required.

### File: package.json

```json
{"name":"react-policy-lab","private":true,"type":"module",
 "scripts":{"test":"node --test test.mjs"}}
```

### File: view.mjs

```js
import { createElement } from 'react';
export function Summary({label, mayEdit}) {
	return createElement('section', null,
		createElement('p', {id: 'label'}, label),
		mayEdit ? createElement('button', {type: 'button'}, 'Edit') : null);
}
export function fixedMarkupBaseline() {
	return createElement('p', {dangerouslySetInnerHTML: {__html: '<b>LAB</b>'}});
}
```

### File: server.mjs

```js
import { createServer } from 'node:http';
export function authorize(principal, record) {
	return principal !== null && principal.role === 'editor' && principal.id === record.owner;
}
export function makeServer(resolvePrincipal) {
	const record = Object.freeze({id: 'DEMO-7', owner: 'user-a', label: 'Synthetic record'});
	return createServer((request, response) => {
		let status;
		if (request.url !== '/record') status = 404;
		else if (request.method !== 'GET') status = 405;
		else status = authorize(resolvePrincipal(request), record) ? 200 : 403;
		response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
		response.end(JSON.stringify(status === 200 ? {id: record.id, label: record.label} : {error: 'denied'}));
	});
}
```

The principal resolver is an injected test seam, not an authentication implementation. It never trusts a request header/body to establish identity. A production adapter must derive the principal from verified authentication.

### File: test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { Summary, fixedMarkupBaseline } from './view.mjs';
import { makeServer } from './server.mjs';

test('real React renderer preserves a text-only contract', () => {
	assert.match(renderToStaticMarkup(fixedMarkupBaseline()), /<b>LAB<\/b>/);
	const html = renderToStaticMarkup(createElement(Summary, {label: '<b>LAB</b>', mayEdit: false}));
	assert.match(html, /&lt;b&gt;LAB&lt;\/b&gt;/);
	assert.doesNotMatch(html, /<b>|<button/);
	assert.match(renderToStaticMarkup(createElement(Summary, {label: 'LAB', mayEdit: true})), /<button/);
});
test('HTTP authorization is independent of hidden controls', async () => {
	let principal = null;
	const server = makeServer(() => principal);
	server.listen(0, '127.0.0.1'); await once(server, 'listening');
	const url = `http://127.0.0.1:${server.address().port}/record`;
	try {
		for (const [identity, expected] of [
			[null, 403], [{id: 'user-a', role: 'reader'}, 403],
			[{id: 'user-b', role: 'editor'}, 403], [{id: 'user-a', role: 'editor'}, 200]
		]) {
			principal = identity;
			const response = await fetch(url);
			assert.equal(response.status, expected);
			const body = await response.json();
			if (expected === 200) assert.deepEqual(body, {id: 'DEMO-7', label: 'Synthetic record'});
			else assert.deepEqual(body, {error: 'denied'});
		}
	} finally {
		await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
	}
});
```

### Objectives and Commands

```powershell
npm install --save-exact react react-dom
node --version
npm ls --depth=0
npm test
```

Predict the rendered strings and four service decisions. Explain why the UI test and HTTP test must be independent. The fixed baseline HTML is hardcoded and inert; do not replace it with user-controlled content.

### Hints

JSX escaping is rendering-context behavior, not a property of the original string. The service uses role and ownership; either check alone is incomplete. Injecting identities in a test avoids teaching a client-controlled authentication shortcut.

### Solution and Fixed Retest

The raw fixed baseline creates bold markup, while Summary emits escaped text and no button for mayEdit=false. The authorized display still renders a button. Service statuses are 403, 403, 403, 200; only the final response includes the record. Expected test summary: two passing tests, zero failures. To harden the baseline itself, replace its raw HTML prop with `createElement('p', null, '<b>LAB</b>')` and change the baseline assertion to escaped output. Rerun the same text and service fixtures; authorization expectations stay unchanged.

### Verification, Troubleshooting, and Cleanup

This verifies static React rendering and actual HTTP policy, not hydration, browser accessibility, RSC or a specific framework's Server Functions. A module error usually means missing install or mismatched React/react-dom versions. The listener closes in finally; no persistent service is needed. Retain the lockfile/version evidence, then delete only the disposable directory. No install or tests were run during authoring.

- [ ] Local React exercise: Build a typed editable list with stable IDs, loading/error states, and an abortable fetch. Delete one row and verify neighboring input state stays attached to the correct item.
- [ ] Boundary check: Render a harmless HTML marker as ordinary JSX text and verify escaping. Call a protected endpoint directly while the UI hides its button; require server denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[React]]

## References

- [Official documentation or primary training reference](https://react.dev/learn)
- [DOM elements and raw HTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Server Functions](https://react.dev/reference/rsc/server-functions)
- [Static server rendering](https://react.dev/reference/react-dom/server/renderToStaticMarkup)
