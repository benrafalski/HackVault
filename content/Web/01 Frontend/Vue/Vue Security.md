---
title: "Vue Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[Vue]]"
updated: 2026-11-03
---
# Vue Security

> [!abstract] TL;DR
> Untrusted templates, v-html content, and unsafe URLs can escape normal text-binding protections; client-only checks cannot authorize data.

> [!info] Agent scope
> Security of: Reactivity; components; templates; routing; state; HTML rendering; client/server boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Untrusted templates, v-html content, and unsafe URLs can escape normal text-binding protections; client-only checks cannot authorize data.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Vue 3 security at framework/runtime depth. I know refs,
components, templates, routing and HTTP. Cover trusted templates versus data,
interpolation/v-text versus v-html, URL/style policies, prop/attribute forwarding,
third-party DOM code, reactive state trust, SSR request isolation, serialization
and hydration, and server authorization independent of client guards/stores.
Give complete real Vue renderer tests and direct local service tests with
synthetic identities, allowed/denied cases and cleanup. Explain Vue 2/3 and
runtime-only/compiler-build distinctions. No exploit payloads, bypass steps,
credential access or offensive procedures. Use official Vue/Node sources.
Teach here without editing files or claiming unperformed tests.
```

## Cheatsheet

### Framework Protection and Explicit Trust

Vue text interpolation and v-text use text semantics. Attribute bindings escape relevant syntax, but semantic policies still belong to the application. `v-html` and a render-function `innerHTML` prop are raw HTML sinks; Vue does not sanitize their contents. Component templates are compiled executable application logic, not a safe format for user-authored documents. Never mount Vue over a DOM region whose contents can supply untrusted template source.

| Surface | Defensive design | Important limit |
|---|---|---|
| Plain strings | `{{label}}` or v-text | Does not validate URL/CSS contexts elsewhere |
| Rich content | Maintained sanitizer with an explicit feature policy before raw HTML | No regex sanitizer; do not transform approved output into new unsafe contexts |
| href/src/navigation | Fixed route identifiers or parsed URL allowlist | HTML escaping is not destination approval |
| Styles | Bounded tokens mapped to owned classes | Scoped CSS is not isolation/security enforcement |
| Attribute forwarding | Select owned attributes; use inheritAttrs deliberately | Blind `$attrs` forwarding can expose unexpected behavior |
| Store data | Validate boundary input and project approved fields | Reactive proxies do not authorize or sanitize values |

Runtime-only Vue builds omit client template compilation, while build tooling compiles SFCs ahead of time. This reduces unnecessary compiler capability but does not make raw HTML safe. The lab's server renderer compiles only a fixed developer-authored template with data passed separately. Vue 2 is a legacy major; do not assume its support/security status or implementation matches Vue 3.

### State, Routes, and SSR

Route guards and hidden buttons are UX decisions, not server permissions. A service must derive the principal from verified authentication and compare it with server-owned record ownership or policy. Client-supplied record identifiers select a requested object; they do not prove access. Test approved and denied identities directly against the HTTP handler.

In SSR, a module-global ref/store can be reused across requests. Construct a new app and request-specific store for every request, and serialize only intended public fields. `readonly()` limits some mutation paths, not confidentiality or server identity. Deep watchers can accidentally persist or log more data than intended; prefer explicit fields. Stop pending watchers/requests and clear account-scoped state when identity changes.

Hydration requires consistent initial server/client output. A mismatch warning can reveal parser changes, nondeterministic data or incorrect state transfer; suppressing it is not a security fix. JSON.stringify alone is not safe for every inline HTML embedding context. Prefer the framework's reviewed serialization path, test literal markers and sensitive-field omission, and keep server-only imports out of the client graph.

### Concrete URL Policy Fragment

```js
const destinations = new Map([['help', '/help'], ['home', '/']]);
function destinationFor(value) {
	return typeof value === 'string' && destinations.has(value) ? destinations.get(value) : null;
}
```

Bind only a returned approved destination; do not concatenate untrusted input into a template or blindly forward a URL field. If external destinations are required, use URL parsing and explicit protocol/origin rules. CSP and Trusted Types can add defense in depth where supported, but permissive policies and raw HTML still require review.

## Detection and Defense

Review v-html, innerHTML render props, dynamic templates, arbitrary component/attribute forwarding, stores and SSR serialization. Test DOM structure or server-rendered escaped output, allowed destinations, missing/wrong identities and per-request state separation. Keep browser/hydration checks separate from SSR tests; one does not prove the other. Bound logs and never include real authentication material in fixtures.

## Labs

### Environment and Complete Files

Supported Node LTS (22+ sufficient), npm, Vue 3 and its matching server-renderer. Create `vue-policy-lab` with the four files below. The lab executes Vue's actual SSR interpolation path and a short-lived loopback HTTP service. There is no browser, bundler, database or production authentication.

### File: package.json

```json
{"name":"vue-policy-lab","private":true,"type":"module",
 "scripts":{"test":"node --test test.mjs"}}
```

### File: view.mjs

```js
import { createSSRApp, h } from 'vue';
import { renderToString } from '@vue/server-renderer';
export function renderLabel(label) {
	return renderToString(createSSRApp({
		data: () => ({label}),
		template: '<main><p id="label">{{ label }}</p></main>'
	}));
}
export function renderFixedBaseline() {
	return renderToString(createSSRApp({render: () => h('p', {innerHTML: '<b>LAB</b>'})}));
}
```

### File: service.mjs

```js
import { createServer } from 'node:http';
export function makeServer(resolvePrincipal) {
	const records = new Map([
		['a', {owner: 'user-a', label: 'Ada record'}],
		['b', {owner: 'user-b', label: 'Lin record'}]
	]);
	return createServer((request, response) => {
		const path = new URL(request.url, 'http://127.0.0.1').pathname;
		const id = path.startsWith('/records/') ? path.slice('/records/'.length) : '';
		const record = records.get(id);
		const principal = resolvePrincipal(request);
		const status = request.method !== 'GET' ? 405 : !record ? 404 :
			principal?.id === record.owner ? 200 : 403;
		response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
		response.end(JSON.stringify(status === 200 ? {id, label: record.label} : {error: 'denied'}));
	});
}
```

### File: test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { renderLabel, renderFixedBaseline } from './view.mjs';
import { makeServer } from './service.mjs';

test('Vue interpolation and request-local state', async () => {
	assert.match(await renderFixedBaseline(), /<b>LAB<\/b>/);
	const html = await renderLabel('<b>LAB</b>');
	assert.match(html, /&lt;b&gt;LAB&lt;\/b&gt;/);
	assert.doesNotMatch(html, /<b>/);
	const [first, second] = await Promise.all([renderLabel('USER-A-LABEL'), renderLabel('USER-B-LABEL')]);
	assert.match(first, /USER-A-LABEL/); assert.doesNotMatch(first, /USER-B-LABEL/);
	assert.match(second, /USER-B-LABEL/); assert.doesNotMatch(second, /USER-A-LABEL/);
});
test('service rejects another synthetic owner', async () => {
	let principal = null;
	const server = makeServer(() => principal);
	server.listen(0, '127.0.0.1'); await once(server, 'listening');
	const base = `http://127.0.0.1:${server.address().port}`;
	try {
		for (const [identity, id, status] of [[null, 'a', 403],
			[{id:'user-a'}, 'a', 200], [{id:'user-a'}, 'b', 403], [{id:'user-b'}, 'b', 200]]) {
			principal = identity;
			const response = await fetch(`${base}/records/${id}`);
			assert.equal(response.status, status);
			const body = await response.json();
			if (status === 200) assert.equal(body.id, id);
			else assert.deepEqual(body, {error:'denied'});
			assert.equal(Object.hasOwn(body, 'owner'), false);
		}
	} finally {
		await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
	}
});
```

### Objectives and Commands

```powershell
npm install --save-exact vue@3 @vue/server-renderer@3
node --version
npm ls --depth=0
npm test
```

Verify Vue/server-renderer resolve compatible matching releases; retain the lockfile. Predict escaped output and service statuses. The test closure supplies synthetic identity and never reads a client role/header as authentication. Do not expose this harness beyond loopback.

### Hints

`createSSRApp` is inside renderLabel, so each call owns its own data. The template is fixed code; only label is variable. A direct HTTP request should receive the same policy decision regardless of what a Vue route displays.

### Solution and Fixed Retest

Expected summary: two passing Node tests. The baseline intentionally creates a bold element from a fixed inert string; interpolation emits escaped brackets. Simultaneous request renders must not contain the other label. Service statuses are 403, 200, 403, 200; successful responses omit the owner field. To fix the baseline's text contract, replace its render body with `h('p', null, '<b>LAB</b>')` and change its assertion to escaped output. Repeat all fixtures; legitimate labels and authorized reads must still succeed.

### Verification, Troubleshooting, and Cleanup

These are real SSR and HTTP tests, not browser hydration/accessibility tests. A renderer mismatch usually means Vue and server-renderer versions differ. The listener closes in finally; a hanging process indicates an added open handle. No persistent records exist, so cleanup is deleting only the disposable directory after saving version evidence. No packages, servers or tests were run during this revision.

- [ ] Local Vue exercise: Build a filtered list using computed state and a child component event. Verify filtering updates without duplicated stored state and that loading failures are visible.
- [ ] Boundary check: Display a markup marker through interpolation and confirm literal output. Request another synthetic user's record directly and require the server to reject it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Vue]]

## References

- [Official documentation or primary training reference](https://vuejs.org/guide/best-practices/security.html)
- [SSR and cross-request state pollution](https://vuejs.org/guide/scaling-up/ssr.html)
- [Server-renderer API](https://vuejs.org/api/ssr.html)
- [Attribute fallthrough](https://vuejs.org/guide/components/attrs.html)
