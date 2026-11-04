---
title: "Angular Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[Angular]]"
updated: 2026-11-03
---
# Angular Security

> [!abstract] TL;DR
> Treating attacker data as trusted HTML/resource URLs or compiling untrusted templates bypasses Angular's normal safety boundaries.

> [!info] Agent scope
> Security of: Components and templates; dependency injection; routing; forms; sanitization; trust bypass APIs. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Treating attacker data as trusted HTML/resource URLs or compiling untrusted templates bypasses Angular's normal safety boundaries.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Angular security. I know standalone components, DI, forms,
router and HttpClient. Explain template code versus data, interpolation versus
HTML binding, HTML/URL/resource contexts, DomSanitizer and the risk of trust
assertions, direct DOM/widget boundaries, AOT, CSP/Trusted Types integration,
XSRF client/server cooperation and server authorization independent of guards.
Give complete real Angular rendering assertions and independent local service
tests using inert markup and synthetic identities. Cover supported-version
differences and observable failures without exploit payloads, bypass steps,
credential access or offensive procedures. Use official Angular/Node sources.
Teach here without editing files or claiming unperformed tests.
```

## Cheatsheet

### Context Is the Security Contract

| Binding | Framework behavior | Application responsibility |
|---|---|---|
| `{{ label }}` | Escaped/text output | Validate length/meaning; correct choice for plain text |
| `[innerHTML]="html"` | HTML-context sanitization for ordinary untrusted strings | Decide whether rich markup is allowed at all |
| `[href]="url"` | URL-context safety checks | Enforce allowed origins/routes/business policy |
| Executable resource URL | Cannot be generically sanitized into safe code | Use fixed reviewed sources and deliberate resource policy |
| Direct DOM or widget API | May bypass template binding protections | Review the actual sink and its required context |

`DomSanitizer.sanitize(SecurityContext.HTML, ordinaryString)` can inspect/transform HTML. For other contexts, do not assume the explicit API accepts every plain string in the same way that generated template binding code does; use the documented contract. A SafeValue wrapper created by `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, `bypassSecurityTrustStyle`, `bypassSecurityTrustScript` or `bypassSecurityTrustResourceUrl` is a trust assertion, not a cleaning step. This note provides no trust-bypass procedure; remove unnecessary trust assertions rather than wrapping unreviewed content.

The harmless `<b>LAB</b>` fixture can survive HTML sanitization because bold markup is permitted. That does not make HTML binding correct for a field whose contract is literal text. Security regression tests should assert the intended structure, not merely absence of script. Do not compile external strings as Angular templates: templates are application code, and AOT does not sanitize dynamically supplied code.

### Request and Identity Boundaries

DI services, reactive forms and route guards organize client behavior; they cannot authorize server access. Disabled form controls and typed models remain client data. `HttpClient.get<Model>()` is not runtime validation. Validate responses and server inputs, and derive permissions from server-owned identity and resource ownership. Scope credential-adding interceptors to intended API destinations and avoid sending headers to arbitrary URLs.

Angular's HttpClient XSRF support is only the client half: the service must issue and verify the expected token on eligible state-changing requests. Header behavior depends on request method, URL/origin and Angular version; test actual requests for your installed release. XSRF token validation is not user authorization, and GET must not perform mutations. Do not disable protections to make a misconfigured API appear to work.

### CSP, Trusted Types, and Version Discipline

Production CSP must account for generated scripts, component style insertion, critical CSS and lazy chunks. Nonces need to be unpredictable and fresh per response, consistently applied to the policy and Angular's `ngCspNonce` or `CSP_NONCE` integration. A fixed nonce in static HTML is not a solution. CLI auto-CSP support and deployment limitations vary; check the selected version rather than copying options from newer docs.

Illustrative Trusted Types response-policy fragment for an AOT app requiring lazy chunks:

```http
Content-Security-Policy: trusted-types angular angular#bundler; require-trusted-types-for 'script'
```

This is not a complete CSP resource policy and is not applied by the lab. Only allow policies actually needed; do not enable unsafe-JIT or unsafe-bypass policies as a routine compatibility fix. Browser support differs, and third-party widgets may need remediation. Angular 21 and 22 require different TypeScript/Node ranges; use matching supported packages and inspect security advisories. Sanitizer output is version-sensitive and should be tested on upgrade.

## Detection and Defense

Inventory trust assertions, dynamic template compilation, ElementRef/DOM writes, interceptors, guard assumptions and serialized state. Keep DOM assertions for literal fields and approved rich content. Review development sanitizer warnings as evidence, not as the only detection signal. Test denied and permitted direct service requests without depending on UI navigation. The supplied defensive lab tests service independence directly without changing or circumventing a UI control.

## Labs

### Environment and Complete Files

Node 22.12+ within major 22, npm, modern browser, Angular 21 with TypeScript 5.9 and RxJS 7. Create `angular-policy-lab` with the six files below. Package ranges follow the official compatibility table; installation records actual patches. This lab is independent of the technology page and needs no shared files.

### File: package.json

```json
{"name":"angular-policy-lab","private":true,
 "scripts":{"build":"ng build","start":"ng serve --host 127.0.0.1 --port 4201",
 "test:service":"node --test service.test.mjs"}}
```

### File: angular.json

```json
{"version":1,"projects":{"lab":{"projectType":"application","root":"",
 "sourceRoot":"src","architect":{
 "build":{"builder":"@angular/build:application","options":{"outputPath":"dist/lab",
 "index":"src/index.html","browser":"src/main.ts","tsConfig":"tsconfig.json","aot":true}},
 "serve":{"builder":"@angular/build:dev-server","options":{"buildTarget":"lab:build"}}
 }}}}
```

### File: tsconfig.json

```json
{"compilerOptions":{"target":"ES2022","module":"ES2022","moduleResolution":"bundler",
 "lib":["ES2022","DOM"],"strict":true,"experimentalDecorators":true,
 "useDefineForClassFields":false,"skipLibCheck":true},
 "angularCompilerOptions":{"strictTemplates":true},"files":["src/main.ts"]}
```

### File: src/index.html

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><base href="/">
<title>Angular rendering policy</title></head><body><app-root></app-root></body></html>
```

### File: src/main.ts

```ts
import { Component, SecurityContext, afterNextRender, inject, signal, provideZonelessChangeDetection } from '@angular/core';
import { DomSanitizer, bootstrapApplication } from '@angular/platform-browser';

@Component({selector: 'app-root', standalone: true, template: `
	<main><h1>Binding contexts</h1>
		<h2>Literal label</h2><p id="literal">{{marker}}</p>
		<h2>Intentionally rich fixed fixture</h2><p id="rich" [innerHTML]="marker"></p>
		<pre role="status">{{results()}}</pre>
	</main>`})
class App {
	marker = '<b>LAB</b>';
	results = signal('Pending rendering checks');
	private sanitizer = inject(DomSanitizer);
	constructor() {
		afterNextRender(() => {
			const literal = document.querySelector('#literal')!;
			const rich = document.querySelector('#rich')!;
			const checks = [
				['literal preserves text', literal.textContent === this.marker],
				['literal has no elements', literal.children.length === 0],
				['rich fixture keeps bold', rich.querySelectorAll('b').length === 1],
				['HTML sanitizer permits fixed bold',
					this.sanitizer.sanitize(SecurityContext.HTML, this.marker) === this.marker]
			] as const;
			this.results.set(checks.map(([name, ok]) => `${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n'));
			if (checks.some(([, ok]) => !ok)) throw new Error('Binding regression');
		});
	}
}
bootstrapApplication(App, {providers: [provideZonelessChangeDetection()]}).catch(console.error);
```

### File: service.test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

test('service policy does not depend on an Angular guard', async () => {
	let principal = null;
	const record = {id: 'DEMO-7', owner: 'user-a', label: 'Synthetic'};
	const server = createServer((request, response) => {
		const permitted = principal?.id === record.owner && principal?.role === 'reader';
		const status = request.url !== '/record' ? 404 : request.method !== 'GET' ? 405 : permitted ? 200 : 403;
		response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
		response.end(JSON.stringify(status === 200 ? {id: record.id, label: record.label} : {error: 'denied'}));
	});
	server.listen(0, '127.0.0.1'); await once(server, 'listening');
	try {
		for (const [identity, status] of [[null, 403], [{id:'user-b',role:'reader'},403],
			[{id:'user-a',role:'unknown'},403], [{id:'user-a',role:'reader'},200]]) {
			principal = identity;
			const response = await fetch(`http://127.0.0.1:${server.address().port}/record`);
			assert.equal(response.status, status);
			const body = await response.json();
			if (status === 200) assert.deepEqual(body, {id:'DEMO-7',label:'Synthetic'});
			else assert.deepEqual(body, {error:'denied'});
		}
	} finally {
		await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
	}
});
```

The mutable principal is controlled by the test closure, not by a client field. Real authentication must supply a verified identity; this harness does not implement login.

### Objectives and Commands

```powershell
npm install --save-exact @angular/common@21 @angular/compiler@21 @angular/core@21 @angular/platform-browser@21 rxjs@7 tslib
npm install --save-dev --save-exact @angular/build@21 @angular/cli@21 @angular/compiler-cli@21 typescript@5.9
npx ng version
npm run build
npm run test:service
npm start
```

Open `http://127.0.0.1:4201/` and inspect literal/rich DOM trees. Predict the service decisions before running its test. No input is treated as executable template code, and no UI control is removed to obtain access.

### Hints

Sanitization may legitimately leave the inert bold element intact. A text-only policy therefore requires interpolation, not a sanitizer setting. The service test must deny the wrong owner and wrong role independently.

### Solution and Fixed Retest

Expect four PASS lines in the browser and one passing Node test with service statuses 403, 403, 403, 200. If a rich field is reclassified as literal text, replace `[innerHTML]="marker"` with `{{marker}}` inside that paragraph and change its assertion to zero child elements plus exact text. Repeat the same fixture; both literal fields now meet the text-only contract while the service outcomes remain unchanged.

### Verification, Troubleshooting, and Cleanup

The HTML-context sanitizer output is an upgrade regression assertion, not proof for every input/context. Missing afterNextRender/zoneless APIs indicate a wrong Angular major; mismatched compiler peers must be aligned, not forced. CSP/Trusted Types and XSRF deployment are documented but not exercised by this client/static fixture. Close the page, stop your dev server and delete only the disposable directory after recording resolved versions. No commands, installs, builds, listeners or tests were executed in this revision.

- [ ] Local Angular exercise: Build a form-backed component with a service and a routed detail view. Verify validation feedback, server-error handling, and navigation to a nonexistent record.
- [ ] Boundary check: Bind a harmless HTML marker normally and inspect sanitization. Verify direct synthetic API requests are authorized independently of UI route guards.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Angular]]

## References

- [Official documentation or primary training reference](https://angular.dev/best-practices/security)
- [Version compatibility](https://angular.dev/reference/versions)
- [DomSanitizer contract](https://angular.dev/api/platform-browser/DomSanitizer)
- [Route guards and server authorization](https://angular.dev/guide/routing/route-guards)
