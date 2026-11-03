---
title: "Angular"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[Angular Security]]"
updated: 2026-11-03
---
# Angular

> [!abstract] TL;DR
> Prefer normal property/text binding. Audit bypassSecurityTrust APIs, direct DOM manipulation, and any dynamic template construction.

> [!info] Agent scope
> Components and templates; dependency injection; routing; forms; sanitization; trust bypass APIs.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Angular at expert application/runtime depth. I know TypeScript, DOM
events, HTTP and basic RxJS. Cover standalone components, compiled templates,
signals/computed state, change detection and zoneless versus Zone.js scheduling,
hierarchical DI and provider lifetimes, reactive forms, router parameters and
guards, HttpClient observables/interceptors, teardown, sanitization contexts
and trust-bypass APIs. Give a complete routed form app with a service, synthetic
HTTP fixtures, invalid-input feedback and missing-record behavior. Explain
AOT, strict template checking, subscription ownership, switchMap cancellation,
disabled form values and route reuse. State Angular/Node/TypeScript/RxJS
compatibility and differences from AngularJS and older NgModule examples.
Use official Angular/RxJS sources. Teach here without editing files or
claiming unperformed tests.
```

## Cheatsheet

### Components, Templates, and Change Detection

Angular compiles trusted templates into view instructions. Interpolation displays text; property bindings assign properties in a known binding context; event bindings execute application expressions. `[attr.aria-label]` binds an attribute, whereas `[disabled]` binds the boolean property. Do not generate templates from external data. AOT moves template compilation into the build; `strictTemplates` checks template expressions but does not validate network input.

Standalone components declare their own imported directives/components/pipes. Older NgModule declarations and bootstrap modules remain distinct architecture, not extra requirements to mix into every standalone example. AngularJS 1.x is a different framework and its security/runtime assumptions should not be transferred to modern Angular.

Signals expose tracked values through calls such as `count()`; `set`/`update` notify consumers. `computed()` derives state lazily from tracked dependencies. Mutating a nested object without changing the signal value can leave consumers stale; make explicit immutable updates. Effects synchronize side effects, not redundant derived state. OnPush reduces checks but does not mean a view is permanently frozen: inputs, events and reactive notifications can schedule work.

Zone-based apps use patched async activity to schedule checks; zoneless apps rely on framework notifications such as signals, event handlers and AsyncPipe. Arbitrary external mutation is not automatically visible. The lab opts into zoneless scheduling explicitly and stores async results in a signal; do not copy it into an older version lacking that provider without adapting scheduling.

### DI, HTTP, Forms, and Routes

| Area | Mechanism and decision |
|---|---|
| `providedIn: 'root'` | One service per root application injector; not automatically per component/request |
| Component providers | Scoped instances for that component subtree; can intentionally isolate editor state |
| `inject()` | Requires an injection context, such as a field initializer/constructor/provider factory |
| HttpClient Observable | Usually cold: each subscription starts a request; unsubscribe can cancel transport work |
| `switchMap` | Unsubscribes prior inner stream on a new value; useful for route/read replacement, not guaranteed server write rollback |
| `takeUntilDestroyed` / AsyncPipe | Own subscription teardown; avoid retained components and stale updates |
| Reactive forms | Explicit control tree, synchronous/async validators and value/status streams |
| Router params | May change while component instance is reused; observe paramMap instead of assuming one snapshot forever |

`HttpClient.get<Record>()` is a compile-time assertion about the response, not a decoder. Request `unknown` and validate. Interceptors compose request/response behavior; clone immutable HttpRequest instances and scope credentials to intended destinations. Catch HTTP errors where they can become a useful UI state; catching outside a route stream can terminate future updates.

Typed nonnullable controls avoid reset-to-null surprises. Disabled controls are omitted from an enabled group's `.value`; `getRawValue()` includes them. Neither is authorization. `updateOn: 'blur'` or submit can reduce validation noise; asynchronous validators must complete and their pending state matters. Call `markAllAsTouched()` when surfacing submission errors. Keep server-side validation independent.

Route guards control navigation, not data access. Return a UrlTree/redirect result when redirecting rather than starting conflicting imperative navigation. Lazy routes split code, not privileges. Browser-history routing needs a server fallback for client paths while preserving real asset/API errors; hash routing avoids that deployment requirement for this lab.

### Sanitization and Versions

Angular escapes text interpolation and sanitizes supported HTML/URL binding contexts. HTML allowed by the sanitizer can still exceed a product's text-only contract. Resource URLs capable of loading executable content require a stricter trust decision and cannot be made safe by generic sanitization. `bypassSecurityTrust*` marks a value trusted; it does not clean it. Direct DOM/third-party widgets do not necessarily receive Angular template protections.

Use the official compatibility table, not a blanket latest TypeScript install. At this revision Angular 21 supports TypeScript 5.9 below 6 and Node ranges including 22.12+ within major 22; Angular 22 has different minimum Node and TypeScript requirements. The lab deliberately selects the documented Angular 21 major and records resolved patches. Keep Angular packages and compiler-cli aligned.

## Gotchas

Sanitization rules differ by binding context. A frontend auth service or route guard is not a server access-control mechanism.

## Labs

### Environment and Complete Files

Node 22.12+ within major 22, npm, modern browser; Angular 21, TypeScript 5.9, RxJS 7. These are documented compatibility ranges, not assertions that a particular patch was tested. Create `angular-record-lab` with the six complete files below. The static fixture is the only data source; Save validates and previews locally, not a real database write.

### File: package.json

```json
{"name":"angular-record-lab","private":true,
 "scripts":{"build":"ng build","start":"ng serve --host 127.0.0.1 --port 4200"}}
```

### File: angular.json

```json
{"version":1,"projects":{"lab":{"projectType":"application","root":"",
 "sourceRoot":"src","architect":{
 "build":{"builder":"@angular/build:application","options":{"outputPath":"dist/lab",
 "index":"src/index.html","browser":"src/main.ts","tsConfig":"tsconfig.json",
 "aot":true,"assets":[{"glob":"**/*","input":"public"}]}},
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
<meta name="viewport" content="width=device-width"><title>Angular records</title></head>
<body><app-root></app-root></body></html>
```

### File: public/a.json

```json
{"id":"a","name":"Ada"}
```

### File: src/main.ts

```ts
import { Component, Injectable, inject, signal, provideZonelessChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { HttpClient, provideHttpClient } from '@angular/common/http';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink, RouterOutlet, provideRouter, withHashLocation } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { catchError, map, of, startWith, switchMap } from 'rxjs';

type RecordItem = {id: string; name: string};
type View = {kind: 'loading'} | {kind: 'error'; message: string} | {kind: 'ready'; record: RecordItem};
@Injectable({providedIn: 'root'})
class Records {
	private http = inject(HttpClient);
	get(id: string) {
		return this.http.get<unknown>(`/${encodeURIComponent(id)}.json`).pipe(map(value => {
			if (!value || typeof value !== 'object' || !('id' in value) || !('name' in value) ||
					typeof value.id !== 'string' || typeof value.name !== 'string') throw new Error('schema');
			return {id: value.id, name: value.name};
		}));
	}
}
@Component({standalone: true, imports: [ReactiveFormsModule], template: `
	<h2>Record editor</h2><p role="status">{{status()}}</p>
	@if (view().kind === 'ready') {
		<form (submit)="save($event)">
			<label for="name">Name</label><input id="name" [formControl]="name">
			@if (name.touched && name.invalid) { <p>Name must contain 1-40 characters.</p> }
			<button type="submit">Preview save</button>
		</form>
	}
`})
class Editor {
	private route = inject(ActivatedRoute);
	private records = inject(Records);
	view = signal<View>({kind: 'loading'});
	status = signal('Loading');
	name = new FormControl('', {nonNullable: true,
		validators: [Validators.required, Validators.maxLength(40)]});
	constructor() {
		this.route.paramMap.pipe(
			switchMap(params => this.records.get(params.get('id') ?? '').pipe(
				map(record => ({kind: 'ready', record}) as View),
				catchError(() => of<View>({kind: 'error', message: 'Record unavailable'})),
				startWith<View>({kind: 'loading'})
			)), takeUntilDestroyed()
		).subscribe(view => {
			this.view.set(view);
			this.status.set(view.kind === 'error' ? view.message : view.kind);
			if (view.kind === 'ready') this.name.reset(view.record.name);
		});
	}
	save(event: Event) {
		event.preventDefault();
		this.name.markAsTouched();
		if (this.name.invalid || this.view().kind !== 'ready') return;
		this.status.set(`Preview: ${this.name.value}`);
	}
}
@Component({selector: 'app-root', standalone: true, imports: [RouterLink, RouterOutlet],
	template: `<main><h1>Angular records</h1><nav>
		<a routerLink="/record/a">Ada</a> | <a routerLink="/record/missing">Missing</a>
		</nav><router-outlet /></main>`})
class App {}
bootstrapApplication(App, {providers: [provideZonelessChangeDetection(), provideHttpClient(),
	provideRouter([{path: '', pathMatch: 'full', redirectTo: 'record/a'},
		{path: 'record/:id', component: Editor}], withHashLocation())
]}).catch(console.error);
```

### Objectives and Commands

```powershell
npm install --save-exact @angular/common@21 @angular/compiler@21 @angular/core@21 @angular/forms@21 @angular/platform-browser@21 @angular/router@21 rxjs@7 tslib
npm install --save-dev --save-exact @angular/build@21 @angular/cli@21 @angular/compiler-cli@21 typescript@5.9
node --version
npx ng version
npm run build
npm start
```

Open `http://127.0.0.1:4200/`. If occupied, choose a different unused port in this lab's start script. Load Ada, clear the field and Preview, then enter Lin and Preview. Navigate Missing then Ada without reloading. Throttle Network and switch links rapidly to inspect replacement/cancellation.

### Hints

Missing data is a request/parse failure, not a valid empty record. `catchError` is inside switchMap so one failed request does not terminate future route processing. Signals make subscription results observable in the zoneless view.

### Solution and Expected Results

Initial route becomes `#/record/a`, input contains Ada and status is ready. Empty submit displays validation feedback and does not produce Preview status. Lin produces Preview: Lin. Missing displays Record unavailable and no editor; returning to Ada restores the form. Network should show a missing resource failure or failed JSON parse of a dev fallback, never a successful domain record. The original form exercise is complete without any persistence assumption.

### Verification, Troubleshooting, and Cleanup

Build must pass AOT/strict template checks. Manually assert one name input on a, zero on missing, then one again; check keyboard labels and Back/Forward. DI errors indicate a missing provideHttpClient or an inject call outside context. Version errors require the compatibility table, not forced peer overrides. Retain the lockfile/version evidence, stop your dev server and remove only the lab directory. Author installs, builds, browser checks and tests were not performed.

- [ ] Local Angular exercise: Build a form-backed component with a service and a routed detail view. Verify validation feedback, server-error handling, and navigation to a nonexistent record.
- [ ] Boundary check: Bind a harmless HTML marker normally and inspect sanitization. Verify direct synthetic API requests are authorized independently of UI route guards.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Angular Security]]

## References

- [Official documentation or primary training reference](https://angular.dev/best-practices/security)
- [Version compatibility](https://angular.dev/reference/versions)
- [Signals](https://angular.dev/guide/signals)
- [Dependency injection](https://angular.dev/guide/di)
- [Reactive forms](https://angular.dev/guide/forms/reactive-forms)
- [Routing](https://angular.dev/guide/routing)
