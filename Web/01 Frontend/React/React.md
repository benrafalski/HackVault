---
title: "React"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[React Security]]"
updated: 2026-11-03
---
# React

> [!abstract] TL;DR
> Prefer immutable state updates and stable keys. Avoid unnecessary effects and memoization; inspect raw HTML and external URL props during review.

> [!info] Agent scope
> Components; state and effects; rendering; routing; server/client boundaries; escaping and dangerous HTML APIs.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me React at expert runtime and application depth. I know JavaScript,
TypeScript, DOM events and HTTP. Cover components/props, render versus commit,
state snapshots, updater queues, key identity, controlled forms, reducers,
effects and cleanup, stale closures, async request races, routing, Suspense,
transitions, SSR/hydration and server/client component boundaries. Explain JSX
text escaping and explicit raw HTML APIs. Supply a complete typed editable-list
app with a real router, fetch fixtures, error/empty/loading states and stable-key
regression checks. Distinguish React 18/19 APIs, StrictMode development behavior,
framework responsibilities and optional compiler optimizations. Use official
React/router sources. Teach here without editing files or inventing results.
```

## Cheatsheet

### Render, Commit, and Identity

A component render computes a description from props/state/context. React may repeat, interrupt or abandon render work; do not mutate external state, subscribe, or send requests while rendering. Commit updates the host tree; effects synchronize external systems after committed work. A render is not evidence that a visible DOM change happened.

State belongs to component type/position/key in the rendered tree, not the function object as a global singleton. Keys identify siblings across insertion/deletion/reordering. Index keys attach local state to positions; random keys remount on each render. A `key` is not passed as a normal prop, so pass the identifier separately. Changing a key deliberately resets local state; use that for a different record, not as a routine refresh mechanism.

```tsx
// Fragment: two increments operate on queued previous values.
setCount(previous => previous + 1);
setCount(previous => previous + 1);
// setCount(count + 1) twice uses the same render snapshot instead.
```

Update arrays/objects immutably so identity reflects change. Derive totals and filtered views while rendering rather than storing redundant effect-managed state. A reducer helps when transitions share invariants; it is not inherently a global state solution. Controlled inputs need a defined value and synchronous onChange update; switching between undefined and text changes controlledness.

### Effects, Async Work, and Performance

Effects are for synchronization (subscriptions, timers, imperative widgets, simple fetch), not every computation. Dependencies describe reactive values used by the effect; suppressing the dependency rule can preserve stale closures. Cleanup runs before a changed effect is set up again and at unmount. An effect callback itself must not be async because it must return cleanup or nothing, not a promise.

StrictMode development can run extra renders and setup/cleanup cycles to expose missing cleanup; production does not promise that exact sequence. Make cleanup symmetrical and requests stale-safe instead of disabling StrictMode to conceal symptoms. Abort a fetch and ignore stale completion; abort alone does not undo a server write.

`startTransition` marks nonurgent state work; it does not make a synchronous computation parallel and should not control an urgent input's own value. `useDeferredValue` can let a slow view lag behind input; it is not a network debounce. Memoization is an optimization, not correctness. Use profiling and, where configured, React Compiler guidance before adding blanket `useMemo`/`useCallback`. React 19-era APIs such as Actions, `useActionState`, and newer effect-event support depend on the installed version; this lab uses established React 18+ hooks only.

### Routes and Server Boundaries

| Mechanism | Responsibility / failure mode |
|---|---|
| Client router | Maps URL to UI; not service authorization |
| Hash routing | Avoids server path fallback needs; fragment not sent to server |
| History routing | Cleaner paths; direct reloads need server fallback without swallowing API/asset 404s |
| SSR | Produces initial HTML; browser globals unavailable during server render |
| Hydration | Attaches React to matching server output; nondeterministic initial values cause mismatches |
| Server Components | Framework/build boundary; not synonymous with ordinary SSR |
| Server Functions/Actions | Remotely reachable operations requiring their own validation and authorization |

Effects do not execute during server rendering. Keep request-specific server state isolated per request, and serialize only intended public data to the client. A client-marked module can pull transitive imports into the client graph; never import secrets there. `hydrateRoot` hydrates existing server markup; `createRoot` creates a client tree. Suspense integrates with supported data/framework APIs; a fetch launched in useEffect does not automatically suspend.

JSX `{text}` is rendered as text. `dangerouslySetInnerHTML` is an explicit parsing boundary and needs trusted/sanitized HTML. Escaping text does not validate hrefs, arbitrary prop spreads, styles, or authorization. React does not ship a router, HTTP service, or schema validator; these choices remain explicit.

## Gotchas

A component not being rendered does not make its endpoint inaccessible. Client bundles cannot contain server secrets.

## Labs

### Environment and Complete Files

Use a supported Node LTS satisfying the selected Vite package's engine requirement (Node 22.12+ is the Vite 7 baseline; check newer major requirements), npm and a current browser. React/react-dom must share a compatible major; the declarative router API below is supported by React Router 6/7. TypeScript 5+ and matching React type packages are needed. Install commands resolve and record exact versions rather than assuming unverified patch pins.

Create `react-state-lab` with all files below. Vite's TSX transform is sufficient for this lab; no Fast Refresh plugin is required. This is a client-only app, not an SSR framework.

### File: package.json

```json
{"name":"react-state-lab","private":true,"type":"module",
 "scripts":{"dev":"vite --host 127.0.0.1 --port 5173 --strictPort",
 "check":"tsc --noEmit","build":"vite build"}}
```

### File: tsconfig.json

```json
{"compilerOptions":{"target":"ES2022","lib":["ES2022","DOM","DOM.Iterable"],
 "module":"ESNext","moduleResolution":"Bundler","jsx":"react-jsx",
 "strict":true,"noEmit":true,"esModuleInterop":true,"skipLibCheck":true},
 "include":["src"]}
```

### File: index.html

```html
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>React state lab</title></head>
<body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>
```

### File: public/records.json

```json
[{"id":"a","label":"Ada"},{"id":"b","label":"Lin"},{"id":"c","label":"Sam"}]
```

### File: public/empty.json

```json
[]
```

### File: src/main.tsx

```tsx
import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter, Link, Route, Routes } from 'react-router-dom';

type RecordItem = {id: string; label: string};
function decode(value: unknown): RecordItem[] {
	if (!Array.isArray(value) || value.length > 100) throw new Error('Invalid list');
	const rows = value.map((item: unknown) => {
		if (!item || typeof item !== 'object' || !('id' in item) || !('label' in item) ||
				typeof item.id !== 'string' || typeof item.label !== 'string') throw new Error('Invalid row');
		return {id: item.id, label: item.label};
	});
	if (new Set(rows.map(row => row.id)).size !== rows.length) throw new Error('Duplicate IDs');
	return rows;
}
function Row({item, remove}: {item: RecordItem; remove: (id: string) => void}) {
	const [label, setLabel] = useState(item.label);
	return <li data-id={item.id}>
		<label>Name {item.id} <input value={label} onChange={event => setLabel(event.target.value)} /></label>
		<button onClick={() => remove(item.id)}>Delete {item.id}</button>
	</li>;
}
function Records() {
	const [file, setFile] = useState('records.json');
	const [rows, setRows] = useState<RecordItem[]>([]);
	const [status, setStatus] = useState('Loading');
	useEffect(() => {
		const controller = new AbortController();
		let active = true;
		setStatus('Loading'); setRows([]);
		async function load() {
			try {
				const response = await fetch(`/${file}`, {signal: controller.signal});
				if (!response.ok) throw new Error(`HTTP ${response.status}`);
				const next = decode(await response.json());
				if (active) { setRows(next); setStatus(next.length ? 'Ready' : 'Empty'); }
			} catch (error) {
				if (active) setStatus(error instanceof Error ? error.message : 'Load failed');
			}
		}
		void load();
		return () => { active = false; controller.abort(); };
	}, [file]);
	return <section><h2>Editable records</h2>
		<label>Fixture <select value={file} onChange={event => setFile(event.target.value)}>
			<option value="records.json">Records</option><option value="empty.json">Empty</option>
			<option value="missing.json">Missing</option>
		</select></label>
		<p role="status">{status}</p>
		<ul>{rows.map(item => <Row key={item.id} item={item}
			remove={id => setRows(previous => previous.filter(row => row.id !== id))} />)}</ul>
	</section>;
}
function App() {
	return <HashRouter><main><h1>React state</h1>
		<nav><Link to="/">Records</Link> | <Link to="/about">About</Link></nav>
		<Routes><Route path="/" element={<Records />} />
			<Route path="/about" element={<p>Synthetic local records</p>} /></Routes>
	</main></HashRouter>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
```

### Objectives and Commands

```powershell
npm install --save-exact react react-dom react-router-dom
npm install --save-dev --save-exact vite typescript @types/react @types/react-dom
node --version
npm ls --depth=0
npm run check
npm run build
npm run dev
```

Open `http://127.0.0.1:5173/`. Use another unused port by changing the lab script if occupied. Edit Lin to LIN-EDIT, then delete a. Navigate About/Records; compare deletion preservation with route-unmount reset. Select Empty and Missing. Inspect cancellation under Network throttling when switching routes quickly.

### Hints

Row state starts from a prop once at mount; it is intentionally local draft state. Changing a prop does not reinitialize useState. Router unmount and sibling deletion have different identity effects.

### Solution and Expected Results

The remaining b input must retain LIN-EDIT after deleting a. In the console, `document.querySelector('[data-id="b"] input').value` should equal `LIN-EDIT`. Replacing `key={item.id}` with an index key produces wrong row-state association after deletion; restore stable IDs. Returning from About reloads original fixture names because Records was unmounted. Empty has zero rows and Empty status. Missing may be HTTP 404 or a JSON parse error if Vite's SPA fallback returns HTML; either must show an error, never Ready. Production APIs should return explicit non-HTML error responses.

### Verification, Troubleshooting, and Cleanup

Check/typecheck and build are separate gates: Vite transforms TS without a full typecheck. Confirm three initial rows, two after deletion, zero for empty, no uncaught rejection on route changes, and keyboard access. Development duplicate requests can be StrictMode setup/cleanup, not a production request count guarantee. Keep manifest/lockfile/version output with observations; stop your dev server and remove only the lab directory. Nothing was installed, launched, compiled or tested during this revision.

- [ ] Local React exercise: Build a typed editable list with stable IDs, loading/error states, and an abortable fetch. Delete one row and verify neighboring input state stays attached to the correct item.
- [ ] Boundary check: Render a harmless HTML marker as ordinary JSX text and verify escaping. Call a protected endpoint directly while the UI hides its button; require server denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[React Security]]

## References

- [Official documentation or primary training reference](https://react.dev/learn)
- [Preserving and resetting state](https://react.dev/learn/preserving-and-resetting-state)
- [useEffect](https://react.dev/reference/react/useEffect)
- [Server Components](https://react.dev/reference/rsc/server-components)
- [React Router declarative installation](https://reactrouter.com/start/declarative/installation)
