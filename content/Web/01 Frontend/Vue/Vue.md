---
title: "Vue"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[Vue Security]]"
updated: 2026-11-03
---
# Vue

> [!abstract] TL;DR
> Use text interpolation for untrusted strings; treat v-html and dynamic template compilation as security-sensitive. Keep server secrets out of serialized client state.

> [!info] Agent scope
> Reactivity; components; templates; routing; state; HTML rendering; client/server boundaries.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Vue 3 at expert application/runtime depth. I know JavaScript, DOM and
HTTP. Cover refs/proxies, dependency tracking, computed caching, watch versus
watchEffect and cleanup, batching/nextTick, SFC compilation, props/emits/v-model,
stable component keys, routing and state ownership, async failures, text versus
HTML rendering, SSR state isolation and hydration. Explain destructuring and
ref-unwrapping traps, Vue 2 differences and Vue 3.5-specific APIs. Give complete
SFC projects with a real router, synthetic fetch fixtures, filtered derived
state, child events, error/empty/loading states and reproducible assertions.
Use official Vue/router documentation. Teach here without editing files,
requiring a companion conversation or claiming unperformed tests.
```

## Cheatsheet

### Reactive Dependencies and Scheduling

Vue 3 uses proxies for reactive objects and tracked accessors for refs. Reading a tracked value during a reactive effect registers a dependency; writing it schedules consumers. `ref()` uses `.value` in JavaScript, while top-level refs are generally unwrapped in templates. `reactive()` returns a proxy whose identity differs from the original object; mutate through the proxy. Replacing a local variable holding a reactive object does not retarget existing subscribers.

Destructuring a primitive property from an ordinary reactive object loses its reactive access path; use `toRef`/`toRefs` or a getter. Vue 3.5's compiler-assisted reactive destructuring of `defineProps` in script setup is a specific exception, not a general JavaScript rule. Ref unwrapping has exceptions in arrays and collections; inspect `.value` requirements. Vue 2's getter/setter change-detection limitations and set helpers do not describe Vue 3 proxy behavior.

| API | Use it for | Failure to avoid |
|---|---|---|
| `computed` | Pure derived value with cached dependencies | Network calls or mutating state in a getter |
| `watch(source, callback)` | Explicit dependency and old/new value side effect | Unbounded deep watching or missing async cleanup |
| `watchEffect` | Automatic synchronous dependency capture | Assuming reads after await are tracked in the initial run |
| `nextTick` | Wait for Vue's queued DOM patch | Assuming it waits for images/network or a browser paint |
| `shallowRef` | Large/external immutable objects where only replacement is tracked | Expecting nested mutation to notify automatically |

Vue batches reactive updates. A default watcher is not automatically a post-DOM-update measurement hook; use `flush: 'post'` when the callback needs the updated owner DOM. Synchronous watchers bypass batching and can be costly. Watchers created synchronously in setup are stopped at unmount; asynchronously created watchers need explicit ownership. The callback cleanup argument works across Vue 3 versions; `onWatcherCleanup` is Vue 3.5+ and has synchronous registration constraints.

### Components and State Ownership

Props flow down; components emit named events upward. Props are shallow-readonly from the child's view, but nested object mutation can still alter shared parent data: prefer emitted intents. Declare emits so event ownership is clear. `v-model` is a prop/update-event contract, not magic shared storage; newer `defineModel` syntax is version-specific. Stable keys keep local editor state attached to identity across list changes.

```vue
<!-- Fragment: parent owns the selected identifier. -->
<RecordRow :record="record" @select="selectedId = $event" />
```

Use component-local state for one view, lift state to a common owner for coordinated views, and use Pinia or an established application store when shared state complexity justifies it. A module-global reactive singleton is shared across importing components and, in SSR, potentially across requests. Create server app/store instances per request. `provide`/`inject` is scoped dependency sharing, not an authorization boundary.

### Routing, Fetch, and Rendering

Vue Router 4 is the Vue 3 router. A reused route component must watch relevant params; mounted-only fetching may miss changes. Hash history avoids server fallback configuration; HTML5 history requires direct-route reload support without hiding real asset/API errors. Guards control navigation, not service access. Fetch status and JSON shape still require validation; cancel previous work and reject stale completion before committing data.

SFC templates compile to render functions. `{{label}}` renders text; `v-html` opts into raw HTML and does not compile that HTML as a Vue template or sanitize it. Attribute escaping does not establish URL/style policy. Never use user content as a component template. Scoped CSS rewrites selectors for component styling, not a security sandbox; raw HTML descendants may not have scoped attributes.

SSR creates HTML on the server and hydration attaches client behavior to matching output. Browser APIs belong in client lifecycle hooks or guarded code. Random/time-dependent initial output and HTML parser repairs can create mismatches. Do not serialize confidential server fields; use framework-supported state serialization and request-isolated stores. A client-only Vite app is not automatically an SSR application.

## Gotchas

A reactive object is not a validation boundary. HTML escaping does not make arbitrary JavaScript or URL contexts safe.

## Labs

### Environment and Complete Files

Supported Node LTS satisfying installed Vite engines, npm and a modern browser. Vue 3 and Vue Router 4 are explicit API families; the install records resolved patches. For Vite 7, Node 22.12+ within major 22 is sufficient; check newer Vite/plugin engines before accepting an upgrade. Create `vue-state-lab` with all eight files below. No backend, images or external API is needed.

### File: package.json

```json
{"name":"vue-state-lab","private":true,"type":"module",
 "scripts":{"dev":"vite --host 127.0.0.1 --port 5174 --strictPort","build":"vite build"}}
```

### File: vite.config.js

```js
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
export default defineConfig({plugins: [vue()]});
```

### File: index.html

```html
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Vue records</title></head>
<body><div id="app"></div><script type="module" src="/src/main.js"></script></body></html>
```

### File: src/main.js

```js
import { createApp } from 'vue';
import { createRouter, createWebHashHistory } from 'vue-router';
import App from './App.vue';
import Records from './Records.vue';
const router = createRouter({history: createWebHashHistory(), routes: [
	{path: '/', redirect: '/records/all'},
	{path: '/records/:mode', component: Records}
]});
createApp(App).use(router).mount('#app');
```

### File: src/App.vue

```vue
<template>
	<main><h1>Vue records</h1><nav>
		<RouterLink to="/records/all">All</RouterLink> |
		<RouterLink to="/records/missing">Missing</RouterLink>
	</nav><RouterView /></main>
</template>
```

### File: src/RecordRow.vue

```vue
<script setup>
defineProps({record: {type: Object, required: true}});
const emit = defineEmits(['select']);
</script>
<template>
	<li><button :data-id="record.id" @click="emit('select', record.id)">{{record.label}}</button></li>
</template>
```

### File: src/Records.vue

```vue
<script setup>
import { computed, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import RecordRow from './RecordRow.vue';
const route = useRoute();
const records = ref([]);
const query = ref('');
const selected = ref('');
const status = ref('Loading');
const filtered = computed(() => records.value.filter(record =>
	record.label.toLowerCase().includes(query.value.toLowerCase())));
function decode(value) {
	if (!Array.isArray(value) || value.length > 100 || value.some(record =>
		!record || typeof record.id !== 'string' || typeof record.label !== 'string')) {
		throw new Error('Invalid records');
	}
	if (new Set(value.map(record => record.id)).size !== value.length) throw new Error('Duplicate IDs');
	return value.map(({id, label}) => ({id, label}));
}
watch(() => route.params.mode, async (mode, previous, onCleanup) => {
	const controller = new AbortController();
	let active = true;
	onCleanup(() => { active = false; controller.abort(); });
	status.value = 'Loading'; records.value = []; selected.value = '';
	try {
		const file = mode === 'all' ? '/records.json' : '/missing.json';
		const response = await fetch(file, {signal: controller.signal});
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const next = decode(await response.json());
		if (active) { records.value = next; status.value = next.length ? 'Ready' : 'Empty'; }
	} catch (error) {
		if (active) status.value = error instanceof Error ? error.message : 'Load failed';
	}
}, {immediate: true});
</script>
<template>
	<section><h2>Filter records</h2>
		<label for="query">Name contains</label><input id="query" v-model="query">
		<p role="status">{{status}}</p>
		<p id="count">{{filtered.length}} matches</p>
		<ul><RecordRow v-for="record in filtered" :key="record.id" :record="record"
			@select="selected = $event" /></ul>
		<p v-if="status === 'Ready' && filtered.length === 0">No matching records</p>
		<output id="selected">{{selected}}</output>
	</section>
</template>
```

### File: public/records.json

```json
[{"id":"a","label":"Ada"},{"id":"b","label":"Lin"},{"id":"c","label":"Sam"}]
```

### Objectives and Commands

```powershell
npm install --save-exact vue@3 vue-router@4
npm install --save-dev --save-exact vite @vitejs/plugin-vue
node --version
npm ls --depth=0
npm run build
npm run dev
```

Open `http://127.0.0.1:5174/`; choose a different unused lab port if occupied. Type `a`, select Sam, then type `zzz`. Navigate Missing then All and observe route reuse. Temporarily replace records.json with `[]` for the empty-response case and restore the printed fixture afterward.

### Hints

Filtered results should not be a second independently mutable array. Child events carry the record ID, not authority to change server state. Register async cleanup before await; route params can change without remounting.

### Solution and Expected Results

Initial: Ready and 3 matches. Query a: 2 matches (Ada, Sam). Selecting Sam makes output c. Query zzz: 0 matches and No matching records. Missing shows an HTTP/JSON error, not Ready; All recovers using the same watched param. Empty fixture produces Empty and zero matches. In the console after filtering, `document.querySelectorAll('li button').length` should equal the displayed count. Dev-server fallback can return HTML for missing JSON; the parse failure must remain visible.

### Verification, Troubleshooting, and Cleanup

Build checks SFC compilation, not a JavaScript type system or every runtime path. Check Back/Forward, keyboard operation and fast route switching under throttling. If the watcher does not rerun, confirm its source is a getter of `route.params.mode`, not a one-time destructured value. If SFCs fail to load, verify plugin-vue registration and compatible Vite/plugin majors. Stop your server, restore/delete the disposable fixture directory and retain lockfile/version evidence as needed. No install, build, server or browser test was run in this revision.

- [ ] Local Vue exercise: Build a filtered list using computed state and a child component event. Verify filtering updates without duplicated stored state and that loading failures are visible.
- [ ] Boundary check: Display a markup marker through interpolation and confirm literal output. Request another synthetic user's record directly and require the server to reject it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Vue Security]]

## References

- [Official documentation or primary training reference](https://vuejs.org/guide/best-practices/security.html)
- [Reactivity fundamentals](https://vuejs.org/guide/essentials/reactivity-fundamentals.html)
- [Watchers and cleanup](https://vuejs.org/guide/essentials/watchers.html)
- [Server-side rendering](https://vuejs.org/guide/scaling-up/ssr.html)
- [Vue Router](https://router.vuejs.org/guide/)
