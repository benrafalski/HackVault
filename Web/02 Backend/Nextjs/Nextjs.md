---
title: "Next.js"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Nextjs Security]]"
updated: 2026-11-03
---
# Next.js

> [!abstract] TL;DR
> Authorize inside each route handler/action. Separate public cached data from per-user data; document the exact Next.js version and runtime.

> [!info] Agent scope
> Routing; rendering modes; server components; server actions; data fetching; caching; runtime and deployment boundaries.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Next.js 16 App Router given React, promises, HTTP and session basics.
Trace URL routing, nested layouts, server rendering, RSC payloads, hydration,
Route Handlers and Server Actions. Compare static/dynamic rendering, streaming,
revalidation, request memoization, Data/Full Route/Router caches and Cache
Components. Contrast Next 14, 15 and 16 defaults and async request APIs.
Explain Node versus Edge runtime, deployment replicas, environment variables,
server-only modules, personalized data, action authentication and transactions.
Give complete implementations with commands and regression tests, including
error/loading/not-found behavior and stale-data diagnosis. Use primary docs;
label predictions and version assumptions. Teach here without editing files.
```

## Cheatsheet

### Routing and Rendering

App Router maps directories beneath `app` to segments. `page` renders a route, `layout` persists across navigation, `loading` supplies a Suspense boundary, `error` is a client error boundary, and `not-found` handles `notFound()`. Route groups organize without adding URL segments. A `route.js` exports HTTP methods and cannot share its segment with a page. Dynamic `[id]` parameters and `searchParams` are asynchronous APIs in current Next; await them.

Server Components execute on the server and send an RSC representation, not their source code. Client Components begin at `'use client'`; their transitive imports belong to the client graph. They can still be prerendered on the server, so browser-only APIs belong in effects/events. Passing a value to a Client Component or rendering it into HTML discloses it regardless of where it was computed. `import 'server-only'` detects accidental client imports; it does not authorize requests.

### Cache and Runtime Decisions

| Mechanism | Lifetime and decision |
|---|---|
| Request memoization | Repeated eligible fetches during one React render can share work. It is not a user session or durable cache. Route Handlers are outside that React tree. |
| Data Cache | Explicit `fetch(url, {cache:'force-cache'})` or supported revalidation options persist data. Include all public variation keys; never put credential-dependent responses in a shared key. |
| Full Route Cache | Static HTML/RSC output can be reused. Request-time APIs and explicit dynamic configuration change eligibility. A route with personalized output must not be treated as public static content. |
| Router Cache | Client-side segment/navigation reuse can show stale UI after a server write. Revalidate the affected path/tag and refresh/navigation as appropriate; cache invalidation is not authorization revocation. |
| Cache Components | Next 16 opt-in `cacheComponents` changes the rendering model and permits explicit `use cache` boundaries. This lab leaves it disabled and uses the conventional dynamic route model. |

Next 14 commonly cached server fetches and GET Route Handlers by default; Next 15 changed defaults toward uncached fetches/GET handlers and asynchronous request APIs. Do not infer behavior from a tutorial for another major. Use `cache:'no-store'` for personalized fetches and `Cache-Control: private, no-store` for private HTTP responses. The latter does not retroactively fix an upstream shared data cache.

Node runtime can use Node APIs and database drivers; Edge supports a restricted web API environment, not arbitrary Node modules. Serverless filesystems and process globals are not durable storage. `NEXT_PUBLIC_` values are client-visible and commonly frozen at build time; keep secrets in server-only runtime configuration. Multi-replica caches and Server Action encryption configuration need deployment coordination.

### Actions, Errors and Transactions

`'use server'` marks callable server functions, not trusted inputs. Authenticate and authorize inside each action and Route Handler; validate `FormData` before database calls. Use a single database transaction for dependent writes, then invalidate caches after commit. `redirect()` and `notFound()` work by throwing framework control-flow exceptions: do not swallow them in a broad catch. Return expected validation errors as data, and let unexpected faults reach a boundary with sanitized production output.

Fragment for an external personalized fetch: `await fetch(serviceUrl, {cache:'no-store', headers:{Authorization: verifiedServiceToken}})`. The token and URL must be server-owned, not copied from arbitrary form fields.

## Gotchas

Server-only execution does not imply trusted input. Middleware alone is not a sufficient authorization boundary for every data operation.

## Labs

- [ ] Local Nextjs exercise: Build a small authenticated notes page with a server-side mutation and a detail route. Test two synthetic accounts and inspect the client bundle and network responses for unintended data.
- [ ] Boundary check: Replay a mutation directly with another synthetic identity and verify denial. Load two users' pages sequentially and confirm no personalized response is reused across them.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. Node.js 24 LTS, npm 11, latest patched Next.js 16.x and React 19.2.x supported by that Next release. Resolve these supported lines once, retain the generated lockfile, then use `npm ci` for repeats. This is a Node, single-process exercise with Cache Components disabled. Synthetic identity is fixed by `LAB_USER` at startup, not authenticated over HTTP. The cookie holds only a nonsecret per-browser draft; no database scaffold is missing.

### File: package.json

```json
{"private":true,"type":"module","scripts":{"dev":"next dev --hostname 127.0.0.1","build":"next build","start":"next start --hostname 127.0.0.1","test":"node --test"},"dependencies":{"next":"16.x","react":"19.2.x","react-dom":"19.2.x","server-only":"0.0.1"}}
```

### File: app/layout.js

```jsx
export default function Layout({ children }) {
	return <html lang="en"><body>{children}</body></html>;
}
```

### File: lib/policy.js

```javascript
export function draftInput(user, value) {
	if (!['alice', 'bob'].includes(user)) throw new Error('unauthorized');
	if (typeof value !== 'string' || !value.trim() || value.length > 80) {
		throw new Error('invalid draft');
	}
	return { owner: user, text: value.trim() };
}
```

### File: lib/session.js

```javascript
import 'server-only';
export function fixtureUser() {
	const user = process.env.LAB_USER;
	if (!['alice', 'bob'].includes(user)) throw new Error('Set LAB_USER to alice or bob');
	return user;
}
```

### File: app/actions.js

```javascript
'use server';
import { cookies } from 'next/headers';
import { revalidatePath } from 'next/cache';
import { fixtureUser } from '../lib/session.js';
import { draftInput } from '../lib/policy.js';
export async function saveDraft(formData) {
	const draft = draftInput(fixtureUser(), formData.get('text'));
	const jar = await cookies();
	jar.set(`draft_${draft.owner}`, draft.text, {
		httpOnly: true, sameSite: 'lax', path: '/', maxAge: 600,
		secure: false
	});
	revalidatePath('/');
}
```

### File: app/page.js

```jsx
import { cookies } from 'next/headers';
import { saveDraft } from './actions.js';
import { fixtureUser } from '../lib/session.js';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export default async function Page() {
	const user = fixtureUser();
	const jar = await cookies();
	const text = jar.get(`draft_${user}`)?.value ?? '(empty)';
	return <main><h1>{user}'s draft</h1><p>{text}</p>
		<form action={saveDraft}><input name="text" maxLength={80} required />
			<button type="submit">Save draft</button></form>
		<a href="/api/draft">Draft JSON</a></main>;
}
```

### File: app/api/draft/route.js

```javascript
import { cookies } from 'next/headers';
import { fixtureUser } from '../../../lib/session.js';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function GET() {
	const user = fixtureUser();
	const jar = await cookies();
	return Response.json({ user, text: jar.get(`draft_${user}`)?.value ?? '' },
		{ headers: { 'Cache-Control': 'private, no-store' } });
}
```

### File: policy.test.js

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { draftInput } from './lib/policy.js';
test('draft validation', () => {
	assert.deepEqual(draftInput('alice', ' hello '), { owner: 'alice', text: 'hello' });
	assert.throws(() => draftInput(null, 'hello'));
	assert.throws(() => draftInput('alice', ''));
	assert.throws(() => draftInput('alice', 'x'.repeat(81)));
});
```

### Objectives and Commands

In PowerShell: `npm install`, `$env:LAB_USER='alice'`, `npm test`, `npm run dev`. Open `http://127.0.0.1:3000`, save `alpha`, inspect the form POST and JSON route in browser Network tools. Stop; run `npm run build` then `npm start` for production-mode observations. Stop and set `$env:LAB_USER='bob'`, restart, and confirm Bob's draft is empty in the same browser. Return to Alice and confirm her cookie remains until expiry. POSIX equivalent: `LAB_USER=alice npm run dev`.

### Hints and Separate Solution

Cookies can be read during render but mutated in an action/handler. `revalidatePath` invalidates the displayed route after mutation. The solution uses different cookie keys for the fixture principals and a dynamic render: expected Alice=`alpha`, Bob=`(empty)`, and `/api/draft` reports `private, no-store`. The unit test covers input, not browser/RSC behavior. Cookie values are untrusted presentation data, never identity or authoritative persisted records. React escapes their text rendering.

### Verification, Troubleshooting and Reset

Expected unit result: one passing test. Inspect browser bundles for absence of the server-only session module; inspect both HTML/RSC and JSON responses for only the selected fixture's data. An unset `LAB_USER` intentionally fails closed. Keep server actions same-origin; do not construct internal action IDs manually. A cookie may survive restarts: clear site data to reset drafts. Stop with Ctrl+C and remove the disposable directory. HTTP-only loopback explains `secure:false`; use Secure cookies with real HTTPS and an established session provider in deployment. This lab does not claim production authentication or database durability.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Nextjs Security]]

## References

- [App Router](https://nextjs.org/docs/app)
- [Caching guide](https://nextjs.org/docs/app/guides/caching)
- [Upgrading to Next 16](https://nextjs.org/docs/app/guides/upgrading/version-16)
- [Server Functions](https://nextjs.org/docs/app/getting-started/updating-data)
