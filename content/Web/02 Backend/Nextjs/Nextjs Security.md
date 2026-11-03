---
title: "Next.js Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Nextjs]]"
updated: 2026-11-03
---
# Next.js Security

> [!abstract] TL;DR
> Missing action authorization, cached personalized responses, or accidental client imports can disclose server data despite a protected-looking page.

> [!info] Agent scope
> Security of: Routing; rendering modes; server components; server actions; data fetching; caching; runtime and deployment boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Missing action authorization, cached personalized responses, or accidental client imports can disclose server data despite a protected-looking page.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me Next.js 16 security given React Server Components, HTTP and sessions.
Explain trust boundaries for server/client module graphs, RSC serialization,
Server Actions, Route Handlers, route-level proxy logic, cache keys and runtime
configuration. Show defensive data-access code with verified identity, input
validation, per-object checks, safe DTOs and transaction/invalidation ordering.
Contrast Next 14/15/16 cache and request-API behavior. Provide complete local
negative regression tests with synthetic identities, including permitted cases,
cache isolation and absence of dummy secret markers from browser artifacts.
No exploitation, action-protocol bypass, evasion or credential demonstrations.
Use official sources; distinguish predictions from measurements. Teach here.
```

## Cheatsheet

### Data Access Is the Policy Boundary

An RSC is server-executed, not private by definition: rendered text, serialized props, action return values and error data can reach the browser. Keep credential access in `server-only` modules and return explicit DTOs. A client-hidden button, protected layout, or proxy redirect is a usability gate; enforce identity and object policy again in the data-access function called by every entry point.

Unsafe review fragment: `db.note.update({where:{id: form.get('id')}, data:Object.fromEntries(form)})`. It accepts arbitrary fields and never binds the object to a principal. Fixed shape: validate text and ID, then update with both `{id, ownerId: session.userId}` in one database operation. Check affected rows before revalidating. An action-level read followed by an unrestricted update has a race if ownership can change.

| Boundary | Required control | Limitation |
|---|---|---|
| Server Action POST | Derive identity from validated server session, validate every argument, authorize operation | Framework action IDs and origin/host checks do not replace application policy. Bound arguments are still inputs. |
| Route Handler | Same DAL policy; explicit private/no-store response for personalized data | Browser cache headers do not control an already-shared server data cache. |
| Data Cache | Do not cache session-dependent results globally; use explicit scope/keys for intentional sharing | An omitted tenant dimension can mix identities even when route output is dynamic. |
| Client graph | `server-only`, minimal DTOs, no secrets in `NEXT_PUBLIC_` or props | Obscuring variable names is not confidentiality. |
| Deployment | Maintained patched Next/React releases; consistent action encryption material when required across replicas | In-memory state, ephemeral disk and per-process caches are not distributed storage. |
| Error path | Expected errors as constrained data; unexpected errors logged server-side | Development overlays expose more detail; production behavior must be checked separately. |

Next 16 uses `proxy` terminology for the former middleware convention, but routing interception is still not the sole authorization boundary. Next 15/16 async `cookies`, `headers` and params require awaiting. Cache Components is opt-in in Next 16; do not combine its rules blindly with older route-segment cache configuration.

## Detection and Defense

Record route/action category, opaque request ID, authorization outcome and cache decisions without session cookies or action arguments. Compare permitted/denied access rates with normal client retries. Verify private responses at the deployed CDN as well as origin. Patch framework/React advisories promptly; source-level policy tests do not certify the framework transport.

## Labs

- [ ] Local Nextjs exercise: Build a small authenticated notes page with a server-side mutation and a detail route. Test two synthetic accounts and inspect the client bundle and network responses for unintended data.
- [ ] Boundary check: Replay a mutation directly with another synthetic identity and verify denial. Load two users' pages sequentially and confirm no personalized response is reused across them.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. Node.js 24 LTS, npm 11, latest patched Next 16.x and compatible React 19.2.x. Keep the generated lockfile. No credentials, real accounts or external services. `LAB_USER` is a startup-only synthetic fixture; never expose this fixture mechanism as production authentication. Complete independent project:

### File: package.json

```json
{"private":true,"type":"module","scripts":{"dev":"next dev --hostname 127.0.0.1","build":"next build","start":"next start --hostname 127.0.0.1","test":"node --test"},"dependencies":{"next":"16.x","react":"19.2.x","react-dom":"19.2.x","server-only":"0.0.1"}}
```

### File: lib/policy.js

```javascript
const records = { '1': { owner: 'alice', text: 'alpha', internal: 'DUMMY_INTERNAL_ONLY' },
	'2': { owner: 'bob', text: 'beta', internal: 'DUMMY_INTERNAL_ONLY' } };
export function readNote(user, id) {
	if (!['alice', 'bob'].includes(user)) return { status: 401 };
	const note = Object.hasOwn(records, id) ? records[id] : null;
	if (!note || note.owner !== user) return { status: 404 };
	return { status: 200, note: { id, text: note.text } };
}
export function validateEdit(user, id, text) {
	const result = readNote(user, id);
	if (result.status !== 200) return result;
	if (typeof text !== 'string' || !text.trim() || text.length > 80) return { status: 400 };
	return { status: 200, note: { id, text: text.trim() } };
}
```

### File: lib/dal.js

```javascript
import 'server-only';
import { readNote, validateEdit } from './policy.js';
export function currentNote(id) { return readNote(process.env.LAB_USER, id); }
export function currentEdit(id, text) { return validateEdit(process.env.LAB_USER, id, text); }
```

### File: app/layout.js

```jsx
export default function Layout({ children }) {
	return <html lang="en"><body>{children}</body></html>;
}
```

### File: app/actions.js

```javascript
'use server';
import { cookies } from 'next/headers';
import { revalidatePath } from 'next/cache';
import { currentEdit } from '../lib/dal.js';
export async function previewEdit(form) {
	const result = currentEdit(form.get('id'), form.get('text'));
	const jar = await cookies();
	jar.set('edit_result', String(result.status), { httpOnly: true, sameSite: 'lax', path: '/' });
	revalidatePath('/');
}
```

### File: app/page.js

```jsx
import { cookies } from 'next/headers';
import { previewEdit } from './actions.js';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export default async function Page() {
	const jar = await cookies();
	return <main><h1>Edit authorization preview</h1>
		<p>Result: {jar.get('edit_result')?.value ?? 'none'}</p>
		<form action={previewEdit}><input name="id" defaultValue="1" />
			<input name="text" defaultValue="reviewed" />
			<button type="submit">Validate edit</button></form></main>;
}
```

### File: app/api/notes/route.js

```javascript
import { currentNote } from '../../../lib/dal.js';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export async function GET(request) {
	const result = currentNote(new URL(request.url).searchParams.get('id'));
	return Response.json(result.note ?? { error: 'unavailable' }, {
		status: result.status, headers: { 'Cache-Control': 'private, no-store' }
	});
}
```

### File: policy.test.js

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { readNote, validateEdit } from './lib/policy.js';
test('authorization, DTO and edit validation', () => {
	assert.equal(readNote(null, '1').status, 401);
	assert.equal(readNote('bob', '1').status, 404);
	assert.equal(readNote('alice', '999').status, 404);
	assert.deepEqual(readNote('alice', '1'), { status: 200, note: { id: '1', text: 'alpha' } });
	assert.equal(validateEdit('bob', '1', 'reviewed').status, 404);
	assert.equal(validateEdit('alice', '1', '').status, 400);
	assert.equal(validateEdit('alice', '1', 'reviewed').status, 200);
});
```

### Objectives, Baseline and Hints

Run `npm install`, `npm test`, then PowerShell `$env:LAB_USER='alice'` and `npm run dev`. Baseline: `curl.exe -i "http://127.0.0.1:3000/api/notes?id=1"` returns only ID/text with private/no-store. Load `/`, submit ID 1 then synthetic ID 2: result status should be 200 then 404. This checks a safe authorization preview, not a persisted mutation. Hint: both entry points delegate to the same policy; a successful page render never grants subsequent action permission.

### Solution and Fixed Retest

The solution is the explicit DTO plus owner check in the shared policy. Stop, change `LAB_USER` to `bob`, restart and repeat reads: ID 1 is 404, ID 2 returns beta. Repeat after `npm run build` / `npm start`; inspect Network responses and browser-downloaded scripts for absence of `DUMMY_INTERNAL_ONLY`. Do not search server artifacts and interpret their expected copy as client disclosure. Test no configured user as well: route returns 401. Predicted unit output: one passing test. No executable vulnerable variant is provided.

### Troubleshooting and Reset

An environment change requires a server restart. Delete the `edit_result` site cookie to reset the preview; it contains only a status, never identity. A browser cache inspection alone cannot prove CDN isolation, so no deployed-cache claim is made. Stop Ctrl+C and remove this disposable project to reset dependencies/build artifacts. Real session validation, transactional persistence and multi-replica invalidation are deliberately not simulated by cookie status or in-memory fixtures; their requirements are in the reference above.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Nextjs]]

## References

- [Data security](https://nextjs.org/docs/app/guides/data-security)
- [Authentication and data-access layer](https://nextjs.org/docs/app/guides/authentication)
- [Caching](https://nextjs.org/docs/app/guides/caching)
- [Next security policy](https://github.com/vercel/next.js/security/policy)
