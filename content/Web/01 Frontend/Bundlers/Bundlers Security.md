---
title: "Bundlers (Vite and webpack) Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[Bundlers]]"
updated: 2026-11-03
---
# Bundlers (Vite and webpack) Security

> [!abstract] TL;DR
> Malicious build plugins, leaked source maps, exposed dev servers, and embedded secrets can compromise the build or disclose implementation details.

> [!info] Agent scope
> Security of: Module graphs; dev servers; production builds; tree shaking; source maps; environment-variable exposure; plugins. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Malicious build plugins, leaked source maps, exposed dev servers, and embedded secrets can compromise the build or disclose implementation details.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Vite/webpack security at build and deployment depth. I know
module graphs, env replacement, plugins, chunks and source maps. Explain the
build-process trust boundary, plugin/install authority, client-visible env,
public-directory copies, source-map publication, host/CORS/filesystem controls,
artifact provenance and coherent deployment. Distinguish current Vite/Rolldown
from older releases and webpack 5 defaults. Supply complete dual-builder labs,
synthetic artifact leak fixtures, release-gate tests and loopback-only host
policy checks with permitted behavior preserved. No exploit payloads, bypass,
credential theft, persistence or offensive walkthroughs. Use official Vite,
webpack and Node documentation. Teach here without editing files or claiming
unperformed installs/builds/tests.
```

## Cheatsheet

### Three Distinct Trust Boundaries

The build process can read its environment/files and run config, plugin, loader and dependency lifecycle code. The resulting client artifact is public to anyone allowed to fetch it. The development server additionally exposes source/transforms/HMR and may have filesystem/proxy capabilities absent from production. Securing only one boundary does not secure the others.

| Failure | Root cause | Concrete defense |
|---|---|---|
| Client config contains private value | Broad env substitution or a secret imported into client graph | Explicit public values only; keep server authority outside that graph |
| Ignored file appears in release | public/static-copy path includes it | Audit copied assets and scan the exact publication directory |
| Hidden maps reachable | “Hidden” only removed the map reference | Exclude maps from release or publish by deliberate policy |
| Dev server available to unintended clients | Wildcard bind, broad host/CORS rules, proxy exposure | Loopback bind plus explicit policies; no public tunnels for this lab |
| Plugin has excessive authority | Build inherits credentials/workspace access | Minimal isolated build environment and reviewed dependency graph |
| Old clients lose lazy chunks | Deployment removes immutable assets too early | Coherent release and retained hashed assets; controlled HTML caching |

`VITE_` means exposed, not encrypted. `.gitignore` controls Git tracking, not bundle inclusion. Minification and tree shaking are not confidentiality mechanisms: reachable code may preserve a value and source maps can retain removed source. Do not define the entire `process.env` object in webpack or configure Vite to expose all env names. Use separately authenticated server APIs for operations needing private configuration.

### Dev Server Controls

Vite `host: '127.0.0.1'` limits the listening address; `allowedHosts` restricts accepted hostnames in supported HTTP configurations; CORS controls cross-origin browser reading; `fs.strict` constrains file serving. These are complementary, not authentication. Current Vite allows localhost/IP hosts by default and documents that HTTPS host checks differ. Test your installed version and do not infer policy from a config field alone.

Keep `allowedHosts` explicit, not true; do not use unrestricted CORS to resolve development errors. Explicit filesystem allow paths override workspace auto-detection; broad parent directories increase exposure. Public-directory files are copied/served as public assets and are not protected by every filesystem deny rule. Plugins can read files beyond the server's request filters, so these controls do not sandbox plugin execution.

webpack-dev-server hardening fragment for a separately configured webpack project:

```js
devServer: {
	host: '127.0.0.1',
	allowedHosts: ['localhost'],
	port: 8081
}
```

This fragment is not used by the build-only webpack lab below. Check webpack-dev-server major-specific options before adopting it. A development server or Vite preview is not a production deployment architecture.

### Release and Dependency Policy

Commit reviewed lockfiles in real projects, resolve deliberately, then use `npm ci` in a clean build. Lockfiles improve reproducibility but do not establish that a package is benign or vulnerability-free. Integrity hashes identify downloaded bytes, not author trust. Review lifecycle scripts, new plugins and dependency changes; avoid giving untrusted builds deployment credentials. The lab installs packages only in a disposable directory and contains no credentials.

Inspect the final release, including HTML, JS, CSS, maps, copied JSON and compressed siblings. A string scan is a regression canary, not a complete secret detector: encoding, splitting, generated values or unrecognized secrets can evade simple matching. Fail closed if the expected entry or scripts are absent; a scan of an empty directory must not count as a successful release. Source maps need a positive publication policy, and private error-reporting uploads should not silently copy maps into public output.

## Detection and Defense

Record builder/runtime/plugin versions and lockfiles, audit final file lists, compare unexpected origins/asset additions and verify response headers on the deployed artifact. Test the release gate itself with known synthetic failures so a broken scanner cannot silently pass. Keep build-time permission review separate from browser artifact inspection. The lab's fixed marker is intentionally nonsecret and must never be replaced with a real token.

## Labs

### Environment and Complete Files

Supported Node LTS satisfying selected tool engines (current Vite documents Node 22.12+ within major 22), npm, Vite and webpack 5. All files are printed below; create an independent `bundler-policy-lab`. Unit tests use Node stdlib only. The optional server test creates a short-lived loopback Vite server and never contacts an external host.

### File: package.json

```json
{"name":"bundler-policy-lab","private":true,"type":"module",
 "scripts":{"build:vite":"vite build",
 "build:webpack":"node --env-file=.env ./node_modules/webpack-cli/bin/cli.js --config webpack.config.cjs",
 "test:gate":"node --test gate.test.mjs","test:server":"node --test server.test.mjs",
 "check:vite":"node gate.mjs dist/vite","check:webpack":"node gate.mjs dist/webpack"}}
```

### File: .env

```dotenv
VITE_PUBLIC_LABEL=PUBLIC-LAB-7
SERVER_ONLY_MARKER=PRIVATE-LAB-ONLY
```

### File: index.html

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Release policy</title></head>
<body><main><h1>Public configuration</h1><p id="label"></p></main>
<script type="module" src="/src/main.js"></script></body></html>
```

### File: src/main.js

```js
document.querySelector('#label').textContent = import.meta.env.VITE_PUBLIC_LABEL;
```

### File: vite.config.js

```js
import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('.', import.meta.url));
export default defineConfig({
	base: './', publicDir: false,
	server: {host: '127.0.0.1', port: 5175, strictPort: true,
		allowedHosts: ['localhost'], cors: false, fs: {strict: true, allow: [root]}},
	build: {outDir: 'dist/vite', emptyOutDir: true, sourcemap: false}
});
```

### File: webpack.config.cjs

```js
const path = require('node:path');
const webpack = require('webpack');
const HtmlWebpackPlugin = require('html-webpack-plugin');
module.exports = {
	mode: 'production', entry: './src/main.js', devtool: false,
	output: {path: path.resolve(__dirname, 'dist/webpack'), filename: '[name].[contenthash].js', clean: true},
	plugins: [new webpack.DefinePlugin({
		'import.meta.env.VITE_PUBLIC_LABEL': JSON.stringify(process.env.VITE_PUBLIC_LABEL)
	}), new HtmlWebpackPlugin({templateContent:
		'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Release policy</title></head><body><main><h1>Public configuration</h1><p id="label"></p></main></body></html>'})]
};
```

### File: gate.mjs

```js
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
async function files(root) {
	const paths = [];
	for (const entry of await readdir(root, {withFileTypes: true})) {
		const path = join(root, entry.name);
		if (entry.isDirectory()) paths.push(...await files(path));
		else if (entry.isFile()) paths.push(path);
		else throw new Error('Unsupported release entry');
	}
	return paths;
}
export async function inspect(root) {
	const paths = await files(root);
	const problems = [];
	if (!paths.some(path => relative(root, path) === 'index.html')) problems.push('missing entry');
	if (!paths.some(path => path.endsWith('.js'))) problems.push('missing script');
	let publicFound = false;
	for (const path of paths) {
		const bytes = await readFile(path);
		if (path.endsWith('.map')) problems.push('map published');
		if (bytes.includes(Buffer.from('PRIVATE-LAB-ONLY'))) problems.push('private marker');
		if (bytes.includes(Buffer.from('sourceMappingURL=data:'))) problems.push('inline map');
		if (bytes.includes(Buffer.from('PUBLIC-LAB-7'))) publicFound = true;
	}
	if (!publicFound) problems.push('missing public marker');
	return problems;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		if (!process.argv[2]) throw new Error('Specify release directory');
		const problems = await inspect(resolve(process.argv[2]));
		if (problems.length) { console.error(problems.join('\n')); process.exitCode = 1; }
		else console.log('PASS release policy');
	} catch (error) { console.error(error.message); process.exitCode = 1; }
}
```

### File: gate.test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from './gate.mjs';
test('gate accepts allowed output and detects synthetic regressions', async () => {
	const root = await mkdtemp(join(tmpdir(), 'hv-build-policy-'));
	try {
		assert.ok((await inspect(root)).includes('missing entry'));
		await writeFile(join(root, 'index.html'), '<!doctype html><title>Fixture</title>');
		await writeFile(join(root, 'main.js'), 'console.log("PUBLIC-LAB-7")');
		assert.deepEqual(await inspect(root), []);
		await writeFile(join(root, 'leak.txt'), 'PRIVATE-LAB-ONLY');
		assert.ok((await inspect(root)).includes('private marker'));
		await rm(join(root, 'leak.txt'));
		await writeFile(join(root, 'main.js.map'), '{}');
		assert.ok((await inspect(root)).includes('map published'));
		await rm(join(root, 'main.js.map'));
		await writeFile(join(root, 'inline.js'), '//# sourceMappingURL=data:application/json;base64,e30=');
		assert.ok((await inspect(root)).includes('inline map'));
		await rm(join(root, 'inline.js'));
		assert.deepEqual(await inspect(root), []);
	} finally { await rm(root, {recursive: true, force: true}); }
});
```

### File: server.test.mjs

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createServer } from 'vite';
function status(port, host) {
	return new Promise((resolve, reject) => {
		const operation = request({hostname: '127.0.0.1', port, path: '/',
			headers: {Host: host}}, response => { response.resume(); resolve(response.statusCode); });
		operation.on('error', reject); operation.end();
	});
}
test('loopback and HTTP host policy preserve approved requests', async () => {
	const server = await createServer({server: {port: 0, strictPort: false}});
	try {
		await server.listen();
		const address = server.httpServer.address();
		assert.equal(address.address, '127.0.0.1');
		assert.equal(await status(address.port, `localhost:${address.port}`), 200);
		assert.equal(await status(address.port, `unapproved.example.test:${address.port}`), 403);
	} finally { await server.close(); }
});
```

### Objectives and Commands

```powershell
npm install --save-dev --save-exact vite webpack@5 webpack-cli html-webpack-plugin
node --version
npm ls --depth=0
npm run test:gate
npm run build:vite
npm run build:webpack
npm run check:vite
npm run check:webpack
npm run test:server
```

The hostname test sends an HTTP header only to the loopback socket; it performs no external DNS lookup or connection. It tests denial, not circumvention. To exercise a real build regression, change only the synthetic public value in `.env` to PRIVATE-LAB-ONLY, rebuild both, and run both checks. Restore PUBLIC-LAB-7 and rebuild/recheck afterward.

### Hints

The private marker in a build process is harmless until included in the public graph/artifacts. The same bytes must fail regardless of which builder emitted them. A zero-file release is invalid. Hidden external maps still have a `.map` file; inline maps require a different check.

### Solution and Fixed Retest

Expected: gate unit test passes while internally detecting each known failure; both approved builds print PASS release policy; host test passes with loopback address, 200 approved host and 403 unapproved host. The changed public env fixture makes both release checks exit nonzero with private marker and missing public marker. Restoring the approved public value and rebuilding makes both pass again. The server-only synthetic env value remains present in `.env` but absent from release output.

### Verification, Troubleshooting, and Cleanup

Environment variables already set in the process may override `.env`; inspect only the synthetic lab variable when diagnosing unexpected output. A host test mismatch requires checking installed Vite behavior and whether HTTP versus HTTPS is used; do not relax allowedHosts to make it pass. The scanner is deliberately limited to byte canaries/map policy and does not unpack compressed assets or certify dependency safety. Tests close their own temporary listener/directories. Remove only the disposable project after recording versions/lockfile. No packages, builds, tests or servers were run during this revision.

- [ ] Local Bundlers exercise: Build a small app and inspect its production output for module chunks, source maps, and a deliberately public marker variable. Confirm a server-only dummy value is absent.
- [ ] Boundary check: Search the built files for a synthetic secret marker and verify the release check fails if it appears. Test dev-server binding and allowed-host behavior locally.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Supply Chain Attacks]]
- [[Bundlers]]

## References

- [Official documentation or primary training reference](https://vite.dev/guide/)
- [Vite server security options](https://vite.dev/config/server-options)
- [Vite env exposure](https://vite.dev/guide/env-and-mode)
- [webpack DefinePlugin](https://webpack.js.org/plugins/define-plugin/)
- [webpack map publication implications](https://webpack.js.org/configuration/devtool/)
- [webpack dev-server options](https://webpack.js.org/configuration/dev-server/)
