---
title: "npm Ecosystem"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[npm Ecosystem Security]]"
updated: 2026-11-03
---
# npm Ecosystem

> [!abstract] TL;DR
> npm turns manifest constraints into an installed graph. A lockfile records a resolution; `npm ci` reproduces it subject to platform and configuration. Integrity hashes and clean audits do not establish trust.

> [!info] Agent scope
> Package manifests; lockfiles; dependency resolution; lifecycle scripts; registries; integrity and provenance; dependency maintenance.

## Prerequisites

- Node.js 22.x and npm 10.x; record `node --version` and `npm --version`. Other npm majors can change lockfile and lifecycle behavior.
- JSON, CommonJS, semantic versioning, and a disposable directory outside an existing application. The lab needs no registry dependencies or credentials.

## Learn

```text
Teach me the npm ecosystem at expert engineering depth, assuming JavaScript,
JSON, shell basics, and semantic versioning. Use Node 22/npm 10 as a stated
baseline and distinguish later CLI behavior. Trace manifest constraints through
registry metadata, resolution, tarballs, integrity checks, lifecycle scripts,
node_modules placement, and Node runtime module lookup. Explain peers, optional
dependencies, workspaces, overrides, platform conditions, lockfile v3, and the
differences between install, ci, update, dedupe, and audit. Work through exact
semver examples, inconsistent manifests, omitted dev tools, local tarballs,
script suppression, scoped registries, provenance verification, and maintenance.
Supply complete benign offline fixtures, commands, expected outputs and negative
checks. Explain why a lockfile is not a security proof. Use primary sources.
Do not invent test results, request secrets, edit files, or change study status.
End with difficult questions and worked answers.
```

## Cheatsheet

### Manifest, Resolution, and Runtime

`package.json` describes acceptable dependencies and entry points; `package-lock.json` records the selected graph. Registry metadata maps names/versions to artifacts. npm fetches and verifies artifacts, builds the on-disk graph, and may run scripts. Node then resolves imports from that graph: npm resolution and Node module resolution are different operations.

| Declaration | Meaning and boundary |
|---|---|
| `dependencies` | Runtime requirements; included when dev dependencies are omitted |
| `devDependencies` | Build/test tools; `npm ci --omit=dev` omits installation, not resolution in the lock |
| `peerDependencies` | Host compatibility contract; npm 7+ normally installs peers and can reject conflicts |
| `peerDependenciesMeta.optional` | Optional peer does not require automatic installation |
| `optionalDependencies` | Install failure can be tolerated; code must handle absence |
| `overrides` | Root manifest controls transitive choices; not proof of API compatibility |
| `workspaces` | Locally linked packages with a root-managed graph; review their scripts too |
| `engines` | Compatibility metadata; commonly warnings unless enforcement is configured |
| `type`, `main`, `exports` | Runtime interpretation/public entry points; an exports map can prohibit deep imports |

Semver: `^1.2.3` allows `<2.0.0`; `^0.2.3` allows `<0.3.0`; `~1.2.3` allows `<1.3.0`; `1.2.3` is exact. Prerelease inclusion has separate semver rules. A dist-tag such as `latest` is a mutable label, not a version comparison.

Modern npm commonly writes lockfile version 3. Its `packages` entries record locations such as `node_modules/name`, with `version`, `resolved`, `integrity`, and dependency metadata where applicable. Local directory links need not have registry-style integrity fields. The hidden `node_modules/.package-lock.json` is an optimization, not the committed source of truth.

### Command Decisions

| Goal | Command | Consequence |
|---|---|---|
| Intentionally resolve/change graph | `npm install` | Can change manifest and lock |
| Reproduce reviewed graph | `npm ci --ignore-scripts` | Requires matching manifest/lock; removes node_modules; does not repair lock |
| Explain a dependency | `npm explain package-name` | Shows direct and transitive paths |
| Inspect graph | `npm ls --all` | Reports invalid, missing, extraneous packages; nonzero exit matters |
| Compare releases | `npm outdated` | `wanted` follows constraints; `latest` follows a tag |
| Refresh within constraints | `npm update` | Review lock diff and test compatibility |
| Reduce compatible duplicates | `npm dedupe` | Can change placement; do not rely on incidental hoisting |
| Review known advisories | `npm audit --json` | Not malicious-code detection or reachability analysis |

Use the same project-local resolution options that created the lock (`legacy-peer-deps`, `install-links`, etc.) for `ci`. Do not use `--force` to conceal a peer conflict without understanding the host/plugin contract. OS, CPU, native toolchains, optional packages, environment and scripts still affect reproducibility.

### Scripts, Registries, and Provenance

An explicit `npm run build` invokes the root build command. Install lifecycle hooks can run during install/ci; `prepare` also matters for packing and Git dependencies. `--ignore-scripts` suppresses lifecycle execution but is not a sandbox. Explicit `npm run name` still runs that script (its pre/post hooks are suppressed under ignore-scripts). Inspect before enabling builds; `--foreground-scripts` exposes installation diagnostics.

Project-local configuration fragment with an intentionally nonexistent private registry placeholder:

```ini
registry=https://registry.npmjs.org/
@example:registry=https://packages.example.invalid/
save-exact=true
```

Do not paste this into an existing project or global configuration. Scope routing binds an organization namespace to its intended registry; it does not authenticate authors. Scope authentication to the intended registry host/path and supply it outside source control. Keep TLS verification enabled. This lab requires no VPN, proxy or machine-wide configuration changes.

Integrity binds artifact bytes to a digest. A changed lockfile can select changed bytes with a valid new digest. Registry signatures and provenance can add publication/build attribution (`npm audit signatures` where supported); they do not prove source quality or suitability.

### Maintenance

Review direct/transitive changes, scripts, registries, licenses, native build requirements and API differences. Update narrowly, rebuild in a low-privilege environment, test application behavior, and give exceptions an owner/expiry. `npm audit fix --force` may choose semver-major updates. Record toolchain versions and project `.npmrc` alongside the lock to explain resolution differences.

## Gotchas

- `ci` deletes the installed tree. Work in a disposable folder.
- Development dependencies can execute code during builds too.
- Consumers receive the tarball, not the author's working tree. Inspect `npm pack --dry-run --json` and packed contents.

## Labs

### Environment and Complete Files

Use PowerShell, Node 22.x/npm 10.x and an empty disposable `npm-graph-lab` folder. Create `fixture/` and `app/` beneath it. No network is needed; funding/audit requests are disabled. All files follow.

### File: fixture/package.json

```json
{
	"name": "@vault-lab/math",
	"version": "1.0.0",
	"main": "index.cjs",
	"files": ["index.cjs", "marker.cjs"],
	"scripts": {"postinstall": "node marker.cjs"}
}
```

### File: fixture/index.cjs

```javascript
exports.add = (left, right) => left + right;
```

### File: fixture/marker.cjs

```javascript
require('node:fs').writeFileSync('install-marker.txt', 'benign lab build\n');
```

### File: app/package.json

```json
{
	"name": "npm-graph-lab",
	"version": "1.0.0",
	"private": true,
	"scripts": {"test": "node test.cjs"},
	"dependencies": {"@vault-lab/math": "file:../fixture/vault-lab-math-1.0.0.tgz"}
}
```

### File: app/test.cjs

```javascript
const assert = require('node:assert/strict');
const {add} = require('@vault-lab/math');
assert.equal(add(2, 3), 5);
assert.equal(add(-1, 1), 0);
console.log('PASS arithmetic');
```

### Objectives and Steps

From the lab root:

```powershell
node --version
npm --version
Set-Location fixture
npm pack --ignore-scripts
Set-Location ../app
npm install --ignore-scripts --no-audit --no-fund
npm test
npm ls --all
npm explain '@vault-lab/math'
Test-Path node_modules/@vault-lab/math/install-marker.txt
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

1. Inspect the generated lock entry for `node_modules/@vault-lab/math`: version, local tarball location and integrity. Packing should report `vault-lab-math-1.0.0.tgz`.
2. Change only the app dependency key to `@vault-lab/other` with the same tarball value. Run `npm ci --ignore-scripts --no-audit --no-fund`; require nonzero exit because the requested package location is absent from the lock. Restore the original key without modifying the lock.
3. Run the approved fixture lifecycle and observe its marker:

```powershell
npm ci --foreground-scripts --no-audit --no-fund
Get-Content node_modules/@vault-lab/math/install-marker.txt
npm test
npm ci --ignore-scripts --no-audit --no-fund
Test-Path node_modules/@vault-lab/math/install-marker.txt
```

### Hints

The marker is relative to the installed package's lifecycle working directory. Editing source files does not modify an existing tarball. `ci` deletes the installed tree, explaining the marker's disappearance on the last install.

### Solution and Expected Results

Tests print `PASS arithmetic` before and after script execution. Initial `Test-Path` is false, approved lifecycle writes `benign lab build`, and final `Test-Path` is false again. The deliberate manifest mismatch must fail without repairing the lock. This fixture works without its hook; real native/generated dependencies may not.

### Verification, Troubleshooting, and Cleanup

Inspect `$LASTEXITCODE` immediately after each npm command; only the deliberate mismatch should fail. Missing tarball: check packing directory/name/version. Persistent lock mismatch: restore the manifest exactly. Do not repair offline errors by changing machine-wide network settings.

Unexecuted during authoring. Parent checks: run this sequence, record versions, confirm lock consistency and all marker transitions. Cleanup: leave and delete only the disposable lab directory. No global installation/configuration was required.

- [ ] Local npm Ecosystem exercise: Create a disposable project, install one small dependency, and compare npm install with npm ci after intentionally changing the manifest. Inspect its dependency tree and lifecycle scripts.
- [ ] Boundary check: Use a local toy package whose install script only writes a marker. Compare installation with and without scripts and confirm the expected marker behavior.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Supply Chain Attacks]]
- [[npm Ecosystem Security]]

## References

- [npm ci](https://docs.npmjs.com/cli/v10/commands/npm-ci)
- [Manifest reference](https://docs.npmjs.com/cli/v10/configuring-npm/package-json)
- [Lockfile reference](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json)
- [Lifecycle scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [Provenance](https://docs.npmjs.com/generating-provenance-statements)
