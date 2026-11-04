---
title: "npm Ecosystem Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[npm Ecosystem]]"
updated: 2026-11-03
---
# npm Ecosystem Security

> [!abstract] TL;DR
> Treat dependency selection, artifact verification, install execution, runtime use, and publishing as different trust decisions. Locking a graph prevents accidental drift; it does not approve the code in that graph.

> [!info] Agent scope
> Security of: Package manifests; lockfiles; dependency resolution; lifecycle scripts; registries; integrity and provenance; dependency maintenance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Names/scopes and registry routing select publishers; tarballs and lockfiles select bytes; lifecycle hooks execute with installer permissions; application imports execute later. Build jobs often have more credentials and network access than needed. This note uses only a local arithmetic package and a benign marker, never malicious publication or credential collection.

## Learn

```text
Teach npm supply-chain defense at expert depth for Node 22/npm 10. Assume I know
JavaScript and semver. Separate namespace/registry selection, lockfile review,
artifact integrity, publisher/build provenance, lifecycle execution, runtime
imports and dependency maintenance. Explain scoped registry routing, peer and
optional graph changes, Git/local dependencies, CI privilege minimization,
signature verification limits, advisory reachability and safe update decisions.
Use only a benign local package: demonstrate script suppression, an explicit
approved build, a trusted digest baseline, and in-memory policy rejection cases.
Provide complete files, commands, observable evidence, fixed retests, cleanup,
and primary sources. Discuss false positives and what each control cannot prove.
No malicious packages, publication, credential access, bypass or evasion examples.
Teach here; do not edit files or study status or claim unrun checks succeeded.
```

## Cheatsheet

### Controls by Boundary

| Boundary | Defensive check | What remains unproved |
|---|---|---|
| Name to publisher | Exact scoped names; approved registry per scope; review new maintainers | Namespace ownership does not imply code safety |
| Manifest to graph | Commit lock; `npm ci`; review additions, overrides and resolution flags | A reviewed direct dependency can introduce new transitive code |
| Graph to bytes | Integrity plus an independently approved artifact baseline | Digest equality cannot establish benign intent |
| Bytes to execution | `--ignore-scripts`, inspect hooks, explicit approved build in isolation | Runtime imports and explicit `npm run` still execute code |
| Publication to source | Registry signatures and provenance where available | Provenance identifies a build/source relationship, not freedom from bugs |
| Advisory to response | `npm audit --json`, assess affected path/version, update and retest | No advisory does not mean no vulnerability |

In npm 10, `npm ci --ignore-scripts` suppresses lifecycle hooks and refuses a manifest/lock mismatch. It also removes node_modules. It is not a permission boundary: use an unprivileged disposable build environment with only required network access and no production credentials. Script suppression can leave native modules or generated assets unusable; an installation that exits zero is not necessarily a working build.

### Concrete Review and Configuration

Read `scripts`, `bin`, `files`, `dependencies`, `optionalDependencies`, `peerDependencies`, `overrides`, and `engines`. Review `resolved` URLs and integrity changes in the lock, not just version numbers. A new Git dependency may have different packing/prepare behavior from a registry tarball. Inspect packed contents with `npm pack --dry-run --json`; do not execute unreviewed packages to learn what they do.

Project-local policy fragment, illustrative only:

```ini
registry=https://registry.npmjs.org/
@example:registry=https://packages.example.invalid/
ignore-scripts=true
save-exact=true
```

The private hostname is a placeholder, not a destination to contact. Do not edit global registry/proxy settings. Scope-specific routing should fail closed when unavailable, not fall back to an unintended public namespace. Keep TLS checks enabled. Auth configuration must be scoped to the intended host/path, not included in package archives or committed files.

Inspection commands for an authorized real project (network access may be required; not part of the offline lab):

```powershell
npm ls --all
npm explain package-name
npm audit --json
npm audit signatures
npm outdated
```

`npm audit signatures` support depends on npm and registry signing/provenance metadata. Missing provenance is not automatically evidence of compromise; invalid verification is not something to ignore. Independently verify expected source repository, workflow, commit and publisher policy. Keep acquisition and publishing credentials out of build steps that do not need them; use short-lived, narrowly scoped publishing authority where supported.

### Failure and Maintenance Decisions

| Observation | Appropriate next step |
|---|---|
| Integrity failure | Stop; compare expected artifact/lock and trusted registry metadata; do not merely regenerate lock |
| New install hook | Review exact hook and dependencies; approve in isolated build only if needed |
| Advisory in a dev tool | Assess build exposure as well as shipped runtime; dev does not mean harmless |
| Major upgrade proposed | Read migration/API changes; test separately instead of `audit fix --force` |
| Package no longer maintained | Evaluate replacement and ownership risk; pinning delays change but not risk |
| OS-specific missing optional binary | Reproduce on target platform; distinguish expected omission from broken deployment |

## Detection and Defense

Record package coordinates, resolved registry host, reviewed lock digest, installer version, verification result and approved script names. Alert on unexpected registry changes, script additions, provenance failures and unexplained lock rewrites. Avoid logging environment variables, registry auth values or whole process environments. Preserve a trusted baseline outside the change under review; comparing a changed artifact to its simultaneously changed digest proves nothing about approval.

## Labs

### Environment and Complete Files

Prerequisites: PowerShell, Node 22.x/npm 10.x; empty disposable `npm-policy-lab` with `fixture/` and `app/`. No external dependencies, network requests or real secrets. Create all files below.

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
require('node:fs').writeFileSync('install-marker.txt', 'approved lab hook\n');
```

### File: app/package.json

```json
{
	"name": "npm-policy-lab",
	"version": "1.0.0",
	"private": true,
	"dependencies": {"@vault-lab/math": "file:../fixture/vault-lab-math-1.0.0.tgz"}
}
```

### File: app/check.cjs

```javascript
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const artifact = fs.readFileSync('../fixture/vault-lab-math-1.0.0.tgz');
const approved = 'sha512-' + crypto.createHash('sha512').update(artifact).digest('base64');
const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
function verify(candidate) {
	const entry = candidate.packages['node_modules/@vault-lab/math'];
	assert.ok(entry, 'missing approved package');
	assert.equal(entry.version, '1.0.0');
	assert.equal(entry.resolved, 'file:../fixture/vault-lab-math-1.0.0.tgz');
	assert.equal(entry.integrity, approved, 'artifact differs from approved local fixture');
	const installed = JSON.parse(fs.readFileSync('node_modules/@vault-lab/math/package.json', 'utf8'));
	assert.deepEqual(installed.scripts, {postinstall: 'node marker.cjs'});
}
verify(lock);
const changedDigest = structuredClone(lock);
changedDigest.packages['node_modules/@vault-lab/math'].integrity = 'sha512-not-approved';
assert.throws(() => verify(changedDigest));
const changedSource = structuredClone(lock);
changedSource.packages['node_modules/@vault-lab/math'].resolved = 'https://example.invalid/package.tgz';
assert.throws(() => verify(changedSource));
assert.equal(require('@vault-lab/math').add(20, 22), 42);
console.log('PASS approved artifact, two policy denials, arithmetic');
```

This deliberately narrow checker approves the tarball you just reviewed and packed locally. It is not a general supply-chain verifier: production baselines must be protected independently, all dependencies traversed, and installed content verified or installed afresh from verified artifacts. Neither changing an in-memory lock nor computing a digest contacts a remote site.

### Objectives and Baseline

From lab root, review the three fixture files first, then:

```powershell
node --version
npm --version
Set-Location fixture
npm pack --ignore-scripts
Set-Location ../app
npm install --foreground-scripts --no-audit --no-fund
Get-Content node_modules/@vault-lab/math/install-marker.txt
node check.cjs
```

The baseline hook writes only its marker. Establish that installation is an execution boundary even though application functionality needs no hook. Next require the same artifact and arithmetic checks with lifecycle execution suppressed.

### Hints

`ci` removes the previous installation, including the marker. `--ignore-scripts` changes execution policy, not the package's declared metadata or tarball digest. The two negative cases are in-memory mutations only.

### Solution and Fixed Retest

```powershell
npm ci --ignore-scripts --no-audit --no-fund
Test-Path node_modules/@vault-lab/math/install-marker.txt
node check.cjs
```

Expected: marker false, checker prints `PASS approved artifact, two policy denials, arithmetic`. The same allowed arithmetic operation still returns 42. A consciously approved rebuild is observable and separately authorized:

```powershell
npm rebuild '@vault-lab/math' --foreground-scripts
Get-Content node_modules/@vault-lab/math/install-marker.txt
```

Expected marker: `approved lab hook`. Do this only for the printed fixture. The fix is explicit execution policy with review, not a claim that arbitrary scripts are safe after a single inspection.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must confirm actual npm lock format, all checker assertions, marker true/false/true transitions, and preserved application behavior. A policy failure needs investigation; do not weaken the assertion to obtain green output. Missing marker after rebuild: check project/user `ignore-scripts` configuration without changing global settings. If it is set, pass `--ignore-scripts=false` only for this reviewed rebuild. Remove only this disposable directory after leaving it. No publishing or global configuration is involved.

- [ ] Local npm Ecosystem exercise: Create a disposable project, install one small dependency, and compare npm install with npm ci after intentionally changing the manifest. Inspect its dependency tree and lifecycle scripts.
- [ ] Boundary check: Use a local toy package whose install script only writes a marker. Compare installation with and without scripts and confirm the expected marker behavior.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Supply Chain Attacks]]
- [[npm Ecosystem]]

## References

- [npm ci](https://docs.npmjs.com/cli/v10/commands/npm-ci)
- [npm scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [Registry signature verification](https://docs.npmjs.com/verifying-registry-signatures)
- [Provenance statements](https://docs.npmjs.com/generating-provenance-statements)
- [npm configuration](https://docs.npmjs.com/cli/v10/configuring-npm/npmrc)
