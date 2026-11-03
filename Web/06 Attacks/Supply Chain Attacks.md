---
title: "Supply Chain Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Supply Chain Attacks

> [!abstract] TL;DR
> Supply-chain compromise inserts untrusted behavior through dependencies, build tools, maintainers, registries, or release artifacts that downstream systems treat as trusted.

> [!info] Agent scope
> Dependency and build trust; registry identity; lifecycle scripts; CI artifacts; provenance; pinning and review.

## Learn

```text
Teach software supply-chain failures from source/dependency selection through
build and artifact promotion. Assume package managers, registries, lockfiles, CI,
hashes, signatures, and deployment identities. Explain registry/package identity,
namespace confusion and misspellings conceptually, compromised maintainers,
lifecycle scripts, build plugins, runner trust, artifact substitution, and update
review without creating malicious packages or workflows. Distinguish integrity,
publisher identity, provenance, reproducibility, vulnerability scans, and benign
behavior. Review a local artifact hash gate plus dependency/permission records;
state that provenance signatures require a real trusted verifier. Cite npm,
GitHub, SLSA, and Sigstore documentation and give questions/answers. No installs,
CI execution, credentials, persistence, evasion, theft, bypasses, or chains in the
exercise. Teach, do not edit files or invent test results.
```

## Cheatsheet

> [!important] Defensive scope
> This lab reviews synthetic dependency and build records and hashes a harmless local artifact. It installs no packages, runs no lifecycle scripts or CI, and never handles deployment credentials.

### Trust Graph

Build-time dependencies, plugins, compiler tools, actions, and test fixtures can execute before runtime protections apply. A trusted package name is not necessarily a trusted publisher, registry, version, or artifact. A compromised input needs a consuming execution/promotion path; merely appearing in a manifest does not prove execution or deployment.

| Control/evidence | Answers | Does not answer |
|---|---|---|
| Lockfile/version pin | Which resolved dependency version is expected? | Is its content benign or source trustworthy? |
| Integrity digest | Do bytes match a trusted expected digest? | Who approved the expected digest? |
| Signature | Did a key/identity sign the statement? | Is that identity authorized for this release? |
| Provenance | Which builder/source/inputs are asserted for this artifact? | Was source safe or the builder uncompromised? |
| Reproducible build | Can reviewed inputs reproduce bytes? | Are all inputs and build semantics trustworthy? |
| Vulnerability scan | Are known issues recognized in this inventory? | Is a new malicious behavior absent? |
| SBOM | Which components are reported present? | Is the inventory complete or the release approved? |

Review registry namespaces and package spelling against the intended project identity. Scope private packages to an explicit registry and avoid fallback assumptions. Inspect lockfile origin/integrity changes, transitive additions, scripts, native builds, and workflow changes, not only top-level versions. Pinning improves repeatability but can preserve an old vulnerable dependency indefinitely without an update process.

### Build and Promotion Boundaries

Untrusted pull-request code should not receive deployment secrets or write-capable tokens. Separate build from deployment, use ephemeral isolated runners where appropriate, minimize token permissions, and treat caches/artifacts from untrusted jobs as untrusted. A build artifact should be promoted by digest without rebuilding from mutable inputs after approval.

For GitHub Actions, pin third-party actions to reviewed immutable commit IDs; tags are mutable. Review event semantics, especially workflows that run with privileged context while handling untrusted contributions. OIDC federation avoids long-lived credentials but its trust policy must constrain repository, workflow/ref/environment, issuer, and audience appropriately. An OIDC token is not safe merely because it is short-lived.

For npm, `npm ci` uses a lockfile and fails on certain manifest mismatches, but can still execute lifecycle scripts by default. `ignore-scripts` is a useful control with compatibility tradeoffs; explicitly running scripts is a separate action. A package that requires native build steps may need a reviewed isolated build stage rather than globally relaxing restrictions. No such commands are executed in this lab.

### Provenance and Version Details

SLSA v1.x separates source/build concerns and defines provenance predicates; exact version and builder requirements matter. Verify a signature/attestation using the ecosystem's maintained verifier, then check subject digest, builder identity, source repository/ref, and policy. Do not trust an artifact's self-declared `verified` field. Sigstore identity and transparency evidence still require an expected identity/issuer policy.

The Python 3.12 fixture below verifies bytes against a separately trusted release record. It does not verify signatures, transparency proofs, or SLSA conformance. Its synthetic review data is explicit so a digest comparison is not mislabeled as provenance verification. Primary references are rolling documents; inspect the installed npm/CI/verifier versions when applying them.

## Defense

Maintain a reviewed dependency inventory and update cadence, restrict registries and build privileges, and protect release approval. Bind promotion to immutable artifact bytes and verified provenance under an expected policy. Quarantine unexpected artifacts; retain audit evidence and a rollback plan. Keep builds without deployment authority and deploy only approved outputs.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, temporary harmless artifact, no packages/network/CI. Review a proposed promotion gate that trusts an artifact filename and any successful build. The replacement compares bytes with a trusted reviewer-owned digest and checks synthetic build/dependency metadata. The metadata is not read from the artifact itself.

### File: test_example.py

```python
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


REVIEWED_BYTES = b"Synthetic release notes version 1\n"
TRUSTED_DIGEST = hashlib.sha256(REVIEWED_BYTES).hexdigest()
TRUSTED_DEPENDENCIES = {
	"@training/parser": {"version": "1.2.3", "registry": "https://registry.example"}
}


def review_metadata(dependencies, build):
	if dependencies != TRUSTED_DEPENDENCIES:
		raise PermissionError("dependency identity/version review required")
	if build != {"source": "reviewed-revision-1", "builder": "isolated-builder-1",
				 "deployment_credentials": False, "lifecycle_scripts": False,
				 "approved": True}:
		raise PermissionError("build review required")


def approve_artifact(path, dependencies, build):
	review_metadata(dependencies, build)
	with Path(path).open("rb") as artifact:
		content = artifact.read(4097)
	if len(content) > 4096:
		raise ValueError("artifact size")
	observed = hashlib.sha256(content).hexdigest()
	if observed != TRUSTED_DIGEST:
		raise PermissionError("artifact digest mismatch")
	return {"sha256": observed, "decision": "approved-for-fixture-only"}


class ReleaseGateTests(unittest.TestCase):
	def setUp(self):
		self.build = {"source": "reviewed-revision-1", "builder": "isolated-builder-1",
					  "deployment_credentials": False, "lifecycle_scripts": False,
					  "approved": True}

	def test_reviewed_bytes(self):
		with TemporaryDirectory() as directory:
			path = Path(directory) / "artifact.txt"
			path.write_bytes(REVIEWED_BYTES)
			result = approve_artifact(path, TRUSTED_DEPENDENCIES, self.build)
			self.assertEqual(result["sha256"], TRUSTED_DIGEST)

	def test_changed_bytes_fail(self):
		with TemporaryDirectory() as directory:
			path = Path(directory) / "artifact.txt"
			path.write_bytes(b"Different synthetic release\n")
			with self.assertRaises(PermissionError):
				approve_artifact(path, TRUSTED_DEPENDENCIES, self.build)

	def test_identity_and_privilege_review(self):
		changed = {"@training/parser": {"version": "1.2.3", "registry": "https://other.example"}}
		with self.assertRaises(PermissionError):
			review_metadata(changed, self.build)
		for field in ["deployment_credentials", "lifecycle_scripts"]:
			with self.subTest(field=field), self.assertRaises(PermissionError):
				review_metadata(TRUSTED_DEPENDENCIES, self.build | {field: True})
		with self.assertRaises(PermissionError):
			review_metadata(TRUSTED_DEPENDENCIES, self.build | {"approved": False})


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: who owns `TRUSTED_DIGEST` and the metadata? What would be lost if the artifact supplied its own expected digest and approval record?

Solution: a separate trusted record identifies reviewed bytes and build conditions; the artifact is never executed. Expected: three tests pass, changed bytes and unapproved registry/privilege states fail, and the approved result contains the exact digest. This is a local release-review contract, not cryptographic attestation verification. In production, metadata must come from an authenticated verifier/control plane, and promotion must consume the exact verified object to avoid a later replacement race.

### Verification, Troubleshooting, and Cleanup

No tests or installs ran during authoring. Run beside the file; all data is inline. An expected hash changes when bytes/newlines change, so do not edit a digest to silence a mismatch without review. Temporary files clean up automatically; remove the disposable exercise directory. Actual package provenance, CI token permissions, registry routing, and deployment promotion remain integration checks.

- [ ] Local Supply Chain Attacks exercise: Review dependency, builder, and artifact trust records.
- [ ] Boundary check: Run safe digest and approval-gate regressions without installing anything.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [SLSA specifications](https://slsa.dev/spec/)
- [npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci)
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [GitHub artifact attestation verification](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-the-provenance-of-an-artifact)
- [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/)
