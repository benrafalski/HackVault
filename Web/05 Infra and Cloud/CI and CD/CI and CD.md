---
title: "CI/CD with GitHub Actions"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[CI and CD Security]]"
updated: 2026-11-03
---
# CI/CD with GitHub Actions

> [!abstract] TL;DR
> Pin third-party actions to reviewed commits when practical; constrain events and permissions; separate build from deployment; bind OIDC trust to intended repository/ref/environment.

> [!info] Agent scope
> Workflows; events; jobs; runners; artifacts; token permissions; untrusted pull requests; OIDC federation; dependency pinning.

## Prerequisites

- Git revisions, exit codes, artifact hashing and workload identity; [[Web Lab Setup]].
- Required offline lab: Python 3.12 standard library in a fresh directory. Optional workflow illustration requires a GitHub repository and Actions entitlement; it is not required or executed here.

## Learn

```text
Teach me CI/CD with GitHub Actions at expert depth. Assume Git, exit codes and
hashing. Trace workflow events, refs, job DAGs, runner isolation, step outputs,
artifacts, caches, environments and approval into an immutable release. Contrast
pull_request, push, workflow_dispatch, pull_request_target and workflow_run
trust. Explain explicit GITHUB_TOKEN permissions, per-job OIDC issuance and
cloud issuer/audience/subject policy, reusable workflows and SHA pinning.
Show concrete YAML and a zero-service deterministic package/verification lab.
Cover cancellation, concurrency, retries, reproducibility versus repeatability,
provenance and compromised-dependency limits. Cite primary GitHub documentation
and identify hosted-runner/action-version caveats. No privileged untrusted code,
real secrets or deployment required. Teach here without editing files or status.
```

## Cheatsheet

### Execution and Trust Model

A workflow selects events; jobs form a DAG through `needs`; steps within a job share runner filesystem and process environment but run as separate commands. Job outputs are strings and can contain untrusted data. Separate jobs generally need artifacts for files, not a path printed by the previous runner. Hosted runners are usually fresh per job; a persistent self-hosted runner needs explicit isolation, cleanup and trust-tier separation.

| Event | Review question |
|---|---|
| `pull_request` | Which merge/head revision is checked? What fork-token restrictions apply? |
| `push` | Is the branch protected and is the workflow change reviewed? |
| `workflow_dispatch` | Which ref was selected? Does deployment require protected environment approval? |
| `pull_request_target` | Base-repository context; keep untrusted contribution code out of privileged execution |
| `workflow_run` | A later privileged workflow can receive outputs from an earlier untrusted run; verify source/event/revision/artifact |

Specify `permissions` explicitly. When particular permissions are listed, unspecified permissions become `none`; repository/organization policies can further constrain them. `contents: read` is enough for many source-checking jobs. `id-token: write` allows requesting an OIDC token, not arbitrary cloud writes: cloud trust and role permissions still decide authority. Give it only to the job that needs federation.

### Release Contract

1. Review source revision and dependency lockfiles.
2. Build/test in an identity without deployment authority.
3. Package once; record artifact digest, source revision, builder identity and dependency inventory.
4. Verify provenance and exact artifact identity in a separate trusted promotion stage.
5. Apply environment approval and constrained deployment identity, then deploy the **same bytes**.
6. Observe rollout and retain a tested rollback path; database/data changes need separate compatibility planning.

Caches accelerate rebuilds; they are not approved release artifacts. Scope cache keys to relevant lockfiles/platform and trust tier, and validate restored content. Artifacts need retention/access policy and verification of source workflow/run/revision. An attestation binds claims to an artifact only if its signature and expected issuer/builder/source are verified. An SBOM is inventory, not vulnerability clearance.

### Complete Control-Flow Illustration

This workflow uses no third-party actions and checks out no repository code, so it needs no invented action pins. It hashes a synthetic string, not a deployable app. It can illustrate permissions and job gating but **does not deploy or transfer an artifact**. For optional use, place it at `.github/workflows/w5.yml` in a disposable repository. Create environment `lab-review`, configure required reviewers where the repository plan supports them, and restrict deployment branches to `main`; merely naming an environment does not enforce approval.

```yaml
name: W5 control flow
on:
  pull_request:
  workflow_dispatch:
permissions: {}
concurrency:
  group: w5-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false
jobs:
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: {}
    outputs:
      digest: ${{ steps.package.outputs.digest }}
    steps:
      - id: package
        shell: bash
        run: |
          python3 - <<'PY'
          import hashlib, os
          digest = hashlib.sha256(b"W5 synthetic artifact\n").hexdigest()
          with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
              output.write("digest=" + digest + "\n")
          PY
  review:
    needs: verify
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    environment: lab-review
    permissions: {}
    steps:
      - name: Record synthetic review
        env:
          DIGEST: ${{ needs.verify.outputs.digest }}
        run: printf 'Synthetic artifact digest %s\n' "$DIGEST"
```

The runner label is a real image family, not a fixed dependency snapshot. GitHub updates its contents. Record image/tool versions for reproducibility. Real workflows using actions should pin verified full commit SHAs; resolve and review them from primary repositories rather than substituting made-up hashes. Reusable workflows also need review and ref pinning; caller permissions cannot be escalated casually by a called workflow.

### Failure and Version Caveats

Job success can be weakened by `continue-on-error`, conditional skips or incorrect exit-code handling. Require the intended checks, not just a similarly named status. Concurrency cancellation is useful for superseded tests but can interrupt deployments; choose deployment serialization and recovery deliberately. A retry of a deploy step can repeat side effects; use idempotent release operations and inspect partial state.

OIDC default subjects vary by branch, pull request or environment. An environment-bound subject typically names the environment rather than the branch; enforce branch policy in environment protection as well. Custom subject templates alter the trust contract. No OIDC token is created by the offline lab.

## Gotchas

- Masking is output redaction, not isolation or permission control.
- Build-again-on-deploy breaks the relationship between tested and released bytes.
- Repository visibility/plan and organization policy affect environment protection and runner features; verify availability before treating a YAML name as a control.

## Labs

### Environment and Complete Files

Python 3.12, standard library only. Put this single file in a fresh directory and run `python -m unittest -v test_example`. The archive is built entirely in memory from embedded synthetic source; no GitHub account, action runner, network or disk artifact is needed.

### File: test_example.py

```python
import hashlib
import io
import json
import unittest
import zipfile

SOURCE = {"app.txt": b"synthetic release\n", "version.txt": b"1\n"}


def build(files):
		buffer = io.BytesIO()
		with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
				for name, content in sorted(files.items()):
						info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
						info.create_system = 3
						info.external_attr = 0o100644 << 16
						archive.writestr(info, content)
		return buffer.getvalue()


def manifest(artifact, revision):
		return {"sha256": hashlib.sha256(artifact).hexdigest(),
						"revision": revision, "builder": "synthetic-reviewed-builder"}


def verify(artifact, record, approved_revision):
		return (record.get("revision") == approved_revision
						and record.get("builder") == "synthetic-reviewed-builder"
						and record.get("sha256") == hashlib.sha256(artifact).hexdigest())


class ReleaseTests(unittest.TestCase):
		def test_deterministic_package(self):
				self.assertEqual(build(SOURCE), build(dict(reversed(list(SOURCE.items())))))

		def test_approved_bytes_and_revision(self):
				artifact = build(SOURCE)
				record = json.loads(json.dumps(manifest(artifact, "reviewed-revision")))
				self.assertTrue(verify(artifact, record, "reviewed-revision"))
				self.assertFalse(verify(artifact, record, "different-revision"))

		def test_changed_bytes_require_new_approval(self):
				artifact = build(SOURCE)
				record = manifest(artifact, "reviewed-revision")
				changed = build(dict(SOURCE, **{"app.txt": b"different release\n"}))
				self.assertFalse(verify(changed, record, "reviewed-revision"))

		def test_inventory(self):
				with zipfile.ZipFile(io.BytesIO(build(SOURCE))) as archive:
						self.assertEqual(archive.namelist(), ["app.txt", "version.txt"])


if __name__ == "__main__":
		unittest.main()
```

### Objectives and Steps

1. Run four tests. Explain why sorting filenames, fixing timestamps and modes, and avoiding compressor variability help deterministic packaging.
2. Change one source byte and compare against the original approval record; require rejection.
3. Explain why a changed revision is rejected even when bytes match.
4. Identify the missing real-world trust in this local unsigned manifest: who approves it and who can replace it?

### Hints

Hashing solves byte identity. It does not authenticate the manifest author. This lab assumes the approval record is trusted input; real promotion needs protected storage or verified signatures/attestations and an explicit issuer policy.

### Solution and Expected Results

Four tests should pass. Reordering source mapping entries yields identical bytes; changing content fails digest verification; mismatched source revision fails approval. Archive contents are exactly two synthetic files. The YAML illustrates event/job gating separately; neither local tests nor the YAML claim actual deployment, secret isolation or cryptographic provenance verification.

### Verification, Troubleshooting, and Cleanup

No packages or services are needed. Run from the file's directory. ZIP metadata choices are deliberate; changing them changes the digest. Delete file and `__pycache__` to reset. For optional workflow practice disable/delete only that disposable workflow afterward; no cloud cleanup is involved. Static author review only; neither tests nor Actions runs were executed.

### User-Owned Milestones

Original platform-verification goals remain separate and unchecked.

- [ ] Local CI and CD exercise: Create a toy build workflow with read-only permissions and a separate manually approved deployment job. Verify forked/untrusted changes cannot access a synthetic protected value.
- [ ] Boundary check: Review a synthetic pull request path and verify no privileged job executes its code with secrets. Confirm unexpected OIDC subjects fail the sandbox trust policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Supply Chain Attacks]]
- [[CI and CD Security]]

## References

- [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Workflow syntax](https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions)
- [OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
