---
title: "CI/CD with GitHub Actions Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[CI and CD]]"
updated: 2026-11-03
---
# CI/CD with GitHub Actions Security

> [!abstract] TL;DR
> Executing untrusted code in a privileged event, script interpolation, cache poisoning, or broad tokens can compromise releases and repositories.

> [!info] Agent scope
> Security of: Workflows; events; jobs; runners; artifacts; token permissions; untrusted pull requests; OIDC federation; dependency pinning. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Workflow definitions, event/ref selection, runner state, dependency actions, job tokens, OIDC federation, artifacts, caches and release approvals.
- Source contributors, workflow administrators, artifact approvers and deployers need explicit separation. Do not execute untrusted contribution code on credentialed or persistent privileged runners.

## Learn

```text
Teach me defensive GitHub Actions security at expert depth. Analyze events,
refs, runner trust, explicit job permissions, protected environments, OIDC
issuer/audience/subject and workflow identity, action/module pins, caches and
artifact provenance. Show safe data-to-script handling and separation of
untrusted checks from credentialed promotion. Use offline synthetic job/claim
fixtures to expose overbroad design and demonstrate a fixed regression matrix;
do not implement JWT verification or claim complete provider IAM semantics.
Explain controls, operational tradeoffs, detection and false positives with
public GitHub/provider sources and version caveats. No exploitation, secrets,
evasion or live deployment. Teach here, without editing files or study status.
```

## Cheatsheet

### Events, Runners, and Permission Boundaries

| Design smell | Defensive replacement |
|---|---|
| Privileged job executes contribution code | Unprivileged test job; reviewed trusted promotion source only |
| `permissions: write-all` | Explicit job-level minimum; no token permission when unused |
| Shared persistent runner across trust tiers | Ephemeral isolated runners or separate pools and credentials |
| Deployment consumes artifact by friendly name alone | Verify source repository/workflow/run/revision and immutable digest |
| Cache restored across unrelated trust tiers | Scope caches; validate contents; never equate cache with release approval |
| OIDC trust matches a broad repository family | Exact issuer, supported audience and intended subject/environment constraints |
| Environment name assumed to mean approval | Configure reviewers/branch policy explicitly and verify availability |

Fork restrictions and repository defaults vary; write intended permissions even when current defaults are restrictive. `pull_request_target` is a base-context automation feature, not a safe place to execute untrusted head code with privileges. `workflow_run` can also cross trust tiers; a successful earlier run is not proof its artifact is trusted. Keep the defensive review at configuration/data level, not by executing unsafe candidate workflows.

### Treat Event Fields as Data

Safe step fragment for displaying an issue title, assuming the workflow already has an appropriate event policy:

```yaml
- name: Process title as data
  env:
    TITLE: ${{ github.event.issue.title }}
  shell: bash
  run: |
    python3 - <<'PY'
    import os
    title = os.environ.get("TITLE", "")
    print("title length:", len(title))
    PY
```

Expressions are evaluated before shell execution; putting event text directly into script source merges data with code. Passing through an environment variable and using a language API keeps it data. This does not make the value appropriate for every downstream sink: still validate filenames, URLs and command arguments, avoid shells where possible, and never print sensitive body content.

### OIDC Is a Two-Sided Contract

The job requests a short-lived token with `id-token: write`. The provider verifies signature/issuer/audience/time and applies its trust policy. Then the resulting role/identity has its own permissions. OIDC removes a stored cloud secret but does not reduce a broad cloud role by itself.

AWS trust-condition fragment for a synthetic repository's protected `lab` environment; a complete trust policy also needs the correct federated principal and `sts:AssumeRoleWithWebIdentity` action:

```json
{
  "StringEquals": {
	"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
	"token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:environment:lab"
  }
}
```

Environment subjects do not automatically encode a branch. Protect the environment's allowed branches and approval separately. GitHub custom subject templates can change this string. AWS supports particular GitHub OIDC condition keys; do not assume every JWT claim is available as an IAM condition. Azure federated credentials likewise bind issuer, subject and audience; their audience value differs from AWS. Use the actual provider's supported schema.

Full-length action commit SHAs improve immutability but require a real reviewed commit. A pin does not certify the action's dependencies or behavior. Review transitive actions, downloaded tools, reusable workflows, dependency lockfiles and provenance. Never invent a SHA to make an example look secure; examples here use no third-party actions.

## Detection and Defense

Audit workflow edits, runner registration, token permission increases, environment-policy changes, federation trust changes and unusual deployment approvals. Correlate deployment digest with source/workflow/run identity and provider session logs. Masking is not a data-loss control: prefer no secret in untrusted jobs at all. An expected release changes artifacts; alert on unauthorized builder/source changes, not merely every new digest.

Maintain a revoke/rollback procedure for workflow credentials, federation relationships and released packages. Changing an action pin cannot recall already deployed artifacts; retain deployment inventory and approved rollback versions.

## Labs

### Environment and Complete Files

Python 3.12 standard library, one empty directory, no GitHub account, JWT library, credentials or provider. Start/test: `python -m unittest -v test_example`. Claims below are **preverified synthetic dictionaries**. The checker only validates this lab's exact promotion contract; it does not verify tokens or implement AWS/Azure policy evaluation.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"event": "pull_request", "trusted_source": False,
	"permissions": {"contents": "write", "id-token": "write"},
	"environment": "lab", "approved": False, "ref": "refs/heads/main",
}
CLAIMS = {"iss": "https://token.actions.githubusercontent.com",
		  "aud": "sts.amazonaws.com",
		  "sub": "repo:example-org/example-repo:environment:lab"}


def review_job(job):
	issues = set()
	if job.get("event") != "workflow_dispatch" or job.get("ref") != "refs/heads/main":
		issues.add("event-ref")
	if job.get("trusted_source") is not True:
		issues.add("unreviewed-source")
	if job.get("permissions") != {"contents": "read", "id-token": "write"}:
		issues.add("permissions")
	if job.get("environment") != "lab" or job.get("approved") is not True:
		issues.add("environment-approval")
	return issues


def claims_match(verified_claims):
	return all(verified_claims.get(name) == value for name, value in CLAIMS.items())


def fixed_job():
	job = copy.deepcopy(BASELINE)
	job.update(event="workflow_dispatch", trusted_source=True, approved=True)
	job["permissions"]["contents"] = "read"
	return job


class PromotionTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(review_job(BASELINE), {
			"event-ref", "unreviewed-source", "permissions", "environment-approval"})
		self.assertEqual(review_job(fixed_job()), set())

	def test_legitimate_promotion_contract(self):
		self.assertTrue(not review_job(fixed_job()) and claims_match(CLAIMS))

	def test_unexpected_identity_claims(self):
		for field in CLAIMS:
			with self.subTest(field=field):
				self.assertFalse(claims_match(dict(CLAIMS, **{field: "other"})))

	def test_missing_approval_and_wrong_branch(self):
		job = fixed_job()
		job.update(approved=False, ref="refs/heads/feature")
		self.assertEqual(review_job(job), {"environment-approval", "event-ref"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Identify four baseline review failures without running a workflow or requesting any token.
2. Run the tests; compare the fixed job using the identical review function.
3. Change issuer, audience and subject individually and require rejection. Keep the intended identity accepted.
4. Explain why an `approved=True` fixture is not evidence that GitHub environment protection is configured, and why checking dictionaries is not JWT verification.

### Hints

Job gating and provider trust are separate required checks. Matching an environment subject does not prove a protected branch. The local fixture encodes both requirements explicitly to make that gap visible.

### Solution and Fixed Retest

The fixed job uses trusted source, an explicitly allowed event/ref, minimal listed permissions and approval. Four tests should pass; legitimate promotion intent remains accepted while incorrect claims and missing approvals fail. Real adoption needs provider-supported trust configuration, verified tokens, environment settings, artifact verification and audit evidence; none is silently supplied by this lab.

### Verification, Troubleshooting, and Cleanup

Run from the single file's directory; no YAML parser or package install is needed. Restore fixtures after experiments, then delete file and `__pycache__`. Only static author review was performed; no Actions run, token issuance, provider role assumption or test execution occurred.

### User-Owned Milestones

Retained platform checks remain separate optional work and uncompleted.

- [ ] Local CI and CD exercise: Create a toy build workflow with read-only permissions and a separate manually approved deployment job. Verify forked/untrusted changes cannot access a synthetic protected value.
- [ ] Boundary check: Review a synthetic pull request path and verify no privileged job executes its code with secrets. Confirm unexpected OIDC subjects fail the sandbox trust policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Supply Chain Attacks]]
- [[CI and CD]]

## References

- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [OIDC with AWS](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [OIDC with Azure](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- [Deployment environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment)
