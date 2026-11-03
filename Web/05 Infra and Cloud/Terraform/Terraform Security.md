---
title: "Terraform Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Terraform]]"
updated: 2026-11-03
---
# Terraform Security

> [!abstract] TL;DR
> Leaked state, malicious providers/modules, broad apply credentials, and unreviewed destructive changes can compromise infrastructure.

> [!info] Agent scope
> Security of: Providers; resources; state; plans; modules; remote backends; sensitive values; execution identity; drift. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Providers, modules and provisioners are executable supply-chain inputs. Plans, state, crash logs, variable files and backend configuration can contain sensitive data.
- Separate source approval, plan execution, apply authorization and backend access. A plan job may already hold valuable read credentials.

## Learn

```text
Teach me defensive Terraform security at expert depth. Cover provider/module
trust, checksum and lockfile limits, plan-time code execution, backend access
and locking, sensitive state/plan data, short-lived plan/apply identities, drift,
approval freshness and destructive changes. Show a fail-closed offline JSON
plan gate including unknown values, replacements and nested modules; distinguish
the gate from provider verification and authorization. Explain exact supported
Terraform-version caveats for ephemeral/write-only values. Provide harmless
synthetic fixtures, positive/negative regressions, expected findings and cleanup.
Use HashiCorp sources. No real secrets, paid resources or untrusted code
execution. Teach in this conversation; do not edit files or study status.
```

## Cheatsheet

### Trust and Confidentiality

| Surface | Required control | Limitation |
|---|---|---|
| Provider | Approved source, reviewed constraints and lockfile hashes; isolated runner | Matching checksum proves artifact identity, not safety |
| Module | Reviewed exact registry version or Git commit; inspect transitive modules | Provider lockfile does not pin modules |
| Execution | Trusted source only when credentials are available; no routine provisioners | Even planning may run provider code and read sensitive APIs |
| State/backend | Separate ACLs, encryption, versioning, audit, locking, recovery | Locking prevents concurrent writers, not unauthorized readers |
| Approval | Bind binary plan hash to source commit, backend/workspace and identity | Approving console text does not bind the applied binary |
| Secrets | Avoid persistence where supported; otherwise tightly protect artifacts | `sensitive` is display metadata, not encryption or omission |

The unsafe pattern is placing a credential in an ordinary resource attribute and assuming a sensitive output removes it. A safer design references a secret identifier and grants runtime retrieval only where required. If Terraform must manage a secret value, treat state, plan JSON, backups and logs as secret-bearing. Newer Terraform ephemeral inputs/resources and provider write-only arguments reduce persistence for supported paths; verify exact feature/provider versions before relying on them.

Minimum Terraform feature versions: 1.10 for ephemeral variables, child-module outputs and ephemeral resources; 1.11 for write-only managed-resource arguments. Ephemeral resources and write-only arguments also need provider support, and ephemeral values can only flow into permitted contexts. An ephemeral input copied into an ordinary persistent resource attribute is not a supported universal secret-removal technique. Use current patched binaries within a reviewed version constraint; feature availability is not a security-patch guarantee.

A saved plan is an executable change proposal, not harmless reporting output. Do not post raw plan JSON to public pull requests. Avoid credentials in backend `-backend-config` arguments or checked-in files: backend configuration may be persisted in local working data and plans. Use supported ambient/short-lived credentials with restricted access.

### Plan Review Mechanics

Use `terraform show -json lab.tfplan` only in an authorized protected workspace. `resource_changes` lists addresses, modes/types and actions, including resources in modules. An address beginning `module.` must not be skipped. `change.after_unknown` distinguishes computed values from known false/null; validate required security fields as known and explicit. `after_sensitive` describes sensitivity, not absence of values.

Treat any `delete` action, including replacement `['delete','create']` or `['create','delete']`, as requiring separate approval. An allowlist of resource types alone is insufficient: fields such as public access, role scopes, ingress and secret handling need resource-specific rules. Unknown types or unsupported plan-format versions should cause review, not silently pass.

Example policy gate contract: a reviewed read-only artifact plan may create/update only the approved storage type, must explicitly disable public access, may not contain deletes, and must have no unknown public-access field. The lab implements only that small contract. It does not interpret Terraform expressions, resolve IAM, parse provider schemas or prove remote state.

## Detection and Defense

Audit backend reads as well as writes/deletes, unexpected state versions, lock manipulation, changes to provider/module sources and plan/apply identity scope. Correlate plan hash, approval record, source commit, execution identity and API change events. Alert on logging configuration changes and privilege changes outside the approved plan. A drift finding can be legitimate emergency work: investigate ownership before automatically overwriting it.

Do not grant all contributors plan credentials by default. Isolate untrusted contribution checks from credentialed plans; use a clean trusted runner for apply and verify the approved artifact again. Avoid general workspace artifacts containing state or `.terraform` directories.

## Labs

### Environment and Complete Files

Python 3.12 standard library only, an empty directory, no Terraform CLI or cloud access needed. The plan below is a synthetic subset of Terraform JSON shape. The storage fields model an AWS provider resource; this is **not provider validation or effective AWS authorization**. Start/test: `python -m unittest -v test_example`.

### File: test_example.py

```python
import copy
import json
import unittest

FIELDS = ("block_public_acls", "ignore_public_acls",
		  "block_public_policy", "restrict_public_buckets")
ADDRESS = "module.reports.aws_s3_bucket_public_access_block.lab"
BUCKET = "example-w5-reports"
BASELINE = {
	"format_version": "1.2",
	"resource_changes": [{
		"address": ADDRESS,
		"mode": "managed", "type": "aws_s3_bucket_public_access_block",
		"change": {"actions": ["update"],
				   "after": dict.fromkeys(FIELDS, False) | {"bucket": BUCKET},
				   "after_unknown": {}}}],
}


def gate(plan):
	if not isinstance(plan, dict):
		return {"malformed-plan"}
	if plan.get("format_version") != "1.2":
		return {"unsupported-format"}
	resources = plan.get("resource_changes")
	if not isinstance(resources, list) or len(resources) != 1:
		return {"unexpected-resource-set"}
	issues = set()
	for resource in resources:
		if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
			return {"malformed-resource"}
		if resource.get("address") != ADDRESS:
			issues.add("unapproved-address")
		change = resource["change"]
		if resource.get("mode") != "managed" or resource.get("type") != "aws_s3_bucket_public_access_block":
			issues.add(ADDRESS + ":unreviewed-type")
		if change.get("actions") not in (["no-op"], ["create"], ["update"]):
			issues.add(ADDRESS + ":unapproved-actions")
		after = change.get("after")
		unknown = change.get("after_unknown", {})
		if not isinstance(after, dict) or not isinstance(unknown, dict):
			issues.add(ADDRESS + ":malformed-values")
			continue
		if after.get("bucket") != BUCKET or unknown.get("bucket", False) is not False:
			issues.add(ADDRESS + ":unapproved-bucket")
		for field in FIELDS:
			if after.get(field) is not True or unknown.get(field, False) is not False:
				issues.add(ADDRESS + ":" + field)
	return issues


def fixed():
	plan = copy.deepcopy(BASELINE)
	plan["resource_changes"][0]["change"]["after"] = dict.fromkeys(FIELDS, True) | {"bucket": BUCKET}
	return plan


class PlanGateTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(len(gate(BASELINE)), 4)
		self.assertEqual(gate(fixed()), set())

	def test_unknown_not_safe(self):
		plan = fixed()
		plan["resource_changes"][0]["change"]["after_unknown"] = {FIELDS[0]: True}
		self.assertEqual(len(gate(plan)), 1)

	def test_replacement_requires_review(self):
		plan = fixed()
		plan["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
		self.assertTrue(any("unapproved-actions" in issue for issue in gate(plan)))

	def test_sensitive_is_not_removed(self):
		output = {"sensitive": True, "type": "string", "value": "DUMMY-ONLY"}
		self.assertIn("DUMMY-ONLY", json.dumps(output))

	def test_unsupported_format(self):
		self.assertEqual(gate({"format_version": "9.0"}), {"unsupported-format"})

	def test_target_binding(self):
		plan = fixed()
		plan["resource_changes"][0]["address"] = "module.other.aws_s3_bucket_public_access_block.lab"
		self.assertIn("unapproved-address", gate(plan))
		plan = fixed()
		plan["resource_changes"][0]["change"]["after"]["bucket"] = "other-bucket"
		self.assertIn(ADDRESS + ":unapproved-bucket", gate(plan))

	def test_missing_or_malformed_input(self):
		for plan in (None, {}, {"format_version": "1.2"},
					 {"format_version": "1.2", "resource_changes": [None]}):
			with self.subTest(plan=plan):
				self.assertTrue(gate(plan))
		plan = fixed()
		plan["resource_changes"][0]["change"]["after_unknown"] = True
		self.assertIn(ADDRESS + ":malformed-values", gate(plan))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Identify the four baseline public-access findings and note that the address is inside a module.
2. Run the seven tests. Apply `fixed()` and repeat the same gate; update remains permitted only for the approved address and bucket.
3. Mark a required field unknown and introduce replacement separately. Explain why neither should inherit the ordinary approval.
4. Inspect the dummy sensitive output serialization. Explain where real plans/state would need protected storage.

### Hints

Format version describes JSON compatibility, not the Terraform CLI version. The gate intentionally supports one fixture format, resource type and target; that restrictive contract is not a general-purpose compliance tool. Missing fields are not safe defaults. A legitimate empty/no-change plan is outside this exact one-resource exercise and requires a separately reviewed path, not implicit approval of malformed input.

### Solution and Fixed Retest

Set all four public-access-block values explicitly true; preserve the update action and exact target. Seven tests should pass. Baseline produces four findings, an unknown control produces one, replacement produces an action finding, and serialized dummy output retains its value. Wrong targets and malformed inputs are rejected rather than approved or interpreted as empty plans. This proves gate behavior, not resource deployment, cloud policy, backend ACLs or secret removal.

### Verification, Troubleshooting, and Cleanup

No package installation or server is needed. Use a fresh directory to prevent cross-note imports. Unexpected findings after fixture edits mean the exact allowlisted contract no longer matches; do not loosen it without a reviewed requirement. Restore the printed fixture to reset, delete the directory/`__pycache__` to clean up. Static review only; no tests or backend access checks ran during authoring.

### User-Owned Milestones

These retained broader goals require separate authorized backend/provider evidence.

- [ ] Local Terraform exercise: Use a disposable local or budgeted cloud resource, inspect a plan, apply it, introduce harmless drift, and plan again. Verify state access and destroy only the lab resource.
- [ ] Boundary check: Place a dummy secret in a lab resource and inspect where it appears in state versus console output. Verify an unauthorized identity cannot read the backend.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Terraform]]

## References

- [Sensitive state](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
- [Manage sensitive data](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- [JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- [Dependency lock file](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- [Backend configuration](https://developer.hashicorp.com/terraform/language/backend)
