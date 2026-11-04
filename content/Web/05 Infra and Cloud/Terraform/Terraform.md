---
title: "Terraform"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Terraform Security]]"
updated: 2026-11-03
---
# Terraform

> [!abstract] TL;DR
> Review plan changes, pin providers/modules, protect state, and use scoped short-lived credentials. Never assume sensitive annotations remove values from state.

> [!info] Agent scope
> Providers; resources; state; plans; modules; remote backends; sensitive values; execution identity; drift.

## Prerequisites

- JSON, dependency graphs, cloud resource identity; [[Web Lab Setup]].
- Offline tests: Python 3.12 standard library. Optional real local lifecycle: an already installed Terraform CLI >=1.4 and <2.0, using its built-in `terraform_data` resource, no downloaded provider or cloud credentials.

## Learn

```text
Teach me Terraform at expert engineering depth. Assume JSON, dependency graphs
and basic infrastructure APIs. Trace configuration -> initialization -> refresh
-> graph/plan -> apply -> state. Explain provider schemas, unknown values,
resource addresses, count/for_each identity, modules, dependencies, replacement,
imports/moved blocks, drift and refresh-only operations. Contrast state with
backup, plan with approval, and sensitive with secret-free. Show local-backend
and protected remote-backend designs, locking/versioning and short-lived
execution identity. Give a complete provider-free terraform_data example and
offline plan fixtures, explicitly stating what they cannot verify. Cover
provider lockfiles versus module versioning, plan JSON risks, failures and
version caveats. Use HashiCorp primary sources. No paid resources, actual
secrets or destructive commands against shared state. Teach here; no file edits.
```

## Cheatsheet

### State Machine and Graph

Terraform loads configuration and provider schemas, reads existing objects through providers, computes desired changes and executes a dependency graph. Resource references create implicit edges; `depends_on` is for real dependencies not expressed in attributes, not a way to serialize the whole world. Excess edges can propagate unknown values and reduce parallelism.

State maps Terraform addresses to remote identifiers and recorded attributes. It is not the authoritative cloud API and not a backup of data inside a database. Refresh reconciles observations; it does not by itself make remote resources match configuration. An ordinary plan normally refreshes first; `-refresh=false` can hide drift and should not be a routine approval shortcut.

| Construct | Operational meaning / failure case |
|---|---|
| `count` | Index-based identity; deleting an early list element can change several instances |
| `for_each` | Stable map/set keys; choose durable nonsecret keys |
| Module | Namespaced configuration composition, not a security sandbox |
| `moved` block | Declares an address refactor without intentional recreation where supported |
| Import | Associates existing object with an address; still need matching configuration |
| Replacement | Often delete/create or create/delete; capacity, naming and data loss must be reviewed |
| `prevent_destroy` | Lifecycle guard while the declaration is present; removing configuration is not a permanent resource lock |
| Unknown value | Not yet computable; must not be interpreted as false, empty or safe |

`terraform plan -detailed-exitcode` returns 0 for no changes, 2 for changes, 1 for an error. CI must handle 2 intentionally. Applying a saved plan applies that planned change set, but external systems and intent can change after approval. Keep the approved binary plan immutable and short-lived, replan when stale, and record configuration commit, lockfile, workspace, backend, identity and tool version.

### Providers, Modules, and Credentials

`required_providers` sets source and version constraints; `.terraform.lock.hcl` records selected provider versions and checksums. Commit/review the lockfile. `terraform init -lockfile=readonly` can enforce existing provider selection in CI; deliberate upgrades use a reviewed update workflow. A checksum proves bytes match a recorded artifact, not that the provider is benign. Providers and provisioners execute code during infrastructure workflows; review their origin and permissions.

Registry module `version` constraints and Git commit refs are separate from provider locking. Terraform's dependency lockfile does not lock remote module versions. Prefer exact reviewed module versions/commits and record source provenance; do not fabricate digest or commit pins.

Planning often needs real read credentials and may contact APIs. "Plan only" does not make an untrusted repository safe to execute. The plan identity should lack writes where the provider supports that split; the apply identity gets only approved resource scope and temporary credentials. Some APIs expose sensitive information through reads, so read-only is still privileged.

### Backends and Sensitive Values

Local backend is appropriate only for this disposable exercise. Real team state needs authenticated access, encryption in transit/at rest, audit, versioning, retention, recovery and backend-supported locking. A lock coordinates writers; it does not grant authorization or roll back partial API operations. Never force-unlock another active operation merely because a pipeline timed out.

S3 backend supports native lockfiles in sufficiently recent Terraform releases; legacy DynamoDB locking is deprecated in current documentation. Check the CLI version before choosing backend settings. Azure Blob backends use lease-based locking. Backend authentication is distinct from provider authentication; access to a resource does not imply access to its state backend.

Version boundaries: `terraform_data` requires Terraform 1.4+, ephemeral variables/child-module outputs and ephemeral resources require 1.10+, and resource write-only arguments require 1.11+ plus supporting provider schemas. Native S3 `use_lockfile` support starts in 1.10. These are minimum feature versions, not recommendations to use unpatched binaries.

Real remote-backend reference, **not part of the offline/local lab**; the bucket must already exist with encryption, blocked public access, versioning and approved access/logging policies:

```hcl
terraform {
	required_version = ">= 1.10.0, < 2.0.0"
	backend "s3" {
		bucket       = "example-w5-state"
		key          = "reports/lab.tfstate"
		region       = "us-east-1"
		encrypt      = true
		use_lockfile = true
	}
}
```

Use the backend's supported credential provider chain or federation, not embedded keys. The state object needs read/write permissions; native locking additionally needs appropriate `GetObject`, `PutObject`, `DeleteObject` access on the `.tflock` object. State deletion is not ordinarily required just to update state. Listing and KMS permissions depend on the exact backend design. `encrypt=true` neither creates the bucket nor configures all key/access controls. Backend configuration cannot use normal input variables; initialization and state migration are separate privileged operations.

`sensitive=true` redacts normal display; state and machine-readable plan output can still contain the value. Newer ephemeral values/resources and provider-supported write-only arguments can avoid some persistence, but support is version/provider/attribute-specific. They are not a blanket retrofit for all secrets. Do not publish `terraform show -json` output or state as ordinary build artifacts.

## Gotchas

- Removing a resource block can plan destruction; changing a resource address without a move can look like delete/create.
- `-target` is a recovery/debugging tool, not a complete routine deployment strategy.
- A local `terraform_data` object has no external cloud API to drift. Changing its input demonstrates configuration reconciliation, not provider-observed drift.

## Labs

### Environment and Complete Files

Use a new empty directory containing both files below. The Python path needs only Python 3.12. The optional Terraform path uses CLI >=1.4 and <2.0, with no external providers, provisioners or network resources. No install is part of the exercise. All values are synthetic.

### File: main.tf

```hcl
terraform {
	required_version = ">= 1.4.0, < 2.0.0"
}

variable "revision" {
	type    = string
	default = "blue"
}

resource "terraform_data" "release" {
	input = {
		revision = var.revision
		marker   = "DUMMY-NOT-A-SECRET"
	}
	triggers_replace = [var.revision]
}

output "release_marker" {
	value     = terraform_data.release.output.marker
	sensitive = true
}
```

### File: test_example.py

```python
import unittest


def actions(plan):
		return {entry["address"]: tuple(entry["change"]["actions"])
						for entry in plan.get("resource_changes", [])}


CREATE = {"resource_changes": [{"address": "terraform_data.release",
					"change": {"actions": ["create"], "before": None,
										 "after": {"input": {"revision": "blue"}}}}]}
REPLACE = {"resource_changes": [{"address": "terraform_data.release",
					 "change": {"actions": ["delete", "create"],
											"before": {"input": {"revision": "blue"}},
											"after": {"input": {"revision": "green"}}}}]}
DRIFT = {"resource_drift": [{"address": "example_service.lab",
				 "change": {"actions": ["update"], "before": {"size": 1},
										"after": {"size": 2}}}],
				 "resource_changes": [{"address": "example_service.lab",
				 "change": {"actions": ["update"], "before": {"size": 2},
										"after": {"size": 1}}}]}


class PlanReadingTests(unittest.TestCase):
		def test_create(self):
				self.assertEqual(actions(CREATE), {"terraform_data.release": ("create",)})

		def test_replacement_is_not_plain_update(self):
				self.assertIn("delete", actions(REPLACE)["terraform_data.release"])

		def test_drift_observation_differs_from_correction(self):
				observed = DRIFT["resource_drift"][0]["change"]
				planned = DRIFT["resource_changes"][0]["change"]
				self.assertEqual(observed["after"], planned["before"])
				self.assertEqual(observed["before"], planned["after"])


if __name__ == "__main__":
		unittest.main()
```

### Objectives and Steps

Run the zero-dependency fixture exercise with `python -m unittest -v test_example`. Predict create, replacement and drift-correction results. The `example_service` name is synthetic: no such provider is installed or claimed.

For the complete optional real local lifecycle, run these commands **only in this new lab directory**:

```text
terraform version
terraform init -backend=false
terraform validate
terraform plan -out=lab.tfplan
terraform apply lab.tfplan
terraform plan -detailed-exitcode
terraform plan -var=revision=green -out=green.tfplan
terraform show green.tfplan
terraform apply green.tfplan
terraform output -raw release_marker
terraform state show terraform_data.release
```

`-backend=false` skips backend initialization; the default local state still exists. Do not add a remote backend or cloud provider. No service is started and no public port is opened.

### Hints

`triggers_replace` deliberately turns revision changes into replacement. Output redaction and state storage are different layers. The drift fixture shows remote size changing from 1 to 2, followed by a planned correction to 1.

### Solution and Expected Results

Three Python tests should pass. Initial Terraform plan creates one local `terraform_data` instance; after apply, the unchanged plan should return 0. Changing revision to green should replace it. The raw output command reveals only `DUMMY-NOT-A-SECRET`, despite `sensitive=true`; local state contains the marker too. This is intentional evidence using a dummy value, not a secret-retrieval exercise.

No live drift or remote backend authorization is tested. For those requirements the fixture teaches how to read evidence, while actual provider/backend checks remain separate.

### Verification, Troubleshooting, and Cleanup

Unknown resource `terraform_data` indicates CLI older than 1.4. A registry download attempt indicates extra configuration not in this exercise: stop and inspect the directory. Exit 2 from detailed planning means changes, not failure. Run `terraform destroy -var=revision=green` in the lab directory and approve only the single local resource, then delete the directory including `.terraform`, state backups and saved plans. Python-only cleanup is deletion of the file/directory and `__pycache__`. Author review is static; no listed command was executed.

### User-Owned Milestones

Retained broader milestones are not marked complete by fixture tests.

- [ ] Local Terraform exercise: Use a disposable local or budgeted cloud resource, inspect a plan, apply it, introduce harmless drift, and plan again. Verify state access and destroy only the lab resource.
- [ ] Boundary check: Place a dummy secret in a lab resource and inspect where it appears in state versus console output. Verify an unauthorized identity cannot read the backend.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Terraform Security]]

## References

- [Terraform state and sensitive data](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
- [JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- [terraform_data resource](https://developer.hashicorp.com/terraform/language/resources/terraform-data)
- [Dependency lock file](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- [S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
- [Ephemeral and write-only version requirements](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
