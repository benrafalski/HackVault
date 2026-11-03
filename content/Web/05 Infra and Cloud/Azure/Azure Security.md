---
title: "Azure Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Azure]]"
updated: 2026-11-03
---
# Azure Security

> [!abstract] TL;DR
> Overbroad role assignments, exposed storage, leaked application credentials, and unprotected workload metadata can expose cloud resources.

> [!info] Agent scope
> Security of: Tenants and subscriptions; RBAC; managed identities; networking; compute and storage; metadata; logging; sandbox costs. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Entra principals, federated credentials, role assignments, shared managed identities, storage authorization modes, public endpoints, workload metadata, deployment packages and audit destinations.
- Separate application data access from identity administration, deployment and logging administration. A network restriction is not a permission reduction.

## Learn

```text
Teach me defensive Azure workload hardening, assuming Entra, RBAC and VNet
basics. Trace principal/assignment/scope boundaries, Actions versus DataActions,
account-key alternatives, managed identity lifecycle and federation issuer,
subject and audience constraints. Review Blob public access, Shared Key, TLS,
private endpoints/DNS, Key Vault RBAC, metadata dependencies, diagnostic logs,
deployment supply chains and sandbox costs. Show concrete configuration diffs
and harmless offline negative/positive tests. Explain why fixture checks are
not Azure RBAC evaluation, why NotActions is not global deny, and how inherited
roles and propagation affect evidence. Include rollout tradeoffs and detection
false positives. Use public Microsoft sources. No exploitation, credentials,
paid resources or public listeners. Teach here without editing files or status.
```

## Cheatsheet

### Control Boundaries

| Review target | Baseline risk | Fixed design / compatibility check |
|---|---|---|
| Runtime role | Subscription Contributor for a single blob reader | Container-scoped data reader; remove key-listing and configuration write authority |
| Managed identity | One identity shared by unrelated apps | Per-workload identity; user-assigned reuse only within an explicitly shared trust boundary |
| Federation | Broad repository/environment trust | Exact supported issuer/subject/audience match; review who can edit credentials and workflow |
| Storage | Public endpoint and legacy authorization retained accidentally | Explicit network policy, anonymous-access disablement, Entra-based data access where supported |
| Key Vault | Secret user also changes access policy | Separate administration; use Azure RBAC model with scoped roles and review inherited assignments |
| Metadata | Workload can expose platform metadata through diagnostics | Do not proxy metadata; limit local consumers and identity permissions; use platform-specific isolation |
| Release | Unverified package deployed by broad identity | Verify artifact digest/provenance; approve immutable artifact; separate build and deploy authority |

### Concrete Storage Configuration

Storage-account `properties` fragment for an ARM/Bicep design review, not a complete template or a deploy command:

Schema reference: `Microsoft.Storage/storageAccounts@2023-05-01`. The API version selects the resource-provider contract, not the storage data-plane protocol, Azure CLI release or subscription feature availability. Retain the application's supported TLS/client matrix when upgrading that contract.

```json
{
  "allowBlobPublicAccess": false,
  "allowSharedKeyAccess": false,
  "supportsHttpsTrafficOnly": true,
  "minimumTlsVersion": "TLS1_2",
  "publicNetworkAccess": "Disabled",
  "networkAcls": {"defaultAction": "Deny", "bypass": "None"}
}
```

These settings are intentionally explicit. `allowBlobPublicAccess=false` prevents anonymous blob access but does not itself block authenticated public-endpoint traffic. `publicNetworkAccess=Disabled` requires an approved private connectivity path for clients. `allowSharedKeyAccess=false` has service/client compatibility consequences; validate Azure Files and existing SAS workflows rather than assuming all storage protocols use identical authorization. User-delegation SAS uses Entra delegation, not an account key. A private endpoint without correct private DNS or with public access still enabled is incomplete hardening.

Storage operations generally require both reachability and a supported authorization method. A data-reader role does not compensate for absent DNS routing. Conversely a successful private connection does not authorize a blob read. Test these separately so permission rollouts are not used to "fix" networking failures.

For Key Vault, the resource property `enableRbacAuthorization: true` selects the RBAC permission model. Do not flip models without inventorying current access policies and mapping equivalent roles: a model switch can interrupt applications. Limit secret readers to required vaults/objects as supported; log access metadata, never secret values. Soft delete/purge protection protect recovery, not confidentiality.

### Identity and Metadata Review

Prefer managed identity or workload federation over client secrets. Record principal object ID, tenant, intended token audience, role definitions and every inherited assignment. User-assigned identity deletion and reassignment need lifecycle ownership. Permission removal may not be immediate because of service/token caching; plan bounded rollout/retest windows.

Azure IMDS is not AWS IMDSv2. Azure VM metadata request headers, App Service identity endpoints and AKS federation have distinct contracts; do not apply AWS token/hop-limit settings to Azure. Assess application outbound destinations and local identity access defensively without requesting tokens or credentials as evidence.

## Detection and Defense

Audit role-assignment writes/deletes, federated-credential changes, public-network enablement, Shared Key changes and diagnostic-setting deletion. Entra audit/sign-in logs, Activity Log and resource logs have different coverage and retention. A successful ARM deployment is not proof of data-read logging. Include a synthetic permitted operation in an authorized live acceptance plan and verify the corresponding data-plane event.

An expected deployment can legitimately change role assignments; correlate approval, principal, scope and artifact rather than suppressing all deployer events. Track unrecognized identity reuse and broadening of scope. Alert on logging delivery gaps as well as policy changes. Scope budgets/quotas and teardown ownership; budget alerts are not hard caps.

## Labs

### Environment and Complete Files

Python 3.12, standard library, one empty directory; no Azure SDK, account, CLI, credentials, deployment or network. Start/check with `python -m unittest -v test_example`. The fixture is a desired storage/identity configuration, **not a parsed ARM deployment and not an Azure authorization simulator**.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"storage": {"allowBlobPublicAccess": True, "allowSharedKeyAccess": True,
				"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
				"publicNetworkAccess": "Enabled"},
	"identity": {"role": "Storage Blob Data Reader", "scope": "subscription"},
	"private_dns_reviewed": False,
	"blob_read_logs": False,
}


def review(config):
	expected = {"allowBlobPublicAccess": False, "allowSharedKeyAccess": False,
				"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
				"publicNetworkAccess": "Disabled"}
	findings = {name for name, value in expected.items()
				if config.get("storage", {}).get(name) != value}
	if config.get("identity") != {"role": "Storage Blob Data Reader",
								  "scope": "reports-container"}:
		findings.add("identity-scope")
	for requirement in ("private_dns_reviewed", "blob_read_logs"):
		if config.get(requirement) is not True:
			findings.add(requirement)
	return findings


def fixed():
	config = copy.deepcopy(BASELINE)
	config["storage"].update(allowBlobPublicAccess=False,
							 allowSharedKeyAccess=False,
							 publicNetworkAccess="Disabled")
	config["identity"]["scope"] = "reports-container"
	config["private_dns_reviewed"] = True
	config["blob_read_logs"] = True
	return config


class AzureHardeningTests(unittest.TestCase):
	def test_baseline(self):
		self.assertEqual(review(BASELINE), {
			"allowBlobPublicAccess", "allowSharedKeyAccess", "publicNetworkAccess",
			"identity-scope", "private_dns_reviewed", "blob_read_logs"})

	def test_fix_retains_read_intent(self):
		config = fixed()
		self.assertEqual(review(config), set())
		self.assertEqual(config["identity"]["role"], "Storage Blob Data Reader")

	def test_private_endpoint_is_not_enough(self):
		config = fixed()
		config["private_dns_reviewed"] = False
		self.assertEqual(review(config), {"private_dns_reviewed"})

	def test_missing_setting_rejected(self):
		config = fixed()
		del config["storage"]["allowSharedKeyAccess"]
		self.assertEqual(review(config), {"allowSharedKeyAccess"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Predict the six baseline findings, then run all four tests.
2. Explain which controls address anonymous access, credential mechanisms, network exposure and permission scope.
3. Apply the supplied `fixed()` changes and repeat the identical `review()` function. Confirm the read-role intent survives.
4. Remove the DNS review or a setting and repeat the negative regression. Describe the live evidence still needed for each boolean fixture.

### Hints

An empty finding set means the design matches this exact contract. It does not mean the resources exist, a private endpoint is approved, DNS works or logs arrive. Do not relabel fixture booleans as measured evidence.

### Solution and Fixed Retest

The worked solution disables anonymous/Shared Key/public endpoint access, narrows the role scope, and requires DNS and data-log review. Four tests should pass, including the baseline-failure and missing-control cases. Permitted read intent remains. Real provider testing would need an authorized identity, actual role assignments, private connectivity and a synthetic blob; none is silently required here.

### Verification, Troubleshooting, and Cleanup

Use a separate directory from other notes' `test_example` files. No install or startup service is needed. Restore fixtures for reset and delete the directory plus `__pycache__` for cleanup. Only static author review was performed; tests, Azure permissions and deployed behavior remain unverified.

### User-Owned Milestones

The original sandbox goals below remain optional, uncompleted live follow-up.

- [ ] Local Azure exercise: Use a dedicated sandbox subscription to give a managed identity access to one synthetic resource. Test a denied second resource, inspect activity logs, and tear down all lab resources.
- [ ] Boundary check: Attempt an unapproved data-plane action with the lab identity and require denial. Verify that a management role does not accidentally imply the data access your design intended to withhold.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Azure]]

## References

- [Storage Shared Key authorization prevention](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)
- [Storage account 2023-05-01 schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/2023-05-01/storageaccounts)
- [Prevent anonymous blob access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
- [Storage private endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints)
- [Key Vault RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [Managed identity best practices](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
