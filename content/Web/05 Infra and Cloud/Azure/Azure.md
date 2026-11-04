---
title: "Azure"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Azure Security]]"
updated: 2026-11-03
---
# Azure

> [!abstract] TL;DR
> Prefer managed identities, minimal scoped roles, private access where appropriate, and monitored budgets. Distinguish tenant administration from subscription/resource administration.

> [!info] Agent scope
> Tenants and subscriptions; RBAC; managed identities; networking; compute and storage; metadata; logging; sandbox costs.

## Prerequisites

- JSON, HTTP, identity tokens, CIDR routing; [[Web Lab Setup]].
- Lab: Python 3.12 standard library on Windows, Linux or macOS; one empty directory. No Azure account, CLI, SDK, credentials or network access required.

## Learn

```text
Teach me Azure infrastructure at expert depth, assuming HTTP, JSON, tokens and
IP networking. Distinguish Entra tenants, subscriptions, management groups,
resource groups, management-plane Actions and data-plane DataActions. Trace
managed identity token acquisition conceptually, audience selection and RBAC
scope inheritance. Compare system/user-assigned identity lifetimes, VM/App
Service/Functions/AKS identity boundaries, Blob Storage/Key Vault authorization,
VNet routes, NSGs, private endpoints and DNS. Explain Activity Log versus
resource logs, identity propagation delays, metadata dependencies, and costs.
Give real role/config examples plus offline fixtures; explicitly distinguish
them from full Azure authorization and live deployment. Cover NotActions,
additive assignments, deny assignments and account-key caveats. Use public
Microsoft sources and version caveats. No paid resources or real credentials.
Teach here, do not edit files. Finish with worked design-review questions.
```

## Cheatsheet

### Resource and Identity Hierarchy

An Entra tenant is an identity directory. A subscription is associated with a tenant and provides a resource/billing boundary; it is not itself a user directory. Management groups organize subscriptions. Resource groups hold resources with a shared management lifecycle, but resources in different groups can communicate. Deleting a group is destructive, not a harmless organizational operation.

An Azure RBAC assignment is `(principal, role definition, scope)` with optional conditions. Scope inheritance runs from management group to subscription to resource group to resource. Entra directory roles govern directory administration; Azure resource roles govern resources. Neither name similarity nor tenant membership grants data access by itself.

| Role component | Semantics |
|---|---|
| `Actions` / `NotActions` | Management operations included/excluded by that role |
| `DataActions` / `NotDataActions` | Service data operations included/excluded by that role |
| `AssignableScopes` | Where a role definition may be assigned, not an actual grant |
| Assignment scope | The resource subtree receiving the grant |
| Deny assignment | Separate control with supported creation/management constraints |

`NotActions` is subtraction within a role, **not an explicit deny across all assignments**. Another role may grant that operation. Role assignments are generally additive, subject to denies, conditions and service-specific checks. Some management permissions can list storage keys and thereby enable data access through another authorization mechanism. Do not equate "no DataActions" with "cannot read data" without reviewing those paths.

### Concrete Role Definition

Custom-role JSON example for review, not an executed deployment. The synthetic subscription ID must not be used for a real deployment. Assign the role at the intended container resource scope, not at subscription scope merely because the definition permits it.

```json
{
  "Name": "W5 Report Blob Reader",
  "IsCustom": true,
  "Description": "Read blob content without account key or write operations",
  "Actions": [],
  "NotActions": [],
  "DataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/00000000-0000-0000-0000-000000000001"]
}
```

A real role definition and assignment have resource IDs and principal object IDs; a client/application ID is not interchangeable with a principal object ID. Prefer reviewed built-in roles when their permissions fit, for example Storage Blob Data Reader at a container scope. Portal navigation can require additional management read permissions even when an SDK's data read is allowed.

### Workload Identity and Service Choice

System-assigned managed identity follows one resource's lifecycle. User-assigned managed identity is independent and can attach to multiple resources; reuse simplifies operations but couples privilege and revocation. A token audience identifies the intended API: an ARM token is not a Blob Storage token. An SDK's credential chain may select developer credentials locally and managed identity in Azure; explicitly constrain the production choice and log only the credential type, never token contents.

For SDK token requests, the Storage scope is typically `https://storage.azure.com/.default`; ARM uses `https://management.azure.com/.default`. These are token-request scopes, not Blob container RBAC scopes. Native managed-identity endpoint contracts may instead take a `resource` parameter without `/.default`; let the supported SDK translate rather than interchange protocol parameters. Honor the returned expiry and supported refresh behavior, not a hard-coded assumed token lifetime. Managed identity and authorization caches can delay role/group changes; token refresh alone need not make a permission change immediate.

VM identities use platform metadata interfaces; App Service has its own managed-identity endpoint contract; AKS workload identity uses federation rather than treating every pod as the node. Do not copy one platform's endpoint variables into another. Metadata access is local workload authority and must not be exposed through an application diagnostic endpoint.

| Service | Choice / failure boundary |
|---|---|
| VM | OS patching, disks and instance identity remain application-owner concerns |
| App Service | Managed hosting; deployment slots/configuration and identity need explicit review |
| Functions | Plan/runtime affect scaling, timeouts and networking; idempotency remains application logic |
| Blob Storage | Object semantics; container/blob permissions; versions/retention separate from RBAC |
| Key Vault | Secrets/keys/certificates with data-plane roles; management access is a separate concern |

### Network, Logging, and Costs

NSGs filter network flows with priority-ordered rules and stateful behavior. Routes decide the next hop; an NSG allow cannot create a missing route. A private endpoint gives a service interface a private address. Service DNS must resolve to that address from intended clients. Creating a private endpoint does **not** necessarily disable the service's public endpoint: explicitly configure public access and test both DNS and firewall intent. Service endpoints are different: they extend VNet identity/routing to supported public service endpoints, not private NIC addresses.

Activity Log covers subscription control-plane events. Blob reads and Key Vault secret access need the service's resource logs and diagnostic settings to an approved destination. Logs can incur ingestion/retention charges; select categories deliberately. Correlate operation, resource ID, caller identity, result, request ID and timestamp, without storing secret values.

Budget alerts are not hard caps. For optional live work use a dedicated subscription, approved region/SKU, bounded quotas, owner/expiry tags, explicit resource inventory and cleanup of storage, retained backups, monitoring and private endpoints. The required lab has no provider calls and zero cloud cost.

## Gotchas

- RBAC changes and managed-identity group membership may take time to propagate and be affected by token/service caching; do not conclude correctness from a single immediate result.
- SAS/account-key authorization has distinct semantics from Entra RBAC. Prefer user-delegation SAS when delegation is needed, with bounded scope and lifetime.
- API versions vary by resource type; SDK and hosting-plan capabilities must be checked for a real deployment. Examples here make no current subscription or runtime claims.

## Labs

### Environment and Complete Files

Place this one file in a fresh directory. Start/test: `python -m unittest -v test_example`. The dataset is a synthetic role definition and assignment. This is a **design contract**, not an Azure policy engine: it requires one exact approved principal, role shape and scope.

### File: test_example.py

```python
import copy
import unittest

SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000001"
CONTAINER = (SUBSCRIPTION + "/resourceGroups/w5/providers/Microsoft.Storage/"
			 "storageAccounts/examplew5/blobServices/default/containers/reports")
READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
ROLE = {
	"Actions": [], "NotActions": [], "DataActions": [READ],
	"NotDataActions": [], "AssignableScopes": [SUBSCRIPTION],
}
ASSIGNMENT = {"principalId": "synthetic-report-worker", "scope": CONTAINER}


def review(role, assignment):
	issues = set()
	if role.get("Actions") != [] or role.get("NotActions") != []:
		issues.add("unexpected-management-authority")
	if role.get("DataActions") != [READ] or role.get("NotDataActions") != []:
		issues.add("unexpected-data-authority")
	if role.get("AssignableScopes") != [SUBSCRIPTION]:
		issues.add("unexpected-definition-scope")
	if assignment.get("scope") != CONTAINER:
		issues.add("assignment-too-broad-or-wrong")
	if assignment.get("principalId") != "synthetic-report-worker":
		issues.add("wrong-principal")
	return issues


class RoleDesignTests(unittest.TestCase):
	def test_scoped_read_design(self):
		self.assertEqual(review(ROLE, ASSIGNMENT), set())

	def test_definition_scope_is_not_assignment_scope(self):
		assignment = dict(ASSIGNMENT, scope=SUBSCRIPTION)
		self.assertEqual(review(ROLE, assignment), {"assignment-too-broad-or-wrong"})

	def test_management_authority_is_separate(self):
		role = copy.deepcopy(ROLE)
		role["Actions"] = ["Microsoft.Storage/storageAccounts/listKeys/action"]
		self.assertIn("unexpected-management-authority", review(role, ASSIGNMENT))

	def test_data_write_is_not_read(self):
		role = copy.deepcopy(ROLE)
		role["DataActions"].append(READ.removesuffix("read") + "write")
		self.assertIn("unexpected-data-authority", review(role, ASSIGNMENT))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run the four tests. Explain why subscription-wide `AssignableScopes` does not force a subscription-wide grant.
2. Change the assignment to subscription scope. Predict and inspect the finding, then restore the container scope.
3. Add `listKeys/action` as in the test. Explain why evaluating only `DataActions` would miss a significant capability.
4. Sketch managed identity -> service-specific token -> Blob endpoint -> RBAC check; add the private DNS and public-access configuration as independent network controls.

### Hints

Role definition, assignment and token are different objects. A token identifies a principal/audience; RBAC and the service still decide what the principal may do.

### Solution and Expected Results

The printed `ROLE` and `ASSIGNMENT` are the worked scoped-reader design. Four tests should pass; broad assignment, management authority and writing each generate a finding in their respective tests. Restoring the scoped design retains the exact read action. No actual blob is read and no effective Azure permission is proved.

For real deployment evidence, separately verify a synthetic allowed container read and denied second-container read, key-listing denial, public endpoint restrictions, private DNS resolution and resource-log delivery. That requires an authorized environment and is outside this zero-cost exercise.

### Verification, Troubleshooting, and Cleanup

No packages or shell-specific syntax are required; use Python 3.12. Run from this file's directory. Reset by restoring fixtures; delete directory and `__pycache__` to clean up. Author validation: static only, no execution or Azure verification.

### User-Owned Milestones

These retained live-sandbox goals are optional follow-up and are not completed by offline checks.

- [ ] Local Azure exercise: Use a dedicated sandbox subscription to give a managed identity access to one synthetic resource. Test a denied second resource, inspect activity logs, and tear down all lab resources.
- [ ] Boundary check: Attempt an unapproved data-plane action with the lab identity and require denial. Verify that a management role does not accidentally imply the data access your design intended to withhold.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Azure Security]]

## References

- [Azure RBAC overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
- [Role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
- [Managed identities overview](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [Managed identity token acquisition and caching](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- [Private endpoint DNS](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns)
- [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
