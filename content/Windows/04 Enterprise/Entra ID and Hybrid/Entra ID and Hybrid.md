---
title: "Entra ID and Hybrid"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[Entra ID and Hybrid Security]]"
updated: 2026-11-03
---
# Entra ID and Hybrid

> [!abstract] TL;DR
> Entra ID is a cloud identity control plane, not an LDAP replica of AD. Track tenant-local object IDs, synchronization authority, authentication method, token audience and resource authorization as distinct boundaries.

> [!info] Agent scope
> Cloud identity; tenant roles; device identity; synchronization and federation; conditional access; hybrid trust boundaries.

## Prerequisites

- AD identity lifecycle, OAuth/OIDC concepts, TLS and application authorization. Use only synthetic tenants/identifiers in exercises; never connect a corporate directory.
- Required lab: Python 3.12 standard library (`sqlite3`, `unittest`), no cloud account, SDK, license, browser service or network.
- Cloud behavior is service/version/license dependent. Reference date 2026-11-03; check current Connect Sync/Cloud Sync support matrices before deployment. Live commands below are optional read-only reference snippets, not required setup.

## Learn

```text
Teach Microsoft Entra ID and hybrid identity at expert engineering depth. Assume
AD, TLS and OAuth/OIDC knowledge. Distinguish tenant ID, application/client ID,
application object, tenant-local service principal, object ID and managed
identity. Trace delegated scopes versus app roles/application permissions,
consent versus assignment, tenant roles versus Azure RBAC and app authorization.
Compare registered, joined and hybrid-joined devices, device object versus
deviceId, PRT/SSO versus resource tokens, and identity versus compliance.
Explain Connect Sync/Cloud Sync authority, sourceAnchor, matching, filtering,
deletion thresholds, provisioning latency and lifecycle; separate these from
password hash sync, pass-through authentication and federation. Work through
an on-prem outage and leaver sequence without assuming immediate revocation.
Explain Conditional Access evaluation, report-only, multiple policies, grant/
session controls, workload exclusions and license gates. Provide safe read-only
inspection, actual Graph relationship examples and a complete offline data-
correlation lab, not a token validator or cloud-policy simulator. Cite Microsoft
sources and version-sensitive limits. No tenant provisioning, secrets, forged
tokens, bypasses or file edits. Teach here with worked questions and answers.
```

## Cheatsheet

### Identity Objects and Authority

| Identifier/object | Meaning | Common failure |
|---|---|---|
| Tenant ID | Directory/security boundary used in issuer/authority selection | Accepting any tenant because an application is multitenant without intended tenant authorization. |
| Application `appId` | Client/application ID shared by instances of that application | Confusing it with a service principal object ID in Graph relationship APIs. |
| Application object | App definition in its home tenant: credentials/redirects/exposed permissions | Treating registration as proof that tenant users granted consent. |
| Service principal `id` | Tenant-local instance with grants/assignments and local policy | Joining a grant to an app by display name rather than object ID. |
| Managed identity | Azure-managed workload identity represented by a service principal | Assuming managed credentials mean automatically least-privileged authorization. |
| User object ID | Stable cloud identity while the object exists | UPN/display-name reuse does not make a deleted/recreated user the same identity. |

A directory role such as Global Reader governs Entra administrative capabilities. Azure RBAC assignments apply to resource scopes such as subscriptions/resource groups. Application roles and delegated scopes govern an API's authorization contract. These systems can interact through particular elevation features, but they are not one universal role list. Review each plane explicitly.

### Permission and Token Flow

Delegated access represents an application acting for a user: OAuth scopes are commonly exposed in `scp`; the user must also have relevant resource access. Consent grants the application's permission to act, not arbitrary business-object access. App-only access represents a workload; application permissions are exposed as app roles and commonly appear in `roles`. User app-role assignments can also appear in delegated tokens, so a `roles` claim alone is not a universal proof of app-only authentication.

`appRoleAssignment.principalId` identifies the assigned principal, `resourceId` identifies the resource service principal in that tenant, and `appRoleId` identifies one of that resource's role definitions. Resolve the role against the resource, not the client application's similarly named role. `oauth2PermissionGrant` uses `clientId` for the client service principal object ID, `resourceId` for the API service principal, and a space-separated `scope`; `consentType=AllPrincipals` versus `Principal` changes grant scope.

Resource APIs validate signature via trusted metadata/keys, issuer/tenant, audience, time and the appropriate permission contract using supported middleware. An ID token is for client sign-in, not an API access token. A decoded payload is untrusted until validated; these notes create no tokens and implement no cryptographic token validator. A successful sign-in/Conditional Access evaluation does not establish authorization to a specific API object.

### Hybrid Provisioning Is Not Authentication

Connect Sync runs a synchronization engine with connectors, scoping/rules, join/projection and exports. A staging server is not a second simultaneous active exporter for the same design. Cloud Sync uses provisioning agents with cloud-managed orchestration and a different feature matrix; do not assume one-for-one feature or device/writeback support. Pin the supported versions/features before migration.

Source authority determines where attributes are managed. SourceAnchor/immutable identity relationships keep object continuity; `mS-DS-ConsistencyGuid` is commonly used in supported Connect designs, but migrations must verify actual configuration rather than rewrite anchors. Soft/hard matching and duplicate UPN/proxy-address errors need a reviewed identity decision, not an automatic merge. OU/filter changes can remove objects from scope and trigger deletes; use deletion thresholds, preview/export review and rollback records.

| Sign-in method | Validation location and dependency | Lifecycle consequence |
|---|---|---|
| Password hash synchronization (PHS) | Derived password-hash data synchronized; Entra validates in cloud, not reversible plaintext storage | On-prem account/password changes arrive asynchronously; lockout/password-expired state is not a live DC query. |
| Pass-through authentication (PTA) | Entra uses on-prem agents to validate against AD | Depends on agent/DC/network availability; deploy redundancy. PHS fallback is not automatic merely because PHS was enabled. |
| Federation | Trusted identity provider authenticates and returns assertions | Federation keys, claims/configuration, availability and administrators become cloud-trust dependencies. |

PHS commonly runs on a separate short cadence (documented as every two minutes); ordinary Connect object synchronization commonly uses a 30-minute scheduler. Neither is an SLA or universal Cloud Sync timing. A disabled on-prem user may retain cloud access until object state propagates and relevant sessions/tokens are handled. PTA's live password checks still do not revalidate every request using an already-issued access token.

### Device State and SSO

Registered devices usually represent a work account on a personally managed device; Entra joined devices use cloud organizational join; hybrid joined devices remain AD domain joined and also have an Entra device identity. Registration/join is not proof of compliance, management enrollment, healthy endpoint security or a current user session.

`dsregcmd /status` is a read-only local diagnostic. `AzureAdJoined=YES` plus `DomainJoined=YES` supports hybrid-join state; `AzureAdJoined=YES` with DomainJoined=NO supports Entra join. User-context `WorkplaceJoined` is a different registration signal. PRT/SSO state is user-context dependent; do not treat a SYSTEM-context result as equivalent. Device Graph `id` is the directory object ID; `deviceId` is the device-registration identifier. Handle logs as sensitive metadata and never publish real tenant/device IDs.

### Conditional Access and Sessions

CA combines identity, resource, client, location, risk/device conditions and grant/session controls. All applicable enabled policies must be satisfied; an applicable block prevents access. Within a policy, grant controls can require all or one selected control, so preserve the operator. Report-only evaluates without enforcing; "reportOnlyFailure" can coexist with successful sign-in. Some client prompts can still occur during device evaluation even in report-only.

User CA generally requires Entra ID P1; risk-based policies require P2/appropriate licensing. PIM and governance features have separate licensing, and workload-identity CA requires its own applicable licenses/capabilities. User MFA policy does not automatically govern service principals or managed identities. Test emergency access, app dependencies and noninteractive flows before enforcement.

Session controls and refresh-token revocation do not imply instantaneous invalidation of every access token. Continuous Access Evaluation accelerates selected changes for supported clients/resources but is not universal. A leaver plan must record authoritative disable, sync/export result, cloud state, app-role/consent review and supported session/resource revocation separately.

### Safe Evidence Requests and Errors

Read-only Graph v1.0 request examples for an already authorized tenant review; use an approved client, minimal consent and authorized role. No access token or live tenant is required by the lab. Placeholder IDs are tenant-local object IDs. For service-principal reads use appropriate `Application.Read.All`; for grants use documented permission-grant read permissions; policy/audit APIs require their corresponding read scopes and, for delegated access, suitable directory roles. Do not consent broad permissions just to run these examples.

```http
GET https://graph.microsoft.com/v1.0/servicePrincipals/{client-sp-object-id}/appRoleAssignments
GET https://graph.microsoft.com/v1.0/servicePrincipals/{resource-sp-object-id}?$select=id,appId,displayName,appRoles
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=10
```

These are request-line fragments, not complete runnable requests. Follow `@odata.nextLink` for complete inventory; a first page is not the whole tenant. Record request/correlation IDs and UTC times; 403 can mean missing role, scope or licensing, not absence of data. AADSTS50076 commonly indicates additional authentication required; 53003 means blocked by CA and needs policy-specific sign-in evidence. AADSTS700016 concerns application identification/tenant context. Duplicate-attribute synchronization errors belong to provisioning, not CA. Preserve the exact service error because descriptions and remediation vary.

## Gotchas

- Consent to an API is not an Azure subscription role assignment, and on-prem Domain Admin membership does not automatically confer an Entra role.
- Display names are not unique; join by IDs and tenant, then resolve human-readable labels.
- Removing a synchronization agent does not remove existing cloud objects or consent grants.

## Labs

### Offline App-Role Assignment Join

Python 3.12 standard library only. Put this single file in its own empty exercise directory. SQLite operates entirely in memory. All identifiers are short synthetic labels, not actual GUIDs; column relationships mirror Graph app-role assignments. This is a real relational evidence join, not Entra authorization or token validation.

### File: test_example.py

```python
import sqlite3
import unittest

SCHEMA_AND_DATA = """
CREATE TABLE principals(id TEXT PRIMARY KEY, app_id TEXT, name TEXT);
CREATE TABLE roles(resource_id TEXT, role_id TEXT, value TEXT,
				   PRIMARY KEY(resource_id, role_id));
CREATE TABLE assignments(principal_id TEXT, resource_id TEXT, role_id TEXT);
INSERT INTO principals VALUES
 ('client-sp','client-app','Inventory collector'),
 ('inventory-sp','inventory-api','Inventory API'),
 ('billing-sp','billing-api','Billing API');
INSERT INTO roles VALUES
 ('inventory-sp','read-role','Inventory.Read.All'),
 ('billing-sp','read-role','Billing.Read.All');
INSERT INTO assignments VALUES ('client-sp','inventory-sp','read-role');
"""

QUERY = """
SELECT client.name, resource.name, role.value
FROM assignments AS assignment
JOIN principals AS client ON client.id = assignment.principal_id
JOIN principals AS resource ON resource.id = assignment.resource_id
JOIN roles AS role ON role.resource_id = assignment.resource_id
				  AND role.role_id = assignment.role_id
WHERE client.id = ?;
"""


class IdentityJoinTests(unittest.TestCase):
	def setUp(self):
		self.database = sqlite3.connect(':memory:')
		self.database.executescript(SCHEMA_AND_DATA)
		self.addCleanup(self.database.close)

	def test_correct_resource_join(self):
		rows = self.database.execute(QUERY, ('client-sp',)).fetchall()
		self.assertEqual(rows, [('Inventory collector', 'Inventory API', 'Inventory.Read.All')])

	def test_app_id_is_not_principal_object_id(self):
		self.assertEqual(self.database.execute(QUERY, ('client-app',)).fetchall(), [])

	def test_role_id_alone_is_insufficient_evidence_join(self):
		wrong_query = QUERY.replace('role.resource_id = assignment.resource_id', '1 = 1')
		rows = self.database.execute(wrong_query, ('client-sp',)).fetchall()
		self.assertEqual(len(rows), 2)
		self.assertIn('Billing.Read.All', [row[2] for row in rows])


if __name__ == '__main__':
	unittest.main()
```

### Objectives and Steps

1. Map `principal_id`, `resource_id` and `role_id` to Graph fields. Explain why the two role labels deliberately share a synthetic role ID.
2. Run `py -3.12 -m unittest -v test_example.py`. Three tests should pass.
3. Inspect the bad join: removing the resource equality incorrectly associates a billing permission with the inventory resource. Restore the complete composite join; the permitted Inventory.Read.All record remains.
4. Explain why the second test's empty result is a wrong identifier, not evidence that the actual principal has no permissions.
5. Write the missing authorization checks: actual grant completeness/currentness, resource audience, workload/user context and API business rules. No local SQL result proves these.

### Hints and Solution

Resolve app-role definitions on the resource service principal. `appId` is not `id`. Correct output is one inventory role, wrong join produces two rows, wrong client identifier produces zero. The test deliberately exposes incorrect analysis rather than simulating a token or requesting permission.

### Verification, Troubleshooting, and Cleanup

Not executed by the author. A missing `sqlite3` module means the interpreter lacks the expected standard-library support. Run from this lab's own directory to avoid another note's same-named test. SQLite is only an offline analysis tool, not a replacement for Graph/Entra. Delete the directory/cache to reset; the database is in memory and no cloud resource exists. Original optional live checklist remains uncompleted.

- [ ] Local Entra ID and Hybrid exercise: In a dedicated test tenant, map one synthetic user and application permission flow and inspect sign-in/audit logs. Document hybrid trust assumptions without connecting corporate directories.
- [ ] Boundary check: Use a narrowly permitted test application against an unapproved resource and require denial; verify privileged role/application changes appear in audit logs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Entra ID and Hybrid Security]]

## References

- [Applications and service principals](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Graph appRoleAssignment resource](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment)
- [Hybrid authentication choices](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/choose-ad-authn)
- [Device identities](https://learn.microsoft.com/en-us/entra/identity/devices/overview)
- [Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Conditional Access report-only](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
