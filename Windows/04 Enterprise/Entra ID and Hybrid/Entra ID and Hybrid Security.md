---
title: "Entra ID and Hybrid Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[Entra ID and Hybrid]]"
updated: 2026-11-03
---
# Entra ID and Hybrid Security

> [!abstract] TL;DR
> Secure the cloud and on-premises control planes independently, then review their connections. Report-only is not enforcement, consent is not a business authorization decision, and disabling an identity is not universal immediate session revocation.

> [!info] Agent scope
> Security of: Cloud identity; tenant roles; device identity; synchronization and federation; conditional access; hybrid trust boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Tenant roles/PIM, application owners and credentials, delegated consent/app-role assignments, device identity/compliance, CA policy/exclusions, synchronization agents and federation configuration/key custody.
- Defensive configuration and lifecycle review only. No tokens/assertions are created, no credentials are collected, and no tenant or directory is contacted by the required exercise.

## Learn

```text
Teach defensive Entra ID and hybrid identity security at expert depth. Assume
OAuth/OIDC, AD and device identity basics. Separate directory roles, Azure RBAC,
application ownership, delegated consent, app-only grants and resource-specific
authorization. Explain least-privilege/PIM governance, emergency access,
phishing-resistant authentication and workload identity controls with licensing.
Review Connect Sync/Cloud Sync, PTA and federation as distinct trust components;
show how provisioning filters, source authority, key custody and outages affect
lifecycle without giving abuse techniques. Explain Conditional Access scope,
exclusions, all/one grant operators, report-only versus enabled, device evidence,
session lifetime and CAE limits. Provide exact review fields and a staged secure
configuration with rollback and preserved legitimate access.
Correlate synthetic sign-in, CA and audit evidence; supply a complete offline
baseline/fix/retest challenge and explain what it cannot prove. Use Microsoft
sources. No real tenant actions, secret retrieval, forged tokens/certificates,
relay, persistence, evasion or bypass recipes. Teach here, not by editing files.
```

## Cheatsheet

### Control-Plane Review

| Surface | Root cause to look for | Defensive configuration |
|---|---|---|
| Directory roles | Standing broad grants and unreviewed eligible/active paths | Task-specific roles, scope where supported, PIM approval/time bounds and activation evidence; review role administrators too. |
| Azure resources | Subscription/resource roles confused with directory roles | Review Azure RBAC separately at inherited resource scopes; no assumption that a tenant-role review covers it. |
| Application ownership | Owners can change credentials/configuration independently of a narrow API grant | Named accountable owners, restricted change workflow, expiring credentials or supported managed identity/workload federation. |
| Consent | Tenant-wide delegated grants or app-only permissions exceed business need | Limit user consent, review publisher/permission risk and use admin-consent workflow; remove unused grants/assignments through change control. |
| Device trust | Registered/joined confused with managed/compliant | Require the appropriate device/compliance controls for the workload; validate current device and sign-in context. |
| Hybrid systems | Lower-trust administrators can manage sync/PTA/federation hosts or keys | Treat them as identity control-plane assets; isolate admin access, patch, monitor and protect recovery dependencies. |

Managed identity removes ordinary application secret distribution but still needs minimal resource grants. Workload identity federation trusts issuer/subject/audience relationships and an external execution environment; review those explicit trust conditions. Human-user CA/MFA is not a universal workload control, and workload CA does not cover every identity type such as managed identities. Confirm current feature/licensing support before claiming coverage.

### Conditional Access Configuration, Precisely

Example pilot: group `TrainingUsers`, resource `TrainingInventoryAPI`, all relevant client types, require phishing-resistant authentication strength AND compliant device. Use `grantControls.operator=AND`, not OR, when both are necessary. Target the resource API rather than assuming a client application's name selects every downstream resource. Any applicable enabled block policy still wins; one successful policy result is not global authorization.

Rollout: inventory affected flows and licenses -> establish monitored independent emergency access -> create policy in report-only -> review failures/userActionRequired/notApplied and dependencies -> test approved synthetic users/devices -> enable for a pilot -> verify positive and negative sign-ins -> expand with an explicit rollback owner. Record exclusions by immutable IDs and purpose, especially emergency access; review them periodically. Do not broadly exclude service accounts simply because they cannot satisfy a human MFA prompt; design a supported workload identity instead.

Graph policy state `enabledForReportingButNotEnforced` means report-only, not "enabled but lenient." `enabled` enforces and `disabled` does not. Report-only failure can coexist with a successful sign-in because that policy did not block. Existing MFA satisfaction may mean no new prompt; inspect authentication details rather than counting prompts. CA can affect token issuance/session handling but is not a resource-row authorization engine.

Entra ID P1 generally gates CA; risk policies require P2/applicable licensing. Governance/PIM and workload-identity features have distinct licensing requirements. Retention/export availability also depends on licenses and configured diagnostics; do not infer a complete timeline from a short default retention window.

### Consent and Identity Evidence

For every grant capture tenant, client service-principal ID, resource service-principal ID, permission IDs/values, consent scope, granting actor/time, current owners and last justified use. Resolve app-role IDs against the resource's appRoles; use `oauth2PermissionGrant` for delegated scopes, not the app-only assignment collection. A signed-in user with broad resource privileges is not constrained merely because the client has a harmless display name.

Use the API's supported middleware to validate tokens and then its own authorization checks for tenant/resource/object/action. A successful CA result or `roles` claim does not authorize an arbitrary object. For a defensive API acceptance test, keep permitted Inventory.Read access working and require denial on an unassigned Billing resource; this note provides no real tokens and does not run that live test.

### Hybrid Lifecycle and Recovery

| Change | Evidence required beyond the change itself |
|---|---|
| Disable on-prem user | Synchronization export and cloud account state; supported session revocation and application lifecycle handling. |
| Remove user from sync scope | Deletion-threshold preview, intended object identity, retention/recovery plan; removal may delete cloud objects rather than merely stop updates. |
| PTA/federation outage | Health of agents/DCs or federation services; preplanned cloud-authentication recovery. PHS failover is not automatic. |
| Federation certificate rollover | Trusted metadata/key transition, old/new overlap, monitoring and recovery; signing trust is not the same certificate as HTTPS transport. |
| Remove app grant/credential | Resource authorization and credential inventory, token/session lifetime, owner confirmation and audit event. Already-issued tokens may remain usable until expiry/CAE handling where supported. |

Protect synchronization accounts and permitted source attributes; do not treat the connector as an ordinary desktop application. Use supported synchronization rules and matching procedures, with staging/export review and threshold protections. Emergency-access accounts should remain independent of the failing on-prem dependency and receive alerting on use, with secure authentication and current Microsoft guidance rather than a blanket undocumented CA exclusion.

### Errors and Investigation Order

For 53003 inspect sign-in correlation ID, resource ID, applied policies and exact condition/control result. For 50076 inspect authentication requirements and satisfied methods; a policy may be functioning correctly. For Graph 403 inspect scope, delegated directory role, license and resource-specific restrictions before declaring the object absent. For provisioning duplicate-attribute/matching errors inspect source anchors/UPNs/proxy addresses and authoritative ownership; do not "repair" by merging identities on display name.

`dsregcmd /status` can support a device-state review but contains sensitive tenant/device metadata. It is not compliance proof and should be collected in the relevant user context. Do not include real output in public study notes.

## Detection and Defense

Correlate sign-in ID/correlation ID, UTC time, principal type, resource, status, CA policy results, authentication details and device context. Use audit logs for role/consent/application credential/policy changes and provisioning logs for sync/export outcomes. Distinguish interactive, noninteractive user and service-principal sign-in datasets. Missing export categories or retention are evidence gaps, not no activity.

This read-only KQL fragment requires an already configured Log Analytics/Sentinel workspace receiving `SigninLogs`, appropriate read rights, and the expected schema. It expands recorded policy results; it does not calculate CA or request tokens. It is optional and not a dependency of the offline lab.

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| mv-expand Policy = ConditionalAccessPolicies
| extend PolicyId = tostring(Policy.id), PolicyResult = tostring(Policy.result)
| where PolicyResult in ("failure", "reportOnlyFailure", "reportOnlyInterrupted")
| project TimeGenerated, CorrelationId, AppId, ResourceDisplayName,
		  ResultType, PolicyId, PolicyResult
```

Investigate unexpected grant/owner changes, emergency access usage, disabled enforcement and broad exclusions. Migration pilots, interactive challenge requirements and stale compliance records can cause expected failures; suppress narrowly by approved change/time/resource rather than a permanent actor exemption.

## Labs

### Offline Report-Only Versus Enforcement Case

Dependencies: Python 3.12 standard library, one file, no SDK/network/tenant. All records are compact synthetic extracts using Graph-style policy state and sign-in result labels. The checker validates evidence consistency for one stated control, not the CA decision engine or cloud authorization.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	'policy': {'id': 'training-policy', 'state': 'enabledForReportingButNotEnforced'},
	'negative': {'resource': 'training-api', 'status': 0,
				 'policies': [{'id': 'training-policy', 'result': 'reportOnlyFailure'}]},
	'positive': {'resource': 'training-api', 'status': 0,
				 'policies': [{'id': 'training-policy', 'result': 'reportOnlySuccess'}]},
}


def result_for(signin, policy_id):
	matches = [item['result'] for item in signin['policies'] if item['id'] == policy_id]
	if len(matches) != 1:
		raise ValueError('missing or duplicate policy result')
	return matches[0]


def rollout_findings(evidence):
	policy = evidence['policy']
	negative, positive = evidence['negative'], evidence['positive']
	result = set()
	if policy['state'] != 'enabled':
		result.add('not-enforced')
	if negative['resource'] != 'training-api' or positive['resource'] != 'training-api':
		result.add('wrong-resource-evidence')
	if negative['status'] != 53003 or result_for(negative, policy['id']) != 'failure':
		result.add('negative-denial-not-demonstrated')
	if positive['status'] != 0 or result_for(positive, policy['id']) != 'success':
		result.add('permitted-path-not-demonstrated')
	return result


def post_rollout_evidence():
	evidence = copy.deepcopy(BASELINE)
	evidence['policy']['state'] = 'enabled'
	evidence['negative']['status'] = 53003
	evidence['negative']['policies'][0]['result'] = 'failure'
	evidence['positive']['policies'][0]['result'] = 'success'
	return evidence


class RolloutEvidenceTests(unittest.TestCase):
	def test_report_only_is_not_denial(self):
		self.assertEqual(rollout_findings(BASELINE), {'not-enforced',
						 'negative-denial-not-demonstrated', 'permitted-path-not-demonstrated'})

	def test_post_rollout_positive_and_negative_evidence(self):
		self.assertEqual(rollout_findings(post_rollout_evidence()), set())

	def test_wrong_resource_is_detected(self):
		evidence = post_rollout_evidence()
		evidence['negative']['resource'] = 'other-api'
		self.assertEqual(rollout_findings(evidence), {'wrong-resource-evidence'})

	def test_missing_policy_is_unknown_not_success(self):
		evidence = post_rollout_evidence()
		evidence['positive']['policies'] = []
		with self.assertRaises(ValueError):
			rollout_findings(evidence)


if __name__ == '__main__':
	unittest.main()
```

### Objectives and Baseline

1. Explain why baseline overall status 0 and reportOnlyFailure are consistent, not contradictory.
2. Run `py -3.12 -m unittest -v test_example.py`; four tests should pass. Baseline is rejected as enforcement evidence even though the permitted user did sign in during observation.
3. Review the post-rollout fixture as separately collected synthetic evidence. State that changing a JSON state/result string is not a tenant change and must never be used to rewrite a real audit record.
4. Confirm denial for the negative case and success for the permitted case on the same resource/policy. Mutate the resource or remove a policy result; the checker must not silently accept the evidence.

### Hints and Solution

Report-only records show hypothetical policy outcomes. The accepted fixture requires enabled state, recorded failure/53003 for the negative case and recorded success/status 0 for the permitted path. It still lacks real authentication-method/device/tenant evidence and cannot prove an API's object-level authorization. A live acceptance test must collect those separately and test relevant noninteractive/workload flows too.

### Verification, Troubleshooting, and Cleanup

Author execution not performed. Duplicate/missing result records are an evidence error; do not replace them with success. The numeric 53003 comparison is a chosen synthetic negative case, not an exhaustive taxonomy of all denials. Delete the directory/cache to reset; no policies, grants, tenants, tokens or services were created. Original optional live checklist remains uncompleted.

- [ ] Local Entra ID and Hybrid exercise: In a dedicated test tenant, map one synthetic user and application permission flow and inspect sign-in/audit logs. Document hybrid trust assumptions without connecting corporate directories.
- [ ] Boundary check: Use a narrowly permitted test application against an unapproved resource and require denial; verify privileged role/application changes appear in audit logs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Entra ID and Hybrid]]

## References

- [Conditional Access report-only behavior](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
- [Conditional Access policy resource](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)
- [Permissions and consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)
- [Manage emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Hybrid authentication choices and recovery dependencies](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/choose-ad-authn)
- [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
