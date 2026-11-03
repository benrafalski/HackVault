---
title: "Windows Hardening Baselines Security"
aliases: []
tags: [windows, x7, security]
domain: windows
phase: "X7"
type: security
status: draft
pair: "[[Windows Hardening Baselines]]"
updated: 2026-11-03
---
# Windows Hardening Baselines Security

> [!abstract] TL;DR
> A baseline assurance report must preserve unknowns, conflicts, unsupported settings, and accepted risks. Keep the expected fleet in the denominator, scope exceptions to verified evidence, and require compatibility/recovery alongside configuration checks. A quiet log or green assignment is not runtime assurance.

> [!info] Agent scope
> Defensive assurance for Microsoft baselines, configuration management, privilege/service reduction, effective policy, compatibility, drift, rollback, and residual risks. Analyze limitations through offline evidence and exception-review fixtures only; no bypass procedures or live control changes.

## Attack Surface

- **Policy authority:** GPO links/delegation, Intune assignments/profiles, local management, configuration scripts and approval rights determine intent. Conflicting authorities or broad assignments can affect a whole role/ring.
- **Privilege and services:** excessive local membership, service permissions/identities and unnecessary role components widen exposure; legitimate recovery and management still need supported access.
- **Evidence:** unsupported settings, incomplete exports, stale snapshots, collector/RBAC gaps, wrong OS/role and data coercion can make a dashboard falsely green.
- **Exceptions and recovery:** wildcard exemptions, expired approvals, unverified compensating controls and untested rollback can turn a baseline into either false assurance or an outage.

## Learn

```text
Teach me Windows hardening baseline security assurance at expert engineering depth.
Assume GPO/MDM, Windows groups/services, event logs, and UTC evidence basics. Cover
Microsoft baseline selection by release/edition/role, policy authority and conflict,
SCT comparison versus runtime verification, privilege/service reduction, unsupported
settings, stale state, broad exceptions, compatibility, drift, and tested recovery.
For each trust boundary explain the evidence needed, root cause of false assurance,
supported inspection, concrete correction, and remaining uncertainty. Explain
MDMWinsOverGP's Policy CSP limits, why unassignment is not a universal reset, why
group SIDs matter, and why nested privileges and stopped services need more analysis.
Give actual Sigma and KQL for defensive change review with exact channels/fields,
audit prerequisites, false positives, retention, missing-device and parser checks.
Provide a complete independent Python 3.12 standard-library offline CTF: a flawed
reporting-only denominator, missing/conflicting evidence, a wildcard exemption,
an exact scoped expiring repair, original snapshots, fixed retest, benign workflow
checks, expected results, hints, worked solution, troubleshooting, and cleanup.
Keep accepted risk distinct from strict compliance and prove unknowns cannot be
waived by an exception. Discuss rollout stop conditions and complementary controls
without implying they reproduce unavailable enforcement. Cite Microsoft and SigmaHQ
primary sources, state build/version assumptions, and end with worked questions.
Teach here; do not edit files or study status. No actual attacks, bypass/evasion,
tamper changes, service/host/VPN changes, credential access, persistence or exploits.
Use synthetic coverage analysis only, NOT actual Defender/WDAC/Sysmon enforcement.
Do not fabricate execution or require another agent to supply missing lab steps.
```

## Cheatsheet

### Root Causes and Defensive Repairs

| Failure | Evidence and consequence | Repair and residual risk |
|---|---|---|
| Wrong baseline | Package targets another release, edition, server role or application version | Select supported matching guidance; review release diffs and explicit role exceptions. A historical download is not proof of OS support |
| Intent mistaken for state | Assignment says success but effective settings/runtime evidence are missing | Reconcile GPO resultant policy, MDM setting reports and feature-specific runtime APIs. Deployment success alone cannot prove protection |
| Conflicting authorities | GPO/MDM/local scripts disagree for the same setting | Identify a supported owning authority and resolve conflicts through it. `MDMWinsOverGP` is limited to eligible Policy CSP settings, not all MDM or Defender settings |
| Excess privilege | Unapproved local administrators, nested privileged groups, excessive user rights or service ACLs | Review explicit/nested entitlements, use dedicated admin identities and reviewed least-privilege assignments. A direct-membership inventory misses transitive rights |
| Service over-reduction | Required security, update, accessibility, management or role dependency omitted | Retain justified dependencies and measure workflow impact; stopped is not disabled and disabled is not proof of secure service permissions |
| Wildcard risk waiver | Owner/expiry absent or scope expands beyond an approved device/control/value | Bind exception to exact revision and observed value, approval and current compensating evidence. Accepted risk remains noncompliant with the strict baseline |
| Unsupported/unknown hidden | Export error or absent device is dropped from scoring | Keep expected inventory and explicit unknown/unsupported populations; never turn parse failure into a safe default |
| Blind rollback | Unassignment or Not configured assumed to restore every previous setting | Use documented setting-specific recovery with prechange evidence, authority and compatibility tests. Some settings persist or another source reapplies them |

Baselines reduce configuration risk; they do not prove absence of compromise, timely patching, safe application behavior, correct data authorization or successful recovery. Keep identity security, updates, application control, endpoint telemetry and data access controls as separately evidenced layers. Their presence does not automatically compensate for an unrelated baseline gap.

### Effective Evidence and Policy Review

The minimum record is `(device identity, role, OS/build, baseline revision, control ID, desired value, effective value, collection time, source, error/applicability state)`. Retain assignment identity and raw source evidence where permitted. Do not select the newest row until timestamps, duplicate/conflicting IDs and source provenance are validated; a future-dated bad row can otherwise suppress legitimate evidence indefinitely.

Supported reference surfaces, not exercise steps:

```powershell
gpresult /scope computer /r
auditpol /get /category:* /r
Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object SID,ObjectClass,PrincipalSource
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719,4732,4733} -MaxEvents 30 |
	ForEach-Object { $_.ToXml() }
```

Use an authorized Windows session and relevant modules; some inspection requires elevated read rights. Missing module, access denied, offline collector or unsupported class is an evidence error, not a control value. No permission changes or live policy application are part of this exercise. `gpresult` covers its GPO reporting scope, not every MDM setting. Policy Analyzer compares reviewed GPO snapshots and can expose conflicts; it cannot establish that VBS runs, SMB sessions are signed, or approved apps still work. Query the feature's supported runtime surface and reconcile with its policy owner.

### Sigma: Built-In Administrators Membership Review

Complete Sigma rule. Security event 4732 records a member added to a security-enabled local group; `TargetSid` identifies the group and `MemberSid` the added principal. SID `S-1-5-32-544` avoids localized group-name matching. This is a privileged-membership change review, not a claim of malicious intent or current membership.

```yaml
title: Builtin Administrators Membership Addition Review
id: 3e8b64e8-0519-41e9-99c8-79b2d62bc9d0
status: experimental
description: Review additions to the built-in Administrators group against approved membership.
date: 2026-11-03
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
        TargetSid: 'S-1-5-32-544'
    condition: selection
fields:
    - Computer
    - SubjectUserSid
    - MemberSid
    - TargetSid
falsepositives:
    - Approved administrative provisioning or recovery
    - Managed membership reconciliation
level: medium
```

Prerequisites: successful Security Group Management auditing, Security-channel collection, provider mapping and intact named fields. The `security` log source must resolve to `Microsoft-Windows-Security-Auditing` in the Security channel, not EventID 4732 from any provider. A converter/backend processing pipeline is separate from this reference; conversion is not tested here. A missing `TargetSid` is a quality failure, not a benign unmatched event. Review removals (4733) and current membership separately; retained historical additions do not describe the complete current group.

### KQL: Preserve Membership Data-Quality Failures

Sentinel query for a deployment that ingests Security records into `WindowsEvent` and parses named XML data into `EventData`. Different connectors/tables require a reviewed adapter. It retains missing group/member identity for investigation rather than filtering that evidence out before analysis.

```kusto
WindowsEvent
| where TimeGenerated > ago(1d)
| where Provider == "Microsoft-Windows-Security-Auditing" and Channel == "Security"
| where EventID == 4732
| extend GroupSid=tostring(EventData.TargetSid), MemberSid=tostring(EventData.MemberSid),
		 SubjectSid=tostring(EventData.SubjectUserSid)
| extend Quality=iff(isempty(GroupSid) or isempty(MemberSid), "missing-identity", "usable")
| where GroupSid == "S-1-5-32-544" or Quality != "usable"
| project TimeGenerated, Computer, SubjectSid, GroupSid, MemberSid, Quality, EventData
```

Match usable records to approved change tickets, actor context and subsequent resultant membership. Do not suppress every event by SYSTEM or a management account; legitimate automation and incorrect management assignments share that identity. Broad administrative-event collection has privacy/storage costs. Preserve raw SIDs and restrict readers; do not resolve corporate identities for this exercise.

4719 independently reviews audit-policy changes and is documented as logged regardless of the Audit Policy Change subcategory setting. That does not guarantee collector delivery. Missing 4732 can mean no additions, auditing not enabled, retention loss, role scope or parser failure. Neither event is a heartbeat; use independent inventory and collector freshness for devices with no rows. A 24-hour query is a review window, not a complete historical entitlement audit.

### Coverage, Exceptions, and Recovery Gates

For three expected device/control pairs with one compliant, one drifted and one missing, reporting-only compliance is `1/2`; strict expected-population compliance is `1/3`. If the drift has approved compensating evidence, report `1 compliant, 1 accepted risk, 1 unknown`. Do not report `2/2 compliant` by both removing unknowns and treating exceptions as success. Publish applicability separately; a genuinely unsupported control needs an owner and alternative risk decision, not a fabricated effective value.

An exception record needs exact device/role scope, control, accepted observed value, baseline revision, accountable owner, approval/ticket, expiry, and current evidence for a specifically relevant compensating control. A string naming a control is not proof it works; the offline model assumes its evidence token has already been reviewed. Do not permit exceptions to waive missing or conflicted state: there is no trustworthy value to accept.

Hold rollout when telemetry is stale, policy conflicts remain, expected assets disappear, privileged recovery is unverified, or approved business/update/logon workflows fail. Maintain a prior approved revision and management ownership. A rollback must restore a known configuration through supported mechanisms, then repeat security and compatibility checks; it may reintroduce an accepted or unresolved risk. Never disable protection or disconnect the VPN as a recovery shortcut.

## Detection and Defense

Review baseline artifacts, assignments and exceptions as versioned changes. Separate policy authors/approvers and evidence readers, record release/role applicability, test representative workloads, and deploy only through approved rings. Protect the management and evidence paths with scoped permissions and audit retention. Monitor both setting drift and missing evidence after refresh, restart, upgrade and exception expiry. For a limitation, name the uncovered outcome and explain how a supported complementary control reduces that specific risk; do not claim universal equivalence.

## Labs

### Environment and Complete Files

Offline CTF: find the falsely compliant fleet report and repair exception accounting. Python 3.12 standard library only. Use a new scratch directory outside the vault, separate from the other notes' labs, and create the single file below. All data and implementation are embedded. This is NOT a Microsoft baseline validator or actual Defender/WDAC/Sysmon enforcement test; it accesses no host settings, services, network, registry or credentials. `training-r1` and all device/evidence IDs are fictional. Boolean control values represent normalized evidence supplied by an imaginary trusted importer.

### File: test_example.py

```python
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
REVISION = "training-r1"
EXPECTED = {("lab-a", "audit"), ("lab-b", "signing"), ("lab-c", "audit")}
GOOD = {"revision": REVISION, "seen": NOW, "actual": True,
		"supported": True, "conflict": False, "source": "reviewed-export"}
OBSERVED = {("lab-a", "audit"): dict(GOOD),
			("lab-b", "signing"): dict(GOOD, actual=False)}
BROAD = {"device": "*", "control": "*", "actual": False, "revision": REVISION,
		 "owner": "training-team", "ticket": "LAB-41", "evidence": "review-41",
		 "expires": NOW + timedelta(days=1)}
NARROW = dict(BROAD, device="lab-b", control="signing")
REQUIRED_WORKFLOWS = {"logon", "updates", "business_app", "telemetry", "recovery"}
WORKFLOWS = {name: True for name in REQUIRED_WORKFLOWS}


def state(row):
	if row is None:
		return "missing"
	if row.get("revision") != REVISION or row.get("source") != "reviewed-export":
		return "contract-unknown"
	if row.get("supported") is not True:
		return "unsupported-or-unknown"
	if row.get("conflict") is not False:
		return "conflict-or-unknown"
	seen = row.get("seen")
	if not isinstance(seen, datetime) or seen.tzinfo is None or seen.utcoffset() is None:
		return "time-invalid"
	if not NOW - timedelta(minutes=30) <= seen <= NOW:
		return "stale-or-future"
	if type(row.get("actual")) is not bool:
		return "value-unknown"
	return "compliant" if row["actual"] else "drift"


def accepted(exception, key, row):
	expires = exception.get("expires")
	return (state(row) == "drift"
			and (exception.get("device"), exception.get("control")) == key
			and exception.get("revision") == REVISION
			and type(exception.get("actual")) is bool
			and exception["actual"] == row["actual"]
			and all(isinstance(exception.get(field), str) and exception[field].strip()
					for field in ("owner", "ticket", "evidence"))
			and isinstance(expires, datetime) and expires.tzinfo is not None
			and expires.utcoffset() is not None and expires > NOW)


def report(expected, observed, exceptions=()):
	result = {}
	for key in sorted(expected):
		row = observed.get(key)
		outcome = state(row)
		if outcome == "drift" and any(accepted(item, key, row) for item in exceptions):
			outcome = "accepted-risk"
		result[key] = outcome
	return result


def strict_score(result):
	return (sum(value == "compliant" for value in result.values()), len(result)) if result else None


def gate(result, workflows):
	if not result or any(value not in {"compliant", "accepted-risk"} for value in result.values()):
		return "hold-evidence"
	if any(workflows.get(name) is not True for name in REQUIRED_WORKFLOWS):
		return "hold-compatibility"
	return "eligible-in-model"


class BaselineAssuranceTests(unittest.TestCase):
	def test_denominator_and_missing_device(self):
		self.assertEqual(strict_score(report(set(OBSERVED), OBSERVED)), (1, 2))
		result = report(EXPECTED, OBSERVED)
		self.assertEqual(strict_score(result), (1, 3))
		self.assertEqual(result[("lab-c", "audit")], "missing")
		self.assertIsNone(strict_score({}))

	def test_scoped_exception_never_inflates_compliance(self):
		key = ("lab-b", "signing")
		self.assertFalse(accepted(BROAD, key, OBSERVED[key]))
		self.assertTrue(accepted(NARROW, key, OBSERVED[key]))
		result = report(EXPECTED, OBSERVED, [NARROW])
		self.assertEqual(result[key], "accepted-risk")
		self.assertEqual(strict_score(result), (1, 3))
		for changes in ({"expires": NOW}, {"owner": ""}, {"evidence": ""},
						{"device": "lab-c"}, {"revision": "old"}, {"actual": True}):
			with self.subTest(changes=changes):
				self.assertFalse(accepted(dict(NARROW, **changes), key, OBSERVED[key]))

	def test_exception_cannot_mask_bad_evidence(self):
		key = ("lab-b", "signing")
		cases = ((None, "missing"),
				 (dict(OBSERVED[key], conflict=True), "conflict-or-unknown"),
				 (dict(OBSERVED[key], supported=False), "unsupported-or-unknown"),
				 (dict(OBSERVED[key], seen=NOW - timedelta(hours=1)), "stale-or-future"))
		for row, expected in cases:
			with self.subTest(expected=expected):
				self.assertEqual(report({key}, {key: row}, [NARROW])[key], expected)
				self.assertFalse(accepted(NARROW, key, row))

	def test_repair_compatibility_and_original_snapshot(self):
		repaired = deepcopy(OBSERVED)
		repaired[("lab-c", "audit")] = dict(GOOD)
		accepted_result = report(EXPECTED, repaired, [NARROW])
		self.assertEqual(strict_score(accepted_result), (2, 3))
		self.assertEqual(gate(accepted_result, WORKFLOWS), "eligible-in-model")
		repaired[("lab-b", "signing")]["actual"] = True
		fixed = report(EXPECTED, repaired)
		self.assertEqual(strict_score(fixed), (3, 3))
		for name in REQUIRED_WORKFLOWS:
			self.assertEqual(gate(fixed, dict(WORKFLOWS, **{name: False})), "hold-compatibility")
		self.assertEqual(gate(fixed, {}), "hold-compatibility")
		self.assertFalse(OBSERVED[("lab-b", "signing")]["actual"])
		self.assertEqual(gate(report(EXPECTED, deepcopy(OBSERVED)), WORKFLOWS), "hold-evidence")

	def test_type_time_and_source_integrity(self):
		for changes, expected in (({"actual": "True"}, "value-unknown"),
								  ({"actual": 1}, "value-unknown"),
								  ({"source": "unverified"}, "contract-unknown"),
								  ({"seen": NOW + timedelta(seconds=1)}, "stale-or-future"),
								  ({"seen": NOW.replace(tzinfo=None)}, "time-invalid")):
			with self.subTest(changes=changes):
				self.assertEqual(state(dict(GOOD, **changes)), expected)


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Recover the correct denominator and name each initial gap. The flawed dashboard uses `set(OBSERVED)` instead of `EXPECTED`; no live endpoint evaluation is required.
2. Explain why a wildcard exception must fail and why an exact valid exception changes the disposition to accepted risk, not compliance.
3. Run the exact offline suite below from the scratch directory when execution is authorized. Follow the supplied narrow repair, full repair and snapshot-restoration cases without changing real policies.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Define the expected device/control population before examining reporters. Apply evidence-quality checks before exceptions. An approval for a particular observed value cannot apply to an unknown value, another revision or another device. A security score does not contain application-compatibility evidence unless the release gate explicitly checks it.

### Solution and Fixed Retest

Designed expectation: five tests, `OK`; these are not measured results. Reporting-only strict compliance is `(1, 2)`; expected-population compliance is `(1, 3)`. `lab-b/signing` is drift and `lab-c/audit` is missing. `BROAD` is rejected. `NARROW` makes only the signing drift `accepted-risk`, leaving strict compliance `(1, 3)` and the release gate on hold for missing evidence.

Adding synthetic lab-c evidence yields `(2, 3)` with a separately accepted risk; the model permits review eligibility only when all required workflows also pass. Restoring signing to the baseline in a copy yields `(3, 3)` with no exception needed. A broken or missing workflow still holds rollout. The original snapshot stays unchanged; restoring it restores its drift and missing evidence too. None of these operations configures SMB, audit policy, groups or Windows recovery.

### Verification, Troubleshooting, and Cleanup

Acceptance includes the exact denominator, preserved unknowns, exception identity/revision/value/expiry, stale and conflicting evidence, strict Boolean handling, source integrity, unchanged healthy evidence, all five compatibility checks, and original-snapshot preservation. The model assumes a verified importer supplies evidence; a real string named `reviewed-export` or `review-41` is not authentication. Real systems need authenticated provenance, authorized role scope, duplicate handling, audit history and validation of compensating evidence.

No Python, Sigma conversion, KQL query, live audit or enforcement validation was executed during authorship. If the launcher is absent, use an existing Python 3.12 executable with the same arguments; no packages or installs are required. If discovery fails, verify the scratch directory and exact filename. Never change host controls to resolve a failing synthetic test. `-B` prevents bytecode artifacts; cleanup removes only the scratch file and needs no policy rollback:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

The original milestones are unchanged and user-owned. They are separate live-VM work, neither authorized nor completed by the offline CTF.

- [ ] Local Windows Hardening Baselines exercise: Apply a current matching Microsoft baseline to a disposable role-specific VM after recording its initial state. Test logon, updates, recovery, and the expected security controls.
- [ ] Boundary check: Introduce one harmless controlled deviation in the test VM, verify drift detection, restore the intended setting, and rerun both security and compatibility checks.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Windows Hardening Baselines]]

## References

- [Microsoft security baseline principles](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [SCT and policy comparison boundaries](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [MDM/GPO conflict limitations](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-controlpolicyconflict)
- [Security group member added: event 4732 and field schema](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732)
- [Audit policy changed: event 4719](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719)
- [gpresult supported inspection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [WindowsEvent table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent)

Microsoft's detailed 4719/4732 schema pages may redirect to its archived reference collection. They document event semantics, not a current OS support guarantee; verify event versions and collection mappings on the supported target build.
