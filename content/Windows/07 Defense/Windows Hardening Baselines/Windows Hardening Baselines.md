---
title: "Windows Hardening Baselines"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[Windows Hardening Baselines Security]]"
updated: 2026-11-03
---
# Windows Hardening Baselines

> [!abstract] TL;DR
> A baseline is versioned configuration intent, not an enforcement certificate. Match it to the OS and role, reconcile policy authority, verify effective settings and runtime evidence, and gate rollout on security plus compatibility. Missing evidence is unknown, not compliant.

> [!info] Agent scope
> Microsoft baselines; configuration management; privilege and service reduction; policy verification; compatibility; drift; rollback; residual risks.

## Prerequisites

- Windows policy, local groups, services, event logs, UTC timestamps, and basic PowerShell concepts. Live work belongs in a separately authorized environment described in [[Windows Lab Setup]].
- Required exercise dependency: an existing Python 3.12 interpreter, standard library only, and a fresh writable scratch directory. No administrator access, Windows VM, tenant, network, or baseline package is required.
- For real baseline work record exact Windows release/build/edition, client/server and machine role, baseline package/template version, policy authority, management enrollment, hardware prerequisites, and support lifecycle. A downloadable historical baseline does not imply the OS is still supported.

## Learn

```text
Teach me Windows hardening baseline engineering at expert operational depth.
Assume Windows policy, service, local-group, event-log, and PowerShell knowledge.
Explain Microsoft Security Compliance Toolkit baselines, Policy Analyzer, LGPO,
Intune baseline templates, GPO inheritance/filtering, CSP applicability, and the
limited scope of MDMWinsOverGP. Distinguish source policy, assignment, resultant
configuration, runtime state, action evidence, and application compatibility.
Cover baseline package/build/edition/role matching, revision diffs, privilege and
service reduction, audit policy, SMB signing, firewall profiles, supported VBS
status, update and recovery dependencies, and exception ownership/expiry.
Show concrete supported read-only commands and real Sigma/KQL with exact source
and field contracts, retention/freshness assumptions, and false-positive causes.
Provide a complete Python 3.12 standard-library offline drift lab with all files,
data, commands, expected results, hints, worked solution, tests, and cleanup.
Preserve missing/unsupported/stale evidence, test permitted business workflows,
and demonstrate baseline repair and rollback as in-memory snapshots only.
Explain why not-configured is not a universal reset, policy success is not runtime
proof, and a perfect settings score is not a claim of system security. Use public
Microsoft sources and mark version-sensitive behavior. End with worked questions.
Teach in this conversation; do not edit files or study status. No host controls,
VPN, services, live policy deployment, bypass, evasion, exploits, credential access,
or persistence changes. Synthetic tests are NOT actual Windows enforcement tests.
Do not fabricate execution results or require a follow-up agent to finish the lab.
```

## Cheatsheet

### Baseline Selection and Policy Authority

Microsoft baselines contain recommended settings with security rationale. They assume a managed environment where ordinary users are not administrators; they are not a maximal list of every configurable setting. Start with the matching published package and review its release notes and differences, rather than combining every restrictive setting from unrelated releases.

| Surface | Supported role | Evidence boundary |
|---|---|---|
| Security Compliance Toolkit (SCT) | Published Windows/client/server/application baseline packages and comparison tools | Record downloaded package identity and provenance; Windows, Edge, Office, and Defender policies have separate release cycles |
| Policy Analyzer | Compare GPO sets; identify differences, duplicates, conflicts; compare captured local policy/registry | Differences explain intent/state, not whether an application or protocol obeyed the control |
| LGPO | Export/import local policy and parse policy artifacts | A local backup is not a backup of all domain/MDM settings, secrets, certificates, or application state; no import is needed here |
| GPO | Site/domain/OU and user/computer policy with inheritance, link order, enforcement, security/WMI filters, and extensions | `gpresult` helps explain resultant GPO; it is not a universal MDM or feature-runtime report |
| Intune baseline/profile | Versioned template, assignments, applicability and per-setting deployment reports | Baseline, settings catalog, and endpoint-security profiles can overlap; a successful assignment is not measured protection |
| CSP | Documented per-setting scope, edition/build support, operations and value types | `MDMWinsOverGP` applies to eligible Policy CSP settings, not all CSPs, including not the Defender CSP |

Keep one accountable authority per setting. Do not solve conflicts by repeatedly writing the same value locally: a later policy refresh can restore another value. Distinguish conflict, unsupported, pending restart, not applicable, error, and compliant. An unsupported setting is a coverage gap, not an acceptable alternate value. Applicability needs an explicit role/build reason, not an empty field.

### Concrete Controls and Tradeoffs

These are inspection examples, not a replacement Microsoft baseline or universal recommended values. Select the actual recommendation from the package for the target role.

| Control family | Mechanism and supported verification | Tradeoff or failure case |
|---|---|---|
| Local privilege | Managed membership in built-in Administrators, separate administration identities, scoped user rights; enumerate members by SID | Group names are localized; nested domain-group membership and user-right assignments need additional analysis. Removing the last recovery administrator is an availability defect |
| Services | Role-dependent installed services, service accounts, start mode, dependencies and service ACLs | Stopped is not disabled; trigger-start services may legitimately be stopped. A blanket service list can break updates, print workflows, security sensors, or management |
| Audit policy | Advanced audit subcategories define emitted Security records; collector subscription and retention preserve them | Process auditing without command-line policy does not supply command lines. Command lines can contain secrets; collect only with an approved privacy/retention plan |
| SMB signing | Client/server requirements protect SMB message integrity under negotiated sessions | Client and server settings differ; signing is not encryption or share authorization. Compatibility needs supported peer/protocol evidence |
| Firewall | Profile selection and resultant policy/rule stores control network access | An enabled profile alone says nothing about overly broad rules. Never change host firewall, VPN, routes, or connectivity for this lab |
| VBS/HVCI and boot trust | Policy requests features; hardware/firmware, drivers, and restart state determine activation | Configured is not running; collect supported runtime status and compatibility evidence without changing boot settings |
| Updates and recovery | Managed update paths, supported OS/apps, tested backup/recovery and authorized administrative access | Baseline compliance does not patch software or prove backups restore successfully |

An exception must identify device/role, setting, accepted value, reason, owner, approval, expiry, and current compensating evidence. Track strict baseline compliance separately from accepted risk. More exceptions do not increase the strict compliance numerator.

### Supported Read-Only Inspection

Reference commands only, not required lab steps and not executed during authorship. Use an already authorized Windows session with the relevant modules. Security policy/log inspection may require elevated rights; record access denial and stop rather than changing permissions. Prefer 64-bit Windows PowerShell for the LocalAccounts module on 64-bit Windows.

```powershell
gpresult /scope computer /r
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /r
Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object SID,ObjectClass,PrincipalSource
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
Get-CimInstance Win32_Service -Filter "Name='Spooler'" | Select-Object Name,StartMode,State,StartName
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
	Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning
```

The audit subcategory GUID selects Process Creation independent of display-language names. Parse command output using documented types/fields, not localized success text. `gpresult /r` is a summary; detailed GPO inspection and MDM per-setting reports may be needed. DeviceGuard arrays contain documented numeric service identifiers, not Boolean pass/fail fields. `Get-Smb*Configuration` describes configuration, not the negotiated security of every active connection. Do not publish real usernames, domain names, or management reports in training notes.

### Drift Signals and Actual KQL

Security event 4719 records audit policy changes, not necessarily weakening. Microsoft's event documentation states it is logged regardless of the Audit Policy Change subcategory setting; forwarding, retention, access, and source health still determine whether it is searchable. Preserve provider, channel, host, UTC time, event version/record ID, subject, subcategory GUID, and change codes. Resource strings such as `%%...` are not stable English sentences to search with a substring.

Sentinel reference query below assumes Security events routed into `WindowsEvent`, with named XML fields retained in dynamic `EventData`. A `SecurityEvent` deployment needs a separate field mapping, not just a table rename. This creates a review queue; it neither proves baseline drift nor reports completely missing devices.

```kusto
WindowsEvent
| where TimeGenerated > ago(1d)
| where Provider == "Microsoft-Windows-Security-Auditing" and Channel == "Security"
| where EventID == 4719
| extend SubjectSid=tostring(EventData.SubjectUserSid),
		 SubcategoryGuid=tostring(EventData.SubcategoryGuid),
		 Changes=tostring(EventData.AuditPolicyChanges)
| extend Quality=iff(isempty(SubcategoryGuid) or isempty(Changes), "mapping-review", "usable")
| project TimeGenerated, Computer, EventID, SubjectSid, SubcategoryGuid, Changes, Quality
```

Correlate candidates with an approved change and before/after effective audit policy. Approved GPO refreshes can produce records; a SYSTEM subject does not make the change benign automatically. Use host/channel/log-generation/record identity for deduplication, separate event time from ingestion time, and retain an expected-device inventory plus collection freshness. No recent change event can mean stable configuration, not an unhealthy collector; change events are not heartbeats.

### Staging, Verification, and Rollback

1. Select the exact baseline/role; retain original artifact, review notes, setting-level diff, authority and applicability.
2. Capture authorized prechange policy/runtime evidence and representative workflow results. Define security checks, propagation deadlines, restart requirements and rollback triggers before approval.
3. Use lab/pilot/ring deployment through the owning management plane. This note provides no deployment commands; the offline exercise changes only dictionaries.
4. Verify resultant settings and runtime evidence, then logon, updates, business apps, telemetry and recovery. Configuration compliance alone cannot pass the rollout gate.
5. On a failed gate, hold wider rollout. An approved recovery restores reviewed prior values/assignments using the appropriate authority, with evidence and retests. Unassigning a profile or selecting Not configured is not a universal reset; removal behavior depends on the setting/provider.
6. Monitor drift after refresh, reboot, upgrade, app changes and exception expiry. Preserve the old and new snapshots; a newer baseline changes expected state and should not rewrite historical evidence.

## Gotchas

- More restrictive is not automatically more secure when it breaks updates, logging, recovery or the management channel. Never modify corporate/VPN settings to make an exercise match a baseline.
- A device reporting nothing cannot be dropped from the denominator. A Boolean string such as `"False"` must not be coerced with Python `bool`, which would make it true.
- Baselines do not fix excessive directory/data permissions, vulnerable applications, every identity risk, or unobserved behavior. A compliant snapshot is time-bound evidence for defined settings only.

## Labs

### Environment and Complete Files

Offline drift and release-gate lab. Python 3.12 standard library only, no packages. In a fresh scratch folder outside the vault, create the single file below from its complete fence. All baseline, snapshot, workflow and seed data are embedded; no other file is required. `training-r1` is a three-control teaching subset, NOT a Microsoft baseline package or actual Defender/WDAC/Sysmon enforcement test. The Python process never reads system policy, registry, services, files, network or credentials.

### File: test_example.py

```python
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
EXPECTED = {"lab-a", "lab-b"}
BASELINE = {
	"revision": "training-r1", "release": "fixture-release-A", "role": "workstation",
	"settings": {"smb_signing_required": True, "audit_process_success": True,
				 "local_admins": ["training-admin"]},
}
GOOD = {
	"revision": "training-r1", "release": "fixture-release-A", "role": "workstation",
	"seen": NOW, "settings": deepcopy(BASELINE["settings"]),
}
SNAPSHOTS = {"lab-a": deepcopy(GOOD), "lab-b": deepcopy(GOOD)}
SNAPSHOTS["lab-b"]["settings"]["smb_signing_required"] = False
WORKFLOWS = {"logon": True, "updates": True, "business_app": True,
			 "telemetry": True, "recovery": True}


def assess(snapshot):
	if snapshot is None:
		return {"snapshot": "missing"}
	if any(snapshot.get(key) != BASELINE[key] for key in ("revision", "release", "role")):
		return {"snapshot": "contract-mismatch"}
	seen = snapshot.get("seen")
	if not isinstance(seen, datetime) or seen.tzinfo is None or seen.utcoffset() is None:
		return {"snapshot": "time-invalid"}
	if not NOW - timedelta(minutes=30) <= seen <= NOW:
		return {"snapshot": "stale-or-future"}
	settings = snapshot.get("settings")
	if not isinstance(settings, dict):
		return {"snapshot": "schema-invalid"}
	result = {}
	for control, wanted in BASELINE["settings"].items():
		actual = settings.get(control)
		if type(actual) is not type(wanted):
			result[control] = "unknown"
		elif isinstance(wanted, list):
			if not all(isinstance(member, str) and member for member in actual):
				result[control] = "unknown"
			elif len(actual) != len(set(actual)):
				result[control] = "unknown"
			else:
				result[control] = "compliant" if set(actual) == set(wanted) else "drift"
		else:
			result[control] = "compliant" if actual == wanted else "drift"
	return result


def gate(expected, snapshots, workflows):
	if not expected:
		return "hold-inventory"
	for device in expected:
		if any(state != "compliant" for state in assess(snapshots.get(device)).values()):
			return "hold-evidence"
	if any(workflows.get(name) is not True for name in WORKFLOWS):
		return "hold-compatibility"
	return "ready-in-model"


class BaselineTests(unittest.TestCase):
	def test_baseline_drift_and_fixed_retest(self):
		self.assertEqual(assess(SNAPSHOTS["lab-b"])["smb_signing_required"], "drift")
		self.assertEqual(gate(EXPECTED, SNAPSHOTS, WORKFLOWS), "hold-evidence")
		repaired = deepcopy(SNAPSHOTS)
		repaired["lab-b"]["settings"]["smb_signing_required"] = True
		self.assertEqual(gate(EXPECTED, repaired, WORKFLOWS), "ready-in-model")
		self.assertFalse(SNAPSHOTS["lab-b"]["settings"]["smb_signing_required"])

	def test_missing_and_contract_mismatch(self):
		self.assertEqual(assess(None), {"snapshot": "missing"})
		for field in ("revision", "release", "role"):
			with self.subTest(field=field):
				self.assertEqual(assess(dict(GOOD, **{field: "other"})),
								 {"snapshot": "contract-mismatch"})
		self.assertEqual(gate(EXPECTED, {"lab-a": GOOD}, WORKFLOWS), "hold-evidence")

	def test_time_boundaries(self):
		for seen in (NOW - timedelta(minutes=31), NOW + timedelta(seconds=1)):
			self.assertEqual(assess(dict(GOOD, seen=seen)), {"snapshot": "stale-or-future"})
		self.assertEqual(assess(dict(GOOD, seen=NOW.replace(tzinfo=None))),
						 {"snapshot": "time-invalid"})
		boundary = assess(dict(GOOD, seen=NOW - timedelta(minutes=30)))
		self.assertEqual(set(boundary.values()), {"compliant"})

	def test_missing_types_and_privilege_drift(self):
		for actual, expected in ((None, "unknown"), ("True", "unknown"), (1, "unknown")):
			changed = deepcopy(GOOD)
			changed["settings"]["audit_process_success"] = actual
			self.assertEqual(assess(changed)["audit_process_success"], expected)
		changed = deepcopy(GOOD)
		changed["settings"]["local_admins"].append("unexpected-admin")
		self.assertEqual(assess(changed)["local_admins"], "drift")
		changed["settings"]["local_admins"] = ["training-admin", "training-admin"]
		self.assertEqual(assess(changed)["local_admins"], "unknown")

	def test_compatibility_and_snapshot_rollback(self):
		repaired = {device: deepcopy(GOOD) for device in EXPECTED}
		for name in WORKFLOWS:
			with self.subTest(workflow=name):
				self.assertEqual(gate(EXPECTED, repaired, dict(WORKFLOWS, **{name: False})),
								 "hold-compatibility")
		self.assertEqual(gate(EXPECTED, repaired, {}), "hold-compatibility")
		self.assertEqual(gate(set(), {}, WORKFLOWS), "hold-inventory")
		restored = deepcopy(SNAPSHOTS)
		self.assertEqual(gate(EXPECTED, restored, WORKFLOWS), "hold-evidence")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Identify the baseline drift and predict why the release gate holds. Explain why a missing second device cannot be interpreted as compliant.
2. From the scratch directory, run the commands below when the parent/user authorizes execution. The only required runtime is existing Python 3.12; install nothing for this exercise.
3. Inspect the supplied fixed retest and compatibility failures. Explain why restoring the earlier snapshot also restores its unresolved finding rather than making it secure.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Evaluate identity/version and time before settings. Compare Boolean types exactly, not by truthiness. A missing workflow result is not a passed workflow. Snapshot restoration is a recovery action, not an automatic compliance decision.

### Solution and Expected Results

Designed expectation: five tests, `OK`; no author execution is claimed. `lab-a` has three compliant fields. `lab-b` has signing drift, so the baseline gate is `hold-evidence`. Changing that one synthetic value in a deep copy produces `ready-in-model` while preserving the original evidence. Breaking any required workflow yields `hold-compatibility`, even when every setting matches. Returning to the original snapshot yields `hold-evidence` again. The model never changes Windows SMB, audit policy, memberships or recovery state.

### Verification, Troubleshooting, and Cleanup

Acceptance covers drift/fix, missing inventory, version/role mismatches, exact freshness boundary, future/naive time, missing/wrong-type data, unexpected privilege, duplicated members and compatibility. These tests certify only the printed evaluator on its fixtures. They do not execute PowerShell/KQL, load a baseline, prove runtime enforcement, or validate real GPO/MDM precedence. Real adapters must validate provenance, extract typed fields, preserve collection errors and handle nested groups separately.

If `py` is unavailable, use an existing Python 3.12 executable with `-B -m unittest -v test_example`; do not install dependencies or alter controls to resolve a model failure. Import failure usually means the wrong directory or a filename other than `test_example.py`. Use separate scratch folders for each note because they intentionally reuse that test filename. `-B` avoids bytecode artifacts. Remove only the supplied scratch file after leaving the exercise:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

The original items below are unchanged. They describe separate live-VM work; this offline lab does not authorize or complete policy deployment, service changes, or host deviations.

- [ ] Local Windows Hardening Baselines exercise: Apply a current matching Microsoft baseline to a disposable role-specific VM after recording its initial state. Test logon, updates, recovery, and the expected security controls.
- [ ] Boundary check: Introduce one harmless controlled deviation in the test VM, verify drift detection, restore the intended setting, and rerun both security and compatibility checks.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Windows Hardening Baselines Security]]

## References

- [Microsoft security baseline principles and applicability](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Security Compliance Toolkit, Policy Analyzer, and LGPO](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [MDMWinsOverGP and its Policy CSP boundary](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-controlpolicyconflict)
- [gpresult resultant-policy inspection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [Audit policy change event 4719](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719)
- [WindowsEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent)
- [Verify VBS and memory integrity status](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [SMB signing behavior and version differences](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
