---
title: "AppLocker and WDAC"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[AppLocker and WDAC Security]]"
updated: 2026-11-03
---
# AppLocker and WDAC

> [!abstract] TL;DR
> AppLocker scopes application rules to users/groups and collections; App Control for Business (WDAC) enforces device-wide code trust. Audit is evidence gathering, not blocking. Model policy identity, trust, deployment, and outcome separately before approving enforcement.

> [!info] Agent scope
> Application-control policy; rule types; audit and enforcement; signing trust; deployment; exceptions; controlled limitation tests.

## Prerequisites

- Windows users/groups, ACLs, signatures, services, and event logs; distinguish file identity from behavior.
- Offline lab: Python 3.12 standard library only. No Windows feature, signer certificate, executable, policy installation, administrator access, or network.
- Real deployments require supported OS/edition/build, an authoritative policy owner, application inventory, tested recovery, and a separately approved rollout. Record whether policies are single/multiple format, signed, and audit/enforced.

## Learn

```text
Teach me AppLocker and App Control for Business, formerly WDAC, at expert Windows
policy-engineering depth. Assume ACL, signing, user/group, and event-log knowledge.
Compare enforcement boundaries, AppLocker collections/Application Identity service,
device-wide WDAC UMCI/KMCI, signed policy lifecycle, rule precedence, publisher,
FilePublisher, version, path, hash, managed-installer and reputation trust.
Explain current edition/build prerequisites, default runtime FilePath protection,
multiple base-policy intersection and supplemental-policy expansion, audit versus
enforcement, script-host behavior, and recovery/compatibility planning.
Show concrete policy XML, supported read-only commands, CodeIntegrity/AppLocker
telemetry, actual KQL, and signature-event correlation. Explain why normal SHA256
file hashes are not automatically App Control PE hashes and why signing is not
behavioral safety. Give a complete offline synthetic policy/evidence lab with
approved, unapproved, audit-only, missing-state, and multi-policy regression cases.
Use Microsoft primary sources and label model simplifications and version limits.
Teach here, no file/status edits. Do not deploy policies, generate payloads, change
host controls/VPN, or demonstrate bypass. Offline decisions are not enforcement
tests. End with difficult questions and worked answers.
```

## Cheatsheet

### Choose the Boundary

| Dimension | AppLocker | App Control for Business / WDAC |
|---|---|---|
| Scope | Device rules can target users/groups | Device-wide code trust affects all users |
| Coverage | EXE, DLL, script, MSI, packaged-app collections, with collection-specific modes | Kernel code integrity; user-mode code with UMCI; scripts through participating hosts and policy options |
| Enforcement dependency | Application Identity service and supported deployment/OS | Code-integrity policy activation, options, signatures, and supported build |
| Rule identity | Publisher, path, hash; packaged-app publisher rules | Signer/file attributes/version/hash/path; optional managed-installer/ISG trust |
| Boundary strength | Application administration; Microsoft does not classify it as a security feature under its servicing criteria | Designed as a security feature under Microsoft's servicing criteria |
| Policy interaction | Explicit deny wins over allow; within a configured collection, unmatched files are denied in enforcement | Deny before allow; all enforced base policies must permit code, accounting for each base's supplements |

AppLocker enforcement no longer requires a particular edition on Windows 10 2004+ with the update described by KB5024351 and on Windows 11; older builds/deployment methods have different limits. Do not repeat the obsolete universal claim that only Enterprise can enforce. This is feature history, not a lifecycle guarantee for old Windows versions.

App Control is available on Windows 10/11 client editions and Server 2016+, but features vary. Multiple policy format and supplements start with Windows 10 1903 and Server 2022. User-mode FilePath rules do not allow kernel drivers. Keep current build-specific availability and policy count limits in the deployment record.

### Rule Types, Options, and Trust

| Rule/option | Benefit | Cost or boundary |
|---|---|---|
| Hash | Precise artifact authorization, including unsigned software | Updates require new rules; App Control uses Authenticode/PE-related hash semantics, not simply `Get-FileHash` output |
| Publisher | Survives many updates | Broad publisher trust admits unrelated signed products; signing is provenance, not safety |
| FilePublisher + version | Narrows signer trust to signed file identity and version range | Certificate rotation and metadata/version changes require review; validate supported signature algorithms |
| Path | Operationally convenient for controlled locations | ACLs and path semantics matter; AppLocker lacks WDAC's equivalent default runtime writeability guard |
| Managed installer | Allows artifacts installed through designated management | Installation trust and provenance handling are part of the boundary, not arbitrary future behavior |
| ISG reputation | Reduces explicit allow maintenance | Cloud/reputation dependencies and changing decisions complicate deterministic policy reasoning |
| WDAC option 0, UMCI | Extends policy to user-mode executables/scripts | Kernel-only policy is not a user-mode application allowlist |
| WDAC option 3, Audit Mode | Records would-be blocks | No equivalent binary blocking; some script/dynamic-code behaviors can still differ in audit |
| WDAC option 17 | Base permits supplements | Supplemental policies expand their associated base, not other base policies or deny rules |

WDAC runtime FilePath protection normally rejects path authorization in locations writable by non-administrative identities. Preserve that protection; do not weaken it to accommodate a path rule. Signed policy updates and supplements require correct authorized signers. Audit mode is not universally side-effect-free: script-host behavior and dynamic code security require their own compatibility checks.

### Concrete AppLocker Policy Fragment

Complete XML for one audit-only EXE collection, not a complete workstation policy. It permits a fictional admin-owned app tree for Everyone; all other EXEs are outside this collection's allow set. Do not deploy this example: it lacks operating-system, update, management, and recovery coverage. Its purpose is to show actual schema and mode syntax.

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
	<FilePathRule Id="b53acc09-12fa-4d4a-a9c2-13aad22ec760"
				  Name="Reviewed training app tree"
				  Description="Schema example only"
				  UserOrGroupSid="S-1-1-0" Action="Allow">
	  <Conditions>
		<FilePathCondition Path="C:\Program Files\TrainingApp\*" />
	  </Conditions>
	</FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

Supported authoring surfaces include AppLocker cmdlets/GPO/MDM and the App Control Policy Wizard, ConfigCI cmdlets, and ApplicationControl CSP. `New-CIPolicy`, `Set-RuleOption`, and `ConvertFrom-CIPolicy` author/compile policy artifacts; artifact creation is not policy deployment or activation. Do not hand-author an entire WDAC policy from a simplified decision table. Use reviewed official tooling and capture policy IDs, base IDs, versions, options, and signers.

Read-only inspection references for authorized Windows environments, not lab commands:

```powershell
Get-AppLockerPolicy -Effective -Xml
Get-Service -Name AppIDSvc
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3076,3077,3089,3099} -MaxEvents 30 |
	Select-Object TimeCreated,Id,RecordId,ProviderName
```

`Get-AppLockerPolicy -Effective` describes the policy mechanisms supported by that cmdlet; reconcile MDM-delivered policy through its management diagnostics rather than assuming this is a universal resultant-policy view. AppLocker `Test-AppLockerPolicy` evaluates rules against files/users; it is not proof of actual runtime WDAC enforcement. Policy presence and an AppIDSvc status are prerequisites, not successful-outcome evidence.

### Telemetry and KQL

| Channel/event | Meaning | Correlation boundary |
|---|---|---|
| AppLocker EXE and DLL 8002/8003/8004 | Allowed / audit would-block / enforced block | Correct collection and user scope required; not WDAC event IDs |
| CodeIntegrity Operational 3076/3077 | WDAC audit would-block / enforced block | Preserve policy ID, file/hash, timestamp and activity correlation |
| CodeIntegrity 3089 | Signature details, potentially multiple rows per file | Join by host and System Correlation ActivityID; do not count as separate blocked apps |
| CodeIntegrity 3099 | Policy loaded | Inspect options/version; loaded is not necessarily enforced |
| AppLocker MSI and Script 8028/8029 | App Control script/MSI audit/enforcement evidence | Host controls behavior; PowerShell may constrain language rather than refuse all execution |

CodeIntegrity does not generally log every allowed binary. Absence of 3077 therefore does not prove a successful approved launch. Script telemetry in the AppLocker channel is not automatically an AppLocker policy decision; the event ID and provider semantics matter. Some channel availability differs on Server Core.

Sentinel KQL reference requires `WindowsEvent` ingestion for CodeIntegrity. It intentionally retains raw structured data instead of guessing policy-tag field names across versions:

```kusto
WindowsEvent
| where TimeGenerated > ago(1d)
| where Provider == "Microsoft-Windows-CodeIntegrity"
| where Channel == "Microsoft-Windows-CodeIntegrity/Operational"
| where EventID in (3076, 3077, 3089, 3099)
| extend Meaning=case(EventID == 3076, "would-block", EventID == 3077, "blocked",
					   EventID == 3089, "signature-detail", "policy-loaded")
| project TimeGenerated, Computer, EventID, Meaning, EventData, SystemProperties
| order by TimeGenerated asc
```

Map policy/file fields and `SystemProperties` correlation from inspected raw XML in the actual connector. Missing fields are mapping errors or unavailable data, not evidence that a file is unsigned. Review audit hits by application owner before adding allowances; blindly trusting every observed binary turns an inventory into a policy without a trust decision.

## Gotchas

- Application identity cannot constrain all behavior of allowed software. Scripts, plugins, and dynamic content need appropriate host/policy controls and independent monitoring.
- Signed policy rollout can make recovery difficult. Before an approved production change, test update/signing/recovery procedures and required business workflows; this note supplies no deployment/removal commands.
- Multiple base policies intersect; adding a supplement to one base does not satisfy another enforced base's allow requirement.

## Labs

### Environment and Complete Files

Offline trust-decision and evidence lab. Python 3.12 standard library only. Use one scratch file outside the vault. The evaluator supports exact hash labels, explicit deny precedence, and audit/enforce mapping; it is neither an AppLocker engine nor WDAC enforcement. Hashes are synthetic labels, not real PE hashes. All data is embedded and no executable is launched.

### File: test_example.py

```python
import unittest

POLICY = {"mode": "audit", "allow": {"approved-v1", "updater-v1"}, "deny": {"retired-v1"}}


def decision(artifact, policy):
	if policy.get("mode") not in {"audit", "enforce"}:
		raise ValueError("mode")
	if not artifact:
		return "unknown"
	permitted = artifact in policy["allow"] and artifact not in policy["deny"]
	if permitted:
		return "allow"
	return "would-block" if policy["mode"] == "audit" else "block"


def wdac_evidence(event_id):
	return {3076: "would-block", 3077: "block", 3099: "loaded"}.get(event_id, "other")


def all_bases_allow(artifact, bases, supplements):
	if not bases:
		return None
	return all(artifact not in base["deny"]
			   and artifact in (base["allow"] | supplements.get(name, set()))
			   for name, base in bases.items())


class PolicyTests(unittest.TestCase):
	def test_audit_and_enforce(self):
		self.assertEqual(decision("unapproved-v1", POLICY), "would-block")
		self.assertEqual(decision("unapproved-v1", dict(POLICY, mode="enforce")), "block")

	def test_approved_workflows_survive(self):
		for mode in ("audit", "enforce"):
			for artifact in ("approved-v1", "updater-v1"):
				self.assertEqual(decision(artifact, dict(POLICY, mode=mode)), "allow")

	def test_deny_wins_and_unknown_is_not_allow(self):
		conflict = dict(POLICY, mode="enforce", allow={"retired-v1"})
		self.assertEqual(decision("retired-v1", conflict), "block")
		self.assertEqual(decision(None, POLICY), "unknown")
		with self.assertRaisesRegex(ValueError, "mode"):
			decision("approved-v1", dict(POLICY, mode="unknown"))

	def test_telemetry_meaning(self):
		self.assertEqual(wdac_evidence(3076), "would-block")
		self.assertEqual(wdac_evidence(3077), "block")
		self.assertNotEqual(wdac_evidence(3099), "block")

	def test_supplement_does_not_expand_other_base(self):
		bases = {"base-a": {"allow": {"core"}, "deny": set()},
				 "base-b": {"allow": {"core"}, "deny": set()}}
		self.assertFalse(all_bases_allow("approved-v1", bases, {"base-a": {"approved-v1"}}))
		self.assertTrue(all_bases_allow("approved-v1", bases,
									   {"base-a": {"approved-v1"}, "base-b": {"approved-v1"}}))
		self.assertTrue(all_bases_allow("core", bases, {}))
		self.assertIsNone(all_bases_allow("core", {}, {}))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Predict audit versus enforced decisions for each synthetic artifact. Identify which real event IDs are would-block, blocked, and merely loaded.
2. Run the suite in the scratch directory. Explain why an absent policy population is `None`, not universal approval.
3. Use the supplied supplement retest to show that both independent base policies must authorize the artifact. No base or supplement is installed on Windows.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Separate authorization from mode. The same nonmatching artifact yields different audit/enforce outcomes. For multiple bases, combine allowances within each base first, then intersect across bases.

### Solution and Expected Results

Expected: five tests, `OK`. Unapproved changes from `would-block` to `block` in the model; approved app and updater remain `allow`. Explicit deny beats allow. 3099 means loaded, not blocked. The first supplemental arrangement fails the second base; adding its corresponding authorization passes. Missing artifact identity remains unknown. These are logic results, not measured policy efficacy or code-integrity events.

### Verification, Troubleshooting, and Cleanup

Check audit/enforce distinction, deny precedence, valid baseline workflows, missing state, and base/supplement semantics. The model omits signatures, script-host behavior, managed installer, ISG, actual policy signing/activation, and OS rule precedence details beyond those stated. No author tests were run. Python needs no packages; use an existing Python 3.12 executable if the launcher is absent. Run in the directory containing the file. Cleanup needs no policy rollback because none was deployed:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

The original live-policy milestones remain unchanged and unchecked; this offline lab does not complete or authorize them.

- [ ] Local AppLocker and WDAC exercise: In a snapshot VM, build an audit policy around a harmless signed/unsigned toy executable pair. Review events, then enforce only after testing normal workflows and recovery.
- [ ] Boundary check: Verify the denied toy executable is blocked in enforcement mode while the approved executable and recovery workflow continue to work.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[AppLocker and WDAC Security]]

## References

- [App Control and AppLocker comparison](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview)
- [AppLocker requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker)
- [App Control policy options and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)
- [Multiple base and supplemental policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)
- [App Control event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [AppLocker event monitoring](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
