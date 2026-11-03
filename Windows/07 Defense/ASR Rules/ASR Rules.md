---
title: "Attack Surface Reduction Rules"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[ASR Rules Security]]"
updated: 2026-11-03
---
# Attack Surface Reduction Rules

> [!abstract] TL;DR
> ASR constrains particular behaviors under rule-specific prerequisites. Verify GUID, effective mode, applicability, exclusions, and actual outcome separately. Audit records are not blocks; a block need not create an EDR alert or user notification.

> [!info] Agent scope
> Rule behavior; prerequisites; audit versus block; exclusions; compatibility; telemetry; test plans and compensating controls.

## Prerequisites

- Defender AV mode/policy basics, Windows event logs, application compatibility, and UTC evidence correlation.
- Offline lab: Python 3.12 standard library only; no Defender, Office, tenant, administrator privileges, network, or generated behavior.
- Real ASR requires a supported OS and applicable Defender AV state; rule-specific dependencies include cloud protection, AMSI, RPC, and application installation details. Reporting/management entitlement is separate from local rule availability.

## Learn

```text
Teach me Microsoft Defender Attack Surface Reduction rules at expert operational
depth. Assume Defender mode, event-log, and Windows policy knowledge. Explain
rule GUID identity, behavior boundaries, active AV and per-rule cloud/AMSI/RPC/app
prerequisites, OS/server support, audit/block/warn semantics, and reporting licenses.
Compare Office child-process, executable-content, macro API, script, reputation,
and vulnerable-driver rules without generating those behaviors. Separate prevent
file creation from driver-load protection and rule events from EDR alerts.
Show supported read-only effective-policy inspection, exact GUID/action mapping,
event 1121/1122 interpretation, KQL and Sigma source contracts, global/per-rule
exclusion distinctions, management conflicts, staged compatibility, and metrics.
Provide a complete offline synthetic policy/evidence lab with audit versus block,
missing dependencies, unsupported mode, exclusions, benign outcomes, and regression
tests. Use public Microsoft primary sources and state version-specific caveats.
Teach here, no file/status edits. No actual attacks, live rule changes, evasion,
AMSI patching, credential access, persistence, host-control or VPN changes. Offline
predicates are not ASR enforcement or a reimplementation of proprietary heuristics.
Do not fabricate results; finish with difficult questions and worked answers.
```

## Cheatsheet

### Prevention and Reporting Pipeline

Policy assignment -> effective GUID/action -> rule applicability/dependencies -> evaluated behavior -> exclusion handling -> audit/block/warn decision -> local event -> MDE ingestion/reporting -> optional alert/notification. Each arrow can fail independently. A configured GUID proves intent, not evaluation. An audit records a rule match without equivalent prevention. An EDR alert is an analytic/reporting artifact, not a required one-to-one mirror of local ASR events.

Defender AV must be in the supported primary/active configuration for ASR; passive mode and EDR in block mode are not a replacement for ASR prerequisites. Some rules add cloud protection, AMSI integration, RPC, or application requirements. License and onboarding affect advanced hunting, reporting, and management, not just whether a local GUID can be configured. Older server support may require the modern unified solution; consult the per-rule OS/deployment-method matrix.

### Selected Rules and Meaningful Differences

This is a scoped engineering selection, not an assertion that all rules share behavior or support. Names/GUIDs are from Microsoft's rule reference; recheck it for the target build and platform version.

| Rule and GUID | Scope/dependency beyond the common baseline | Practical distinction |
|---|---|---|
| Office child processes `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Participating Office apps; documented installation-location requirement | A process-start record alone does not encode every ASR eligibility condition |
| Office executable content `3b576869-a4ec-4529-8536-b80a7769e899` | Defender AV and RPC | Different from child-process control; rule-specific exclusion support |
| Office process injection `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` | Documented Office scope/install location; app restart required after configuration changes | Warn unsupported; no injection exercise is supplied |
| Office macro Win32 API calls `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | Defender AV and AMSI; client/server support differs | Not a general ban on every Win32 call by Office |
| Potentially obfuscated scripts `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Defender AV, AMSI, cloud protection | Heuristic evaluation; benign commercial scripts can require review |
| Prevalence/age/trusted-list executable rule `01443614-cd74-433a-b99e-2ecdc07bfc25` | Cloud protection | Newly released legitimate software can be affected; not a deterministic signer allowlist |
| Advanced ransomware protection `c1db55ab-c21a-4637-bb3f-a12568109d35` | Cloud protection and rule-specific heuristics | Not equivalent to Controlled Folder Access or universal ransomware prevention |
| Vulnerable signed driver rule `56a863a9-875e-4185-98a7-b882c64b5ce5` | Rule-specific supported platform/configuration | Prevents saving covered vulnerable drivers; does not block loading every already-present driver |

For Office child-process scope, the current reference requires Office in `%ProgramFiles%` or `%ProgramFiles(x86)%`; treat unsupported installations as coverage gaps needing supported remediation, not as limitation-test execution targets. For driver load assurance, separately review the vulnerable-driver blocklist and App Control configuration/evidence.

### Modes and Configuration Authority

| Action value | Meaning | Evidence requirement |
|---|---|---|
| `0` Disabled | Rule not providing prevention | Must not be scored as protected |
| `1` Enabled/block | Matched applicable behavior is prevented under rule semantics | Policy + applicable prerequisite state + action outcome |
| `2` Audit | Match recorded without equivalent block | Would-block evidence and compatibility observation |
| `6` Warn | Supported rules can present a warning/temporary user continuation path | Not equivalent to block; support and notifications vary by rule/build |

Absent/not-configured is not always synonymous with disabled: effective state can come from another management source. Avoid combining raw source policies by a guessed universal precedence. Resolve conflicts through the owning Intune, supported MDE security-settings management, Configuration Manager, GPO, or CSP workflow. Preserve GUID/action pairing; arrays must have matching lengths and no duplicate GUID ambiguity.

Supported read-only inspection reference for authorized Windows PowerShell with the Defender module. It prints configuration evidence and refuses to silently truncate mismatched arrays. It changes no settings:

```powershell
$preferences = Get-MpPreference
$ruleIds = @($preferences.AttackSurfaceReductionRules_Ids)
$actions = @($preferences.AttackSurfaceReductionRules_Actions)
if ($ruleIds.Count -ne $actions.Count) { throw 'ASR GUID/action length mismatch' }
for ($index = 0; $index -lt $ruleIds.Count; $index++) {
	[pscustomobject]@{ RuleId=$ruleIds[$index]; Action=$actions[$index] }
}
Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AMProductVersion,AMEngineVersion
```

ASR-specific exclusions are distinct from Defender AV exclusions. Global ASR exclusions can affect multiple rules; per-rule exclusions and supported matching behavior vary by rule and management surface. Some rules have limited exclusion support. Record the exact rule, file/folder scope, management mechanism, owner, reason, expiry, and residual risk. Do not copy AV exclusions into ASR or infer that a signed file is automatically exempt.

### Telemetry and Query Contract

Defender Operational 1121 records an ASR block; 1122 records an audit. Preserve rule GUID, process/file, user/device, and UTC time from raw XML, respecting privacy. Event 5007 can report configuration change, not the success of the expected rule behavior. Warn-related reporting varies; use the documented ActionType for the selected rule rather than assigning a generic invented event.

Defender XDR Advanced Hunting reference using documented Office child-process ActionTypes. Requires MDE onboarding and hunting entitlement/RBAC plus `DeviceEvents`. These event types need not create an EDR alert. The query preserves `AdditionalFields` because its rule-specific contents must be checked against actual rows.

```kusto
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType in ("AsrOfficeChildProcessAudited", "AsrOfficeChildProcessBlocked")
| extend Outcome=iff(ActionType == "AsrOfficeChildProcessBlocked", "blocked", "audited")
| project Timestamp, DeviceId, DeviceName, ReportId, ActionType, Outcome,
		  FileName, FolderPath, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

Use the Advanced Hunting schema pane to verify fields and available ActionTypes. Missing rows can mean no matching behavior, unsupported rule, mode, exclusions, stale device, retention, role scope, or collection loss. Do not infer exclusion coverage from event counts alone. Match event identities with device/time context; count distinct devices and affected application versions separately from repeated event records.

### Rollout and Compatibility

Inventory -> supported prerequisites -> approved test matrix -> staged policy -> effective-state verification -> audit analysis where appropriate -> scoped exception review -> approved enforcement -> ongoing drift/compatibility monitoring. Existing protections remain intact in this note; there are no live mode-changing commands. Compatibility cases must include document opening/saving, line-of-business integrations, updates, accessibility, management, and recovery relevant to the selected rule. A zero-event audit interval without representative workflows proves little.

## Gotchas

- A block can deny an operation while the initiating application continues running; process survival does not disprove a rule's effect.
- Warn is not supported by every rule. Never silently map unsupported warn to block or audit in an assurance report.
- Cloud-dependent decisions may change with reputation and connectivity; preserve platform/intelligence versions and prerequisites without disconnecting the network to test.

## Labs

### Environment and Complete Files

Offline prerequisite/mode evaluator. Python 3.12 standard library only, one file in a new scratch folder outside the vault. The fixture's `matched` input is a supplied synthetic fact; the program does not implement ASR behavior heuristics or launch an Office/script/driver operation. `excluded` represents a reviewed exclusion already determined applicable by the fictional contract, not universal ASR exclusion semantics.

### File: test_example.py

```python
import unittest

OFFICE_CHILD = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
REPUTATION = "01443614-cd74-433a-b99e-2ecdc07bfc25"
OFFICE_MEMORY = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
RULES = {
	OFFICE_CHILD: {"cloud": False, "warn": True},
	REPUTATION: {"cloud": True, "warn": True},
	OFFICE_MEMORY: {"cloud": False, "warn": False},
}
DEVICE = {"supported": True, "active_av": True, "cloud": True, "applicable": True}


def evaluate(rule_id, mode, device, matched, excluded=False):
	rule = RULES.get(rule_id)
	if rule is None:
		return "unknown-rule", None
	if mode not in {0, 1, 2, 6}:
		return "unknown-mode", None
	if mode == 6 and not rule["warn"]:
		return "unsupported-mode", None
	if not all(device.get(field) is True for field in ("supported", "active_av", "applicable")):
		return "prerequisite-gap", None
	if rule["cloud"] and device.get("cloud") is not True:
		return "prerequisite-gap", None
	if mode == 0:
		return "inactive", None
	if excluded:
		return "excluded-in-model", None
	if not matched:
		return "allowed-no-match", None
	return {1: ("blocked-in-model", 1121), 2: ("audited-in-model", 1122),
			6: ("warned-in-model", None)}[mode]


class AsrTests(unittest.TestCase):
	def test_audit_and_block_retest(self):
		self.assertEqual(evaluate(OFFICE_CHILD, 2, DEVICE, True), ("audited-in-model", 1122))
		self.assertEqual(evaluate(OFFICE_CHILD, 1, DEVICE, True), ("blocked-in-model", 1121))

	def test_benign_stays_allowed(self):
		for mode in (1, 2, 6):
			self.assertEqual(evaluate(OFFICE_CHILD, mode, DEVICE, False), ("allowed-no-match", None))

	def test_prerequisites_are_rule_specific(self):
		no_cloud = dict(DEVICE, cloud=False)
		self.assertEqual(evaluate(REPUTATION, 1, no_cloud, True), ("prerequisite-gap", None))
		self.assertEqual(evaluate(OFFICE_CHILD, 1, no_cloud, True), ("blocked-in-model", 1121))
		self.assertEqual(evaluate(OFFICE_CHILD, 1, dict(DEVICE, active_av=False), True),
						 ("prerequisite-gap", None))

	def test_unknown_and_unsupported_are_not_blocks(self):
		self.assertEqual(evaluate(OFFICE_MEMORY, 6, DEVICE, True), ("unsupported-mode", None))
		self.assertEqual(evaluate("unknown", 1, DEVICE, True), ("unknown-rule", None))
		self.assertEqual(evaluate(OFFICE_CHILD, None, DEVICE, True), ("unknown-mode", None))

	def test_exclusion_and_inactive(self):
		self.assertEqual(evaluate(OFFICE_CHILD, 1, DEVICE, True, excluded=True),
						 ("excluded-in-model", None))
		self.assertEqual(evaluate(OFFICE_CHILD, 0, DEVICE, True), ("inactive", None))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Predict separate outcomes for audit, block, benign no-match, unsupported warn, absent cloud prerequisite, and exclusion.
2. Run the exact offline suite in the scratch directory. The supplied retest changes only a function argument from audit to block.
3. Explain why the `blocked-in-model` label cannot establish real Defender prevention and why no alert is expected from this program.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

A mode value is meaningful only with rule support and applicable prerequisites. A healthy local rule can produce an event without an EDR alert. The synthetic no-match case should remain allowed in every active mode.

### Solution and Expected Results

Expected: five tests, `OK`. The matching Office-child fixture produces modeled audit/1122 or block/1121. The benign fixture stays `allowed-no-match`. Cloud absence affects the reputation fixture, not this model's Office-child fixture; passive AV fails the common prerequisite. Unsupported warn, unknown GUID, and unknown action are explicit outcomes. No rule is configured and no protected operation is attempted.

### Verification, Troubleshooting, and Cleanup

Acceptance includes positive mode mapping, benign preservation, missing prerequisites, unknown values, and exclusions. This deterministic model omits actual application installation checks, cloud verdicts, real-time engines, exclusion path matching, and telemetry delivery. All expected outputs are unexecuted author expectations. If `py` is missing use an existing Python 3.12 executable; no packages are needed. Discovery errors require the file's directory. Cleanup only the scratch file:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

Original milestones remain unchanged and unchecked. They are separate live-device work, not authorized or completed by this offline lab.

- [ ] Local ASR Rules exercise: Choose one applicable rule in an isolated managed test VM. Use Microsoft's documented benign evaluation in audit mode, review impact, then compare block mode with a rollback available.
- [ ] Boundary check: Confirm the same documented test action is observed in audit mode and prevented in block mode, without blocking the approved baseline workflow.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[ASR Rules Security]]

## References

- [ASR rule GUIDs, dependencies, OS support, and ActionTypes](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [ASR modes and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- [ASR configuration methods](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- [ASR deployment testing and reporting prerequisites](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test)
- [ASR Windows event evidence](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)
- [DeviceEvents hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
