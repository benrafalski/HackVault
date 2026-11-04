---
title: "Defender and EDR Architecture"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[Defender and EDR Architecture Security]]"
updated: 2026-11-03
---
# Defender and EDR Architecture

> [!abstract] TL;DR
> Antivirus prevention, EDR collection, cloud analytics, and response are separate state machines. Prove each with its own evidence; an installed service, a healthy heartbeat, or an alert alone cannot prove the whole pipeline.

> [!info] Agent scope
> Sensors; prevention and response pipeline; telemetry; cloud and local decisions; policy; tamper protection; controlled limitation tests and defenses.

## Prerequisites

- Windows process/service and event-log fundamentals; UTC timestamps, device identity, and basic KQL.
- The offline lab needs only Python 3.12 standard library, a writable scratch folder, and no administrator rights, tenant, network, or endpoint product.
- Product references assume a supported Windows build. Record OS edition/build, AV platform/engine/intelligence versions, sensor version, onboarding, license, policy authority, and timestamp before interpreting real evidence. Server onboarding and feature parity differ from clients.

## Learn

```text
Teach me Microsoft Defender Antivirus and Defender for Endpoint architecture at
expert engineering depth. Assume Windows process/service, event-log, and basic
KQL knowledge. Separate file/content scanning, AMSI's supported content-scanning
interface, behavior sensors, local prevention, cloud verdicts, EDR telemetry,
analytics, incidents, and response. Explain active/passive AV and EDR block mode;
client/server, licensing, onboarding, engine/platform, and connectivity differences.
Trace policy assignment -> effective settings -> decision -> local evidence ->
transport -> normalized event -> alert -> response authorization -> completion.
Give supported read-only APIs and queries, stable event identities, health and
latency contracts, retention/deduplication pitfalls, RBAC and privacy tradeoffs.
Use complete offline synthetic fixtures to distinguish collection loss, stale
health, no match, prevention, and response failure while preserving benign cases.
Explain tamper protection without changing it. Do not equate no alerts with safety
or infer undocumented sensor internals. Cite current public Microsoft sources,
label version-dependent claims, and provide hard questions with worked answers.
Teach in this conversation; do not edit files or study status. No actual attacks,
evasion, patching, credential access, host-control or VPN changes. Do not invent
execution results; offline evaluations are not product-enforcement tests.
```

## Cheatsheet

### Pipeline and Evidence Boundaries

| Stage | Mechanism and useful evidence | What it cannot establish |
|---|---|---|
| Content inspection | Defender AV scans files/content; applications can submit buffers through supported AMSI interfaces such as `AmsiScanBuffer`; platform, engine, and intelligence have separate versions | Not every application uses AMSI; an AMSI result is not a universal execution policy |
| Local prevention | Real-time/behavior protection and applicable ASR rules make local decisions; cloud protection can enrich decisions | Onboarding is not proof AV is primary or a particular rule applies |
| Sensor | MDE endpoint sensors produce product telemetry; some signals originate from OS facilities | A product record does not identify a unique internal sensor unless documented |
| Transport | Endpoint buffers and sends through supported service connectivity; proxy/TLS/network conditions affect delivery | Local evidence need not arrive centrally immediately or at all |
| Analytics | Normalized events feed detections; alerts can aggregate evidence across time and devices | One event need not yield an alert; alert creation need not be synchronous |
| Response | Authorized action is queued, delivered, executed, and reported; Action center/API state supplies evidence | Accepted/queued is not completed; completed is not proof all related risk is removed |

Keep event time, collection/ingestion time, alert time, and action completion time separate. A five-minute alert delay could be transport, scheduled analytics, or correlation waiting, not necessarily a sensor fault. Clock skew can create apparently negative latency; quarantine such measurements instead of clamping them silently.

### Modes, Policy, and Supported Surfaces

| State/control | Interpretation | Decision consequence |
|---|---|---|
| AV active (`AMRunningMode` normally `Normal`) | Defender is primary antivirus | Still verify real-time protection, updates, exclusions, and rule-specific applicability |
| AV passive | Coexistence/onboarding-dependent mode; not ordinary AV real-time blocking | Never label passive AV equivalent to active AV; DLP-specific activity is not AV enforcement |
| EDR in block mode | Eligible MDE configuration uses Defender components for post-breach remediation, including with another primary AV | Does not supply every active-AV capability or make ASR universally effective |
| Tamper protection | Protects selected security settings against unauthorized changes; management source and product version matter | A requested setting may not become effective; inspect supported reports, never disable protection to test |
| Exclusions | AV, ASR, EDR indicators, and other exception mechanisms have different scopes | Never assume an AV exclusion removes all EDR telemetry or an EDR allow indicator permits every operation |
| Management | Intune, supported MDE security-settings management, Configuration Manager, or GPO | Record assignment, resultant state, conflicts, and source; no universal precedence shortcut |

AV is included with supported Windows editions; MDE capabilities, hunting, response, and server entitlements depend on the subscribed plan and onboarding path. Older server support may require the modern unified solution. A historical OS support entry is not a lifecycle/support guarantee in November 2026.

Read-only reference commands, not lab prerequisites; use only where inspection is authorized. The Windows Defender module is normally available through Windows PowerShell on an installed supported system. These commands do not change protection:

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,AMProductVersion,AMEngineVersion,AntivirusSignatureVersion,AntivirusSignatureLastUpdated
Get-MpPreference | Select-Object MAPSReporting,SubmitSamplesConsent,ExclusionPath,ExclusionProcess
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,5007} -MaxEvents 30 |
	Select-Object TimeCreated,Id,RecordId,ProviderName
```

Local Defender Operational 1116 records a detection, 1117 an action, and 5007 a configuration change. Read event details and result/error fields; 1117 alone does not mean every action succeeded. Exclusion paths can be sensitive: do not publish actual inventories. `Get-MpPreference` is one view, not a complete proof of applied tenant policy.

The documented MDE machine, alert, and machine-action APIs support inventory and response integration with scoped OAuth permissions. Separate read-only collection credentials from response principals; apply device-group RBAC, approval, rate-limit/backoff, pagination, and audit retention. Do not place tokens in scripts or lab data.

### KQL: Latest Sensor State Against an Expected Inventory

Defender XDR Advanced Hunting reference. The synthetic expected inventory is deliberately included: querying `DeviceInfo` alone cannot find devices that never reported. Replace it with an authoritative, access-controlled inventory for production, including device-ID merge/reimage handling. The 2-hour freshness threshold and 7-day lookup are illustrative service objectives, not Microsoft defaults.

```kusto
let Expected = datatable(DeviceId:string) ["lab-a", "lab-b", "lab-c"];
let Latest = DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId;
Expected
| join kind=leftouter Latest on DeviceId
| extend Coverage = case(
	isnull(Timestamp), "missing",
	Timestamp > now() + 5m, "clock-error",
	Timestamp < ago(2h), "stale",
	OnboardingStatus != "Onboarded", "not-onboarded",
	isempty(SensorHealthState), "unknown-health",
	SensorHealthState != "Active", "degraded",
	"reporting")
| project DeviceId, DeviceName, Timestamp, OnboardingStatus, SensorHealthState, Coverage
```

Confirm actual enum values in your tenant schema. `DeviceInfo.IsExcluded` concerns vulnerability-management experiences, not AV exclusions. This query measures inventory/health evidence, not AV prevention. Data can be restricted by RBAC; unseen devices may be out of scope rather than absent from the service. Missing tables require deployment/entitlement investigation, not treating an empty result as success.

### Decision Checklist

For a documented evaluation, require an expected device and UTC interval, exact effective policy revision, expected local event, expected central schema/fields, a measured delivery deadline, and a separate expected outcome. Retain raw event XML plus normalized rows when authorized. Deduplicate using a source-specific identity: Defender hunting `ReportId` needs device/time context, not a global standalone key. Keep health alerts separate from behavior alerts so collection failures are not hidden by detection tuning.

## Gotchas

- Local protection can continue while cloud connectivity is impaired, but cloud-dependent decisions and remote response can degrade. Never disconnect a VPN or alter proxies to manufacture this condition; use synthetic timestamps.
- Benign administrative tools generate security-relevant telemetry. An observation is not a maliciousness verdict.
- Retention, sampling/product filtering, late arrival, privacy restrictions, and role scoping limit retrospective reconstruction. Preserve these as unknowns in a report.

## Labs

### Environment and Complete Files

Offline pipeline accounting, not Defender execution or enforcement. Python 3.12, standard library only; all fixture data is embedded in the one file below. Work in a new scratch folder outside the vault. No installs, services, network calls, credentials, or Windows APIs are used. The function treats `alert` and `response` as synthetic records, not vendor field names.

### File: test_example.py

```python
import unittest
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
FRESHNESS = timedelta(minutes=15)
DEVICES = {
	"lab-a": {"seen": NOW, "onboarded": True, "health": "Active"},
	"lab-b": {"seen": NOW - timedelta(hours=1), "onboarded": True, "health": "Active"},
}
EVENTS = [
	{"device": "lab-a", "id": "marker-1", "stage": "local"},
	{"device": "lab-a", "id": "marker-1", "stage": "central"},
	{"device": "lab-a", "id": "marker-1", "stage": "central"},
	{"device": "lab-a", "id": "marker-1", "stage": "alert"},
	{"device": "lab-a", "id": "marker-1", "stage": "response", "status": "queued"},
	{"device": "lab-a", "id": "marker-2", "stage": "local"},
	{"device": "lab-a", "id": "benign", "stage": "local"},
	{"device": "lab-a", "id": "benign", "stage": "central"},
]


def assess(device, marker, devices, events, expect_alert):
	state = devices.get(device)
	if state is None:
		return "missing-device"
	if state["seen"] > NOW:
		return "clock-error"
	if NOW - state["seen"] > FRESHNESS:
		return "stale-device"
	if not state["onboarded"] or state["health"] != "Active":
		return "unhealthy-device"
	selected = [event for event in events
				if event["device"] == device and event["id"] == marker]
	stages = {event["stage"] for event in selected}
	if "local" not in stages:
		return "missing-local"
	if "central" not in stages:
		return "collection-gap"
	if not expect_alert:
		return "observed-benign"
	if "alert" not in stages:
		return "analytic-gap"
	if not any(event["stage"] == "response" and event.get("status") == "completed"
			   for event in selected):
		return "response-incomplete"
	return "pipeline-complete"


class PipelineTests(unittest.TestCase):
	def test_baseline_and_completed_response(self):
		self.assertEqual(assess("lab-a", "marker-1", DEVICES, EVENTS, True),
						 "response-incomplete")
		repaired = EVENTS + [{"device": "lab-a", "id": "marker-1",
							  "stage": "response", "status": "completed"}]
		self.assertEqual(assess("lab-a", "marker-1", DEVICES, repaired, True),
						 "pipeline-complete")

	def test_collection_and_analytic_are_distinct(self):
		self.assertEqual(assess("lab-a", "marker-2", DEVICES, EVENTS, True),
						 "collection-gap")
		repaired = EVENTS + [{"device": "lab-a", "id": "marker-2", "stage": "central"}]
		self.assertEqual(assess("lab-a", "marker-2", DEVICES, repaired, True),
						 "analytic-gap")

	def test_missing_stale_and_future(self):
		self.assertEqual(assess("lab-c", "marker-1", DEVICES, EVENTS, True), "missing-device")
		self.assertEqual(assess("lab-b", "marker-1", DEVICES, EVENTS, True), "stale-device")
		future = {"lab-a": dict(DEVICES["lab-a"], seen=NOW + timedelta(seconds=1))}
		self.assertEqual(assess("lab-a", "marker-1", future, EVENTS, True), "clock-error")

	def test_benign_and_duplicate_invariance(self):
		for rows in (EVENTS, EVENTS + EVENTS):
			self.assertEqual(assess("lab-a", "benign", DEVICES, rows, False),
							 "observed-benign")

	def test_health_and_local_evidence(self):
		degraded = {"lab-a": dict(DEVICES["lab-a"], health="ImpairedCommunication")}
		self.assertEqual(assess("lab-a", "marker-1", degraded, EVENTS, True),
						 "unhealthy-device")
		self.assertEqual(assess("lab-a", "absent", DEVICES, EVENTS, True), "missing-local")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Put the complete file in the scratch folder. Predict the result for `marker-1`, `marker-2`, `benign`, `lab-b`, and absent `lab-c` before running it.
2. From that folder run the commands below. They are reader instructions, not author-executed results.
3. Explain why adding central delivery for `marker-2` still does not satisfy its alert expectation. Explain why duplicating central rows cannot complete response.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Follow the first unsatisfied prerequisite. Device health gates interpretation; a queued response has not crossed the completion boundary. For benign input, no alert is expected, but local and central evidence still are.

### Solution and Expected Results

Expected: five tests, `OK`. Initial labels are `response-incomplete`, `collection-gap`, `observed-benign`, `stale-device`, and `missing-device`. The supplied retests add only in-memory synthetic evidence: completion fixes the first case; central delivery advances the second to `analytic-gap`. No host is contacted or protected by these changes.

### Verification, Troubleshooting, and Cleanup

Acceptance: all five tests pass; the benign workflow stays observed; duplicate delivery changes no verdict; future time is a clock error. These are designed expectations, not measured author results. A missing Python launcher requires an existing Python 3.12 executable (`python -B -m unittest -v test_example`); no third-party packages are needed. Discovery errors mean the shell is not in the file's directory. Keep timezone-aware UTC values when extending fixtures. Delete only the scratch file after leaving the exercise; `-B` avoids bytecode artifacts:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

The original milestones below remain unchanged and unchecked. This offline lab does not fulfill their live-device evidence requirements; they are not instructions to change host controls during this exercise.

- [ ] Local Defender and EDR Architecture exercise: In an authorized test device/tenant, trace a vendor-provided benign evaluation from endpoint event through collection and alert. Record policy, licensing, delay, and cleanup without changing corporate settings.
- [ ] Boundary check: Run an approved benign evaluation and confirm the expected event and alert on the test device; distinguish a missing rule from a missing sensor event.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Defender and EDR Architecture Security]]

## References

- [Microsoft Defender for Endpoint capabilities and licensing](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint)
- [Defender Antivirus compatibility and modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [DeviceInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)
- [Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Management and automation APIs](https://learn.microsoft.com/en-us/defender-endpoint/api/management-apis)
- [AMSI interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
