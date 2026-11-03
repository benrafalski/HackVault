---
title: "Defender and EDR Architecture Security"
aliases: []
tags: [windows, x7, security]
domain: windows
phase: "X7"
type: security
status: draft
pair: "[[Defender and EDR Architecture]]"
updated: 2026-11-03
---
# Defender and EDR Architecture Security

> [!abstract] TL;DR
> Measure coverage against the expected fleet, not only reporting devices. Treat stale policy, missing evidence, broad exceptions, and unverified response as separate findings; preserve the distinction between an unknown outcome and a demonstrated prevention failure.

> [!info] Agent scope
> Security of sensors, prevention/response, local/cloud decisions, telemetry, policy, and tamper protection. Analyze prerequisite and coverage failures with offline synthetic evidence, not live bypass or evasion procedures.

## Attack Surface

- **Management plane:** exclusion writers, policy assignments, device groups, response roles, and application API permissions can affect many endpoints at once.
- **Evidence plane:** stale heartbeats, missing channels, clock skew, reimaged device IDs, retention, RBAC scope, and dropped/duplicated rows can bias claims.
- **Decision plane:** primary-AV mode, cloud prerequisites, platform versions, effective policy, and documented feature scope determine what a control actually prevents.
- **Response plane:** approval, device reachability, action state, and independent recovery verification determine whether a requested response completed safely.

## Learn

```text
Teach me defensive assurance for Microsoft Defender Antivirus and MDE at expert
depth. Assume Windows endpoint and event-log knowledge. Cover fleet denominators,
onboarding, AV mode versus EDR block mode, local/cloud decisions, sensor health,
tamper protection, policy authority, exception governance, RBAC, and response.
For each trust boundary distinguish configured, effective, observed, alerted,
prevented, and remediated states. Show public supported read-only inspection,
Sigma/KQL rules and exact telemetry contracts, freshness/retention assumptions,
false-positive and false-negative causes, and client/server/license prerequisites.
Give a complete offline synthetic coverage audit with a flawed metric, corrected
metric, missing/stale records, narrow time-bound exceptions, negative regression
tests, and preserved benign outcomes. Explain why an absent alert is not proof
of absence and why a queued response is not proof of remediation. Include privacy,
least-privilege administration, staged deployment, and compensating-control limits.
Use Microsoft primary sources and explicitly label unknown product internals.
Teach here without editing files or status. No actual attacks, EDR bypass,
unhooking, AMSI patching, tamper changes, credential access, persistence, VPN or
host-control changes. Offline models must not be presented as product enforcement.
```

## Cheatsheet

### Root Causes, Evidence, and Repairs

| Finding | Evidence needed before claiming it | Defensive repair and residual risk |
|---|---|---|
| Fleet blind spot | Expected active asset with no current onboarded device record after accounting for RBAC, merges, and retirement | Reconcile authoritative inventory and onboarding ownership; inventory itself can be incomplete |
| Mode mismatch | Supported status reports primary-AV/passive mode inconsistent with approved design | Correct through the owning management plane; passive EDR remediation is not all active-AV prevention |
| Policy drift | Effective revision/settings differ from intended assignment after a defined propagation interval | Resolve conflicts, unsupported settings, and assignment filters; delivery acknowledgement is not enforcement evidence |
| Excessive exclusions | Exact scope, affected control, publisher/path ownership, business reason, owner, expiry, and compensating evidence | Narrow or retire through approved policy review; do not assume one exclusion type's behavior applies to others |
| Transport gap | Local marker/evidence exists but expected central record misses a delivery SLO | Diagnose supported connectivity and collector health; never disable a VPN/firewall to test |
| Response uncertainty | Action ID is pending/failed, or post-action evidence is missing | Escalate through authorized response roles; retries need idempotency and separate outcome checks |

Tamper protection guards selected settings, not every administrative or cloud trust boundary. Do not treat it as a substitute for privileged-access governance or a guarantee of universal telemetry. Keep legitimate update and management workflows intact; use product-supported troubleshooting rather than manipulating services.

### A Defensible Coverage Metric

Report at least: expected assets, current observed assets, stale assets, unsupported assets, devices with policy drift, unknown outcomes, and explicitly evidenced healthy controls. Do not calculate fleet coverage as `healthy / devices_that_reported`: a missing device disappears from that denominator. Do not score unknown as compliant or silently exclude unsupported assets; publish them in a separate residual-risk population.

Example: three expected devices, two reporting, one policy-compliant. The flawed reporting-only metric is `1/2`; evidence-supported fleet coverage is `1/3`, with two named gaps. This is coverage of the defined evidence contract, not measured attack-prevention efficacy. A valid exception is risk acceptance, not compliance with the unmodified baseline.

### Supported Inspection and Permission Boundaries

`Get-MpComputerStatus` supplies AV mode/protection/version evidence; `Get-MpPreference` supplies configuration evidence. Neither grants a right to change tenant controls. Intune/MDE policy reports supply source, assignment, conflicts, and deployment results. MDE Advanced Hunting supplies device/alert/evidence records subject to retention and role scope. The machine-actions API/Action center supplies response state; isolate read-only roles from responders and policy authors.

Record collection errors explicitly: `AccessDenied` is insufficient permission, missing module is an environment mismatch, and an unavailable hunting table is a deployment/schema issue. None means a control is off. Avoid collecting actual command lines, usernames, or exclusion paths into public training material.

### Sigma: Configuration-Change Review Queue

This is a low-severity change-review rule, not evidence that protection was weakened. It requires the Defender Operational channel forwarded with the provider and EventID preserved. Legitimate management and platform updates commonly produce 5007; enrich with approved change windows, actor evidence where available, and effective-state comparisons instead of globally suppressing it.

```yaml
title: Defender Configuration Change Review
id: 71fba5b4-9ed8-4ceb-bbb9-6da18dbbd176
status: experimental
description: Queue Defender configuration changes for effective-policy review.
date: 2026-11-03
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5007
    condition: selection
fields:
    - Computer
    - EventID
falsepositives:
    - Approved policy and platform updates
level: low
```

The backend must map `windefend` to `Microsoft-Windows-Windows Defender/Operational`; selecting EventID 5007 across all providers is invalid. No Sigma engine is included in the offline test.

### KQL: Preserve Evidence When Correlating Alerts

Defender XDR reference, requiring `AlertInfo` and `AlertEvidence` and authorized hunting access. Keep alert identity, source, device, and event times; evidence rows can multiply one alert. A left join keeps alerts without device evidence visible.

```kusto
let Alerts = AlertInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, *) by AlertId;
let Evidence = AlertEvidence
| where Timestamp > ago(2d)
| where isnotempty(DeviceId)
| summarize Devices=make_set(DeviceId, 100), EvidenceRows=count() by AlertId;
Alerts
| join kind=leftouter Evidence on AlertId
| extend EvidenceState=iff(isnull(EvidenceRows), "no-device-evidence-in-window", "linked")
| project Timestamp, AlertId, Title, Severity, ServiceSource, Devices, EvidenceRows, EvidenceState
```

The longer evidence window reduces, but does not eliminate, timing gaps. Truncation at 100 devices must be acknowledged for large incidents. This query neither correlates response completion nor proves prevention. Missing evidence can be a non-endpoint alert, retention, permission, or delay rather than malfunction.

## Detection and Defense

Use independent health, policy, and behavior monitors. Gate changes on baseline workflows, staged assignments, rollback ownership, and security evidence. Alert on stale collection against expected inventory even when behavior detections are quiet. Require exception owner, ticket, control scope, expiry, and compensating-control evidence; never infer safety from a filename or signature alone. Keep AV intelligence current even where supported passive mode is part of the design. Reconcile local status, tenant policy, and response outcomes after upgrades.

## Labs

### Environment and Complete Files

Offline assurance CTF: find the falsely green dashboard. Python 3.12 standard library only, no product/tenant or administrator access. The only required file follows; fixtures model three expected assets, stale policy, and missing evidence. These are organization-defined fields, not an MDE API schema. No network or host settings are accessed.

### File: test_example.py

```python
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
EXPECTED = {"lab-a", "lab-b", "lab-c"}
OBSERVED = {
	"lab-a": {"seen": NOW, "revision": "r7", "mode": "Normal", "tamper": True},
	"lab-b": {"seen": NOW, "revision": "r6", "mode": "Normal", "tamper": True},
}
EXCEPTION = {"device": "lab-b", "control": "policy-revision", "owner": "training-team",
			 "ticket": "LAB-17", "expires": NOW + timedelta(days=1),
			 "compensating_evidence": "review-17"}


def findings(expected, observed):
	result = {}
	for device in sorted(expected):
		record = observed.get(device)
		reasons = []
		if record is None:
			reasons.append("missing")
		else:
			if not NOW - timedelta(minutes=30) <= record["seen"] <= NOW:
				reasons.append("time-quality")
			if record["revision"] != "r7":
				reasons.append("policy-revision")
			if record["mode"] != "Normal":
				reasons.append("mode")
			if record["tamper"] is not True:
				reasons.append("tamper-evidence")
		result[device] = reasons
	return result


def accepted_exception(exception, device, control):
	return (exception.get("device") == device
			and exception.get("control") == control
			and bool(exception.get("owner"))
			and bool(exception.get("ticket"))
			and bool(exception.get("compensating_evidence"))
			and exception.get("expires", NOW) > NOW)


def coverage(expected, observed):
	if not expected:
		return None
	result = findings(expected, observed)
	return sum(not reasons for reasons in result.values()), len(expected)


class AssuranceTests(unittest.TestCase):
	def test_baseline_denominator(self):
		self.assertEqual(coverage(set(OBSERVED), OBSERVED), (1, 2))
		self.assertEqual(coverage(EXPECTED, OBSERVED), (1, 3))
		self.assertEqual(findings(EXPECTED, OBSERVED)["lab-c"], ["missing"])

	def test_repair_keeps_original_evidence(self):
		repaired = deepcopy(OBSERVED)
		repaired["lab-b"]["revision"] = "r7"
		repaired["lab-c"] = dict(repaired["lab-a"])
		self.assertEqual(coverage(EXPECTED, repaired), (3, 3))
		self.assertEqual(OBSERVED["lab-b"]["revision"], "r6")

	def test_exception_is_scoped_and_expires(self):
		self.assertTrue(accepted_exception(EXCEPTION, "lab-b", "policy-revision"))
		self.assertFalse(accepted_exception(EXCEPTION, "lab-c", "policy-revision"))
		self.assertFalse(accepted_exception(EXCEPTION, "lab-b", "mode"))
		self.assertFalse(accepted_exception(dict(EXCEPTION, expires=NOW), "lab-b", "policy-revision"))
		self.assertEqual(coverage(EXPECTED, OBSERVED), (1, 3))

	def test_bad_evidence_is_not_green(self):
		for changes in ({"seen": NOW - timedelta(hours=1)},
						{"seen": NOW + timedelta(seconds=1)},
						{"mode": "Passive"}, {"tamper": None}):
			with self.subTest(changes=changes):
				changed = {"lab-a": dict(OBSERVED["lab-a"], **changes)}
				self.assertEqual(coverage({"lab-a"}, changed), (0, 1))

	def test_empty_population_is_not_perfect(self):
		self.assertIsNone(coverage(set(), {}))
		self.assertFalse(accepted_exception(dict(EXCEPTION, owner=""), "lab-b", "policy-revision"))


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Use a new scratch folder outside the vault; place the complete file there. Identify the incorrect denominator and both baseline gaps without running a real endpoint evaluation.
2. Predict which records change in the supplied fixed retest. Explain why an approved exception must not increase strict compliance.
3. Run only the offline suite from that folder when execution is authorized:

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

A fleet dashboard cannot define its own denominator from reporters. A valid exception belongs to one device and one control and must still have unexpired evidence. `None` represents unknown tamper state, not a passed check.

### Solution and Fixed Retest

Expected: five tests, `OK`. Baseline reporting-only score is `(1, 2)`; the correct fleet score is `(1, 3)`. `lab-b` has `policy-revision`; `lab-c` is `missing`. The repaired in-memory snapshot changes `lab-b` to `r7` and supplies `lab-c`, yielding `(3, 3)` without mutating original evidence. The exception accepts only a specific policy-revision risk, never mode or missing-device risk. No actual policy or tamper state changes.

### Verification, Troubleshooting, and Cleanup

Check stale and future timestamps, passive-mode evidence, unknown tamper state, exception expiry at the exact boundary, and empty inventory. The model assumes typed trusted snapshots; a production importer must validate schemas, provenance, and timestamp parsing before this evaluator. Python tests do not parse Sigma or execute KQL. No tests were run during authorship. If import discovery fails, change to the scratch folder; if `py` is unavailable use an existing Python 3.12 executable. Cleanup removes only the exercise file; no services or configurations need restoration:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

These original items remain user-owned; the offline CTF does not claim their live-device completion or authorize control changes.

- [ ] Local Defender and EDR Architecture exercise: In an authorized test device/tenant, trace a vendor-provided benign evaluation from endpoint event through collection and alert. Record policy, licensing, delay, and cleanup without changing corporate settings.
- [ ] Boundary check: Run an approved benign evaluation and confirm the expected event and alert on the test device; distinguish a missing rule from a missing sensor event.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Defender and EDR Architecture]]

## References

- [Defender Antivirus compatibility and modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Tamper protection overview](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview)
- [Defender Antivirus events](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [AlertInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [AlertEvidence schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
