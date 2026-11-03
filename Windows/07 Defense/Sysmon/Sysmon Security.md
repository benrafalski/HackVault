---
title: "Sysmon Security"
aliases: []
tags: [windows, x7, security]
domain: windows
phase: "X7"
type: security
status: draft
pair: "[[Sysmon]]"
updated: 2026-11-03
---
# Sysmon Security

> [!abstract] TL;DR
> A quiet Sysmon rule may reflect discarded or undelivered data. Review filters, schema mappings, expected events, and collector freshness as part of detection coverage; no query can restore evidence excluded at the source.

> [!info] Agent scope
> Security of event schemas, filtering, collection, correlation, volume, and coverage. Analyze synthetic filter and delivery failures, detection assumptions, and compensating controls without live evasion or service changes.

## Attack Surface

- Configuration administration determines what survives collection; forwarding and ingestion determine what analysts can search.
- Commands, paths, DNS names, signatures, and other event attributes are evidence, not intrinsically trustworthy labels. Do not grant benign status solely from an image name.
- Record retention, duplicate delivery, clock skew, missing fields, and PID-only joins can create false narratives even when the sensor works as configured.

## Learn

```text
Teach me defensive Sysmon coverage validation at expert depth. Assume Windows
event-log and XML knowledge. Explain filter precedence and grouping, missing event
classes, schema drift, GUID/PID correlation, channel forwarding, collector loss,
retention, volume budgets, and privacy. Distinguish no matching behavior from no
usable evidence; explain version-specific observation versus file-block features.
Provide supported read-only config/schema inspection and actual Sigma/KQL examples
with source mappings, benign explanations, data-quality prerequisites, and tuning
tradeoffs. Give a complete offline synthetic CTF where a broad exclusion drops a
required marker, a narrow repair preserves approved noise filtering, and a separate
collector loss remains visible. Include duplicate, missing-field, wrong-provider,
and timestamp tests; do not implement a pretend full Sysmon engine.
Use Microsoft and Sigma primary docs, state version assumptions, and separate
model results from live endpoint evidence. End with difficult questions/answers.
Teach here, no file/status edits. No actual attacks, evasion, sensor tampering,
unhooking, service changes, host-control or VPN changes; analyze defensive coverage.
```

## Cheatsheet

### Failure Analysis by Boundary

| Boundary | Harmless evidence test | Correct interpretation and repair |
|---|---|---|
| Sensor/config | Compare expected event class and named fields to deployed schema/config hash | A class excluded by design is a coverage gap, not an analytic miss; review the minimum collection needed |
| Include/exclude | Evaluate required and noise fixtures against exact filter predicates | Exclude wins over include; narrow exceptions to measured noise, not an entire directory or tool family |
| Local/forwarded | Compare the same provider/host/channel/record generation locally and centrally | Local present + central absent means forwarding, retention, parser, or deadline gap; not necessarily sensor failure |
| Parser | Preserve raw XML and compare named fields to normalized output | Wrong capitalization/type/namespace can erase predicates; quarantine malformed rows rather than turn null into benign |
| Correlation | Reuse a synthetic PID for two process GUIDs and include another host | PID-only joins invent relationships; use process identity with host and time boundaries |
| Analytics | Required positive and benign fixtures plus a missing-source fixture | A working predicate still needs a health gate and independent inventory |

Enabling every event class is not a free fix. Image loads and process access can produce large volumes; file archives consume disk and may retain sensitive files. A narrower filter reduces cost but must document the resulting blind spots. Keep a versioned coverage matrix linking each rule to event IDs, required fields, source settings, collector subscription, parser revision, and test evidence.

### Supported Configuration and Operational Monitoring

For authorized read-only inspection, `Sysmon64.exe -s` shows supported fields, `Sysmon64.exe -c` shows current configuration, and `Get-WinEvent` reads the Operational channel. Changes belong to the owning management workflow, not local experimentation. Event 16 records config change, 4 service state, and 255 errors; they are not a complete audit trail or heartbeat. Pair them with collector delivery and managed configuration-inventory evidence. Restrict configuration writers and log readers, retain reviewed revisions, and monitor deviations from the approved hash after upgrades.

### Sigma: Sysmon Health Review

This complete example detects health-review records, not compromise. Sigma 2.1-style syntax; a backend pipeline must map `service: sysmon` to the Sysmon provider/channel. Planned changes and operational failures are expected false positives for an incident interpretation.

```yaml
title: Sysmon Configuration Or Error Review
id: 98550928-3dcb-44f7-821d-1d3eb334c4ea
status: experimental
description: Surface Sysmon configuration changes and errors for coverage review.
date: 2026-11-03
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
            - 16
            - 255
    condition: selection
fields:
    - Computer
    - EventID
falsepositives:
    - Approved configuration rollout
    - Operational sensor errors unrelated to malicious activity
level: low
```

Do not suppress all 16 events during maintenance: retain the evidence and attach the change ticket. A configuration can be correct while the forwarding subscription is wrong. Conversely, 255 can describe a task-specific error rather than total collection failure; inspect its payload and unaffected event families.

### KQL: Bad Identity Fields Are a Separate Queue

Sentinel `WindowsEvent`, populated with Sysmon XML parsed to dynamic `EventData`. This query cannot enumerate completely missing devices, so combine it with expected inventory and collector health. The zero-count branch prevents a divide-by-zero result from looking like a healthy population.

```kusto
WindowsEvent
| where TimeGenerated > ago(1h)
| where Provider == "Microsoft-Windows-Sysmon"
| where Channel == "Microsoft-Windows-Sysmon/Operational" and EventID in (1, 3, 22)
| extend Guid=tostring(EventData.ProcessGuid), Image=tostring(EventData.Image)
| summarize Rows=count(), BadIdentity=countif(isempty(Guid) or isempty(Image)) by Computer, EventID
| extend BadFraction=iff(Rows == 0, real(null), todouble(BadIdentity) / Rows)
| where BadIdentity > 0
```

Actual Sysmon GUID validation should distinguish absent, malformed, and unmapped fields. This query only checks emptiness. Record IDs may reset on log rollover/recreation; deduplicate within a known generation, never permanently on `Computer + EventRecordID` alone. Source time skew and ingestion lag need separate monitors.

## Detection and Defense

Use a change gate: compare old/new filters on a fixed corpus, require every mandatory marker, preserve expected benign suppression, then review event-volume delta and downstream parsing. Require positive health evidence before calling an empty detection result clean. If a necessary event class is unavailable, state the gap and add an independent supported source such as MDE process telemetry or Security process auditing with its own prerequisites; neither is a field-for-field Sysmon replacement.

## Labs

### Environment and Complete Files

Offline CTF: two defects make the dashboard quiet. Python 3.12 standard library only; one scratch file outside the vault contains all data. The filter model supports only one exact included image and substring exclusions, case-insensitively. It models exclude precedence, not Sysmon's complete XML semantics or Windows path resolution. Images and event records are harmless strings; nothing is executed or collected.

### File: test_example.py

```python
import unittest
from copy import deepcopy

PROVIDER = "Microsoft-Windows-Sysmon"
ROWS = [
	{"id": "marker", "provider": PROVIDER, "image": r"C:\Lab\marker.exe", "guid": "A", "minute": 10},
	{"id": "noise", "provider": PROVIDER, "image": r"C:\Lab\noise.exe", "guid": "B", "minute": 10},
	{"id": "ordinary", "provider": PROVIDER, "image": r"C:\Apps\reader.exe", "guid": "C", "minute": 10},
]
BAD = {"include_image": r"C:\Lab\marker.exe", "exclude_contains": ["C:\\Lab\\"]}
FIXED = {"include_image": r"C:\Lab\marker.exe", "exclude_contains": [r"C:\Lab\noise.exe"]}


def selected(row, config):
	if row.get("provider") != PROVIDER:
		raise ValueError("provider")
	if not row.get("image") or not row.get("guid"):
		raise ValueError("identity")
	image = row["image"].casefold()
	included = image == config["include_image"].casefold()
	excluded = any(term.casefold() in image for term in config["exclude_contains"])
	return included and not excluded


def coverage(rows, config, delivered_ids, now_minute=12):
	chosen = {row["id"]: row for row in rows if selected(row, config)}
	marker = chosen.get("marker")
	if marker is None:
		return "source-filter-gap"
	if not 0 <= now_minute - marker["minute"] <= 5:
		return "time-quality-gap"
	if "marker" not in delivered_ids:
		return "delivery-gap"
	return "covered"


class FilterTests(unittest.TestCase):
	def test_exclude_precedence_and_repair(self):
		self.assertEqual(coverage(ROWS, BAD, {"marker"}), "source-filter-gap")
		self.assertEqual(coverage(ROWS, FIXED, {"marker"}), "covered")

	def test_forwarding_is_separate(self):
		self.assertEqual(coverage(ROWS, FIXED, set()), "delivery-gap")

	def test_benign_noise_stays_unselected(self):
		self.assertFalse(selected(ROWS[1], FIXED))
		self.assertFalse(selected(ROWS[2], FIXED))
		self.assertTrue(selected(dict(ROWS[0], image=r"c:\lab\MARKER.EXE"), FIXED))

	def test_missing_identity_and_provider(self):
		for changes in ({"guid": ""}, {"image": None}, {"provider": "Other"}):
			with self.subTest(changes=changes), self.assertRaises(ValueError):
				selected(dict(ROWS[0], **changes), FIXED)

	def test_duplicates_and_time_quality(self):
		self.assertEqual(coverage(ROWS + ROWS, FIXED, {"marker"}), "covered")
		for minute in (0, 20):
			changed = deepcopy(ROWS)
			changed[0]["minute"] = minute
			self.assertEqual(coverage(changed, FIXED, {"marker"}), "time-quality-gap")


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Predict why `BAD` rejects the mandatory marker even though its include matches. Identify the second failure when `FIXED` is used with an empty delivery set.
2. Run from the scratch folder. Explain why adding more detection predicates cannot fix either missing-evidence boundary.
3. Confirm that the corrected in-memory filter retains the required marker while the noise and ordinary fixtures remain unselected.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Evaluate include and exclude separately. A true include is insufficient when exclude also matches. Then evaluate delivery only for events that survived source filtering.

### Solution and Fixed Retest

Expected: five tests, `OK`. Baseline returns `source-filter-gap`; narrowing the synthetic exclusion to the noise image returns `covered` only if marker delivery exists. With no delivered IDs it returns `delivery-gap`. Stale or future marker time returns `time-quality-gap`. This is a coverage test, not a recipe to evade or reconfigure Sysmon. A fully collected benign workflow need not alert; here non-target benign fixtures are deliberately outside the tiny model's source scope.

### Verification, Troubleshooting, and Cleanup

Check exclusion precedence, mixed-case paths, absent identity/provider, duplicates, freshness, and collection independence. Duplicate fixtures must be byte-equivalent for this toy dictionary deduplication; conflicting duplicate IDs require rejection in a real collector. No Sysmon, Sigma converter, KQL engine, or live enforcement is tested; author execution was prohibited. Use an existing Python 3.12 executable if `py` is missing and run in the correct directory. Do not diagnose failures by changing host filters or forwarding. Cleanup only the scratch file:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

These original items remain unchanged. Live filter/VM milestones are not completed or authorized by this offline exercise.

- [ ] Local Sysmon exercise: In a disposable VM, use a reviewed Sysmon configuration and run a harmless process/file/DNS marker. Inspect the expected events and correlate them by process identity.
- [ ] Boundary check: Change one test filter deliberately and verify the expected marker's inclusion/exclusion, then restore the reviewed configuration and confirm forwarding.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Sysinternals]]
- [[Detection Engineering]]
- [[Sysmon]]

## References

- [Sysmon filtering and event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event Forwarding design and collection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [WindowsEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
