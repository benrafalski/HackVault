---
title: "Detection Engineering (Sigma and KQL) Security"
aliases: []
tags: [windows, x7, security]
domain: windows
phase: "X7"
type: security
status: draft
pair: "[[Detection Engineering]]"
updated: 2026-11-03
---
# Detection Engineering (Sigma and KQL) Security

> [!abstract] TL;DR
> Test the detection system, not just its positive predicate. Late ingestion, null coercion, broad suppression, wrong identity, and silent source loss can invalidate a logically correct rule. Keep quality failures, review candidates, and benign negatives separate.

> [!info] Agent scope
> Defensive assurance for hypotheses, telemetry contracts, Sigma/KQL mappings, fixtures, false positives/negatives, lifecycle, and coverage. Demonstrate synthetic pipeline defects and repairs, not live evasion or attack generation.

## Attack Surface

- Ingestion/parsing can lose or coerce fields; a wrong mapping can make a correct rule permanently quiet.
- Scheduling and suppression can lose late events or collapse unrelated events/users/devices into one identity.
- Rule administration, backend conversion, exception lists, and review labels can change detection behavior without changing the source event.

## Learn

```text
Teach me security assurance for Windows detection engineering at expert depth.
Assume Sigma, KQL, process telemetry, and UTC basics. Analyze wrong field/log-source
mappings, case/path/null semantics, event-versus-ingestion windows, delayed data,
duplicates, PID reuse, broad suppressions, missing-source health, and rule lifecycle.
For each failure explain root cause, prerequisites, observable result, correction,
residual risk, and negative regression. Show real Sigma/KQL syntax with explicit
schemas and backend dependencies, not pseudoqueries. Give a complete offline
synthetic CTF where a late positive is missed by an event-time-only schedule,
missing fields cannot count as benign, and corrected scheduling preserves valid
benign behavior with bounded deduplication. Include suppression ownership/expiry,
precision/recall denominator limits, triage, rollout/rollback, and privacy.
Use SigmaHQ and Microsoft primary docs; separate reference-model tests, compiler
validation, query execution, and deployed-alert evidence. Teach here without file
or status edits. No actual attacks, evasion experiments, live response/control
changes, services, or VPN changes. Do not fabricate test or performance results.
```

## Cheatsheet

### Failure Modes and Discriminating Tests

| Failure | Cheap synthetic test | Corrective contract |
|---|---|---|
| Wrong source/mapping | Same field strings under another provider or missing parent mapping | Pin source/category/field/type mapping and reject unsupported inputs |
| Case/path mismatch | Mixed-case Windows path and a longer lookalike basename | Match intended component/case semantics; avoid generic substring/token substitutions |
| Null becomes benign | Required parent absent or wrong type | Separate data-quality disposition; do not silently coerce to a harmless default |
| Late-arrival loss | Event at minute 3 arrives during minute 9 of a 10-minute run | Sufficient event-time lookback plus ingestion-aware scheduling or overlapping runs/dedup |
| Duplicate inflation | Deliver one exact event twice | Source-specific durable identity and idempotent alert handling |
| Correlation collision | Same PID on two devices or after process restart | Device + process-lifetime identity + bounded causal time window |
| Overbroad suppression | Approved workflow and a distinct review candidate share only user or publisher | Scope to justified context with owner/expiry, preserve suppressed counts and positive tests |
| Empty-source green | Expected device has no health or events | Independent inventory/heartbeat contract, not behavior-query output as its own denominator |

Keep failures in the appropriate layer. A missing event cannot be repaired by rewriting a Sigma predicate. A correct mapping does not fix a stale collector. A working hunting query does not ensure the scheduled detection runs successfully, retains required identity columns, or has permission to see the target data.

### Query Semantics and Deployment Risks

Sigma maps AND their fields, lists OR values by default, and `not filter` can behave differently when fields are absent after backend translation. Test empty, null, and missing fields explicitly. `contains`, `endswith`, regex, and KQL `has` are not interchangeable. Regex case defaults differ from ordinary Sigma string matching. Backend/pipeline upgrades must rerun the same corpus and compare exact match identities.

KQL joins can multiply rows when the right side is not unique. Summarize/deduplicate deliberately before joining or use a join kind appropriate to the question; do not hide errors with a final `distinct` that erases meaningful records. Default join behavior should not be assumed for event sequences. For process correlation, require the event-time relationship in addition to the key; same-key events outside the process lifetime are not related.

Schedule example: run every 2 minutes, search the last 10 minutes of event time, and evaluate newly ingested rows within the last 2 minutes. This accommodates delays under that event-time budget, but a delay over 10 minutes still needs a late-data queue/backfill. Exact boundaries should be half-open `[start, end)` and anchored to a persisted run time/watermark. Actual ingestion timestamps depend on backend support; do not assume `ingestion_time()` is available or stable in every Defender/Sentinel context.

### Complete KQL Timing Fixture

Synthetic `datatable` uses seconds relative to a fixed run, so no service data or live clock is needed. It demonstrates window logic, not production scheduling. Run ends at 600; ingest interval is `[480,600)`, event lookback `[0,600)`. The late event at 200 arrived at 550 and must be considered. A naive event-time interval `[480,600)` loses it.

```kusto
let RunEnd=600;
datatable(Id:string, EventSecond:long, IngestSecond:long, Parent:string, Child:string)
[
  "late", 200, 550, "winword.exe", "cmd.exe",
  "benign", 520, 550, "explorer.exe", "cmd.exe",
  "missing", 530, 560, "", "cmd.exe",
  "next-run", 590, 600, "winword.exe", "cmd.exe"
]
| where IngestSecond >= RunEnd - 120 and IngestSecond < RunEnd
| extend Quality=case(EventSecond > IngestSecond, "clock-error",
					   EventSecond < RunEnd - 600, "too-late",
					   isempty(Parent) or isempty(Child), "missing-fields", "usable")
| extend Candidate=Quality == "usable" and Parent =~ "winword.exe" and Child =~ "cmd.exe"
| project Id, Quality, Candidate
```

Expected: `late` usable/true, `benign` usable/false, `missing` missing-fields/false. `next-run` is intentionally deferred at the upper boundary, not lost forever. The next run must use a compatible watermark. Persist run metadata and duplicate suppression state in a real system; the Python lab makes this explicit in memory.

### Sigma: Required-Field Quality Companion

This quality rule is distinct from the behavioral rule. Missing versus explicit null behavior and `exists` support must be verified in the target pipeline. It is intentionally not an automatic threat rule.

```yaml
title: Process Creation Parent Field Quality Review
id: 7ce454bf-186e-4ab8-9d6d-5067032f0f89
status: experimental
description: Surface empty or absent normalized parent image fields for parser review.
date: 2026-11-03
logsource:
    category: process_creation
    product: windows
detection:
    selection_absent:
        ParentImage|exists: false
    selection_empty:
        ParentImage: ''
    selection_null:
        ParentImage: null
    condition: 1 of selection_*
falsepositives:
    - Source-specific process records without a represented parent
level: low
```

Some process records legitimately lack parent context, and pipeline mappings can omit it. Classify them as unsupported/incomplete for the behavioral predicate, not necessarily sensor faults. If the backend does not implement the modifier faithfully, fail conversion or supply a reviewed native quality query; do not silently drop the quality rule.

### Metrics, Exceptions, and Triage

Report corpus-level positive recall and benign-match rate separately from analyst-reviewed production precision. Production recall requires a known positive population; unknown events and source gaps invalidate claims of perfect recall. Track parser rejects, required-field null rate, source coverage, late-arrival percentiles, duplicate rate, analytic job failures, alert volume, and triage latency.

Suppressions need exact scope, reason, owner, approval, expiry, hit counts, and regression fixtures that still alert outside that scope. Tuning must not discard the only evidence for a high-value behavior. Store sensitive raw data with least-privilege access and retention controls; use synthetic fixtures in public rule repositories. A detected relationship can be legitimate automation, so triage before disruptive response.

## Detection and Defense

Version rule, pipeline, query, fixture corpus, schedule, and exception changes together. Require exact expected match IDs plus an explicit missing-source finding. Stage in observation mode, monitor performance and benign workload coverage, then deploy through review; keep the last known-good rule revision for rollback without touching endpoint protections. A rule rollback does not recover events already lost upstream.

## Labs

### Environment and Complete Files

Offline scheduling and quality CTF. Python 3.12 standard library only, one file, all synthetic rows embedded. Use a fresh scratch folder outside the vault. No endpoint processes, query backend, Sigma engine, or services are used. Relative seconds and fixture IDs are intentionally simple; production adapters need UTC parsing and source-scoped identities.

### File: test_example.py

```python
import unittest

ROWS = [
	{"id": "late", "device": "lab-a", "event": 200, "ingest": 550, "parent": "winword.exe", "child": "cmd.exe"},
	{"id": "benign", "device": "lab-a", "event": 520, "ingest": 550, "parent": "explorer.exe", "child": "cmd.exe"},
	{"id": "missing", "device": "lab-a", "event": 530, "ingest": 560, "parent": "", "child": "cmd.exe"},
	{"id": "next-run", "device": "lab-a", "event": 590, "ingest": 600, "parent": "winword.exe", "child": "cmd.exe"},
]


def candidate(row):
	return row["parent"].casefold() == "winword.exe" and row["child"].casefold() == "cmd.exe"


def naive(rows, end):
	return {row["id"] for row in rows if end - 120 <= row["event"] < end and candidate(row)}


def run(rows, end, delivered_alerts):
	alerts, quality = set(), {}
	for row in rows:
		if not end - 120 <= row["ingest"] < end:
			continue
		identity = (row["device"], row["id"])
		if row["event"] > row["ingest"]:
			quality[identity] = "clock-error"
		elif row["event"] < end - 600:
			quality[identity] = "too-late"
		elif not all(isinstance(row.get(field), str) and row[field] for field in ("parent", "child")):
			quality[identity] = "missing-fields"
		elif candidate(row) and identity not in delivered_alerts:
			alerts.add(identity)
	return alerts, quality


class SchedulingTests(unittest.TestCase):
	def test_late_positive_and_corrected_window(self):
		self.assertNotIn("late", naive(ROWS, 600))
		alerts, quality = run(ROWS, 600, set())
		self.assertEqual(alerts, {("lab-a", "late")})
		self.assertEqual(quality, {("lab-a", "missing"): "missing-fields"})

	def test_next_boundary_is_deferred_not_lost(self):
		alerts, quality = run(ROWS, 720, set())
		self.assertEqual(alerts, {("lab-a", "next-run")})
		self.assertEqual(quality, {})

	def test_duplicates_and_replayed_run_are_idempotent(self):
		first, _ = run(ROWS + ROWS, 600, set())
		repeated, quality = run(ROWS, 600, first)
		self.assertEqual(first, {("lab-a", "late")})
		self.assertEqual(repeated, set())
		self.assertIn(("lab-a", "missing"), quality)

	def test_benign_and_missing_source_are_distinct(self):
		alerts, quality = run([ROWS[1]], 600, set())
		self.assertEqual((alerts, quality), (set(), {}))
		expected = {"lab-a", "lab-b"}
		healthy_sources = {"lab-a"}
		self.assertEqual(expected - healthy_sources, {"lab-b"})

	def test_late_budget_and_future_clock(self):
		old = dict(ROWS[0], id="old", event=-1)
		future = dict(ROWS[0], id="future", event=551)
		alerts, quality = run([old, future], 600, set())
		self.assertEqual(alerts, set())
		self.assertEqual(quality, {("lab-a", "old"): "too-late", ("lab-a", "future"): "clock-error"})


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Identify why the naive event-time-only window loses `late`; distinguish this from a wrong behavior predicate.
2. Run the suite in the scratch directory. Follow the corrected first and next run, including the exact upper ingestion boundary.
3. Explain why duplicate suppression must not erase the quality finding and why the absent `lab-b` requires independent source-health evidence.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Ask when the data became searchable, not only when the event occurred. A fixed lookback still has a maximum tolerated delay. A benign negative and a nonreporting source are different populations.

### Solution and Fixed Retest

Expected: five tests, `OK`. At run end 600 the fixed result is alert `('lab-a', 'late')` plus quality finding `('lab-a', 'missing')`. At run end 720, `next-run` is considered exactly once. Repeating the first run with its delivered-alert set returns no new alerts but retains quality findings. The benign fixture remains nonmatching; lab-b remains a source gap. Too-old and future-clock fixtures are explicitly classified instead of silently labeled benign.

### Verification, Troubleshooting, and Cleanup

The model assumes typed trusted timing data and identical-payload duplicate IDs; production needs validation, conflicting-duplicate handling, durable state, retry-safe alert writes, and backfill policy. Do not treat its ten-minute budget as a vendor default. Python tests do not certify Sigma backend null semantics, KQL scheduling, or real end-to-end coverage. No tests were run by the author. Use an existing Python 3.12 executable if `py` is unavailable; run from the scratch folder. Cleanup:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

Original milestones remain unchanged and user-owned; the reference model alone does not establish backend equivalence or deployment completion.

- [ ] Local Detection Engineering exercise: Create synthetic process-event fixtures for one unusual parent/child relationship. Write a Sigma rule and a mapped KQL query, then test a positive, a benign lookalike, and a missing-field case.
- [ ] Boundary check: Require the positive fixture to match, the benign fixture not to match, and the missing-source case to surface as a coverage/health problem rather than a clean result.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Detection Engineering]]

## References

- [Sigma rule and null/existence semantics](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma processing and conversion documentation](https://sigmahq.io/docs/)
- [Kusto join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- [Kusto ingestion_time function](https://learn.microsoft.com/en-us/kusto/query/ingestion-time-function)
- [Sentinel ingestion-delay handling](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Defender custom detection requirements](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
