---
title: "Windows Evasion"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Evasion

> [!abstract] TL;DR
> A missing alert can arise at instrumentation, collection, parsing, correlation, policy, or delivery. Diagnose that pipeline before claiming evasion; absence of content telemetry does not establish absence of process or kernel-visible behavior.

> [!info] Agent scope
> AMSI, ETW, user-mode hooks, architectural limits of unhooking/direct-syscall claims, coverage evaluation, and compensating controls. No bypass implementation, sensor patching, protection disablement, or evasion recipes.

## Learn

```text
Teach Windows telemetry limitations and evasion claims as defensive engineering.
Assume process/API boundaries, ETW providers, logs, and endpoint policy basics.
Explain AMSI host/provider/result semantics, ETW provider-session-consumer flow,
buffer loss, user-mode API instrumentation, protected consumers, and independent
kernel/file/network observations. Discuss unhooking and direct syscalls only as
architectural claims: no instructions, bytes, syscall identifiers, or implementation.
Distinguish configured/active/supported/observed coverage, sensor failure, parser
loss, rule nonmatch, and missing alert delivery. Explain why unsupported content
hosts and absent heartbeats require different classifications, and why direct
kernel entry does not imply invisible effects or authorization bypass.
Give a self-contained offline Python 3.12 stdlib challenge using synthetic content,
process, heartbeat, loss, and rule-hit metadata; include expected/late/unsupported
cases, a flawed absence-based rule, corrected logic, tests, and separate solution.
Do not patch AMSI/ETW/hooks, disable sensors, run evasive payloads, alter exclusions,
or change host policy. Use public primary sources and explicit OS/provider/schema
limits. Include controls, latency/volume tradeoffs, failure analysis, and challenging
questions with answers. No confidential data or page-table material; no debugger
commands outside WinDbg. Teach without editing notes or marking completion.
```

## Cheatsheet

### Observation and Enforcement Are Different Contracts

| Layer | What it sees or decides | What cannot be inferred |
|---|---|---|
| AMSI-integrated host | Supplies content/context to a registered antimalware provider and consumes the scan result | Not every executable or host submits content; scan success is not a permanent guarantee |
| ETW provider | Emits defined events when enabled under its contract | Event emission is not collection, storage, alerting, or prevention |
| ETW session/consumer | Enables provider keywords/levels, transports/consumes buffers | Permissions, filters, loss, and schema decoding can remove evidence |
| User-mode hooks | Observe selected application/API paths within the instrumented context | Not an OS-wide reference monitor; implementation details are product/build-specific |
| Kernel and protected telemetry | Observes supported system activity with different privileges and visibility | Not unlimited, universally accessible, or equivalent across products/builds |
| Detection rule | Correlates available evidence against an analytic | A nonmatch is not a proof of benignness; rule versions and exceptions matter |
| Prevention policy | Allows, blocks, audits, or responds at a defined enforcement point | An audit event does not imply blocking; alert delivery may be delayed |

AMSI is an interface, not a single malware engine. The API's call status and scan-result classification are distinct. Hosts must handle errors and apply policy appropriately; treating a provider error as a known-clean verdict is a fail-open design mistake. Not all scanned content is retained as a retrievable event, so "no content log" can be normal even when scanning occurred.

ETW's providers, sessions, and consumers have separate enablement and access rules. Keywords/levels select subsets; finite buffers, consumer lag, and storage pressure can cause loss. Manifest/schema revisions affect decoding. A collector heartbeat proves only the particular component reported recently, not that every provider delivered every event. ETW-TI has protected-access requirements; it is not interchangeable with ordinary user-accessible ETW sessions.

### Architectural Limits, Not Bypass Instructions

Unhooking refers conceptually to interfering with user-mode interception. Direct-syscall claims concern entering a system-service boundary without using a particular instrumented API wrapper. Neither changes the kernel's access checks or guarantees removal of memory, file, process, thread, image-load, or network effects. Product visibility cannot be deduced from a public API name. This note provides no method to change code pages, call undocumented service numbers, or evade instrumentation.

Use a coverage matrix: activity class, expected sensor, provider/schema, collection policy, independent source, benign positive control, maximum delay, and responsible owner. Exclusions should be treated as explicit coverage exceptions with expiry and review, not as evidence that an action is safe. A trustworthy baseline distinguishes "not supported", "not observed yet", "collection unhealthy", and "rule did not match".

### Failure Analysis Order

1. Establish that the harmless expected activity occurred and define its scope/time.
2. Verify whether the host/provider contract promises the specific observation; do not invent an AMSI event for every scan.
3. Check source enablement, health, timestamp bounds, dropped buffers, filtering, and ingest latency.
4. Check schema parsing, join keys, time windows, rule version, exceptions, and audit/block mode.
5. Compare an independent signal and record the narrowest supported conclusion.

For example, process evidence plus missing expected content evidence is a coverage gap, not "execution invisible." A stale collector heartbeat makes the content result unknown even if yesterday's policy said enabled. A clean health report with a missing expected rule hit points to an analytic problem only after input coverage is established.

### Collector Freshness Query

**Fragment / prerequisites:** Azure Monitor Logs KQL with read access to the `Heartbeat` table and agent collection already configured. Replace the synthetic expected-host list with a maintained inventory using the same canonical `Computer` values; names must be unique in the workspace or use a stable resource key. This checks collector coverage, not AMSI/ETW provider coverage.

```kusto
let Expected = datatable(Computer:string) ["lab-ws"];
let Latest = Heartbeat
	| where TimeGenerated > ago(1d)
	| summarize LastSeen = max(TimeGenerated) by Computer;
Expected
| join kind=leftouter Latest on Computer
| extend Coverage = case(
	isnull(LastSeen), "no-heartbeat-in-lookback",
	LastSeen > now(), "clock-error",
	LastSeen < ago(15m), "stale-collector",
	"recent-heartbeat-only")
| project Computer, LastSeen, Coverage
```

**Interpretation / false positives:** the left join retains expected hosts with no events. One day and 15 minutes are example lookback/freshness thresholds, not product defaults. Sleep, maintenance, ingestion delay, inventory drift, and clock skew can trigger findings. A recent heartbeat does not prove event delivery, rule coverage, or absence of tampering; reconcile independent benign controls and loss counters before attribution. Query syntax and workspace mappings have not been executed here.

## Defense

Use supported tamper protection, restricted administration, application control, least privilege, and multiple independent telemetry sources. Monitor loss and freshness alongside security alerts. Pin detection schemas/rule versions and keep a versioned coverage contract. Protect collection transport and retention; redundant sensors sharing one failed collector are not fully independent.

Higher event volume improves some visibility but may increase loss and cost; broad allowlists reduce noise but can hide changed behavior. Stage changes using benign controls, size buffers/retention to workload, and test delivery latency. Do not disable protections to demonstrate a gap. Review health failure as an operational and security issue without attributing it to tampering absent evidence.

## Labs

### Environment and Complete Files

Python **3.12**, `unittest` only, no packages, network, sensors, or administrator access. This defensive analysis challenge processes synthetic coverage snapshots; `content_expected` means the fixture's invented logging contract, not a universal AMSI promise. Seconds are relative to one synthetic epoch.

### File: test_example.py

```python
import unittest


NOW = 100
SEED = {"content_expected": True, "content_seen": True, "process_seen": True,
		"heartbeat": 95, "lost": 0, "rule_hit": True}
CASES = {
	"healthy": SEED,
	"unsupported-host": dict(SEED, content_expected=False, content_seen=False),
	"gap": dict(SEED, content_seen=False),
	"stale": dict(SEED, heartbeat=20, content_seen=False),
	"loss": dict(SEED, lost=3),
	"analytic": dict(SEED, rule_hit=False),
}


def assess(record, now=NOW):
	required = ("content_expected", "content_seen", "process_seen", "rule_hit")
	if any(type(record.get(field)) is not bool for field in required):
		return "unknown-schema"
	heartbeat, lost = record.get("heartbeat"), record.get("lost")
	if type(heartbeat) is not int or type(lost) is not int or lost < 0:
		return "unknown-health"
	if heartbeat > now:
		return "clock-error"
	if now - heartbeat > 15 or lost > 0:
		return "collection-unhealthy"
	if not record["process_seen"]:
		return "expected-activity-unconfirmed"
	if not record["content_expected"]:
		return "process-visible-content-outside-contract"
	if not record["content_seen"]:
		return "content-coverage-gap"
	if not record["rule_hit"]:
		return "analytic-gap"
	return "expected-evidence-present"


class CoverageTests(unittest.TestCase):
	def test_missing_content_does_not_mean_invisible(self):
		self.assertFalse(CASES["unsupported-host"]["content_seen"])
		self.assertTrue(CASES["unsupported-host"]["process_seen"])
		self.assertEqual(assess(CASES["unsupported-host"]),
						 "process-visible-content-outside-contract")

	def test_distinct_failure_stages(self):
		self.assertEqual([assess(record) for record in CASES.values()], [
			"expected-evidence-present", "process-visible-content-outside-contract",
			"content-coverage-gap", "collection-unhealthy",
			"collection-unhealthy", "analytic-gap",
		])

	def test_synthetic_collection_repair_preserves_control(self):
		fixed = dict(CASES["loss"], lost=0, heartbeat=NOW)
		self.assertEqual(assess(fixed), "expected-evidence-present")
		self.assertEqual(CASES["loss"]["lost"], 3)

	def test_unknown_clock_and_boundary_cases(self):
		self.assertEqual(assess({}), "unknown-schema")
		self.assertEqual(assess(dict(SEED, heartbeat=101)), "clock-error")
		self.assertEqual(assess(dict(SEED, heartbeat=85)), "expected-evidence-present")
		self.assertEqual(assess(dict(SEED, heartbeat=84)), "collection-unhealthy")
		self.assertEqual(assess(dict(SEED, process_seen=False)),
						 "expected-activity-unconfirmed")


if __name__ == "__main__":
	for name, record in CASES.items():
		print(name, assess(record))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

Refute the flawed baseline claim "missing content means evasion succeeded" using `unsupported-host` and `stale`. Attribute each case to its narrowest pipeline stage. For `loss`, propose collector capacity/health follow-up and examine the supplied synthetic fixed snapshot; do not change a real provider or buffer setting.

### Hints

Health takes precedence over interpreting absent events. The fixture's freshness threshold is 15 seconds inclusive, not a platform default. Restoring health does not invent missing historical evidence; a repaired snapshot represents a new interval.

### Solution and Fixed Retest

`unsupported-host` still has process evidence, `gap` lacks contracted content evidence, `stale` and `loss` have unhealthy collection, and `analytic` lacks the expected rule hit despite its supplied inputs. `healthy` is the positive control. The synthetic repair changes only the new interval's loss/freshness metadata and leaves the original record intact. Neither healthy classification proves malware absence nor unhealthy classification proves deliberate tampering.

### Evidence, Troubleshooting, and Cleanup

Expected: six classification lines and **4 passing tests**. Retain the coverage contract, fixture ID, health interval, classification, and independent-source rationale. Unknown schema means a field is missing or not Boolean; do not coerce arbitrary strings to truth. Future heartbeats signal clock inconsistency. The model omits actual ETW buffering, AMSI provider behavior, transport authentication, and detection latency distributions.

Tests were not executed during authoring. Remove only this exercise's directory. No hooks, exclusions, AMSI providers, ETW sessions, or protection policies were modified.

- [ ] Local Windows Evasion exercise: Diagnose the supplied offline coverage snapshots without executing evasive behavior.
- [ ] Boundary check: Preserve the healthy positive control and distinguish unsupported, missing, stale, and analytic evidence.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [AMSI architecture](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [AmsiScanBuffer contract](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer)
- [About event tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [EVENT_TRACE_PROPERTIES and loss counters](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
- [Tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
