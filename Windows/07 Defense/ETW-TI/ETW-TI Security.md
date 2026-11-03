---
title: "ETW Threat Intelligence Security"
aliases: []
tags: [windows, x7, security]
domain: windows
phase: "X7"
type: security
status: draft
pair: "[[ETW-TI]]"
updated: 2026-11-03
---
# ETW Threat Intelligence Security

> [!abstract] TL;DR
> The security task is proving what evidence supports a coverage claim. Unknown authorization, schema, provenance, loss, or scenario support must remain unknown, not become a clean bill of health or a claim that ETW-TI was bypassed.

> [!info] Agent scope
> Defensive coverage analysis of protected consumer requirements, supported observation, version-dependent schemas, provenance, and limitations. Use synthetic evidence and compensating-source analysis, not live bypass techniques.

## Attack Surface

- Evidence can be misclassified at the product/provider boundary: a generic endpoint alert is not necessarily TI, and no alert is not necessarily no sensor event.
- Consumers and decoders rely on version-specific contracts, authorized access, buffer health, and correct process/time correlation.
- Claims of complete coverage can hide unsupported scenarios, missing evidence, stale exports, and intentional product filtering.

## Learn

```text
Teach me ETW-TI security assurance and limitation analysis at expert depth, assuming
Windows ETW and process-security knowledge. Focus on protected consumer entitlement,
build/schema compatibility, provider attribution, expected-signal contracts, loss,
retention, product aggregation, and correlation errors. Distinguish absence of
behavior, source unavailable, unsupported scenario, delivery failure, decode error,
analytic miss, and unknown provenance. Explain public ETW/TDH APIs and protected
antimalware prerequisites without bypassing or recreating a protected consumer.
Provide a complete offline synthetic CTF with expected scenarios, observed rows,
independent corroboration, a flawed green dashboard, a corrected fail-unknown
assessment, and negative regressions. Include real KQL with declared custom fields,
data-quality tests, supported diagnostics, compensating controls, false positives,
and explicit limits: corroboration is not proof of TI attribution or enforcement.
Use Microsoft primary sources and flag where they do not supply a TI contract.
Teach here without file or status edits. No live access attempts, evasion,
unhooking, AMSI patching, tamper changes, memory-manipulation payloads, credential
access, persistence, VPN or host-control changes. Do not invent test results.
```

## Cheatsheet

### Coverage Claims Need a Contract

Define the tested claim before looking at events: supported product/build, documented scenario, allowed consumer, exact exported schema, expected fields, time interval, maximum delivery latency, expected alert behavior, and independent operation outcome. A claim can be narrower than the underlying product's capability; do not generalize a passing scenario into all memory or process operations.

| Observation | Supported conclusion | Not supported |
|---|---|---|
| Ordinary viewer cannot consume protected provider | Consumer access was not established | Provider absent, broken, or bypassed |
| Product is healthy but provenance absent | Product evidence available; TI attribution unknown | Event came from TI |
| Raw event exists, analytic did not match | Check normalized fields, rule version, timing, and scenario expectation | The sensor never saw the behavior |
| No event, counter reports loss | Collection is incomplete for that interval | Activity was benign or impossible |
| No event, no exposed loss counters | Insufficient evidence to assess loss | Zero loss |
| Event decoded using another build's layout | Decoder contract unsupported | Fields reliably describe the operation |
| Corroborating process event from another source | A process observation supports a narrower timeline fact | TI emitted the corresponding sensitive-operation event |

Do not describe an access-denied outcome as a protection weakness. It may be the intended boundary. Protected-service signing, ELAM registration, and process protection are prerequisite concepts; none alone is a universal permission to every provider. Escalate unsupported observation to the security-product owner/vendor rather than changing the consumer trust boundary.

### Error Handling and Defensive Repairs

Use public ETW APIs only within an explicitly supported integration: check the returned `EnableTraceEx2` status, decode using TDH and the exact event version, and inspect allowed session statistics through the owning product. Keep raw/normalized event lineage where privacy permits. Unsupported schema must quarantine or reject, not silently reuse the nearest known layout. For repeated events, use the product's documented identity; never invent a global unique ID from PID or timestamp alone.

Repair evidence handling, not security boundaries: correct the parser, pin compatible schema/build versions, restore supported collector delivery through its owner, and retain errors as health findings. Do not stop a product-owned ETW session or weaken protection to make a viewer work. Generic ETW events can be lost when consumers fall behind or buffers/resources are insufficient; supported product health diagnostics should determine whether and how to tune resources.

### KQL: Expected Scenario Versus Observed Evidence

Complete synthetic KQL; no real TI table or product entitlement is implied. `DocumentedSource`, `SchemaKnown`, and `Losses` are fields of this training contract only. This query shows independent quality dimensions instead of masking loss behind a single green status.

```kusto
let Expected=datatable(Scenario:string) ["case-a", "case-b", "case-c"];
let Observed=datatable(Scenario:string, EventCount:long, DocumentedSource:bool, SchemaKnown:bool, Losses:long)
[
  "case-a", 1, true, true, 0,
  "case-b", 1, false, true, 2
];
Expected
| join kind=leftouter Observed on Scenario
| extend Evidence=iff(isnull(EventCount), "missing", "present"),
		 Attribution=iff(DocumentedSource == true, "documented-in-fixture", "unknown"),
		 Schema=iff(SchemaKnown == true, "known-in-fixture", "unknown"),
		 Loss=case(isnull(Losses), "unknown", Losses > 0, "reported", "none-reported")
| project Scenario, Evidence, Attribution, Schema, Loss
```

Expected: case-a has present/documented/known/none-reported; case-b present/unknown/known/reported; case-c missing/unknown/unknown/unknown. A missing row is never converted to an event count of zero and then declared benign. A real ingestion adapter would validate enum types and deduplicate observations before this join to avoid one-to-many inflation.

### Complementary Sources and Tradeoffs

| Source/control | Useful independent fact | Boundary |
|---|---|---|
| Sysmon or Security process auditing | Process creation identity and parent context if configured | Not raw TI or complete memory-operation coverage; auditing/collection prerequisites differ |
| Product health/export diagnostics | Consumer/version/transport state where exposed | Heartbeat alone does not prove a specific event path |
| Application control and ASR | Supported prevention policies and action evidence | Not a substitute for proving the TI analytic's telemetry contract |
| Vendor-documented evaluation evidence | Product-specific expected output and provenance if stated | Valid only for supported product/build/scenario; not a universal coverage certificate |

More telemetry increases storage, CPU, and sensitive-data exposure. Narrow collection and access controls can be appropriate, but must be reflected in the coverage claim. Forensics can reconstruct only what was preserved; adding a source after an interval cannot repair historical absence.

## Detection and Defense

Keep three outputs: product-level scenario outcome, evidence quality, and provider attribution. Version the contract with the rule and parser. Block an assurance sign-off on unknown schema, missing expected signals, invalid timing, or reported loss. Retain independent corroboration as supporting evidence without upgrading it into TI provenance. Maintain supported prevention controls throughout diagnostics; a coverage gap is a risk-management finding, not permission to change protection.

## Labs

### Environment and Complete Files

Offline CTF: remove an unsupported green claim. Python 3.12 standard library only; all fictional scenario manifests and evidence are in the single file. Use a fresh scratch folder outside the vault. The `consumer_supported` and `documented_ti` booleans are synthetic evidence assertions, not a way to obtain Windows privileges or validate a real provider.

### File: test_example.py

```python
import unittest
from copy import deepcopy

EXPECTED = {"case-a": True, "case-b": True, "case-c": True, "case-d": False}
BASE = {"consumer_supported": True, "schema_known": True, "documented_ti": True,
		"event_count": 1, "losses": 0, "fresh": True, "corroborated": True}
OBSERVED = {"case-a": dict(BASE), "case-b": dict(BASE, documented_ti=False)}


def assess(expected, observed):
	result = {}
	for scenario, supported in expected.items():
		if not supported:
			result[scenario] = ["unsupported-scenario"]
			continue
		row = observed.get(scenario)
		if row is None:
			result[scenario] = ["missing-evidence"]
			continue
		gaps = []
		for field, reason in (("consumer_supported", "consumer-unknown"),
							  ("schema_known", "schema-unknown"),
							  ("documented_ti", "attribution-unknown"),
							  ("fresh", "stale-evidence")):
			if row.get(field) is not True:
				gaps.append(reason)
		if type(row.get("event_count")) is not int or row["event_count"] < 1:
			gaps.append("expected-signal-missing")
		if type(row.get("losses")) is not int or row["losses"] < 0:
			gaps.append("loss-unknown")
		elif row["losses"] > 0:
			gaps.append("loss-reported")
		result[scenario] = gaps or ["contract-supported"]
	return result


class CoverageTests(unittest.TestCase):
	def test_baseline_all_scenarios_remain_visible(self):
		self.assertEqual(assess(EXPECTED, OBSERVED), {
			"case-a": ["contract-supported"], "case-b": ["attribution-unknown"],
			"case-c": ["missing-evidence"], "case-d": ["unsupported-scenario"]})

	def test_corroboration_does_not_invent_provenance(self):
		for value in (True, False):
			rows = {"case-b": dict(OBSERVED["case-b"], corroborated=value)}
			self.assertEqual(assess({"case-b": True}, rows)["case-b"], ["attribution-unknown"])

	def test_fixed_retest_is_narrow(self):
		repaired = deepcopy(OBSERVED)
		repaired["case-b"]["documented_ti"] = True
		repaired["case-c"] = dict(BASE)
		result = assess(EXPECTED, repaired)
		self.assertEqual(sum(value == ["contract-supported"] for value in result.values()), 3)
		self.assertEqual(result["case-d"], ["unsupported-scenario"])
		self.assertFalse(OBSERVED["case-b"]["documented_ti"])

	def test_loss_and_staleness_are_not_suppressed(self):
		rows = {"case-a": dict(BASE, losses=2, fresh=False)}
		self.assertEqual(assess({"case-a": True}, rows)["case-a"],
						 ["stale-evidence", "loss-reported"])

	def test_zero_missing_and_bad_schema(self):
		rows = {"case-a": dict(BASE, event_count=0, losses=None, schema_known=False)}
		self.assertEqual(assess({"case-a": True}, rows)["case-a"],
						 ["schema-unknown", "expected-signal-missing", "loss-unknown"])


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Identify why a dashboard showing `event_count > 0` for all reporting cases overstates coverage. Account for all four expected scenarios.
2. Predict why independent corroboration does not resolve case-b. Run the offline suite from the scratch directory.
3. Inspect the corrected snapshot and explain why case-d remains unsupported even after the other evidence is supplied.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

The expected manifest defines the denominator. Provenance is a separate predicate from event presence. Preserve multiple findings: a stale record can also report event loss.

### Solution and Fixed Retest

Expected: five tests, `OK`. Baseline has one supported contract, one unknown attribution, one missing record, and one unsupported scenario. The fixed in-memory snapshot supplies documented attribution for case-b and evidence for case-c; three contracts are supported, but case-d stays unsupported. The healthy case-a is unchanged. This demonstrates evidence-accounting repair only, not a change to an actual sensor or proof of enforcement.

### Verification, Troubleshooting, and Cleanup

Check all scenarios remain visible, corroboration never substitutes for provenance, simultaneous quality failures survive, and original evidence is not mutated. Tests do not validate actual ETW permissions, schemas, loss counters, or threat coverage; no author execution occurred. If Python 3.12 is available without `py`, use its executable directly. Import errors usually mean the wrong scratch directory. Do not probe a live provider to settle a synthetic unknown. Cleanup:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

Original milestones remain unchanged and user-owned. The offline CTF neither completes them nor authorizes a live process-memory evaluation.

- [ ] Local ETW-TI exercise: Using an approved security-product test environment, inspect documented telemetry for a benign process-memory operation. Record the product/build and whether its documentation attributes that signal to ETW-TI.
- [ ] Boundary check: Verify the supported consumer is healthy and receives its documented benign evaluation signal; label provider attribution unknown when the product does not expose it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[ETW-TI]]

## References

- [ETW architecture and missing events](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Protected antimalware service requirements](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [EnableTraceEx2 statuses and access requirements](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
- [TDH metadata decoding](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation)
- [ETW session properties and loss statistics](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)

These sources establish the public ETW/protected-service boundaries, not a universal TI event schema. Any product-specific attribution or consumer entitlement must be separately documented.
