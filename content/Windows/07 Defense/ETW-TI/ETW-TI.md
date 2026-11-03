---
title: "ETW Threat Intelligence"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[ETW-TI Security]]"
updated: 2026-11-03
---
# ETW Threat Intelligence

> [!abstract] TL;DR
> ETW Threat Intelligence is a protected security-telemetry source, not a general Event Viewer feed or a public promise to record every memory operation. Separate provider identity, consumer authorization, decoding, transport health, and product attribution.

> [!info] Agent scope
> Threat-intelligence provider purpose; protected access requirements; consumers; supported observation; version-dependent coverage and limitations.

## Prerequisites

- Windows process/security fundamentals, ETW provider/controller/consumer roles, UTC time, and versioned event schemas.
- Offline lab: Python 3.12 standard library only. No driver, protected process, security product, administrator access, ETW session, or network is required.
- Live product evidence would require an approved supported consumer, documented entitlement, OS build, product/sensor version, diagnostics access, and retention. Ordinary administrator membership is not sufficient proof of ETW-TI access.

## Learn

```text
Teach me ETW Threat Intelligence at expert Windows defensive-telemetry depth.
Assume process/security and ordinary ETW basics. Explain the Threat-Intelligence
provider's purpose, sensitive process/memory-operation telemetry, protected
consumer requirements, and why admin rights, provider enumeration, or creating
a trace session do not establish authorized access or successful delivery.
Separate the stable public ETW API model from build-dependent TI event schemas
and product-private collection. Cover controller/provider/consumer APIs, event
descriptor/version/keyword/opcode, TDH decoding, process identity, buffers/loss,
event versus ingestion time, and supported product diagnostics. Explain protected
antimalware service signing/ELAM prerequisites without building or impersonating
a protected consumer; PPL status alone is not a universal provider entitlement.
Give real KQL over explicitly synthetic records, a complete offline schema and
provenance validation lab, failure classifications, and worked expected outputs.
Do not attribute generic product events to TI unless documented. State what public
primary sources do and do not guarantee, with version and prerequisite distinctions.
Teach here, no file/status edits. No live subscription experiments, attacks,
evasion, memory manipulation, patching, host-control or VPN changes. Do not claim
model results prove actual Windows protection. Finish with difficult worked questions.
```

## Cheatsheet

### Mechanism and Trust Boundaries

`Microsoft-Windows-Threat-Intelligence` provides security-relevant observations for appropriately trusted consumers. Treat descriptions of sensitive memory/process operations as categories, not a stable public enumeration of event IDs, keywords, or guaranteed coverage. Observed schemas and access checks can change with OS builds; product output can aggregate TI with other sensors. This note deliberately does not prescribe provider-enable masks or a homemade subscription client.

ETW production is not itself a prevention decision. A security product consumes evidence, enriches/correlates it, then may alert or take a separately authorized action. A read/write/protection-related observation does not alone identify intent, prove a successful operation, or guarantee an alert. The meaning of status/result fields belongs to the exact event schema.

| Boundary | Required evidence | Common invalid inference |
|---|---|---|
| Provider availability | Exact build and documented product capability | A provider name in a list means it is enabled or accessible |
| Controller/session | Supported product diagnostic state and enable result | Successful session creation means every provider enabled |
| Authorization | Product-supported trust/signing/registration requirements satisfied | An elevated ordinary process or any PPL process can consume TI |
| Decoding | Provider identity plus descriptor ID/version and payload schema | Same event ID on another build has identical layout |
| Delivery | Consumer progress, session-loss diagnostics where exposed, central arrival | Healthy product heartbeat proves a specific TI event reached analytics |
| Attribution | Vendor-documented source mapping or exposed provenance | A product memory alert must have come from TI |
| Prevention | Explicit control and result evidence outside the trace | Presence of an event proves an operation was blocked |

Windows protected antimalware services use signing and ELAM registration requirements to restrict loaded code and access. The public protected-service documentation explains that model, not blanket permission for every protected ETW provider. Use the vendor-supported integration path; do not alter protection levels, process memory, or access controls to inspect TI.

### Supported ETW APIs and Their Limits

| API/surface | Ordinary documented role | Important error/boundary |
|---|---|---|
| `StartTraceW` with `EVENT_TRACE_PROPERTIES` | Create/configure a session | Session existence/name conflicts and resource limits are distinct from provider permission |
| `EnableTraceEx2` | Enable a provider with level/keyword/filter parameters | Its returned status must be checked; successful session creation is not its result |
| `OpenTraceW`, `ProcessTrace` | Consume a permitted real-time session or ETL file | Session/file access, delivery mode, and consumer progress affect availability |
| `TdhGetEventInformation`, `TdhGetProperty` | Decode supported event metadata/properties | Missing metadata, version mismatch, and field types must be handled explicitly |
| `ControlTraceW` query operation | Obtain properties/statistics for an owned, authorized session | Loss counters describe a session, not universal sensor coverage; do not modify product-owned sessions |
| Vendor diagnostics/export | Supported observation of product health/events | May not expose raw TI events, buffer counts, or provenance; keep unavailable fields unknown |

ETW controller calls commonly return a status code directly; do not replace that status with an unrelated `GetLastError`. Some other APIs use different conventions, so follow each function's contract. Access denied is an authorization result, not a challenge to escalate or a silent success. Resource errors, no metadata, and zero events are different diagnoses.

### Schema and Data Quality Contract

Preserve provider GUID/name, event descriptor ID/version/opcode/task/keywords, OS build, consumer version, original event time, clock basis, activity/correlation ID if supplied, and payload bytes or normalized fields under an approved retention policy. The emitting header PID is not necessarily the operation's source or target PID; use documented payload roles. Resolve PIDs to process lifetime identity on the same host, not a timeless PID join.

Handle 32/64-bit pointer widths, schema lengths, optional fields, status encodings, and endian/type decoding through metadata rather than positional guesses. Do not publish raw process addresses or sensitive trace data. If a product does not expose a field, report `unknown`; do not manufacture a zero or map a generic product field to TI without documentation.

ETW buffering trades memory/flush latency against loss during bursts or a slow consumer. Lost event/buffer counts and consumer errors are useful only when the supported consumer exposes them. Zero known losses is weaker than proven complete coverage: unsupported operations, filtering, and unreported counters remain. A provider with no relevant activity can legitimately emit no matching events; evidence needs a documented expected signal.

### KQL: Source Attribution Without Guessing

Complete synthetic KQL using `datatable`, executable in a compatible Kusto query environment with no endpoint data. `VendorDocumented` is fixture evidence supplied by a hypothetical export contract, not a real MDE column. No built-in `ETWTI` hunting table is assumed. The frozen time makes results reproducible; live dashboards need current time and an authoritative expected population.

```kusto
let AsOf=datetime(2026-11-03T12:00:00Z);
datatable(Device:string, Seen:datetime, Provider:string, VendorDocumented:bool, Losses:long)
[
  "lab-a", datetime(2026-11-03T11:59:00Z), "Microsoft-Windows-Threat-Intelligence", true, 0,
  "lab-b", datetime(2026-11-03T11:59:00Z), "", false, 0,
  "lab-c", datetime(2026-11-03T10:00:00Z), "Microsoft-Windows-Threat-Intelligence", true, 2
]
| extend Attribution=iff(VendorDocumented and Provider == "Microsoft-Windows-Threat-Intelligence",
						  "documented-in-fixture", "unknown")
| extend Delivery=case(Seen > AsOf, "clock-error", Seen < AsOf - 15m, "stale",
					   isnull(Losses), "loss-unknown", Losses > 0, "loss-reported", "no-reported-loss")
| project Device, Attribution, Delivery
```

Expected rows: `lab-a` documented/no-reported-loss, `lab-b` unknown/no-reported-loss, `lab-c` documented/stale. Freshness takes precedence in this display; preserve the raw loss count as well when diagnosing. Even `lab-a` is not a prevention or completeness claim.

## Gotchas

- Generic ETW documentation is not a TI event-layout reference. Do not promote reverse-engineered event numbers into a supported cross-build contract.
- TI telemetry is not automatically stored in an ordinary Windows Event Log channel. Event Viewer queries and Sentinel WindowsEvent collection do not inherently collect it.
- An endpoint product may support a scenario without exposing its sensor provenance. Report product-level coverage and unknown TI attribution separately.

## Labs

### Environment and Complete Files

Offline provenance and schema validator. Python 3.12 standard library only, one file, no ETW or product dependencies. Use a fresh scratch directory outside the vault. `fixture-schema-v1` and `fixture-build-A` are explicitly fictional contract labels, not Windows builds or TI event versions. The validator checks a model contract, not actual Windows consumer authorization.

### File: test_example.py

```python
import unittest

PROVIDER = "Microsoft-Windows-Threat-Intelligence"
CONTRACT = {"build": "fixture-build-A", "schema": "fixture-schema-v1"}
BASE = {
	"device": "lab-a", "build": "fixture-build-A", "schema": "fixture-schema-v1",
	"authorized": True, "provider": PROVIDER, "documented_source": True,
	"source_process": "process-A", "target_process": "process-B",
	"event_seconds": 100, "arrival_seconds": 103, "lost": 0,
}


def validate(row):
	if row.get("authorized") is not True:
		return "consumer-not-established"
	if (row.get("build"), row.get("schema")) != (CONTRACT["build"], CONTRACT["schema"]):
		return "schema-unsupported"
	if row.get("provider") != PROVIDER or row.get("documented_source") is not True:
		return "attribution-unknown"
	if not all(row.get(field) for field in ("device", "source_process", "target_process")):
		return "identity-incomplete"
	event_time, arrival_time = row.get("event_seconds"), row.get("arrival_seconds")
	if type(event_time) is not int or type(arrival_time) is not int:
		return "time-invalid"
	if arrival_time < event_time or arrival_time - event_time > 10:
		return "time-invalid"
	losses = row.get("lost")
	if type(losses) is not int or losses < 0:
		return "loss-unknown"
	if losses > 0:
		return "loss-reported"
	return "contract-satisfied"


class ContractTests(unittest.TestCase):
	def test_baseline_and_source_fix(self):
		unknown = dict(BASE, documented_source=False)
		self.assertEqual(validate(unknown), "attribution-unknown")
		self.assertEqual(validate(BASE), "contract-satisfied")

	def test_authorization_and_schema_are_independent(self):
		self.assertEqual(validate(dict(BASE, authorized=False)), "consumer-not-established")
		self.assertEqual(validate(dict(BASE, build="fixture-build-B")), "schema-unsupported")
		self.assertEqual(validate(dict(BASE, schema="fixture-schema-v2")), "schema-unsupported")

	def test_wrong_provider_and_missing_identity(self):
		self.assertEqual(validate(dict(BASE, provider="ProductAggregate")), "attribution-unknown")
		self.assertEqual(validate(dict(BASE, target_process="")), "identity-incomplete")

	def test_time_and_loss(self):
		for changes, expected in (({"arrival_seconds": 99}, "time-invalid"),
								  ({"arrival_seconds": 111}, "time-invalid"),
								  ({"lost": None}, "loss-unknown"),
								  ({"lost": 1}, "loss-reported")):
			with self.subTest(changes=changes):
				self.assertEqual(validate(dict(BASE, **changes)), expected)

	def test_allowed_operation_is_not_classified_as_malicious(self):
		for purpose in ("debugger", "accessibility", "inventory"):
			self.assertEqual(validate(dict(BASE, purpose=purpose)), "contract-satisfied")
		self.assertNotIn("blocked", validate(BASE))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Predict separate labels for undocumented provenance, unauthorized consumer evidence, unsupported schema, and reported loss.
2. Run the suite in the scratch directory. The supplied repair adds synthetic documented provenance; it does not grant authorization or enable a provider.
3. Explain why the benign-purpose fixtures and the baseline have the same verdict: the validator tests evidence quality, not threat intent.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

A provider string is not sufficient provenance. A process relationship is not an intent verdict. Even a fully satisfied model contract says nothing about unmodeled Windows operations.

### Solution and Expected Results

Expected: five tests, `OK`. The baseline yields `contract-satisfied`; undocumented provenance yields `attribution-unknown`; changed build/schema yields `schema-unsupported`. Missing identity, negative/late delivery, missing loss counters, and reported loss each have a distinct outcome. A zero-loss documented fixture passes only this model's evidence contract. It never asserts real TI access or prevention.

### Verification, Troubleshooting, and Cleanup

Acceptance includes all five tests and an explanation of the authorization/schema/provenance distinction. Author execution was not performed. Python does not execute the KQL example; optional KQL execution requires an existing compatible query service, not an installed package or endpoint connection. If `py` is missing use an existing Python 3.12 executable; use the scratch directory for unittest discovery. Do not resolve an unknown verdict by trying live access. Cleanup:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

The original product-evidence milestones remain unchanged and uncompleted; this offline lab neither performs them nor authorizes live experiments.

- [ ] Local ETW-TI exercise: Using an approved security-product test environment, inspect documented telemetry for a benign process-memory operation. Record the product/build and whether its documentation attributes that signal to ETW-TI.
- [ ] Boundary check: Verify the supported consumer is healthy and receives its documented benign evaluation signal; label provider attribution unknown when the product does not expose it.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[ETW-TI Security]]

## References

- [ETW roles, buffers, and missing events](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Configuring ETW sessions and enabling providers](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session)
- [EnableTraceEx2 API contract](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
- [TDH event metadata](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation)
- [Protected antimalware service requirements](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)

These primary sources document ordinary ETW and protected services. They do not publish a universal supported ETW-TI event schema or grant arbitrary consumers access; product/build-specific attribution remains a separate evidence requirement.
