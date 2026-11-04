---
title: "ETW and Event Log Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[ETW and Event Log]]"
updated: 2026-11-03
---
# ETW and Event Log Security

> [!abstract] TL;DR
> Excessive logging permissions, disabled collection, unsafe sensitive fields, and unmonitored loss can expose data or create detection gaps.

> [!info] Agent scope
> Security of: Providers; sessions; consumers; event channels; manifests; permissions; collection; loss and retention; distinction from ETW-TI. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Collection authorization/configuration, event provenance/schema, payload parsing, privacy, buffer loss, forwarding/bookmarks, retention and consumer health.
- All security exercises use offline synthetic XML and health fixtures. No live provider/channel/session is disabled, cleared, altered or impersonated.

## Learn

```text
Teach defensive ETW/Event Log engineering with explicit evidence contracts.
Assume providers, sessions, channels, XML, access masks and timestamps. Separate
provider/schema identity from authenticated provenance, event ID from version,
record ID from application sequence, and emitted events from durable collection.
Explain trace-controller versus channel read/write/clear permissions, Security
channel constraints, manifest/TraceLogging decoding and ETW-TI protected access.
Design a bounded named-field parser and collection-health review using only
synthetic offline event XML: prove an ID-only false positive, correct provider/
version/channel checks, detect a sequence gap and stale heartbeat/loss evidence,
and show valid events still pass. Include reordered/missing/duplicate fields,
unknown versions and time handling. Explain why a gap is an investigation signal
not proof of malicious activity, and why zero loss counters do not prove coverage.
Use official sources and complete regression tests. No live collection changes,
log clearing, bypass/evasion, persistence, exploit or credential workflows.
Do not edit notes or fabricate runs; end with answered detection-design questions.
```

## Cheatsheet

### Evidence Contract

| Field/control | What it establishes | What it does not establish |
|---|---|---|
| Provider GUID/name + ID + version | Expected schema selection | Authenticated business actor or uncompromised endpoint. |
| Channel/computer/record ID | Source-scoped event location | Globally unique event identity or complete history. |
| Activity ID / application sequence | Producer-defined correlation/order | Universal causal order across producers/boots. |
| ETW loss counters | Reported loss for a particular session/path | Coverage of disabled/excluded providers or events never emitted. |
| Collector heartbeat/bookmark | Consumer progress/position according to its contract | All relevant events arrived or old records remain available. |
| Message rendering | Human-readable interpretation using available resources | A stable machine-readable schema across languages/versions. |

For native ETW, record session configuration, enabled provider GUIDs, level/keyword/filter choices, buffer settings, timing mode and loss statistics. For Event Log, record channel enablement/access/retention, query selectors/suppressors, oldest/newest retained evidence, bookmark and forwarding status. Keep clocks/time zones explicit. Missing events can arise at instrumentation, filtering, buffering, persistence, forwarding or parsing; diagnose each stage separately.

### Parsing and Authorization

Use `EvtRender` XML/values and named event data, not message substrings or fixed property offsets. Select the known provider, ID, version and channel before applying a decoder. Unknown versions should be reported as unsupported coverage, not silently mapped to old semantics. Reject duplicate required fields, validate numeric ranges, bound input sizes, and retain unmodified raw evidence separately under appropriate controls. `UserData` can have a publisher-specific schema; not every event uses `EventData/Data`.

Event Log XML's namespace must be handled by an ordinary XML parser. Its query engine's restricted XPath rules are a separate contract; a Python XPath working over an exported fixture is not automatically a valid `EvtQuery` expression. Rendered text can include untrusted application data; escape it in dashboards and never execute it as commands.

Trace-session control, provider enablement and channel ACLs are different capabilities. Typical trace authorization may involve administrators/Performance Log Users or explicitly delegated rights; this is not blanket Security-channel access or protected-provider access. Grant collectors only necessary source and destination rights, protect their configuration and bookmarks, and separate log-reader roles from policy administrators. [[ETW-TI]] has additional protected-access restrictions; no ordinary ETW example implies access to it.

### Health and Retention

Continuous producer sequence numbers are meaningful only if the schema guarantees them for the same producer instance. A filtered channel's record-ID gaps are normal and cannot be equated to lost source events. Heartbeats need a declared cadence and maximum lag; an old event time can reflect backlog rather than current failure. Distinguish producer time from receipt time and reject implausible future health timestamps rather than treating them as permanently fresh.

Overwriting oldest events loses history; retain/no-overwrite can lose new coverage when full; automatic archives require disk monitoring and collection. Forwarding is not immutable storage and can duplicate/reorder events across retries. Design deduplication around source identity and lifecycle, not event ID alone. Minimize secret/PII fields before emission; later redaction cannot remove copies already retained.

## Detection and Defense

Alert separately on schema failures, collection heartbeat lag, reported loss, forwarding backlog, source-policy drift and unexpected retention gaps. Correlate with maintenance windows, reboots, application upgrades and permission changes before assigning cause. Preserve raw fixtures and parser versions so a rule can be retested after upgrades. A synthetic fixture tests parsing and reasoning only; it cannot prove the live collector observed every event or that the source host is trustworthy.

## Labs

### Environment and Complete Files

Python 3.11+ stdlib, any OS. Two files in a new scratch directory. All events are authored fixtures in Windows Event XML shape, wrapped in an `Events` container for the exercise; they are not EVTX files or actual Microsoft provider records. No collector or event source is created. The application-specific `Sequence` is declared contiguous for one synthetic producer instance.

### File: events.xml

```xml
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event><System>
	<Provider Name="HackVault.Fixture" Guid="{8C321F42-984F-4EED-912A-1D2BC3445566}" />
	<EventID>1</EventID><Version>1</Version><Level>4</Level>
	<TimeCreated SystemTime="2026-11-03T12:00:00Z" />
	<EventRecordID>100</EventRecordID><Channel>HackVault/Fixture</Channel><Computer>offline.invalid</Computer>
  </System><EventData><Data Name="Sequence">1</Data><Data Name="Message">BENIGN</Data></EventData></Event>
  <Event><System>
	<Provider Name="Other.Fixture" Guid="{11111111-2222-4333-8444-555555555555}" />
	<EventID>1</EventID><Version>1</Version><Level>4</Level>
	<TimeCreated SystemTime="2026-11-03T12:00:01Z" />
	<EventRecordID>101</EventRecordID><Channel>HackVault/Fixture</Channel><Computer>offline.invalid</Computer>
  </System><EventData><Data Name="Sequence">2</Data><Data Name="Message">BENIGN</Data></EventData></Event>
  <Event><System>
	<Provider Name="HackVault.Fixture" Guid="{8C321F42-984F-4EED-912A-1D2BC3445566}" />
	<EventID>1</EventID><Version>1</Version><Level>4</Level>
	<TimeCreated SystemTime="2026-11-03T12:00:02Z" />
	<EventRecordID>102</EventRecordID><Channel>HackVault/Fixture</Channel><Computer>offline.invalid</Computer>
  </System><EventData><Data Name="Message">BENIGN</Data><Data Name="Sequence">3</Data></EventData></Event>
</Events>
```

### File: test_example.py

```python
import copy
from datetime import datetime, timezone
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
GUID = "{8c321f42-984f-4eed-912a-1d2bc3445566}"
NOW = datetime(2026, 11, 3, 12, 0, 30, tzinfo=timezone.utc)
HEALTH = {"last_receipt": "2026-11-03T12:00:02Z", "events_lost": 0}

def load():
	data = Path(__file__).with_name("events.xml").read_bytes()
	if len(data) > 65536:
		raise ValueError("fixture too large")
	return ET.fromstring(data)

def decode(event):
	provider = event.find("e:System/e:Provider", NS)
	if provider is None or provider.get("Guid", "").lower() != GUID:
		return None
	if event.findtext("e:System/e:Channel", namespaces=NS) != "HackVault/Fixture":
		return None
	if event.findtext("e:System/e:EventID", namespaces=NS) != "1":
		return None
	if event.findtext("e:System/e:Version", namespaces=NS) != "1":
		raise ValueError("unsupported version")
	fields = {}
	for node in event.findall("e:EventData/e:Data", NS):
		name = node.get("Name")
		if name in fields:
			raise ValueError("duplicate field")
		fields[name] = node.text
	if set(fields) != {"Sequence", "Message"} or fields["Message"] != "BENIGN":
		raise ValueError("schema")
	sequence = int(fields["Sequence"])
	if not 1 <= sequence <= 10000:
		raise ValueError("sequence range")
	return sequence

def gaps(sequences):
	values = set(sequences)
	return set(range(min(values), max(values) + 1)) - values if values else set()

def health_findings(record):
	timestamp = datetime.fromisoformat(record["last_receipt"].replace("Z", "+00:00"))
	if timestamp.tzinfo is None:
		raise ValueError("timezone required")
	age = (NOW - timestamp).total_seconds()
	findings = set()
	if age < 0 or age > 60:
		findings.add("receipt age")
	if record.get("events_lost") != 0:
		findings.add("loss or missing loss evidence")
	return findings

class EventReview(unittest.TestCase):
	def test_baseline_id_only_is_wrong(self):
		events = load()
		naive = [event for event in events if event.findtext("e:System/e:EventID", namespaces=NS) == "1"]
		self.assertEqual(len(naive), 3)
		accepted = [value for event in events if (value := decode(event)) is not None]
		self.assertEqual(accepted, [1, 3])
		self.assertEqual(gaps(accepted), {2})

	def test_fixed_retest_keeps_valid_events(self):
		event = load()[0]
		self.assertEqual(decode(event), 1)
		self.assertEqual(health_findings(HEALTH), set())
		self.assertEqual(gaps([1, 2, 3]), set())

	def test_named_fields_and_duplicates(self):
		event = load()[2]
		self.assertEqual(decode(event), 3)
		data = event.find("e:EventData", NS)
		data.append(copy.deepcopy(data[0]))
		with self.assertRaisesRegex(ValueError, "duplicate"):
			decode(event)

	def test_unknown_version_is_coverage_error(self):
		event = load()[0]
		event.find("e:System/e:Version", NS).text = "2"
		with self.assertRaisesRegex(ValueError, "unsupported"):
			decode(event)

	def test_stale_health_and_loss(self):
		stale = {"last_receipt": "2026-11-03T11:58:00Z", "events_lost": 2}
		self.assertEqual(health_findings(stale), {"receipt age", "loss or missing loss evidence"})
		self.assertEqual(health_findings(HEALTH), set())

if __name__ == "__main__":
	unittest.main()
```

### Objectives, Baseline, and Hints

Run `python -m unittest -v test_example`. The ID-only baseline selects three records, falsely allowing an unrelated provider to fill sequence 2. The fixed decoder selects only sequences 1 and 3, exposing a gap under the declared producer contract. Hint: the two legitimate records deliberately use different data-field order; named parsing must retain both.

### Solution and Fixed Retest

Expected five passing tests. Legitimate events still decode; another provider is ignored; an unknown version and duplicate field raise coverage errors. Stale receipt/loss fixtures generate two health findings, while the healthy fixture passes unchanged. The `[1,2,3]` retest is a complete synthetic sequence, not a claim that a missing real record was recovered. No live logging component is touched.

### Verification, Troubleshooting, and Cleanup

Require five tests with `OK`, not a fabricated live collection result. Missing file means XML and test are not colocated. The namespace and literal fixture timestamps are intentional; `NOW` is fixed for reproducibility. This parser is for bounded authored fixtures, not a hardened ingestion service for arbitrary hostile XML. Remove only the two scratch files and local `__pycache__`. Source reviewed; parent must run the tests. Live ETW loss accounting, Event Log ACLs, forwarding, retention and ETW-TI access remain unexecuted and unverified.

- [ ] Local ETW and Event Log exercise: Decode provider/version-aware offline fixtures and declared collection-health evidence.
- [ ] Boundary check: Detect false-positive schema matches, sequence gaps and stale/lost collection evidence while preserving valid records.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[ETW-TI]]
- [[Detection Engineering]]
- [[ETW and Event Log]]

## References

- [About ETW and missing events](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Consuming Event Log events](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)
- [Event XML schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema)
- [Event tracing properties and counters](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
- [Windows Event Log API](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
