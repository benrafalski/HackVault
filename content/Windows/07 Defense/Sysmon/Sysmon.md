---
title: "Sysmon"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[Sysmon Security]]"
updated: 2026-11-03
---
# Sysmon

> [!abstract] TL;DR
> Sysmon produces selected, versioned endpoint events. Design filters from evidence requirements, correlate with host plus ProcessGuid, and verify delivery separately. Most events are observations; newer file-blocking features have distinct semantics and are not a general EDR engine.

> [!info] Agent scope
> Event schema; configuration and filtering; collection; correlation; event volume; coverage limitations; controlled validation.

## Prerequisites

- Windows process lifetimes, XML event structure, UTC time, and event forwarding. [[Detection Engineering]] covers rule lifecycle.
- Offline lab: Python 3.12 standard library only, no installed Sysmon, Windows VM, privileges, or network.
- For real inspection record Sysmon binary version, configuration schema version/hash, Windows build, event version, and collector mapping. The current download page lists Windows 11+ and Server 2019+; historical event support is not support for the latest binary on an old OS.

## Learn

```text
Teach me Windows Sysmon at expert telemetry-engineering depth. Assume knowledge
of process lifetimes, event logs, XML, and UTC. Explain driver/service -> filters
-> Operational channel -> forwarding -> normalized schema -> correlation/rules.
Distinguish binary, XML configuration schema, and event versions; cover event
families 1/3/5/6/7/8/10/11/12-14/16/22/23/25-29/255 without attack procedures.
Explain include/exclude precedence, empty filters, explicit RuleGroup relations,
ProcessGuid and ParentProcessGuid versus PID reuse, timestamp and record identity,
high-volume classes, signatures/hashes, privacy, retention, and loss diagnosis.
Show real XML, read-only inspection, WEF XPath, Sigma/KQL mappings, and a complete
offline synthetic XML parsing/correlation lab with positive, benign, duplicate,
missing-field, wrong-provider, and PID-reuse tests. Separate observation from
specific supported file-blocking capabilities and from an EDR detection engine.
Cite public Microsoft documentation, state build/configuration prerequisites and
unsupported assumptions, and give difficult questions with worked answers.
Teach here; do not edit files or status. Do not install/configure services, generate
attacks, change VPN/host controls, or claim synthetic fixtures prove live coverage.
```

## Cheatsheet

### Event Contract and Correlation

Sysmon's driver/service observes supported activity and writes `Microsoft-Windows-Sysmon/Operational`. Preserve `System.Provider`, `EventID`, `Version`, `Computer`, `TimeCreated`, `EventRecordID`, and named `EventData` fields. Parse XML by names and namespace, not rendered `Message` positions: localization and schema revisions change those positions. `EventRecordID` is channel-local and can reset; include host/channel and a log-generation boundary for durable deduplication.

| Events | Evidence and useful fields | Coverage/cost boundary |
|---|---|---|
| 1 / 5 | Process start/exit; `ProcessGuid`, `ProcessId`, `Image`; start adds parent, command line, hashes | Correlate by host + GUID; parent/process start can predate retention |
| 3 / 22 | Network connection / DNS query; process identity and destination/query | Network logging is not enabled by default; DNS query is not proof of a connection or successful resolution |
| 6 / 7 | Driver / image load; hashes and signature metadata | Image-load volume can be large; signature processing can be asynchronous; signed does not mean safe |
| 8 / 10 | Remote-thread / process-access observations | Not every memory operation or compromise; diagnostics can be noisy; inferred module/function fields may be empty |
| 11 / 12-14 | File creation/overwrite; registry object/value/rename | Selected operations only; not an audit of every file read or registry read |
| 16 / 4 / 255 | Configuration change / service state / errors | Operational-health evidence, not periodic device heartbeats; no recent 16 is often normal |
| 23 / 26 | File deletion with archive / without archive | Archive disk use and sensitive content handling differ substantially |
| 25 / 29 | Process image-change detection / executable-file detection | Version-dependent specific signals, not universal execution coverage |
| 27 / 28 | Executable-file creation block / file-shredding block | Specific prevention features; a 1/3/10 observation does not imply blocking |

Normalize GUID case and brace representation consistently across all sources; do not invent a GUID when absent. Scope joins to host even if GUIDs are designed to be unique. For PID-only sources require device, process start time, and a bounded lifetime; joining every event on PID creates false chains after reuse. Keep UTC event time separate from collector ingestion time.

### Filter Semantics and Concrete XML

Use the installed binary's schema as the authority. Configuration `schemaversion` is not the executable's version. `onmatch="include"` keeps matching events; `onmatch="exclude"` drops matching events, with exclusions taking precedence over includes. Empty include means include none for that event; empty exclude means exclude none. Make compound relations explicit with `RuleGroup`/`Rule`; do not rely on defaults remembered from another schema version. Conditions are case-insensitive; a substring path match is not a signer or ACL check.

This reference configuration requests process starts, DNS queries, and network connections only for a fictitious `C:\Lab\marker.exe`. It is not a fleet configuration and is not installed in the lab. Confirm schema compatibility with the actual binary before any separately approved deployment.

```xml
<Sysmon schemaversion="4.82">
	<HashAlgorithms>SHA256</HashAlgorithms>
	<EventFiltering>
		<RuleGroup name="marker-process" groupRelation="or">
			<ProcessCreate onmatch="include">
				<Image condition="is">C:\Lab\marker.exe</Image>
			</ProcessCreate>
		</RuleGroup>
		<RuleGroup name="marker-network" groupRelation="or">
			<NetworkConnect onmatch="include">
				<Image condition="is">C:\Lab\marker.exe</Image>
			</NetworkConnect>
			<DnsQuery onmatch="include">
				<Image condition="is">C:\Lab\marker.exe</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
```

Read-only inspection references for an already installed, authorized system. `-s` displays schema; `-c` without a file displays configuration. Neither installs or changes rules:

```powershell
.\Sysmon64.exe -s
.\Sysmon64.exe -c
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,22,255} -MaxEvents 20 |
		ForEach-Object { $_.ToXml() }
```

This WEF subscription query fragment selects both observations and diagnostic events. It is not a complete subscription or an instruction to enable forwarding; subscription authentication, ACLs, delivery mode, collector retention, and existing management ownership still require configuration.

```xml
<QueryList>
	<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
		<Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=1 or EventID=3 or EventID=4 or EventID=16 or EventID=22 or EventID=255)]]</Select>
	</Query>
</QueryList>
```

### KQL: Correlate Start and DNS Records

Microsoft Sentinel `WindowsEvent` reference, assuming collection into that table and a dynamic `EventData` bag retaining these names. An `Event` or `SecurityEvent` connector needs a different parser; do not substitute the table name alone. DNS can arrive before the start event in ingestion order; a left join preserves unmatched DNS for review.

```kusto
let Source = WindowsEvent
| where TimeGenerated > ago(1d)
| where Provider == "Microsoft-Windows-Sysmon"
| where Channel == "Microsoft-Windows-Sysmon/Operational"
| extend ProcessGuid=tolower(tostring(EventData.ProcessGuid));
let Starts = Source
| where EventID == 1 and isnotempty(ProcessGuid)
| summarize arg_min(TimeGenerated, *) by Computer, ProcessGuid
| project Computer, ProcessGuid, StartTime=TimeGenerated, Image=tostring(EventData.Image);
Source
| where EventID == 22
| extend QueryName=tostring(EventData.QueryName)
| join kind=leftouter Starts on Computer, ProcessGuid
| extend Correlation=iff(isnull(StartTime), "missing-start", "linked")
| project TimeGenerated, Computer, ProcessGuid, QueryName, Image, StartTime, Correlation
```

Use a longer start-event lookback for long-lived processes, balanced against join cost. A missing start can mean filter loss, retention, startup before the window, or malformed GUID, not necessarily maliciousness. For production, parse the provider's `UtcTime` and compare to `TimeGenerated`; bound negative deltas and late arrivals rather than assuming clock accuracy.

### Volume and Data Quality

Estimate raw daily bytes as devices × events/second × average bytes × 86,400, then measure forwarding and index overhead separately. For 100 devices × 2 events/s × 1,000 bytes, raw volume is 17.28 GB/day (decimal), before indexing. Size retention for peak rates and collector outages, not just averages. Use p95/p99 latency, invalid-field rate, event counts by ID/config revision, and expected synthetic-marker delivery to assess changes. Event 255 is useful but not a complete loss counter; no errors is not proof no events were dropped.

## Gotchas

- Empty `StartModule` is permitted in some events; it is not sufficient evidence of a threat.
- Network and image-load coverage are configuration-dependent. Broad collection may expose sensitive command lines, DNS names, and deleted contents.
- Sysmon filtering can remove evidence before forwarding. Downstream queries cannot recover discarded events.

## Labs

### Environment and Complete Files

Offline XML parsing and PID-reuse CTF. Python 3.12 standard library only. Put this single file in a new scratch folder outside the vault. The abbreviated XML preserves real Sysmon field names but is synthetic, not captured output. No marker process, DNS request, service, or live collector is created. All input data is embedded.

### File: test_example.py

```python
import unittest
import xml.etree.ElementTree as ET

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDER = "Microsoft-Windows-Sysmon"


def fixture(host, event_id, guid, image, record):
		event = ET.Element("Event", xmlns=NS)
		system = ET.SubElement(event, "System")
		ET.SubElement(system, "Provider", Name=PROVIDER)
		for key, value in (("EventID", event_id), ("Computer", host),
											 ("EventRecordID", record)):
				ET.SubElement(system, key).text = str(value)
		data = ET.SubElement(event, "EventData")
		for key, value in (("ProcessGuid", guid), ("ProcessId", "42"), ("Image", image)):
				ET.SubElement(data, "Data", Name=key).text = value
		return ET.tostring(event, encoding="unicode")


def parse(text):
		root = ET.fromstring(text)
		namespaces = {"ev": NS}
		provider = root.find("ev:System/ev:Provider", namespaces)
		if provider is None or provider.get("Name") != PROVIDER:
				raise ValueError("provider")
		def field(name):
				return root.findtext("ev:System/ev:" + name, namespaces=namespaces)
		data = {item.attrib["Name"]: item.text or ""
						for item in root.findall("ev:EventData/ev:Data", namespaces)}
		if not field("Computer") or not data.get("ProcessGuid"):
				raise ValueError("identity")
		return {"host": field("Computer"), "event": int(field("EventID")),
						"record": int(field("EventRecordID")), "guid": data["ProcessGuid"].lower(),
						"image": data.get("Image", ""), "pid": data.get("ProcessId")}


def correlate(rows):
		starts = {(row["host"], row["guid"]): row["image"]
							for row in rows if row["event"] == 1}
		return [(row["record"], starts.get((row["host"], row["guid"]), "missing-start"))
						for row in rows if row["event"] == 22]


ROWS = [
		fixture("lab-a", 1, "{A}", r"C:\Lab\first.exe", 1),
		fixture("lab-a", 1, "{B}", r"C:\Lab\second.exe", 2),
		fixture("lab-a", 22, "{a}", r"C:\Lab\first.exe", 3),
		fixture("lab-b", 22, "{A}", r"C:\Lab\other.exe", 4),
]


class SysmonTests(unittest.TestCase):
		def test_guid_not_reused_pid(self):
				rows = [parse(text) for text in ROWS]
				self.assertEqual({row["pid"] for row in rows}, {"42"})
				self.assertEqual(correlate(rows), [(3, r"C:\Lab\first.exe"), (4, "missing-start")])

		def test_input_order_does_not_change_identity(self):
				rows = [parse(text) for text in ROWS]
				self.assertEqual(sorted(correlate(rows)), sorted(correlate(list(reversed(rows)))))

		def test_missing_identity_is_error(self):
				with self.assertRaisesRegex(ValueError, "identity"):
						parse(fixture("lab-a", 22, "", "", 5))

		def test_wrong_provider_is_error(self):
				with self.assertRaisesRegex(ValueError, "provider"):
						parse(ROWS[0].replace(PROVIDER, "OtherProvider"))

		def test_missing_start_and_fixed_retest(self):
				rows = [parse(text) for text in ROWS[2:]]
				self.assertEqual(correlate(rows)[0], (3, "missing-start"))
				rows.append(parse(ROWS[0]))
				self.assertEqual(correlate(rows)[0], (3, r"C:\Lab\first.exe"))


if __name__ == "__main__":
		unittest.main()
```

### Objectives and Steps

1. Predict which image owns record 3 and why record 4 must remain unmatched, despite every event using PID 42.
2. Run the exact offline suite from the scratch folder. No configuration XML is installed.
3. Inspect the missing-start retest: restoring a start record repairs a correlation, not an actual Windows process or sensor.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

The host boundary is independent of GUID normalization. Build an identity index from all starts rather than assuming arrival order. Reject a missing identity instead of joining empty values across events.

### Solution and Expected Results

Expected: five tests, `OK`. Record 3 maps to `C:\Lab\first.exe`, never `second.exe`; record 4 remains `missing-start`. The deliberately flawed alternative, a PID-keyed dictionary, would overwrite `first.exe` with `second.exe`. Sorting delivery does not repair that identity error. Missing GUID and wrong provider are explicit errors. These short GUID labels are synthetic identifiers, not a GUID-format validator.

### Verification, Troubleshooting, and Cleanup

The tests cover parser namespacing, wrong provider, absent identity, reordered rows, host separation, and missing evidence. They do not execute Sysmon XML filtering, WEF, or KQL. Production parsing also needs event version/type validation, duplicate-field policy, log-generation identity, and timestamp checks. No execution was performed during authorship. If the launcher is absent, use an existing Python 3.12 executable; if tests cannot import, use the directory containing the file. The XML parser handles only the supplied trusted small fixtures, not arbitrary uploaded XML. Cleanup:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

Original milestones remain unchanged; this offline lab does not claim their live-VM completion or authorize live filter changes.

- [ ] Local Sysmon exercise: In a disposable VM, use a reviewed Sysmon configuration and run a harmless process/file/DNS marker. Inspect the expected events and correlate them by process identity.
- [ ] Boundary check: Change one test filter deliberately and verify the expected marker's inclusion/exclusion, then restore the reviewed configuration and confirm forwarding.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Sysinternals]]
- [[Detection Engineering]]
- [[Sysmon Security]]

## References

- [Sysmon schema, configuration, event IDs, and current platform support](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event Forwarding design](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [WindowsEvent table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent)
- [Windows event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema)
