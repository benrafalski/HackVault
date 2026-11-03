---
title: "PatchGuard Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[PatchGuard]]"
updated: 2026-11-03
---
# PatchGuard Security

> [!abstract] TL;DR
> Unsupported modifications and assumptions about delayed integrity checks can cause instability or create unsafe security products.

> [!info] Agent scope
> Security of: Kernel Patch Protection purpose; unsupported modification risks; version sensitivity; supported alternatives; crash-analysis links only. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsupported modifications and assumptions about delayed integrity checks can cause instability or create unsafe security products.
- Distinguish unsupported driver design, accidental corruption, hardware faults, and incomplete evidence. Integrity-related crashes require provenance and version-matched analysis, not automatic attribution to the most recently loaded driver.

## Learn

```text
Teach defensive Kernel Patch Protection triage and driver-design review at
expert depth. Assume x64 driver lifecycle and Windows crash artifacts. Explain
the documented meaning of 0x109, parameter/version limits, detection latency,
and the distinction among unsupported modification, accidental driver damage,
hardware faults, and incomplete evidence. Compare signing, HVCI, and PatchGuard
without treating any one as universal protection. Give complete synthetic
evidence bundles, integrity checks, baseline/fixed triage logic, and supported
callback/filter alternatives with lifetime requirements. Use Microsoft primary
sources and put debugger procedures in a dedicated reference, not this lesson.
No bypasses, induced corruption, patching recipes, host changes, or file edits.
```

## Cheatsheet

### What a 0x109 Report Means

`CRITICAL_STRUCTURE_CORRUPTION` (0x109) reports detected corruption of critical kernel code/data. Microsoft's public reference reserves parameters 1-3 and documents parameter 4 as a corruption-region/type discriminator. For example, 0x1 describes function modification, 0x1C driver-object corruption, and 0x101 general pool corruption. These labels classify observed state; they do not identify the writer or prove malicious intent. Unknown subtypes require current build-matched documentation rather than guessed decoding.

Possible causes include accidental or deliberate driver modification, hardware corruption, and unsupported debugging/modification scenarios. The detection point can be later than the write. A dump with a kernel detection routine on top is not evidence that the kernel caused the defect. Small dumps can omit memory needed for attribution. Symbol mismatch can produce misleading names/interpretation; preserve exact OS and driver binaries/builds.

The x64 patching restriction is documented historically from Windows Server 2003 SP1; protected targets and detection implementation are not fixed public contracts across Windows versions. Do not claim a universal timer, complete target list, or health Boolean. No-crash testing is not a supported-design certificate. Keep all debugger commands in [[WinDbg]].

### Defensive Design Review

| Proposed product behavior | Required redesign/evidence |
|---|---|
| Modify undocumented kernel code/data to observe activity | Use documented notification, filter, WFP, or telemetry interface |
| Treat a signed driver as safe | Review input capabilities, bounds, access checks, synchronization, and lifetime |
| Use notification API as universal enforcement | Identify actual veto/access-reduction semantics and coverage gaps |
| Free callback state on unregister call entry | Honor API draining semantics and separately drain queued work |
| Treat immediate stability as compatibility | Document supported DDIs and test lifecycle/error paths on supported builds |
| Disable integrity protection to resolve a crash | Update/remove the incompatible component through supported approved servicing; preserve protection |

The supported alternatives still require engineering: process/image notifications borrow transient parameters; object callbacks have limited access-reduction operations; minifilters require volume/operation coverage and draining; WFP requires layer/action-right/flow lifetime correctness. Offloading policy to a service reduces kernel complexity but introduces availability and message-authentication requirements.

### Evidence Collection Contract

Record UTC incident time, OS build/revision, dump provenance/hash, bug-check value/parameters, driver versions/hashes/signature observations, recent approved changes, workload, and firmware/hardware health indicators. A file hash detects later alteration relative to the manifest; it does not prove trustworthy collection if an adversary controls both. Keep dumps private because they can contain secrets.

Complete read-only `Observe-Integrity.ps1` for an already provisioned disposable Windows 11 VM. This gathers bounded event/OS metadata only; it does not trigger a crash, enumerate secrets, change logging, or upload data.

```powershell
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$events = @()
$queryState = 'OK'
try {
	$events = @(Get-WinEvent -FilterHashtable @{
		LogName = 'System'
		ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
		Id = 1001
	} -MaxEvents 10 | ForEach-Object {
		[pscustomobject]@{
			TimeUtc = $_.TimeCreated.ToUniversalTime().ToString('o')
			Id = $_.Id
			Provider = $_.ProviderName
			RecordId = $_.RecordId
		}
	})
} catch { $queryState = 'NO_DATA_OR_QUERY_FAILURE' }
[pscustomobject]@{
	CapturedUtc = [DateTime]::UtcNow.ToString('o')
	Build = $os.BuildNumber
	LastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
	QueryState = $queryState
	Events = $events
} | ConvertTo-Json -Depth 4
```

A System 1001 record is provider-specific; not every event with ID 1001 is a bug check. This collector intentionally does not parse localized message text into a supposed trustworthy bug-check diagnosis. Analysis of the actual dump is separate. Read-only `Get-FileHash -Algorithm SHA256 -LiteralPath .\synthetic-report.json` illustrates artifact inventory without collecting a real dump.

## Detection and Defense

Preserve evidence before maintenance; compare reviewed driver releases and approved changes, then use supported servicing in a disposable reproduction environment. Correlation is a prioritization signal, not causal proof. Hardware errors require hardware-oriented investigation; repeated identical driver repros strengthen but do not alone complete attribution. Maintain code integrity, restrictive driver admission, least-privilege interfaces, and monitored inventory. Never reproduce unsupported writes to "confirm" a PatchGuard theory.

## Labs

### Environment and Complete Files

Python 3.11+ standard library, no elevation, VM, build, network, or dump needed. Save `synthetic-report.json` and `triage.py` below in an empty scratch directory. These are explicitly fabricated training records, not collected observations.

### File: synthetic-report.json

```json
[
  {"id":"integrity","build":"26100-lab","code":"0x109","parameter4":"0x1c","symbolsMatched":true,"dumpAvailable":true,"recentDriver":"ExampleSensor.sys"},
  {"id":"unknown-subtype","build":"26100-lab","code":"0x109","parameter4":"0x999","symbolsMatched":true,"dumpAvailable":true,"recentDriver":"ExampleSensor.sys"},
  {"id":"missing-dump","build":"26100-lab","code":"0x109","parameter4":"0x1","symbolsMatched":false,"dumpAvailable":false,"recentDriver":"ExampleSensor.sys"},
  {"id":"different-stop","build":"26100-lab","code":"0x9f","parameter4":"0x0","symbolsMatched":true,"dumpAvailable":true,"recentDriver":"ExampleSensor.sys"}
]
```

### File: triage.py

```python
import hashlib
import json
from pathlib import Path

LABELS = {0x1: "function modification", 0x1C: "driver-object corruption",
		  0x101: "general pool corruption"}

def flawed(report):
	return {"culprit": report["recentDriver"], "certainty": "confirmed"}

def triage(report):
	if int(report["code"], 16) != 0x109:
		route = "OTHER_BUGCHECK"
		region = "not decoded here"
	elif not report["dumpAvailable"] or not report["symbolsMatched"]:
		route = "INSUFFICIENT_EVIDENCE"
		region = "unverified"
	else:
		subtype = int(report["parameter4"], 16)
		region = LABELS.get(subtype, "unknown: consult build-matched documentation")
		route = "INTEGRITY_TRIAGE" if subtype in LABELS else "UNKNOWN_SUBTYPE"
	return {"route": route, "region": region, "culprit": None,
			"candidate": report["recentDriver"]}

raw = Path("synthetic-report.json").read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert hashlib.sha256(raw + b" ").hexdigest() != digest
reports = json.loads(raw)
assert flawed(reports[0])["certainty"] == "confirmed"
expected = ["INTEGRITY_TRIAGE", "UNKNOWN_SUBTYPE", "INSUFFICIENT_EVIDENCE", "OTHER_BUGCHECK"]
for report, route in zip(reports, expected, strict=True):
	result = triage(report)
	assert result["route"] == route
	assert result["culprit"] is None
	assert result["candidate"] == "ExampleSensor.sys"
	print(report["id"], result["route"], result["region"])
print("artifact-sha256=" + digest)
print("PASS: four evidence routes; no unsupported attribution; tamper detectable")
```

### Objectives, Hints, and Worked Solution

Run `python triage.py`. The flawed baseline calls the most recent driver confirmed responsible for every report. The fix classifies only the supported evidence, routes unknown/missing data explicitly, and keeps that driver as an investigation candidate rather than a verdict. The unrelated 0x9F record remains outside this decoder, preserving correct handling for nonintegrity cases.

Hint: a well-formed record and a matched symbol flag are synthetic prerequisites here, not a real debugger result. The four expected routes are printed in JSON order. The hash changes when even a trailing space is appended; this detects change relative to a retained manifest, not authenticity. A real case still needs private dump analysis using [[WinDbg]] and independent evidence before attribution.

### Verification, Troubleshooting, and Cleanup

No author execution. Python 3.11+ is required for strict zip behavior; malformed JSON or wrong working directory should fail rather than report success. No build is needed. Optional collector execution is `powershell.exe -NoProfile -File .\Observe-Integrity.ps1` inside an authorized disposable VM. No-data/query-failure must stay visible; do not trigger a crash to produce an event.

Actual dump analysis, driver load/work/unload stability, hardware diagnosis, and vendor reproduction remain unexecuted VM-only scope with snapshot, console, reviewed package, and matched symbols. This lab supplies no runtime driver or signing instructions. Delete synthetic files and keep any real evidence private under the user's retention policy. No host protections, boot settings, services, or VPN changes.

### Existing Study Checklist

- [ ] Local PatchGuard exercise: Review a driver design and replace proposed kernel patching with documented callbacks or filters. Study a public sample crash analysis without modifying protected kernel structures.
- [ ] Boundary check: Validate that the benign lab driver uses only documented registration/unregistration paths and remains stable through load, workload, and unload cycles.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[PatchGuard]]

## References

- [0x109 CRITICAL_STRUCTURE_CORRUPTION](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption)
- [Driver security checklist](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist)
- [Memory-integrity-compatible driver code](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hvci-compatible-code)
