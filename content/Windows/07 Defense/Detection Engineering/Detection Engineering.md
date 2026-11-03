---
title: "Detection Engineering (Sigma and KQL)"
aliases: []
tags: [windows, x7]
domain: windows
phase: "X7"
type: tech
status: draft
pair: "[[Detection Engineering Security]]"
updated: 2026-11-03
---
# Detection Engineering (Sigma and KQL)

> [!abstract] TL;DR
> A detection is a versioned hypothesis plus a telemetry contract, tested predicate, deployment schedule, and triage procedure. Sigma expresses intent; backend mappings and KQL determine actual matches. Missing data must produce a health finding, not a clean result.

> [!info] Agent scope
> Hypotheses; telemetry contracts; Sigma; KQL; mappings; test fixtures; false positives/negatives; rule lifecycle and coverage validation.

## Prerequisites

- Windows process identity/parentage, event schemas, Boolean logic, UTC timestamps, and basic query operations.
- Required lab dependency: Python 3.12 standard library only. No Sigma converter, Kusto service, endpoint agent, attacks, or internet access is required for the Python exercise.
- Optional backend validation requires an existing authorized Kusto environment and a pinned Sigma CLI/pySigma backend plus its matching processing pipeline. Those are separate dependencies and are not installed or validated here.

## Learn

```text
Teach me Windows detection engineering with Sigma and KQL at expert production
depth. Assume Windows process/event knowledge and Boolean/UTC basics. Derive a
review-worthy parent/child hypothesis, define source/field/type/identity/freshness
contracts, and show actual Sigma 2.1 syntax, Windows log-source mapping, Defender
XDR versus Sentinel KQL, and a complete synthetic fixture corpus. Explain map/list
AND/OR, modifiers, case/path/null semantics, exclusions, correlation identity,
event time versus ingestion time, late data, deduplication, and schedule windows.
Walk through positive, benign, lookalike, missing-field, wrong-source, and duplicate
tests with expected IDs. Distinguish testing a Python reference predicate from
parsing/converting Sigma, executing KQL, and deployed alert generation. Include
precision/recall limits, source health, triage evidence, ownership, peer review,
tuning, rollback, and versioned rule/mapping/fixture releases. Cite SigmaHQ and
Microsoft primary docs, state backend dependencies, and do not invent conversion
or execution results. Give difficult questions and worked answers.
Teach here; do not edit files or status. Use offline synthetic records only, no
actual attacks, endpoint behavior generation, live control changes, or VPN changes.
```

## Cheatsheet

### Hypothesis and Telemetry Contract

Example hypothesis: an Office word processor creating a shell-like child deserves contextual review. That relationship is not proof of malicious intent; approved automation can create the same relationship. The rule here is deliberately small and synthetic fixtures do not launch either application.

| Contract element | Concrete choice | Failure handling |
|---|---|---|
| Source | Windows process creation; Sysmon event 1 or mapped MDE `DeviceProcessEvents` | Other event classes/providers are not silently accepted |
| Required behavior fields | Child image and parent image/basename, nonempty strings | Missing/wrong-type fields enter a quality queue |
| Identity | Source event identity plus device; process GUID/unique ID where available | PID alone is not a permanent identity; conflicting duplicate IDs require review |
| Time | UTC event time, separate ingestion time, defined lookback and lateness budget | Future/skewed/late records are measured, not silently discarded |
| Decision | Parent `winword.exe`; child `cmd.exe` or `powershell.exe` | Approved automation can match; no blanket signed/admin exemption |
| Outcome | Review candidate with raw event and triage context | Not an ASR block claim or an incident by itself |

Keep raw source, parser version, normalized fields, rule version, query version, and alert identity linked. A successful query with the wrong source or time window is still a broken detection. Use an expected-device/source inventory for health, not only the rows that happened to match.

### Sigma: Exact Intent

Complete example rule using Sigma specification 2.1-compatible syntax. A map combines parent and child predicates with AND; the child list is OR. `endswith` gives a path-component suffix including the backslash, not a substring such as `notpowershell.exe`. Normal Sigma string comparisons are case-insensitive; backend conversion must preserve that.

```yaml
title: Word Processor Creating A Shell Review
id: 857608c8-e1fc-4ed1-b182-97244de8cb17
status: experimental
description: Review a word processor creating a shell child; legitimate automation can match.
date: 2026-11-03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\winword.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
fields:
    - Computer
    - ParentImage
    - Image
    - CommandLine
falsepositives:
    - Approved document automation
level: medium
```

This detects only two child names and one parent name. It is not complete Office coverage, not a detection of every shell, and not an implementation of the ASR Office-child rule. A rule tag or technique label does not expand its demonstrated scope. Missing parent fields need a separate quality test; negative matches cannot certify that those records are harmless.

### Mapping to Actual Tables

| Intent | Sysmon event 1 | MDE DeviceProcessEvents | Mapping caveat |
|---|---|---|---|
| Child image | `Image` full path | `FileName` basename plus `FolderPath` | A path suffix can map to basename equality only under a declared Windows path/basename contract |
| Parent image | `ParentImage` | `InitiatingProcessFileName` plus initiating folder fields | Parent identity is not the event header's collector process |
| Command line | `CommandLine` | `ProcessCommandLine` | Nullable/truncated/sensitive; not required for this predicate |
| Process identity | `ProcessGuid` | `ProcessUniqueId` where available, otherwise device/PID/start-time contract | Availability varies; never pretend MDE ReportId is a ProcessGuid |
| Event identity | Host/channel/log generation/record ID | `DeviceName`, `Timestamp`, `ReportId` context | ReportId alone repeats; rule deployment may require identity columns |

This hand-mapped Defender XDR query assumes onboarded MDE process telemetry and hunting access. It is not presented as verified Sigma compiler output. `in~` and `=~` preserve case-insensitive basename matching; `has` would tokenize strings and is not an equivalent path predicate.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ActionType == "ProcessCreated"
| where isnotempty(FileName) and isnotempty(InitiatingProcessFileName)
| where InitiatingProcessFileName =~ "winword.exe"
| where FileName in~ ("cmd.exe", "powershell.exe")
| project Timestamp, DeviceId, DeviceName, ReportId, FileName, FolderPath,
		  ProcessId, ProcessCreationTime, ProcessCommandLine,
		  InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime
```

For Sentinel `WindowsEvent`, first constrain Sysmon provider/channel/EventID and explicitly extract named `EventData` fields. `SecurityEvent` process auditing is another source with different fields and audit-policy prerequisites. A Sigma processing pipeline encodes these source and field mappings; changing only the backend name is not enough. Pin specification, CLI, backend, pipeline, and rule versions together and diff the generated query before release.

### Complete Synthetic KQL Check

This uses Kusto `datatable`, not a tenant table. Expected positive IDs are `positive` and `mixed-case`; the missing row remains a quality issue. Optional execution needs an existing compatible Kusto environment. The required offline lab below uses no Kusto service.

```kusto
datatable(Id:string, ParentImage:string, Image:string)
[
  "positive", @"C:\Apps\winword.exe", @"C:\Windows\System32\cmd.exe",
  "mixed-case", @"C:\Apps\WINWORD.EXE", @"C:\Tools\PowerShell.EXE",
  "benign", @"C:\Windows\explorer.exe", @"C:\Windows\System32\cmd.exe",
  "lookalike", @"C:\Apps\winword.exe", @"C:\Lab\notpowershell.exe",
  "missing", "", @"C:\Windows\System32\cmd.exe"
]
| extend Quality=iff(isempty(ParentImage) or isempty(Image), "missing-fields", "usable")
| extend Candidate=Quality == "usable"
	and ParentImage endswith @"\winword.exe"
	and (Image endswith @"\cmd.exe" or Image endswith @"\powershell.exe")
| project Id, Quality, Candidate
```

KQL `endswith` is case-insensitive; `endswith_cs` would change the contract. Kusto strings represent missing values as empty strings in many tabular contexts, unlike nullable numeric values; do not blindly translate SQL/Python null checks. Validate coercion/type behavior in the target schema.

### Lifecycle, Metrics, and Triage

Release unit: hypothesis + owner + source prerequisites + Sigma + backend mapping + generated/handwritten query + fixtures + triage instructions + schedule + dedup key + rollback revision. Roll out in review/shadow mode, measure representative benign volume, document narrow contextual exceptions, and retain positive regressions when tuning. A parser change is a detection change even if the Sigma file is untouched.

Precision is reviewed true positives divided by reviewed alerts; recall needs a known positive population and cannot be inferred from production quietness. Fixture recall is only corpus coverage. Report label uncertainty, alert volume per device/day, analyst effort, source freshness/field completeness, and detection latency separately. Monitor the analytic job's failures as well as endpoint health.

For a candidate, inspect device/user, parent/child identities, command line where permitted, app version, policy/ASR evidence, approved workflow context, and adjacent events. Escalate from evidence; do not auto-isolate a device solely on this toy relationship. Preserve original evidence and record tuning rationale without erasing contradictory rows.

## Gotchas

- A basic Sigma selection is not a stateful correlation engine; use the supported correlation specification/backend where sequence/aggregation is needed.
- Overlapping query windows improve late-event coverage but require event-level deduplication. Narrow nonoverlapping event-time windows can miss delayed ingestion.
- Detection deployment has additional platform constraints: required identity/time fields, frequency, lookback, RBAC, and action settings. A hunting query is not automatically a valid scheduled detection.

## Labs

### Environment and Complete Files

Offline predicate and adapter-contract lab, Python 3.12 standard library only. One file contains all synthetic events and the predicate. Use a fresh scratch directory outside the vault. No processes are launched; Windows paths are string data. The tests do not parse YAML, run a Sigma converter, execute KQL, or deploy an analytic. They establish the reference behavior against which those separate stages should be checked.

### File: test_example.py

```python
import unittest

FIXTURES = [
	{"id": "positive", "source": "process_creation", "parent": r"C:\Apps\winword.exe", "image": r"C:\Windows\System32\cmd.exe"},
	{"id": "mixed-case", "source": "process_creation", "parent": r"C:\Apps\WINWORD.EXE", "image": r"C:\Tools\PowerShell.EXE"},
	{"id": "benign", "source": "process_creation", "parent": r"C:\Windows\explorer.exe", "image": r"C:\Windows\System32\cmd.exe"},
	{"id": "lookalike", "source": "process_creation", "parent": r"C:\Apps\winword.exe", "image": r"C:\Lab\notpowershell.exe"},
	{"id": "missing", "source": "process_creation", "parent": "", "image": r"C:\Windows\System32\cmd.exe"},
]


def classify(row):
	if row.get("source") != "process_creation":
		return "wrong-source"
	if not all(isinstance(row.get(field), str) and row[field] for field in ("parent", "image")):
		return "missing-fields"
	parent, image = row["parent"].casefold(), row["image"].casefold()
	matched = parent.endswith("\\winword.exe") and image.endswith(("\\cmd.exe", "\\powershell.exe"))
	return "candidate" if matched else "no-match"


def evaluate(rows):
	seen = {}
	for row in rows:
		identity = row["id"]
		if identity in seen and seen[identity] != row:
			raise ValueError("conflicting-identity")
		seen[identity] = row
	return {identity: classify(row) for identity, row in seen.items()}


def from_mde(row):
	def full_name(value):
		return "C:\\fixture\\" + value if isinstance(value, str) and value else ""
	return {"id": row["id"], "source": "process_creation",
			"parent": full_name(row.get("InitiatingProcessFileName")),
			"image": full_name(row.get("FileName"))}


class DetectionTests(unittest.TestCase):
	def test_exact_expected_labels(self):
		self.assertEqual(evaluate(FIXTURES), {"positive": "candidate", "mixed-case": "candidate",
						 "benign": "no-match", "lookalike": "no-match", "missing": "missing-fields"})

	def test_source_and_types(self):
		self.assertEqual(classify(dict(FIXTURES[0], source="file_creation")), "wrong-source")
		self.assertEqual(classify(dict(FIXTURES[0], parent=None)), "missing-fields")
		self.assertEqual(classify(dict(FIXTURES[0], image=17)), "missing-fields")

	def test_duplicate_delivery_and_conflict(self):
		self.assertEqual(evaluate(FIXTURES + FIXTURES), evaluate(FIXTURES))
		with self.assertRaisesRegex(ValueError, "conflicting-identity"):
			evaluate(FIXTURES + [dict(FIXTURES[0], image=r"C:\Apps\reader.exe")])

	def test_mapped_basename_semantics(self):
		mapped = from_mde({"id": "mapped", "InitiatingProcessFileName": "WINWORD.EXE", "FileName": "cmd.exe"})
		self.assertEqual(classify(mapped), "candidate")
		missing = from_mde({"id": "missing", "FileName": "cmd.exe"})
		self.assertEqual(classify(missing), "missing-fields")

	def test_naive_contains_and_fixed_suffix(self):
		lookalike = FIXTURES[3]
		self.assertTrue("powershell.exe" in lookalike["image"].casefold())
		self.assertEqual(classify(lookalike), "no-match")
		self.assertEqual(classify(FIXTURES[0]), "candidate")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Predict all five fixture labels and compare the Sigma map/list logic with the KQL Boolean expression.
2. Run the exact offline suite. Explain how the suffix repair removes the lookalike without losing the two expected candidates.
3. Check missing fields separately from negative matches and identify the adapter's contract: its fabricated prefix exists only to compare basename semantics, not to reconstruct a real path.

```powershell
py -3.12 --version
py -3.12 -B -m unittest -v test_example
```

### Hints

Match a path component, not any substring. Case normalization must preserve intended Windows semantics. Never fill a missing parent with an assumed application name. Duplicate IDs with different payloads are not harmless delivery retries.

### Solution and Expected Results

Expected: five tests, `OK`; candidate IDs exactly `positive`, `mixed-case`. `benign` and `lookalike` are no-match; `missing` is a quality problem. Duplicates do not change the result, conflicting duplicates raise an error, and the MDE-basename adapter preserves the positive and missing-field cases. A candidate is review-worthy, not automatically a true security incident. The KQL fixture has the same expected labels, but backend equivalence remains unexecuted.

### Verification, Troubleshooting, and Cleanup

Acceptance includes exact IDs, not merely a match count. The model uses globally unique fixture IDs; production identities require source/device/time scope. No author execution or Sigma/KQL validation occurred. Python requires no third-party packages; use an existing Python 3.12 executable if `py` is unavailable. If discovery fails, run in the directory containing the file. Do not launch the named programs to create data; fixtures are sufficient. Cleanup:

```powershell
Remove-Item -LiteralPath .\test_example.py
```

### Preserved User Milestones

Original milestones remain unchanged and user-owned; running this model does not claim backend conversion or deployed detection validation.

- [ ] Local Detection Engineering exercise: Create synthetic process-event fixtures for one unusual parent/child relationship. Write a Sigma rule and a mapped KQL query, then test a positive, a benign lookalike, and a missing-field case.
- [ ] Boundary check: Require the positive fixture to match, the benign fixture not to match, and the missing-source case to surface as a coverage/health problem rather than a clean result.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X7 Defense|X7 Defense]]
- [[Detection Engineering Security]]

## References

- [Sigma rules specification 2.1](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma conversion and processing pipelines](https://sigmahq.io/docs/)
- [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Defender custom detections](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [Kusto string operators](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators)
- [Sentinel scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
