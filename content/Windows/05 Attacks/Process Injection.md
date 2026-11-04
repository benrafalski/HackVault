---
title: "Process Injection"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Process Injection

> [!abstract] TL;DR
> Injection analysis asks whether execution inside a process is consistent with that process's authorized origin and purpose. Cross-process access, memory characteristics, and thread evidence are complementary signals, not interchangeable proof.

> [!info] Agent scope
> Cross-process access/execution concepts, rights, common families, architecture constraints, detection and mitigation. No injection routines, payloads, memory modification, thread manipulation, or operational sequences; the lab uses offline metadata.

## Learn

```text
Teach process-injection mechanisms and defensive evidence at expert depth. Assume
Windows process/thread objects, handles, PE loading, virtual memory protections,
tokens, and ABI basics. Explain memory provenance versus execution provenance;
separate access rights, data changes, mapping, scheduling, and execution evidence
without assembling an operational sequence. Compare library-backed execution,
private executable regions, APC-associated activity, existing-thread context
changes, and image/state inconsistencies conceptually. Explain same-user rights,
integrity/PPL restrictions, handle lifetime, WOW64/architecture constraints, loader
lock, mitigations, and legitimate debugger/JIT/security-tool overlap.
Show how Sysmon process access, remote-thread, image-load, process-tampering, and
independent behavior records support or fail to support a hypothesis. Require
stable process IDs, host/boot/time scope, event availability, and explicit unknowns.
Give a complete Python 3.12 stdlib offline synthetic correlation lab with benign
controls, missing events, unrelated source/target pairs, and malformed metadata.
No shellcode, injection code, remote allocation/writes, thread/APC manipulation,
payload loading, mitigation bypass, or other-process modification, even in a toy
CTF. No execution of attacks or real process inspection is required. Explain
controls, compatibility and version limits using public primary references.
No confidential data or page-table material; debugger commands only in WinDbg.
Include hints, separate solution, tests, and questions; do not edit study status.
```

## Cheatsheet

### Mechanisms Without Implementation Recipes

| Family | Distinguishing concept | Evidence question / limitation |
|---|---|---|
| Library-backed execution | Execution associated with an image mapped in another process | Is the image/loading relationship authorized? A signed image is not proof of authorized invocation |
| Private-region execution | Executable memory not represented as a normal loaded image | JIT runtimes also use private executable regions; provenance and behavior matter |
| APC-associated execution | Work associated with a thread's APC delivery semantics | Queue-related evidence is not proof of execution; thread state and APC type matter |
| Existing-thread state changes | Execution context inconsistent with the thread's normal continuation | A new-thread-only analytic can miss this family; debugger activity overlaps |
| Image/state replacement families | Process identity or original image metadata differs from observed execution state | Packaging, instrumentation, and incomplete telemetry can also produce mismatches |

Do not treat this taxonomy as a sequence of actions. It identifies different hypotheses to evaluate from already available evidence. Not every family needs a new thread, a newly loaded DLL, or simultaneously writable/executable memory. Conversely, observing one of these features does not establish injection.

### Access, Architecture, and Lifetime

Process-object rights are separate from thread-object rights. For defensive mask interpretation, `PROCESS_VM_OPERATION=0x0008`, `PROCESS_VM_READ=0x0010`, `PROCESS_VM_WRITE=0x0020`, `PROCESS_CREATE_THREAD=0x0002`, and `PROCESS_QUERY_LIMITED_INFORMATION=0x1000`. A granted process mask indicates an allowed capability, not a performed operation. Rights can originate from earlier handle acquisition or duplication, so absence of a nearby open event is not proof of absence of access.

An object's DACL, caller token, integrity restrictions, protected-process state, and supported API contract affect access. Debug privileges are not a universal exception to PPL. Handles retain object identity; numeric PIDs do not. Use sensor-provided process GUIDs or a host/boot/PID/start-time tuple to avoid joining to a later process with a recycled PID.

Pointer width, executable machine type, WOW64 state, ABI, and runtime layout affect interpretation. A 32-bit collector's view may differ from a 64-bit target's complete module/address view. Loader-lock and initialization semantics complicate attributing module-related behavior; a successful mapping is not proof of successful initialization or execution. Do not infer platform support from one observed event on another Windows build.

### Detection Contract

| Signal | Useful fields | Limits |
|---|---|---|
| Sysmon 10 ProcessAccess | Source/target process GUID, granted access, call-trace context when present | Configurable/noisy; not all denial or memory-operation evidence |
| Sysmon 8 CreateRemoteThread | Source/target identity, start address/module/function when resolved | A specific family only; unresolved start module is not a verdict |
| Sysmon 7 ImageLoad | Image identity, signature context, process | Must be configured; high volume; module presence is not intent |
| Sysmon 25 ProcessTampering | Supported image-tampering categories | Coverage/version-specific, not universal memory-integrity monitoring |
| Memory/EDR evidence | Region provenance, protection, thread context, behavior | Product-specific acquisition, rights, retention and schema |

Correlate independent evidence for the same host/source/target within a justified interval. A known debugger, profiler, accessibility tool, runtime, or sensor may have legitimate overlapping behavior; approvals should be bound to identity, version, target scope, and change ownership. Do not silently drop all signed tools. Sparse evidence should remain a lower-confidence review, not become "benign" simply because a compound rule cannot match.

The lab's rule correlates abstract access and thread events. Its extra `private_start` and `approved_pair` fields are **synthetic enrichment**, not claimed native Sysmon fields. It is an executable example of a correlation contract, not a universal injection detector.

## Defense

Minimize debugging/administrative rights, restrict process exposure, use supported protected processes for security components, and deploy compatible application/exploit controls. ACG constrains dynamic executable-memory policy; CIG constrains image signature policy; CFG/XFG and shadow stacks cover selected control transfers. Each has application, OS, compiler, and hardware requirements. See [[Windows Exploit Mitigations]] rather than assuming one control stops all families.

Preserve legitimate debugging/JIT workflows through scoped development environments and reviewed policies, not broad production exemptions. In an incident, assess the integrity and identity context of both source and target; terminating a suspect source alone does not establish that the target is clean. Evidence acquisition and containment require authorized procedures beyond this offline exercise.

## Labs

### Environment and Complete Files

Defensive correlation challenge, not execution of injection. Python **3.12**, standard library only, an offline exercise directory and ordinary account. All process identities are labels; no process handles, memory reads/writes, or Windows APIs are used.

### File: test_example.py

```python
import unittest


ACCESS = {"kind": "access", "host": "lab", "source": "guid-a", "target": "guid-b",
		  "time": 10, "granted": 0x0028, "approved_pair": False}
THREAD = {"kind": "thread", "host": "lab", "source": "guid-a", "target": "guid-b",
		  "time": 12, "private_start": True}


def review(events):
	alerts = []
	for event in events:
		if event.get("kind") != "thread":
			continue
		matches = [record for record in events
				   if record.get("kind") == "access"
				   and all(record.get(field) == event.get(field)
						   for field in ("host", "source", "target"))
				   and all(isinstance(record.get(field), str) and record[field]
						   for field in ("host", "source", "target"))
				   and type(record.get("time")) is int
				   and type(event.get("time")) is int
				   and 0 <= event["time"] - record["time"] <= 30]
		if len(matches) != 1:
			alerts.append("unresolved-correlation")
			continue
		access = matches[0]
		mask = access.get("granted")
		if type(mask) is not int or mask < 0:
			alerts.append("unknown-rights")
		elif access.get("approved_pair") is True:
			alerts.append("approved-context-review")
		elif mask & 0x0028 == 0x0028 and event.get("private_start") is True:
			alerts.append("correlated-review")
		else:
			alerts.append("limited-evidence-review")
	return alerts


class InjectionEvidenceTests(unittest.TestCase):
	def test_compound_evidence_is_review_not_verdict(self):
		self.assertEqual(review([ACCESS, THREAD]), ["correlated-review"])

	def test_false_join_is_rejected(self):
		for field in ("host", "source", "target"):
			with self.subTest(field=field):
				unrelated = dict(THREAD, **{field: "other"})
				self.assertEqual(review([ACCESS, unrelated]), ["unresolved-correlation"])

	def test_benign_and_weaker_evidence_is_preserved(self):
		self.assertEqual(review([dict(ACCESS, approved_pair=True), THREAD]),
						 ["approved-context-review"])
		self.assertEqual(review([dict(ACCESS, granted=0x1000), THREAD]),
						 ["limited-evidence-review"])

	def test_missing_stale_and_invalid_records(self):
		self.assertEqual(review([THREAD]), ["unresolved-correlation"])
		self.assertEqual(review([ACCESS, dict(THREAD, time=41)]), ["unresolved-correlation"])
		self.assertEqual(review([dict(ACCESS, granted="0x28"), THREAD]), ["unknown-rights"])
		self.assertEqual(review([ACCESS]), [])


if __name__ == "__main__":
	print("Pair:", review([ACCESS, THREAD]))
	print("Thread only:", review([THREAD]))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

The flawed baseline is "any write-capable access and any thread event in a window are related." Use the mismatched fixtures to refute it. Explain why the complete matching pair gets review priority, why the approved pair is still retained, and why access-only input produces no conclusion from this thread-focused rule.

### Hints

Relationship identity matters before mask interpretation. Empty results mean no thread record was evaluated, not absence of injection. The mask check identifies two granted capabilities in this model; it does not prove they were used or that a complete execution mechanism existed.

### Solution and Fixed Retest

The matching pair yields `correlated-review`; a thread alone yields `unresolved-correlation`. The corrected host/source/target predicate rejects unrelated joins, preserves approved context, and avoids upgrading query-only access to the compound finding. The final access-only assertion explicitly exposes the rule's blind spot: other families need other analytics. No finding warrants a claim that code actually ran in another process.

### Evidence, Troubleshooting, and Cleanup

Expected: two printed summaries and **4 passing tests**. Preserve matched identities, timestamp difference, granted-mask interpretation, enrichment provenance, and alternative explanations. Missing/ambiguous correlations should trigger data review; do not lengthen the window until unrelated events match. This model omits handle duplication, APC/context families, native memory classification, audit loss, and downstream behavior.

Authoring did not execute the tests. Delete only the exercise directory when finished. No process was opened or modified and no payload was created; there is no process-level rollback.

- [ ] Local Process Injection exercise: Analyze synthetic access/thread records and correct the broad correlation assumption.
- [ ] Boundary check: Preserve benign/unknown evidence and reject unrelated source/target or stale matches.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Thread security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights)
- [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)
- [MITRE ATT&CK process injection taxonomy](https://attack.mitre.org/techniques/T1055/)
