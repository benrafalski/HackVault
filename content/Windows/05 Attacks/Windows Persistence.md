---
title: "Windows Persistence"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Persistence

> [!abstract] TL;DR
> Persistence risk is an unwanted durable execution relationship: trigger, configuration, principal, action, and dependencies. Detection must compare that relationship over time; an unchanged display name or signed executable is insufficient.

> [!info] Agent scope
> Autostarts, services, tasks, WMI and registry mechanisms, permissions, detection, and cleanup reasoning. The reversible demonstration is an in-memory synthetic inventory repair, never installation of persistence.

## Learn

```text
Teach Windows persistence mechanisms as defensive lifecycle analysis at expert
depth. Assume registry, SCM, Task Scheduler, WMI, tokens, and file ACL basics.
Explain user autostarts, registry-driven activation, service start/recovery,
scheduled task triggers/principals/actions, and permanent WMI filter-consumer-
binding relationships. Distinguish configuration presence, trigger eligibility,
attempted execution, successful action, and durable recurrence. Explain permissions
on configuration versus referenced files, registry views, user/system scope,
inventory completeness, upgrades, orphaned resources, and legitimate management.
Show semantic before/after comparison of synthetic records, correlate changes with
execution metadata, and explain why name/signature allowlists are insufficient.
Provide a complete Python 3.12 stdlib offline challenge with embedded inventories,
negative controls, an approved update, separate hints/solution, regression tests,
and cleanup verification. No autostart creation, task/service registration, WMI
subscription installation, registry writes, launch strings, or persistence steps.
Do not execute malware, change host protections, or modify other processes. Use
public primary references; qualify event coverage by audit policy/build. No
page-table content or confidential data; WinDbg commands stay in its own note.
Teach without vault access, file edits, or changing my completion status.
```

## Cheatsheet

### Mechanisms and Authority

| Family | What makes recurrence possible | Review boundaries and normal explanations |
|---|---|---|
| User autostarts / registry activation | A user-session component consumes stored configuration at its trigger | User context, relevant registry view/profile, action dependencies; normal application updaters are common |
| Services | SCM consumes persistent service configuration and start/recovery policy | Service-object ACL, service account, binary/configuration ACLs, dependencies; installation is not proof of a later start |
| Scheduled tasks | Registered trigger, principal/logon conditions, action, and scheduler state | Task ACL and action resources differ; disabled task or unmet conditions may prevent launch |
| Permanent WMI subscriptions | Stored event filter, consumer, and binding connect an event condition to a response | Namespace/object permissions, provider availability, and all three objects matter; an orphan consumer is not an active binding |
| Registry-backed component activation | A consumer resolves configuration during a legitimate lifecycle operation | Process bitness/view, per-user versus machine scope, file integrity, and actual activation must be established |

Scope affects authority: current-user recurrence is not automatically system-wide execution. A privileged principal on a task definition is not evidence that the observer can alter it. A service's display name, executable signer, task folder, or WMI class name cannot establish business authorization. Legitimate management agents use the same underlying facilities, so ownership and change approval are essential context.

Inventory keys should include host, mechanism, stable resource ID, and scope. Store action identity/hash, normalized arguments or a sanitized action fingerprint, principal, trigger, enabled state, owner, and ACL evidence. Do not normalize away meaningful argument order, path differences, registry views, or task security changes. Canonicalization must follow the actual consumer's parsing rules; naive lowercasing of all arguments can erase a real change.

### Configuration Is Not Execution

Use a five-stage evidence chain: **configuration change**, **eligible trigger**, **launch attempt**, **observed action**, **recurrence**. Missing later stages limit the conclusion. A registration event followed by process creation is stronger when the process parent, action identity, user, host, and timing agree. Time proximity alone is not causation.

| Source | Coverage | Caveat |
|---|---|---|
| Sysmon 12/13/14 | Selected registry create/delete, value set, rename events | Configuration filters and views matter; not a complete autorun inventory |
| 4697 / 7045 | Service installation | Do not assume complete configuration-edit history |
| 4698 / 4702 / 4699 | Task creation/update/deletion | Required auditing; event fields vary by version |
| Sysmon 19/20/21 | WMI event filter, consumer, binding activity | Not every provider behavior or execution outcome |
| Task Scheduler / WMI operational logs | Mechanism-specific runtime context | Channel retention/collection must be verified |
| Sysmon 1 / Security 4688 | Process start context | In-process actions may not create a child process |

[[Sysinternals]] Autoruns can help an authorized administrator inventory activation points, but "hide Microsoft entries" and signature verification are triage conveniences, not trust decisions. This exercise does not run Autoruns or change any entry.

### Semantic Detection Rule

Compare meaning, not only names. The lab's executable rule detects added/removed entries and changes to `action_id`, `principal`, `trigger`, and `enabled`. Approved changes require the **exact before and after fingerprints**. This prevents a standing name-only exception from authorizing future unrelated changes. Production rules additionally need ACL, dependency, signer, path-resolution, and source-health evidence.

## Defense

Restrict both the registration interface and referenced resources. Assign an owner to every durable execution relationship, monitor semantic drift, and constrain administrative tooling through policy. Application control helps restrict which code may run, but does not certify every permitted program's invocation or configuration.

Response needs a dependency-aware removal plan: preserve evidence, contain the unauthorized principal, identify all linked objects and running instances, and coordinate removal through the owning mechanism. Removing a binary can leave repeated failure/recovery behavior; deleting a trigger does not terminate an already running process. Reappearance may be legitimate configuration management or an unresolved compromise. Verify configuration absence, relevant subsequent trigger coverage, and continued legitimate functions before declaring cleanup complete. No removal or installation procedures are performed in this lab.

## Labs

### Environment and Complete Files

Defensive inventory challenge only, with Python **3.12** and standard library in an offline ordinary-user directory. `action_id` values are labels, not executable paths or commands. All changes below affect Python dictionaries; nothing is registered with Windows.

### File: test_example.py

```python
import copy
import unittest


FIELDS = ("action_id", "principal", "trigger", "enabled")
BEFORE = {
	"service:inventory": {"action_id": "inventory-v1", "principal": "svc-inventory",
						  "trigger": "boot", "enabled": True},
	"task:report": {"action_id": "report-v1", "principal": "report-user",
					"trigger": "daily", "enabled": True},
}
AFTER = copy.deepcopy(BEFORE)
AFTER["service:inventory"]["action_id"] = "inventory-v2"
AFTER["task:report"]["principal"] = "SYSTEM"
AFTER["wmi:unowned-binding"] = {
	"action_id": "unowned-consumer", "principal": "unknown",
	"trigger": "synthetic-event", "enabled": True,
}


def fingerprint(record):
	return tuple(record[field] for field in FIELDS)


APPROVED = {
	("service:inventory", fingerprint(BEFORE["service:inventory"]),
	 fingerprint(AFTER["service:inventory"]))
}


def compare(before, after):
	result = []
	for key in sorted(before.keys() | after.keys()):
		if key not in before:
			result.append((key, "added"))
		elif key not in after:
			result.append((key, "removed"))
		else:
			old, new = fingerprint(before[key]), fingerprint(after[key])
			if old != new:
				result.append((key, "approved-change" if (key, old, new) in APPROVED
							   else "review-change"))
	return result


def repaired_inventory():
	repaired = copy.deepcopy(AFTER)
	repaired["task:report"] = copy.deepcopy(BEFORE["task:report"])
	del repaired["wmi:unowned-binding"]
	return repaired


class PersistenceInventoryTests(unittest.TestCase):
	def test_baseline_name_comparison_misses_modified_task(self):
		self.assertNotIn("task:report", AFTER.keys() - BEFORE.keys())
		self.assertIn(("task:report", "review-change"), compare(BEFORE, AFTER))

	def test_semantic_delta(self):
		self.assertEqual(compare(BEFORE, AFTER), [
			("service:inventory", "approved-change"),
			("task:report", "review-change"),
			("wmi:unowned-binding", "added"),
		])

	def test_synthetic_repair_preserves_update(self):
		repaired = repaired_inventory()
		self.assertEqual(compare(BEFORE, repaired),
						 [("service:inventory", "approved-change")])
		self.assertIn("wmi:unowned-binding", AFTER)
		self.assertEqual(repaired["task:report"]["principal"], "report-user")

	def test_approval_is_not_a_name_only_allowlist(self):
		modified = copy.deepcopy(AFTER)
		modified["service:inventory"]["trigger"] = "different-trigger"
		self.assertIn(("service:inventory", "review-change"), compare(BEFORE, modified))
		self.assertIn(("task:report", "removed"), compare(BEFORE, {}))


if __name__ == "__main__":
	print("Delta:", compare(BEFORE, AFTER))
	print("Repaired:", compare(BEFORE, repaired_inventory()))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

Identify one approved update, one same-name authority change, and one unowned relationship. Explain why a names-only inventory misses the task change. Repair the supplied inventory without losing the approved update. State what runtime evidence would still be needed to claim execution or verified absence after cleanup.

### Hints

Compare the task principal, not just its name. The WMI record is deliberately only a normalized relationship; it does not contain a real filter/query or consumer configuration. Approved updates are specific transitions, not permission for all future edits.

### Solution and Fixed Retest

The service update is approved. The task's change from `report-user` to `SYSTEM` needs investigation; the fixture does not establish who caused it or that it ran. The added WMI relationship lacks an owner and also needs review. The in-memory repair restores the task principal and removes the unowned relationship. Only the approved update remains in the baseline comparison; the original `AFTER` snapshot stays intact for evidence.

### Evidence, Troubleshooting, and Cleanup

Expected: two delta summaries and **4 passing tests**. Preserve resource IDs, changed fields, approval fingerprints, and the absence of runtime evidence. A missing field raises an error rather than silently treating an incomplete inventory as unchanged. Duplicate IDs, collector coverage, host scope, object ACLs, and WMI dependency expansion require a real ingest schema; this model does not provide them.

No author execution was performed. Delete only the exercise directory after retaining synthetic evidence. No actual persistence was created, so do not delete real services, tasks, registry entries, or WMI objects for cleanup.

- [ ] Local Windows Persistence exercise: Compare the supplied offline startup inventories and identify semantic changes.
- [ ] Boundary check: Verify the in-memory repair removes only unapproved changes and preserves the legitimate update.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [Task Scheduler security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
- [WMI permanent event consumers](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times)
- [Service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Autoruns coverage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
