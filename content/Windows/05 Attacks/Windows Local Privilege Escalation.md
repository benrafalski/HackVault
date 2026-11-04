---
title: "Windows Local Privilege Escalation"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Local Privilege Escalation

> [!abstract] TL;DR
> A local authority boundary fails when a less-trusted principal can influence a more-trusted operation without an adequate access check. A writable resource, elevated process, or token privilege alone does not demonstrate escalation.

> [!info] Agent scope
> Local privilege boundaries; service/task/file permissions; token privileges; configuration mistakes; defensive validation and remediation. Execution of escalation is excluded; labs analyze offline synthetic permissions only.

## Learn

```text
Teach Windows local privilege-boundary failures at expert depth. Assume knowledge
of SIDs, tokens, ACLs, services, tasks, and Win32 handles. Trace caller identity,
requested access, object security, privileged consumer, and lifetime of authority.
Separate service-object permissions from executable, directory, configuration,
and task permissions. Explain primary/impersonation tokens, restricted SIDs,
deny-only groups, integrity labels, enabled privileges, and UAC's boundary limits.
Compare configuration exposure, reachable operation, and demonstrated impact;
never equate a scanner label or privilege name with an exploitable condition.
Explain path ambiguity, reparse-point/TOCTOU risks, broker authorization, and
version-specific defects conceptually, without procedures for exploiting them.
Work through synthetic ACL and audit records, benign counterexamples, explicit
unknowns, least-privilege fixes, compatibility tradeoffs, and regression tests.
Include a self-contained offline Python 3.12 stdlib analysis challenge with all
data, hints, separate solution, and preservation of legitimate administration.
No escalation, impersonation acquisition, token manipulation, attack commands,
vulnerable services, live configuration changes, or crash triggers. No confidential
data or page-table material; debugger commands belong only in the WinDbg note.
Use public Microsoft primary references; qualify build/policy assumptions. Ask
questions that distinguish evidence from inference, then supply reasoned answers.
Teach without vault access, file edits, or changing my study/completion status.
```

## Cheatsheet

### Authority Is Not a Single Number

An access token contains user/group SIDs, privileges, integrity information, and restrictions. An object access check compares a requested mask against the applicable security descriptor and token. Integrity policy can restrict access in addition to discretionary ACLs; a high integrity label is not a grant. A service running as LocalSystem still encounters other boundaries, including remote identity and protected-process restrictions.

| Boundary | Evidence required | Common incorrect inference |
|---|---|---|
| Service configuration | Effective rights on the service object, caller token, intended administrator set | SCM connectivity implies permission to change a service |
| Executable/configuration | File and parent-directory rights, inherited ACEs, owner, replacement semantics | Read access or a writable unrelated directory implies control |
| Scheduled task | Task security descriptor, principal/logon type, action resource permissions, trigger | A task is elevated merely because it exists |
| Broker/IPC | Authenticated client identity, per-operation authorization, impersonation scope | A permitted connection authorizes every request |
| Token privileges | Present versus enabled privilege, API checks, token type and impersonation level | SeImpersonatePrivilege or SeDebugPrivilege is a universal bypass |
| Vulnerable component | Exact affected build, reachable input boundary, relevant patch and configuration | Product name or CVE match alone proves applicability |

Privileges authorize particular operations. Backup/restore semantics differ from ordinary file access; debugging rights do not dissolve protected-process signer restrictions. Identification-level impersonation does not authorize acting as the client. A thread token can change the identity used for an operation relative to the process token. Restricted-token checks and deny-only SIDs invalidate naive "union of allowed groups" calculations.

### Resource and Lifecycle Review

For a privileged consumer, record **who controls each input**, the **operation it controls**, and **when the consumer reads it**. Binary, configuration, working directory, plugin directory, and task arguments are different resources. A path containing spaces is a review signal, not proof: parsing context, quoting, access rights, and the consumer's behavior all matter. Do not construct alternative execution paths as part of this exercise.

Canonicalizing a filename does not establish ownership or make an open/check/use sequence atomic. Reparse points, rename/replacement permissions, and changes between validation and use require handle-based design and stable ownership. A resource can be unsafe without a current activation path; report that as exposure with reachability unknown, not as a successful authority change.

UAC splits administrator workflows into different token contexts. It is not equivalent to the security boundary separating an ordinary user from an administrator. Describe which principal actually held administrative authority before the event; avoid conflating consent, integrity changes, and acquisition of a new identity.

### Evidence and Detection

| Evidence | What it supports | Qualification |
|---|---|---|
| Security 4697 / System 7045 | Service installation and configured identity/path | Different channels and audit prerequisites; not all later edits |
| Security 4698 / 4702 | Task creation/update | Audit policy and event-version fields vary |
| Security 4672 | Special privileges assigned at logon | Common for normal system activity; not evidence of use |
| Security 4673 / 4674 | Audited privileged operations | Coverage depends on privilege/audit settings |
| Security 4688 / Sysmon 1 | Process identity and ancestry context | Correlate host, time, process identity; PID reuse matters |
| Object-access evidence | A sensitive object's access or modification | Appropriate subcategory and SACL needed; no event is not denial |

A useful finding states: synthetic principal `LAB\\Reader`, excessive effective `write_config` on `inventory-service`, privileged consumer `SYSTEM`, observed change `none`, activation `unknown`, impact `configuration exposure`. Remediation targets the excessive grant, not every administrative right. Keep copies of normalized before/after descriptors and the rule version used to assess them.

The Python policy below is an executable **post-access-check review model**. It accepts already-resolved effective rights; it is deliberately not an implementation of Windows AccessCheck, SDDL parsing, inheritance, or service startup.

## Defense

Use dedicated low-privilege service identities, service SIDs where appropriate, tightly owned program/configuration directories, and explicit broker authorization. Restrict service/task configuration separately from files. Patch privileged components and remove unnecessary local administrator membership and privileges. Compatibility testing must preserve installation, update, backup, and recovery workflows without granting broad write permissions to runtime users.

Fixes should close the authority boundary: a deny rule bolted onto an otherwise broad inherited grant may be harder to maintain than a narrow positive ACL. Test effective rights for both the ordinary operator and approved maintainer. Record inherited permissions and ownership; a one-time file ACL change can be undone by the installer or parent-directory policy.

## Labs

### Environment and Complete Files

This is a defensive configuration-analysis challenge, not execution of an attack. Use Python **3.12**, standard library only, an ordinary account, and a separate empty exercise directory. No Windows host access, VM, service, network, or administrator rights are needed. The single file contains all synthetic seed data and tests. Put the printed file in that directory for later manual execution; no fixture is downloaded.

### File: test_example.py

```python
import copy
import unittest


SENSITIVE = {"write_config", "replace_binary", "change_task"}
SEED = [
	{"id": "svc", "kind": "service", "consumer": "SYSTEM",
	 "activation": "unknown", "approved": ["Maintainer"],
	 "effective": {"Reader": ["read", "write_config"],
				   "Maintainer": ["read", "write_config"]}},
	{"id": "task", "kind": "task", "consumer": "SYSTEM",
	 "activation": "scheduled", "approved": ["Maintainer"],
	 "effective": {"Reader": ["read"],
				   "Maintainer": ["read", "change_task"]}},
	{"id": "user-app", "kind": "file", "consumer": "Reader",
	 "activation": "manual", "approved": ["Reader"],
	 "effective": {"Reader": ["read", "replace_binary"]}},
]


def findings(records):
	result = []
	for record in records:
		for principal, rights in record["effective"].items():
			excess = sorted(set(rights) & SENSITIVE)
			if excess and principal not in record["approved"]:
				result.append((record["id"], principal, tuple(excess),
							   record["activation"]))
	return result


def repair(records):
	fixed = copy.deepcopy(records)
	for record in fixed:
		for principal, rights in record["effective"].items():
			if principal not in record["approved"]:
				record["effective"][principal] = [
					right for right in rights if right not in SENSITIVE
				]
	return fixed


class BoundaryTests(unittest.TestCase):
	def test_baseline_exposure_not_execution(self):
		self.assertEqual(findings(SEED), [
			("svc", "Reader", ("write_config",), "unknown")
		])

	def test_repair_closes_reported_exposure(self):
		self.assertEqual(findings(repair(SEED)), [])
		self.assertIn("write_config", SEED[0]["effective"]["Reader"])

	def test_legitimate_permissions_remain(self):
		fixed = repair(SEED)
		self.assertEqual(fixed[0]["effective"]["Reader"], ["read"])
		self.assertIn("write_config", fixed[0]["effective"]["Maintainer"])
		self.assertIn("change_task", fixed[1]["effective"]["Maintainer"])
		self.assertIn("replace_binary", fixed[2]["effective"]["Reader"])

	def test_each_mutating_resource_is_reviewed(self):
		for right in sorted(SENSITIVE):
			with self.subTest(right=right):
				records = copy.deepcopy(SEED)
				records[1]["effective"]["Reader"] = ["read", right]
				self.assertEqual(len(findings(records)), 2)
				self.assertEqual(findings(repair(records)), [])


if __name__ == "__main__":
	print("Baseline:", findings(SEED))
	print("After repair:", findings(repair(SEED)))
	unittest.main()
```

### Objectives and Baseline

Run only the offline file, from its exercise directory:

```powershell
py -3.12 -B test_example.py -v
```

Explain why `svc` is reported but the maintainer and user-owned application are not. Separate configuration exposure from activation and impact. Locate the excessive effective permission, propose the smallest change, and confirm maintenance and read-only access survive. The baseline intentionally contains a finding; tests passing does not mean the seed was secure.

### Hints

Approval is per resource, not global membership in a magic administrator group. `activation=unknown` must remain unknown. The repair removes only sensitive rights from unapproved writers and deep-copies input so the baseline remains available.

### Solution and Fixed Retest

The sole baseline finding is `('svc', 'Reader', ('write_config',), 'unknown')`. Remove `write_config` from that principal on that resource; retain its `read` and the maintainer's configuration rights. `repair` applies that policy to every supplied resource, yielding `[]`. The last test adds each kind of excessive mutation permission in turn and verifies the same fix handles all three resources. None of these assertions establishes an actual Windows ACL result.

### Evidence, Troubleshooting, and Cleanup

Expected: two printed summaries and **4 passing tests**. Preserve baseline/fixed findings, interpreter version, approved-owner rationale, and the unresolved activation condition. If a valid maintainer is flagged, fix the approved-principal inventory rather than globally suppressing the finding. If local results differ, compare the exact seed and test file; the model cannot ingest native event logs or SDDL.

No tests were executed during authoring. Remove only this exercise's file/directory after retaining any chosen synthetic report. `-B` avoids bytecode files; no service, task, ACL, token, or host policy was changed, so no system rollback is required.

- [ ] Local Windows Local Privilege Escalation exercise: Analyze the supplied offline effective-permission records and distinguish exposure from demonstrated impact.
- [ ] Boundary check: Confirm the synthetic repair removes unapproved mutation rights while read and maintenance permissions remain.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [How DACLs control access](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Security event 4698](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)
