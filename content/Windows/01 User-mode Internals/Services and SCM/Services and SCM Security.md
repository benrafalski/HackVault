---
title: "Services and SCM Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Services and SCM]]"
updated: 2026-11-03
---
# Services and SCM Security

> [!abstract] TL;DR
> Writable service configuration or binaries, excessive service privileges, and unsafe IPC can let a lower-trust user influence privileged execution.

> [!info] Agent scope
> Security of: Service lifecycle; SCM APIs; service identities; configuration permissions; dependencies; recovery; service isolation. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- SCM database rights, individual service DACLs, executable/configuration/dependency file permissions, recovery actions, execution identity, and service IPC are independent boundaries.
- This note audits offline evidence only. No installation, autostart, service control, impersonation experiment, or privileged execution is performed.

## Learn

```text
Teach defensive Windows service security to a reader familiar with SCM APIs,
tokens and DACLs. Explain the difference between SC_MANAGER_CREATE_SERVICE,
SERVICE_CHANGE_CONFIG, WRITE_DAC/WRITE_OWNER, SERVICE_START/STOP and query rights.
Trace how account, service SID, restricted SID, required privileges, dependency
files, recovery configuration and IPC authorization determine effective trust.
Use offline service configuration and access-evidence fixtures: establish a
read-only baseline, detect an overbroad configuration grant, correct the fixture,
and show authorized query access still passes. Explain ambiguous command lines
without constructing executable candidates or demonstrating exploitation.
Distinguish null/empty DACLs, inherited rights, owner authority, stale ACL
snapshots, shared hosts, and per-user service templates on modern Windows.
Describe audit sources and false positives, especially installation versus
configuration changes versus actual process execution. Give exact masks,
documented APIs and source-backed limits, not a pretend AccessCheck evaluator.
No persistence, privilege escalation, credential access, bypass, evasion,
service registration/control, file edits, or confidential examples. Conclude
with difficult evidence-triage questions and worked defensive answers.
```

## Cheatsheet

### Rights Are Object-Specific

| Service right | Mask | Defensive meaning |
|---|---|---|
| `SERVICE_QUERY_CONFIG` / `SERVICE_QUERY_STATUS` | `0x1` / `0x4` | Observation, not permission to change configuration. |
| `SERVICE_CHANGE_CONFIG` | `0x2` | Controls executable/account/dependencies and additional settings; high-trust administrative capability. |
| `SERVICE_START` / `SERVICE_STOP` | `0x10` / `0x20` | Availability/control rights; do not confuse with configuration authority. |
| `DELETE` / `WRITE_DAC` / `WRITE_OWNER` | `0x10000` / `0x40000` / `0x80000` | Object removal or security-descriptor authority; must be audited alongside specific bits. |
| `READ_CONTROL` | `0x20000` | Reads descriptor excluding SACL; not the same as query configuration. |

Map generic rights for the **service object**, not for a file. SDDL abbreviations are context-dependent: service `DC` is change configuration, `CC` is query configuration, `LC` is query status. `D:(A;;CCLC;;;BU)` is an illustrative allow ACE granting built-in Users those query rights; it is not a complete recommended service descriptor and is not applied here. Null DACL permits access; empty DACL grants none. Deny/allow order, groups, restricted SIDs, privileges, ownership, and mandatory integrity make substring-based SDDL scanners unsuitable as access evaluators.

### Layered Review

1. Establish principal and token groups. Evaluate service-object rights with documented Windows access-check facilities or an approved effective-access review; preserve what was actually checked.
2. Read binary path and arguments separately. Quotes address parsing ambiguity, **not** write access. Inspect executable and parent-directory replacement rights, configuration, plug-ins, dependencies, and recovery commands.
3. Review account requirements. Prefer the least-capable supported account; service SID isolation protects per-service resources, but does not authorize requests arriving over IPC.
4. Evaluate IPC using authenticated caller identity and per-operation authorization, bounded messages, and guaranteed impersonation reversion. A protected service DACL does not protect an independently exposed pipe endpoint.
5. Record uncertainty: missing file ACL evidence, unavailable services, inaccessible SACL, and collection time. An absent observation is not a passing check.

Read-only commands for a separately authorized host review (not required by the offline lab):

```powershell
sc.exe qc EventLog
sc.exe sdshow EventLog
sc.exe qsidtype EventLog
sc.exe qprivs EventLog
sc.exe qfailure EventLog
```

Use `QueryServiceConfig2W` for structured recovery/privilege/SID data. `QueryServiceObjectSecurity` reads service security; `GetNamedSecurityInfoW` reads file security. Never infer one from the other. On Vista+ session-0 isolation prevents ordinary desktop interaction, not all cross-process communication. Per-user services and changing service-host grouping make blanket name/PID assumptions unreliable.

## Detection and Defense

- System/Service Control Manager 7045 describes installation; 7040 start-type changes and 7036 state changes have different meanings. Security 4697 requires applicable audit configuration. Do not label every configuration modification as a 7045 event.
- Correlate service name, image, account, event time, deployment records, and resulting process identity. Legitimate software updates are common explanations; missing logs may reflect retention or permissions.
- Protect executable and parent directories, grant narrow service-management rights, minimize account privileges, isolate writable data, and authorize IPC operations. Roll out changes through the owning deployment process with compatibility tests, not ad hoc service modification.

## Labs

### Environment and Complete Files

Python 3.11+ standard library, any OS, an empty user-owned scratch directory. No build, Windows connection, executable target, or installation. The JSON is normalized **synthetic review evidence**, not an SCM import format. The supplied mask means already-evaluated service rights for one fictional standard-user token; the checker is not a DACL evaluator.

### File: service.json

```json
{
  "name": "HVOffline",
  "account": "NT AUTHORITY\\LocalService",
  "image": "\"C:\\Program Files\\HVOffline\\reader.exe\" --readonly",
  "effective_service_mask": 7,
  "image_writable_by_subject": false,
  "parent_writable_by_subject": false,
  "recovery_command": "",
  "ipc_review": "read-only authorized"
}
```

### File: test_example.py

```python
import copy
import json
from pathlib import Path
import unittest

CONFIG_AUTHORITY = 0x0002 | 0x10000 | 0x40000 | 0x80000

def findings(record):
	problems = set()
	mask = record["effective_service_mask"]
	if not isinstance(mask, int) or mask < 0 or mask > 0xFFFFFFFF:
		raise ValueError("invalid access mask")
	if mask & CONFIG_AUTHORITY:
		problems.add("configuration authority")
	for key in ("image_writable_by_subject", "parent_writable_by_subject"):
		if record.get(key) is not False:
			problems.add(key)
	if record.get("recovery_command") != "":
		problems.add("review recovery command")
	return problems

class ServiceReview(unittest.TestCase):
	def setUp(self):
		self.record = json.loads(Path(__file__).with_name("service.json").read_text())

	def test_baseline_exposes_configuration_grant(self):
		self.assertEqual(findings(self.record), {"configuration authority"})

	def test_fixed_retest_keeps_queries(self):
		fixed = copy.deepcopy(self.record)
		fixed["effective_service_mask"] = 0x0001 | 0x0004
		self.assertEqual(findings(fixed), set())
		self.assertEqual(fixed["effective_service_mask"] & 5, 5)

	def test_missing_evidence_is_not_safe(self):
		fixed = copy.deepcopy(self.record)
		fixed["effective_service_mask"] = 5
		del fixed["parent_writable_by_subject"]
		self.assertIn("parent_writable_by_subject", findings(fixed))

	def test_security_descriptor_authority_is_in_scope(self):
		for right in (0x10000, 0x40000, 0x80000):
			with self.subTest(right=right):
				changed = dict(self.record, effective_service_mask=5 | right)
				self.assertIn("configuration authority", findings(changed))

if __name__ == "__main__":
	unittest.main()
```

### Objectives, Hints, and Solution

Run `python -m unittest -v test_example` in the scratch directory. Before running, decode mask 7: it combines query configuration, **change** configuration, and query status. The fixture therefore violates a read-only reviewer policy despite its protected image. Hint: removing write permission on the image does not remove bit `0x2` on the service.

The solution is the in-memory fixed fixture with mask 5. All four tests should pass: they assert the baseline defect, the repaired evidence, missing-evidence handling, and descriptor-control rights. The source fixture intentionally remains defective so the baseline remains reproducible. No real ACL is modified. To translate this to production, an authorized administrator must establish actual effective access and change the owning deployment policy; these tests cannot certify that step.

### Verification, Troubleshooting, and Cleanup

Expected: four passing tests and no external side effects. File-not-found means the two files are not colocated. JSON backslashes require JSON escaping. Python does not need elevation. Remove only the two scratch files and their local `__pycache__`. Source reviewed, not executed; parent must run the four tests. Windows DACL evaluation, service isolation, IPC authorization, and telemetry availability remain unverified.

- [ ] Local Services and SCM exercise: Audit the offline service evidence and explain each independent boundary.
- [ ] Boundary check: Detect the overbroad grant, apply the fixture correction, and preserve permitted queries.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Local Privilege Escalation]]
- [[Windows Persistence]]
- [[Services and SCM]]

## References

- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Service accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts)
- [Service SID information](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Security event 4697](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)
