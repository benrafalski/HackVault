---
title: "LAPS Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[LAPS]]"
updated: 2026-11-03
---
# LAPS Security

> [!abstract] TL;DR
> Minimize who can read, decrypt, expire and administer LAPS policy. Measure backup and local rotation without exposing passwords; audit access and validate recovery independently of routine rotation.

> [!info] Agent scope
> Security of: Windows LAPS and legacy distinctions; password rotation; storage; delegation; retrieval auditing; deployment and recovery. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Directory attribute ACLs, decryptor-group membership, Entra device credential permissions, expiry delegation, policy ownership, local administration and recovery backups.
- This note never retrieves passwords, including from real users/devices, and contains no credential-dumping or lateral-use procedures. Audit records are synthetic metadata only.

## Learn

```text
Teach defensive Windows LAPS security at expert depth. Assume AD ACL/GPO/MDM
knowledge. Separate metadata read, password-attribute read, encrypted-value
decryption, expiry reset, device SELF write and policy/group administration.
Explain confidential attributes, extended-right delegation, DPAPI-NG principal
binding, history and legacy migration. Compare AD and Entra access/audit paths.
Design a narrow Training OU deployment with exact policy values, supported OS/
DFL gates, post-authentication actions and recoverability, without retrieving
passwords. Trace a future expiry plus stale backup, incomplete rotation and
audit coverage gaps. Explain why changing decryptor policy does not reencrypt
history and why existing sessions may survive password rotation.
Provide safe nonsecret inspection, a complete offline metadata audit challenge,
baseline/fix/retest, positive access-evidence case, negative regression and
cleanup. State what requires real directory validation. Cite Microsoft docs.
No secrets, dumping, real-user password retrieval, abuse or bypass recipes.
Teach here without modifying notes or study status.
```

## Cheatsheet

### Privilege Separation

| Capability | Authority / risk | Narrow configuration |
|---|---|---|
| Read expiry metadata | Computer-object metadata visibility | Monitoring identity reads only required nonsecret attributes. |
| Update own backup | Computer SELF on Windows LAPS attributes | Delegate to descendants in the managed OU using supported LAPS tooling; not arbitrary computer write access. |
| Read password attributes | Confidential attribute permissions/extended rights | Dedicated OU-scoped reader group; review all-extended-rights and inherited broad grants. |
| Decrypt AD values | DPAPI-NG configured principal plus effective access to ciphertext | Purpose-specific decryptor group, approved time-bound membership, protected group administration. |
| Set expiry | Expiration-write permission | Separate reset/expiration operators; do not bundle password-read rights automatically. |
| Change policy/decryptor | GPO/MDM administrators and group owners | Control-plane administration, approvals and audit trail. |
| Entra credential access | Role/custom action permissions and scope | Review `microsoft.directory/deviceLocalCredentials/password/read` separately from metadata access; account for built-in role grants. |

Encryption is a second layer, not a replacement for AD ACLs. `ADPasswordEncryptionPrincipal` selects the principal when the device encrypts a new value. Changing it does not rewrite old values or history. Rotating after a change and reviewing retained history are separate lifecycle steps; do not assert old ciphertext became inaccessible solely because the policy text changed.

An administrator who can alter the decryptor group's membership or the policy can alter the future trust boundary. A broad AD all-extended-rights grant can undermine confidential-attribute isolation. Review explicit/inherited ACEs, owner and WriteDacl paths, not just the group created during initial LAPS setup.

### Baseline and Concrete Repair

Synthetic finding: Training devices use encrypted AD backup, but `AllHelpdesk` is both reader and decryptor and can write expiry across server and workstation OUs. Correct by separating workstation and server OUs/roles, selecting a dedicated `TrainingLapsDecryptors` group, narrow readers and expiry operators, and removing unjustified broader ACEs at their inheritance source. Merely adding the new narrow group leaves the old broad grant in place.

Through supported GPO/MDM settings for compatible clients, use `BackupDirectory=2`, encryption enabled, explicit authorized principal, length 20/complexity 4, age 30 days, expiration protection enabled and history 0 unless recovery requirements justify retention. These are example design choices, not Microsoft defaults. With DFL <2016, encrypted AD backup is unavailable; plan a supported migration rather than claiming the encryption flag alone protects data. For Entra backup choose value 1 and review Entra roles; AD decryptor policy does not apply there.

On older manual-account mode clients leave account name unset for RID 500 or precreate the approved custom account. New automatic-account options require Windows 11 24H2/Server 2025+. Do not leave an unmanaged fallback administrator with a shared password while declaring LAPS complete. Legacy attributes/backups require separate retention/access review after native migration.

### Rotation, Sessions and Recovery

The strongest operational evidence combines active policy context, directory-backup success (10018 AD / 10029 Entra), local update 10020, cycle result, and nonsecret expiration metadata. Neither a future expiry nor 10004 alone proves a recent rotation. An offline device may retain its previous local secret; manually moving directory expiry forward can conceal overdue work from a naive dashboard.

Post-authentication delay is in hours; 0 disables the action. Action 3 resets/signs out, 5 resets/reboots, and newer action 11 also terminates remaining managed-identity processes. Validate recovery access and user disruption before changing these controls. Rotation cannot promise termination of every preexisting process/session or repair a compromised endpoint.

Recovery from AD backup depends on supported OS/tooling and protected backup contents, not only live reader-group membership. Treat recovery media as highly sensitive, with separate access controls and tested procedures. Snapshot rollback can desynchronize directory and local state; newer AD-only version-GUID mitigation requires Server 2025 schema and functioning machine authentication. Never infer that all restored machines are recoverable from a future expiration timestamp.

### Safe Inspection Without Retrieval

Prerequisites: authorized Windows LAPS management host, directory read rights and local Event Log access. This reads delegation and nonsecret event metadata only:

```powershell
Find-LapsADExtendedRights -Identity 'OU=Training,DC=lab,DC=example'
Get-WinEvent -FilterHashtable @{
	LogName='Microsoft-Windows-LAPS/Operational'
	Id=10004,10005,10018,10020,10029,10031,10041,10043,10044
} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName
```

Do not use broad `Get-ADComputer -Properties *` exports, credential-returning APIs, or transcript capture as a monitoring shortcut. The required lab uses no LAPS module and contacts no device.

## Detection and Defense

For AD retrieval auditing, configure Directory Service Access auditing on DCs plus an appropriate SACL on the managed computer objects/attributes; supported `Set-LapsADAuditing` tooling can establish the intended audit scope. Successful 4662 records must be interpreted with the attribute/control-access GUID and access mask. SACL presence alone is insufficient without policy and collection; no event alone is not proof of no access. Directory changes to delegation/group membership need their own audit coverage.

For Entra, credential access auditing belongs to the cloud device credential API/portal audit path, not the endpoint's LAPS rotation log. Correlate actor, target device, time, operation result and approved support ticket. Access-audit evidence is not evidence that the managed account subsequently signed in; correlate endpoint 10041 and security logon evidence separately without collecting secrets.

Alert on unexpected decryptor/reader membership changes, unsupported policy-root drift, repeated 10005/10043 failures, overdue backups and authorized access lacking a support context. Expected servicing, offline devices, clock skew and collector delay can explain some records; classify missing coverage as unknown, not healthy. Never include a password field in a central detection dataset.

## Labs

### Offline Support-Access and Rotation Review

Python 3.12 standard library only. Use a new empty exercise directory containing the file below. All data is embedded synthetic normalized metadata, not literal API/event schemas. `credential-read` names a fictional audit record; the code never performs a read and contains no password. This tests evidence correlation and freshness, not AD/Entra authorization.

### File: test_example.py

```python
import copy
from datetime import datetime, timedelta
import unittest

NOW = datetime.fromisoformat('2026-11-03T12:00:00+00:00')
BASELINE = {
	'readers': ['TrainingSupport', 'AllHelpdesk'],
	'decryptors': ['TrainingSupport', 'AllHelpdesk'],
	'audit_collection': False,
	'last_backup': '2026-09-01T10:00:00+00:00',
	'expiry': '2026-12-01T10:00:00+00:00',
	'access': {'actor': 'TrainingSupport', 'device': 'TRAINING01',
			   'operation': 'credential-read', 'ticket': 'CASE-7'},
	'approval': {'actor': 'TrainingSupport', 'device': 'TRAINING01', 'ticket': 'CASE-7'},
}


def review(record):
	result = set()
	for field in ('readers', 'decryptors'):
		if set(record[field]) != {'TrainingSupport'}:
			result.add(field)
	if not record['audit_collection']:
		result.add('audit-gap')
	backup = datetime.fromisoformat(record['last_backup'])
	if backup > NOW or NOW - backup > timedelta(days=30):
		result.add('backup-freshness')
	access = record['access']
	if access['operation'] != 'credential-read':
		result.add('unexpected-operation')
	if any(access[field] != record['approval'][field]
		   for field in ('actor', 'device', 'ticket')):
		result.add('unapproved-access-evidence')
	return result


def repaired():
	record = copy.deepcopy(BASELINE)
	record.update(readers=['TrainingSupport'], decryptors=['TrainingSupport'],
				  audit_collection=True, last_backup='2026-11-03T11:00:00+00:00')
	return record


class LapsEvidenceTests(unittest.TestCase):
	def test_baseline_future_expiry_does_not_hide_stale_backup(self):
		self.assertGreater(datetime.fromisoformat(BASELINE['expiry']), NOW)
		self.assertEqual(review(BASELINE), {'readers', 'decryptors', 'audit-gap', 'backup-freshness'})

	def test_repair_preserves_approved_case(self):
		self.assertEqual(review(repaired()), set())

	def test_other_device_is_not_covered_by_ticket(self):
		record = repaired()
		record['access']['device'] = 'TRAINING02'
		self.assertEqual(review(record), {'unapproved-access-evidence'})

	def test_future_backup_is_clock_or_evidence_problem(self):
		record = repaired()
		record['last_backup'] = '2026-11-04T11:00:00+00:00'
		self.assertEqual(review(record), {'backup-freshness'})


if __name__ == '__main__':
	unittest.main()
```

### Objectives and Baseline

1. Find four baseline issues without looking at the assertions. Explain why the future expiry cannot establish backup freshness.
2. Run `py -3.12 -m unittest -v test_example.py`; four tests should pass. Baseline tests pass because defects are detected.
3. Review the fixed evidence. In real operations, changing these dictionary values would not remediate anything: ACL/group changes, rotation and collected audit evidence must occur through approved systems.
4. Test that a valid ticket for TRAINING01 is not accepted for TRAINING02 and that an impossible future backup is flagged. Preserve the approved support case.

### Hints and Solution

Find excessive reader and decryptor sets, disabled audit collection and a backup older than the 30-day example SLA. The allowed record matches actor/device/ticket exactly; the fixture does not test time-window or nested-group authorization. In a real design add approved access windows and central identity IDs, and verify native access separately. The fixed fixture is a new post-remediation evidence set; retain the original audit record unchanged.

### Verification, Troubleshooting, and Cleanup

Not executed by the author. All timestamps require UTC offsets; timezone-naive edits should fail instead of silently shifting results. A missing Python interpreter is an environment issue. Remove the exercise directory/cache to reset. No password was generated/read, no access grant changed, and no secret needs rotation because of this exercise. Offline acceptance is not proof that unauthorized retrieval is denied on an actual directory. Original optional live checklist remains uncompleted.

- [ ] Local LAPS exercise: Enable Windows LAPS for one disposable lab machine and inspect policy, rotation, backup, and retrieval auditing using a designated operator account.
- [ ] Boundary check: Verify an unauthorized synthetic directory user cannot retrieve the password and that the permitted operator's retrieval is auditable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[LAPS]]

## References

- [Windows LAPS architecture and security layers](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)
- [AD deployment and delegation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [Windows LAPS policy reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- [Windows LAPS event log](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-event-log)
- [Set-LapsADAuditing](https://learn.microsoft.com/en-us/powershell/module/laps/set-lapsadauditing)
