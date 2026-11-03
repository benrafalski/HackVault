---
title: "Group Policy Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[Group Policy]]"
updated: 2026-11-03
---
# Group Policy Security

> [!abstract] TL;DR
> Review the policy author, link owner, file/resource owner and applying client separately. A locked GPO can still consume an untrusted file; a correct setting can still be filtered out or fail to apply.

> [!info] Agent scope
> Security of: GPO storage; linking; inheritance; filtering; processing; delegation; security settings; resultant policy. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- AD GPO objects and container links, SYSVOL files, referenced packages/scripts, WMI filters, delegation, client-side extensions and secrets mistakenly included in preferences or backups.
- This note reviews and repairs configuration evidence. It does not execute policy scripts, manipulate privileged endpoints, recover stored secrets or provide policy-abuse recipes.

## Learn

```text
Teach defensive Group Policy security at expert depth. Assume AD/ACL basics.
Map GPC, GPT, gPLink/gPOptions, WMI filter, referenced scripts/packages and client
processing to distinct owners and permissions. Show why editing, linking,
applying and reading are different rights; include inherited ACEs and MS16-072.
Explain enforced/block-inheritance/loopback behavior without treating them as
security boundaries. Work through a synthetic deployment with correct GPO
delegation but an overly broad script-resource ACL, an integrity mismatch,
and a missing client result. Give safe read-only inventory, precise remediation,
rollback capture and negative/positive regression evidence. Cover version skew,
CSE errors, preference secret hygiene, audit prerequisites and false positives.
Provide a complete offline challenge, all data and a separate solution, without
executing referenced content or claiming to validate real AD policy. Use primary
Microsoft sources for patched Server 2022/2025 and Windows 11. No exploitation,
secret recovery, bypass, evasion or persistence. Teach here; do not edit files.
```

## Cheatsheet

### Four Authorization Decisions

| Decision | Relevant authority | Secure configuration |
|---|---|---|
| Who authors the GPO? | GPC and GPT permissions, including ownership/DACL control | Restricted policy-maintainer group; distinguish Edit settings from Edit/delete/modify security. Use supported GPMC delegation to keep directory/files consistent. |
| Who deploys it? | Write access to `gPLink`/`gPOptions` on a site/domain/OU | Separate linking approval; delegate only the pilot OU where needed. Authoring alone should not imply domain-wide deployment. |
| Who receives it? | Read + Apply, computer retrieval read rights, WMI/section status, link scope | Explicit pilot population and documented exclusions. Read-only computer access must not accidentally broaden Apply. |
| Who controls consumed resources? | Script/package share and NTFS ACL, owner, distribution pipeline | Only approved publishers write; clients read. Capture content hash/signature and publication version, not just path. |

GPO execution context depends on the extension and setting: computer startup scripts normally run as Local System, user logon scripts normally as the user; preferences and scheduled work have their own context. Do not infer safety from a `.ps1` extension or trust merely because the file lives on a familiar share. File signatures help only when the relevant execution policy/control actually validates them; a published hash compared to an attacker-controlled manifest is not independent integrity evidence.

### Vulnerable and Fixed Configuration Review

Example intent: `Training Notice` contains a harmless logon notice; an optional inventory script is approved only for Training computers. GPO editors and linkers are correctly scoped, but the referenced share grants ordinary users Modify. Root cause is a second write path outside the GPO's delegation model. Correction: remove the unnecessary publisher ACE at its actual explicit/inherited source while preserving SYSTEM/administrative recovery access and client read access. Review both share and NTFS ACLs, owner and deployment service membership. Do not replace a production ACL with a toy lab descriptor.

Also inspect content and actual results: correct permissions after a fix do not prove earlier content was trustworthy. Republish from an approved source, compare integrity evidence, confirm GPC/GPT convergence, and capture endpoint applied/denied GPO and CSE results. Stage to a pilot before expanding scope. Preserve a permitted positive case and an out-of-scope negative case.

| Risk | Evidence to collect | Remediation boundary |
|---|---|---|
| Overbroad GPO editing | GPMC delegation plus directory/SYSVOL ACL comparison | Remove only unjustified rights; retain read/apply needs. |
| Excessive OU link authority | Container ACL, changed `gPLink`, link order/enforced state | Reduce deployment scope; distinguish approved linking from authoring. |
| Legacy password-bearing preferences | Presence of disallowed password fields, never their values | Remove from deployed content and review backups; rotate the affected synthetic/service credentials via approved owners. Deletion alone is insufficient. |
| "Not configured" mistaken for rollback | Endpoint settings and CSE-specific removal semantics | Explicitly restore prior supported configuration where values persist. |
| Client looks compliant only in GPMC | `gpresult`, Operational CSE evidence, actual setting | Correct applicability/replication/processing cause, not the reporting label. |

A preference field named `cpassword` is an immediate hygiene finding, not a task to decrypt or log it. Scan metadata/presence in authorized backups and keep report output value-free. Never place passwords, tokens or private keys in GPO files, scripts, command arguments or public evidence.

### Safe Read-Only Review Commands

Requires Windows PowerShell with GroupPolicy RSAT and read access to the named synthetic GPO/share. `Get-FileHash` reads bytes but does not execute the script. Remote paths below are owned-lab placeholders, not targets to discover.

```powershell
Import-Module GroupPolicy
Get-GPPermission -Name 'Training Notice' -All -Domain lab.example
Get-GPInheritance -Target 'OU=Training,DC=lab,DC=example' -Domain lab.example
$resource = '\\files.lab.example\PolicyRead\inventory.ps1'
Get-Acl -LiteralPath $resource | Select-Object Owner, AccessToString
Get-FileHash -LiteralPath $resource -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $resource |
	Select-Object Status, StatusMessage
```

These commands do not show every effective nested-group or share permission. On the file server, authorized administrators must separately inspect the share's permissions and publication pipeline. For a live rollout use GPMC backup plus an explicit record of links, filters and resources; restore only the intended pilot changes. A copied XML report is not a restorable GPO backup.

## Detection and Defense

- Directory Service Changes auditing plus targeted SACLs can produce 5136 for GPC/container changes, including `gPLink`. Attribute names and object DNs distinguish a deployment change from an ordinary user change.
- File System auditing with appropriate SACLs can record 4663 resource access; Detailed File Share auditing can add 5145 context. Neither should be assumed enabled nor interpreted as a complete file-content history.
- Correlate editor actor/time, GPO GUID/version, changed file hash, DC replication status and client GroupPolicy Operational ActivityID. Separate approved broad maintenance from unapproved drift using a change record, not an account-name exemption.
- Monitor missing client telemetry as unknown, not compliant. GPOs can be filtered, clients offline, logs overwritten or collection delayed. Retain endpoint state and the selected DC alongside reports.

## Labs

### Offline Deployment Evidence Challenge

Dependencies: Python 3.12 standard library. One file, no domain, network, secrets or script execution. All data is synthetic and embedded. This is a manifest/evidence review, not a Windows ACL or Group Policy engine. Create a separate empty exercise directory with the file below.

### File: test_example.py

```python
import copy
import hashlib
import unittest
import xml.etree.ElementTree as ET

APPROVED = b"Write-Output 'training inventory marker'\r\n"
PUBLISHED = b"Write-Output 'old training marker'\r\n"
BASELINE = {
	"editors": ["PolicyMaintainers"],
	"linkers": ["TrainingDeployers"],
	"resource_writers": ["PolicyPublishers", "OrdinaryUsers"],
	"client_read": True,
	"expected_sha256": hashlib.sha256(APPROVED).hexdigest(),
	"content": PUBLISHED,
	"preferences": '<Groups><Properties cpassword="SYNTHETIC-NOT-A-SECRET"/></Groups>',
	"pilot_result": None,
}


def findings(evidence):
	result = set()
	expected_groups = {
		"editors": {"PolicyMaintainers"},
		"linkers": {"TrainingDeployers"},
		"resource_writers": {"PolicyPublishers"},
	}
	for field, permitted in expected_groups.items():
		if set(evidence[field]) != permitted:
			result.add(field)
	if not evidence["client_read"]:
		result.add("client-read")
	digest = hashlib.sha256(evidence["content"]).hexdigest()
	if digest != evidence["expected_sha256"]:
		result.add("integrity")
	root = ET.fromstring(evidence["preferences"])
	if any("cpassword" in element.attrib for element in root.iter()):
		result.add("password-field-present")
	if evidence["pilot_result"] != "observed-applied":
		result.add("missing-pilot-evidence")
	return result


def repaired():
	evidence = copy.deepcopy(BASELINE)
	evidence.update(resource_writers=["PolicyPublishers"], content=APPROVED,
					preferences='<Groups/>', pilot_result="observed-applied")
	return evidence


class DeploymentTests(unittest.TestCase):
	def test_baseline(self):
		self.assertEqual(findings(BASELINE), {"resource_writers", "integrity",
						 "password-field-present", "missing-pilot-evidence"})

	def test_repair_keeps_legitimate_read_and_publish(self):
		self.assertEqual(findings(repaired()), set())
		self.assertTrue(repaired()["client_read"])

	def test_regression_is_not_hidden_by_other_fixes(self):
		evidence = repaired()
		evidence["linkers"].append("OrdinaryUsers")
		self.assertEqual(findings(evidence), {"linkers"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Review the baseline without running the byte strings as PowerShell. Identify four independent blockers to approving the deployment.
2. Run `py -3.12 -m unittest -v test_example.py`; three tests should pass. Baseline success means all intended defects were detected.
3. Explain why removing broad writers alone is insufficient, and why deleting a password field is not a credential-rotation procedure.
4. Review the fixed fixture and then the negative linker mutation. Keep the approved publisher and client read access intact.

### Hints and Solution

The GPO's editor list is already correct. The resource ACL, old content, password-field presence and missing endpoint evidence are the four defects. The fixed fixture narrows resource writers, republishes approved bytes, removes the field and supplies a labeled synthetic observation. A real report must obtain that observation from the client rather than inventing the string. The linker regression remains detectable independently.

### Verification, Troubleshooting, and Cleanup

No author execution; expected tests are not measured results. XML parsing errors are invalid evidence, not a clean finding list. The checker uses exact expected group sets and does not expand nested membership, evaluate ACEs or prove publication origin. Delete only the exercise directory/cache. No GPO/resource was changed and no credentials were retrieved. Retained live checklist below remains optional and uncompleted.

- [ ] Local Group Policy exercise: Create a harmless setting in a test OU, scope it to one synthetic computer, and inspect resultant policy. Verify another OU remains unchanged and document rollback.
- [ ] Boundary check: Confirm a delegated test operator cannot edit a higher-scope GPO or modify a protected script consumed by policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Group Policy]]

## References

- [Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [Get-GPPermission](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission)
- [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes)
- [MS14-025: Group Policy Preferences security update](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
