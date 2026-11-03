---
title: "Group Policy"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[Group Policy Security]]"
updated: 2026-11-03
---
# Group Policy

> [!abstract] TL;DR
> A GPO is an AD object plus SYSVOL files, selected by scope and filters and interpreted by client-side extensions. Configuration, replication, applicability and actual resultant state are four different checks.

> [!info] Agent scope
> GPO storage; linking; inheritance; filtering; processing; delegation; security settings; resultant policy.

## Prerequisites

- AD OU placement, DNS, access tokens and directory/file ACLs; see [[Active Directory]]. Reference baseline: patched Server 2022/2025 DCs and Windows 11 clients, modern DFSR SYSVOL.
- Required lab: Python 3.12 standard library only. Live read-only examples additionally require Windows, GroupPolicy RSAT/GPMC where specified, and permission to read the named lab GPO/client evidence.

## Learn

```text
Teach Group Policy at expert Windows engineering depth. Assume knowledge of AD,
DNS, ACLs and registry types. Use one synthetic Training OU, two clients and a
harmless legal-notice setting. Explain GPC attributes, GPT files, AD replication
versus DFSR, GUID identity, and the user/computer halves of version numbers.
Work through local/site/domain/OU ordering, link order, enforced links, block
inheritance, disabled sections, Read plus Apply Group Policy, WMI filters and
loopback merge/replace. Include computer read access to user GPOs after MS16-072.
Trace foreground/background processing, synchronous requirements, CSE behavior,
preferences/item-level targeting, registry tattooing and removal behavior.
Distinguish GPMC modeling from endpoint gpresult/Operational evidence. Supply
read-only commands, concrete intended settings, version skew and access-denied
cases, a complete offline evidence lab and expected results. Explain edit/link/
resource delegation and backup/rollback. Cite Microsoft docs; distinguish
Server 2022/2025 and client build support. No harmful scripts, secrets, policy
bypasses or infrastructure provisioning. Teach here, without editing files.
```

## Cheatsheet

### Storage and Replication

| Layer | Concrete representation | Diagnostic implication |
|---|---|---|
| GPC | `CN={GUID},CN=Policies,CN=System,DC=lab,DC=example`; `versionNumber`, `gPCFileSysPath`, extension lists and DACL | Replicated by AD DS, independently of files. |
| GPT | `\\lab.example\SYSVOL\lab.example\Policies\{GUID}`; `gpt.ini`, Machine/User configuration, scripts and preference XML | Replicated by DFSR on modern domains. Reachability and ACLs matter as well as file existence. |
| Link | `gPLink` on site/domain/OU, plus link flags/order | Not stored as a property of the GPO itself; editing a GPO does not require the same right as linking it. |
| ADMX/ADML | Administrative Templates schema and localized UI strings, optionally Central Store | They define the editor UI; endpoints generally consume resulting policy, not the editor's ADMX files. A new setting may still require a newer client. |

The 32-bit version value encodes user version in the high 16 bits and computer version in the low 16 bits. Decimal `196613 = 3 * 65536 + 5`: user 3, computer 5. GPT value `196612` means user 3, computer 4. A GPC/GPT mismatch is replication or inconsistent-edit evidence, not proof which file should be copied over the other. Compare the same GUID on the selected DC, not an arbitrary SYSVOL referral on another DC. Back up through GPMC/GroupPolicy tooling; do not repair version counters by hand.

### Applicability and Precedence

Ordinary order is local, site, domain, outer OU, inner OU; later applicable settings normally win for conflicting single-valued settings. Within one container, link order 1 has highest precedence. Processing is per setting/extension, not a universal merge of registry files.

| Control | Exact effect / common mistaken inference |
|---|---|
| Link disabled | That link is inactive; the same GPO may remain active through another link. |
| GPO user/computer section disabled | Omits that side regardless of a healthy link. |
| Block inheritance | Suppresses ordinary inherited domain/site/ancestor-OU links; not enforced links. It is not a security isolation mechanism. |
| Enforced link | Ancestor settings cannot be overridden by lower containers and survive block inheritance. Filtering still applies. Enforced is a link property. |
| Security filter | Applying principal needs Read and Apply Group Policy, considering deny and membership. Read-only access is not permission to apply. |
| WMI filter | Evaluated on the destination computer; must return true. Query cost, namespace and OS version can cause delay/failure. |
| Loopback Merge | User's normal GPO list followed by user settings selected from the computer's location; computer-location list wins conflicts. |
| Loopback Replace | User settings are selected from the computer's location instead of the user's normal list. It does not convert user settings to computer settings. |

For user policy retrieval after MS16-072, the computer account also needs read access. When removing Authenticated Users from security filtering, preserve appropriate computer read access, commonly Domain Computers with Read but not Apply, while the intended users retain Read+Apply. Validate with delegation and resultant policy; do not grant editing rights to solve a read failure.

Example: domain GPO sets inactivity timeout 900; child OU sets 600. Normally 600 wins. Enforce the domain link and 900 wins even if the child blocks inheritance. Exclude the computer from the domain GPO's applicability and enforcement does not force that filtered-out GPO to apply. This is a precedence illustration, not a recommended inactivity baseline.

### Processing and Resultant State

Computer policy runs at startup, user policy at sign-in. Foreground may be synchronous or asynchronous; some changes need a new startup/sign-in cycle. Typical background refresh is 90 minutes plus up to 30 minutes jitter, while DC computer policy defaults to five minutes. Software installation/folder redirection and individual startup/logon scripts do not behave like arbitrary background registry updates. `gpupdate /force` does not mean every action occurs immediately or that replication has converged.

Preferences support Create/Replace/Update/Delete, item-level targeting and apply-once behavior. Removing a preference item does not necessarily undo its prior change; use its documented removal behavior. Administrative-template policy can clean up managed policy values when no longer applicable, but security settings and individual CSEs have their own semantics. Never promise that unlinking a GPO rolls back every setting.

### Safe Observation and Configuration Example

These are read/report commands for an owned lab, not a deployment script. GPMC's `Training Notice` GPO and `Training` OU must already exist for the RSAT commands. Run endpoint reports locally; computer-scope evidence may require elevation. Output files can contain identity/configuration information and should stay in the lab.

```powershell
Import-Module GroupPolicy
Get-GPO -Name 'Training Notice' -Domain lab.example |
	Select-Object DisplayName, Id, GpoStatus, ModificationTime
Get-GPInheritance -Target 'OU=Training,DC=lab,DC=example' -Domain lab.example
Get-GPPermission -Name 'Training Notice' -All -Domain lab.example
Get-GPOReport -Name 'Training Notice' -Domain lab.example -ReportType Xml -Path .\gpo.xml
gpresult.exe /scope computer /r
gpresult.exe /h .\result.html /f
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 20 |
	Select-Object TimeCreated, Id, LevelDisplayName, Message
```

A harmless configuration example in GPMC is Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Interactive logon: Message title/text for users attempting to log on. Use title `Training` and text `Synthetic lab endpoint`. Pilot only in Training; confirm outside-OU exclusion, effective values and sign-in display. Exact registry locations are `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, `legalnoticecaption` and `legalnoticetext`, both REG_SZ. A registry value alone does not establish which management channel wrote it.

Before a real change, capture GPO backup, links/order/enforcement, filters, delegation and affected resource ACLs separately. Restoration of a GPO backup does not restore all external links/resources. Record previous configured/not-configured state; for settings that persist, define an explicit rollback value instead of assuming unlinking suffices.

### Failure Isolation

Event 1058 commonly points to inability to read policy files: inspect the specific DC/path, DNS, SYSVOL access and file replication. Event 1030 indicates policy query failure; retain accompanying error codes. Access denied, WMI false, disabled section and pending synchronous processing are distinct causes. Correlate GroupPolicy Operational ActivityID, GPO GUID, DC and CSE; a successful overall refresh can coexist with a skipped or failed extension.

## Gotchas

- GPMC Modeling predicts policy; `gpresult`/Group Policy Results and endpoint state provide observed evidence. Neither certifies every app consumed a changed setting.
- Domain account password policy and fine-grained password policies are not ordinary OU user-policy overrides.
- Intune/MDM and GPO conflict behavior is setting-specific. Do not apply a blanket "MDM always wins" rule.

## Labs

### Offline GPC/GPT Version Reconciliation

Python 3.12 standard library, no domain or network. In an empty exercise directory create the single file below. Its XML is a reduced synthetic evidence envelope, not the full `Get-GPOReport` schema; INI uses the real GPT version field. No actual policy is processed.

### File: test_example.py

```python
import configparser
import unittest
import xml.etree.ElementTree as ET

REPORT = '<Evidence guid="11111111-2222-3333-4444-555555555555" dc="dc-b"><GPCVersion>196613</GPCVersion></Evidence>'
GPT = '[General]\nVersion=196612\n'


def halves(value):
	if not 0 <= value <= 0xFFFFFFFF:
		raise ValueError("version outside unsigned 32-bit range")
	return value >> 16, value & 0xFFFF


def compare(xml_text, ini_text):
	root = ET.fromstring(xml_text)
	parser = configparser.ConfigParser()
	parser.read_string(ini_text)
	directory = halves(int(root.findtext("GPCVersion")))
	files = halves(parser.getint("General", "Version"))
	return [side for index, side in enumerate(("user", "computer"))
			if directory[index] != files[index]]


class PolicyEvidenceTests(unittest.TestCase):
	def test_baseline(self):
		self.assertEqual(halves(196613), (3, 5))
		self.assertEqual(compare(REPORT, GPT), ["computer"])

	def test_reconciled_evidence(self):
		self.assertEqual(compare(REPORT, '[General]\nVersion=196613\n'), [])

	def test_other_half_and_bad_range(self):
		self.assertEqual(compare(REPORT, '[General]\nVersion=131077\n'), ["user"])
		with self.assertRaises(ValueError):
			halves(-1)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Decode both baseline values by hand. Identify which section can be stale and what cannot be inferred about actual endpoint state.
2. Run `py -3.12 -m unittest -v test_example.py`. Three tests should pass, including the test that detects the baseline defect.
3. Treat the second fixture as evidence captured after supported replication repair, not instructions to edit `gpt.ini` manually. Explain why equal version numbers still do not verify script hashes, CSE success or resultant settings.
4. Write the next diagnostic request: same GUID/DC, file read result, DFSR evidence and endpoint ActivityID. Keep the scope on Training.

### Hints and Solution

Divide by 65536 to recover the user counter; use the remainder for the computer counter. Baseline is user 3/computer 5 in AD versus user 3/computer 4 in SYSVOL. The user side agrees; computer side differs. The repaired evidence agrees, while the third test proves the checker distinguishes the other half. Permitted consistent evidence remains accepted.

### Verification, Troubleshooting, and Cleanup

Author execution not performed. Missing Python 3.12 is a prerequisite issue; malformed XML/INI must fail rather than be considered healthy. Run from this lab's directory, not another note's directory with the same test filename. Remove that directory and cache to reset. This is not AD/DFSR replication, a GPO precedence engine, or live Windows policy validation.

Original optional live checklist, preserved without completion:

- [ ] Local Group Policy exercise: Create a harmless setting in a test OU, scope it to one synthetic computer, and inspect resultant policy. Verify another OU remains unchanged and document rollback.
- [ ] Boundary check: Confirm a delegated test operator cannot edit a higher-scope GPO or modify a protected script consumed by policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Group Policy Security]]

## References

- [Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [GroupPolicy PowerShell module](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/)
- [Group Policy troubleshooting guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
- [MS16-072 policy retrieval change](https://support.microsoft.com/en-us/topic/ms16-072-security-update-for-group-policy-june-14-2016-7570425d-d460-3003-b2ac-a55fe811a70d)
