---
title: "Active Directory Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[Active Directory]]"
updated: 2026-11-03
---
# Active Directory Security

> [!abstract] TL;DR
> Review who can change identity state, permissions, policy and the systems administering them. A narrow delegation must remain narrow after inheritance, group expansion, OU moves and lifecycle changes.

> [!info] Agent scope
> Security of: Domains; forests; trusts; domain controllers; objects; replication; ACLs; administrative tiers; identity lifecycle. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Directory ACLs/owners, privileged group membership, trusts, DC/backup administration, identity provisioning and synchronization, DNS/time dependencies, and privileged workstation access.
- Scope is defensive review with synthetic evidence. No credential collection, replication of secrets, authentication abuse, ticket creation or persistence procedures.

## Learn

```text
Teach defensive Active Directory security at expert depth. Assume I understand
domains, Kerberos and Windows DACLs. Follow a synthetic help-desk delegation
from an OU ACE to descendant user objects: object/property GUIDs, inheritance,
group expansion, owner/WriteDacl rights, protected accounts and token lifetime.
Contrast description-only delegation with broad object control; inspect native
security descriptors without claiming an offline parser proves effective access.
Explain forest/domain/trust boundaries, selective authentication, SID filtering,
DC/backup/control-plane protection, replication convergence and identity lifecycle.
Design evidence-led review of joiner/mover/leaver and privileged-session policy,
including detection prerequisites, false positives and revocation latency.
Give precise read-only commands, secure configuration changes through supported
administration, and a complete synthetic baseline/fix/retest exercise. Cover
Server 2022/2025, functional levels, AdminSDHolder and current enterprise access
model guidance. Cite Microsoft docs. Do not provide exploitation, credential
dumping, secret replication, relay, forged artifacts, evasion or bypass recipes.
Teach in this conversation, not by editing files or marking progress complete.
```

## Cheatsheet

### Authorization Review, Not Name Matching

For each assignment capture principal SID, expanded membership, object GUID/DN/class, owner, DACL protection, ACE type/mask, object-type GUID, inherited-object-type GUID and inheritance flags. Then state the operation being authorized. An allow on `description` is not an allow on `member`; `WriteProperty` is not the same right as a control-access extended right. A property-set ACE can cover multiple attributes. An empty object-type GUID may broaden the right to all applicable properties/rights.

| Finding | Root cause | Defensive correction and regression |
|---|---|---|
| Help desk has all-property write on users | Convenience delegation exceeded the required task | Delegate only the approved attribute on descendant user objects in the Training OU; preserve its allowed edit and require denial on group membership and ACL changes. |
| OU scope looks narrow but privileged users are inside it | Object placement and identity purpose disagree | Separate administration objects and workstations; review inherited rights and owners before moves. |
| Removed administrator still appears privileged | Existing token/session or nested group path remains | Review all membership paths, reauthenticate in an approved test, close relevant sessions; disabling an account is not a universal session kill. |
| Protected account ignores OU delegation | AdminSDHolder/SDProp protects designated administrative objects | Do not weaken the protected object's ACL to make the workflow work; move ordinary work to a nonprivileged identity. |
| Domain-root replication rights have non-DC owners | Sensitive control-access rights were delegated too broadly | Inventory approved identity services and remove unjustified grants under change control; do not exercise secret replication to validate. |
| Trust is mistaken for authorization | Authentication path confused with resource permission | Review direction, transitivity, SID filtering, selective authentication and destination ACL independently. |

Explicit deny is not a substitute for removing broad unnecessary grants. Denies, inheritance and group membership interact; manual ACE sorting or rebuilding a production descriptor from a simplified example can destroy legitimate permissions. Use ADUC Advanced Security/Delegation of Control or approved ACL tooling with a captured prechange descriptor and rollback plan.

### Narrow Delegation Example

Desired policy: `LAB\TrainingEditors` may write the `description` attribute of ordinary user objects under `OU=Training,DC=lab,DC=example`. It may not create users, write other attributes, reset passwords, change membership, change ownership/DACLs, or affect other OUs. In ADUC with Advanced Features enabled: Training OU -> Delegate Control -> custom task -> only User objects -> property-specific Write description. Confirm the resulting ACE's scope in Advanced Security; do not grant Full Control to resolve a failed test.

Public schema identifiers used in the offline lab: `description` = `bf967950-0de6-11d0-a285-00aa003049e2`; user class = `bf967aba-0de6-11d0-a285-00aa003049e2`. For a real schema, resolve identifiers from the schema naming context rather than trusting an unlabeled GUID inventory. A single correct ACE does not exclude other granting ACEs.

On an authorized RSAT workstation, the following only reads the synthetic OU descriptor. It requires the ActiveDirectory module/AD provider and directory read rights; it neither changes ACLs nor reads password attributes.

```powershell
Import-Module ActiveDirectory
$descriptor = Get-Acl 'AD:\OU=Training,DC=lab,DC=example'
$descriptor | Select-Object Owner, AreAccessRulesProtected
$descriptor.Access | Select-Object IdentityReference, AccessControlType,
	ActiveDirectoryRights, ObjectType, InheritedObjectType,
	InheritanceType, IsInherited
```

For a live acceptance test, an approved synthetic operator must still edit a harmless description while denied other requested operations. Such a test needs real AD, correct group-token freshness and representative ACL inheritance; this note's offline test does not perform it.

### Replication and Privilege Lifecycle

Check both the DC accepting a security change and the DC used for authentication/resource lookup. A membership removal may be replicated while an existing service session retains its token. Record object metadata, DC names, UTC time and session age, not just a screenshot of ADUC. Compare originating attribute metadata and linked-value metadata for memberships; local USNs are not globally ordered.

A leaver workflow should disable at the authoritative source, remove role/group assignments, handle synchronized cloud identity, review service ownership, revoke/terminate supported sessions, and retain audit evidence. Do not delete first and lose linkage between events and the original SID. Service identities need explicit owners, constrained logon rights and managed rotation. Use gMSAs where supported; protecting the systems permitted to use a gMSA is as important as avoiding a manually managed password.

### Administrative Boundaries

DCs, enterprise CAs, federation/synchronization servers, management agents, virtualization hosts and identity backups can control the identity plane. Separate their administration from user endpoint administration; avoid privileged interactive sessions on lower-trust systems. Domain separation within one forest does not establish a hostile-administrator boundary. Trust selective authentication and SID filtering reduce exposure but do not neutralize control of either forest's administrative plane.

## Detection and Defense

Enable Advanced Audit Policy subcategories for Directory Service Changes and Directory Service Access as justified, with targeted SACLs on sensitive objects/attributes. Audit policy alone does not generate every desired access event.

| Evidence | Interpretation and limitation |
|---|---|
| Security 5136 | Directory attribute modified; correlate object GUID, attribute, actor and operation correlation ID. Old/new values can be separate records; SACL and audit policy determine visibility. |
| 5137 / 5141 | Object creation/deletion, useful for identity lifecycle and policy object inventory. |
| 4662 | Directory object access with rights/property GUIDs; interpret GUID and access mask. A missing event may mean no SACL, not no access. |
| 4728 / 4732 / 4756 | Addition to global/local/universal security group respectively; watch removals and group changes too. |
| 4719 / 1102 | Audit policy change / Security log cleared; correlate legitimate maintenance and collector outages. |

Alert on unexpected actors changing privileged memberships, ownership/DACLs or trust configuration. Suppress approved provisioning narrowly by actor, target, operation and time, not by granting the automation account a permanent monitoring exemption. Collect logs centrally with retention and least-privilege read access; full directory event values can themselves contain personal data.

## Labs

### Offline Native ACL Review

Dependencies: Windows 10/11 or Windows Server with Windows PowerShell 5.1 and .NET Framework. No modules, domain, elevated token or network. Create an empty exercise directory containing the single file below. It parses real Windows SDDL using the platform security-descriptor API; it does not apply the descriptor anywhere or simulate AD access checks.

### File: review.ps1

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$editorSid = 'S-1-5-21-111-222-333-1100'
$descriptionGuid = [guid]'bf967950-0de6-11d0-a285-00aa003049e2'
$userGuid = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$baseline = "O:SYG:SYD:(OA;CIIO;WP;;$userGuid;$editorSid)"
$fixed = "O:SYG:SYD:(OA;CIIO;WP;$descriptionGuid;$userGuid;$editorSid)"

function Get-AceEvidence([string]$Sddl) {
	$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
	$ace = $descriptor.DiscretionaryAcl[0]
	[pscustomobject]@{
		Trustee = $ace.SecurityIdentifier.Value
		Mask = $ace.AccessMask
		Flags = $ace.AceFlags.ToString()
		ObjectFlags = $ace.ObjectAceFlags.ToString()
		Property = $ace.ObjectAceType
		ChildClass = $ace.InheritedObjectAceType
	}
}

function Assert-DescriptionScope([string]$Sddl) {
	$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
	if ($descriptor.DiscretionaryAcl.Count -ne 1) { throw 'Unexpected ACE count' }
	$ace = $descriptor.DiscretionaryAcl[0]
	if ($ace -isnot [System.Security.AccessControl.ObjectAce]) { throw 'Not an object ACE' }
	if ($ace.SecurityIdentifier.Value -ne $editorSid) { throw 'Wrong trustee' }
	if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { throw 'Wrong qualifier' }
	if ($ace.AccessMask -ne 32) { throw 'Not exactly WriteProperty' }
	if ([int]$ace.AceFlags -ne 10) { throw 'Expected ContainerInherit + InheritOnly' }
	if ([int]$ace.ObjectAceFlags -ne 3) { throw 'Both object GUID flags required' }
	if ($ace.ObjectAceType -ne $descriptionGuid) { throw 'Wrong property' }
	if ($ace.InheritedObjectAceType -ne $userGuid) { throw 'Wrong child class' }
}

$rejected = $false
try { Assert-DescriptionScope $baseline } catch { $rejected = $true }
if (-not $rejected) { throw 'Baseline must be rejected' }
Assert-DescriptionScope $fixed
$wrongClass = $fixed.Replace($userGuid.ToString(), [guid]::Empty.ToString())
$rejected = $false
try { Assert-DescriptionScope $wrongClass } catch { $rejected = $true }
if (-not $rejected) { throw 'Wrong-class mutation must be rejected' }
Get-AceEvidence $baseline
Get-AceEvidence $fixed
'PASS: broad baseline rejected; narrow ACE accepted; wrong-class mutation rejected'
```

### Objectives, Hints and Solution

1. Inspect baseline SDDL: `OA` is object-specific allow, `WP` is WriteProperty, `CIIO` means container-inherit/inherit-only, and the empty first GUID broadens the property scope.
2. Run `powershell.exe -NoProfile -File .\review.ps1` in the exercise directory under the existing execution policy. Do not weaken machine policy if script execution is disallowed; inspect the file manually instead.
3. Compare output masks and both GUID flags. The repaired ACE retains the harmless task but adds the exact description GUID. The wrong-class mutation must be rejected.
4. Explain the missing evidence needed for live approval: other ACEs, nested memberships, inherited effective descriptor, protected status, actual operation and current token.

Hint: inheritance flags select where an ACE propagates; its object GUID selects what property/right it authorizes. Both matter. Expected result is the final PASS line with two evidence objects, not a real allow/deny from a DC.

### Verification, Troubleshooting, and Cleanup

Not executed by the author. All identifiers are fabricated except public schema GUIDs. Malformed SDDL should throw before any report. Run on Windows; cross-platform .NET security APIs may not support this operation. Delete only the exercise directory to reset; no ACLs were installed. This checks an exact proposed ACE shape, not arbitrary ACL safety or real AD policy enforcement.

The retained optional live checklist is not completed by this offline case.

- [ ] Local Active Directory exercise: Use GOAD or a small isolated test forest to map synthetic users, groups, OUs, delegated ACLs, and one trust relationship. Validate one permission path manually rather than relying only on a graph.
- [ ] Boundary check: Delegate only a harmless test-OU task and verify the operator cannot modify protected groups or replication-related rights.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[BloodHound]]
- [[Active Directory]]

## References

- [Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
- [ACE strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)
- [Protected accounts and groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes)
- [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
