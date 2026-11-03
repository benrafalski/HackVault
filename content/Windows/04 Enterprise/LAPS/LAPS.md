---
title: "LAPS"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[LAPS Security]]"
updated: 2026-11-03
---
# LAPS

> [!abstract] TL;DR
> Windows LAPS is a device-driven rotation and backup workflow. Policy processing, directory backup, local password update, delegated read, decryption and recovery are separate operations with separate evidence.

> [!info] Agent scope
> Windows LAPS and legacy distinctions; password rotation; storage; delegation; retrieval auditing; deployment and recovery.

## Prerequisites

- AD computer objects/ACLs, GPO or MDM policy, local account RIDs and UTC timestamps. See [[Active Directory]] and [[Group Policy]].
- Baseline: supported, patched Windows 11/Server 2019 or later with Windows LAPS. Windows 11 24H2/Server 2025 features must not be assumed on older builds. AD encryption requires domain functional level 2016 or later.
- Required offline lab: Windows PowerShell 5.1/.NET Framework only. No directory, modules, elevated access, passwords or recovery media.

## Learn

```text
Teach Windows LAPS at expert operations/identity engineering depth. Assume AD
ACLs, local RIDs and GPO/MDM fundamentals. Contrast legacy Microsoft LAPS,
Windows LAPS native mode and legacy emulation, schema attributes and coexistence.
Trace policy-root precedence without cross-root merging, account selection,
hourly processing, password generation, directory backup and local update.
Explain AD versus Entra destinations, computer SELF rights, read versus expiry
delegation, DPAPI-NG encryption/decryptor identity, DFL requirements and history.
Cover post-authentication grace/action behavior, offline clients, backup failure,
snapshot rollback and recovery prerequisites without retrieving any password.
Distinguish Windows 11 24H2/Server 2025 account management, passphrases and schema-
dependent rollback detection from earlier clients. Provide exact safe policy
values, read-only nonsecret commands and complete synthetic event/FILETIME labs.
Use Microsoft sources; separate expected from executed results. No passwords,
credential dumping, real-user access or bypass recipes. Teach in conversation,
not through file edits or study-state changes.
```

## Cheatsheet

### Deployment Modes and Version Gates

| Mode/feature | Storage and requirements |
|---|---|
| Legacy Microsoft LAPS | Separate legacy client-side extension and `ms-Mcs-AdmPwd`/`ms-Mcs-AdmPwdExpirationTime` attributes. Password protected by AD ACLs, not Windows LAPS encrypted-password storage. |
| Windows LAPS, native AD | Built-in supported OS component, Windows LAPS schema, computer SELF delegation, `msLAPS-*` attributes. Encryption requires DFL 2016+. |
| Windows LAPS, Entra | Device identity backs up to the Entra device object; Entra roles/permissions govern access. No AD schema update is needed for Entra-only backup. |
| Legacy emulation | Windows LAPS can honor legacy policy under documented conditions; not equivalent to native encryption/features. Avoid two engines managing the same account. |
| Automatic account management | Windows 11 24H2/Server 2025+: can create/manage a custom account and optionally randomize its name. Older manual mode requires the custom account to exist. |
| Passphrases / newer actions | Complexity values 5-8, passphrase settings and action 11 require Windows 11 24H2/Server 2025+. Older clients may fall back to defaults for unsupported settings. |

Hybrid join does not mean dual backup: `BackupDirectory=1` is Entra only, `2` is AD only, `0` disables backup/management policy. Choose the recovery authority deliberately. AD DSRM backup requires encrypted AD storage and a supported DC; it is not backed up to Entra. Domain functional level and the local DC's OS support are separate gates.

### Policy Resolution and Account Selection

Windows LAPS searches policy roots in this order and selects the first containing any explicitly configured setting. Missing settings then use defaults; lower roots are not merged.

| Order | Registry root under HKLM |
|---|---|
| 1 CSP | `Software\Microsoft\Policies\LAPS` |
| 2 GPO | `Software\Microsoft\Windows\CurrentVersion\Policies\LAPS` |
| 3 Local testing configuration | `Software\Microsoft\Windows\CurrentVersion\LAPS\Config` |
| 4 Legacy | `Software\Policies\Microsoft Services\AdmPwd` |

Worked failure: GPO sets AD backup and encryption, but CSP contains only `PasswordLength=20`. CSP wins and its absent BackupDirectory uses default 0. The device does not merge in the GPO backup destination. Fix the management assignment at its authoritative source; a local registry edit is not a durable policy rollout.

In manual mode, an unset `AdministratorAccountName` targets the built-in administrator by RID 500 even if renamed/localized. An explicit custom name must already exist. LAPS can manage a disabled account's password without enabling it. Automatic account management is a newer distinct mode; its target/enable/name settings replace this manual-account selection behavior.

### Rotation and Backup

The built-in background cycle runs hourly and is not a configurable scheduled task or the old GPO CSE. GPO notifications and supported explicit processing can also trigger it. AD-backed clients query directory expiration; Entra-backed clients track expiration locally rather than polling Entra for it. Changing PasswordAgeDays does not immediately recalculate the current password's expiry or force rotation.

When rotation is needed, the device creates a policy-compliant random secret, backs it up to the selected directory, then updates the local account. Verify both operations, not just policy processing. Offline directory connectivity, missing SELF rights, an invalid encryption principal or incompatible local password policy can prevent completion. Expiring the directory timestamp requests a future device-side rotation; it does not itself change the local SAM account immediately.

| Event in `Microsoft-Windows-LAPS/Operational` | Meaning |
|---|---|
| 10003 / 10004 / 10005 | Cycle started / succeeded / failed; a successful no-change cycle is not a rotation. |
| 10021 / 10022 / 10023 | Active AD / Entra / legacy policy details. |
| 10018 / 10029 | Password backup to AD / Entra succeeded. |
| 10020 | Managed local account password update succeeded. |
| 10027 | Password generation incompatible with policy, requiring exact event/error review. |
| 10031 | External managed-password change blocked. |
| 10041 / 10042 / 10044 / 10043 | Authentication observed / grace expired / post-auth actions succeeded / failed. |

LAPS Operational on a DC describes that DC's own DSRM management, not all member-device activity. Collect client logs to measure fleet rotation.

### Permissions and Encryption

Computer SELF permissions allow the device to update its own backup/expiry attributes. Delegated read permission and delegated expiration-write permission are different workflows. Encrypted-password readers also need the designated decryptor authority; reading ciphertext is not permission to decrypt. DPAPI-NG protects the AD encrypted value for a single configured principal, typically a purpose-specific group. Default decryptor is the domain's Domain Admins group if not configured.

Changing `ADPasswordEncryptionPrincipal` affects future encrypted values; it does not rewrite existing ciphertext/history. A group can provide controlled membership for multiple operators, but group administration then becomes part of the credential trust boundary. History is encrypted-only, default 0 and supported range 0-12; balance recovery needs against retention. Computer SELF must not receive general decryption authority.

### Precise Pilot Configuration

Example design for a supported AD-backed Training OU, not a universal baseline: DFL >=2016; `BackupDirectory=2`, `PasswordAgeDays=30`, `PasswordLength=20`, `PasswordComplexity=4`, `PasswordExpirationProtectionEnabled=1`, `ADPasswordEncryptionEnabled=1`, `ADPasswordEncryptionPrincipal=LAB\TrainingLapsDecryptors`, history 0 unless recovery requirements justify retention. Leave account name unset to manage RID 500. Use post-authentication delay 1 hour and action 3 only after evaluating session-disruption impact. A delay of 0 disables post-authentication actions; it does not mean immediate execution.

Through Computer Configuration -> Policies -> Administrative Templates -> System -> LAPS, configure this as a dedicated pilot GPO. Ensure current LAPS ADMX and matching ADML are available in Central Store; OS updates do not automatically copy them there. Forest schema extension is a one-time privileged change requiring change control. Then delegate computer SELF on Training, narrow reader/reset groups and decryptor membership independently, and audit their ACLs. Do not grant the whole domain help-desk access to solve a single-device error.

Read-only examples on an authorized supported Windows LAPS/RSAT host; no password attributes are selected:

```powershell
Find-LapsADExtendedRights -Identity 'OU=Training,DC=lab,DC=example'
Get-ADComputer -Identity 'TRAINING01' -Properties 'msLAPS-PasswordExpirationTime' |
	Select-Object Name, @{Name='ExpiryUtc'; Expression={
		$expiry = $_.'msLAPS-PasswordExpirationTime'
		if ($expiry -and $expiry -gt 0) { [datetime]::FromFileTimeUtc([long]$expiry) }
	}}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-LAPS/Operational'; Id=10003,10004,10005,10018,10020,10021,10029} -MaxEvents 30 |
	Select-Object TimeCreated, Id, LevelDisplayName
```

`Find-LapsADExtendedRights` inventories sensitive delegation, not an effective-access proof. For production telemetry avoid broad property queries and transcripts that might capture secrets.

### Recovery and Rollback

Post-authentication action 1 resets; 3 resets/signs out; 5 resets/reboots; 11 on newer OS also terminates remaining managed-identity processes. These can lose work; password rotation alone does not invalidate every existing token/session. LAPS cannot make a compromised local administrator trustworthy.

Windows 11 24H2/Server 2025 AD rollback detection compares local and directory password-version GUIDs. It requires `msLAPS-CurrentPasswordVersion` from the Server 2025 forest schema, not merely `Update-LapsADSchema`; machine authentication must still work. It is not supported for Entra backup. Recovery plans must account for unavailable DCs, encrypted history, protected directory backups and build-specific recovery tools without assuming a snapshot retains the current local password. No password recovery commands are included here.

## Gotchas

- LAPS rotates one selected local account; other local administrators and service credentials remain separate inventory items.
- A future expiry is not evidence that the latest backup and local update both succeeded.
- Retiring legacy LAPS requires checking policy, client extension and old attribute ACL/retention, not simply deploying a new ADMX.

## Labs

### Offline Rotation Timeline and FILETIME

Windows PowerShell 5.1/.NET only. Create the single file in an empty exercise directory. Its compact CSV is explicitly synthetic, with a reviewer-assigned cycle label; actual event collection must correlate host/time/activity and preserve original records. No passwords are present. This demonstrates actual FILETIME conversion and log-evidence reasoning, not a LAPS engine.

### File: inspect.ps1

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$csv = @'
Host,Cycle,Utc,Id
TRAINING01,first,2026-11-03T10:00:00Z,10003
TRAINING01,first,2026-11-03T10:00:01Z,10004
TRAINING01,second,2026-11-03T11:00:00Z,10003
TRAINING01,second,2026-11-03T11:00:01Z,10018
TRAINING01,second,2026-11-03T11:00:02Z,10020
TRAINING01,second,2026-11-03T11:00:03Z,10004
'@
$events = @($csv | ConvertFrom-Csv)
function Test-AdRotationEvidence($Rows) {
	$ordered = @($Rows | Sort-Object Utc)
	$ids = @($ordered | ForEach-Object { [int]$_.Id })
	if ($ids -contains 10005) { return $false }
	$backupIndex = [array]::IndexOf($ids, 10018)
	$localIndex = [array]::IndexOf($ids, 10020)
	return ($backupIndex -ge 0 -and $localIndex -gt $backupIndex -and
		$ids[-1] -eq 10004)
}
$first = @($events | Where-Object Cycle -eq 'first')
$second = @($events | Where-Object Cycle -eq 'second')
if (Test-AdRotationEvidence $first) { throw 'No-change cycle falsely accepted as rotation' }
if (-not (Test-AdRotationEvidence $second)) { throw 'Complete evidence not recognized' }
$missingLocal = @($second | Where-Object Id -ne '10020')
if (Test-AdRotationEvidence $missingLocal) { throw 'Incomplete evidence accepted' }
$expiry = [datetime]::SpecifyKind([datetime]'2026-12-03T11:00:00', [DateTimeKind]::Utc)
$fileTime = $expiry.ToFileTimeUtc()
$roundTrip = [datetime]::FromFileTimeUtc($fileTime)
if ($roundTrip -ne $expiry) { throw 'FILETIME round-trip failed' }
"Expiry UTC: $($roundTrip.ToString('o'))"
'PASS: no-change and missing-local evidence rejected; complete AD rotation evidence recognized'
```

### Objectives, Hints and Solution

1. Predict which cycle supports a rotation claim. Run `powershell.exe -NoProfile -File .\inspect.ps1` under existing execution policy.
2. Explain why the first 10004 record means success but not a password change. The second cycle contains AD backup 10018 followed by local update 10020 and cycle success.
3. Remove 10020 mentally and identify what evidence remains missing; the script tests this regression. An Entra-backed case would need 10029 rather than 10018 and its own policy-context validation.
4. Explain the round-trip: AD expiration is a Windows FILETIME (100-nanosecond intervals since 1601 UTC), not Unix seconds. Zero/unset is not a meaningful future expiration date.

Expected outcome: UTC `2026-12-03T11:00:00.0000000Z` and PASS. This is a deliberately bounded evidence predicate for one host/cycle, not a universal log-health or secret-consistency proof.

### Verification, Troubleshooting, and Cleanup

Author execution not performed. CSV timestamps must stay ISO UTC; mixed hosts/cycles must be separated before use. Do not weaken execution policy if blocked. Remove the exercise directory to reset. No schema, policy, account, directory attributes or passwords were changed. Original live checklist remains optional and uncompleted; no retrieval is needed for this offline lab.

- [ ] Local LAPS exercise: Enable Windows LAPS for one disposable lab machine and inspect policy, rotation, backup, and retrieval auditing using a designated operator account.
- [ ] Boundary check: Verify an unauthorized synthetic directory user cannot retrieve the password and that the permitted operator's retrieval is auditable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[LAPS Security]]

## References

- [Windows LAPS architecture](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)
- [Windows LAPS policy settings and defaults](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- [Windows LAPS event logs](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-event-log)
- [AD-backed deployment prerequisites](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
