---
title: "PowerShell Security"
aliases: []
tags: [windows, x3, security]
domain: windows
phase: "X3"
type: security
status: draft
pair: "[[PowerShell]]"
updated: 2026-11-03
---
# PowerShell Security

> [!abstract] TL;DR
> String evaluation, broad remoting rights, untrusted modules, and sensitive output can turn automation into privileged code execution or data exposure.

> [!info] Agent scope
> Security of: Objects and pipeline; scripts and modules; remoting; error handling; language modes; signing; logging; automation permissions. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Input binding, command discovery/module loading, filesystem authority, endpoint admission, and the identity under which a command runs are separate boundaries.
- Scope: read-only synthetic records, Windows 11, PowerShell 7.4/7.5 locally; Windows PowerShell 5.1 for optional JEA in an already provisioned disposable VM. No privileged production automation or host configuration changes.

## Learn

```text
Teach me defensive PowerShell engineering at expert depth. Assume knowledge of
object pipelines and Windows ACLs. Trace typed input through command resolution,
module import, errors, serialization, and a JEA endpoint. Separate syntactic
validation, business authorization, execution identity, endpoint ACLs, signing,
application control, ConstrainedLanguage, logging, and execution policy.
Compare 5.1 and 7.4/7.5, native argument semantics, trusted module paths, and
secret-safe telemetry. Demonstrate harmless baseline/fix regressions for record
allowlists and an independently reproducible read-only JEA role. Explain which
properties cannot be established by local unit tests. Use official sources and
concrete failure contracts. No offensive payloads, policy workarounds, host
control changes, or secrets. Teach in conversation, not by editing notes/files.
```

## Cheatsheet

### Trust Decisions and Fixed Contracts

| Boundary | Incomplete control | Required decision |
|---|---|---|
| Identifier | Regex matches a well-formed record name | Explicit membership in caller's authorized record set |
| Path | `LiteralPath` avoids wildcard parsing | ACLs and trusted directory ownership; do not expose arbitrary paths in a privileged function |
| Command | A friendly command name | Trusted absolute module path, reviewed exports, no writable search roots |
| Signature | Valid Authenticode signature | Approved publisher/version/content; protect the installed file after verification |
| Remoting | User may connect | Endpoint role plus per-operation checks and minimum execution identity |
| Language | Interactive session says ConstrainedLanguage | Enforced application-control policy; it is not an excuse to expose broad trusted functions |
| Errors/logs | Catch everything and print the object | Stable error codes, fail closed, redact values, retain sufficient audit context |

An advanced function's validators run before the body, but they do not prove the user should read a matching record. The lab baseline returns synthetic `private` because its regex is only grammar. The fixed version allowlists `alpha` and `beta` before lookup. There is no code evaluation in either version.

Use structured parameter binding and `-LiteralPath`; never convert data to script text. Review native executable switches separately from shell quoting. Avoid returning credentials, entire environment variables, or full exception dumps in remote results. `$ErrorActionPreference = 'Stop'` affects cmdlet errors but native exit codes still need checking. Never use `SilentlyContinue` to conceal an authorization failure.

### JEA, Lifetimes, and Versions

JEA is a Windows PowerShell remoting endpoint model. A `.pssc` maps identities to `.psrc` role capabilities installed in modules. RestrictedRemoteServer has a small built-in command set; explicitly expose only reviewed functions and parameter values. Roles combine when a user matches multiple entries, so check the effective capability rather than a single file. `NoLanguage` blocks general language constructs in the endpoint but approved commands remain powerful.

Do not grant run-as administrator just because the default JEA examples use virtual accounts. This lab uses `RunAsVirtualAccount = $false`; operations run with the connecting user's authority. No second-hop access is required. CredSSP, TrustedHosts changes, and broad remoting enablement are not lab steps. Close PSSessions in `finally`; deserialized return values are not live objects. Review endpoint and module ACLs, transcript destination permissions, and installed role files as part of deployment.

Signing example for an already provisioned approved code-signing certificate (fragment; `$approvedCertificate` must be supplied by the organization):

```powershell
Set-AuthenticodeSignature -FilePath .\Records.psm1 -Certificate $approvedCertificate
Get-AuthenticodeSignature -FilePath .\Records.psm1 |
	Select-Object Status, StatusMessage, SignerCertificate
```

Do not create a new trust root or change machine policy for this exercise. Hashes/signatures detect content changes but do not grant an operation to a caller.

## Detection and Defense

- With approved logging already configured, correlate Windows PowerShell Operational events 4103/4104, JEA transcripts, identity, endpoint, and the function's stable denial code. PowerShell 7 uses its own operational channel/policy options; inspect the actual host.
- Module imports and denied requests can be legitimate. Correlate with deployment records rather than treating every import or validation failure as malicious.
- Restrict write access to modules/role capabilities, review effective JEA commands, and alert on unexpected exported commands or endpoint changes. Logging is evidence, not prevention; avoid recording secrets in the first place.

## Labs

### Environment and Complete Files

No packages or elevation for the local portion. Put these files in `$env:TEMP\X3-PowerShellSecurity`. The optional VM section uses the same fixed module but includes its own manifest and role creation instructions; it needs no companion-note source.

`Records.psm1` (fixed implementation):

```powershell
Set-StrictMode -Version 3.0
function Get-LabRecord {
	[CmdletBinding()]
	param([Parameter(Mandatory)][string] $Name)
	if ($Name -cnotmatch '^[a-z]{1,16}$') { throw 'INVALID_NAME' }
	if ($Name -cnotin @('alpha','beta')) { throw 'NOT_AUTHORIZED' }
	$records = @{ alpha = 'public-a'; beta = 'public-b'; private = 'synthetic-private' }
	[pscustomobject]@{ Name = $Name; Value = $records[$Name] }
}
Export-ModuleMember -Function Get-LabRecord
```

`Check.ps1`:

```powershell
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
function Get-BaselineRecord([string] $Name) {
	if ($Name -cnotmatch '^[a-z]{1,16}$') { throw 'INVALID_NAME' }
	$records = @{ alpha = 'public-a'; beta = 'public-b'; private = 'synthetic-private' }
	[pscustomobject]@{ Name = $Name; Value = $records[$Name] }
}
Import-Module (Join-Path $PSScriptRoot 'Records.psm1') -Force
if ((Get-BaselineRecord private).Value -ne 'synthetic-private') { throw 'Baseline changed' }
foreach ($allowed in @('alpha','beta')) {
	if ((Get-LabRecord $allowed).Name -cne $allowed) { throw 'Allowed request failed' }
}
foreach ($denied in @('private','Alpha','alpha;marker','..','')) {
	$rejected = $false
	try { $null = Get-LabRecord -Name $denied } catch { $rejected = $true }
	if (-not $rejected) { throw "Unexpected acceptance: $denied" }
}
'PASS: baseline exposed synthetic private; fixed allowlist rejected it; public reads work'
```

### CTF Objectives and Baseline

```powershell
Set-Location "$env:TEMP\X3-PowerShellSecurity"
$PSVersionTable
pwsh -NoProfile -File .\Check.ps1
if ($LASTEXITCODE -ne 0) { throw 'Local checks failed' }
```

Explain why the well-formed `private` request is denied only after the fix, and why punctuation rejection is independent of permission. Neither baseline nor solution executes input. The fixtures are the complete seed dataset.

### Optional Complete JEA Boundary Exercise

Only in a disposable Windows VM with an approved existing WSMan listener, remoting authentication, transcript policy, and a provisioned nonadministrator test account. The administrator must have permission to register an endpoint; the account needs no local administrator membership. Use Windows PowerShell 5.1 on that VM. If these prerequisites are absent, stop at the local checks. Do not configure the host, weaken authentication, or disconnect VPN.

Copy the printed fixed `Records.psm1` to the VM lab directory. In elevated Windows PowerShell on the VM, enter the existing test identity when prompted. These commands create every additional configuration file:

```powershell
$ErrorActionPreference = 'Stop'
$account = Read-Host 'Existing VM test account, e.g. LABVM\LabReader'
$sid = ([System.Security.Principal.NTAccount]::new($account)).Translate(
	[System.Security.Principal.SecurityIdentifier]).Value
$moduleRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\X3Records'
if (Test-Path -LiteralPath $moduleRoot) { throw 'Use a fresh VM; module path already exists' }
$roles = Join-Path $moduleRoot 'RoleCapabilities'
$null = New-Item -ItemType Directory -Path $roles
Copy-Item -LiteralPath .\Records.psm1 -Destination (Join-Path $moduleRoot 'Records.psm1')
New-ModuleManifest -Path (Join-Path $moduleRoot 'X3Records.psd1') `
	-RootModule Records.psm1 -ModuleVersion 1.0.0 -PowerShellVersion 5.1 `
	-FunctionsToExport Get-LabRecord -CmdletsToExport @() -AliasesToExport @()
$visible = @{ Name = 'Get-LabRecord'; Parameters = @(@{ Name = 'Name'; ValidateSet = @('alpha','beta') }) }
New-PSRoleCapabilityFile -Path (Join-Path $roles 'X3Read.psrc') `
	-ModulesToImport X3Records -VisibleFunctions $visible
$definitions = @{}
$definitions[$account] = @{ RoleCapabilities = 'X3Read' }
New-PSSessionConfigurationFile -Path .\X3Read.pssc `
	-SessionType RestrictedRemoteServer -RunAsVirtualAccount:$false `
	-RoleDefinitions $definitions
if (-not (Test-PSSessionConfigurationFile .\X3Read.pssc)) { throw 'Invalid PSSC' }
$sddl = "O:BAG:BAD:P(A;;GA;;;BA)(A;;GA;;;$sid)"
Register-PSSessionConfiguration -Name InventoryJEA -Path .\X3Read.pssc `
	-SecurityDescriptorSddl $sddl -Force
Get-PSSessionCapability -ConfigurationName InventoryJEA -Username $account
```

Endpoint registration may restart WinRM and affect VM sessions; use the VM console. Do not run these commands on shared hosts. Default Program Files ACLs protect the module from ordinary users; verify no local customization has granted the test account write rights. Administrators can manage the endpoint but are not given a role by this role map.

From an approved Windows PowerShell client with permitted authentication to this VM, replace `LABVM` with its actual approved name. Enter credentials interactively, never in source:

```powershell
$ErrorActionPreference = 'Stop'
$credential = Get-Credential
$session = New-PSSession -ComputerName LABVM -ConfigurationName InventoryJEA -Credential $credential
try {
	$record = Invoke-Command -Session $session -ScriptBlock { Get-LabRecord -Name alpha }
	if ($record.Value -ne 'public-a') { throw 'Allowed remote read failed' }
	$denied = $false
	try { Invoke-Command -Session $session -ScriptBlock { Get-LabRecord -Name private } -ErrorAction Stop }
	catch { $denied = $true }
	if (-not $denied) { throw 'Private name accepted' }
	$denied = $false
	try { Invoke-Command -Session $session -ScriptBlock { Get-Service } -ErrorAction Stop }
	catch { $denied = $true }
	if (-not $denied) { throw 'Unexpected command exposure' }
	'PASS: endpoint allowed alpha and denied private/Get-Service'
} finally { Remove-PSSession $session }
```

### Hints and Fixed Retest

The function allowlist remains necessary even with role parameter restrictions: local invocation and future role changes must not widen its domain. The solution is the printed fixed module plus narrow endpoint role; the baseline function is test-only and never exported to JEA. `Get-Service` is a harmless unavailable-command probe, not an attempt to alter service state. Endpoint denial, parameter denial, and function denial may produce different error records; record which layer rejected the request.

### Verification, Troubleshooting, and Cleanup

Expected: local `PASS`; optional endpoint returns alpha but rejects private and unavailable commands. No tests, endpoint registration, or VM access were performed during authoring. Authentication failures do not establish method authorization; missing command failures for alpha indicate module/role loading problems. Inspect effective capability before changing permissions. Do not add broad roles to silence errors.

VM administrator cleanup, then restore its snapshot:

```powershell
Unregister-PSSessionConfiguration -Name InventoryJEA -Force
Remove-Item -LiteralPath "$env:ProgramFiles\WindowsPowerShell\Modules\X3Records" -Recurse -Force
Remove-Item -LiteralPath .\X3Read.pssc
```

Local cleanup after closing sessions and unloading the module:

```powershell
Remove-Module Records -ErrorAction SilentlyContinue
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-PowerShellSecurity" -Recurse -Force
```

- [ ] Local PowerShell exercise: Write a read-only inventory function with typed parameters and structured output. Test missing resources, nonterminating versus terminating errors, and an explicitly constrained lab remoting endpoint.
- [ ] Boundary check: Pass a harmless metacharacter string as a typed parameter and verify it remains data. Confirm the lab remoting role cannot invoke an unapproved administrative operation.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[PowerShell]]

## References

- [PowerShell security features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
- [JEA overview](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)
- [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities)
- [JEA session configurations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/session-configurations)
- [Execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
