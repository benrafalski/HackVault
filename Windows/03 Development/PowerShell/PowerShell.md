---
title: "PowerShell"
aliases: []
tags: [windows, x3]
domain: windows
phase: "X3"
type: tech
status: draft
pair: "[[PowerShell Security]]"
updated: 2026-11-03
---
# PowerShell

> [!abstract] TL;DR
> Use approved verbs, parameter validation, objects instead of parsed tables, and -ErrorAction Stop where failure must terminate. Avoid Invoke-Expression for data.

> [!info] Agent scope
> Objects and pipeline; scripts and modules; remoting; error handling; language modes; signing; logging; automation permissions.

## Prerequisites

- Windows 11 x64; PowerShell 7.4 LTS or 7.5 for the local lab, without elevation. Windows PowerShell 5.1 is a different host/runtime, used for the optional JEA exercise in the paired note.
- Basic .NET types, Windows ACLs, script parameters, and [[Windows Lab Setup]]. No gallery packages are required. Respect managed execution policy; use an approved signed copy if scripts are blocked.

## Learn

```text
Teach me PowerShell automation at expert depth, assuming C# basics and Windows
ACL knowledge. Compare Windows PowerShell 5.1/.NET Framework with PowerShell
7.4/7.5/.NET: parser, command discovery, parameter binding, pipeline enumeration,
begin/process/end, objects versus formatting records, streams, and remoting
serialization. Trace a module function from binding to error record to caller.
Explain terminating/nonterminating/native-process errors, strict mode, module
scope, manifests, signing, application control, language modes, JEA, logging,
and endpoint versus operation authorization. Demonstrate typed read-only file
inventory, pipeline input, LiteralPath, disposal, and exact regression checks.
Explain WSMan versus SSH and what survives remoting. Use public Microsoft
sources and version-specific contracts. No execution-policy workarounds, host
control changes, secrets, or offensive examples. Teach here, not by authoring
files or editing notes; give worked answers to difficult lifecycle questions.
```

## Cheatsheet

### Execution and Object Contracts

| Mechanism | Contract and consequence |
|---|---|
| Pipeline | Enumerates most collections one level; `Write-Output -NoEnumerate` or unary comma preserves an array as one object. Assignment can yield null, a scalar, or an array; use `@(...)` for a stable collection. |
| Advanced function | `[CmdletBinding()]` supplies common parameters. `process` runs per incoming object; `begin` initializes once; `end` aggregates. `clean` exists in 7.3+, not 5.1. |
| Binding | Parameters bind by name/position, then pipeline by value/property name with conversion. Validation rejects at the function boundary but does not confer authority. |
| Streams | 1 success, 2 error, 3 warning, 4 verbose, 5 debug, 6 information; progress is separate. A stray expression becomes success output and changes the API. |
| Formatting | `Format-Table` emits formatting records, not the original file objects. Filter/select/export before formatting. |
| Scope | A module has session state, not a sandbox. Import executes top-level code. Use an explicit trusted module path and a narrow export list. |
| Remoting | WSMan usually transports serialized property bags, e.g. `Deserialized.System.IO.FileInfo`, not live handles/methods. Run operations at the endpoint, return data. |

Strings are data unless explicitly evaluated as code. `Get-Item -LiteralPath $Path` avoids wildcard expansion but still obeys filesystem resolution/ACLs; it is not a confinement primitive. `& $exe @arguments` invokes a command with an argument array, but the invoked program has its own option grammar. Native argument passing changed in 7.3; test Windows legacy executable quoting explicitly.

### Error and Lifetime Rules

```powershell
try {
	$item = Get-Item -LiteralPath $Path -ErrorAction Stop
	$stream = [System.IO.File]::OpenRead($item.FullName)
	try { $length = $stream.Length } finally { $stream.Dispose() }
} catch [System.UnauthorizedAccessException] {
	throw
}
```

This is a fragment: `$Path` is caller supplied. `-ErrorAction Stop` promotes a cmdlet's nonterminating error so `catch` can intercept it; it does not turn every native exit code into an exception. For native tools, inspect `$LASTEXITCODE` immediately. `$?` describes the preceding command, not the durable outcome of a workflow. `throw` is terminating; `$PSCmdlet.WriteError()` lets callers choose `Continue` or `Stop`. `finally` runs during ordinary unwinding, not guaranteed during process termination or power failure.

`Set-StrictMode -Version 3.0` detects missing variables/properties; it does not make input safe. Avoid `Latest` in distributed scripts when behavior must stay stable across host upgrades. Prefer `SupportsShouldProcess` and `$PSCmdlet.ShouldProcess()` for destructive automation; a read-only function should not pretend to need it.

### Permissions, Policy, and Remoting

- Execution policy manages accidental script execution; it is not a security boundary. Its precedence includes machine/user policy, process, current user, local machine. Never change it to make this lab run.
- Authenticode identifies a signer and detects modification. Trust the publisher and delivery path separately; signing does not prove benign behavior. `Get-AuthenticodeSignature -FilePath .\Inventory.psm1` is an inspection command, not authorization.
- Application control can enforce ConstrainedLanguage. `$ExecutionContext.SessionState.LanguageMode` reports the current session, not the trust of every endpoint. A caller-selected mode is not a containment boundary.
- JEA uses a restricted endpoint, role capabilities, and an explicitly chosen execution identity. Connecting to an endpoint and invoking a particular operation are separate grants. Do not select a privileged virtual account for read-only file inventory.
- WSMan remoting requires an existing approved listener, authentication and endpoint ACL; SSH remoting requires an SSH subsystem and has different feature support. Neither is enabled by this note. With an approved endpoint, `Invoke-Command -ComputerName LABVM -ConfigurationName InventoryJEA -ScriptBlock { Get-LabRecord -Name alpha }` returns serialized results. See the complete optional setup in [[PowerShell Security]].
- Script-block logging (4104), module logging (4103), transcription, and PowerShell operational logs have different coverage. PowerShell 7 and Windows PowerShell use distinct policy/log configuration. Protect logs and exclude sensitive arguments.

## Gotchas

- `$HOME`, `$PID`, and variable names differing only in case are not independent scratch names. Use descriptive names.
- PowerShell 7 defaults to UTF-8 without BOM; Windows PowerShell 5.1 has legacy encoding defaults. Specify encoding for interchange. Native redirection behavior also differs across versions.
- Remoting a live `FileStream` does not transfer ownership of a usable remote stream. Close it on the machine that opened it.

## Labs

### Environment and Complete Files

Local lab directory: `$env:TEMP\X3-PowerShell`. Create it and put the following three files there. Run with an approved PowerShell 7 host as a standard user. The fixture is synthetic; no registry, services, remoting or host-policy changes occur.

`Inventory.psm1`:

```powershell
Set-StrictMode -Version 3.0
function Get-LabFile {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[Alias('FullName')]
		[ValidateNotNullOrEmpty()]
		[string[]] $LiteralPath
	)
	process {
		foreach ($candidate in $LiteralPath) {
			try {
				$item = Get-Item -LiteralPath $candidate -ErrorAction Stop
				if ($item -isnot [System.IO.FileInfo]) {
					throw [System.ArgumentException]::new('Expected a file')
				}
				$stream = [System.IO.File]::OpenRead($item.FullName)
				try {
					[pscustomobject]@{
						PSTypeName = 'X3.FileRecord'
						Name = $item.Name
						Length = $stream.Length
						FullName = $item.FullName
					}
				} finally { $stream.Dispose() }
			} catch {
				$PSCmdlet.WriteError($_)
			}
		}
	}
}
Export-ModuleMember -Function Get-LabFile
```

`Inventory.psd1`:

```powershell
@{
	RootModule = 'Inventory.psm1'
	ModuleVersion = '1.0.0'
	GUID = '3de1fb76-9153-4ad0-92c7-ad6d3bc89df9'
	PowerShellVersion = '7.4'
	FunctionsToExport = @('Get-LabFile')
	CmdletsToExport = @()
	VariablesToExport = @()
	AliasesToExport = @()
}
```

`Check.ps1`:

```powershell
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Inventory.psd1') -Force
$fixture = Join-Path $PSScriptRoot 'data'
$null = New-Item -ItemType Directory -Path $fixture -Force
$file = Join-Path $fixture 'alpha[1];marker.txt'
[System.IO.File]::WriteAllText($file, 'abc', [System.Text.UTF8Encoding]::new($false))
$records = @($file | Get-LabFile)
if ($records.Count -ne 1 -or $records[0].Length -ne 3) { throw 'Object contract failed' }
if ($records[0].Name -ne 'alpha[1];marker.txt') { throw 'Literal path changed' }
$byProperty = @([pscustomobject]@{ FullName = $file } | Get-LabFile)
if ($byProperty.Count -ne 1) { throw 'Property binding failed' }
$failures = @()
$missing = Join-Path $fixture 'absent.txt'
$partial = @(Get-LabFile -LiteralPath $missing,$file -ErrorAction SilentlyContinue -ErrorVariable failures)
if ($failures.Count -ne 1 -or $partial.Count -ne 1) { throw 'Continue contract failed' }
$caught = $false
try { Get-LabFile -LiteralPath $missing -ErrorAction Stop } catch { $caught = $true }
if (-not $caught) { throw 'Stop contract failed' }
$exclusive = [System.IO.File]::Open($file, 'Open', 'ReadWrite', 'None')
$exclusive.Dispose()
$records | ConvertTo-Json | Write-Output
'PASS: binding, literal data, error policy, disposed handle'
```

### Objectives and Steps

```powershell
Set-Location "$env:TEMP\X3-PowerShell"
$PSVersionTable
Test-ModuleManifest .\Inventory.psd1
pwsh -NoProfile -File .\Check.ps1
if ($LASTEXITCODE -ne 0) { throw 'Lab failed' }
Get-AuthenticodeSignature .\Inventory.psm1
$ExecutionContext.SessionState.LanguageMode
```

Trace how `FullName` binds to the alias, identify which statements emit success output, and explain why the later exclusive open is an ownership check. No parameter string is evaluated. If policy requires signing, request approved signing before running; do not lower policy. Signing validation alone is not expected to return `Valid` for these unsigned teaching files.

### Hints

`@(...)` normalizes pipeline cardinality. `-ErrorVariable` receives records even when error display is suppressed. A semicolon inside an already bound string is a filename character, not a command separator.

### Solution and Expected Results

The supplied implementation is the solution: one object with length 3, one captured missing-file error, continued processing of the second item, a caught terminating error under `Stop`, and successful exclusive reopen. These are expected results, not recorded execution. Moving formatting into the function breaks the object contract; removing `finally` makes ownership dependent on GC.

### Verification, Troubleshooting, and Cleanup

No commands were executed during authoring. Parent validation should execute the exact files and preserve host/version, exit code, and output. A sharing violation during reopen indicates an outstanding handle or another application touching the fixture; an execution-policy failure is an environment prerequisite, not a reason to bypass policy. Delete only this lab's data and module from the session:

```powershell
Remove-Module Inventory -ErrorAction SilentlyContinue
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-PowerShell" -Recurse -Force
```

The optional endpoint boundary requires the separate disposable-VM procedure in the paired note; the local test does not claim remoting authorization coverage.

- [ ] Local PowerShell exercise: Write a read-only inventory function with typed parameters and structured output. Test missing resources, nonterminating versus terminating errors, and an explicitly constrained lab remoting endpoint.
- [ ] Boundary check: Pass a harmless metacharacter string as a typed parameter and verify it remains data. Confirm the lab remoting role cannot invoke an unapproved administrative operation.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[PowerShell Security]]

## References

- [Advanced functions and methods](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_methods)
- [Error handling](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_try_catch_finally)
- [Remoting output](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_output)
- [Security features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
- [Language modes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes)
