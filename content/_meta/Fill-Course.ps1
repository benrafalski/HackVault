[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Phase)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Course Catalog.json') -Raw | ConvertFrom-Json
$data = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Templates/Course Drafts.json') -Raw | ConvertFrom-Json -AsHashtable
$written = 0
$preserved = 0

foreach ($phaseId in $Phase) {
    if ($phaseId -eq 'Tools') {
        $entries = $catalog.tools
        $domain = 'tools'
        $folder = 'Tools'
    }
    else {
        $phaseInfo = $catalog.phases | Where-Object id -eq $phaseId
        if (-not $phaseInfo) { throw "Unknown phase: $phaseId" }
        $entries = $catalog.notes | Where-Object phase -eq $phaseId
        $domain = $phaseInfo.domain.ToLowerInvariant()
        $folder = "$($phaseInfo.domain)/$($phaseInfo.folder)"
    }
    foreach ($entry in $entries) {
        if (-not $data.ContainsKey($entry.name)) { throw "Missing authored content: $($entry.name)" }
        $draft = $data[$entry.name]
        foreach ($field in @('model', 'concepts', 'exercise', 'quick', 'risk', 'test', 'defense', 'gotcha', 'reference')) {
            if (-not $draft.ContainsKey($field) -or -not $draft[$field]) { throw "Missing $field for $($entry.name)" }
        }
        if ($draft.concepts.Count -lt 3) { throw "At least three concrete concepts required: $($entry.name)" }
        $names = @($entry.name)
        $noteFolder = $folder
        $kind = 'method'
        if ($phaseId -ne 'Tools') { $kind = $entry.kind }
        if ($kind -eq 'pair') { $names += "$($entry.name) Security"; $noteFolder += "/$($entry.name)" }
        foreach ($name in $names) {
            $path = Join-Path $root "$noteFolder/$name.md"
            $existing = Get-Content -LiteralPath $path -Raw
            if ($existing -notmatch '(?m)^status: stub\r?$') { $preserved++; continue }
            $metadataMatch = [regex]::Match($existing, '(?s)\A---\r?\n.*?\r?\n---\r?\n')
            if (-not $metadataMatch.Success) { throw "Missing frontmatter: $name" }
            $header = $metadataMatch.Value.Replace('status: stub', 'status: draft')
            $heading = [regex]::Match($existing, '(?m)^# .+$').Value.TrimEnd()
            $scope = [regex]::Match($existing, '(?m)^> \[!info\] Agent scope\r?\n> .+$').Value.TrimEnd()
            $relatedMatch = [regex]::Match($existing, '(?ms)^## Related(?: Techniques)?\r?\n(.*?)(?=^## References|\z)')
            $related = $relatedMatch.Groups[1].Value.Trim()
            $core = @($draft.concepts | Select-Object -First 2 | ForEach-Object { "- $_" }) -join "`n"
            $internals = @($draft.concepts | Select-Object -Skip 2 | ForEach-Object { "- $_" }) -join "`n"
            $labSetup = if ($domain -eq 'web') { 'Web Lab Setup' } else { 'Windows Lab Setup' }
            $prerequisite = "- Use an isolated, disposable environment; record OS, runtime, and tool versions."
            if ($name -ne $labSetup -and $domain -ne 'tools') { $prerequisite += "`n- [[${labSetup}]]" }
            $labs = "- [ ] Local $($entry.name) exercise: $($draft.exercise)`n- [ ] Boundary check: $($draft.test)`n- [ ] Record the observed result, relevant version, and a retest after applying the control."
            $references = "- [Official documentation or primary training reference]($($draft.reference))"
            $security = $name -ne $entry.name
            if ($security) {
                $summary = $draft.risk
                $body = @"
## Attack Surface

- $($draft.risk)
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

### Root Causes

$($draft.risk)

### Hands-On Exercises

1. In an authorized disposable lab, establish the expected behavior with synthetic data.
2. $($draft.test)
3. Apply the documented control and repeat the same request or operation; preserve both observations.

## Cheatsheet

### Exploitation Cheatsheet

- **Check:** $($draft.test)
- **Constraint:** $($draft.gotcha)
- Use harmless markers and synthetic identities; do not test production services or access unrelated data.

## Detection and Defense

$($draft.defense)

## Labs

$labs

## Related Techniques

$related

## References

$references
"@
            }
            elseif ($kind -eq 'technique') {
                $summary = $draft.model
                $body = @"
## Learn

### Root Cause

$($draft.model)

### Variants

$core

### Detection - Finding It

$internals

### Hands-On Exercises

$($draft.exercise)

## Cheatsheet

### Exploitation Cheatsheet

$($draft.quick)

- **Controlled test:** $($draft.test)
- **Prerequisite and impact:** $($draft.risk)

### Bypasses

$($draft.gotcha)

## Defense

$($draft.defense)

## Labs

$labs

## Related

$related

## References

$references
"@
            }
            else {
                $summary = $draft.quick
                $exerciseHeading = if ($kind -eq 'method') { 'Practice the Workflow' } else { 'Build It' }
                $body = @"
## Prerequisites

$prerequisite

## Learn

### Mental Model

$($draft.model)

### Core Concepts

$core

### Under the Hood

$internals

### $exerciseHeading

$($draft.exercise)

## Cheatsheet

$($draft.quick)

## Gotchas

$($draft.gotcha)

## Labs

$labs

## Related

$related

## References

$references
"@
            }
            $content = "$header$heading`n`n> [!abstract] TL;DR`n> $summary`n`n$scope`n`n$body`n"
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $written++
        }
    }
}
Write-Output "Drafted $written notes; preserved $preserved existing non-stub notes. Exercises remain unexecuted and unchecked."
& (Join-Path $PSScriptRoot 'Test-Vault.ps1')