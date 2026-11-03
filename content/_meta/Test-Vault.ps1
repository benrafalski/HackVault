[CmdletBinding()]
param(
    [string]$VaultRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipObsidianSettings,
    [switch]$CheckRevisedContent
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Course Catalog.json') -Raw | ConvertFrom-Json
$issues = [System.Collections.Generic.List[string]]::new()
$files = @(Get-ChildItem -LiteralPath $VaultRoot -Filter '*.md' -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/]\.obsidian[\\/]'
})
$duplicates = @($files | Group-Object BaseName | Where-Object Count -gt 1)
foreach ($duplicate in $duplicates) { $issues.Add("Duplicate basename: $($duplicate.Name)") }
$publicNotes = @{}
$metadataByName = @{}
$textByName = @{}
$requiredFields = @('title', 'aliases', 'tags', 'domain', 'phase', 'type', 'status', 'pair', 'updated')
$revisedCount = 0

function Get-Scalar {
    param([string]$Value)
    if ($Value.StartsWith('"')) { return (ConvertFrom-Json -InputObject $Value) }
    if ($Value.StartsWith("'")) { return $Value.Trim("'").Replace("''", "'") }
    return $Value
}

foreach ($file in $files) {
    $relative = [System.IO.Path]::GetRelativePath($VaultRoot, $file.FullName).Replace('\', '/')
    if ($relative -match '^(Private/|_meta/Templates/)' -or $relative -eq 'AGENTS.md') { continue }
    $publicNotes[$file.BaseName] = $file
    $text = Get-Content -LiteralPath $file.FullName -Raw
    $textByName[$file.BaseName] = $text
    if ($file.BaseName -match '[/\\:#&?.]' -or $file.BaseName -match ' - ') {
        $issues.Add("Unsafe filename: $relative")
    }
    if ($text -notmatch '(?s)^---\r?\n(.*?)\r?\n---') {
        $issues.Add("Missing frontmatter: $relative")
        continue
    }
    $metadata = @{}
    foreach ($line in ($Matches[1] -split '\r?\n')) {
        if ($line -match '^([a-z]+):\s*(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]
            if ($metadata.ContainsKey($key)) { $issues.Add("Duplicate field ${key}: $relative") }
            $metadata[$key] = Get-Scalar $value
        }
    }
    $metadataByName[$file.BaseName] = $metadata
    if ($relative -eq '_meta/Course Plan.md') { continue }
    foreach ($field in $requiredFields) {
        if (-not $metadata.ContainsKey($field)) { $issues.Add("Missing ${field}: $relative") }
    }
    if ($metadata.type -notin @('tech', 'security', 'technique', 'method', 'moc', 'lab')) { $issues.Add("Invalid type: $relative") }
    if ($metadata.status -notin @('stub', 'draft', 'learning', 'practiced', 'mastered')) { $issues.Add("Invalid status: $relative") }
    if ($metadata.domain -notin @('web', 'windows', 'tools', 'meta')) { $issues.Add("Invalid domain: $relative") }
    if ($metadata.phase -and $metadata.phase -notin $catalog.phases.id) { $issues.Add("Invalid phase: $relative") }
    $parsedDate = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$metadata.updated, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
        $issues.Add("Invalid updated date: $relative")
    }
    foreach ($field in @('aliases', 'tags')) {
        if ([string]$metadata[$field] -notmatch '^\[.*\]$') { $issues.Add("Expected inline YAML list for ${field}: $relative") }
    }
    if ($metadata.type -in @('tech', 'security', 'technique', 'method', 'lab')) {
        foreach ($heading in @('Learn', 'Cheatsheet', 'Labs')) {
            if ($text -notmatch "(?m)^## $heading\r?$") { $issues.Add("Missing $heading heading: $relative") }
        }
        $prose = [regex]::Replace($text, '(?s)```.*?```|`[^`\r\n]+`', '')
        if ($prose -match '\{\{[^}]+\}\}') { $issues.Add("Unresolved template token: $relative") }
        if ($metadata.status -eq 'stub' -and $text -notmatch '> \[!info\] Agent scope\r?\n> \S') {
            $issues.Add("Missing Agent scope: $relative")
        }
        if ($CheckRevisedContent -and $metadata.type -ne 'lab') {
            $revisedCount++
            $learn = [regex]::Match($text, '(?ms)^## Learn\r?\n(.*?)(?=^## |\z)').Groups[1].Value
            if ($learn -notmatch '(?ms)^```text\r?\n\S.*?^```\r?$') {
                $issues.Add("Learn needs a copy-ready text prompt: $relative")
            }
            foreach ($sectionName in @('Cheatsheet', 'Labs')) {
                $section = [regex]::Match($text, "(?ms)^## $sectionName\r?`n(.*?)(?=^## |\z)").Groups[1].Value
                $examplePattern = if ($sectionName -eq 'Cheatsheet') { '(?m)^```\S+|`[^`\r\n]+`' } else { '(?m)^```\S+' }
                if ($section -notmatch $examplePattern) {
                    $issues.Add("$sectionName needs concrete code or command examples: $relative")
                }
            }
        }
    }
    if ($metadata.type -notin @('tech', 'security') -and $metadata.pair) { $issues.Add("Unexpected pair: $relative") }
}

$linkCount = 0
foreach ($name in $publicNotes.Keys) {
    $text = [regex]::Replace($textByName[$name], '(?ms)^```[^\r\n]*\r?\n.*?^```\s*$', '')
    foreach ($match in [regex]::Matches($text, '\[\[([^\]\r\n]+)\]\]')) {
        $linkCount++
        $destination = ($match.Groups[1].Value -split '\|', 2)[0]
        $parts = $destination -split '#', 2
        $target = $parts[0]
        if (-not $target) { $target = $name }
        if (-not $publicNotes.ContainsKey($target)) {
            $issues.Add("Unresolved or excluded link in ${name}: $destination")
            continue
        }
        if ($parts.Count -eq 2 -and $parts[1]) {
            $heading = [regex]::Escape($parts[1])
            if ($textByName[$target] -notmatch "(?m)^#{1,6} $heading\r?$") { $issues.Add("Missing heading in ${target}: $($parts[1])") }
        }
    }
    if (-not $metadataByName.ContainsKey($name)) { continue }
    $metadata = $metadataByName[$name]
    if ($metadata.type -notin @('tech', 'security')) { continue }
    if ($metadata.pair -notmatch '^\[\[([^\]]+)\]\]$') {
        $issues.Add("Missing or invalid pair: $name")
        continue
    }
    $sibling = $Matches[1]
    if (-not $metadataByName.ContainsKey($sibling)) { $issues.Add("Missing pair target: $name -> $sibling"); continue }
    $other = $metadataByName[$sibling]
    if ($other.pair -ne "[[$name]]") { $issues.Add("Nonreciprocal pair: $name -> $sibling") }
    if ($other.phase -ne $metadata.phase -or $other.domain -ne $metadata.domain) { $issues.Add("Pair crosses phase/domain: $name") }
    $expectedType = if ($metadata.type -eq 'tech') { 'security' } else { 'tech' }
    if ($other.type -ne $expectedType) { $issues.Add("Invalid sibling type: $name") }
}

$expectedCount = 0
foreach ($phase in $catalog.phases) {
    $roadmapName = "$($phase.domain) Roadmap"
    if (-not $textByName.ContainsKey($roadmapName)) { $issues.Add("Missing roadmap: $roadmapName"); continue }
    $roadmap = $textByName[$roadmapName]
    $phaseHeading = [regex]::Escape("## $($phase.id) $($phase.title)")
    $section = [regex]::Match($roadmap, "(?ms)^$phaseHeading\r?`n(.*?)(?=^## |\z)").Groups[1].Value
    foreach ($heading in @('Phase Goal', 'Notes', 'Labs', 'Exit Criteria')) {
        if ($section -notmatch "(?m)^### $heading\r?$") { $issues.Add("Missing roadmap section $($phase.id): $heading") }
    }
    foreach ($entry in ($catalog.notes | Where-Object phase -eq $phase.id)) {
        $expectedNames = @($entry.name)
        $folder = "$($phase.domain)/$($phase.folder)"
        if ($entry.kind -eq 'pair') { $expectedNames += "$($entry.name) Security"; $folder += "/$($entry.name)" }
        foreach ($name in $expectedNames) {
            $expectedCount++
            if (-not (Test-Path -LiteralPath (Join-Path $VaultRoot "$folder/$name.md"))) { $issues.Add("Missing course note: $folder/$name.md") }
            $link = [regex]::Escape("[[$name]]")
            if ([regex]::Matches($section, "(?m)^- \[[ xX]\] $link\r?$").Count -ne 1) { $issues.Add("Roadmap must list $name exactly once in $($phase.id)") }
            if ($metadataByName.ContainsKey($name)) {
                $metadata = $metadataByName[$name]
                $expectedType = $entry.kind
                if ($entry.kind -eq 'pair') { $expectedType = if ($name -eq $entry.name) { 'tech' } else { 'security' } }
                if ($metadata.type -ne $expectedType -or $metadata.phase -ne $phase.id -or $metadata.domain -ne $phase.domain.ToLowerInvariant()) {
                    $issues.Add("Catalog metadata mismatch: $name")
                }
            }
        }
    }
}
foreach ($entry in $catalog.tools) {
    if (-not (Test-Path -LiteralPath (Join-Path $VaultRoot "Tools/$($entry.name).md"))) { $issues.Add("Missing tool: $($entry.name)") }
}
foreach ($path in @('index.md', 'AGENTS.md', 'Web/Labs/Web Labs.md', 'Windows/Labs/Windows Labs.md', 'Tools/Tools Index.md')) {
    if (-not (Test-Path -LiteralPath (Join-Path $VaultRoot $path))) { $issues.Add("Missing scaffold path: $path") }
}
foreach ($kind in @('Tech', 'Security', 'Technique', 'Lab Writeup', 'Roadmap')) {
    if (-not (Test-Path -LiteralPath (Join-Path $VaultRoot "_meta/Templates/$kind Template.md"))) { $issues.Add("Missing template: $kind") }
}
if (Test-Path -LiteralPath (Join-Path $VaultRoot 'Welcome.md')) { $issues.Add('Welcome.md should have been removed.') }
if (-not $SkipObsidianSettings) {
if (-not (Test-Path -LiteralPath (Join-Path $VaultRoot 'Private'))) { $issues.Add('Missing reserved Private folder.') }
$settingsPath = Join-Path $VaultRoot '.obsidian/templates.json'
if (Test-Path -LiteralPath $settingsPath) {
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    if ($settings.folder -ne '_meta/Templates') { $issues.Add('Incorrect Obsidian Templates folder.') }
}
else { $issues.Add('Missing Obsidian Templates settings.') }
$pluginsPath = Join-Path $VaultRoot '.obsidian/core-plugins.json'
if (Test-Path -LiteralPath $pluginsPath) {
    $plugins = Get-Content -LiteralPath $pluginsPath -Raw | ConvertFrom-Json
    $enabled = if ($plugins -is [array]) { 'templates' -in $plugins } else { $plugins.templates -eq $true }
    if (-not $enabled) { $issues.Add('Obsidian Templates plugin is disabled.') }
}
else { $issues.Add('Missing Obsidian core plugin settings.') }
}
if ($issues.Count) {
    foreach ($issue in $issues) { Write-Output "FAIL: $issue" }
    throw "Vault validation failed with $($issues.Count) issue(s)."
}
$pairCount = @($catalog.notes | Where-Object kind -eq 'pair').Count
Write-Output "PASS: $expectedCount course notes, $pairCount reciprocal pairs, $(@($catalog.tools).Count) tools, 16 phase sections, and $linkCount resolving public wikilinks."
Write-Output 'PASS: unique basenames, metadata schema, required headings, scope callouts, and roadmap coverage.'
if ($CheckRevisedContent) {
    Write-Output "PASS: $revisedCount learning notes have teaching prompts, reference syntax, and fenced lab examples. This is structural validation, not a technical-accuracy or execution certification."
}
if (-not $SkipObsidianSettings) { Write-Output 'PASS: local Obsidian Templates settings and reserved Private folder.' }