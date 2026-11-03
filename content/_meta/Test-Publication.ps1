[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path -LiteralPath $OutputRoot).Path
$files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)
foreach ($file in $files) {
    $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
    if ($relative -match '(^|/)(Private|\.obsidian)(/|$)' -or $relative -match '^_meta/Templates(/|$)' -or $relative -match '(^|/)AGENTS\.(md|html)$') {
        throw "Excluded content was published: $relative"
    }
}
foreach ($page in @('index.html', 'Web/Web-Roadmap.html', 'Windows/Windows-Roadmap.html')) {
    $path = Join-Path $root $page
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing published page: $page" }
    $html = Get-Content -LiteralPath $path -Raw
    if ($html.Length -lt 1000 -or $html -notmatch '<title>') { throw "Invalid published page: $page" }
}
$indexPath = Join-Path $root 'static/contentIndex.json'
if (-not (Test-Path -LiteralPath $indexPath)) { throw 'Missing Quartz search index.' }
$index = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
foreach ($entry in $index.PSObject.Properties) {
    if ($entry.Name -match '(^|/)(Private|\.obsidian)(/|$)|^_meta/Templates(/|$)|(^|/)AGENTS$') {
        throw "Excluded content entered the search index: $($entry.Name)"
    }
}
$homeHtml = Get-Content -LiteralPath (Join-Path $root 'index.html') -Raw
if ($homeHtml -notmatch 'Web/Web-Roadmap' -or $homeHtml -notmatch 'Windows/Windows-Roadmap') { throw 'Home page is missing roadmap links.' }
if ($homeHtml -notmatch 'data-callout=') { throw 'Expected home-page callout did not render.' }
Write-Output "PASS: $($files.Count) output files; both roadmaps, home links, search index, and callout render; excluded paths are absent."