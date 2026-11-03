[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [string[]]$Note = @('FastAPI', 'FastAPI Security'),
    [switch]$ExtractOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$vault = Split-Path -Parent $PSScriptRoot
$workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "HackVault-Examples-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $workRoot
$pattern = '(?ms)^#{3,4} File: `?(?<name>[a-zA-Z0-9_.][a-zA-Z0-9_./ -]*)`?\r?\n\r?\n```[a-zA-Z0-9_+-]*\r?\n(?<code>.*?)^```\r?$'

foreach ($title in $Note) {
    $paths = @('Web', 'Windows', 'Tools') | ForEach-Object {
        Get-ChildItem -LiteralPath (Join-Path $vault $_) -Recurse -File -Filter '*.md'
    } | Where-Object { $_.BaseName -eq $title }
    if (@($paths).Count -ne 1) { throw "Expected exactly one learning note: $title" }
    $path = $paths.FullName
    $text = Get-Content -LiteralPath $path -Raw
    $blocks = [regex]::Matches($text, $pattern)
    if ($blocks.Count -eq 0) { throw "No named example files found in $title" }
    $directory = Join-Path $workRoot ($title -replace ' ', '-')
    $null = New-Item -ItemType Directory -Path $directory
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($block in $blocks) {
        $name = $block.Groups['name'].Value.Trim()
        if ([System.IO.Path]::IsPathRooted($name) -or '..' -in ($name -split '/')) {
            throw "Example filename must stay inside its lab directory: $name"
        }
        if (-not $seen.Add($name)) { throw "Duplicate example file: $name" }
        $destination = Join-Path $directory $name
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination)
        [System.IO.File]::WriteAllText(
            $destination,
            $block.Groups['code'].Value,
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    if ($ExtractOnly) {
        Write-Output "EXTRACTED: $title ($($blocks.Count) files) at $directory"
        continue
    }
    Push-Location $directory
    try {
        & $Python -m pytest -q
        if ($LASTEXITCODE -ne 0) { throw "Example tests failed: $title" }
    }
    finally { Pop-Location }
    Write-Output "PASS: $title example files extracted and tested at $directory"
}