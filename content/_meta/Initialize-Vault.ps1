[CmdletBinding()]
param(
    [string]$VaultRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Updated = (Get-Date -Format 'yyyy-MM-dd')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Course Catalog.json') -Raw | ConvertFrom-Json
$templateRoot = Join-Path $PSScriptRoot 'Templates'
$script:created = 0
$script:preserved = 0

function Expand-Template {
    param([string]$Template, [hashtable]$Values)
    $result = $Template
    foreach ($key in $Values.Keys) {
        $result = $result.Replace("{{$key}}", [string]$Values[$key])
    }
    if ($result -match '\{\{[^}]+\}\}') {
        throw "Unresolved template token: $($Matches[0])"
    }
    return $result
}

function Write-NewNote {
    param([string]$RelativePath, [string]$Content)
    $path = Join-Path $VaultRoot $RelativePath
    if (Test-Path -LiteralPath $path) {
        $script:preserved++
        return
    }
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew)
    try {
        $bytes = $encoding.GetBytes($Content.TrimEnd() + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
    $script:created++
}

function Get-DisplayTitle {
    param($Entry)
    if ($Entry.PSObject.Properties.Name -contains 'title') { return $Entry.title }
    return $Entry.name
}

function Get-NoteValues {
    param($Entry, [string]$Domain, [string]$Phase, [string]$Tag, [string]$Pair, [string]$Scope, [string]$Related)
    $jsonTitle = ConvertTo-Json -InputObject (Get-DisplayTitle $Entry) -Compress
    return @{
        title = $jsonTitle.Substring(1, $jsonTitle.Length - 2)
        domain = $Domain.ToLowerInvariant()
        phase = $Phase
        tag = $Tag
        pair = $Pair
        date = $Updated
        scope = $Scope
        related = $Related
    }
}

$templates = @{}
foreach ($kind in @('Tech', 'Security', 'Technique', 'Roadmap')) {
    $templates[$kind] = Get-Content -LiteralPath (Join-Path $templateRoot "$kind Template.md") -Raw
}

$relatedTechniques = @{
    'Browser Security Model' = @('CORS Misconfiguration', 'CSRF', 'XSS', 'Clickjacking')
    'HTTP' = @('Request Smuggling', 'Host Header Attacks')
    'HTTP2 and HTTP3' = @('Request Smuggling')
    'URLs and Encoding' = @('Path Traversal', 'SSRF')
    'HTML' = @('XSS', 'Clickjacking')
    'CSS' = @('Clickjacking')
    'JavaScript' = @('XSS', 'Prototype Pollution')
    'DOM and Browser APIs' = @('XSS', 'Prototype Pollution')
    'React' = @('XSS')
    'Angular' = @('XSS')
    'Vue' = @('XSS')
    'npm Ecosystem' = @('Supply Chain Attacks')
    'Bundlers' = @('Supply Chain Attacks')
    'WebSockets' = @('WebSocket Attacks')
    'postMessage' = @('XSS')
    'Nodejs and Express' = @('Prototype Pollution', 'Command Injection')
    'Template Engines' = @('SSTI', 'XSS')
    'Serialization' = @('XXE', 'Insecure Deserialization')
    'REST APIs' = @('Broken Access Control and IDOR', 'Business Logic Attacks')
    'GraphQL' = @('GraphQL Attacks')
    'MySQL' = @('SQL Injection')
    'PostgreSQL' = @('SQL Injection')
    'Web SQL Server' = @('SQL Injection', 'Windows SQL Server')
    'SQLite' = @('SQL Injection')
    'ORMs' = @('SQL Injection', 'Broken Access Control and IDOR')
    'MongoDB' = @('NoSQL Injection')
    'Object Storage' = @('File Upload Attacks', 'Broken Access Control and IDOR')
    'Sessions and Cookies' = @('CSRF')
    'JWT' = @('JWT Attacks')
    'OAuth2' = @('OAuth Attacks')
    'OpenID Connect' = @('OAuth Attacks', 'JWT Attacks')
    'CI and CD' = @('Supply Chain Attacks')
    'Reverse Proxies CDN and WAF' = @('Request Smuggling', 'Host Header Attacks', 'Cache Poisoning and Deception')
    'HTTP Caching' = @('Cache Poisoning and Deception')
    'Burp Workflow' = @('Burp Suite')
    'Windows Tooling Setup' = @('Sysinternals', 'System Informer', 'x64dbg', 'Ghidra and IDA', 'WinDbg')
    'Windows Lab Setup' = @('WinDbg')
    'Virtual Memory' = @('Windows Heap Exploitation', 'Windows Exploit Mitigations', 'WinDbg')
    'Windows Security Model' = @('Windows Local Privilege Escalation')
    'Loader and DLLs' = @('Windows Persistence', 'Process Injection')
    'Services and SCM' = @('Windows Local Privilege Escalation', 'Windows Persistence')
    'Scheduled Tasks' = @('Windows Persistence')
    'Exceptions and SEH' = @('Windows Stack and SEH Overflows', 'WinDbg')
    'ETW and Event Log' = @('ETW-TI', 'Detection Engineering')
    'Windows Drivers' = @('Windows Kernel Exploitation', 'WinDbg')
    'Kernel Architecture' = @('WinDbg')
    'Driver Development' = @('Windows Kernel Exploitation', 'WinDbg')
    'SMB' = @('Windows Lateral Movement', 'AD Attacks', 'Impacket')
    'NTLM' = @('AD Attacks')
    'Kerberos' = @('AD Attacks')
    'Active Directory' = @('AD Attacks', 'BloodHound')
    'AD CS' = @('AD Attacks')
    'Windows SQL Server' = @('Web SQL Server', 'Windows Lateral Movement')
    'Windows Kernel Exploitation' = @('WinDbg', 'Windows Exploit Mitigations')
    'Windows Stack and SEH Overflows' = @('WinDbg', 'Windows Exploit Mitigations')
    'Windows Heap Exploitation' = @('WinDbg', 'Windows Exploit Mitigations')
    'Malware Analysis and RE' = @('Ghidra and IDA', 'x64dbg', 'WinDbg')
    'Sysmon' = @('Sysinternals', 'Detection Engineering')
}

foreach ($phase in $catalog.phases) {
    $tag = $phase.id.ToLowerInvariant()
    $phaseNotes = @($catalog.notes | Where-Object phase -eq $phase.id)
    foreach ($entry in $phaseNotes) {
        $folder = "$($phase.domain)/$($phase.folder)"
        $related = @("- [[$($phase.domain) Roadmap#$($phase.id) $($phase.title)|$($phase.id) $($phase.title)]]")
        if ($relatedTechniques.ContainsKey($entry.name)) {
            $related += @($relatedTechniques[$entry.name] | ForEach-Object { "- [[$_]]" })
        }
        $pair = ''
        if ($entry.kind -eq 'pair') {
            $folder += "/$($entry.name)"
            $pair = "[[$($entry.name) Security]]"
            $related += "- $pair"
        }
        $values = Get-NoteValues $entry $phase.domain $phase.id $tag $pair $entry.scope ($related -join "`n")
        $template = $templates.Tech
        if ($entry.kind -eq 'technique') { $template = $templates.Technique }
        if ($entry.kind -eq 'method') {
            $template = $template.Replace('type: tech', 'type: method').Replace('### Build It', '### Practice the Workflow')
        }
        Write-NewNote "$folder/$($entry.name).md" (Expand-Template $template $values)
        if ($entry.kind -eq 'pair') {
            $values.title += ' Security'
            $values.pair = "[[$($entry.name)]]"
            $values.scope = "Security of: $($entry.scope) Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques."
            if ($phase.id -eq 'X7') {
                $values.scope += ' Include bypass prerequisites, coverage limitations, and compensating controls in controlled labs.'
            }
            $values.related = (@($related | Where-Object { $_ -ne "- $pair" }) + "- $($values.pair)") -join "`n"
            Write-NewNote "$folder/$($entry.name) Security.md" (Expand-Template $templates.Security $values)
        }
    }
}

foreach ($entry in $catalog.tools) {
    $related = "- [[Tools Index]]"
    if ($entry.name -eq 'Burp Suite') { $related += "`n- [[Burp Workflow]]" }
    if ($entry.name -eq 'Sysinternals') { $related += "`n- [[Sysmon]]" }
    $values = Get-NoteValues $entry 'tools' '' 'workflow' '' $entry.scope $related
    $template = $templates.Tech.Replace('type: tech', 'type: method').Replace('### Build It', '### Practice the Workflow')
    Write-NewNote "Tools/$($entry.name).md" (Expand-Template $template $values)
}

$phaseMarker = '## {{phase}} {{phaseTitle}}'
$markerIndex = $templates.Roadmap.IndexOf($phaseMarker, [System.StringComparison]::Ordinal)
if ($markerIndex -lt 0) { throw 'Roadmap template is missing its phase section.' }
$roadmapHeader = $templates.Roadmap.Substring(0, $markerIndex)
$phaseTemplate = $templates.Roadmap.Substring($markerIndex)
foreach ($domain in @('Web', 'Windows')) {
    $headerValues = @{ title = "$domain Roadmap"; domain = $domain.ToLowerInvariant(); date = $Updated }
    $content = Expand-Template $roadmapHeader $headerValues
    $content += "[[index|Home]] | [[$domain Labs]] | [[Tools Index]]`n`n"
    $content += "Work in phase order. Check each note only after meeting its learning and lab goals; complete both sides of every pair. Status progression: stub -> draft -> learning -> practiced -> mastered.`n`n"
    foreach ($phase in ($catalog.phases | Where-Object domain -eq $domain)) {
        $links = @()
        foreach ($entry in ($catalog.notes | Where-Object phase -eq $phase.id)) {
            $links += "- [ ] [[$($entry.name)]]"
            if ($entry.kind -eq 'pair') { $links += "- [ ] [[$($entry.name) Security]]" }
        }
        $values = @{
            phase = $phase.id
            phaseTitle = $phase.title
            goal = $phase.goal
            notes = $links -join "`n"
            labs = ($phase.labs | ForEach-Object { "- [ ] $_" }) -join "`n"
            exit = "- [ ] $($phase.exit)"
        }
        $content += (Expand-Template $phaseTemplate $values).TrimEnd() + "`n`n"
    }
    Write-NewNote "$domain/$domain Roadmap.md" $content
}

Write-Output "Scaffold: $script:created files created; $script:preserved existing files preserved."
& (Join-Path $PSScriptRoot 'Test-Vault.ps1') -VaultRoot $VaultRoot