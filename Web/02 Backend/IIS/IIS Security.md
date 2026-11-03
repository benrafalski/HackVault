---
title: "IIS Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[IIS]]"
updated: 2026-11-03
---
# IIS Security

> [!abstract] TL;DR
> Overprivileged pools, unsafe handler mappings, inherited configuration surprises, and exposed diagnostics can disclose data or execute unintended content.

> [!info] Agent scope
> Security of: Sites and bindings; application pools; handlers and modules; request filtering; authentication; web.config inheritance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Overprivileged pools, unsafe handler mappings, inherited configuration surprises, and exposed diagnostics can disclose data or execute unintended content.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach defensive IIS 10 review at expert Windows/web depth. Trace site bindings,
application boundaries, pools, anonymous/authenticated/impersonated identities,
NTFS ACLs, module/handler selection, filtering and effective configuration. Explain
why No Managed Code is not a no-execution guarantee, why upload folders need a
static-only policy, and how inherited or locked configuration changes diagnosis.
Build an independent disposable-VM lab with exact files/admin setup, a genuine
pool-process ACL read check, harmless static media, a restrictive baseline and
small repair. Include positive controls, substatus/log interpretation and cleanup.
Distinguish filtering from object authorization and TLS from identity. Cite official
Microsoft sources and version requirements. No execution payloads, bypasses, real
credentials, external targets or changes to existing production IIS objects.
```

## Cheatsheet

### Boundary Review

| Surface | Failure mechanism | Defensive check |
|---|---|---|
| Pool identity | Shared/privileged account reads unrelated data | Separate virtual accounts; targeted NTFS grants; real process read check |
| Anonymous identity | IUSR used while reviewing only pool ACLs | Inspect effective anonymous userName and impersonation policy |
| Media files | Inherited execution handler or writable config | Static-only handler collection; separate non-writable policy/config; no script access |
| Filtering | Unbounded body/path/verb surface | Exact required verbs/extensions, body/URL/query limits, positive controls |
| Inheritance | Parent grants/handlers silently retained | Inspect effective application/path config and collection merging |
| Diagnostics | Detailed errors or traces disclose internals | Remote custom errors; restrict/expire traces; redact secrets |

No Managed Code only controls .NET Framework CLR loading. Classic ASP, FastCGI and native modules can still execute. Disabling one script extension is not a general static-content boundary. Use dedicated content storage, immutable handler policy, and an account that cannot edit configuration. The lab combines `handlers accessPolicy="Read"`, a cleared collection and a StaticFileModule mapping; application-level upload validation and safe download naming remain separate.

### Identity and Configuration

ApplicationPoolIdentity maps to `IIS AppPool\PoolName`. An empty anonymous-authentication username selects that identity; named anonymous users and impersonation may change the filesystem token. Read access granted to `Users` or `IIS_IUSRS` can undermine per-pool separation. Evaluate group membership and inherited ACLs, not just explicit entries. Keep private data outside document roots as well as ACL-protected. Configuration ACLs should prevent a worker from rewriting its own access policy.

Authentication, URL authorization and NTFS checks do not replace application object/tenant authorization. Windows authentication adds SPN/Kerberos/delegation considerations; avoid enabling broad delegation to solve a second-hop access failure. HTTPS protects transport but does not choose which records an authenticated user owns.

`applicationHost.config`, location tags and web.config hierarchy determine effective settings. Locked sections fail with `500.19` rather than accepting local overrides. Delegate narrowly; do not unlock sections globally just to make a sample run. Back up intended configuration and compare only the named site/app before deployment. `appcmd list config` is diagnostic output, not proof of process-level access.

### Filtering and Evidence

Request Filtering rejects inputs before application logic: `404.6` verb, `404.7` extension, `404.8` hidden segment, `404.11` double escaping, `404.14` URL length, `404.15` query length; content too large is `413.1`. Record `sc-status`, `sc-substatus`, `sc-win32-status` in W3C logs. A browser's generic 404 cannot distinguish these causes. `allowDoubleEscaping` defaults false; enabling it changes normalization policy and needs an application-specific reason.

`maxAllowedContentLength` is bytes, not a complete time/concurrency budget. Application parsers, proxy limits and hosting-module limits also matter. `removeServerHeader` is version-sensitive (IIS 10 on Windows 10/Server version 1709+), not a security substitute. Detailed errors/FREB should be temporary and access-controlled. Alert on unexpected configuration changes, denied private-file reads and repeated filtering denials, but retain benign positive checks so an outage is not mistaken for protection.

## Detection and Defense

Separate identities, constrain handlers and request filtering, protect configuration files, and review inherited policy. Monitor IIS logs, failed-request tracing in controlled diagnostics, and configuration changes.

## Labs

### Independent Pool ACL and Static Media Lab

**Requirements:** disposable Windows 11 Pro/Enterprise VM with IIS 10, snapshot, administrator access, 64-bit Windows PowerShell 5.1 and `curl.exe`. All data is synthetic. **VM, ACL and handler behavior unverified.** This is a genuine Classic ASP filesystem read check; no malicious script or upload endpoint is used.

In the VM's elevated terminal, enable the prerequisites and reboot if requested:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-CommonHttpFeatures,IIS-StaticContent,IIS-DefaultDocument,IIS-HttpErrors,IIS-HttpLogging,IIS-RequestFiltering,IIS-ManagementConsole,IIS-ManagementScriptingTools,IIS-ASP -All
```

Create the following files in a temporary source directory.

### File: site/marker.txt

```text
PUBLIC-MARKER
```

### File: private/marker.txt

```text
PRIVATE-MARKER
```

### File: site/probe.asp

```asp
<%@ Language="VBScript" %>
<%
Response.ContentType = "text/plain"
Response.AddHeader "Cache-Control", "no-store"
Dim filesystem, stream, readError
Set filesystem = Server.CreateObject("Scripting.FileSystemObject")
On Error Resume Next
Set stream = filesystem.OpenTextFile("C:\W2IisSecurity\private\marker.txt", 1, False)
readError = Err.Number
Err.Clear
On Error GoTo 0
If readError = 70 Then
		Response.Status = "403 Forbidden"
		Response.Write "ACL-DENIED"
ElseIf readError <> 0 Then
		Response.Status = "500 Internal Server Error"
		Response.Write "UNEXPECTED-FIXTURE-ERROR"
Else
		stream.Close
		Response.Status = "500 Internal Server Error"
		Response.Write "UNEXPECTED-READ-ACCESS"
End If
%>
```

### File: site/web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
	<system.webServer>
		<security>
			<requestFiltering>
				<requestLimits maxAllowedContentLength="1024" />
				<fileExtensions allowUnlisted="false">
					<clear />
					<add fileExtension=".asp" allowed="true" />
					<add fileExtension=".txt" allowed="false" />
				</fileExtensions>
				<verbs allowUnlisted="false">
					<clear />
					<add verb="GET" allowed="true" />
					<add verb="HEAD" allowed="true" />
				</verbs>
			</requestFiltering>
		</security>
		<httpErrors errorMode="DetailedLocalOnly" existingResponse="PassThrough" />
	</system.webServer>
</configuration>
```

### File: site/media/marker.asp

```text
DATA-ONLY-MARKER
```

### File: site/media/web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
	<system.webServer>
		<handlers accessPolicy="Read">
			<clear />
			<add name="LabStaticOnly" path="*" verb="GET,HEAD" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
		</handlers>
		<staticContent>
			<remove fileExtension=".asp" />
			<mimeMap fileExtension=".asp" mimeType="text/plain" />
		</staticContent>
	</system.webServer>
</configuration>
```

### File: setup.ps1

```powershell
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration
$root = 'C:\W2IisSecurity'
$name = 'W2IisBoundary'
if ((Test-Path $root) -or (Test-Path "IIS:\Sites\$name") -or (Test-Path "IIS:\AppPools\$name")) {
		throw 'Lab destination or IIS object already exists'
}
New-Item -ItemType Directory $root | Out-Null
Copy-Item "$PSScriptRoot\site", "$PSScriptRoot\private" $root -Recurse
New-WebAppPool -Name $name | Out-Null
Set-ItemProperty "IIS:\AppPools\$name" -Name managedRuntimeVersion -Value ''
Set-ItemProperty "IIS:\AppPools\$name" -Name processModel.identityType -Value 4
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
if ($LASTEXITCODE) { throw 'Root ACL setup failed' }
& icacls.exe "$root\site" /grant:r 'IIS AppPool\W2IisBoundary:(OI)(CI)(RX)'
if ($LASTEXITCODE) { throw 'Site ACL setup failed' }
& icacls.exe "$root\private" /grant:r 'IIS AppPool\W2IisBoundary:(RX)'
if ($LASTEXITCODE) { throw 'Private directory ACL setup failed' }
New-Website -Name $name -IPAddress 127.0.0.1 -Port 18086 -HostHeader lab.test -PhysicalPath "$root\site" -ApplicationPool $name | Out-Null
$filter = 'system.webServer/security/authentication/anonymousAuthentication'
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $name -Filter $filter -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $name -Filter $filter -Name userName -Value ''
```

The private directory grants listing/traversal to the pool, **without inheritance**; its marker file remains readable only by SYSTEM/Administrators. The site grants read/execute, not write. The worker cannot alter either web.config. Run `powershell.exe -NoProfile -File .\setup.ps1` in an already elevated VM terminal following its script policy.

**Objective:** repair public text access while preserving process-level private-file denial and static media handling. Baseline: public `/marker.txt` is incorrectly denied with `404.7`; `/probe.asp` returns application-generated `403 ACL-DENIED`; `/media/marker.asp` returns `200 DATA-ONLY-MARKER`. **Hint:** only the `.txt` extension entry is intentionally over-restrictive.

### Solution and Acceptance

Change `.txt` to `allowed="true"` in `C:\W2IisSecurity\site\web.config`; leave pool identity, ACLs, verb limits and media handlers unchanged. Run the same matrix before/after:

```powershell
$base = 'http://127.0.0.1:18086'
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/probe.asp"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/media/marker.asp"
curl.exe --noproxy "*" -i -X POST -H "Host: lab.test" "$base/marker.txt"
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
& $appcmd list config 'W2IisBoundary/media' /section:system.webServer/handlers
& $appcmd list config 'W2IisBoundary/' /section:system.webServer/security/authentication/anonymousAuthentication
& icacls.exe C:\W2IisSecurity\private\marker.txt
```

Expected after repair: public `200`; probe still exactly `403 ACL-DENIED`; media `200` with `text/plain` and unchanged marker text; POST denied as `404.6` in W3C logs. A generic 403 without the probe marker is not evidence the filesystem check ran. Effective media handlers must contain only `LabStaticOnly`; there is no script execution mapping there. The media marker deliberately contains no executable syntax, so the handler inspection is essential alongside its response.

Troubleshooting: `500.19` means configuration/locking/duplicate collection trouble; inspect locally rather than globally unlocking. Probe `UNEXPECTED-FIXTURE-ERROR` is a failed lab setup, not an accepted denial; verify the exact file path and local ASP diagnostics. `UNEXPECTED-READ-ACCESS` means the intended identity/ACL boundary failed; stop and inspect inherited grants and impersonation. Do not copy ASP source into an accidentally static application directory. Restore the printed `.txt` entry to reproduce baseline.

Cleanup only the named lab objects in the elevated VM session:

```powershell
Import-Module WebAdministration
Remove-Website -Name W2IisBoundary
Remove-WebAppPool -Name W2IisBoundary
Remove-Item C:\W2IisSecurity -Recurse -Force
```

Restore the VM snapshot for feature cleanup. The lab does not validate TLS, Windows authentication/delegation, remote logging, upload validation or application object authorization; those require separate deployment-specific tests.

- [ ] Local IIS exercise: Host a local static site and a toy app in separate pools. Inspect effective authentication, handler mappings, and filesystem rights; test missing and denied resources.
- [ ] Boundary check: Place a harmless marker in a directory inaccessible to the pool identity and confirm the app cannot read it. Verify uploaded text is never routed to an executable handler.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[IIS]]

## References

- [Application pool identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [Request Filtering configuration](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/)
- [Handler mappings](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/)
- [Anonymous authentication](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/anonymousauthentication/)
