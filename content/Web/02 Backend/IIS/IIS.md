---
title: "IIS"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[IIS Security]]"
updated: 2026-11-03
---
# IIS

> [!abstract] TL;DR
> Use explicit bindings and least-privilege pool identities. Keep upload directories nonexecuting and detailed errors restricted to local diagnostics.

> [!info] Agent scope
> Sites and bindings; application pools; handlers and modules; request filtering; authentication; web.config inheritance.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach IIS 10 request processing and configuration at expert depth. Assume HTTP,
TLS, Windows accounts and NTFS. Trace HTTP.sys bindings/request queues, WAS,
application pools/w3wp, native and managed modules, handler selection, request
filtering, authentication, authorization and file/application access. Distinguish
sites, applications, virtual directories and pools; explain pool identity versus
anonymous identity and impersonation. Show applicationHost.config/web.config
inheritance, locks, effective configuration and HTTP substatus diagnosis. Build a
complete isolated Windows lab with a static site and tiny real application in
separate pools, known identities, explicit ACLs and a request matrix. Explain TLS
SNI/certificate bindings and ASP.NET Core hosting separately. Cite Microsoft docs,
state feature/OS prerequisites, and never require production changes or payloads.
```

## Cheatsheet

### Request and Identity Model

HTTP.sys owns kernel HTTP listeners, request queues and some caching. WAS manages pool configuration/process activation; `w3wp.exe` executes the user-mode pipeline. A site is a binding/content boundary, an application is an application/configuration boundary, a virtual directory maps a URL to disk, and an application pool is a worker-process/identity boundary. Several applications can share a pool; different pools still share the OS and can share permissions.

| Decision | Inspect | Important distinction |
|---|---|---|
| Binding | Protocol, IP, port, host name | HTTPS also needs certificate/SSL binding; Host is not user identity |
| Pool | Runtime, pipeline mode, bitness, identity | No Managed Code means no .NET Framework CLR; native handlers can still execute |
| Module | Request events and enabled native/managed modules | Filtering/authentication can stop processing before the handler |
| Handler | Path, verb, resource type, module and access requirements | Extension alone does not determine execution |
| Authentication | Anonymous, Windows, Basic etc. | Authentication is not record ownership or an NTFS grant |
| Filesystem | Effective token and ACL | Anonymous `IUSR` differs from the pool virtual account |

ApplicationPoolIdentity uses the virtual account `IIS AppPool\PoolName`. An empty anonymous-authentication `userName` selects the pool identity; the usual named anonymous account can instead be IUSR. Impersonation and authenticated-file access change which token is checked. Don't grant a whole service group access merely because one pool needs a directory. Grant read/execute for application content and write only to narrowly designated data paths.

### Configuration and Diagnosis

Global configuration lives in applicationHost.config; location tags and site/application/directory web.config files refine inherited sections. Collections support `add`, `remove` and `clear`, subject to locks. A child setting cannot override a locked section: `500.19` is configuration failure, not proof of an ACL denial. Inspect effective settings at the requested application path and inherited handler collections.

```powershell
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
& $appcmd list sites
& $appcmd list apppools
& $appcmd list config 'SiteName/' /section:system.webServer/handlers
& $appcmd list config 'SiteName/' /section:system.webServer/security/requestFiltering
& $appcmd list config 'SiteName/' /section:system.webServer/security/authentication/anonymousAuthentication
```

Replace `SiteName` with the actual site. Protect configuration output; it can contain sensitive settings. IIS W3C fields `sc-status`, `sc-substatus`, `sc-win32-status` distinguish failures hidden behind the browser response. Common examples: `404.6` denied verb, `404.7` denied extension, `404.8` hidden segment, `404.14` URL length, `404.15` query length, `413.1` content length. `401.3` often indicates filesystem ACL authorization. Detailed local errors and Failed Request Tracing help in an isolated lab; traces can contain sensitive headers/data.

### Hosting and Operational Edges

HTTPS requires a matching certificate/private key and binding policy; SNI is available on IIS 8+. Configure the HTTP.sys SSL binding through supported IIS tools and verify the actual served chain/name. A site hostname is not an implicit certificate binding. Do not copy production keys to a lab.

ASP.NET Core uses the ASP.NET Core Module from a compatible hosting bundle; in-process hosting runs in the worker, out-of-process hosting forwards to a separate process. A .NET SDK alone does not install every IIS hosting component. Classic ASP is a different native feature, used only for the small lab below. Pool recycling can interrupt in-memory state and long requests: store durable state externally and implement graceful application shutdown where supported.

## Gotchas

An IIS authentication setting does not automatically enforce application object ownership. Diagnose effective configuration rather than only the nearest web.config file.

## Labs

### Two Sites, Two Pools, Real Handler Selection

**Requirements:** disposable Windows 11 Pro/Enterprise VM with IIS 10, snapshot, administrator access, Windows PowerShell 5.1 (64-bit), and `curl.exe`. Do not run these administration scripts on a workstation hosting real sites. **All Windows/VM behavior is unverified.** The ASP fixture is deliberately tiny; it is not an ASP.NET Core example.

Enable these optional features manually in an elevated Windows PowerShell session inside the VM, then reboot if requested before continuing:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-CommonHttpFeatures,IIS-StaticContent,IIS-DefaultDocument,IIS-HttpErrors,IIS-HttpLogging,IIS-RequestFiltering,IIS-ManagementConsole,IIS-ManagementScriptingTools,IIS-ASP -All
```

Create all files below in a temporary source directory. Use the exact names; setup copies them to a new `C:\W2IisTech` tree and refuses to reuse that tree or the named sites/pools.

### File: site/marker.txt

```text
STATIC-MARKER
```

### File: site/web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
	<system.webServer>
		<handlers accessPolicy="Read">
			<clear />
			<add name="LabStatic" path="*" verb="GET,HEAD" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
		</handlers>
		<security>
			<requestFiltering>
				<requestLimits maxAllowedContentLength="1024" />
				<verbs allowUnlisted="false">
					<clear />
					<add verb="GET" allowed="true" />
					<add verb="HEAD" allowed="true" />
				</verbs>
			</requestFiltering>
		</security>
		<httpErrors errorMode="DetailedLocalOnly" />
	</system.webServer>
</configuration>
```

### File: app/default.asp

```asp
<%@ Language="VBScript" %>
<%
Response.ContentType = "text/plain"
Response.AddHeader "Cache-Control", "no-store"
Response.Write "APP-MARKER"
%>
```

### File: app/web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
	<system.webServer>
		<handlers accessPolicy="Read, Script" />
		<security>
			<requestFiltering>
				<requestLimits maxAllowedContentLength="1024" />
			</requestFiltering>
		</security>
		<httpErrors errorMode="DetailedLocalOnly" />
	</system.webServer>
</configuration>
```

### File: setup.ps1

```powershell
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration
$root = 'C:\W2IisTech'
$names = @('W2IisStatic', 'W2IisApp')
if (Test-Path $root) { throw 'Lab destination already exists' }
foreach ($name in $names) {
		if ((Test-Path "IIS:\Sites\$name") -or (Test-Path "IIS:\AppPools\$name")) {
				throw "IIS object already exists: $name"
		}
}
New-Item -ItemType Directory $root | Out-Null
Copy-Item "$PSScriptRoot\site", "$PSScriptRoot\app" $root -Recurse
foreach ($name in $names) {
		New-WebAppPool -Name $name | Out-Null
		Set-ItemProperty "IIS:\AppPools\$name" -Name managedRuntimeVersion -Value ''
		Set-ItemProperty "IIS:\AppPools\$name" -Name processModel.identityType -Value 4
}
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
if ($LASTEXITCODE) { throw 'Root ACL setup failed' }
& icacls.exe "$root\site" /grant:r 'IIS AppPool\W2IisStatic:(OI)(CI)(RX)'
if ($LASTEXITCODE) { throw 'Static ACL setup failed' }
& icacls.exe "$root\app" /grant:r 'IIS AppPool\W2IisApp:(OI)(CI)(RX)'
if ($LASTEXITCODE) { throw 'App ACL setup failed' }
New-Website -Name W2IisStatic -IPAddress 127.0.0.1 -Port 18084 -HostHeader lab.test -PhysicalPath "$root\site" -ApplicationPool W2IisStatic | Out-Null
New-Website -Name W2IisApp -IPAddress 127.0.0.1 -Port 18085 -HostHeader app.test -PhysicalPath "$root\app" -ApplicationPool W2IisApp | Out-Null
foreach ($name in $names) {
		$filter = 'system.webServer/security/authentication/anonymousAuthentication'
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $name -Filter $filter -Name enabled -Value $true
		Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $name -Filter $filter -Name userName -Value ''
}
```

Run `powershell.exe -NoProfile -File .\setup.ps1` from an already elevated VM terminal. Do not weaken the machine execution policy to run unreviewed content; follow the VM's script policy. The script makes machine-level IIS changes only for the named objects and ACL changes only in its new lab tree.

**Objective:** distinguish executed application output from static data and filtering failures. **Hint:** inspect the handler collection and the anonymous identity, not just the pool name.

```powershell
curl.exe --noproxy "*" -i -H "Host: lab.test" http://127.0.0.1:18084/marker.txt
curl.exe --noproxy "*" -i -H "Host: app.test" http://127.0.0.1:18085/default.asp
curl.exe --noproxy "*" -i -H "Host: lab.test" http://127.0.0.1:18084/missing.txt
curl.exe --noproxy "*" -i -X POST -H "Host: lab.test" http://127.0.0.1:18084/marker.txt
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
& $appcmd list config 'W2IisStatic/' /section:system.webServer/handlers
& $appcmd list config 'W2IisApp/' /section:system.webServer/handlers
& icacls.exe C:\W2IisTech\site
& icacls.exe C:\W2IisTech\app
```

### Solution and Acceptance

Expected: static `200 STATIC-MARKER`; application `200 APP-MARKER` without ASP source; missing file `404`; POST denied with request-filtering substatus `404.6` in IIS logs. Verify distinct pool identities and that each content ACL grants only its intended pool. This checks configuration and positive access, not yet a process-level cross-pool read attempt.

For a harmless baseline/fix exercise, change the static configuration's GET entry to `allowed="false"`: the same marker becomes `404.6`. Restore `true` and repeat for `200`. IIS notices web.config changes; no global `iisreset` is needed. A `500.19` instead means a config/lock/collection issue. `404.3` or `404.17` on ASP suggests missing handler/feature support; never fix it by serving source. A `401.3` requires checking both effective identity and ACLs.

Cleanup in the elevated VM session, after recording observations:

```powershell
Import-Module WebAdministration
Remove-Website -Name W2IisStatic
Remove-Website -Name W2IisApp
Remove-WebAppPool -Name W2IisStatic
Remove-WebAppPool -Name W2IisApp
Remove-Item C:\W2IisTech -Recurse -Force
```

Restore the VM snapshot to remove installed IIS features. Do not disable shared features or delete other sites/pools. If setup failed partway, inspect named objects before removing only those it created.

- [ ] Local IIS exercise: Host a local static site and a toy app in separate pools. Inspect effective authentication, handler mappings, and filesystem rights; test missing and denied resources.
- [ ] Boundary check: Place a harmless marker in a directory inaccessible to the pool identity and confirm the app cannot read it. Verify uploaded text is never routed to an executable handler.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[IIS Security]]

## References

- [IIS architecture](https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/introduction-to-iis-architecture)
- [Application pool identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [Handler mappings](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/)
- [Request Filtering configuration](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/)
- [Anonymous authentication](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/anonymousauthentication/)
