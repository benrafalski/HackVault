---
title: "WMI"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[WMI Security]]"
updated: 2026-11-03
---
# WMI

> [!abstract] TL;DR
> Separate read queries from action methods; record namespace, class, provider, caller identity, and transport. Use CIM cmdlets for supported automation.

> [!info] Agent scope
> Namespaces; classes; providers; queries; remote access; permissions; event subscriptions; telemetry.

## Prerequisites

- Windows 10/11 or Server 2016+, Windows PowerShell 5.1 with built-in CimCmdlets, standard user. Understand objects, tokens, namespaces and process IDs.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows Management Instrumentation and CIM at provider/API depth.
Assume Windows processes, tokens, ACLs, PowerShell objects and COM basics.
Explain namespace/class/instance/provider roles, repository metadata versus
dynamic data, keys and object paths, qualifiers, associations and WQL limits.
Trace local Get-CimInstance and native IWbemLocator/IWbemServices queries;
compare local COM, remote DCOM and CIM/WS-Man transport and authentication.
Separate property retrieval from state-changing methods, namespace rights from
provider checks, and HRESULT transport failure from method ReturnValue.
Explain intrinsic WITHIN polling versus extrinsic events, temporary observer
lifetime and permanent filter/consumer/binding graphs without registering any.
Provide a complete read-only local query lab for the caller's own process,
class metadata and a bounded invalid-class case. Use offline subscription
inventory for event reasoning; no consumers or autostart objects are created.
Cover null fields, PID reuse, provider architecture, query cost, access denial,
telemetry gaps and WMIC deprecation. Use primary sources, exact commands and
answered questions. No exploitation, privilege escalation, credential access,
bypass/evasion, confidential data, note edits or fabricated execution claims.
```

## Cheatsheet

### Data and Execution Model

WMI implements Windows management infrastructure around CIM classes. A namespace, such as `root\cimv2`, scopes classes and security. A class schema declares properties, keys, qualifiers, methods and associations; an instance supplies values. Repository-backed metadata and dynamic provider results are different: `Win32_Process` instances are supplied from live process state, not a durable process-history table. Provider hosting/isolation and bitness influence availability and failure behavior.

An object path such as `Win32_Process.Handle="1234"` identifies an instance by class keys in a namespace/server context. Its key is a string even when the value looks numeric. A PID can be reused; retain creation time and collection timestamp for identity-sensitive correlation. Null means missing/unavailable/not applicable according to the provider, not necessarily zero or permission denied.

```powershell
Get-CimClass -Namespace root/cimv2 -ClassName Win32_Process
Get-CimInstance -Namespace root/cimv2 -Query "SELECT ProcessId,Name,CreationDate FROM Win32_Process WHERE ProcessId = $PID"
Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber
```

WQL supports a subset of SQL-like selection and association/event queries, not general joins or SQL DML. `ASSOCIATORS OF {object-path}` and `REFERENCES OF {object-path}` traverse modeled relationships. Prefer explicit projections and provider-side filters; client-side `Where-Object` first retrieves more instances. Do not concatenate untrusted class/property/operator fragments. Whitelist schema identifiers and validate typed literals; WQL is not a parameterized SQL connection.

### APIs, Transport, and Rights

| Surface | Contract |
|---|---|
| `IWbemLocator::ConnectServer` | Connects to namespace; native COM callers initialize COM/security first. |
| `IWbemServices::ExecQuery` | Returns an enumerator; semisynchronous forward-only queries can reduce memory and blocking. Check `Next` timeout/status and release COM objects. |
| `Get-CimInstance` without ComputerName/session | Local Windows access uses local COM; no remote WinRM listener is required. |
| Remote CIM session | Normally WS-Man for remote CIM; explicitly chosen DCOM sessions have different firewall/authentication behavior. Do not assume one transport's policy covers another. |
| Method invocation | Can change state. An API success may still return a provider-defined nonzero `ReturnValue`; read that method's contract. This lab invokes none. |
| Namespace descriptor | Enable account, execute methods, write classes/instances, provider write, remote enable and descriptor rights are independent. Providers can perform further checks. |

Remote access may depend on namespace Remote Enable, DCOM or WinRM access, network/firewall policy, UAC remote restrictions and provider-specific privileges. There is no universal "WMI admin" switch. Async callbacks can add reverse-path authentication/firewall requirements. Use least privilege and avoid changing transport/security settings merely to collect a query.

### Event Subscriptions and Observation

Intrinsic events such as `__InstanceCreationEvent` monitor instance changes; `WITHIN 2` requests polling at a two-second interval, with cost and short-lived-instance miss risk. Extrinsic events are produced by an event provider directly. This WQL is an **offline illustration only**, not executed or registered:

```sql
SELECT * FROM __InstanceCreationEvent WITHIN 2
WHERE TargetInstance ISA 'Win32_Process'
```

A temporary client observation ends when its subscription/client lifetime ends and should be explicitly canceled by that client. Permanent subscriptions use stored `__EventFilter`, consumer instance, and `__FilterToConsumerBinding` objects, often in `root\subscription`; the filter's `EventNamespace` can differ. Inventory all three and their identities/security. A dangling object or binding is not proof of execution, and a class name alone is not provenance. No permanent subscription is created here.

WMI-Activity/Operational provides diagnostic events but not a complete audit of every query or method. Client PID, namespace, operation, provider and result need time/host correlation. WMIC is deprecated/optional/removed depending on Windows release; use supported CIM APIs. PowerShell 7 does not include legacy `Get-WmiObject`; this note targets Windows PowerShell 5.1 for reproducibility.

## Gotchas

- Querying a dynamic provider can incur substantial work; "read" is not the same as zero cost. Choose known benign classes and minimal fields.
- `WBEM_E_INVALID_NAMESPACE` (`0x8004100E`), `WBEM_E_INVALID_CLASS` (`0x80041010`), and `WBEM_E_ACCESS_DENIED` (`0x80041003`) describe different failures. RPC/transport errors are another layer.
- Provider class/method availability varies with Windows edition, optional components and architecture; do not repair the WMI repository as a routine response to a failed query.

## Labs

### Environment and Complete Files

One script in a new scratch directory; Windows PowerShell 5.1 and functioning local WMI/CIM provider are prerequisites. Standard user, no build or modules to install. It queries only OS version and its own process, inspects schema, and requests a deliberately nonexistent class. No subscription or method invocation occurs.

### File: inspect-wmi.ps1

```powershell
$ErrorActionPreference = 'Stop'
$currentId = [int]$PID
$schema = Get-CimClass -Namespace root/cimv2 -ClassName Win32_Process -OperationTimeoutSec 10
$os = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem `
	-Property Caption,Version,BuildNumber -OperationTimeoutSec 10
$rows = @(Get-CimInstance -Namespace root/cimv2 -Query `
	"SELECT ProcessId,Name,CreationDate FROM Win32_Process WHERE ProcessId = $currentId" `
	-OperationTimeoutSec 10)
if ($rows.Count -ne 1 -or $rows[0].ProcessId -ne $currentId) { throw 'Own-process query mismatch' }
$keys = @($schema.CimClassProperties | Where-Object {
	$_.Qualifiers['Key'] -and $_.Qualifiers['Key'].Value
} | Select-Object -ExpandProperty Name)
if ($keys -notcontains 'Handle') { throw 'Unexpected Win32_Process key metadata' }
$invalidObserved = $false
try {
	Get-CimClass -Namespace root/cimv2 -ClassName HV_NoSuchClass_20261103 `
		-OperationTimeoutSec 10 | Out-Null
} catch [Microsoft.Management.Infrastructure.CimException] {
	if ($_.Exception.StatusCode.ToString() -ne 'InvalidClass') { throw }
	$invalidObserved = $true
}
if (-not $invalidObserved) { throw 'Expected InvalidClass was not observed' }
$os | Select-Object Caption,Version,BuildNumber
$rows | Select-Object ProcessId,Name,CreationDate
'Keys: ' + ($keys -join ', ')
'PASS: own process, key metadata and InvalidClass; no subscriptions created'
```

### Objectives, Steps, and Hints

Run `powershell.exe -NoProfile -File .\inspect-wmi.ps1` under existing script policy. Predict why `ProcessId` is used in the filter but `Handle` is the schema key. Compare the returned PID with the child PowerShell process running the script, not with a different parent shell. Hint: the dynamic instance and its schema describe different things.

### Solution and Expected Results

Expected one OS record, one own-process record, `Keys: Handle`, and PASS. Names/version/build/timestamps vary. The invalid-class case must be explicitly classified as `InvalidClass`, not accepted merely because any error occurred. No process command line, credential data or unrelated process inventory is collected.

### Verification, Troubleshooting, and Cleanup

Access denial, provider failure or timeout fails the lab; record the error without elevating, reconfiguring WMI/WinRM or rebuilding the repository. No CIM session object or event subscriber is created, so no subscription cleanup is necessary. Delete only the scratch script. Source reviewed, not run; parent must validate Windows PowerShell 5.1, CimException classification, schema key metadata and local query behavior. Remote access and event delivery are explained but unexecuted.

- [ ] Local WMI exercise: Query the caller's own process and inspect actual provider class metadata.
- [ ] Boundary check: Distinguish invalid class, access/transport errors, read queries and method/subscription operations.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[WMI Security]]

## References

- [WMI architecture](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture)
- [WQL](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
- [Securing WMI namespaces](https://learn.microsoft.com/en-us/windows/win32/wmisdk/securing-wmi-namespaces)
- [Receiving WMI events](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event)
- [Get-CimInstance](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance)
