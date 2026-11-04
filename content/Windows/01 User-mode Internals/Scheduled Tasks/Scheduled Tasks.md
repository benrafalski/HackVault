---
title: "Scheduled Tasks"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Scheduled Tasks Security]]"
updated: 2026-11-03
---
# Scheduled Tasks

> [!abstract] TL;DR
> Review principal, run level, action path/arguments, working directory, ACLs, and trigger. Keep task evidence separate from actual process-execution evidence.

> [!info] Agent scope
> Task definitions; triggers; principals; actions; registration; permissions; execution context; operational logs.

## Prerequisites

- Windows 10/11 or Server 2016+, Windows PowerShell 5.1, standard user. The lab uses the installed Task Scheduler COM API but never registers a task.
- [[Windows Lab Setup]]

## Learn

```text
Teach Task Scheduler 2.0 internals and engineering on Windows 10/11 and Server.
Assume XML namespaces, COM basics, tokens, file permissions, and process exit
codes. Trace a task definition through schema validation, registration as a
conceptual security boundary, trigger evaluation, conditions, principal/logon
selection, action execution, instance policy, completion, and retained history.
Distinguish ITaskDefinition from IRegisteredTask and IRunningTask. Compare
InteractiveToken, Password, S4U, service-account identities, LeastPrivilege and
HighestAvailable, including network/EFS limits and UAC implications.
Explain time zones/DST, missed runs, repetition limits, event subscriptions,
working directories, quoting, environment expansion, action order, retries,
execution limits, and IgnoreNew/Queue/Parallel/StopExisting tradeoffs.
Give a complete in-memory COM XML round-trip, disabled offline XML fixtures,
and read-only evidence examples. Do not register/run/change tasks or provide
persistence procedures. Separate scheduler HRESULTs from action exit codes and
explain why logs do not prove application success. Use primary documentation,
worked failure cases, verification criteria and difficult answered questions.
Do not edit notes; do not claim examples were executed without evidence.
```

## Cheatsheet

### Definition to Execution

`ITaskService::Connect` opens a scheduler connection; `NewTask(0)` creates a memory-only `ITaskDefinition`. The definition contains `RegistrationInfo`, `Triggers`, `Principals`, `Settings`, and `Actions`. Registration, which is deliberately not performed here, checks folder/task rights and principal/logon requirements and produces a persistent `IRegisteredTask`. A running instance is represented separately by `IRunningTask`; editing a definition is not evidence that an existing instance changed.

Task Scheduler 2.0 arrived with Vista/Server 2008. Legacy `.job`/1.0 APIs have different capabilities. XML schema revisions depend on the target OS: schema acceptance and runtime support are separate. Email and message-box actions are deprecated on Windows 8/Server 2012 onward; use `Exec` for current application designs. COM handler actions load a registered handler and therefore depend on COM activation security too.

| Field | Mechanism and constraint |
|---|---|
| `Principal.UserId`, `LogonType` | The runtime identity, not merely the author string. InteractiveToken requires a matching logged-on session. Password logon and S4U have different credential/network semantics; S4U does not provide network or EFS access. |
| `RunLevel` | `HighestAvailable` uses available authority; it does not manufacture administrator membership for a standard user. Registration rights still matter. |
| `Actions/@Context` | Refers to the principal's `id`; a string in a different namespace is not the same element. |
| `Exec/Command` | Executable path, separate from `Arguments` and `WorkingDirectory`. No shell metacharacter interpretation unless a shell is explicitly the executable. |
| Triggers | Time/calendar/event/logon/boot/idle/session triggers select opportunities, not a guarantee of success. Disabled triggers and disabled task are distinct. |
| Conditions | Power, idle, network, and availability constraints can prevent or defer a triggered run. `StartWhenAvailable` changes missed-run behavior, not all failure recovery. |
| `MultipleInstancesPolicy` | `IgnoreNew` drops overlap; `Queue` serializes; `Parallel` needs concurrency-safe work; `StopExisting` risks partial work. |
| `ExecutionTimeLimit` | ISO 8601 duration, e.g. `PT5M`; `PT0S` means no limit. Forced termination can skip application cleanup. |

Use explicit working directories; neither the author's current directory nor mapped drive letters are portable to another logon. Environment values may be cached by the task engine. Use absolute local paths for reviewable dependencies; an absolute path alone says nothing about write permissions. A date/time with an offset expresses different scheduling intent from an offset-free local time; inspect DST behavior on the actual OS/time zone instead of assuming exactly one run per wall-clock day.

### Read-Only Evidence

```powershell
Get-ScheduledTask | Select-Object TaskPath,TaskName,State
Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' |
	Get-ScheduledTaskInfo | Select-Object LastRunTime,LastTaskResult,NextRunTime
Get-WinEvent -FilterHashtable @{
	LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=100,102,200,201
} -MaxEvents 20 | Select-Object TimeCreated,Id,RecordId
```

These are optional authorized observations, not lab prerequisites. Built-in task availability, permissions, and channel enablement vary. `0x41301` means running; `0x41303` means not yet run. A zero action exit code can still accompany incorrect application output. Correlate task path and instance/activity identifiers across start/action/completion records; do not match by display name alone.

## Gotchas

- Schema-valid XML is not authorization, registration success, or proof that a referenced executable exists.
- `RegistrationInfo.Author` is descriptive metadata, not authenticated creator identity.
- Task DACL, folder permissions, and action-file ACLs are different. Running a task and modifying it require different authority.

## Labs

### Environment and Complete Files

Only Windows PowerShell 5.1 and the local scheduler COM service are needed; no compiler, external modules, elevation, or task installation. Put this single file in an empty scratch directory. It creates a disabled, triggerless definition in memory, round-trips its XML, and releases COM references. It never requests a task folder or registration method.

### File: inspect-task.ps1

```powershell
$ErrorActionPreference = 'Stop'
$service = $definition = $copy = $null
try {
	$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
	$command = [System.Security.SecurityElement]::Escape("$env:SystemRoot\System32\whoami.exe")
	$working = [System.Security.SecurityElement]::Escape("$env:SystemRoot\System32")
	$xml = @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Offline inspection only</Description></RegistrationInfo>
  <Triggers />
  <Principals><Principal id="Reader">
	<UserId>$sid</UserId><LogonType>InteractiveToken</LogonType>
	<RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
	<AllowStartOnDemand>false</AllowStartOnDemand><Enabled>false</Enabled>
	<ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Reader"><Exec>
	<Command>$command</Command><Arguments>/user</Arguments>
	<WorkingDirectory>$working</WorkingDirectory>
  </Exec></Actions>
</Task>
"@
	$service = New-Object -ComObject 'Schedule.Service'
	$service.Connect()
	$definition = $service.NewTask(0)
	$definition.XmlText = $xml
	$copy = $service.NewTask(0)
	$copy.XmlText = $definition.XmlText
	[xml]$result = $copy.XmlText
	$ns = New-Object System.Xml.XmlNamespaceManager($result.NameTable)
	$ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
	function Value([string]$path) {
		$node = $result.SelectSingleNode($path, $ns)
		if ($null -eq $node) { throw "Missing XML node: $path" }
		$node.InnerText
	}
	if ((Value '/t:Task/t:Settings/t:Enabled') -ne 'false') { throw 'Enabled unexpectedly' }
	if ((Value '/t:Task/t:Principals/t:Principal/t:UserId') -ne $sid) { throw 'SID changed' }
	if ($result.SelectNodes('/t:Task/t:Triggers/*', $ns).Count -ne 0) { throw 'Trigger added' }
	if ((Value '/t:Task/t:Actions/t:Exec/t:Command') -ne "$env:SystemRoot\System32\whoami.exe") {
		throw 'Command changed'
	}
	'PASS: disabled definition, no triggers, principal and executable preserved'
} finally {
	foreach ($item in @($copy, $definition, $service)) {
		if ($null -ne $item -and [Runtime.InteropServices.Marshal]::IsComObject($item)) {
			[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)
		}
	}
}
```

### Objectives and Steps

From a normal PowerShell session in that directory, run `powershell.exe -NoProfile -File .\inspect-task.ps1` under your existing script policy. Predict whether `whoami.exe` executes and whether a task appears. Inspect the code for the difference between `NewTask` and registration. Do not change execution policy if organizational policy blocks scripts.

### Hints

Creating an `ITaskDefinition` is not installing it. XML default namespaces require a namespace-aware XPath. Serializer whitespace and optional default fields need not round-trip byte-for-byte; compare semantics.

### Solution and Expected Results

Expected one `PASS` line, no `whoami` output, no new task, and no generated files. All four invariants must hold. The definition has neither triggers nor demand execution enabled, and is never registered. COM may normalize XML; textual equality is not an appropriate test.

### Verification, Troubleshooting, and Cleanup

COM activation/connect errors indicate the Windows scheduler component or local access policy is unavailable; stop rather than changing services. XML errors require checking the printed namespace and element spelling. Delete only the scratch script; there is no task to unregister. Documentation/source review only: the COM round-trip is unexecuted and must be checked by the parent on Windows PowerShell 5.1. No process-execution or scheduling-timing behavior is validated by this lab.

- [ ] Local Scheduled Tasks exercise: Round-trip a disabled in-memory task definition without registration.
- [ ] Boundary check: Distinguish principal, action-file authority, task security, and registration/execution evidence.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Persistence]]
- [[Scheduled Tasks Security]]

## References

- [Task Scheduler overview](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [Task security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
- [Task Scheduler constants](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants)
