---
title: "Services and SCM"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Services and SCM Security]]"
updated: 2026-11-03
---
# Services and SCM

> [!abstract] TL;DR
> SCM configuration, service status, process lifetime, and service identity are different objects of observation. Query each with the minimum access mask; never infer readiness from a PID alone.

> [!info] Agent scope
> Service lifecycle; SCM APIs; service identities; configuration permissions; dependencies; recovery; service isolation.

## Prerequisites

- Windows 10/11 or Server 2016+; standard-user local session. Native lab: VS 2022 x64 Native Tools prompt with MSVC and Windows SDK already installed.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows Services and the Service Control Manager at native API depth.
Assume C++, Unicode Win32, handles, tokens, DACLs, and process basics. Target
Windows 10/11 and Server 2016+, distinguishing older service-host behavior.
Trace OpenSCManager/OpenService, configuration queries, SCM dispatch,
ServiceMain, HandlerEx, SetServiceStatus, worker shutdown, and handle closure.
Explain pending states, checkpoints, wait hints, controls accepted, dependencies,
delayed/trigger start, recovery semantics, shared hosts, and deletion lifetime.
Compare LocalSystem, LocalService, NetworkService, virtual accounts, service
SIDs, restricted SIDs, privileges, and session-0 isolation. Separate config ACL,
binary/config file ACL, IPC authorization, and application health.
Use a complete read-only query client and offline configuration/status examples.
Explain buffer resizing, races, missing services, access denial, and PID reuse.
Give predictions, counterexamples, checks, and worked answers using primary
Microsoft sources. Do not install/register/start/stop/reconfigure services,
teach persistence or escalation, use confidential data, or edit notes. Debugger
commands are out of scope. Identify unexecuted platform assumptions explicitly.
```

## Cheatsheet

### Lifecycle and State

SCM owns the service database; a service executable connects its dispatcher with `StartServiceCtrlDispatcherW`. SCM invokes `ServiceMain`; the service registers a `HandlerEx`, reports status, and runs its workers. These are service-process contracts, not functions a normal console program can substitute for registration.

| State or field | Contract and diagnostic consequence |
|---|---|
| `STOPPED -> START_PENDING -> RUNNING` | Initialization precedes readiness. A process existing does not establish `RUNNING` or application health. |
| `STOP_PENDING -> STOPPED` | Stop accepting work, drain/cancel workers, then report stopped. Do not report stopped while workers still own resources. |
| `dwControlsAccepted` | Advertise implemented controls only; normally zero during initialization. Control handlers must return promptly and delegate long work. |
| `dwCheckPoint`, `dwWaitHint` | Pending-operation progress and estimated duration in milliseconds; advancing fake checkpoints does not make a hung initializer healthy. Poll with a deadline, not a busy loop. |
| `dwWin32ExitCode` | For `ERROR_SERVICE_SPECIFIC_ERROR` inspect `dwServiceSpecificExitCode`; it is not necessarily a process exit code. |
| `dwProcessId` | Snapshot, valid only in documented states; zero/stale PID and shared-host services complicate process correlation. |

Dependencies are a startup ordering graph, not a transaction or continuous health guarantee. `lpDependencies` is MULTI_SZ; a `+` prefix denotes a load-order group. Demand start can still be activated by a service trigger. Delayed automatic start is separate from the base start type. Recovery actions and the non-crash-failure flag decide which failures cause recovery; graceful stopping is not equivalent to crashing. Review recovery commands as executable configuration, without executing them.

### API and Access Reference

| Operation | Requested access / lifetime |
|---|---|
| `OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)` | Local SCM connection only; does not grant service rights. |
| `OpenServiceW(...,SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)` | Service object's DACL controls access; use internal name, not display name. |
| `QueryServiceConfigW` | Caller buffer contains pointers into that buffer. Read before releasing it; retry boundedly if configuration changes size. |
| `QueryServiceConfig2W` | Additional levels include failure actions, delayed start, service SID type, required privileges, and triggers. Buffer shapes differ by level. |
| `QueryServiceStatusEx(...,SC_STATUS_PROCESS_INFO,...)` | Returns `SERVICE_STATUS_PROCESS`; status can change immediately afterward. |
| `QueryServiceObjectSecurity` | `READ_CONTROL` for DACL/owner; SACL access needs separate rights/privilege. |
| `CloseServiceHandle` | Required for `SC_HANDLE`; not `CloseHandle`. Deletion is deferred while service runs or handles remain. |

`LocalSystem` is highly privileged locally and normally uses machine credentials remotely. `LocalService` has limited local rights and anonymous network identity; `NetworkService` has limited local rights and machine network identity. A service SID (`NT SERVICE\Name`) can isolate resources from other services sharing an account. Restricted service SIDs add a second access-check constraint; they are not merely a renamed account. Virtual accounts and gMSAs solve different identity/password-management problems. Do not assume service privileges equal an interactive administrator's token.

Services run in session 0 on Vista+; UI belongs in a separate authenticated user application. Shared-process services share failure and process-level resource boundaries. Modern Windows can split service hosts according to configuration and memory thresholds; never hardcode one PID per service.

Read-only inspection, from PowerShell (`sc.exe`, not the historical `sc` alias):

```powershell
sc.exe queryex EventLog
sc.exe qc EventLog
sc.exe qfailure EventLog
sc.exe qfailureflag EventLog
sc.exe qsidtype EventLog
sc.exe qprivs EventLog
sc.exe qtriggerinfo EventLog
sc.exe sdshow EventLog
```

## Gotchas

- A quoted executable and its arguments are distinct; quoting an entire command line changes parsing. A formatting finding alone does not establish unauthorized control.
- Enumeration can omit services the caller cannot query. Access denied is missing evidence, not proof of absence.
- Configuration observed now may differ from the configuration used to create the current process. Correlate timestamps, image identity, and service status.

## Labs

### Environment and Complete Files

Read-only local observation. No service is installed, controlled, or changed. In a new, user-owned scratch directory, create the single file below. All Windows libraries used are SDK libraries; no downloads are required.

### File: inspect.cpp

```cpp
#include <windows.h>
#include <winsvc.h>
#include <cstdio>
#include <cwchar>
#include <vector>

struct ServiceHandle {
	SC_HANDLE value;
	~ServiceHandle() { if (value) CloseServiceHandle(value); }
};

int wmain(int argc, wchar_t** argv) {
	const wchar_t* name = argc == 2 ? argv[1] : L"EventLog";
	ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
	if (!manager.value) { std::wprintf(L"SCM error=%lu\n", GetLastError()); return 1; }
	ServiceHandle service{OpenServiceW(manager.value, name,
		SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)};
	if (!service.value) { std::wprintf(L"Open error=%lu\n", GetLastError()); return 2; }
	SERVICE_STATUS_PROCESS status{};
	DWORD needed = 0;
	if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
		reinterpret_cast<BYTE*>(&status), sizeof(status), &needed)) {
		std::wprintf(L"Status error=%lu\n", GetLastError()); return 3;
	}
	std::wprintf(L"state=%lu pid=%lu checkpoint=%lu wait_ms=%lu\n",
		status.dwCurrentState, status.dwProcessId,
		status.dwCheckPoint, status.dwWaitHint);
	std::vector<BYTE> buffer;
	for (unsigned attempt = 0; attempt < 4; ++attempt) {
		auto config = buffer.empty() ? nullptr :
			reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
		if (QueryServiceConfigW(service.value, config,
			static_cast<DWORD>(buffer.size()), &needed)) {
			std::wprintf(L"account=%ls\nimage=%ls\nstart=%lu\n",
				config->lpServiceStartName, config->lpBinaryPathName,
				config->dwStartType);
			return 0;
		}
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 8192) {
			std::wprintf(L"Config error=%lu needed=%lu\n", error, needed); return 4;
		}
		buffer.resize(needed);
	}
	std::wprintf(L"Configuration changed repeatedly; retry later.\n");
	return 5;
}
```

### Objectives and Steps

In the x64 Native Tools command prompt, in that scratch directory:

```bat
cl /nologo /W4 /EHsc /std:c++17 inspect.cpp /link Advapi32.lib
inspect.exe EventLog
sc.exe queryex EventLog
sc.exe qc EventLog
inspect.exe HackVaultNoSuchService_20261103
```

Compare the API state/PID and account/image/start type with the CLI output. Explain why two successive snapshots can differ. The deliberately nonexistent name tests error reporting without requesting write access.

### Hints

`SERVICE_RUNNING` is 4; start types 2/3/4 mean automatic/demand/disabled. The account name describes service execution, not your caller token. Error 1060 means the internal service name does not exist.

### Solution and Expected Results

On an ordinary Windows installation, `EventLog` is running and both views describe the same service. Exact account, image, PID, and host layout are machine-dependent. A successful client exits 0; the absent-name case exits 2 and prints `Open error=1060`. If the name unexpectedly exists, choose another clearly unique nonexistent name. An access-denied result (5) is a valid boundary observation, but does not satisfy the successful-query acceptance check.

### Verification, Troubleshooting, and Cleanup

Acceptance: successful read agrees on service identity; nonexistent-name error is explicit; the program contains no mutation/control API. `cl` unavailable means the preinstalled toolchain requirement is unmet; do not install as part of this exercise. Link errors mentioning SCM APIs mean `Advapi32.lib` was omitted. Do not change service ACLs to force success. Delete only `inspect.cpp`, `inspect.obj`, and `inspect.exe` in your scratch directory after closing them.

Author validation: documentation and source review only; compilation and Windows observations are unexecuted. Parent validation must compile and run both cases on the stated platform.

- [ ] Local Services and SCM exercise: Complete the read-only SCM client and correlate status/configuration evidence.
- [ ] Boundary check: Explain separately the caller's query rights, service execution identity, and file/IPC authorization.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Local Privilege Escalation]]
- [[Windows Persistence]]
- [[Services and SCM Security]]

## References

- [Services overview](https://learn.microsoft.com/en-us/windows/win32/services/services)
- [Service state transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions)
- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
