---
title: "System Informer"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# System Informer

> [!abstract] TL;DR
> Record PID plus start time, identity, token, relevant handles/modules, and the exact observation time. Correlate with [[Sysmon]] when historical evidence is needed.

> [!info] Agent scope
> Process and thread inspection; handles; tokens; services; tool permissions; interpreting observations.

## Prerequisites

- Windows 11 x64 disposable VM; official System Informer release; MSVC v143/VS 2022 C++ tools and Windows SDK; an ordinary local lab account. Record application version/channel, Windows build, compiler version, and whether optional driver support is active.
- Use the official project distribution/signature guidance. Nightly and stable builds, architecture support, plugin interfaces, and driver capabilities can differ. The former Process Hacker name does not make old screenshots or plugins version-compatible.
- No driver installation, administrator token, kernel component, service creation, or protection changes are required by the fixture. If visibility is restricted, record it; do not enable powerful components just to fill a table.
- A second **already provisioned** standard local account and an interactive desktop for it are needed only for the optional cross-user token comparison. Do not collect its password in scripts or notes. The complete same-user lifecycle exercise needs no second account.

## Learn

```text
Teach me System Informer at expert Windows inspection depth, using only a
self-authored process in a disposable VM. Assume handles, tokens, threads,
services, PE modules, and virtual-memory regions. Establish exact application
version/channel, OS, observer token, and whether driver assistance is active.
Explain PID plus creation-time identity, ancestry limits, process properties,
thread IDs/start routines/current wait states, module paths/signatures, handles
and granted access, memory type/protection versus intent, and refresh races.
Teach token user/groups, deny-only groups, integrity, elevation type, privileges
present versus enabled, restricted tokens, and process versus impersonation
tokens. Explain why access denied means visibility is unknown, not no activity.
Provide a complete MSVC program that holds a uniquely named temporary file,
starts a descriptively named worker waiting on an event, then closes resources
while the process remains alive. Show exact build and observation steps, values
the program prints for independent correlation, expected lifecycle checks,
hints, solution and cleanup. Include read-only service-to-process mapping and
an optional comparison with an already provisioned standard user's process,
without account creation or credential handling. Distinguish snapshots from
history and discuss corroboration with persistent telemetry. No terminate,
inject, close-remote-handle, token-edit, service-change, driver-enable, or
protection-bypass operations. Use primary project and Microsoft references.
Teach in this conversation; do not edit files or study status.
```

## Cheatsheet

### Process, Thread, and Resource Views

| View / action | Read and correlate | Limit |
|---|---|---|
| Processes -> Properties -> General/Image | PID, creation/start time, image path, parent, command line, current directory | Parent PID can be reused; current environment does not establish original launch intent. |
| Threads | TID, description, start address/module, CPU, state/wait | Start routine is not the current instruction; transient states and worker pools make one snapshot incomplete. |
| Modules | Full path, base, size, version/signature | Mapped image is not proof every export executed. A filename can be misleading. |
| Handles | Type, name, handle value, granted access | Handle values are process-local/reused. A file handle does not establish a successful read or write. |
| Memory | Private/mapped/image regions, committed bytes, protections | Working set differs from private committed bytes; executable memory can be ordinary runtime code. No intent verdict follows from protection bits alone. |
| Token | User SID, groups/attributes, integrity, elevation, privileges | Process token may differ from a thread's impersonation token. Visibility depends on observer rights. |
| Services | Name, state, configured account/type, associated PID | One host PID may contain many services. Stopped service has no live PID; configuration is not execution evidence. |

Use the program's printed PID and thread ID to find the exact row. Refresh after each phase; some tools color recently removed entries before removing them. Search handle names by the unique filename. The name may be presented as a native volume path rather than a drive-letter path. Do not use Close Handle: release resources through the fixture's own prompt.

### Token Interpretation

| Field | Correct distinction | Common false conclusion |
|---|---|---|
| User SID | Security principal in this token, not just display name | Same username text means same SID across machines. |
| Groups | Enabled, disabled and deny-only attributes change access-check use | Membership in Administrators means every process has an enabled admin token. |
| Integrity | Mandatory integrity level is separate from DACL grants | High integrity is a universal permission to every object. |
| Elevation type | Default/full/limited relates to UAC token arrangement | Default always means administrator or always means standard user. |
| Privileges | Present and enabled are different states | A displayed disabled privilege was necessarily exercised. |
| Restricted token | Additional restrictions can constrain otherwise matching grants | Account ACL rights fully predict actual process access. |

Inspect only; do not toggle privileges, groups, integrity, or elevation. Optional driver assistance and elevation can expose more information but do not make unsupported structures universally reliable or remove all protected-process restrictions. An unavailable field must be recorded as **not observed**, not zero/false. Do not inspect sensitive processes to demonstrate this boundary.

### Read-only Service Correlation

In Services, choose a running service in the lab VM, record its service name and PID, then find that PID's process and Services property page if present. Do not start/stop/reconfigure it. A corresponding PowerShell view for a named local service is:

```powershell
Get-CimInstance Win32_Service -Filter "Name='EventLog'" |
	Select-Object Name, State, StartName, ProcessId, PathName
```

This query is local and read-only, but its output may reveal host configuration. Retain only synthetic-lab observations. If EventLog is unavailable, state that fact; the main fixture remains a normal process and is not installed as a service. There should be no service association for it.

### Evidence and Tool Trust

Use `(PID, start time, executable hash, observer identity, UTC observation time)` as the correlation key. Collect before/held/closed phases with the same refresh interval. Handle/thread counts fluctuate because runtime libraries also own resources; match the named worker TID and exact file path, not total counts alone.

Do not upload unknown files through reputation or plugin integrations. Signature status depends on trust-chain/revocation availability and proves neither safety nor exploitability. Tool plugins and driver-assisted features extend trust into additional code. For history, correlate approved event sources such as [[Sysmon]]; a fresh snapshot cannot reconstruct activity that ended before collection. Debugger commands remain in [[WinDbg]].

## Gotchas

- The System Informer process's own token is the observer, not the selected target's token. Record which properties window you used.
- Pausing/suspending or terminating a worker changes the state under study. This lab uses a normal event signal and join instead.
- Without symbols, a start address can appear as module+offset. Record it honestly; do not invent a function name.

## Labs

### Environment and Complete File

Create a new `C:\Lab\Informer` directory. The fixture uses `GetTempFileNameW` to allocate its own temporary marker and `FILE_FLAG_DELETE_ON_CLOSE` to remove it. Its worker sets the thread description `HV waiting worker`, signals readiness, and waits for a manual-reset event. No service is installed.

### File: observer.cpp

```cpp
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <cstdio>

struct WorkerState {
	HANDLE stop;
	HANDLE ready;
};

DWORD WINAPI Worker(void* parameter) {
	WorkerState* state = static_cast<WorkerState*>(parameter);
	SetThreadDescription(GetCurrentThread(), L"HV waiting worker");
	SetEvent(state->ready);
	return WaitForSingleObject(state->stop, INFINITE) == WAIT_OBJECT_0 ? 0 : 1;
}

int wmain() {
	wchar_t directory[MAX_PATH]{};
	wchar_t marker[MAX_PATH]{};
	const DWORD length = GetTempPathW(MAX_PATH, directory);
	if (length == 0 || length >= MAX_PATH ||
		GetTempFileNameW(directory, L"HVI", 0, marker) == 0) {
		return 10;
	}
	HANDLE file = CreateFileW(marker, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		DeleteFileW(marker);
		return 11;
	}
	const char message[] = "synthetic-only\n";
	DWORD written = 0;
	if (!WriteFile(file, message, sizeof(message) - 1, &written, nullptr) ||
		written != sizeof(message) - 1) {
		CloseHandle(file);
		return 12;
	}
	WorkerState state{CreateEventW(nullptr, TRUE, FALSE, nullptr),
					  CreateEventW(nullptr, TRUE, FALSE, nullptr)};
	if (!state.stop || !state.ready) {
		if (state.stop) CloseHandle(state.stop);
		if (state.ready) CloseHandle(state.ready);
		CloseHandle(file);
		return 13;
	}
	DWORD thread_id = 0;
	HANDLE thread = CreateThread(nullptr, 0, Worker, &state, 0, &thread_id);
	if (!thread) {
		CloseHandle(state.ready);
		CloseHandle(state.stop);
		CloseHandle(file);
		return 14;
	}
	WaitForSingleObject(state.ready, INFINITE);
	std::wprintf(L"PID=%lu TID=%lu FILE=%ls\n", GetCurrentProcessId(), thread_id, marker);
	std::wprintf(L"Held: inspect handles, thread and token; Enter to close.\n");
	std::fflush(stdout);
	std::getchar();
	SetEvent(state.stop);
	WaitForSingleObject(thread, INFINITE);
	DWORD worker_exit = 1;
	GetExitCodeThread(thread, &worker_exit);
	CloseHandle(thread);
	CloseHandle(state.ready);
	CloseHandle(state.stop);
	CloseHandle(file);
	const DWORD attributes = GetFileAttributesW(marker);
	const DWORD attribute_error = GetLastError();
	const bool removed = attributes == INVALID_FILE_ATTRIBUTES &&
						 attribute_error == ERROR_FILE_NOT_FOUND;
	std::wprintf(L"Closed: worker=%lu removed=%d; refresh views, Enter to exit.\n",
				 worker_exit, static_cast<int>(removed));
	std::fflush(stdout);
	std::getchar();
	return worker_exit == 0 && removed ? 0 : 15;
}
```

Build/run in x64 Native Tools Command Prompt (cmd):

```bat
cd /d C:\Lab\Informer
cl /nologo /W4 /EHsc /Zi /Od /MD /Fdobserver_compile.pdb /Feobserver.exe observer.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:observer.pdb
observer.exe
echo %ERRORLEVEL%
```

### Objectives and Steps

1. At the held prompt, record PID/TID/file path. In System Informer find the PID, verify full image path and creation time, and record its ordinary user token/integrity. A same-name process elsewhere is not the fixture.
2. Locate the printed TID in Threads. After readiness settles, expect a waiting thread and, on supported builds, its description. Confirm the start address belongs to the executable or the expected Windows thread-start wrapper; record unresolved symbols as module+offset.
3. In Handles find the exact temporary filename and record its File type and granted access. Locate Event handles if visible, but do not expect friendly names: these events are unnamed. Inspect the module list and memory map read-only; identify the main image and at least one runtime DLL.
4. Verify the fixture is not a service, then perform the read-only service correlation from the Cheatsheet separately. Do not attribute a service host's token to this process.
5. Press Enter once in the fixture. Refresh while it remains at the second prompt. The selected worker TID and marker handle must disappear; the marker should be deleted and the process must still exist. Record `worker=0 removed=1`.
6. Optional separate-user comparison: in the VM's already provisioned standard account desktop, build/run the same source in that user's own writable lab directory and inspect it from that account's System Informer. Compare sanitized token fields with the first run. Expect distinct user SIDs; both may have medium integrity. Do not assume one must be elevated. If the second account is unavailable, mark this comparison not performed; do not create accounts or request credentials for it.

### Hints

- A rapidly refreshed thread row can show transition states. Wait for the printed held prompt and take a second snapshot before interpreting a transient state.
- The file is delete-pending by design while held. Its visibility through filesystem tools may differ from its handle's lifetime; the final disappearance is the required check.
- Token access denied is a measurement limit. The current-user lifecycle can still be established using the program's output and visible handles; do not claim the hidden token comparison passed.

### Solution and Expected Results

The worker waits on `state.stop`, not on file I/O. The main thread waits for console input while holding the file and synchronization handles. Enter signals the stop event, joins the worker, closes all handles, and deletes the marker through delete-on-close. The main thread remains alive for a second observation. This demonstrates that disappearance of the worker/file handle does not require process termination. The default fixture uses the launcher's ordinary token and requests no privilege changes.

### Verification, Troubleshooting, and Cleanup

**6 core manual gates**: PID/start/image identity; named worker TID/wait; exact held file; token fields or explicitly recorded denial; fixture-not-a-service plus separate service correlation; worker/handle/file disappearance with `worker=0 removed=1` and final exit 0. Optional seventh gate: separate standard-user comparison. No automated test count is claimed.

Expected failure exit codes 10..14 indicate setup/resource creation problems; 15 means worker or deletion verification failed. Check compiler SDK support for `SetThreadDescription`, writable temp storage, and whether another lab tool held the file open. Do not forcibly close another process's handle. Stop your observation tools normally, let the fixture finish, and recheck deletion. If an interrupted run leaves a marker, delete only the exact printed path after its process exits. Remove only this lab's source/build/database artifacts; no system services or token settings need restoration.

Author validation: **no compilation, execution, token comparison, driver activation, or GUI verification performed**. UI field names, thread-description visibility, and permissions remain build-dependent and unverified.

- [ ] Local System Informer exercise: Inspect your own harmless toy process in a disposable VM, identify one thread and file handle, and compare its token with a separate limited user's process.
- [ ] Boundary check: Verify a known file handle appears while the toy process holds it and disappears after normal closure; document any access-denied visibility limits.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]

## References

- [System Informer official site](https://systeminformer.io/)
- [System Informer official repository](https://github.com/winsiderss/systeminformer)
- [Windows access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [SetThreadDescription](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
