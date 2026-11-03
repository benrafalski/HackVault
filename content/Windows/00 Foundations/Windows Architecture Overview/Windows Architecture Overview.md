---
title: "Windows Architecture Overview"
aliases: []
tags: [windows, x0]
domain: windows
phase: "X0"
type: tech
status: draft
pair: "[[Windows Architecture Overview Security]]"
updated: 2026-11-03
---
# Windows Architecture Overview

> [!abstract] TL;DR
> Distinguish API contract from implementation, service from driver, and process identity from the effective thread token. Use public symbols and documented interfaces for observations.

> [!info] Agent scope
> User/kernel boundary; executive and kernel; subsystems; services; sessions; system components; object and I/O overview.

## Prerequisites

- Processes, threads, C++ functions and basic Win32 handles. Use [[Windows Lab Setup]] for a disposable Windows 11 x64 VM.
- Native lab: VS 2022 Build Tools 17.10+ (17.x), Desktop development with C++, v143 x64 and Windows SDK 10.0.22621.0+. These are assumed compatible versions; record the actual OS/toolset build.

## Learn

```text
Teach me Windows architecture at expert foundation depth using public Windows
11 x64 contracts. Assume basic C++ and processes/threads. Distinguish user mode,
kernel mode, executive managers, low-level kernel, HAL, drivers, Win32 subsystem,
services, sessions, logon identities and object namespaces. Trace one CreateFileW/
WriteFile/ReadFile request and one event wait through the conceptual layers;
separate documented API guarantees from version-specific implementation.
Explain handles, access rights, references, synchronous versus asynchronous I/O,
service hosting and WOW64 without page-table material. Supply a complete MSVC
x64 program using synthetic files and an event, exact builds and observations,
error paths, expected checks, reset, and a defensible evidence diagram. Never
infer a service dependency merely from temporal correlation. Use primary sources,
keep debugger commands in WinDbg, do not edit files/status, and include worked
questions about mode transitions, effective identity and lifetime boundaries.
```

## Cheatsheet

### Components and Execution Boundaries

| Component | Responsibility | Boundary to remember |
|---|---|---|
| User application / runtime | Application logic, CRT, user-mode libraries | A process is a resource/security container; a thread is the scheduled execution context. |
| Win32 subsystem interfaces | Documented application APIs in libraries such as Kernel32/KernelBase, User32, Advapi32 | Some calls execute entirely in user mode; API sets/forwarders mean an import name is not necessarily the final implementation module. |
| Native API / system call transition | OS service entry, usually reached through user-mode Ntdll for NT services | Do not hardcode service numbers or private structures. A mode transition is not inherently a process/context switch. |
| Executive | Object, process, memory, security, configuration, I/O and other high-level OS management | Largely kernel-mode services. Component responsibilities overlap; the diagram is conceptual, not a stable internal ABI. |
| Low-level kernel | Scheduling/dispatch, traps, interrupts and synchronization machinery | Runs in kernel mode with execution-level constraints. A service process is not this kernel. |
| HAL and drivers | Hardware abstraction, devices, buses, filesystems, filters | Kernel drivers run in a high-trust context. UMDF is a distinct user-mode driver framework; not every driver is kernel-mode code. |

Windows is not "one service per kernel feature." `ntoskrnl.exe` contains major kernel/executive functionality. `services.exe` is the user-mode Service Control Manager; `svchost.exe` hosts configured groups of user-mode services. Hosting groups change across builds and system configurations. A process image name alone does not establish identity, privilege or legitimacy.

### System Processes, Subsystems and Sessions

| Name/concept | Foundation interpretation |
|---|---|
| Session Manager (`smss.exe`) | Participates in session/system initialization. Do not terminate critical system processes as a learning experiment. |
| `csrss.exe`, `wininit.exe`, `winlogon.exe` | User-mode system/session components with distinct initialization and interactive-logon responsibilities; instances vary by session. |
| `lsass.exe` | Local security/authentication subsystem process; do not inspect its memory or collect credentials in this phase. |
| Session 0 | Hosts services and other noninteractive system work on modern Windows; it is isolated from ordinary interactive desktops. |
| Session vs logon session | A Terminal Services session identifier is not an authentication logon identifier and is not a user SID. One session can contain multiple identities. |
| Window station / desktop | GUI object/security scopes within a session; not synonymous with a process token. |
| WOW64 | Compatibility environment for supported 32-bit applications on 64-bit Windows. Filesystem/registry views and pointer widths can differ; use native x64 builds for this lab. |
| WSL | A different subsystem: WSL 2 uses a lightweight VM and Linux kernel. Do not infer native NT implementation from a Linux userspace observation. |

A process has a primary token. A thread can have an impersonation token that determines effective access for relevant operations. Elevation, an enabled privilege, an integrity level, a session ID and membership in a group are distinct attributes. A service can use a restricted service SID and a low-privilege account rather than LocalSystem. Full security mechanics are in later notes; do not substitute "administrator" for an access-check explanation.

### Objects, Handles and I/O

An object is an OS-managed instance with type-specific behavior and lifetime. A process-local handle references an object and carries granted access. The same numeric value in another process need not refer to the same object. A thread, event and file have different access masks and failure sentinels. Closing one handle releases one reference; other handles, pending operations or kernel references can keep the object alive. Inheritance is explicit and should be disabled unless required.

For a local disk-file operation, a useful conceptual trace is:

```text
application -> Win32 API -> NT service boundary -> object/security/I/O machinery
			-> filesystem and relevant filters -> storage stack -> device
completion -> status/byte count -> application
```

This is not a guarantee of one syscall, one IRP or one physical disk access per call. Cached I/O, fast paths, filters, buffering and filesystem semantics change the observed path. A file handle names a file object; an open can fail for ACL, sharing or path reasons. `CreateFileW` also opens devices/pipes under different contracts; this lab opens only its own disk file. A successful `WriteFile` and even a flush are not a universal proof against all hardware/power-loss failure modes.

`WaitForSingleObject` waits on a waitable object, not on a CPU instruction. With an auto-reset event, a successful wait consumes the signaled state; a manual-reset event remains signaled until reset. Timeouts are observations, not proof another thread never ran. `WAIT_FAILED` requires immediate `GetLastError`; `WAIT_TIMEOUT` is not an API failure. A ready thread may not run immediately after a signal.

### Observation Commands and Limits

These are ordinary OS/SDK commands, not debugger commands:

```bat
tasklist /svc
sc.exe query RpcSs
sc.exe qc RpcSs
dumpbin /imports architecture.exe
dumpbin /headers architecture.exe
```

`sc.exe` is explicit because PowerShell historically aliases `sc` to a different command. `query` reports current service status; `qc` reports configured dependencies and startup/account configuration, not every runtime interaction. Imports show static dependency declarations, not all dynamically resolved modules or kernel drivers. A user-mode module list cannot enumerate the entire I/O stack. [[Sysinternals]] and [[WinDbg]] provide deeper observation workflows.

## Gotchas

- Do not draw a network hop just because RPCSS is running; local procedure calls and remote RPC are distinct cases.
- A service account may be privileged while the service remains user mode. Kernel mode is a processor execution boundary, not a synonym for administrator.
- Unsupported internal offsets and undocumented structures change across Windows builds. Use symbols only for the matching binary and distinguish inference from API promises.

## Labs

### Environment and Complete File

Use the development VM/toolchain above, standard-user execution, one empty directory `%USERPROFILE%\X0-Architecture`, and no network targets. The program overwrites **only `architecture.bin` in its current directory**. Budget 1 GiB workspace. In an x64 developer prompt, create that directory and `cd /d` into it. Create **architecture.cpp**:

```cpp
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

class OwnedHandle {
	HANDLE value_;
public:
	explicit OwnedHandle(HANDLE value) noexcept : value_(value) {}
	~OwnedHandle() {
		if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
	}
	OwnedHandle(const OwnedHandle&) = delete;
	OwnedHandle& operator=(const OwnedHandle&) = delete;
	HANDLE get() const noexcept { return value_; }
};

int main() {
	static_assert(sizeof(void*) == 8);
	DWORD session = 0;
	if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return 2;
	std::printf("pid=%lu main_tid=%lu session=%lu\n",
		GetCurrentProcessId(), GetCurrentThreadId(), session);
	OwnedHandle file(CreateFileW(L"architecture.bin", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (file.get() == INVALID_HANDLE_VALUE) return 3;
	constexpr char marker[] = "X0 architecture\r\n";
	constexpr DWORD length = static_cast<DWORD>(sizeof(marker) - 1);
	DWORD transferred = 0;
	if (!WriteFile(file.get(), marker, length, &transferred, nullptr) ||
		transferred != length) return 4;
	if (!FlushFileBuffers(file.get())) return 5;
	LARGE_INTEGER start{};
	if (!SetFilePointerEx(file.get(), start, nullptr, FILE_BEGIN)) return 6;
	char received[sizeof(marker)]{};
	if (!ReadFile(file.get(), received, length, &transferred, nullptr) ||
		transferred != length || std::memcmp(received, marker, length) != 0) return 7;
	OwnedHandle event(CreateEventW(nullptr, FALSE, FALSE, nullptr));
	if (event.get() == nullptr) return 8;
	std::atomic<DWORD> wait_result{WAIT_FAILED};
	std::thread worker([&] {
		wait_result.store(WaitForSingleObject(event.get(), 5000));
	});
	const BOOL signaled = SetEvent(event.get());
	worker.join();
	const DWORD second_wait = WaitForSingleObject(event.get(), 0);
	std::printf("bytes=%lu worker_wait=%lu second_wait=%lu\n",
		transferred, wait_result.load(), second_wait);
	if (!signaled || wait_result.load() != WAIT_OBJECT_0 ||
		second_wait != WAIT_TIMEOUT) return 9;
	std::puts("Inspect this PID now; press Enter to close owned handles and exit.");
	(void)std::getchar();
	return 0;
}
```

The worker has a bounded wait and is joined before its referenced event and atomic go out of scope. An event signal is retained until consumed even if the worker has not yet started waiting. Thread creation can throw `std::system_error`; under this lab's normal resource budget it is expected to succeed, but a resource failure is not an access-boundary finding. The scope-owned handles still unwind if construction throws.

### Objectives and Steps

In **x64 Native Tools Command Prompt for VS 2022**:

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf architecture.cpp /Fearchitecture.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
architecture.exe
```

While it waits for Enter, use a second Windows PowerShell console. Replace the numeric `1234` below with the **printed PID**, not a guessed system-process ID:

```powershell
$labProcessId = 1234
Get-Process -Id $labProcessId | Select-Object Id, ProcessName, SessionId, HandleCount
(Get-Process -Id $labProcessId).Modules | Select-Object ModuleName, FileName
Get-Content -LiteralPath "$env:USERPROFILE\X0-Architecture\architecture.bin"
sc.exe query RpcSs
sc.exe qc RpcSs
```

PowerShell `$PID` is reserved for its own process, hence the separate variable name. Inspect only your sample. Optionally install Microsoft's signed Process Explorer/Process Monitor from the official Sysinternals pages inside the VM: extract, check signatures, accept the license, select the printed PID in Process Explorer, use lower-pane Handles view for the file/event, and in Process Monitor filter **Process Name is architecture.exe**, clear old events, start capture, then rerun the sample. Stop capture immediately after exit. Process Monitor's capture driver may require approved elevation **inside the VM**, never disabled protections. The exercise remains usable with the built-in observations above.

Draw a text diagram labeling the app, CRT/Win32 DLLs, system-call boundary, executive/I/O path and file/event objects. Put RPCSS/SCM in a separate observed service branch. Do not claim the sample contacted RPCSS simply because it was running. Identify which statements are documented models and which were directly observed.

### Hints

The file contains 17 bytes including CRLF; it is not NUL-terminated on disk. The worker's successful wait consumes the auto-reset event. DLL modules are user-mode mappings; kernel filesystem work need not appear there.

### Solution and Expected Observations

Expected stable line: `bytes=17 worker_wait=0 second_wait=258`. PID, TID, session, module paths and handle count vary. The file reads `X0 architecture` followed by a newline. After Enter the process exits 0 and its owned handles close. The file remains, illustrating the difference between handle lifetime and persistent data. A second wait times out because the event was auto-reset, not because `SetEvent` failed.

Changing only the `CreateEventW` manual-reset parameter from `FALSE` to `TRUE` would make the second wait return 0; the existing exit check would deliberately fail. This is a useful reasoning experiment, not a prescribed edit to make before collecting the baseline.

### Verification, Troubleshooting, and Cleanup

Author validation: **unexecuted native build, process/module observations and optional capture**. Record actual service names/dependencies rather than copying expected implementation details. If module enumeration is denied, use the same standard-user identity and native x64 PowerShell for your own process; do not attach to protected processes. A file read failure while the sample runs may indicate an unexpected sharing or path issue. Return 9 means a synchronization expectation failed; inspect resource pressure and actual wait results, not security settings.

Press Enter, stop captures, close tools and delete only `%USERPROFILE%\X0-Architecture`, or restore the snapshot. The preserved study items below also reference the companion security exercise for identity/access comparisons.

- [ ] Local Windows Architecture Overview exercise: In a Windows VM, map a test application, its service dependency, loaded modules, and device interactions using Sysinternals. Produce a diagram labeling user/kernel and identity boundaries without adding page-table material.
- [ ] Boundary check: Run the same harmless resource access under standard and elevated synthetic lab users; compare access decisions and relevant object permissions instead of assuming elevation bypasses every control.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[Windows Architecture Overview Security]]

## References

- [User mode and kernel mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)
- [Windows kernel-mode managers and libraries](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/overview-of-windows-components)
- [Services](https://learn.microsoft.com/en-us/windows/win32/services/services)
- [Object handles](https://learn.microsoft.com/en-us/windows/win32/sysinfo/object-handles)
- [CreateEventW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
- [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
