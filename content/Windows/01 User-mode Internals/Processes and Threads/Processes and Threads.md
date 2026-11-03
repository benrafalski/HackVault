---
title: "Processes and Threads"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Processes and Threads Security]]"
updated: 2026-11-03
---
# Processes and Threads

> [!abstract] TL;DR
> Track PID plus creation time, identity, parent evidence, threads, handles, and loaded images. Distinguish process lifetime from object-handle lifetime.

> [!info] Agent scope
> Process/thread lifecycle; scheduling view; address spaces; synchronization; access rights; enumeration and observation.

## Prerequisites

- C++ pointers, ownership, the Windows x64 ABI, and [[Windows Lab Setup]].
- Lab target: Windows 11 x64, Visual Studio 2022 Build Tools with MSVC v143 and Windows SDK 10.0.22621 or newer, already installed. No administrator rights are needed.

## Learn

```text
Teach me Windows process and thread internals at expert engineering depth. Assume
C++ ownership and x64 ABI knowledge. Explain process address-space/resource/token
ownership versus thread stack, TEB, TLS, execution and optional impersonation
state. Trace CreateProcessW from caller inputs to initial thread, initialization,
normal shutdown, signaled process object, and final handle closure. Teach mutable
command lines, exact return/error contracts, PID reuse, creation-time correlation,
minimal process/thread rights, Toolhelp snapshots, and observation races.
Explain preemptive scheduling, ready versus waiting, priorities and boosts without
promising fairness or fixed quanta. Compare events, SRW locks, condition variables,
mutex abandonment and atomic counters. Work through two self-process workers,
cooperative cancellation, joining before freeing context, and failure cleanup.
Use complete benign Win32 examples and predicted acceptance checks; separate
predictions from measured evidence. Cite Microsoft public documentation and label
build-dependent details. No remote memory operations, injection, bypasses, private
data, or debugger commands. Teach here; do not author files or mark study progress.
```

## Cheatsheet

### Lifetime and Scheduling

A process supplies a virtual address space, handle table, primary token, environment, and loaded images. Threads share those resources but have independent stacks, register contexts, thread IDs, TEB/TLS state, and potentially impersonation tokens. A thread is the scheduler's execution unit; a process is not a single schedulable entity. A pointer valid in one process is not automatically meaningful in another.

`CreateProcessW` creates a process and initial thread, but success does **not** mean DLL initialization or application startup completed. `main` returning invokes CRT shutdown and ultimately process exit. Ending the last thread ends the process. Process exit closes its handles and tears down its address space; a handle held by an observer can keep the process object available for exit-status queries. Closing a thread handle does not stop that thread.

Windows uses preemptive, priority-based scheduling. Ready threads can run; waiting threads require a condition to become runnable. Priority class plus relative thread priority determine base priority; dynamic adjustments and processor topology affect actual scheduling. Do not infer a deadlock from a single waiting sample or increase priority to repair synchronization. Real-time priority can starve essential system work. Quantum length, boost behavior, CPU groups, and heterogeneous-core placement are not fixed application contracts.

### Contracts and Access

| API / operation | Contract and ownership |
| --- | --- |
| `CreateProcessW(app, command, ..., inherit, flags, env, cwd, &startup, &info)` | `BOOL`; failure is zero, capture `GetLastError` immediately. `app` can be a full executable path; `command` must be writable and at most 32,767 UTF-16 code units including terminator. Initialize `startup.cb`. Close both returned handles. |
| Environment and working directory | Null inputs inherit the parent's values. An explicit Unicode environment is double-NUL-terminated and requires `CREATE_UNICODE_ENVIRONMENT`; it is not a C++ string vector. Do not transmit secrets on command lines. |
| `CreateThread` | Returns owned `HANDLE` or `NULL`. Entry is `DWORD WINAPI Function(void*)`. The thread may run before creation returns. Context must already be initialized and remain alive until the join. C++ CRT-heavy workers can instead use `_beginthreadex`, whose failure is zero and error convention is CRT-specific. |
| `WaitForSingleObject(handle, milliseconds)` | Requires `SYNCHRONIZE`. Distinguish `WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED` (last error), and for mutexes `WAIT_ABANDONED`. Closing a handle while a wait is pending is undefined. |
| `GetExitCodeProcess` / `GetExitCodeThread` | `BOOL`; output is meaningful on success. Query-capable rights required. Wait for signaled termination first; `STILL_ACTIVE` (259) is ambiguous if an application returns that value. |
| `OpenProcess(mask, FALSE, pid)` | Returns owned handle or `NULL`; query-only observation normally uses `PROCESS_QUERY_LIMITED_INFORMATION`, adding `SYNCHRONIZE` only for waits. Enumerating a PID grants no access. |
| `GetProcessTimes` | Returns creation/exit times plus accumulated kernel/user CPU times in `FILETIME` units of 100 ns; elapsed wall time is different. Pair PID with creation time, not parent PID alone. |
| Toolhelp | `CreateToolhelp32Snapshot` fails with `INVALID_HANDLE_VALUE`, not `NULL`. Initialize `PROCESSENTRY32W.dwSize` or `THREADENTRY32.dwSize`; iteration ends with `ERROR_NO_MORE_FILES`. Close the snapshot. |

### Synchronization Decisions

Manual-reset events represent a persistent condition until `ResetEvent`; auto-reset events release one waiter and are not counters. `PulseEvent` is unreliable. A mutex has ownership and abandonment semantics; an event does not. SRW locks are process-local, not recursive, and not guaranteed fair. Condition-variable waits must occur in a predicate loop because wakes can be spurious or stolen. Atomics protect individual operations, not automatically a multi-field invariant. `volatile` is not a substitute for C++ synchronization.

For shutdown: publish stop state, wake blocked workers, wait for their exit, then destroy shared context and synchronization objects. Never use thread termination as ordinary cancellation: it can leave locks, heap state, and application invariants inconsistent. UI threads need message-aware waits; an indefinite non-pumping wait can deadlock message-dependent work.

### Observation

Toolhelp gives snapshots, not a transaction over process lifetime. A process may exit between enumeration and opening; treat that as normal. A successful open refers to that object even if the numeric ID is later reused. Thread counts fluctuate, CPU time is cumulative, and parent identity is supporting evidence, not proof of provenance. Cross-bitness module enumeration has additional limits; this exercise enumerates only thread IDs and owns the target process.

## Gotchas

- `CreateProcessW` uses the caller's process primary token, not an impersonation token on the calling thread.
- Inheritable return handles and inheritance of existing parent handles are separate controls.
- Suspend/resume is not a safe general lock; a suspended thread may own a lock you need.
- Timing sleeps do not establish readiness. Use a synchronization object and check its result.

## Labs

### Environment and Complete Files

> [!warning] Validation status
> Authored for the prerequisites above; no compiler, runtime, or VM execution was available to this authoring session under its no-execution constraint. All results below are predictions, not recorded runs. Cross-identity denial and scheduler telemetry remain unverified; this exercise launches only its own binary.

Open an **x64 Native Tools Command Prompt for VS 2022**, make a fresh directory, and place the following complete source there as `lifecycle.cpp`. No project file, package, input data, or other source is required.

```bat
mkdir x1-processes
cd x1-processes
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>

struct Work { HANDLE gate; volatile LONG count; };
DWORD WINAPI Worker(void* argument) {
	auto* work = static_cast<Work*>(argument);
	if (WaitForSingleObject(work->gate, 10000) != WAIT_OBJECT_0) return 20;
	for (unsigned index = 0; index < 10000; ++index)
		InterlockedIncrement(&work->count);
	return 0;
}
int Child() {
	Work work{CreateEventW(nullptr, TRUE, FALSE, nullptr), 0};
	if (!work.gate) return 10;
	HANDLE workers[2]{};
	unsigned created = 0;
	for (; created < 2; ++created) {
		workers[created] = CreateThread(nullptr, 0, Worker, &work, 0, nullptr);
		if (!workers[created]) break;
	}
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	unsigned ownThreads = 0;
	bool enumerated = false;
	if (snapshot != INVALID_HANDLE_VALUE) {
		THREADENTRY32 entry{};
		entry.dwSize = sizeof(entry);
		if (Thread32First(snapshot, &entry)) {
			do {
				if (entry.th32OwnerProcessID == GetCurrentProcessId()) ++ownThreads;
				entry.dwSize = sizeof(entry);
			} while (Thread32Next(snapshot, &entry));
			enumerated = GetLastError() == ERROR_NO_MORE_FILES;
		}
		CloseHandle(snapshot);
	}
	bool passed = created == 2 && enumerated && ownThreads >= 3;
	if (!SetEvent(work.gate)) passed = false;
	for (unsigned index = 0; index < created; ++index) {
		if (WaitForSingleObject(workers[index], INFINITE) != WAIT_OBJECT_0)
			ExitProcess(30);
		DWORD code = 99;
		if (!GetExitCodeThread(workers[index], &code) || code != 0) passed = false;
		CloseHandle(workers[index]);
	}
	CloseHandle(work.gate);
	std::printf("child threads=%u count=%ld\n", ownThreads, work.count);
	return passed && work.count == 20000 ? 7 : 11;
}
int wmain(int argc, wchar_t**) {
	if (argc == 2) return Child();
	wchar_t image[32768]{};
	DWORD length = GetModuleFileNameW(nullptr, image, 32768);
	if (!length || length >= 32768) return 1;
	std::wstring text = L"\"" + std::wstring(image) + L"\" child";
	std::vector<wchar_t> command(text.begin(), text.end());
	command.push_back(L'\0');
	STARTUPINFOW startup{};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION process{};
	if (!CreateProcessW(image, command.data(), nullptr, nullptr, FALSE, 0,
						nullptr, nullptr, &startup, &process)) {
		std::printf("CreateProcessW error=%lu\n", GetLastError());
		return 2;
	}
	CloseHandle(process.hThread);
	DWORD waited = WaitForSingleObject(process.hProcess, 15000);
	DWORD code = 99;
	FILETIME creation{}, exit{}, kernel{}, user{};
	bool passed = waited == WAIT_OBJECT_0;
	if (!GetExitCodeProcess(process.hProcess, &code)) passed = false;
	if (!GetProcessTimes(process.hProcess, &creation, &exit, &kernel, &user))
		passed = false;
	std::printf("pid=%lu creation=%08lx:%08lx exit=%lu\n", process.dwProcessId,
				creation.dwHighDateTime, creation.dwLowDateTime, code);
	CloseHandle(process.hProcess);
	return passed && code == 7 ? 0 : 3;
}
```

### Objectives and Steps

1. Predict why the initial thread handle can close before child exit, but `work` cannot die before worker joins.
2. Build and run the exact source. The direct compiler invocation is the entire build configuration.
3. Explain why the snapshot should find at least three child threads, but an exact count is not portable.

```bat
cl /nologo /W4 /EHsc /std:c++17 lifecycle.cpp /Fe:lifecycle.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
lifecycle.exe
echo Exit=%ERRORLEVEL%
```

### Hints

An event can remain signaled before a waiter starts waiting. The process handle belongs to the parent; its closure is not the child's exit request. `InterlockedIncrement` supplies the atomic operation, not the `volatile` keyword alone.

### Solution and Expected Results

The child starts two workers whose contexts already exist. Both block on a manual-reset event. Enumeration occurs before signaling; the main child thread and both workers should still exist. Setting the event lets both increment a shared counter atomically. Each thread returns zero, joins complete, the counter is 20,000, and the child returns 7. The parent waits on the process object, reads exit code 7 and creation time, then returns zero. PIDs and times vary. Holding the process handle after exit preserves query access, not an executing process or its former address space.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe `count=20000`, child `exit=7`, and parent `Exit=0`; explain every handle owner.
- [ ] Rebuild and repeat after any synchronization change; preserve the positive path.
- [ ] Record OS build, compiler version, predicted versus actual thread counts, and any failure.

Compiler not found means the developer prompt/toolchain prerequisite is unmet. A wait timeout is a failed lab, not a successful timing measurement; the worker's own ten-second timeout lets it return without forced termination. If policy blocks child creation, record the error without weakening policy. Optional graphical observation uses [[Sysinternals]]; debugger procedures belong to [[WinDbg]].

```bat
del lifecycle.exe lifecycle.obj
```

The program creates no persistent OS objects or files; remove the source directory when finished. Separate identities, elevated tokens, and external telemetry are not required or validated by this lab.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Processes and Threads Security]]

## References

- [Processes and threads](https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads)
- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Scheduling priorities](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
- [Taking a snapshot and viewing processes](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
