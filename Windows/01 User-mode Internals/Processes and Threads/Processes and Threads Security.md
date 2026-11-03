---
title: "Processes and Threads Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Processes and Threads]]"
updated: 2026-11-03
---
# Processes and Threads Security

> [!abstract] TL;DR
> Overbroad process rights, unsafe handle inheritance, and synchronization defects can expose cross-process operations or corrupt state.

> [!info] Agent scope
> Security of: Process/thread lifecycle; scheduling view; address spaces; synchronization; access rights; enumeration and observation. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Opening a process turns an identifier into authority. Requesting broad rights for observation exposes unnecessary control to later code.
- Process creation consumes executable paths, command-line text, environment, current directory, and inherited handles. Each has a separate contract.
- Worker context, cancellation state, and shared handles must outlive all users. An access check does not repair a data race.

## Learn

```text
Teach defensive Windows process/thread API use at expert depth. Assume C++ and
Win32 handle familiarity. Cover exact process/thread access masks, the difference
between enumeration and authorization, pseudo versus owned handles, PID reuse,
creation-time correlation, impersonation versus process creation identity, and
protected-process restrictions. Explain command-line parsing contracts, explicit
application paths, environment trust, explicit inheritance, cooperative shutdown,
join-before-free, and TOCTOU races. Show a benign self-process baseline with
unnecessary control rights, reduce it to query rights, demonstrate a harmless
SetPriorityClass denial, and prove query access still works. Do not claim this is
a sandbox against other code in the same process. Include diagnostics and repeatable
positive/negative checks. Use Microsoft primary docs; distinguish version-dependent
telemetry from guarantees. No injection, arbitrary process memory access, privilege
changes, exploitation or bypass instructions. Teach in chat, not file authoring.
```

## Cheatsheet

### Authority Is Per Handle

`OpenProcess` evaluates the requested rights against the process object's security and applicable system policy. Its returned handle carries granted rights. Do not retry denied inspection with `PROCESS_ALL_ACCESS` or enabled debugging privileges. Protected processes, token state, and integrity policy can impose additional restrictions; access denied is a result, not an invitation to bypass them.

| Operation | Deliberate authority |
| --- | --- |
| Query path, creation time, basic identity | `PROCESS_QUERY_LIMITED_INFORMATION` for APIs documenting support; check each API, not just this category |
| Wait for termination | `SYNCHRONIZE`; querying alone does not grant waits |
| Set priority class | `PROCESS_SET_INFORMATION`; omitted from observation handles |
| Query thread basics | `THREAD_QUERY_LIMITED_INFORMATION` where documented |
| Wait for thread exit | `SYNCHRONIZE`; retain ownership until the wait completes |
| Duplicate handles | Process `PROCESS_DUP_HANDLE`; powerful authority that observers normally do not need |

`GetCurrentProcess()` is a context-sensitive pseudo-handle, not an owned handle to close. Passing it to an observer grants broad self-process authority; open a real, noninheritable, limited-rights handle when the interface should constrain accidental operations. This is API hygiene, **not** a trust boundary against arbitrary code already running in the same address space: such code can acquire another self handle.

### Creation and Concurrency Invariants

Use an explicit absolute `lpApplicationName`, a mutable command-line buffer, and quote the program name. Arguments are parsed by the child's runtime, not by a universal Windows argv API; quoting a path does not escape arguments for a shell. Avoid shells for ordinary executable launch. Do not infer user identity from a parent PID or executable basename. `CreateProcessW` runs under the process primary token even when the caller's thread impersonates.

Set `bInheritHandles=FALSE` unless inheritance is intentional. When needed, use `STARTUPINFOEXW` plus `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` and `EXTENDED_STARTUPINFO_PRESENT`; list entries must be inheritable and the create call uses `TRUE`. The list controls that launch, but other concurrent broad-inheritance launches can still race with temporarily inheritable handles. Coordinate all launch paths or use dedicated noninheritable ownership and a controlled transfer design. See [[Objects and Handles]] for lifetime rules.

Process enumeration followed by opening is a TOCTOU boundary. An identifier can expire; open only when needed and query identity using the resulting handle. Creation time plus PID improves correlation but is not a cryptographic provenance guarantee. Never close a handle while a waiter or worker can use it. Shutdown order is stop request, wake, join, close, free. Terminating a thread can abandon locks and invariants; timeouts should produce explicit failure and a cooperative shutdown path.

### Baseline and Fix

The lab's baseline handle has `PROCESS_SET_INFORMATION` despite being handed to an observer. A same-priority update succeeds, demonstrating unnecessary authority without changing scheduling policy. The fixed handle requests only `PROCESS_QUERY_LIMITED_INFORMATION`; `GetPriorityClass` remains permitted while `SetPriorityClass` must fail with `ERROR_ACCESS_DENIED`. Capture last error immediately after failure; successful APIs need not clear it.

## Detection and Defense

Log requested mask, API result, captured error, PID plus creation time, and the operation's purpose. Do not log full command lines or environments when they may contain secrets. Process creation auditing and Sysmon process events require separately configured collection; they do not prove which access mask every application requested. Unexpected access denial may be normal policy enforcement, while a successful broad open by itself is not evidence of malicious activity. Review call sites and lifetime ownership as well as telemetry.

Regression coverage must include permitted queries, denied control, noninheritable handles, shutdown with zero/one/multiple workers, and normal child initialization failure. A passing self-process test does not establish cross-user isolation, restricted-token containment, or protection against a privileged administrator.

## Labs

### Environment and Complete Files

Windows 11 x64, an already installed VS 2022 x64 Native Tools prompt, MSVC v143, Windows SDK 10.0.22621+, standard user. No network, other processes, accounts, services, or external data. The sole source is `process-rights.cpp`; the compiler command is the complete project configuration.

> [!warning] Unverified
> No build or runtime/VM test was performed during authoring. Expected errors below follow documented contracts. Cross-identity, protected-process, inheritance, and external audit behavior are not tested by this self-process exercise.

```bat
mkdir x1-process-rights
cd x1-process-rights
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>

bool Observe(HANDLE process, bool expectControl) {
	DWORD priority = GetPriorityClass(process);
	if (!priority) {
		std::printf("query failed=%lu\n", GetLastError());
		return false;
	}
	BOOL changed = SetPriorityClass(process, priority);
	DWORD error = changed ? ERROR_SUCCESS : GetLastError();
	DWORD flags = 0;
	bool flagsOk = GetHandleInformation(process, &flags) != FALSE;
	std::printf("priority=%lu control=%d error=%lu inherit=%d\n", priority,
				changed != FALSE, error, (flags & HANDLE_FLAG_INHERIT) != 0);
	return flagsOk && !(flags & HANDLE_FLAG_INHERIT) &&
		(expectControl ? changed != FALSE :
			changed == FALSE && error == ERROR_ACCESS_DENIED);
}
int main() {
	DWORD pid = GetCurrentProcessId();
	HANDLE broad = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
							   PROCESS_SET_INFORMATION, FALSE, pid);
	if (!broad) return 1;
	bool baseline = Observe(broad, true);
	CloseHandle(broad);
	HANDLE limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!limited) return 2;
	bool fixed = Observe(limited, false);
	FILETIME created{}, exited{}, kernel{}, user{};
	bool query = GetProcessTimes(limited, &created, &exited, &kernel, &user) != FALSE;
	CloseHandle(limited);
	std::printf("baseline=%d fixed=%d retained-query=%d\n", baseline, fixed, query);
	return baseline && fixed && query ? 0 : 3;
}
```

### Objectives and Baseline

1. Build and run, then identify the one extra right in the baseline.
2. Predict both `SetPriorityClass` results before reading the solution.
3. Confirm the fixed handle is noninheritable and still supports creation-time queries.

```bat
cl /nologo /W4 /EHsc /std:c++17 process-rights.cpp /Fe:process-rights.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
process-rights.exe
echo Exit=%ERRORLEVEL%
```

### Hints

A handle is not merely a PID encoded as an integer. The two handles refer to the same process but carry different granted masks. Neither call changes the DACL or the user's token.

### Solution and Fixed Retest

The baseline performs a no-op priority-class assignment and returns `control=1 error=0`. With `PROCESS_SET_INFORMATION` removed, the identical assignment returns `control=0 error=5`. Both lines show `inherit=0`. The final line should be `baseline=1 fixed=1 retained-query=1`, with `Exit=0`. The priority number depends on how the process was launched. Re-run the same executable to repeat the full baseline/fixed comparison. No scheduling elevation or other-process access is performed.

### Verification, Troubleshooting, and Cleanup

- [ ] Record both control outcomes and the retained successful query.
- [ ] Explain why this restricts an API consumer but does not sandbox same-process code.
- [ ] Record OS/compiler versions and any deviations; do not mark success on a nonzero exit.

If the baseline fails, check job/policy restrictions and developer-prompt setup; do not elevate or relax policy to force a pass. If the fixed assignment succeeds, verify the compiled source actually omitted `PROCESS_SET_INFORMATION`. No raw handle value should be reused after closure.

```bat
del process-rights.exe process-rights.obj
```

There are no persistent OS changes; remove the lab directory when done. Additional identities and privileged services are deliberately outside this lab.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Processes and Threads]]

## References

- [Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Thread security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights)
- [SetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass)
- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
