---
title: "Win32 Native API and Syscalls"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Win32 Native API and Syscalls Security]]"
updated: 2026-11-03
---
# Win32 Native API and Syscalls

> [!abstract] TL;DR
> Prefer supported Win32 contracts in production. Record OS build and architecture for low-level observations; do not hardcode syscall numbers.

> [!info] Agent scope
> Win32 versus Native API contracts; ntdll; syscall boundary; handles and status codes; version-sensitive behavior.

## Prerequisites

- C/C++ ABI, pointer widths, [[Objects and Handles]], and [[Windows Lab Setup]].
- Windows 11 x64, already installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools Command Prompt, standard user.

## Learn

```text
Teach Win32, the Native API and the system-service boundary at expert depth. Assume
C++ ABI and handle knowledge. Explain documented Win32 contracts versus ntdll
exports and internal structures, user-mode work versus kernel transitions, API-set
forwarding, WOW64 architecture implications, and why API names are not one syscall
each. Compare BOOL, HANDLE, LSTATUS, HRESULT and signed NTSTATUS, including pending,
warning and information results, byte/character lengths and partial outputs.
Work through a self-process NtQueryInformationProcess query using SDK declarations
and runtime export lookup, with a too-short buffer and a successful bounded query;
compare GetCurrentProcessId. Never dereference the returned PEB. Explain supported
Win32 alternatives, version/calling-convention caveats, capture of last error,
resource ownership and kernel access checks. Use primary Microsoft docs and exact
build/run/check commands, with predicted results labeled. No syscall stubs/numbers,
evasion, bypasses, arbitrary process memory access or private data. Teach here;
do not author files or update study status.
```

## Cheatsheet

### Layers and Contracts

Win32 is an application-facing contract family, not a single DLL or a guarantee of one kernel transition. A call may validate and transform parameters, perform entirely user-mode work, use RPC to another service, or request one or more kernel services. Imports through Kernel32, KernelBase, Advapi32 and API-set contracts are implementation layers whose exact routing can change. `ntdll` includes Native service entry points **and** user-mode runtime routines; not every export is a syscall.

The system-service boundary transfers a request into the kernel, where user buffers, object handles, rights and operation-specific parameters are validated. A lower-level entry point does not grant extra authority. Kernel `Nt`/`Zw` distinctions concerning caller mode are driver-context rules; a user-mode caller does not become trusted by choosing a differently named entry point. Production applications should use documented Win32 alternatives when available.

Native export availability is not a permanent application contract. Microsoft explicitly warns that `NtQueryInformationProcess` and returned internal structures can change. Resolve it at runtime, check absence and status, use SDK declarations, and avoid private offsets. Dynamic lookup detects a missing export, not an incompatible semantic/signature change. A successful current-build test is not a compatibility guarantee.

### Return Values Must Keep Their Type

| Convention | Correct decision / caveat |
| --- | --- |
| `BOOL` | Usually zero failure, nonzero success; only use last error as documented. A nonzero value is not necessarily exactly 1 |
| `HANDLE` | Failure sentinel is API-specific: `CreateFileW` uses `INVALID_HANDLE_VALUE`; `OpenProcess` uses `NULL` |
| Registry `LSTATUS` | `ERROR_SUCCESS == 0`; returned error code is authoritative, not thread last error |
| `HRESULT` | `SUCCEEDED`/`FAILED` test sign; `S_FALSE` is success with a distinct meaning |
| `NTSTATUS` | Signed 32-bit value. `NT_SUCCESS(status)` is `status >= 0`, including informational results; warnings/errors have the sign bit set. Do not treat nonzero as success |
| Pending I/O | `STATUS_PENDING` is nonnegative, but completion and output consumption must follow the API's asynchronous contract; it does not mean data is ready |

NTSTATUS severity occupies the top two bits: success `00`, informational `01`, warning `10`, error `11`. Some APIs return meaningful partial output with a warning; consume it only if their specific contract permits it. Win32 translation may collapse multiple statuses into one error. `RtlNtStatusToDosError` provides a documented conversion but cannot preserve every native distinction. Log original native status in hexadecimal alongside a translation when needed.

`GetLastError` is per-thread state, not the result of the previous arbitrary function. Capture it immediately after an API's documented failure, before formatting/logging/cleanup; success often leaves stale state. Native calls return NTSTATUS directly and need not update last error. Do not label a Native failure using an unrelated stale Win32 value.

### Structures, Buffers, and Handles

`NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)` uses a **byte** buffer length in a 32-bit `ULONG`. `ProcessBasicInformation` uses the SDK's `PROCESS_BASIC_INFORMATION`; its PID field is pointer-sized. The lab passes `GetCurrentProcess()` and never reads another process or dereferences the returned PEB pointer. Use `GetProcessId`, `GetExitCodeProcess`, `QueryFullProcessImageNameW`, or `IsWow64Process2` instead of Native information classes for ordinary application needs.

`UNICODE_STRING.Length` and `MaximumLength` are byte counts in `USHORT`; a string need not be NUL-terminated. Pointer-containing outputs require backing buffers to remain alive, correct alignment, bounds on each referenced span, and care before resizing/moving the buffer. Do not pass an arbitrary C++ packed struct or assume a 64-bit OS means every process has 64-bit pointers. Windows x64 uses 32-bit `LONG` and 64-bit pointers; WOW64 changes the process ABI and transition path. Never hardcode service numbers or parse instruction bytes to invent a compatibility layer.

The process pseudo-handle is borrowed and should not be closed. An acquired module reference uses `FreeLibrary`; ordinary object handles use `CloseHandle`. Returning from a low-level call does not transfer ownership unless its contract says so. For variable-size queries, bound both allocation and retry count: data can grow between a length probe and fetch. A length probe is not a stable snapshot.

### A File Request in Context

`CreateFileW(path, access, share, NULL, disposition, flags, NULL)` returns an owned file handle or `INVALID_HANDLE_VALUE`. Access rights request authority; sharing controls compatibility with other opens, not permission to override an ACL. `ReadFile` returns `BOOL` with byte count for synchronous success; asynchronous use additionally needs stable `OVERLAPPED` and buffer lifetime through completion. These documented interfaces hide lower-layer details while retaining kernel-enforced file and handle policy. Static imports show dependencies, not runtime call counts or a proven kernel stack.

## Gotchas

- Do not equate `status == 0` with the full NT-success class, or `if (status)` with success.
- Size queries may intentionally fail with a documented buffer-size result; unrelated failures are not sizing hints.
- Native-layout changes require a version/architecture validation matrix; runtime lookup alone is insufficient.
- Debugger commands belong only to [[WinDbg]].

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No compiler, Native call, VM, trace or debugger was run during authoring. Results are predictions. The lab does not claim syscall-stack evidence, denied-access equivalence across APIs, cross-bitness compatibility or stable private structures.

Create a fresh folder in the developer prompt. The entire program is `api-layers.cpp`; it requires no project file, data, import library for ntdll, or extra package.

```bat
mkdir x1-api-layers
cd x1-api-layers
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <winternl.h>
#include <cstdio>

int main() {
	HMODULE native = LoadLibraryExW(L"ntdll.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!native) return 1;
	using QueryProcess = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	auto query = reinterpret_cast<QueryProcess>(
		GetProcAddress(native, "NtQueryInformationProcess"));
	if (!query) { FreeLibrary(native); return 2; }
	ULONG required = 0;
	NTSTATUS shortStatus = query(GetCurrentProcess(), ProcessBasicInformation,
								 nullptr, 0, &required);
	PROCESS_BASIC_INFORMATION information{};
	ULONG returned = 0;
	NTSTATUS status = query(GetCurrentProcess(), ProcessBasicInformation,
		&information, static_cast<ULONG>(sizeof information), &returned);
	std::printf("short-status=0x%08lx required=%lu\n",
				static_cast<ULONG>(shortStatus), required);
	std::printf("query-status=0x%08lx returned=%lu\n",
				static_cast<ULONG>(status), returned);
	bool passed = static_cast<ULONG>(shortStatus) == 0xC0000004UL &&
				  status >= 0 && returned == sizeof information;
	if (status >= 0 && returned == sizeof information) {
		DWORD supportedPid = GetCurrentProcessId();
		std::printf("native-pid=%llu Win32-pid=%lu\n",
					static_cast<unsigned long long>(information.UniqueProcessId),
					supportedPid);
		passed = information.UniqueProcessId == supportedPid && passed;
	}
	if (!FreeLibrary(native)) passed = false;
	std::printf("checks=%d\n", passed);
	return passed ? 0 : 3;
}
```

### Objectives and Steps

1. Predict the short-buffer result and contrast it with Win32's BOOL convention.
2. Compare the supported PID API with the bounded Native result.
3. Inspect the executable's imports and explain why dynamically resolved calls are not normal named imports.

```bat
cl /nologo /W4 /EHsc /std:c++17 api-layers.cpp /Fe:api-layers.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
api-layers.exe
echo Exit=%ERRORLEVEL%
dumpbin /imports api-layers.exe
```

### Hints

`0xC0000004` is `STATUS_INFO_LENGTH_MISMATCH`. Interpret the original signed `NTSTATUS` before casting for hex printing. No output fields are consumed on the failed call.

### Solution and Expected Results

The zero-sized request should report `0xC0000004`; the correctly sized request should return success, a structure-sized length, and the same PID as `GetCurrentProcessId`. Final `checks=1` and exit zero are expected. Exact PID and reported sizes depend on runtime architecture/SDK. `dumpbin` shows the supported loader and Win32 imports, but the literal runtime lookup of `NtQueryInformationProcess` is not a static import and proves no specific syscall sequence.

### Verification, Troubleshooting, and Cleanup

- [ ] Record both raw statuses, returned length and equal PIDs.
- [ ] Explain which output is safe to consume and why the PEB pointer is unused.
- [ ] Record OS build, compiler/SDK and architecture; do not infer other-build compatibility.

Missing export or unexpected size/status is a compatibility failure; keep the supported API and record the result. Do not substitute private definitions or numbers. If `cl`/headers are unavailable, the build prerequisite is unmet. No external process, file data or machine policy is modified.

```bat
del api-layers.exe api-layers.obj
```

Remove the source directory when done.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Win32 Native API and Syscalls Security]]

## References

- [NtQueryInformationProcess and supported alternatives](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
- [Using NTSTATUS values](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values)
- [Nt and Zw context](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)
- [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
- [RtlNtStatusToDosError](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror)
