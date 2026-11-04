---
title: "Win32 Programming"
aliases: []
tags: [windows, x3]
domain: windows
phase: "X3"
type: tech
status: draft
pair: "[[Win32 Programming Security]]"
updated: 2026-11-03
---
# Win32 Programming

> [!abstract] TL;DR
> Check return values immediately, capture GetLastError only when the API contract requires it, and track ownership/lifetime for every resource.

> [!info] Agent scope
> Unicode APIs; handles; process and file APIs; synchronization; errors; asynchronous I/O; access-right minimization.

## Prerequisites

- Windows 11 x64, Visual Studio 2022 Build Tools with Desktop development with C++, MSVC v143 and Windows 11 SDK 10.0.26100.x already installed. Use an x64 Native Tools command environment and PowerShell 7; no elevation or external libraries.
- C++17 RAII, exceptions, basic Windows access masks and [[Windows Lab Setup]]. This is a regular user-mode console application, not a driver.

## Learn

```text
Teach me native Win32 programming at expert depth, assuming C++17 and Windows
ACL basics. Explain W APIs/UTF-16, handle versus pointer identity, pseudo-handles,
access/share/disposition flags, process query rights, RAII and error conventions.
Trace an overlapped ReadFile/WriteFile through immediate success, pending,
completion, cancellation races and cleanup. Explain event reset rules, buffer
and OVERLAPPED ownership, partial transfers, offsets, EOF, timeouts and IOCP
scaling. Build a bounded Unicode copy example plus process-image query with
minimal rights; provide exact build/run/failure checks and explain each ABI.
Contrast events, mutexes, critical sections and SRW locks; cover inherited
handles and command-line construction. Use public primary sources. No process
manipulation, offensive techniques or host-control changes. Teach here rather
than writing notes, and give worked lifecycle/error-path reasoning questions.
```

## Cheatsheet

### API Contracts

| API/result | Correct interpretation | Lifetime/privilege |
|---|---|---|
| `CreateFileW` | `INVALID_HANDLE_VALUE` on failure; `GetLastError` immediately | Close with `CloseHandle`; request only needed data access |
| `CreateEventW`/`OpenProcess` | null on failure, not `INVALID_HANDLE_VALUE` | Kernel handles need `CloseHandle`; noninheritable by default here |
| `GetCurrentProcess` | Pseudo-handle to caller | Do not put borrowed pseudo-handles in owning wrappers |
| `QueryFullProcessImageNameW` | BOOL; size in UTF-16 code units | `PROCESS_QUERY_LIMITED_INFORMATION` normally sufficient; protected process rules still apply |
| `ReadFile` with OVERLAPPED | TRUE immediate; FALSE + `ERROR_IO_PENDING` accepted; other errors terminal | Buffer and OVERLAPPED survive until completion |
| `GetOverlappedResult` | BOOL and final byte count | `bWait=TRUE` waits on the operation event; only consume outputs on success |
| `CancelIoEx` | Requests cancellation, does not await it; `ERROR_NOT_FOUND` may mean already completed | Still drain completion before releasing state |
| `WaitForSingleObject` | `WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_ABANDONED`, `WAIT_FAILED` differ | Mutex abandonment requires invariant recovery; only WAIT_FAILED uses last error |

Use explicit `W` APIs and UTF-16 buffers. Counts may be characters, bytes, or include/exclude a terminator depending on the API. `sizeof(wchar_t)` is two on Windows; it is not the number of characters in a string. `MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ...)` rejects malformed UTF-8 rather than silently using an ANSI code page. Long-path support depends on the application's manifest and OS policy; the lab uses short temporary paths and does not change policy.

`CreateFileW` access, share, creation disposition, and flags are independent. `GENERIC_READ` asks for read rights; `FILE_SHARE_READ` allows other readers, not writers/deleters. `CREATE_NEW` refuses existing destinations, avoiding accidental overwrite and same-file copying. Share violations are not ACL denial. Returning a path string from an earlier lookup does not bind it to a future object: trusted-directory ownership and opened-handle checks matter when other users can rename/reparse paths.

### Asynchronous State Machine

1. Allocate stable buffer, zeroed `OVERLAPPED`, offsets, and a manual-reset event. One live operation owns that state.
2. Submit. Immediate success is still completion; pending is not failure. Do not resubmit using the same structure before the operation finishes.
3. Optionally request cancellation. Completion can win, so success after cancellation request is legal.
4. Observe the final completion, then inspect byte count/status. Only now reuse/free buffer/event/OVERLAPPED.
5. Advance offsets by actual transferred bytes, handle short writes, reject zero-progress writes, and close handles after all operations drain.

The lab creates a fresh event per transfer; a reusable manual-reset event must be reset before each new operation. Serial submission with overlapped handles demonstrates contracts, not throughput. A scalable copier can use IOCP, bounded in-flight buffers and completion-owned state. A timeout is a policy decision to request cancellation and drain, not permission to free pending memory.

### Synchronization and Process Creation

- Critical sections and SRW locks synchronize threads within a process; SRW locks are not recursive. Kernel mutexes/events can synchronize processes when correctly named and ACL-protected. An event signals a condition but does not automatically protect the associated data.
- Acquire locks in one order; avoid calling external callbacks while holding locks. A signaled auto-reset event releases one waiter; manual-reset remains signaled until reset.
- For a child process, `CreateProcessW` takes a separate application path and a mutable command-line buffer. Do not concatenate untrusted arguments; quoting follows the target's parser. Use explicit handle inheritance lists (`STARTUPINFOEX`) when inheritance is needed, and close both returned process/thread handles.
- `GetLastError` after success may be stale or have special API-specific meaning; never use it as a universal status flag. Preserve the numeric code before logging/cleanup calls.

## Gotchas

- `CancelIo` affects calling-thread requests; `CancelIoEx` supports selecting an operation across threads. Neither is completion.
- The file buffer must remain stable even if a C++ container resizes or a task object moves. Keeping only the handle alive is insufficient.
- `FindFirstFile` uses `FindClose`, registry keys use `RegCloseKey`, COM pointers use `Release`; a generic CloseHandle wrapper cannot own all Windows resources.

## Labs

### Environment and Complete Files

Create `$env:TEMP\X3-Win32`, then put `Copy.cpp` there. The program opens only the supplied source and a new destination, and queries its own process image. Cancellation is a race with legal completion, not a deterministic abort requirement.

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <array>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include <system_error>

[[noreturn]] void Fail(DWORD code, const char* operation) {
	throw std::system_error(static_cast<int>(code), std::system_category(), operation);
}
struct Handle {
	HANDLE value;
	explicit Handle(HANDLE handle) : value(handle) {
		if (value == nullptr || value == INVALID_HANDLE_VALUE) Fail(GetLastError(), "create/open");
	}
	~Handle() { CloseHandle(value); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
};
struct Cancelled {};

DWORD Transfer(HANDLE file, bool writing, BYTE* buffer, DWORD capacity,
			   unsigned long long offset, bool cancel) {
	Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
	OVERLAPPED operation{};
	operation.Offset = static_cast<DWORD>(offset);
	operation.OffsetHigh = static_cast<DWORD>(offset >> 32);
	operation.hEvent = event.value;
	BOOL submitted = writing
		? WriteFile(file, buffer, capacity, nullptr, &operation)
		: ReadFile(file, buffer, capacity, nullptr, &operation);
	if (!submitted) {
		DWORD error = GetLastError();
		if (!writing && error == ERROR_HANDLE_EOF) return 0;
		if (error != ERROR_IO_PENDING) Fail(error, "submit");
	}
	DWORD cancelError = ERROR_SUCCESS;
	if (cancel && !CancelIoEx(file, &operation)) {
		cancelError = GetLastError();
		if (cancelError == ERROR_NOT_FOUND) cancelError = ERROR_SUCCESS;
	}
	DWORD transferred = 0;
	BOOL completed = GetOverlappedResult(file, &operation, &transferred, TRUE);
	DWORD completionError = completed ? ERROR_SUCCESS : GetLastError();
	if (cancelError != ERROR_SUCCESS) Fail(cancelError, "cancel after drain");
	if (completionError == ERROR_OPERATION_ABORTED) throw Cancelled{};
	if (!writing && completionError == ERROR_HANDLE_EOF) return 0;
	if (!completed) Fail(completionError, "completion");
	return transferred;
}

void Copy(const wchar_t* source, const wchar_t* destination, bool cancel, bool& created) {
	Handle input(CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr));
	Handle output(CreateFileW(destination, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr));
	created = true;
	std::array<BYTE, 65536> buffer{};
	unsigned long long offset = 0;
	bool requested = false;
	for (;;) {
		bool requestNow = cancel && !requested;
		requested = requested || requestNow;
		DWORD received = Transfer(input.value, false, buffer.data(),
			static_cast<DWORD>(buffer.size()), offset, requestNow);
		if (received == 0) break;
		DWORD written = 0;
		while (written < received) {
			DWORD amount = Transfer(output.value, true, buffer.data() + written,
				received - written, offset + written, false);
			if (amount == 0) throw std::runtime_error("zero-progress write");
			written += amount;
		}
		offset += received;
	}
	if (!FlushFileBuffers(output.value)) Fail(GetLastError(), "flush");
	std::wprintf(L"copied=%llu; cancellation-requested=%d\n", offset, requested ? 1 : 0);
}

int wmain(int argc, wchar_t** argv) {
	if (argc != 3 && !(argc == 4 && std::wcscmp(argv[3], L"--cancel") == 0)) {
		std::fwprintf(stderr, L"usage: Copy source destination [--cancel]\n");
		return 64;
	}
	bool created = false;
	int result = 0;
	try {
		Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId()));
		std::array<wchar_t, 32768> image{};
		DWORD capacity = static_cast<DWORD>(image.size());
		if (!QueryFullProcessImageNameW(process.value, 0, image.data(), &capacity))
			Fail(GetLastError(), "query image");
		std::wprintf(L"image=%ls\n", image.data());
		Copy(argv[1], argv[2], argc == 4, created);
	} catch (const Cancelled&) {
		std::fwprintf(stderr, L"cancelled after completion drain\n"); result = 2;
	} catch (const std::exception& error) {
		std::fprintf(stderr, "%s\n", error.what()); result = 1;
	}
	if (result != 0 && created && !DeleteFileW(argv[2])) {
		DWORD error = GetLastError();
		std::fwprintf(stderr, L"partial-output cleanup failed: %lu\n", error);
	}
	return result;
}
```

### Objectives and Steps

Use an x64 MSVC developer environment. These are instructions only, not author-executed commands:

```powershell
Set-Location "$env:TEMP\X3-Win32"
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /O2 Copy.cpp /Fe:Copy.exe
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
[byte[]]$data = 0..255
[System.IO.File]::WriteAllBytes("$PWD\source.txt", $data * 1024)
.\Copy.exe .\source.txt .\copy.txt
if ($LASTEXITCODE -ne 0) { throw 'Copy failed' }
if ((Get-FileHash .\source.txt).Hash -ne (Get-FileHash .\copy.txt).Hash) { throw 'Hash mismatch' }
.\Copy.exe .\source.txt .\copy.txt
if ($LASTEXITCODE -ne 1) { throw 'Existing destination should fail' }
.\Copy.exe .\absent.txt .\missing-copy.txt
if ($LASTEXITCODE -ne 1 -or (Test-Path .\missing-copy.txt)) { throw 'Missing-source handling failed' }
.\Copy.exe .\source.txt .\cancel-copy.txt --cancel
$cancelExit = $LASTEXITCODE
if ($cancelExit -eq 0) {
	if ((Get-FileHash .\source.txt).Hash -ne (Get-FileHash .\cancel-copy.txt).Hash) { throw 'Race winner corrupted data' }
} elseif ($cancelExit -eq 2) {
	if (Test-Path .\cancel-copy.txt) { throw 'Partial output left behind' }
} else { throw "Unexpected cancellation result: $cancelExit" }
[System.IO.File]::WriteAllBytes("$PWD\empty.txt", [byte[]]@())
.\Copy.exe .\empty.txt .\empty-copy.txt
if ($LASTEXITCODE -ne 0 -or (Get-Item .\empty-copy.txt).Length -ne 0) { throw 'EOF failed' }
```

Run these additional checks from the same directory as a standard user on local NTFS. The filename is constructed from explicit Unicode code points; no locale setting changes. The ACL test changes only its own new synthetic file, retaining the current user as owner so `finally` can restore the original DACL.

```powershell
$unicodeSource = Join-Path $PWD (([char]0x03A9).ToString() + ([char]0x4E2D).ToString() + '.txt')
$unicodeCopy = Join-Path $PWD 'unicode-copy.txt'
[System.IO.File]::WriteAllBytes($unicodeSource, [byte[]](65,66,67))
.\Copy.exe $unicodeSource $unicodeCopy
if ($LASTEXITCODE -ne 0) { throw 'Unicode copy failed' }
if ((Get-FileHash -LiteralPath $unicodeSource).Hash -ne (Get-FileHash $unicodeCopy).Hash) {
	throw 'Unicode hash mismatch'
}
$deniedSource = Join-Path $PWD 'denied-source.txt'
if (Test-Path -LiteralPath $deniedSource) { throw 'Inspect existing ACL fixture before rerun' }
[System.IO.File]::WriteAllBytes($deniedSource, [byte[]](65,66,67))
$originalAcl = Get-Acl -LiteralPath $deniedSource
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
try {
	$writeOnly = [System.Security.AccessControl.FileSecurity]::new()
	$writeOnly.SetOwner($identity.User)
	$writeOnly.SetAccessRuleProtection($true, $false)
	$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
		$identity.User, [System.Security.AccessControl.FileSystemRights]::Write,
		[System.Security.AccessControl.AccessControlType]::Allow)
	$writeOnly.AddAccessRule($rule)
	Set-Acl -LiteralPath $deniedSource -AclObject $writeOnly
	.\Copy.exe $deniedSource .\denied-copy.txt
	if ($LASTEXITCODE -ne 1 -or (Test-Path .\denied-copy.txt)) { throw 'Denied read mishandled' }
} finally {
	Set-Acl -LiteralPath $deniedSource -AclObject $originalAcl
	Remove-Item -LiteralPath $deniedSource
	$identity.Dispose()
}
```

Expected: Unicode hashes match; the write-only source cannot be opened for reading and no destination is created. This tests access failure independently of missing-file and sharing failures, without opening protected system files.

### Hints

`CREATE_NEW` is the nonoverwrite invariant. The boolean `created` means this process owns the right to remove that new output on failure. A cancellation request can lose to a cached file read; treating success as failure would be an incorrect test. EOF is not a successful write of zero bytes.

### Solution and Expected Results

The printed code is the solution. Normal copy is 262144 bytes with matching hashes, duplicate destination and missing source return 1, empty copy returns 0, and cancellation either returns 2 with no destination or 0 with a complete matching destination. File/event/OVERLAPPED/buffer lifetimes remain valid through final completion in both branches. A cleanup error is reported rather than silently treated as success.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Disk/cache timing means the lab cannot promise an aborted request on every machine. Parent validation should retain exit codes/hash results and review lifetime ordering; a single passing run does not stress concurrent cancellation or IOCP. `/WX` makes compiler diagnostics a gate. Run as a standard user, not elevated to conceal ACL failures.

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-Win32" -Recurse -Force
```

- [ ] Local Win32 Programming exercise: Build a Unicode file-copy toy with bounded buffers, explicit access masks, cancellation, and cleanup. Test missing files, denied access, and cancellation mid-operation.
- [ ] Boundary check: Run the toy under a restricted identity and verify denied access is handled without using invalid outputs or leaking handles.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[Win32 Programming Security]]

## References

- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Synchronous and asynchronous I/O](https://learn.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o)
- [Canceling pending I/O](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations)
- [GetOverlappedResult](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult)
- [Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Synchronization objects](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-objects)
