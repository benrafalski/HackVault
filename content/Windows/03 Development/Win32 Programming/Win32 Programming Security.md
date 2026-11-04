---
title: "Win32 Programming Security"
aliases: []
tags: [windows, x3, security]
domain: windows
phase: "X3"
type: security
status: draft
pair: "[[Win32 Programming]]"
updated: 2026-11-03
---
# Win32 Programming Security

> [!abstract] TL;DR
> Unchecked errors, integer/length mistakes, excessive access masks, and asynchronous lifetime defects can cause corruption or privilege misuse.

> [!info] Agent scope
> Security of: Unicode APIs; handles; process and file APIs; synchronization; errors; asynchronous I/O; access-right minimization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Integer/length boundaries, error-dependent output validity, access masks, pathname resolution, handle inheritance and pending I/O ownership. Native API success is not a business authorization decision.
- The lab uses a synthetic current-user file with a deliberately read-only DACL. No protected files, other processes, privilege adjustments, or host controls are touched.

## Learn

```text
Teach me defensive Win32 C++ engineering at expert depth. Assume knowledge of
Windows ACLs and RAII. Derive access-mask minimization, share versus permission
failures, Unicode/NUL/length contracts, checked arithmetic, noninheritable handle
ownership, asynchronous completion/cancellation and output validity on failure.
Use a harmless file with a controlled DACL to compare excessive read/write access
against minimum read access. Include bounded malformed-input tests, error-path
cleanup and handle-count evidence, with limitations. Explain path/reparse races,
trusted directory design, application manifests, compiler hardening, process
query rights and why elevation is not a fix. Use official sources and versioned
contracts. No offensive actions, host-control changes or real protected targets.
Teach here, not by authoring notes/files; end with worked boundary reviews.
```

## Cheatsheet

### Root Causes and Correctness Rules

| Defect | Observable consequence | Fix and remaining limit |
|---|---|---|
| Reader asks for `GENERIC_WRITE` too | Read-only DACL denies an otherwise legitimate read | Request `GENERIC_READ`; this does not authorize unrelated operations |
| Consumes out buffer after failed call | Stale/uninitialized data influences later decisions | Branch on documented return value before consuming outputs |
| `count * sizeof(T)` overflows | Underallocation relative to later access | Validate count, use checked size arithmetic and match API widths |
| Cancels then frees | Kernel completion still uses released state | Cancel, observe final completion, then release all request-owned state |
| Path string checked then reopened | Rename/reparse races can change target | Keep the opened handle; use trusted directory ownership and handle-based validation |
| Broad inherited handles | Child receives unintended capabilities | Default noninheritance; explicit allowlist when inheritance is necessary |
| Logging calls before reading last error | Wrong error reported | Capture immediately, log stored numeric code |

ACL denial is `ERROR_ACCESS_DENIED` (5); sharing conflict is commonly `ERROR_SHARING_VIOLATION` (32); nonexistent file is `ERROR_FILE_NOT_FOUND` (2). The same high-level symptom can have different causes. Do not retry with administrator rights or request `*_ALL_ACCESS` as a default.

For process introspection, query only your authorized target and prefer `PROCESS_QUERY_LIMITED_INFORMATION`; protected processes may still deny access. Handle values are process-local capabilities, not global IDs or pointers. Duplicating/inheriting a handle creates an additional ownership obligation; closing one reference does not revoke all duplicates.

### Input, Filesystem, and Build Policy

- `CreateFileW` consumes a NUL-terminated UTF-16 path. When converting length-delimited input, reject embedded NUL where truncation would change identity. Avoid ANSI fallbacks.
- Validate syntax and maximum size before narrowing to `DWORD`; keep actual bytes read separate from requested capacity. A zero-byte read can be EOF, not proof of failure.
- A safe filename regex does not establish a safe directory. The lab accepts caller-owned paths only and runs unprivileged; a privileged service would need a stronger handle/root/ACL design. `FILE_FLAG_OPEN_REPARSE_POINT` alone does not prevent all intermediate-component traversal.
- `/W4 /WX /sdl /GS /guard:cf` plus linker `/DYNAMICBASE /NXCOMPAT` provide useful diagnostics/mitigations; they do not prove bounds, lifetime, or authorization correctness. Do not disable mitigations to make the lab pass.
- On cancellation, `ERROR_NOT_FOUND` from `CancelIoEx` can mean completion won the race. Drain the operation anyway. Never return stack-backed `OVERLAPPED` while pending.

## Detection and Defense

- Capture operation name, requested rights, numeric Win32 result and final byte count without exposing file contents. Separate expected ACL denial from program faults.
- Compare handle counts after warm-up over repeated operations; stable counts are supporting evidence, not proof of absence of every leak. Crash-free runs do not establish memory safety under concurrent cancellation.
- Audit DACL changes only for the synthetic fixture here. Production SACL/auditing changes require a separate approved deployment, not a teaching script.

## Labs

### Environment and Complete Files

Windows 11 x64, MSVC v143/Windows SDK 10.0.26100.x, PowerShell 7. Standard-user token, even if your account can elevate. No packages. Create `$env:TEMP\X3-Win32Security` and these two files. The PowerShell harness restores the original file ACL in `finally`.

`Reader.cpp`:

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <array>
#include <cstdio>
#include <cwchar>
#include <system_error>

[[noreturn]] void Fail(DWORD code, const char* operation) {
	throw std::system_error(static_cast<int>(code), std::system_category(), operation);
}
struct Handle {
	HANDLE value;
	explicit Handle(HANDLE raw) : value(raw) {
		if (raw == nullptr || raw == INVALID_HANDLE_VALUE) Fail(GetLastError(), "open");
	}
	~Handle() { CloseHandle(value); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
};

DWORD Read(const wchar_t* path, DWORD access, DWORD count) {
	Handle file(CreateFileW(path, access, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr));
	Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
	OVERLAPPED operation{};
	operation.hEvent = event.value;
	std::array<BYTE, 4096> bytes{};
	if (!ReadFile(file.value, bytes.data(), count, nullptr, &operation)) {
		DWORD error = GetLastError();
		if (error == ERROR_HANDLE_EOF) return 0;
		if (error != ERROR_IO_PENDING) Fail(error, "submit");
	}
	DWORD received = 0;
	if (!GetOverlappedResult(file.value, &operation, &received, TRUE)) {
		DWORD error = GetLastError();
		if (error == ERROR_HANDLE_EOF) return 0;
		Fail(error, "completion");
	}
	if (received > count) Fail(ERROR_INVALID_DATA, "byte contract");
	return received;
}

int wmain(int argc, wchar_t** argv) {
	if (argc != 4) return 64;
	bool broad = std::wcscmp(argv[1], L"broad") == 0;
	if (!broad && std::wcscmp(argv[1], L"read") != 0) return 64;
	DWORD count = 0;
	size_t digits = std::wcslen(argv[3]);
	if (digits == 0 || digits > 4) return 64;
	for (size_t index = 0; index < digits; ++index) {
		wchar_t character = argv[3][index];
		if (character < L'0' || character > L'9') return 64;
		count = count * 10 + static_cast<DWORD>(character - L'0');
	}
	if (count == 0 || count > 4096) return 64;
	try {
		DWORD access = GENERIC_READ | (broad ? GENERIC_WRITE : 0);
		DWORD received = Read(argv[2], access, count);
		DWORD before = 0;
		if (!GetProcessHandleCount(GetCurrentProcess(), &before)) Fail(GetLastError(), "count before");
		for (int attempt = 0; attempt < 128; ++attempt)
			if (Read(argv[2], access, count) != received) Fail(ERROR_INVALID_DATA, "unstable fixture");
		DWORD after = 0;
		if (!GetProcessHandleCount(GetCurrentProcess(), &after)) Fail(GetLastError(), "count after");
		std::wprintf(L"bytes=%lu; handles-before=%lu; handles-after=%lu\n", received, before, after);
		if (before != after) return 3;
		return 0;
	} catch (const std::system_error& error) {
		std::fprintf(stderr, "win32=%d; %s\n", error.code().value(), error.what());
		return error.code().value() == ERROR_ACCESS_DENIED ? 2 : 1;
	}
}
```

`Check.ps1`:

```powershell
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
	throw 'Use a non-elevated terminal'
}
$path = Join-Path $PSScriptRoot 'fixture.txt'
if (Test-Path -LiteralPath $path) { throw 'Fixture already exists; inspect before rerun' }
[System.IO.File]::WriteAllBytes($path, [byte[]](65,66,67))
$original = Get-Acl -LiteralPath $path
try {
	$readOnly = [System.Security.AccessControl.FileSecurity]::new()
	$readOnly.SetOwner($identity.User)
	$readOnly.SetAccessRuleProtection($true, $false)
	$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
		$identity.User, [System.Security.AccessControl.FileSystemRights]::Read,
		[System.Security.AccessControl.AccessControlType]::Allow)
	$readOnly.AddAccessRule($rule)
	Set-Acl -LiteralPath $path -AclObject $readOnly
	& "$PSScriptRoot\Reader.exe" broad $path 3
	if ($LASTEXITCODE -ne 2) { throw 'Baseline must fail with access denied' }
	& "$PSScriptRoot\Reader.exe" read $path 3
	if ($LASTEXITCODE -ne 0) { throw 'Least-privilege read failed' }
	foreach ($count in @('0','4097','-1','abc','999999999999')) {
		& "$PSScriptRoot\Reader.exe" read $path $count
		if ($LASTEXITCODE -ne 64) { throw "Expected input rejection: $count" }
	}
	& "$PSScriptRoot\Reader.exe" read ($path + '.absent') 3
	if ($LASTEXITCODE -ne 1) { throw 'Missing file did not fail cleanly' }
	$exclusive = [System.IO.File]::Open($path, 'Open', 'Read', 'None')
	$exclusive.Dispose()
	'PASS: access masks, bounded input, error paths, stable handles, exclusive reopen'
} finally {
	Set-Acl -LiteralPath $path -AclObject $original
	Remove-Item -LiteralPath $path
	$identity.Dispose()
}
```

### Objectives and Baseline

```powershell
Set-Location "$env:TEMP\X3-Win32Security"
cl /nologo /std:c++17 /EHsc /W4 /WX /sdl /GS /guard:cf Reader.cpp /Fe:Reader.exe /link /DYNAMICBASE /NXCOMPAT
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
pwsh -NoProfile -File .\Check.ps1
if ($LASTEXITCODE -ne 0) { throw 'Checks failed' }
```

Explain why the file owner can restore its DACL but a read/write open still fails under the current DACL. Identify the first point at which the byte count becomes valid and the last use of the event and buffer. The fixture owner is not a hostile security principal; this is an API access-right regression, not an isolation test against the owner.

### Hints

`GENERIC_READ | GENERIC_WRITE` asks the object manager to grant both. Removing unnecessary write access repairs the reader without widening the ACL. Validation occurs before `Read`, so invalid counts cannot trigger a file open or overflow the fixed buffer.

### Solution and Fixed Retest

The fixed `read` mode retains exactly the same file ACL and data as `broad`. Expected: baseline `win32=5`, exit 2; fixed `bytes=3` and equal handle counts, exit 0; five bad counts exit 64; missing file exits 1; exclusive reopen succeeds. No output contents are logged. The OVERLAPPED, event and buffer stay in scope until `GetOverlappedResult` finishes.

### Verification, Troubleshooting, and Cleanup

No builds/tests were executed during authoring. A non-NTFS filesystem or managed policy can invalidate the ACL fixture assumptions; use an approved local NTFS temp directory. If interrupted after ACL replacement, the current user remains owner and can restore inheritance on this lab file through its Security dialog, then delete it. Do not change any parent-directory ACL. Equal handle counts do not test cancellation races; the paired note covers drain semantics.

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-Win32Security" -Recurse -Force
```

- [ ] Local Win32 Programming exercise: Build a Unicode file-copy toy with bounded buffers, explicit access masks, cancellation, and cleanup. Test missing files, denied access, and cancellation mid-operation.
- [ ] Boundary check: Run the toy under a restricted identity and verify denied access is handled without using invalid outputs or leaking handles.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[Win32 Programming]]

## References

- [File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
- [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
- [GetProcessHandleCount](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesshandlecount)
- [Control Flow Guard compiler option](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
