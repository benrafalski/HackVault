---
title: "Win32 Native API and Syscalls Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Win32 Native API and Syscalls]]"
updated: 2026-11-03
---
# Win32 Native API and Syscalls Security

> [!abstract] TL;DR
> Undocumented assumptions, mismatched structures, and belief that lower-level calls bypass authorization can produce fragile or unsafe software.

> [!info] Agent scope
> Security of: Win32 versus Native API contracts; ntdll; syscall boundary; handles and status codes; version-sensitive behavior. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Wrong failure sentinels, stale last-error values, incorrect length units, and mismatched ABI declarations can turn ordinary API failures into unsafe state.
- Resource authorization belongs at the actual object/handle boundary. A user-mode API family is not a privilege grant.

## Learn

```text
Teach defensive Win32/Native API contract validation at expert depth. Assume C++
and Windows handles. Explain why BOOL, HANDLE, LSTATUS, HRESULT and NTSTATUS need
distinct success predicates, how stale last error and partial output cause bugs,
and how to validate byte lengths, architecture, structures and asynchronous
lifetimes. Cover supported Win32 alternatives to unstable Native interfaces,
signed NTSTATUS semantics, pending results and kernel authorization independent
of user-mode entry names. Give a complete benign self-process file exercise:
create synthetic data, demonstrate an unnecessarily writable handle, transfer
read-only rights, prove the identical write is denied and the read still succeeds.
Capture exact errors before cleanup and use the correct invalid-handle sentinel.
Include code, setup, checks, worked results and cleanup. No direct syscall code,
evasion, unhooking, bypasses, arbitrary process memory access or private data.
Use Microsoft primary sources, label unverified results, and teach rather than
authoring files or marking progress.
```

## Cheatsheet

### Validate the Contract Before the Data

| Defect | Correct rule | Consequence of getting it wrong |
| --- | --- | --- |
| `if (file)` after `CreateFileW` | Compare with `INVALID_HANDLE_VALUE` | Failure is a nonnull value; invalid resource can enter the ownership graph |
| `if (status)` for NTSTATUS | Use signed `NT_SUCCESS` semantics, then API-specific completion rules | Zero success is rejected while nonzero failure can be accepted |
| Read `GetLastError` after logging/cleanup | Capture immediately after documented failure | Another call can overwrite the evidence |
| Treat `RegGetValueW` as BOOL | Compare returned `LSTATUS` to `ERROR_SUCCESS` | Success and failure logic is inverted |
| Treat HRESULT as Boolean | Use `SUCCEEDED`/`FAILED`, inspect special success values | `S_FALSE` is not general failure |
| Trust a queried size forever | Bound allocation and retries; check the fetch result and actual length | Concurrent data growth invalidates the probe |
| Guess native structure packing | Use SDK/public definitions and exact pointer/length widths | ABI mismatch corrupts interpretation even when the call returns |

NTSTATUS includes warnings and informational results, not just zero and fatal errors. `STATUS_PENDING` falls in the success class but is not completed I/O. A buffer must stay valid through completion; canceling an operation is not proof that its completion has been observed. Never close an event or free an `OVERLAPPED`/buffer while an operation may still use it. APIs with partial output need their own rules; don't consume all fields merely because some bytes were returned.

`UNICODE_STRING` lengths are bytes and need not include a terminator. Win32 wide-string capacities often use characters instead. `DWORD` is 32 bits on x64, `SIZE_T` and pointers are pointer-sized, and Win32 `BOOL` is not C++ `bool`. Bindings must match calling convention and layout, not merely names. Runtime export discovery provides an absence check, not a signature guarantee.

### Rights and Error Semantics in a Real Operation

The lab creates only `api-marker.bin` in a fresh user-owned directory with `CREATE_NEW`, so an existing file is never overwritten. The owned file handle has read/write/delete access and `FILE_FLAG_DELETE_ON_CLOSE`. A baseline `WriteFile` of the same synthetic byte succeeds. `DuplicateHandle` then creates a noninheritable reader with `FILE_GENERIC_READ`; options are zero, **not** `DUPLICATE_SAME_ACCESS`, which would ignore the requested reduction. The original owner closes, and the same `WriteFile` on the reader must fail with error 5. `ReadFile` still returns the byte.

This verifies file-handle rights on a genuine kernel-backed file object. It does not change the DACL and does not prevent same-process code from attempting a separate open. A duplicate shares file position and file object state; reset the position explicitly before the positive read. Do not interpret a sharing violation as an ACL denial: share modes constrain compatibility among opens, whereas access masks and security policy govern authority.

### Native Boundaries and Versions

`ntdll` provides both user-mode helpers and Native entry points. Internal information classes and structures are build-sensitive; prefer documented Win32 contracts. Kernel resource policy is still applied to requests made from user mode. This page supplies no alternate access path, service numbers or transition instructions. The lab verifies the supported interface only; it is not evidence that two API layers generated identical requests or statuses.

For native diagnostics, log the original NTSTATUS in hex; only translate with a documented function when needed. A Win32 translation can lose distinctions, and last error may be unrelated to the native result. On a build mismatch, disable the optional observation or use the supported alternative rather than guessing private fields.

## Detection and Defense

Record API name, object owned by the test, requested/granted purpose, return sentinel, immediate error and output byte count only when valid. Redact real paths/data outside the synthetic lab. Repeated denial can be correct enforcement, not an API failure to work around. Event collection and file auditing require separate configuration; this program's checks are not a claim that an external audit record exists. Review bindings and ownership on every error branch, not only the success path.

## Labs

### Environment and Complete Files

Windows 11 x64, installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools Command Prompt. Standard user and a fresh user-writable **local** directory. No services, extra identities, Native entry points or packages. The sole source is `api-rights.cpp`; synthetic file data is created by the program.

> [!warning] Unverified execution
> No compiler/runtime, VM, filesystem-policy test or telemetry collection was run during authoring. Output below is predicted. Cross-layer denial, remote filesystems, asynchronous I/O and other identities are not validated.

```bat
mkdir x1-api-rights
cd x1-api-rights
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>

int main() {
	HANDLE owner = CreateFileW(L"api-marker.bin", GENERIC_READ | GENERIC_WRITE | DELETE,
		0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
	if (owner == INVALID_HANDLE_VALUE) {
		std::printf("create error=%lu\n", GetLastError());
		return 1;
	}
	const char marker = 'L';
	DWORD written = 0;
	BOOL baseline = WriteFile(owner, &marker, 1, &written, nullptr);
	if (!baseline || written != 1) { CloseHandle(owner); return 2; }
	HANDLE reader = nullptr;
	if (!DuplicateHandle(GetCurrentProcess(), owner, GetCurrentProcess(), &reader,
						 FILE_GENERIC_READ, FALSE, 0)) {
		CloseHandle(owner);
		return 3;
	}
	if (!CloseHandle(owner)) { CloseHandle(reader); return 4; }
	owner = INVALID_HANDLE_VALUE;
	DWORD deniedCount = 0;
	BOOL changed = WriteFile(reader, &marker, 1, &deniedCount, nullptr);
	DWORD error = changed ? ERROR_SUCCESS : GetLastError();
	LARGE_INTEGER start{};
	bool positioned = SetFilePointerEx(reader, start, nullptr, FILE_BEGIN) != FALSE;
	char observed = 0;
	DWORD received = 0;
	BOOL read = positioned ? ReadFile(reader, &observed, 1, &received, nullptr) : FALSE;
	bool passed = !changed && error == ERROR_ACCESS_DENIED && read &&
				  received == 1 && observed == marker;
	std::printf("baseline=1 fixed-write=%d error=%lu retained-read=%d\n",
				changed != FALSE, error, read && received == 1 && observed == marker);
	if (!CloseHandle(reader)) passed = false;
	reader = nullptr;
	DWORD attributes = GetFileAttributesW(L"api-marker.bin");
	DWORD lookupError = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
	passed = attributes == INVALID_FILE_ATTRIBUTES &&
			 lookupError == ERROR_FILE_NOT_FOUND && passed;
	std::printf("cleanup-and-checks=%d\n", passed);
	return passed ? 0 : 5;
}
```

### Objectives and Baseline

1. Show an allowed baseline write, deny that write after rights reduction, and preserve the read.
2. Identify why `DUPLICATE_SAME_ACCESS` would defeat the intended fix.
3. Confirm deletion occurs only after the last duplicate file handle closes.

```bat
cl /nologo /W4 /EHsc /std:c++17 api-rights.cpp /Fe:api-rights.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
api-rights.exe
echo Exit=%ERRORLEVEL%
if exist api-marker.bin echo FAIL: marker remains
```

### Hints

The reader is a real file handle with a smaller granted mask, not a wrapper Boolean. The file-position reset is necessary because duplicates refer to the same file object. Last error is captured before other API calls.

### Solution and Fixed Retest

Expected line: `baseline=1 fixed-write=0 error=5 retained-read=1`, followed by `cleanup-and-checks=1` and exit zero. The first handle closes before the limited handle is used, so no broad handle is accidentally passed into the retest. Delete-on-close waits until the final relevant handle closes. Repeat the program: `CREATE_NEW` should succeed again because cleanup removed the prior fixture.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe denied write, retained read and absent marker file.
- [ ] Explain failure sentinel, returned status family and cleanup ordering for each API.
- [ ] Record actual OS/toolchain/filesystem and results, including failures.

Error 80/183 on creation means the directory was not clean; inspect the file and use a new directory, never overwrite unrelated data. Error 5 at initial creation indicates a directory/policy prerequisite problem, not the expected reduced-handle denial. Do not elevate. Delete-on-close normally handles error exits as the process releases handles; verify absence before declaring cleanup complete.

```bat
del api-rights.exe api-rights.obj
```

Remove only the source and lab directory you created. No system configuration changed.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Win32 Native API and Syscalls]]

## References

- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)
- [Using NTSTATUS values](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values)
- [NtQueryInformationProcess compatibility warning](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
