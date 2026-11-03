---
title: "Objects and Handles"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Objects and Handles Security]]"
updated: 2026-11-03
---
# Objects and Handles

> [!abstract] TL;DR
> Request minimum rights, close owned handles once, and restrict inheritance. Treat a privileged handle as a capability, not merely an integer.

> [!info] Agent scope
> Object manager; namespaces; handle tables; reference lifetime; duplication; access masks; inheritance.

## Prerequisites

- C++ ownership, access masks, and [[Windows Lab Setup]].
- Windows 11 x64, installed VS 2022 MSVC v143/Windows SDK 10.0.22621+, x64 Native Tools Command Prompt, standard user.

## Learn

```text
Teach Windows objects and handles at expert engineering depth. Assume C++ lifetime
and basic access masks. Explain object-manager typed objects, namespaces, names
versus per-process handle-table entries, granted rights, standard/specific/generic
masks, kernel references versus handles, and type-specific destruction. Cover
CloseHandle ownership, pseudo handles, Get/SetHandleInformation, duplication,
shared file positions, inheritance and explicit child handle lists. Explain
Local/Global namespaces, ACLs, name collisions, ERROR_ALREADY_EXISTS, stale handle
reuse and close-while-waiting races. Provide a complete named self-process event
lab with a current-user DACL, query/wait-only open, explicit duplicate, original
handle closure and retained event access. Use public Microsoft docs, exact build
and cleanup commands, and predicted results clearly marked. No arbitrary-process
access, privilege escalation, exploitation or private data. Teach in chat; do not
author files or change study progress.
```

## Cheatsheet

### Three Different Identities

An object is a typed kernel-managed resource with state and security. A name optionally exposes it through a namespace. A handle is a process-local reference with a granted access mask and attributes. A handle's integer value is not a permanent object ID, not a pointer to the object, and not meaningful in a different process unless inheritance/duplication deliberately established a corresponding entry.

Opening a named object requests rights and performs the relevant security checks. Later APIs check the granted handle rights and operation-specific rules. Changing the DACL generally affects later opens, not authority already granted through existing handles. Duplicate or inherited handles can preserve authority without another pathname lookup. Therefore ownership and distribution of handles matter as much as names and ACLs.

Closing an owned handle releases that reference. An unnamed event normally disappears after the last reference is gone; named-object lifetime also depends on object type and other references. A file's directory entry and file object's lifetime are different concepts. Kernel references, pending I/O, mapped views and other handles can outlive a particular handle closure. Never infer destruction solely from closing your own handle.

### Masks and Resource Families

| Kind | Contract |
| --- | --- |
| Standard rights | `READ_CONTROL` reads ordinary security information; `WRITE_DAC` changes DACL; `WRITE_OWNER` changes owner subject to policy; `DELETE` is type-specific deletion authority; `SYNCHRONIZE` permits waits where supported |
| Object-specific rights | Event `EVENT_MODIFY_STATE` permits Set/ResetEvent; process/file/key rights have different meanings even if numeric bits overlap |
| Generic rights | `GENERIC_READ/WRITE/EXECUTE/ALL` map to object-specific sets; custom access checks require the correct `GENERIC_MAPPING` |
| `MAXIMUM_ALLOWED` | Requests all rights policy will grant, not the minimum needed; poor default for a constrained consumer |
| Kernel handles | Process/thread/event/file/section handles normally close with `CloseHandle`; failure sentinels vary by creator |
| Other resource families | Registry keys use `RegCloseKey`; modules use `FreeLibrary`; sockets use `closesocket`. Do not generalize from the typedef spelling |

`GetCurrentProcess` and `GetCurrentThread` return pseudo-handles interpreted relative to the caller. Do not close them as owned resources. Passing a thread pseudo-handle to another thread does not identify the original thread; acquire an actual reference if identity must survive that change of context.

### Duplicate and Inherit

`DuplicateHandle(sourceProcess, source, targetProcess, &target, desired, inherit, options)` returns `BOOL`; failure uses last error. Process handles need `PROCESS_DUP_HANDLE`; the source is interpreted in the source process, the result in the target. `DUPLICATE_SAME_ACCESS` ignores `desired`. `DUPLICATE_CLOSE_SOURCE` closes the source even on error, so avoid it in simple copy-ownership code. Right increases are object-dependent and must not be assumed; the labs only deliberately reduce rights.

A duplicate refers to the same underlying object. Event state is shared; file duplicates share current file position, while separate opens can have independent file objects. Both owned handles must close exactly once. `bInheritHandle` affects the new handle's eligibility for future child inheritance, not whether duplication itself occurs.

`SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)` clears inheritance; it does not reduce access rights. `HANDLE_FLAG_PROTECT_FROM_CLOSE` is an accidental-close guard, not a security boundary. Normal process creation with inheritance enabled can transfer every eligible handle. Use `STARTUPINFOEXW` and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` for a deliberate allowlist; entries must be inheritable and creation still uses `bInheritHandles=TRUE`. See [[Objects and Handles Security]] for a complete self-child example.

### Namespaces and Collisions

Named events, mutexes and several other kernel objects share namespaces. `Local\` explicitly selects the session namespace; `Global\` selects the global namespace. Global **file mapping creation** can require `SeCreateGlobalPrivilege` outside session zero; do not apply that rule indiscriminately to every named object or to opening an existing mapping. Namespace reach and DACL permission are independent.

`CreateEventW` returns a handle to an existing event if the name exists, setting last error to `ERROR_ALREADY_EXISTS`; its requested reset/initial-state/security parameters do not recreate or resecure that object. Another object type with the same name can cause failure. `CreateEventW` requests `EVENT_ALL_ACCESS` for an existing event; `CreateEventExW` lets a caller specify desired access. Reject unexpected existing objects instead of trusting their state or ACL. An unpredictable name lowers collisions but does not replace a DACL. Private namespaces are a separate design option for stronger name isolation.

## Gotchas

- Double-close can hit an unrelated newly allocated handle if the number was reused.
- Closing a handle while another thread waits on it has undefined behavior; join/quiesce before closing.
- A successful `GetHandleInformation` verifies attributes of the current handle entry, not object identity or trust.
- Default security descriptors depend on effective creation context. Use explicit ACLs when the intended boundary matters.

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No compiler/runtime, VM, separate-identity or namespace-policy test was performed during authoring. Results are expected. This lab checks self-process rights and references, not cross-user isolation or global namespace behavior.

Create a fresh folder in the developer prompt. Only `objects.cpp` is needed. It obtains the current token's SID locally, creates a DACL granting that SID wait/modify rights, and never prints personal identity data. Advapi32 is supplied by the Windows SDK.

```bat
mkdir x1-objects
cd x1-objects
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>
#include <vector>

int wmain() {
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 1;
	DWORD needed = 0;
	BOOL probe = GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
	DWORD error = probe ? ERROR_SUCCESS : GetLastError();
	if (probe || error != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 65536) {
		CloseHandle(token); return 2;
	}
	std::vector<unsigned char> storage(needed);
	if (!GetTokenInformation(token, TokenUser, storage.data(), needed, &needed)) {
		CloseHandle(token); return 3;
	}
	CloseHandle(token);
	auto* user = reinterpret_cast<TOKEN_USER*>(storage.data());
	LPWSTR sid = nullptr;
	if (!ConvertSidToStringSidW(user->User.Sid, &sid)) return 4;
	std::wstring sddl = L"D:P(A;;0x00100002;;;" + std::wstring(sid) + L")";
	LocalFree(sid);
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
		SDDL_REVISION_1, &descriptor, nullptr)) return 5;
	SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
	std::wstring name = L"Local\\HackVault.Event." + std::to_wstring(GetCurrentProcessId());
	HANDLE owner = CreateEventW(&attributes, TRUE, FALSE, name.c_str());
	DWORD creationError = GetLastError();
	LocalFree(descriptor);
	if (!owner) return 6;
	if (creationError == ERROR_ALREADY_EXISTS) { CloseHandle(owner); return 7; }
	HANDLE observer = OpenEventW(SYNCHRONIZE, FALSE, name.c_str());
	if (!observer) { CloseHandle(owner); return 8; }
	HANDLE duplicate = nullptr;
	bool passed = DuplicateHandle(GetCurrentProcess(), observer, GetCurrentProcess(),
								   &duplicate, SYNCHRONIZE, FALSE, 0) != FALSE;
	if (!SetEvent(owner)) passed = false;
	CloseHandle(owner);
	CloseHandle(observer);
	if (!duplicate) return 9;
	DWORD waited = WaitForSingleObject(duplicate, 0);
	BOOL modified = ResetEvent(duplicate);
	DWORD denied = modified ? ERROR_SUCCESS : GetLastError();
	passed = passed && waited == WAIT_OBJECT_0 && !modified && denied == ERROR_ACCESS_DENIED;
	if (!CloseHandle(duplicate)) passed = false;
	std::printf("retained-wait=%d modify-error=%lu checks=%d\n",
				waited == WAIT_OBJECT_0, denied, passed);
	return passed ? 0 : 10;
}
```

### Objectives and Steps

1. Decode mask `0x00100002`: `SYNCHRONIZE | EVENT_MODIFY_STATE`.
2. Predict which state survives closure of the creating and observing handles.
3. Explain why the limited duplicate cannot reset the event even though the same user created it.

```bat
cl /nologo /W4 /EHsc /std:c++17 objects.cpp /Fe:objects.exe /link Advapi32.lib /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
objects.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The named open performs a rights request; the duplicate carries only wait authority. The DACL permits more than the observer requested, but the observer's granted handle mask remains limited. The event is manual-reset, so waiting does not clear it.

### Solution and Expected Results

The creator signals the event and closes its handle. The observer closes too, but the duplicate keeps a reference to the same signaled object. Wait succeeds; `ResetEvent` requires the omitted modify right and returns error 5. Expected `retained-wait=1 modify-error=5 checks=1`, exit zero. The final close removes the lab's last reference; there is no persistence after all handles are gone.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe retained wait, denied modification and zero exit.
- [ ] Explain name, object, handle entry and granted mask independently.
- [ ] Record Windows/compiler versions and any unexpected collision or access result.

Exit 7 indicates an unexpected existing name; abort rather than using that object. Failure under a restricted token may reflect missing assumptions about the token/DACL; record it without granting broad rights. The SID is used only in memory and no ACL is applied to an existing user resource.

```bat
del objects.exe objects.obj
```

Remove the source directory when done; no persistent object or registry configuration is created.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Objects and Handles Security]]

## References

- [Object handles](https://learn.microsoft.com/en-us/windows/win32/sysinfo/object-handles)
- [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [CreateEventW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw)
- [Kernel object namespaces](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces)
- [Synchronization object security](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights)
