---
title: "Objects and Handles Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Objects and Handles]]"
updated: 2026-11-03
---
# Objects and Handles Security

> [!abstract] TL;DR
> Leaked or inherited privileged handles, permissive object ACLs, and confused object names can give a lower-trust process unintended authority.

> [!info] Agent scope
> Security of: Object manager; namespaces; handle tables; reference lifetime; duplication; access masks; inheritance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Handle transfer is authority transfer. A child may need an event wait, not event modification or every inheritable handle in its parent.
- Name collisions, permissive ACLs, close/use races and accidental rights-preserving duplication can undermine otherwise correct object creation.

## Learn

```text
Teach defensive Windows handle authority and lifetime management at expert depth.
Assume C++ and Win32 process creation. Explain per-handle granted rights, DACL
checks versus existing handles, named-object collisions, Local/Global namespaces,
reference lifetime, duplication options and handle-value reuse. Build a complete
self-child regression using STARTUPINFOEXW and PROC_THREAD_ATTRIBUTE_HANDLE_LIST:
baseline transfers event wait+modify authority, fixed transfers only SYNCHRONIZE,
and the child proves wait still succeeds while SetEvent is denied. Explain why
numeric handle absence is not a reliable object-identity test, and how concurrent
broad-inheritance launches can race. Include all source, setup, errors, cleanup
and acceptance checks. Use public Microsoft docs and label predicted results.
No arbitrary processes, privilege escalation, exploit primitives or private data.
Teach here; do not write notes or mark user study progress.
```

## Cheatsheet

### Transfer the Operation, Not the Creator's Authority

For an event consumer that only waits, `SYNCHRONIZE` is sufficient. `EVENT_MODIFY_STATE` permits Set/ResetEvent and should stay with the owner. A DACL can restrict new opens, but it does not normally strip rights from an already granted handle. Reducing the duplicate's mask is an independent control. Setting noninheritability prevents ambient transfer at creation time but does not prevent deliberate duplication by an authorized process.

| API / decision | Exact rule |
| --- | --- |
| `DuplicateHandle` | Source and target process handles need `PROCESS_DUP_HANDLE`; output is owned in the target process. Specify the reduced mask and options zero. `DUPLICATE_SAME_ACCESS` ignores the mask |
| `DUPLICATE_CLOSE_SOURCE` | Source closes regardless of error; avoid surprise ownership transfer on failure |
| `SetHandleInformation` | Mask selects attributes to change; flags zero clears selected inheritance. It does not change granted access |
| `InitializeProcThreadAttributeList` | First null-buffer call obtains size and normally fails with `ERROR_INSUFFICIENT_BUFFER`; allocate bounded storage, then initialize |
| `UpdateProcThreadAttribute` | Attribute `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, pointer to a HANDLE array, **byte** size. Entries must be inheritable; pseudo handles are not valid entries |
| `CreateProcessW` | Use `STARTUPINFOEXW`, its full `cb`, `EXTENDED_STARTUPINFO_PRESENT`, and `bInheritHandles=TRUE` with the explicit list |
| Cleanup | Attribute storage and its value buffers must live through creation. Delete the initialized list, free its storage, close parent transfer handles and both returned process/thread handles at their own lifetime endpoints |

Do not pass unrelated standard handles via `STARTF_USESTDHANDLES`; if used, they must be valid and explicitly accounted for in the transfer policy. Launch sites without explicit lists can race with temporarily inheritable handles in a multithreaded parent. Coordinate those sites or centralize launch ownership. The lab is single-threaded and never enables a broad inheritance launch.

### Names and Access Checks

Named object creation can return an existing object. Check `ERROR_ALREADY_EXISTS` immediately and reject unexpected reuse before trusting state or security. Other object types can occupy the same namespace. `Local\` and `Global\` control visibility, not access permission; a predictable name is not an authentication mechanism. Use explicit DACLs for intended principals and private namespaces where appropriate. Avoid NULL DACLs; an empty DACL and a NULL DACL have very different meanings.

Handle values can be reused in both parent and child. Testing whether the child has a particular numeric value does not prove it has the same object; that value might now identify an unrelated runtime resource. Prefer behavioral tests on the deliberately transferred object and positive evidence of the launch attribute list. Do not probe arbitrary inherited numeric values by mutating whatever object happens to be there.

### Reference and Race Hygiene

Use a single owner or explicit shared ownership for each handle. A waiter's handle must remain open until the wait finishes. A duplicate lets a worker own an independent reference, but not independent object state. Close-on-error and double-close paths deserve the same review as normal cleanup. Holding a process object's handle after exit preserves an object reference, not the exited address space.

`PROCESS_DUP_HANDLE` is sensitive authority and should not be requested by generic observers. Do not assume duplicates always have identical rights or that every type permits rights expansion; this page only reduces rights on an owned event. `HANDLE_FLAG_PROTECT_FROM_CLOSE` is an accidental-close aid, not a security isolation boundary.

## Detection and Defense

Record the requested mask and intended recipient at each transfer, not only raw handle integers. Audit unexpected inheritance-enabled creation paths and repeated handle growth. Object access auditing depends on SACL and audit policy; not every duplication or event operation produces a default event record. Leaks may arise from ordinary error paths, so correlate counts with ownership traces. The strongest regression combines denied excess authority with retained intended behavior.

## Labs

### Environment and Complete Files

Windows 11 x64, installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools prompt, standard user. One file, `transfer.cpp`, is both parent and its self-launched child. No additional program, data, account or service is required.

> [!warning] Unverified execution
> No build, child launch, VM or audit collection was performed during authoring. All results are predicted. Cross-session, protected-process, cross-user and concurrent-launch behavior remain untested. The example verifies reduced rights, not absence of arbitrary numeric handles.

```bat
mkdir x1-transfer
cd x1-transfer
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cerrno>
#include <string>
#include <vector>

bool Launch(const std::wstring& image, HANDLE event, DWORD access, bool expectModify) {
	HANDLE transferred = nullptr;
	if (!DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(),
						 &transferred, access, TRUE, 0)) return false;
	SIZE_T bytes = 0;
	BOOL probe = InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
	DWORD probeError = probe ? 0 : GetLastError();
	if (probe || probeError != ERROR_INSUFFICIENT_BUFFER || !bytes || bytes > 65536) {
		CloseHandle(transferred); return false;
	}
	auto* attributes = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
		HeapAlloc(GetProcessHeap(), 0, bytes));
	if (!attributes) { CloseHandle(transferred); return false; }
	if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) {
		HeapFree(GetProcessHeap(), 0, attributes);
		CloseHandle(transferred); return false;
	}
	HANDLE handles[] = {transferred};
	bool updated = UpdateProcThreadAttribute(attributes, 0,
		PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof handles, nullptr, nullptr) != FALSE;
	std::wstring text = L"\"" + image + L"\" " +
		std::to_wstring(reinterpret_cast<ULONG_PTR>(transferred)) +
		(expectModify ? L" 1" : L" 0");
	std::vector<wchar_t> command(text.begin(), text.end());
	command.push_back(L'\0');
	STARTUPINFOEXW startup{};
	startup.StartupInfo.cb = sizeof(startup);
	startup.lpAttributeList = attributes;
	PROCESS_INFORMATION process{};
	BOOL created = updated && CreateProcessW(image.c_str(), command.data(),
		nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
		&startup.StartupInfo, &process);
	DWORD createError = created ? 0 : GetLastError();
	DeleteProcThreadAttributeList(attributes);
	HeapFree(GetProcessHeap(), 0, attributes);
	CloseHandle(transferred);
	if (!created) { std::printf("launch error=%lu\n", createError); return false; }
	CloseHandle(process.hThread);
	DWORD waited = WaitForSingleObject(process.hProcess, 10000);
	DWORD code = 99;
	bool passed = waited == WAIT_OBJECT_0 &&
		GetExitCodeProcess(process.hProcess, &code) && code == 0;
	CloseHandle(process.hProcess);
	return passed;
}
int wmain(int argc, wchar_t** argv) {
	if (argc == 3) {
		wchar_t* end = nullptr;
		errno = 0;
		unsigned long long number = std::wcstoull(argv[1], &end, 10);
		if (errno || !number || end == argv[1] || *end ||
			(std::wcscmp(argv[2], L"0") && std::wcscmp(argv[2], L"1"))) return 10;
		HANDLE event = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(number));
		bool expected = std::wcscmp(argv[2], L"1") == 0;
		DWORD waited = WaitForSingleObject(event, 0);
		BOOL modified = SetEvent(event);
		DWORD error = modified ? 0 : GetLastError();
		bool passed = waited == WAIT_OBJECT_0 &&
			(expected ? modified != FALSE : !modified && error == ERROR_ACCESS_DENIED);
		std::printf("child wait=%d modify=%d error=%lu\n",
					waited == WAIT_OBJECT_0, modified != FALSE, error);
		if (!CloseHandle(event)) passed = false;
		return passed ? 0 : 11;
	}
	if (argc != 1) return 12;
	wchar_t image[32768]{};
	DWORD length = GetModuleFileNameW(nullptr, image, 32768);
	if (!length || length >= 32768) return 1;
	HANDLE event = CreateEventW(nullptr, TRUE, TRUE, nullptr);
	if (!event) return 2;
	bool baseline = Launch(image, event, SYNCHRONIZE | EVENT_MODIFY_STATE, true);
	bool fixed = Launch(image, event, SYNCHRONIZE, false);
	CloseHandle(event);
	std::printf("baseline=%d fixed=%d\n", baseline, fixed);
	return baseline && fixed ? 0 : 3;
}
```

### Objectives and Baseline

1. Identify the only transferable handle in each explicit attribute list.
2. Compare the same `SetEvent` call in baseline and fixed child runs.
3. Explain why closing the parent's temporary duplicate after creation does not invalidate the child's inherited reference.

```bat
cl /nologo /W4 /EHsc /std:c++17 transfer.cpp /Fe:transfer.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
transfer.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The event starts signaled and is manual-reset. Both children should wait successfully, and baseline signaling is a harmless no-op. The fixed duplicate is inheritable but lacks modification authority; inheritance eligibility is not access permission.

### Solution and Fixed Retest

Baseline child: `wait=1 modify=1 error=0`. Fixed child: `wait=1 modify=0 error=5`. Parent: `baseline=1 fixed=1`, exit zero. Each child owns and closes its inherited event reference. The list excludes every other parent handle by construction; numeric-handle probing is intentionally not used as evidence. Both paths use explicit inheritance, so the baseline demonstrates excessive rights, not broad ambient handle leakage.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe retained waits and the changed modification outcome.
- [ ] Trace cleanup of attribute list, heap storage, duplicate, thread and process handles.
- [ ] Record versions, child exit codes and any launch restriction.

Error 87 often indicates attribute/list/creation-flag mismatch. Confirm inherited entries are real and inheritable. A failed launch or timeout fails the lab; do not weaken policy. Child code has only nonblocking waits and should exit immediately. The x64-only build is intentional; the argument conversion is not offered as a portable cross-bitness transfer protocol.

```bat
del transfer.exe transfer.obj
```

No persistent objects, accounts or configuration changes remain after parent and children exit. Remove the source directory when finished.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Objects and Handles]]

## References

- [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [InitializeProcThreadAttributeList](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [SetHandleInformation](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation)
