---
title: "Windows Architecture Overview Security"
aliases: []
tags: [windows, x0, security]
domain: windows
phase: "X0"
type: security
status: draft
pair: "[[Windows Architecture Overview]]"
updated: 2026-11-03
---
# Windows Architecture Overview Security

> [!abstract] TL;DR
> Confusing component boundaries leads to incorrect assumptions about who validates input, which identity authorizes access, and which code runs with kernel privilege.

> [!info] Agent scope
> Security of: User/kernel boundary; executive and kernel; subsystems; services; sessions; system components; object and I/O overview. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- User-mode service interfaces, kernel device interfaces, named objects, inherited handles and filesystem/registry permissions each have distinct trust decisions.
- This page demonstrates access-mask and DACL behavior using only a process-owned synthetic event. It does not access other processes, load drivers, change service permissions or collect credentials.

## Learn

```text
Teach me defensive Windows architecture trust boundaries at expert foundation
depth. Assume C++ and ordinary Win32 handles. Distinguish processor mode,
process/thread effective tokens, service identities, UAC, integrity, sessions,
namespaces, DACL checks and per-handle granted access. Explain a least-privilege
event example where waiting is permitted but signaling is denied, both through
a restricted handle and through a restrictive object DACL. Provide complete
MSVC x64 source, SDDL construction for a synthetic current-user event, build
commands, expected error codes, positive/negative retests and cleanup. Explain
why object ownership and existing handles limit what this demonstration proves.
Discuss services and driver validation conceptually, not through offensive
examples. Use public primary references; no exploit chains, bypass, injection,
credential access, host changes, page tables or duplicated WinDbg commands.
Teach in conversation, do not edit files/status; finish with worked scenarios.
```

## Cheatsheet

### Boundary Map

| Boundary | Authoritative question | Common false assumption |
|---|---|---|
| User mode to kernel mode | Does the OS/driver validate sizes, access, lifetime and the caller's request according to the interface contract? | "The caller is local, so its pointer/length is trusted." |
| Client to user-mode service | Which authenticated identity and operation/object authorization apply? Is impersonation scoped and reverted correctly? | "The service is privileged, therefore its caller is authorized." |
| Token to object DACL | Does the effective token satisfy the requested rights and other applicable policy? | "Same session or username means full access." |
| Handle to operation | Was this specific right granted to this handle? | "The DACL would allow a new full-access open, so every existing handle has full rights." |
| Namespace to object | Did creation produce a new object of the expected type and security descriptor? | "A successful create always used my supplied DACL." |
| Build/tool to trusted system | Is the executable/driver authentic, supported and necessary? | "Signed means harmless, current or least-privileged." |

A primary token belongs to a process; an impersonation token can alter a thread's effective access. Token user/groups, enabled privileges, restricted SIDs and integrity policy all matter. UAC elevation is not the same as switching to kernel mode. An elevated user-mode process remains user mode and still uses documented access checks. Some privileges enable specific alternate operations; they are not a universal all-access flag.

### Access and Lifetime Contracts

- A security descriptor includes owner, group, DACL and possibly SACL/mandatory label. A **null DACL** and an **empty DACL** are radically different: the former grants discretionary access broadly, the latter grants no access through allow ACEs. Other policy can still apply.
- A DACL is evaluated for the requested access at open/create time. The resulting handle carries granted rights. Changing a DACL generally does not revoke rights on existing handles; design revocation and connection lifecycle deliberately.
- Owners normally have implicit security-management rights such as `WRITE_DAC`, subject to rules including the OWNER RIGHTS SID. The lab's current-user owner can change its own object's DACL; this is **not** a sandbox against that owner.
- A wait on an event requires `SYNCHRONIZE` (`0x00100000`). `SetEvent` requires `EVENT_MODIFY_STATE` (`0x00000002`). A SYNCHRONIZE-only handle cannot signal even if the caller could separately open a signaling handle.
- `Local\` names are session-scoped, not automatically private to a user. `Global\` introduces cross-session namespace considerations and object-specific privilege rules; do not switch namespaces just to suppress a failure.
- `CreateEventW` requests broad event access. Use `CreateEventExW` with explicit desired access for a narrow handle. When an event already exists, the supplied security attributes do not replace its descriptor; check `ERROR_ALREADY_EXISTS` and reject collisions when freshness matters.
- Null security attributes ordinarily prevent handle inheritance; explicitly control inheritance and process creation handle lists. Handles are capabilities that should not be leaked to unrelated children.
- `GetLastError` is meaningful only on documented paths. Capture it immediately after the failing call; a subsequent successful API or cleanup can change it.

The examples target Windows 11 x64. `CreateEventExW` is documented from Windows Vista; access constants and SDDL are public contracts. Numeric syscall IDs, private token layouts and internal object offsets are not contracts and are unnecessary here.

### Services, Drivers and Observation

SCM configuration permissions, a service's process token, permissions on its executable/configuration, and the service's own IPC authorization are separate layers. Session 0 isolation prevents ordinary interactive desktop assumptions; it does not automatically make IPC trustworthy. Prefer narrow service identities and rights, explicit endpoint ACLs, bounded message formats and audited policy changes.

For drivers, device-interface permissions do not replace per-request buffer and access validation. Retain signing, Secure Boot and supported virtualization protections; use a separate disposable target for any later driver-debug exercise. No signing/debug policy change is required for this page. Kernel debugging is documented only in [[WinDbg]].

Telemetry must match the claim. An access-denied return establishes one failed operation under one effective token; it does not prove a specific audit event was emitted. Object auditing requires applicable audit policy/SACL configuration and can be noisy. Process names or a sparse module list are not evidence of hidden execution. Collect only your lab process and synthetic objects.

## Detection and Defense

For each finding record object type/name, request mask, effective identity, handle provenance, API result and error, plus a permitted control operation. Fix the smallest authorization contract, then rerun the same operations. A process running as the same owner is not a suitable adversary for proving owner-resistant isolation; that requires separate identities and a different threat model. The lab below intentionally isolates **handle-rights correctness**, not a complete multi-user policy.

## Labs

### Environment and Complete File

Windows 11 x64 disposable development VM; VS 2022 Build Tools 17.10+ (17.x), v143 Desktop development with C++ and SDK 10.0.22621.0+. Standard-user runtime, no network/driver dependencies, 1 GiB workspace budget. Make `%USERPROFILE%\X0-Access` and change into it in **x64 Native Tools Command Prompt for VS 2022**. Create **access.cpp**:

```cpp
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>
#include <vector>

class Handle {
	HANDLE value_;
public:
	explicit Handle(HANDLE value) noexcept : value_(value) {}
	~Handle() { if (value_ != nullptr) CloseHandle(value_); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
	HANDLE get() const noexcept { return value_; }
};

bool current_user_sid(std::wstring& result) {
	HANDLE raw_token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) return false;
	Handle token(raw_token);
	DWORD required = 0;
	if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &required) ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
	std::vector<unsigned char> storage(required);
	if (!GetTokenInformation(token.get(), TokenUser, storage.data(), required,
							 &required)) return false;
	const auto user = reinterpret_cast<const TOKEN_USER*>(storage.data());
	LPWSTR text = nullptr;
	if (!ConvertSidToStringSidW(user->User.Sid, &text)) return false;
	try { result.assign(text); }
	catch (...) { LocalFree(text); throw; }
	LocalFree(text);
	return true;
}

bool exercise(const std::wstring& sid, bool restricted) {
	const std::wstring rights = restricted ? L"0x00100000" : L"0x00100002";
	const std::wstring sddl = L"D:P(A;;" + rights + L";;;" + sid + L")";
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
	SECURITY_ATTRIBUTES attributes{};
	attributes.nLength = sizeof(attributes);
	attributes.lpSecurityDescriptor = descriptor;
	attributes.bInheritHandle = FALSE;
	const std::wstring name = L"Local\\X0Access-" +
		std::to_wstring(GetCurrentProcessId()) + (restricted ? L"-fixed" : L"-baseline");
	SetLastError(ERROR_SUCCESS);
	HANDLE raw_event = CreateEventExW(&attributes, name.c_str(),
		CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE);
	const DWORD create_error = GetLastError();
	LocalFree(descriptor);
	Handle event(raw_event);
	if (event.get() == nullptr || create_error == ERROR_ALREADY_EXISTS) return false;

	const BOOL wrong_handle_signal = SetEvent(event.get());
	const DWORD handle_error = wrong_handle_signal ? ERROR_SUCCESS : GetLastError();
	HANDLE raw_writer = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
	const DWORD open_error = raw_writer ? ERROR_SUCCESS : GetLastError();
	Handle writer(raw_writer);
	bool writer_ok = false;
	if (writer.get() != nullptr) writer_ok = SetEvent(writer.get()) != FALSE;
	const DWORD wait_result = WaitForSingleObject(event.get(), 0);
	std::printf("%s handle_denied=%lu writer_open=%lu wait=%lu\n",
		restricted ? "fixed" : "baseline", handle_error, open_error, wait_result);
	if (wrong_handle_signal || handle_error != ERROR_ACCESS_DENIED) return false;
	if (restricted) {
		return writer.get() == nullptr && open_error == ERROR_ACCESS_DENIED &&
			wait_result == WAIT_TIMEOUT;
	}
	return writer.get() != nullptr && writer_ok && wait_result == WAIT_OBJECT_0;
}

int main() {
	static_assert(sizeof(void*) == 8);
	std::wstring sid;
	if (!current_user_sid(sid)) return 2;
	if (!exercise(sid, false)) return 3;
	if (!exercise(sid, true)) return 4;
	return 0;
}
```

The token is queried only to construct a current-user ACE; no credentials are read. The process is not impersonating, so its primary token supplies the intended identity. `D:P` protects this explicit DACL from inheritance. The program supplies no SACL and changes no existing object. Resources are scoped; named events disappear after the last handle closes.

### Objectives and Baseline

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf access.cpp Advapi32.lib /Feaccess.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
access.exe
echo %ERRORLEVEL%
```

Before running, predict all six values in the two output lines. Explain why the baseline DACL permits a fresh signaling open but does not upgrade the original handle. The fixed case uses a new object with a narrowed descriptor so previously granted handles cannot confuse the result. Run again to establish that handles/names were cleaned up.

For a standard/elevated comparison, repeat **only this same synthetic program inside the disposable VM** from an elevated developer prompt using the same account. Do not change any policies. Expected checks are unchanged: elevation does not add `EVENT_MODIFY_STATE` to an already SYNCHRONIZE-only handle. If organizational policy prevents elevation, record that comparison as unperformed; it is not required for the core nonprivileged lab.

### Hints

`WAIT_TIMEOUT` (258) is a successful non-signaled wait observation, not an access error. `ERROR_ACCESS_DENIED` is 5. The manual-reset event stays signaled in the baseline after the writer signals it. The fixed event starts nonsignaled and no authorized signaling handle is opened.

### Solution and Fixed Retest

Expected output:

```text
baseline handle_denied=5 writer_open=0 wait=0
fixed handle_denied=5 writer_open=5 wait=258
```

Expected exit 0. In both cases the limited handle cannot signal. Baseline: the DACL grants both wait and modify rights to this user, so a separate modify-only handle succeeds. Fixed: the DACL grants only wait rights, so the modify open fails, while waiting is still permitted and returns timeout. This preserves the legitimate operation instead of treating all failures as success. The baseline is deliberately overbroad for a wait-only policy; it is not a claim that normal Windows event defaults are vulnerable.

### Verification, Troubleshooting, and Cleanup

Author validation: **unexecuted MSVC build, ACL/access results and elevated comparison**. Verify exact codes and exit 0 on repeated runs. A name collision is a failed freshness assumption, not permission to reuse a preexisting object; close your own previous instance and rerun. Missing `ConvertStringSecurityDescriptor...` symbols mean `Advapi32.lib` was omitted. If a security product blocks execution, retain the evidence and request approved lab access, not exclusions or disabling protection.

No persistent ACLs, accounts or services were created. Close consoles/tools and remove only `%USERPROFILE%\X0-Access`, or restore the VM snapshot. Existing checklist items remain intact; the companion architecture page supplies the separate process/I/O mapping exercise.

- [ ] Local Windows Architecture Overview exercise: In a Windows VM, map a test application, its service dependency, loaded modules, and device interactions using Sysinternals. Produce a diagram labeling user/kernel and identity boundaries without adding page-table material.
- [ ] Boundary check: Run the same harmless resource access under standard and elevated synthetic lab users; compare access decisions and relevant object permissions instead of assuming elevation bypasses every control.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[Windows Architecture Overview]]

## References

- [Access-control model](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-model)
- [Synchronization object security and access rights](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights)
- [CreateEventExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventexw)
- [SetEvent](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setevent)
- [Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
- [Kernel object namespaces](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces)
- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
