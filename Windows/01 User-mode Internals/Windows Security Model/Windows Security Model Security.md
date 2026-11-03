---
title: "Windows Security Model Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Windows Security Model]]"
updated: 2026-11-03
---
# Windows Security Model Security

> [!abstract] TL;DR
> Overbroad ACLs, excessive privileges, unsafe impersonation, and mistaken elevation assumptions can grant unintended resource access.

> [!info] Agent scope
> Security of: Tokens; SIDs; privileges; integrity levels; DACL/SACL; access checks; impersonation; UAC; restricted tokens. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Broad DACL grants, confusing API success with authorization success, stale handles and wrong effective-token selection can defeat intended least privilege.
- Identity, integrity, privileges, requested rights and object type must be evaluated together; “administrator” is not a complete access explanation.

## Learn

```text
Teach defensive Windows authorization at expert depth. Assume tokens, SIDs and
Win32 handles. Explain ordered DACL evaluation, NULL versus empty DACLs, owner
rights, privilege state, integrity, restricting SIDs, UAC and impersonation levels.
Focus on exact API contracts: AccessCheck's function result versus AccessStatus,
generic mapping, token query rights, descriptor owner/group requirements, audit
limits and actual-object checks. Supply a complete self-process named-event lab:
baseline current-user wait+modify DACL, tighten to wait-only, deny a new modify
open, retain wait, compare AccessCheck, and prove an already granted handle keeps
its old rights. Explain the fix's limits rather than claiming revocation. Include
all code, setup, checks, worked results and cleanup. No privilege enabling, token
stealing, bypasses, service setup, other identities or private data. Use Microsoft
primary docs and label runtime predictions. Teach here; do not author files.
```

## Cheatsheet

### Check the Operation Under the Intended Identity

An authorization decision is about a specific token, descriptor, desired mask and operation. Checking a username or admin membership and then acting through a broader service token is not equivalent. A client-supplied path or identifier is not proof of ownership. For real resources, let the operating system perform the operation under the intended context or use a correctly designed broker with explicit object authorization; do not substitute a detached ACL snapshot for an atomic resource operation.

| Failure | Concrete correction | Residual limitation |
| --- | --- | --- |
| DACL grants modification to an observer | Grant only the type-specific read/wait rights; deny new excess opens | Existing handles keep previously granted rights |
| `AccessCheck` returns TRUE, so caller allows | Require both API success **and** `AccessStatus == TRUE` | Detached check can race with later policy/resource changes |
| Generic bits passed unchanged | Map desired rights with the correct object `GENERIC_MAPPING` | Wrong mapping tests the wrong rights even if API succeeds |
| NULL DACL confused with default security | Explicit descriptor policy; never install a NULL DACL to mean private | Default creation security is token/API-dependent |
| Privilege present treated as enabled | Inspect attributes; avoid enabling privileges unnecessary to the operation | Some operations have privilege-specific or integrity policy |
| Impersonation failure falls back to self | Fail closed; do not use a more privileged token on arbitrary failure | Thread-local context must survive the entire intended operation |

Canonical ACE order matters: explicit denies, explicit allows, then inherited ACEs in their defined order. An empty DACL grants no ordinary data rights; a NULL/absent DACL supplies no discretionary restriction. Owner `READ_CONTROL`/`WRITE_DAC` rules and applicable privileges mean “empty DACL denies absolutely everything” is false. Changing DACLs may need `WRITE_DAC`; querying them needs `READ_CONTROL`. Request neither SACL rights nor privilege adjustments for ordinary DACL work.

### Supported API Contracts

`GetSecurityInfo(handle, type, information, ..., &descriptor)` returns a **DWORD error code**; zero means success. The returned descriptor is allocated with local allocation and freed by `LocalFree`; ACL pointers it returns point into that allocation. `SetSecurityInfo` also returns a DWORD code, not BOOL, and does not reorder ACEs for you. `PROTECTED_DACL_SECURITY_INFORMATION` prevents DACL inheritance where meaningful; it does not make an object immutable or revoke existing handles.

`AccessCheck` needs a queryable impersonation token (identification level suffices for this check), owner/group in a valid descriptor, and a privilege-set output buffer whose length is in bytes. Its function result reports whether the check executed; `AccessStatus` reports allowed/denied. On API failure, output masks may be unset. It does not create an audit. Use concrete masks in the lab so no generic bits remain; a zero-initialized mapping is acceptable here only because mapping is never requested or needed by those concrete masks.

`DuplicateTokenEx` with `TOKEN_QUERY`, `SecurityIdentification`, `TokenImpersonation` creates a query token for `AccessCheck`; it does **not** make the calling thread impersonate. Source requires `TOKEN_DUPLICATE`. Close both source and duplicate. Do not escalate the impersonation level or request `TOKEN_ALL_ACCESS` for this analysis.

### Integrity, UAC and Restricted Contexts

Mandatory integrity labels constrain operations independently of DACL grants. A SACL can contain a label and audit ACEs; an audit ACE alone does not ensure a recorded event. UAC limited/full linked tokens can differ in SID attributes, privileges and integrity, but neither an elevation prompt nor membership alone describes every authorization result. Avoid treating same-admin UAC contexts as universal security isolation.

Restricted tokens can disable SIDs, delete privileges and introduce restricting SIDs whose additional check must grant access. Privilege reduction does not automatically remove existing object handles, lower integrity or isolate code in the same process. Effective-token selection must handle `OpenThreadToken`'s `ERROR_NO_TOKEN` distinctly from actual failure. With real impersonation, success and reversion must be checked; failed `RevertToSelf` cannot be ignored while continuing privileged work. This lab never changes thread identity.

### Why the Fix Does Not Revoke the Owner

The baseline event's current-user ACE grants `SYNCHRONIZE | EVENT_MODIFY_STATE`. The fix replaces it with `SYNCHRONIZE`. A **new** open for modification should fail. The creator's old full-access handle remains capable of signaling; DACL tightening is not retroactive revocation. To remove an already distributed capability, coordinate closure or recreate the resource under a new lifecycle rather than assuming a changed ACL invalidated all references.

## Detection and Defense

Record requested rights, actual API error, effective-context choice and policy revision without logging personal SIDs or real secrets. Keep “check ran” separate from “access allowed” in telemetry. Sensitive object auditing needs SACL and system audit policy plus collection; `AccessCheck` itself emits none. Least-privilege rights and identities, safe handle distribution, and regression tests on actual resource operations complement audits. The lab's process-local printout is evidence only of its checks once run, not of enterprise audit coverage.

## Labs

### Environment and Complete Files

Windows 11 x64, installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools prompt, ordinary standard user. One complete file, `access.cpp`; no project, data, accounts, service, privilege enabling or machine policy changes.

> [!warning] Unverified execution
> No build, VM, DACL change, token operation or runtime check was performed during authoring. All results are predicted. Cross-user/service impersonation, SACL auditing, UAC elevation and integrity-denial behavior remain unverified.

```bat
mkdir x1-access
cd x1-access
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstdio>
#include <string>
#include <vector>

bool Check(PSECURITY_DESCRIPTOR descriptor, HANDLE token, DWORD desired, bool expected) {
	GENERIC_MAPPING mapping{};
	PRIVILEGE_SET privileges{};
	DWORD bytes = sizeof privileges;
	DWORD granted = 0;
	BOOL allowed = FALSE;
	BOOL checked = AccessCheck(descriptor, token, desired, &mapping,
							   &privileges, &bytes, &granted, &allowed);
	std::printf("mask=%lx check-ran=%d allowed=%d\n", desired, checked != FALSE, allowed != FALSE);
	return checked && (allowed != FALSE) == expected;
}
int wmain() {
	HANDLE primary = nullptr, client = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary)) return 1;
	DWORD needed = 0;
	BOOL probe = GetTokenInformation(primary, TokenUser, nullptr, 0, &needed);
	DWORD error = probe ? 0 : GetLastError();
	if (probe || error != ERROR_INSUFFICIENT_BUFFER || !needed || needed > 65536) {
		CloseHandle(primary); return 2;
	}
	std::vector<unsigned char> storage(needed);
	if (!GetTokenInformation(primary, TokenUser, storage.data(), needed, &needed) ||
		!DuplicateTokenEx(primary, TOKEN_QUERY, nullptr, SecurityIdentification,
						   TokenImpersonation, &client)) {
		CloseHandle(primary); return 3;
	}
	CloseHandle(primary);
	auto* user = reinterpret_cast<TOKEN_USER*>(storage.data());
	LPWSTR text = nullptr;
	if (!ConvertSidToStringSidW(user->User.Sid, &text)) { CloseHandle(client); return 4; }
	std::wstring sid(text);
	LocalFree(text);
	std::wstring prefix = L"O:" + sid + L"G:" + sid + L"D:P(A;;";
	std::wstring broadText = prefix + L"0x00100002;;;" + sid + L")";
	std::wstring fixedText = prefix + L"0x00100000;;;" + sid + L")";
	PSECURITY_DESCRIPTOR broad = nullptr, fixed = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(broadText.c_str(),
		SDDL_REVISION_1, &broad, nullptr)) { CloseHandle(client); return 5; }
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(fixedText.c_str(),
		SDDL_REVISION_1, &fixed, nullptr)) {
		LocalFree(broad); CloseHandle(client); return 6;
	}
	SECURITY_ATTRIBUTES attributes{sizeof(attributes), broad, FALSE};
	std::wstring name = L"Local\\HackVault.Access." + std::to_wstring(GetCurrentProcessId());
	HANDLE owner = CreateEventW(&attributes, TRUE, TRUE, name.c_str());
	DWORD creationError = GetLastError();
	LocalFree(broad);
	if (!owner || creationError == ERROR_ALREADY_EXISTS) {
		if (owner) CloseHandle(owner);
		LocalFree(fixed); CloseHandle(client); return 7;
	}
	HANDLE baseline = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
	bool passed = baseline != nullptr;
	if (baseline) CloseHandle(baseline);
	PACL dacl = nullptr;
	BOOL present = FALSE, defaulted = FALSE;
	bool extracted = GetSecurityDescriptorDacl(fixed, &present, &dacl, &defaulted) && present && dacl;
	DWORD changed = extracted ? SetSecurityInfo(owner, SE_KERNEL_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		nullptr, nullptr, dacl, nullptr) : ERROR_INVALID_SECURITY_DESCR;
	LocalFree(fixed);
	passed = changed == ERROR_SUCCESS && passed;
	HANDLE denied = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
	DWORD deniedError = denied ? 0 : GetLastError();
	if (denied) CloseHandle(denied);
	HANDLE reader = OpenEventW(SYNCHRONIZE, FALSE, name.c_str());
	bool retained = reader && WaitForSingleObject(reader, 0) == WAIT_OBJECT_0;
	if (reader) CloseHandle(reader);
	bool oldAuthority = SetEvent(owner) != FALSE;
	PSECURITY_DESCRIPTOR actual = nullptr;
	DWORD obtained = GetSecurityInfo(owner, SE_KERNEL_OBJECT,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		nullptr, nullptr, nullptr, nullptr, &actual);
	if (obtained == ERROR_SUCCESS) {
		passed = Check(actual, client, SYNCHRONIZE, true) && passed;
		passed = Check(actual, client, EVENT_MODIFY_STATE, false) && passed;
		LocalFree(actual);
	} else passed = false;
	passed = !denied && deniedError == ERROR_ACCESS_DENIED && retained && oldAuthority && passed;
	CloseHandle(owner);
	CloseHandle(client);
	std::printf("new-modify-error=%lu wait=%d old-handle=%d checks=%d\n",
				deniedError, retained, oldAuthority, passed);
	return passed ? 0 : 8;
}
```

### Objectives and Baseline

1. Establish that a new modifying open succeeds under the original ACE.
2. Tighten the real event DACL, then repeat the exact modifying open and a permitted wait.
3. Distinguish `AccessCheck` API success from its authorization result and from existing-handle authority.

```bat
cl /nologo /W4 /EHsc /std:c++17 access.cpp /Fe:access.exe /link Advapi32.lib /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
access.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The duplicate token is for an access-check input only; the thread never impersonates. Both access checks should execute successfully. Only the wait request should be authorized by the tightened DACL.

### Solution and Fixed Retest

Expected check lines show mask `100000`, `check-ran=1 allowed=1`, then mask `2`, `check-ran=1 allowed=0`. The real modifying open fails with 5, wait remains 1, old-handle signaling remains 1, `checks=1`, exit zero. The owner was granted full access at creation and that reference was never revoked. Re-running creates a fresh event and repeats both policies. This is a genuine DACL/handle test, not a simulated role table.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe both AccessCheck results and matching new-open outcomes.
- [ ] Explain why the old handle can still modify and why owner rights do not grant new event modification.
- [ ] Record OS/toolchain and actual results without recording personal SID strings.

The fixed privilege buffer suffices for these concrete wait/modify checks, which use no privilege override; any API failure is a failed lab, not an authorization denial. Unexpected named-object reuse aborts. A restricted token with additional restricting SIDs can change the baseline grant; record the unmet ordinary-token assumption, do not elevate or relax ACLs.

```bat
del access.exe access.obj
```

All descriptors/token handles are local allocations/references, and the named event vanishes when its final reference closes. Remove the source directory when done.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Local Privilege Escalation]]
- [[Windows Security Model]]

## References

- [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [How DACLs control access](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
- [DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
- [Mandatory integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
