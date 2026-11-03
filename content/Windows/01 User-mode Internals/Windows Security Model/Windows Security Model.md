---
title: "Windows Security Model"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Windows Security Model Security]]"
updated: 2026-11-03
---
# Windows Security Model

> [!abstract] TL;DR
> Record effective token, requested mask, DACL, integrity level, privileges, and impersonation level. Explain the actual access decision rather than only group membership.

> [!info] Agent scope
> Tokens; SIDs; privileges; integrity levels; DACL/SACL; access checks; impersonation; UAC; restricted tokens.

## Prerequisites

- [[Objects and Handles]], C++ variable-size buffers, and [[Windows Lab Setup]].
- Windows 11 x64, already installed VS 2022 MSVC v143/Windows SDK 10.0.22621+, x64 Native Tools Command Prompt, ordinary non-elevated desktop token.

## Learn

```text
Teach the Windows security model at expert systems-engineering depth. Assume
Win32 handles and C++ buffers. Explain primary/effective impersonation tokens,
user/group/logon/restricting SIDs, enabled/deny-only groups, privilege state,
integrity labels, owner/group/DACL/SACL descriptors, ACE ordering and generic masks.
Trace an actual requested access decision, distinguishing absent/NULL/empty DACLs,
owner rights, privileges, mandatory policy and existing granted handles. Compare
UAC split tokens, elevation type, integrity and membership without equating them.
Explain impersonation levels, fail-closed reversion, and restricted tokens including
the second restricting-SID check and DISABLE_MAX_PRIVILEGE limits. Provide a complete
self-process token inspection and restricted-copy lab, with exact API rights,
buffer lengths, cleanup, predicted checks and source references. No token stealing,
privilege enabling, bypasses, services, other identities or private data. Use
Microsoft primary docs, state version limits and never invent execution. Teach in
chat; do not author files or update user study status.
```

## Cheatsheet

### Token Is Context, Not Just Username

A process has a primary token. A thread may have an impersonation token that supplies the effective security context for operations honoring impersonation; otherwise the primary token applies. Individual APIs can have additional context rules. `CreateProcessW`, for example, does not automatically launch as an impersonated client. A handle to a token is itself a securable resource with rights such as `TOKEN_QUERY`, `TOKEN_DUPLICATE` and `TOKEN_IMPERSONATE`.

| Token information | Interpretation |
| --- | --- |
| `TokenUser` | User SID; a binary SID is an identity identifier, not a password or an access decision |
| `TokenGroups` | SID attributes matter: enabled groups participate in allows/denies; deny-only SIDs match deny ACEs but cannot supply allow rights |
| `TokenPrivileges` | LUID plus attributes for each privilege. Present is not necessarily enabled; privileges authorize specific system operations, not arbitrary ACL access |
| `TokenIntegrityLevel` | Mandatory label SID; final RID identifies level, e.g. low `0x1000`, medium `0x2000`, high `0x3000`, system `0x4000`. Intermediate levels exist |
| `TokenElevationType` | `Default`, `Full`, `Limited` describe UAC-linked token state, not a universal admin Boolean |
| `TokenRestrictedSids` | Additional restricting SID set can require a second grant calculation; removing privileges alone is a different restriction |
| `TokenStatistics` | Token/logon-related IDs and modification information aid correlation; do not confuse them with a PID |

`OpenProcessToken` with `TOKEN_QUERY` permits inspection. `GetTokenInformation` uses byte lengths; variable classes normally require a failed zero-buffer probe yielding `ERROR_INSUFFICIENT_BUFFER`, allocation under a cap, then a checked fetch. Structures contain pointers into the returned buffer; retain it while using SIDs. State can change between calls, so production code needs bounded retry for mutable information. `ConvertSidToStringSidW` allocates a string freed by `LocalFree`.

`OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)` distinguishes no impersonation token (`ERROR_NO_TOKEN`) from an access/API failure. `OpenAsSelf=TRUE` changes the context used to check access to the token object; it does not switch the thread's execution identity. Never interpret all failures as permission to use a more privileged process token.

### Descriptors and Access Decisions

A security descriptor contains owner, primary group, DACL, SACL and control bits. DACL ACEs grant/deny discretionary rights; SACL audit ACEs request audit records, while mandatory-label ACEs also reside in the SACL. Auditing additionally needs applicable audit policy and a collector. Reading/writing audit information generally requires `ACCESS_SYSTEM_SECURITY` and the appropriate enabled privilege; do not request that just to inspect a DACL. Mandatory-label operations have their own rights/policy rules.

For a concrete desired access, map generic bits according to the object type. Evaluate relevant enabled/deny-only/restricting SIDs and ACEs in order; an applicable deny for a still-requested right fails, allows accumulate rights, and an ungranted requested right fails. Canonical ACL ordering puts explicit denies before explicit allows, then inherited ACEs in inheritance order. “Deny always wins” is an imprecise replacement for the ordered algorithm. Owner and privilege rules can supply or affect rights outside ordinary allow ACE reasoning; owner typically has implicit `READ_CONTROL`/`WRITE_DAC`, with OWNER RIGHTS ACE nuances.

- Absent or present-NULL DACL: no discretionary restriction from that DACL. It is not a safe default for an object meant to be private.
- Present empty DACL: no ACE grants. Ordinary requested data access is denied, subject to owner/privilege and operation-specific rules.
- A NULL security-descriptor pointer passed to a creation API normally selects **default security**, not a deliberately installed NULL DACL.

Mandatory integrity policy is separate from the DACL. Typical no-write-up policy prevents lower-integrity writes to higher-integrity objects even when a DACL would otherwise permit them; exact label policy and object type matter. Integrity is neither authentication nor a complete sandbox. Kernel enforcement, object-specific rules, privileges and restrictions mean a simplistic user-mode ACL calculation cannot certify every real operation.

### AccessCheck, Impersonation, and UAC

`AccessCheck(descriptor, impersonationToken, desired, mapping, privileges, &bytes, &granted, &allowed)` has **two results**: API `BOOL` and `allowed`. API success can report access denied. It requires a token handle with `TOKEN_QUERY`, an impersonation token, a valid descriptor with owner/group, and desired rights already mapped to concrete bits. It does not generate an audit. Use actual object operations to confirm enforcement and don't mistake a detached descriptor check for an atomic check-and-use on a mutable resource.

Impersonation levels range from anonymous and identification through impersonation to delegation. Identification is sufficient for suitable access checks, not acting as the user on resources. Services must validate impersonation success, keep work within the intended context, and always revert; if `RevertToSelf` fails, continuing with an unintended identity is unsafe. This lab never impersonates a client or changes thread identity.

UAC can give an administrator a filtered limited token and a linked full token. Group attributes and privileges differ. A medium-integrity process is not necessarily a non-administrator account, and a standard-user token can report `TokenElevationTypeDefault`. Membership, elevation type and integrity answer different questions. Do not treat UAC as a universal isolation boundary between an administrator's own contexts.

### Restricted Tokens

`CreateRestrictedToken` takes a token opened for `TOKEN_DUPLICATE`, flags, SIDs to disable, privileges to delete and restricting SIDs. It returns a new owned token; it does not mutate or replace the caller's primary token. Disabled SIDs become deny-only, deleted privileges cannot be re-enabled in that copy, and nonempty restricting SIDs add a second access check that must also grant access. `DISABLE_MAX_PRIVILEGE` disables all privileges except `SeChangeNotifyPrivilege`; it does not automatically lower integrity, add restricting SIDs or isolate handles already held.

`IsTokenRestricted` checks for restricting SIDs, not every possible form of reduced authority. Therefore a privilege-reduced token can have no restricting SIDs and report false. Restricted-token creation alone is not containment; inherited handles, namespace reach, process identity and application design remain relevant. The lab only inspects the new token and closes it.

## Gotchas

- `AdjustTokenPrivileges` cannot add absent privileges, and success can coexist with `ERROR_NOT_ALL_ASSIGNED`; no privilege enabling is needed here.
- DACL changes usually do not revoke rights on already-open handles.
- Do not log token SIDs, usernames or privilege inventories from real environments into public notes. This lab prints only counts and integrity/elevation values.

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No token query, compiler/runtime, VM, elevation, alternate identity or audit test was performed during authoring. Output below is predicted and token-dependent. Restricted-process launch, impersonation and cross-identity enforcement are not exercised.

Use the non-elevated developer prompt and a fresh directory. Only `token.cpp` is needed; no project, input data, accounts or services.

```bat
mkdir x1-token
cd x1-token
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>
#include <vector>

bool Query(HANDLE token, TOKEN_INFORMATION_CLASS kind, std::vector<unsigned char>& output) {
	DWORD needed = 0;
	BOOL probe = GetTokenInformation(token, kind, nullptr, 0, &needed);
	DWORD error = probe ? 0 : GetLastError();
	if (probe || error != ERROR_INSUFFICIENT_BUFFER || !needed || needed > 65536) return false;
	output.resize(needed);
	return GetTokenInformation(token, kind, output.data(), needed, &needed) != FALSE;
}
int main() {
	HANDLE primary = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary)) return 1;
	std::vector<unsigned char> userBytes, integrityBytes, privilegeBytes;
	if (!Query(primary, TokenUser, userBytes) ||
		!Query(primary, TokenIntegrityLevel, integrityBytes) ||
		!Query(primary, TokenPrivileges, privilegeBytes)) {
		CloseHandle(primary); return 2;
	}
	auto* user = reinterpret_cast<TOKEN_USER*>(userBytes.data());
	auto* integrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrityBytes.data());
	if (!IsValidSid(user->User.Sid) || !IsValidSid(integrity->Label.Sid)) {
		CloseHandle(primary); return 3;
	}
	BYTE count = *GetSidSubAuthorityCount(integrity->Label.Sid);
	if (!count) { CloseHandle(primary); return 4; }
	DWORD level = *GetSidSubAuthority(integrity->Label.Sid, count - 1);
	TOKEN_ELEVATION_TYPE elevation{};
	DWORD returned = 0;
	if (!GetTokenInformation(primary, TokenElevationType, &elevation,
							 sizeof elevation, &returned)) {
		CloseHandle(primary); return 5;
	}
	HANDLE restricted = nullptr;
	if (!CreateRestrictedToken(primary, DISABLE_MAX_PRIVILEGE,
		0, nullptr, 0, nullptr, 0, nullptr, &restricted)) {
		CloseHandle(primary); return 6;
	}
	std::vector<unsigned char> reducedPrivileges, reducedUser;
	bool passed = Query(restricted, TokenPrivileges, reducedPrivileges) &&
				  Query(restricted, TokenUser, reducedUser);
	if (passed) {
		auto* before = reinterpret_cast<TOKEN_PRIVILEGES*>(privilegeBytes.data());
		auto* after = reinterpret_cast<TOKEN_PRIVILEGES*>(reducedPrivileges.data());
		auto* identity = reinterpret_cast<TOKEN_USER*>(reducedUser.data());
		LUID traverse{};
		passed = LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &traverse) != FALSE;
		for (DWORD index = 0; index < after->PrivilegeCount; ++index) {
			const auto& item = after->Privileges[index];
			bool isTraverse = item.Luid.LowPart == traverse.LowPart &&
							  item.Luid.HighPart == traverse.HighPart;
			if ((item.Attributes & SE_PRIVILEGE_ENABLED) && !isTraverse) passed = false;
		}
		passed = EqualSid(user->User.Sid, identity->User.Sid) && passed;
		std::printf("integrity=0x%lx elevation-type=%u privileges=%lu reduced=%lu\n",
			level, static_cast<unsigned>(elevation), before->PrivilegeCount, after->PrivilegeCount);
	}
	CloseHandle(restricted);
	CloseHandle(primary);
	std::printf("same-user and no-enabled-extra-privileges=%d\n", passed);
	return passed ? 0 : 7;
}
```

### Objectives and Steps

1. Inspect identity validity, integrity/elevation classification and privilege counts without publishing personal SIDs.
2. Verify the restricted copy retains the same user SID and has no enabled privilege other than the documented exception.
3. Explain why the calling process remains unchanged.

```bat
cl /nologo /W4 /EHsc /std:c++17 token.cpp /Fe:token.exe /link Advapi32.lib /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
token.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The restricted token is merely an owned object handle until explicitly used by another operation. Checking SID equality is not a group-based authorization test. Do not assume a specific privilege count across machines.

### Solution and Expected Results

A typical non-elevated desktop token has medium integrity, but that is an observation to record, not a universal assertion. The valid checks are SID equality, no enabled non-traverse privilege in the restricted copy, final Boolean 1, and exit zero. The initial token's privilege count and elevation type can differ by account and policy. Closing the restricted token discards it; no process launch, elevation or impersonation occurred.

### Verification, Troubleshooting, and Cleanup

- [ ] Record non-identifying classifications and the two acceptance invariants.
- [ ] Explain why reduced privileges are not equivalent to restricting SIDs or lower integrity.
- [ ] Record OS/compiler versions and any policy failures without elevating.

This program bounds each query to 64 KiB and fails if a fetch changes size; it does not loop forever. An unusual restricted/AppContainer launch can violate the ordinary desktop-token prerequisite. Keep the error as evidence of that environment rather than changing identity to force success.

```bat
del token.exe token.obj
```

Remove the source directory when done; no security settings or accounts were changed.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Local Privilege Escalation]]
- [[Windows Security Model Security]]

## References

- [Access-control model](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-model)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [Mandatory integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
