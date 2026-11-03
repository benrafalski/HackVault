---
title: "Registry Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Registry]]"
updated: 2026-11-03
---
# Registry Security

> [!abstract] TL;DR
> Writable privileged configuration, unsafe path interpretation, and autostart settings can redirect trusted behavior.

> [!info] Agent scope
> Security of: Hives; keys and values; views; access rights; notifications; virtualization; configuration storage. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Type-confused values, unchecked sizes/ranges, wrong view/context and overbroad key handles can turn configuration into unintended behavior.
- Key ACLs protect key/value operations, not the semantic correctness of data written by an authorized user. This page uses only a synthetic retry-count setting under HKCU.

## Learn

```text
Teach defensive Windows registry consumption at expert depth. Assume Win32 and
typed configuration. Explain key ACLs versus value schemas, precise query/set
rights, LSTATUS return conventions, byte counts and UTF-16 termination, exact
RegGetValueW type filters, zero-on-failure, range budgets, view consistency and
HKCU impersonation caveats. Cover notifications as invalidation rather than audit,
concurrent writers, multi-value consistency, volatility and virtualization limits.
Build an independent benign HKCU lab that shows a raw reader accepting binary
bytes as a DWORD retry count, fixes it with exact type/size/range checks, rejects
malformed and missing values, retains a valid DWORD, and proves a query-only key
handle cannot set the value. Supply all source, fixtures, commands and cleanup.
No privileged service, autostarts, execution-path configuration, bypasses, real
secrets or system edits. Use primary Microsoft docs and distinguish expected from
observed results. Teach in chat; do not author files or change study progress.
```

## Cheatsheet

### Schema Validation Is Separate from Authorization

| Boundary | Required defense |
| --- | --- |
| Key open | Request `KEY_QUERY_VALUE` for a value reader; avoid `KEY_ALL_ACCESS`. Use the intended root, identity and one explicit WOW64 view |
| API result | Registry routines return `LSTATUS`; zero success, nonzero error. Never treat them as BOOL or replace the returned error with `GetLastError` |
| DWORD | `RegGetValueW(..., RRF_RT_REG_DWORD, ...)`, verify size `sizeof(DWORD)` and permitted range. `RRF_RT_DWORD` also permits four-byte binary and is not an exact-type gate |
| String | Bound bytes, require the intended type, use termination-aware API, reject unexpected embedded NUL/trailing data according to schema |
| Expandable string | Choose literal `RRF_NOEXPAND` or explicit expansion policy. Environment-dependent expansion changes meaning across identities; do not trust it as a path approval |
| Missing/malformed value | Fail closed or apply an explicitly safe documented default; do not reuse stale output after failure |
| Config refresh | Treat notification as invalidation; re-read and validate an entire logical snapshot under a consistency protocol |

`RegSetValueExW` stores caller-specified type and byte count; it does not guarantee that data tagged DWORD actually contains four bytes or that strings are terminated. `RegQueryValueExW` exposes raw data; a four-byte buffer containing 7 with `REG_BINARY` can fool a consumer that ignores the returned type. The fixed lab uses `RRF_RT_REG_DWORD | RRF_ZEROONFAILURE` plus an exact byte count and range 1..10. Zero-on-failure is defense in depth, not permission to accept zero without checking status.

For variable strings, a length query then allocation is a race with concurrent writers. Reinitialize capacity on each bounded retry, cap maximum bytes, reject odd UTF-16 byte lengths, and don't read failed output. `RegGetValueW` can append missing string terminators if capacity permits, but it does not validate application semantics. `REG_MULTI_SZ` requires a bounded sequence and final double termination; unbounded `wcslen` over raw registry data is unsafe.

### Least Privilege and Its Limits

Keys, not individual values, have ACLs. Put settings with distinct writers into separate keys, and protect privileged configuration from lower-trust writers. A reader needs `KEY_QUERY_VALUE`; a watcher adds `KEY_NOTIFY`; setting/deleting values needs `KEY_SET_VALUE`. `KEY_READ` is broader than query-only and includes enumeration/notification/read-control. `WRITE_DAC` lets policy be changed and should not be given to a consumer.

Do not claim a query-only handle is a complete sandbox: some registry operations, such as subkey creation, perform checks against the key security descriptor rather than treating the existing handle's requested mask as the whole decision. Same-process code may also open another handle. The concrete tested contract is `RegSetValueExW` requiring `KEY_SET_VALUE` on its handle. Other-user denial requires an actual separate-identity ACL test and is not inferred here.

`RegCreateKeyExW` can open an existing key; inspect disposition before mutation or cleanup. New security/options do not automatically replace existing state. Close handles with `RegCloseKey`; use the same explicit view during delete. Never recursively delete a broad parent key as “cleanup.” The lab creates a unique leaf, aborts on collision, and deletes only a leaf it created.

### Views, Identity and Races

On 64-bit Windows, registry views can be redirected or shared by path. `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY` select views, not privileges. Don't set both, don't hardcode `Wow6432Node`, and don't conclude from a shared HKCU Software test that HKLM/class keys behave identically. Legacy virtualization is compatibility behavior, not isolation; it does not apply universally to services, x64 programs or manifested applications.

HKCU is context-sensitive and predefined handles may be cached; code impersonating users should use the documented current-user-open API and check identity/lifetime rather than reuse an unrelated cached root. HKCR is a merged view, not a straightforward policy store. Privileged applications should avoid consuming mutable user configuration as commands or trusted executable paths.

Notifications have no actor identity, old/new data, or guaranteed record of every mutation. Register before observing the protected state as appropriate, rearm after signaling, and design for coalescing and races. A read-only handle does not stop another writer. Multi-value reads are not a transactional snapshot; use a single bounded versioned representation or coordinated revision protocol where consistency matters. `RegFlushKey` addresses persistence, not consistency or authorization, and is unnecessarily costly per setting.

## Detection and Defense

Log schema version, exact value type, bounded length, chosen view, validation reason and returned API code without dumping real configuration data. An invalid type can be a deployment mistake rather than malicious activity. Targeted auditing needs configured policy/SACL or a collector; notifications and this lab's console output are not audit logs. Defend at both layers: restrict writers and validate every consumed value even when an authorized writer produced it.

## Labs

### Environment and Complete Files

Windows 11 x64, installed VS 2022 MSVC v143/Windows SDK 10.0.22621+, x64 Native Tools prompt, standard user with writable HKCU Software. One file, `registry-schema.cpp`; all fixture values are seeded by the program. No service, external identity, project file or package is needed.

> [!warning] Unverified execution
> No build, registry operation, runtime/VM test or audit collection was performed during authoring. Results are predicted. Separate-identity ACL enforcement, service consumption, redirected views, concurrent refresh and policy telemetry remain unverified.

```bat
mkdir x1-registry-schema
cd x1-registry-schema
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>
#include <string>

bool WeakRead(HKEY key) {
	DWORD type = 0, value = 0, bytes = sizeof value;
	LSTATUS result = RegQueryValueExW(key, L"Retries", nullptr, &type,
		reinterpret_cast<BYTE*>(&value), &bytes);
	return result == ERROR_SUCCESS && bytes == sizeof value && value >= 1 && value <= 10;
}
bool FixedRead(HKEY key) {
	DWORD value = 0, type = 0, bytes = sizeof value;
	LSTATUS result = RegGetValueW(key, nullptr, L"Retries",
		RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, &type, &value, &bytes);
	return result == ERROR_SUCCESS && type == REG_DWORD &&
		bytes == sizeof value && value >= 1 && value <= 10;
}
bool Case(HKEY key, const char* name, DWORD type, DWORD value,
		  DWORD bytes, bool weakExpected, bool fixedExpected) {
	LSTATUS stored = RegSetValueExW(key, L"Retries", 0, type,
		reinterpret_cast<const BYTE*>(&value), bytes);
	if (stored != ERROR_SUCCESS) return false;
	bool weak = WeakRead(key), fixed = FixedRead(key);
	std::printf("%s weak=%d fixed=%d\n", name, weak, fixed);
	return weak == weakExpected && fixed == fixedExpected;
}
bool Exercise(HKEY key, const std::wstring& path) {
	bool passed = Case(key, "binary", REG_BINARY, 7, sizeof(DWORD), true, false);
	passed = Case(key, "valid", REG_DWORD, 7, sizeof(DWORD), true, true) && passed;
	passed = Case(key, "out-of-range", REG_DWORD, 700, sizeof(DWORD), false, false) && passed;
	passed = Case(key, "short", REG_DWORD, 7, 1, false, false) && passed;
	if (RegDeleteValueW(key, L"Retries") != ERROR_SUCCESS) return false;
	bool missingWeak = WeakRead(key), missingFixed = FixedRead(key);
	std::printf("missing weak=%d fixed=%d\n", missingWeak, missingFixed);
	passed = !missingWeak && !missingFixed && passed;
	passed = Case(key, "restored", REG_DWORD, 7, sizeof(DWORD), true, true) && passed;
	HKEY reader = nullptr;
	LSTATUS opened = RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
		KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reader);
	if (opened != ERROR_SUCCESS) return false;
	DWORD attempted = 8;
	LSTATUS denied = RegSetValueExW(reader, L"Retries", 0, REG_DWORD,
		reinterpret_cast<const BYTE*>(&attempted), sizeof attempted);
	bool retained = FixedRead(reader);
	DWORD observed = 0, bytes = sizeof observed;
	LSTATUS read = RegGetValueW(reader, nullptr, L"Retries", RRF_RT_REG_DWORD,
							   nullptr, &observed, &bytes);
	RegCloseKey(reader);
	passed = denied == ERROR_ACCESS_DENIED && retained && read == ERROR_SUCCESS &&
			 bytes == sizeof observed && observed == 7 && passed;
	std::printf("reader-set=%ld retained-read=%d unchanged=%d\n", denied, retained, observed == 7);
	return passed;
}
int wmain() {
	std::wstring path = L"Software\\HackVault.X1.Schema." + std::to_wstring(GetCurrentProcessId());
	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS created = RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr,
		REG_OPTION_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
		nullptr, &key, &disposition);
	if (created != ERROR_SUCCESS) { std::printf("create=%ld\n", created); return 1; }
	if (disposition != REG_CREATED_NEW_KEY) { RegCloseKey(key); return 2; }
	std::printf("owned key=HKCU\\%ls\n", path.c_str());
	bool passed = Exercise(key, path);
	LSTATUS closed = RegCloseKey(key);
	LSTATUS deleted = RegDeleteKeyExW(HKEY_CURRENT_USER, path.c_str(), KEY_WOW64_64KEY, 0);
	std::printf("checks=%d close=%ld delete=%ld\n", passed, closed, deleted);
	return passed && closed == ERROR_SUCCESS && deleted == ERROR_SUCCESS ? 0 : 3;
}
```

### Objectives and Baseline

1. Demonstrate a four-byte binary value accepted by the weak reader even though the schema requires DWORD.
2. Reject wrong type, short data, out-of-range value and absence while preserving valid value 7.
3. Prove a query-only handle cannot set a valid replacement value, and the original remains readable and unchanged.

```bat
cl /nologo /W4 /EHsc /std:c++17 registry-schema.cpp /Fe:registry-schema.exe /link Advapi32.lib /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
registry-schema.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The weak reader deliberately ignores the returned `type`; it does not overflow a buffer. Exact-type filtering differs from the broader DWORD-or-binary convenience flag. The final permission test uses a real key handle, not a Boolean role simulation.

### Solution and Fixed Retest

Expected matrix: `binary weak=1 fixed=0`; `valid` and `restored` both `1/1`; `out-of-range`, `short` and `missing` all `0/0`. The query-only set returns 5, retained read is 1 and unchanged is 1. Final `checks=1 close=0 delete=0`, exit zero. The registry permits storing deliberately malformed typed fixture bytes; the consumer must reject them. If a target API rejects fixture creation itself, record that version-specific result rather than inventing the expected matrix.

### Verification, Troubleshooting, and Cleanup

- [ ] Record six schema verdicts and the denied set with retained value 7.
- [ ] Explain why changing only handle rights would not fix a wrong-type reader.
- [ ] Record OS/compiler versions and verify deletion of the exact printed leaf key.

An existing key is left untouched. If an interrupted run leaves a newly created key, substitute the actual printed PID and inspect only that owned leaf before cleanup:

```bat
reg query "HKCU\Software\HackVault.X1.Schema.<PID>" /reg:64
reg delete "HKCU\Software\HackVault.X1.Schema.<PID>" /reg:64 /f
del registry-schema.exe registry-schema.obj
```

Normal successful runs already delete the key. No machine configuration, executable paths, autostart values or services are touched. Remove the source directory when done.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Registry]]

## References

- [RegGetValueW type and buffer contract](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew)
- [RegQueryValueExW string caveats](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)
- [RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)
- [Registry key security and access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- [Registry virtualization](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-virtualization)
