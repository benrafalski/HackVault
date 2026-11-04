---
title: "Registry"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Registry Security]]"
updated: 2026-11-03
---
# Registry

> [!abstract] TL;DR
> Use explicit registry APIs/views and typed values. Back up only the test key before changes; never bulk-edit system configuration during a lab.

> [!info] Agent scope
> Hives; keys and values; views; access rights; notifications; virtualization; configuration storage.

## Prerequisites

- [[Objects and Handles]], UTF-16 byte lengths, and [[Windows Lab Setup]].
- Windows 11 x64, already installed VS 2022 MSVC v143/Windows SDK 10.0.22621+, x64 Native Tools Command Prompt, standard user with a writable HKCU Software branch.

## Learn

```text
Teach the Windows registry at expert engineering depth. Assume Win32 handles and
UTF-16 buffers. Explain hives, predefined roots, HKCU context, HKCR merged views,
key security versus typed values, volatile/persistent keys, WOW64 shared/redirected
views and virtualization limits. Cover exact RegCreateKeyExW/RegOpenKeyExW rights,
dispositions, LSTATUS returns, RegSetValueExW byte lengths, RegGetValueW type filters,
termination guarantees, enumeration races, change notification rearming and
configuration consistency/durability. Provide a complete self-process disposable
HKCU lab with DWORD/string values, notification, explicit 64/32 view opens where
the chosen branch is shared, checked reads and cleanup. No system configuration,
services, autostarts, privilege changes or confidential data. Use Microsoft primary
docs, distinguish expected and observed behavior, include exact setup/build/run
checks, and explain version caveats. Teach here; do not author files or mark progress.
```

## Cheatsheet

### Storage and Context

Hives are storage units containing keys, values and security information. Keys form a namespace and carry security descriptors; values are named typed byte sequences under a key and do not have separate ACLs. The default value is simply the unnamed value, not guaranteed to exist. Names are normally case-insensitive; preserve spelling for display, not identity.

| Root / concept | Meaning |
| --- | --- |
| `HKEY_LOCAL_MACHINE` | Machine configuration assembled from several hives, not one universal writable file |
| `HKEY_USERS` | Loaded user profiles; HKCU maps to the current user's profile context |
| `HKEY_CURRENT_USER` | User-specific view; cached predefined-handle behavior matters during impersonation. Services should use `RegOpenCurrentUser` for the intended effective context rather than assuming cached HKCU follows every thread |
| `HKEY_CLASSES_ROOT` | Merged class-registration view; not an independent simple hive. Writes and elevated/impersonated behavior need their documented rules |
| Volatile key | `REG_OPTION_VOLATILE` stores the key in memory, discarded when its hive unloads. It still needs explicit lab cleanup and is not a security sandbox |
| Persistent key | Default nonvolatile storage; successful writes do not promise every byte is already durably on disk |

`RegCloseKey` releases an owned key handle; it does not force persistence. `RegFlushKey` forces a costly hive flush and can block other work; ordinary configuration code should not flush after every value. Multi-value updates and enumeration are not automatically transactional. A single validated, versioned value or an application coordination protocol is often simpler than assuming several writes form one atomic configuration change. Registry transaction APIs exist but are a separate compatibility/design decision, not the default behavior of ordinary calls.

### API Contracts

Registry APIs here return `LSTATUS`: **zero is success**; otherwise the returned error is authoritative. Do not fetch unrelated thread last error for these failures.

| API / right | Contract |
| --- | --- |
| `RegCreateKeyExW` | Returns a handle plus `REG_CREATED_NEW_KEY` or `REG_OPENED_EXISTING_KEY`; an existing key is not reset to the requested new options/security. Creating subkeys requires authorization against the parent descriptor; do not assume the parent handle's mask alone defines all create behavior |
| `RegOpenKeyExW` | Explicit desired mask plus at most one WOW64 view selector; no automatic create. Return handle must close with `RegCloseKey` |
| `KEY_QUERY_VALUE` / `KEY_SET_VALUE` | Query values / set or delete values. `KEY_READ` additionally includes enumeration, notification and standard read-control rights; request only needed operations |
| `KEY_ENUMERATE_SUB_KEYS` / `KEY_NOTIFY` | Enumerate subkeys / receive notifications. Values use query rights; keys and values have different enumeration APIs |
| `RegSetValueExW` | Type plus byte pointer and **byte** count. REG_SZ/EXPAND_SZ include the NUL; MULTI_SZ includes the final double NUL. The API does not enforce your application's semantic schema |
| `RegGetValueW` | Query rights; `pcbData` is bytes. Select exact `RRF_RT_REG_DWORD`, `RRF_RT_REG_SZ`, etc.; `RRF_ZEROONFAILURE` clears supplied output on failure. `ERROR_MORE_DATA` requires bounded retry or failure |
| `RegQueryValueExW` | Raw type/data retrieval; strings are not guaranteed terminated. Never pass raw output directly to an unbounded string function |
| `RegEnumValueW` | Value-name capacity is in characters, data capacity in bytes; reinitialize both each iteration. `ERROR_NO_MORE_ITEMS` ends enumeration. Concurrent changes can skip/reorder entries |
| `RegDeleteKeyExW` | Deletes a key with no subkeys, using an explicit view selector. Existing values do not require individual deletion first. Open handles can delay final removal |

`REG_DWORD` is a little-endian 32-bit value; `REG_QWORD` is 64-bit; `REG_BINARY` has no implied schema. `REG_SZ` is a string and `REG_EXPAND_SZ` is a string requiring environment expansion when desired. Expansion depends on the consuming process context. `RRF_NOEXPAND` preserves literal environment references; don't expand user-controlled values into trusted paths without separate validation. `RRF_RT_DWORD` is broader than `RRF_RT_REG_DWORD`: it also accepts compatible binary data.

For `RegGetValueW`, termination is checked/added for supported string types if space permits; insufficient room returns `ERROR_MORE_DATA`. Still validate returned length, type, logical range, embedded NUL semantics and an application-specific maximum. A size probe followed by a fetch can race with writers; cap retries and do not consume failed output.

### Views and Virtualization

On 64-bit Windows, some registry paths have separate 32-bit and 64-bit views; others are shared. Specify `KEY_WOW64_32KEY` or `KEY_WOW64_64KEY` with the access mask consistently for related opens/deletes. These flags select a view, not extra authority, and must not both be set. Avoid hardcoding `Wow6432Node`; use the view API. `reg.exe query ... /reg:32` and `/reg:64` select views for manual inspection.

The lab's ordinary custom `HKCU\Software` branch is shared on the target systems, so reading the same value through both selectors is expected. It does **not** prove that redirected machine/class paths behave the same. ARM64 and historical reflection behavior require their own platform matrix.

Registry virtualization is a compatibility feature for certain legacy 32-bit interactive applications attempting selected machine-software writes. It is not applied universally: 64-bit applications, services, and manifested applications with requested execution level do not rely on it. Do not treat virtualization as a security boundary or design configuration around accidental redirection. This x64 lab uses HKCU explicitly.

### Notifications

`RegNotifyChangeKeyValue(key, subtree, filter, event, TRUE)` asynchronously signals an event when a matching change occurs; key needs `KEY_NOTIFY`. The event must remain alive through the registration. Notification is one-shot: rearm after a signal. It reports “something changed,” not a durable ordered log of each edit. Re-read and validate configuration, and tolerate changes between reads. Closing a key or ending a registering thread can also affect notification behavior; use `REG_NOTIFY_THREAD_AGNOSTIC` where supported and appropriate for pooled threads (Windows 8+). This lab uses one long-lived main thread and one registration.

## Gotchas

- Successful open does not prove the data is well-typed or trusted.
- A notification signal is not proof of a particular value or actor; it can coalesce changes.
- Do not delete a pre-existing key merely because a lab reused its name; check disposition first.
- Do not store plaintext secrets or user-supplied executable commands as trusted configuration.

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No registry operation, compiler/runtime, VM or view test was run during authoring. Results are predicted. Redirected machine branches, services, virtualization, concurrent writers, persistence and audit collection remain unverified.

Create an empty folder in the developer prompt. Only `registry.cpp` is needed. The program creates its synthetic values and removes only its newly created leaf key. No project, data, service or package is required.

```bat
mkdir x1-registry
cd x1-registry
ver
cl /Bv
```

```cpp
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <string>

bool Exercise(HKEY key, const std::wstring& path, HANDLE changed) {
	DWORD initial = 1;
	const wchar_t label[] = L"LAB";
	if (RegSetValueExW(key, L"Count", 0, REG_DWORD,
		reinterpret_cast<const BYTE*>(&initial), sizeof initial) != ERROR_SUCCESS) return false;
	if (RegSetValueExW(key, L"Label", 0, REG_SZ,
		reinterpret_cast<const BYTE*>(label), sizeof label) != ERROR_SUCCESS) return false;
	LSTATUS registered = RegNotifyChangeKeyValue(key, FALSE,
		REG_NOTIFY_CHANGE_LAST_SET, changed, TRUE);
	DWORD next = 2;
	LSTATUS written = registered == ERROR_SUCCESS ? RegSetValueExW(key, L"Count", 0,
		REG_DWORD, reinterpret_cast<const BYTE*>(&next), sizeof next) : registered;
	DWORD waited = written == ERROR_SUCCESS ? WaitForSingleObject(changed, 5000) : WAIT_FAILED;
	if (registered != ERROR_SUCCESS || written != ERROR_SUCCESS || waited != WAIT_OBJECT_0)
		return false;
	DWORD value = 0, bytes = sizeof value, type = 0;
	LSTATUS read = RegGetValueW(key, nullptr, L"Count",
		RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, &type, &value, &bytes);
	bool passed = read == ERROR_SUCCESS && type == REG_DWORD && bytes == sizeof value && value == 2;
	wchar_t text[16]{};
	bytes = sizeof text;
	read = RegGetValueW(key, nullptr, L"Label", RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
						&type, text, &bytes);
	passed = read == ERROR_SUCCESS && type == REG_SZ && bytes == sizeof label &&
			 std::wcscmp(text, label) == 0 && passed;
	HKEY alternate = nullptr;
	LSTATUS opened = RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0,
		KEY_QUERY_VALUE | KEY_WOW64_32KEY, &alternate);
	DWORD other = 0;
	bytes = sizeof other;
	if (opened == ERROR_SUCCESS) {
		read = RegGetValueW(alternate, nullptr, L"Count", RRF_RT_REG_DWORD,
							nullptr, &other, &bytes);
		passed = read == ERROR_SUCCESS && bytes == sizeof other && other == 2 && passed;
		RegCloseKey(alternate);
	} else passed = false;
	bytes = sizeof value;
	LSTATUS missing = RegGetValueW(key, nullptr, L"Absent", RRF_RT_REG_DWORD,
								   nullptr, &value, &bytes);
	passed = missing == ERROR_FILE_NOT_FOUND && passed;
	std::printf("notified=1 shared-view-count=%lu missing=%ld checks=%d\n", other, missing, passed);
	return passed;
}
int wmain() {
	std::wstring path = L"Software\\HackVault.X1.Registry." + std::to_wstring(GetCurrentProcessId());
	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS created = RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr,
		REG_OPTION_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_NOTIFY | KEY_WOW64_64KEY,
		nullptr, &key, &disposition);
	if (created != ERROR_SUCCESS) { std::printf("create=%ld\n", created); return 1; }
	if (disposition != REG_CREATED_NEW_KEY) { RegCloseKey(key); return 2; }
	std::printf("owned key=HKCU\\%ls\n", path.c_str());
	HANDLE changed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	bool passed = changed && Exercise(key, path, changed);
	LSTATUS closed = RegCloseKey(key);
	if (changed) CloseHandle(changed);
	LSTATUS deleted = RegDeleteKeyExW(HKEY_CURRENT_USER, path.c_str(), KEY_WOW64_64KEY, 0);
	std::printf("close=%ld delete=%ld\n", closed, deleted);
	return passed && closed == ERROR_SUCCESS && deleted == ERROR_SUCCESS ? 0 : 3;
}
```

### Objectives and Steps

1. Write/read exact typed values and observe a one-shot change event.
2. Read the chosen shared branch through the alternate explicit view.
3. Distinguish missing value, notification success, and deletion result.

```bat
cl /nologo /W4 /EHsc /std:c++17 registry.cpp /Fe:registry.exe /link Advapi32.lib /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
registry.exe
echo Exit=%ERRORLEVEL%
```

### Hints

Register before writing the changed value. Byte capacity includes wide-character terminators. HKCU Software sharing is specific to the selected branch, not proof that view flags are ignored everywhere.

### Solution and Expected Results

The initial values are Count DWORD 1 and Label string `LAB`. Notification is armed, Count becomes 2, the event signals, typed reads succeed, and the 32-view open sees 2 in this shared branch. Absent value returns 2 (`ERROR_FILE_NOT_FOUND`). Expected `checks=1`, `close=0 delete=0`, exit zero. The key name includes the actual PID and changes between runs; deletion removes only the owned leaf.

### Verification, Troubleshooting, and Cleanup

- [ ] Observe notification, typed values, missing error and zero cleanup statuses.
- [ ] Explain which state is shared and which view behavior remains untested.
- [ ] Record OS/compiler and actual results; verify the printed key is gone.

Exit 2 means the name already existed and was left untouched. If a failed run leaves a key, inspect the **exact printed name**; the following manual commands require substituting that run's PID, and must never target the entire Software branch:

```bat
reg query "HKCU\Software\HackVault.X1.Registry.<PID>" /reg:64
reg delete "HKCU\Software\HackVault.X1.Registry.<PID>" /reg:64 /f
del registry.exe registry.obj
```

Normal successful runs need no manual registry deletion. If initial creation is denied, use an authorized writable user lab environment, not elevation. Remove the source directory when finished.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Registry Security]]

## References

- [Registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [RegGetValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew)
- [RegNotifyChangeKeyValue](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue)
- [Registry keys affected by WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
- [Registry virtualization](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-virtualization)
- [Registry key security and access rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
