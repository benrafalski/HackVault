---
title: "Loader and DLLs Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Loader and DLLs]]"
updated: 2026-11-03
---
# Loader and DLLs Security

> [!abstract] TL;DR
> Writable search locations, ambiguous dependency names, and unsafe initialization or unload behavior can redirect execution or corrupt process state.

> [!info] Agent scope
> Security of: PEB; module loading; search order; IAT/EAT; relocations; loader lock; initialization; DLL lifetime. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Module selection, transitive dependencies, initialization, export ABI and unload synchronization are separate validation responsibilities.
- An absolute path and an ABI version are useful controls, but neither proves code is trustworthy. Normal loading runs initialization before the caller can inspect exports.

## Learn

```text
Teach defensive Windows DLL integration at expert depth. Assume PE imports/exports
and C++ ownership. Cover explicit paths and bounded dependency search, directory
permissions, deployment provenance, ABI version/size checks, exact GetProcAddress
signatures, loader lock and CRT initialization, reference ownership, callbacks and
unload races. Explain why PEB lists and successful module loads are not trust checks,
and why post-load validation cannot stop already-run initialization. Give a complete
self-process exercise using two self-authored harmless DLLs: both load, but an ABI
gate accepts only version 1 and preserves its successful data query. Also reject a
missing export without calling it. Include deterministic cleanup, exact commands,
expected checks, version caveats and detection limits. No DLL placement attacks,
hijacking, injection, bypasses, unhooking or private data. Use primary Microsoft
docs and do not invent execution. Teach in conversation, not file authoring.
```

## Cheatsheet

### Independent Gates

| Gate | Defensive contract | What it does not prove |
| --- | --- | --- |
| Resolution | Use a full application-owned path; narrow dependencies with per-call `LOAD_LIBRARY_SEARCH_*` flags | Files at that path may still be writable or untrusted; loaded modules/API sets/manifests affect resolution |
| Deployment | Protect binary and dependency directories from lower-trust writes; validate package/publisher policy before deployment | An ABI number or basename is not a signer identity |
| Initialization | Keep `DllMain` and static initialization minimal; perform complex work after load through an explicit API | Calling an ABI export is already executing the DLL; it cannot safely vet arbitrary code |
| Interface | Require a documented version and exact calling convention, widths, layout and buffer sizes | A matching version does not guarantee memory safety or benign behavior |
| Ownership | Keep an owned module reference over calls/callbacks; drain users before final release | A nonnull cached pointer does not keep code mapped |

For a normal executable DLL load, `LoadLibraryExW` returns `NULL` on failure and an owned `HMODULE` on success. Its second parameter must be null. A valid `HMODULE` is not a kernel-object handle: `FreeLibrary`, not `CloseHandle`, releases it. `GetModuleHandleW` does not increment the count, so treating it as owned can prematurely unload a module. `GetModuleHandleExW` normally acquires ownership; explicitly opting out restores the borrowed-reference race.

`GetProcAddress` uses case-sensitive narrow export names. Nonnull means an export was found, not that it has your guessed C prototype. Avoid ordinal lookup unless the ABI guarantees ordinals; sparse export ordinal assignments have surprising lookup behavior. For cross-toolchain/plugin ABIs, prefer `extern "C"`, fixed-width scalar values, caller-sized structs beginning with a size/version field, explicit buffer lengths and same-module deallocation. Do not export STL ownership or let exceptions cross an ABI not designed for them.

### Baseline and Fixed Pattern

The mistake exercised below is `loaded != NULL` being treated as interface compatibility. Both versions of the self-authored fixture load, so that predicate accepts both. The fixed path resolves **both** `LabAbi` and `LabValue`, checks `LabAbi() == 1`, then calls the data function while the owner object retains the module. The incompatible fixture is rejected without invoking `LabValue`; its harmless initialization has already run, so this is a compatibility gate, not a security sandbox.

`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32` limits dependency directories for the explicit target. The target directory must itself be trusted. `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS` is broader because it includes application and registered user directories. Avoid process-wide current-directory changes as a loading strategy; another thread can observe them. `AddDllDirectory` cookies need deliberate lifetime and removal, and order among multiple directories is unspecified. Packaged apps and older supported flag availability require a separate deployment test matrix.

### Races and Least Privilege

Hashing a pathname then loading it later can race with replacement. Protect installation/update operations and use supported signing/application-control policy, rather than assuming a post-load path check reverses initialization. A PEB module entry is mutable bookkeeping and not a trust oracle. `GetModuleFileNameW` is useful provenance evidence but does not close deployment races.

Ordinary loading needs no administrator privileges. It consumes executable code with the host's authority: a plugin is not a lower-privilege process. Keep a single owner or synchronized shared owner; reject new calls during shutdown, unregister callbacks, join workers, then release. Never wait for those workers from `DllMain`, where loader lock can participate in a deadlock. Do not call a function pointer after its module owner is gone, even if a test happens not to crash because another reference exists.

## Detection and Defense

Log resolved target path, intended dependency policy, ABI result, lookup/load error and application version. Do not classify all unsigned development DLLs as hostile or treat signatures as proof of benignness. Image-load telemetry requires an enabled provider/collector and may be filtered or absent; no image-load event is claimed here. Defense includes controlled deployment, minimal host privileges, documented ABI checks and deterministic teardown, not a user-mode module-list scan alone.

## Labs

### Environment and Complete Files

Windows 11 x64, installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools prompt, standard user. Only the two source files below are needed. Both DLL variants are intentionally benign and built from the same source; there is no external module input or search-path redirection exercise.

> [!warning] Unverified execution
> No build, runtime, VM, signing-policy or telemetry validation was performed during authoring. All results are expected. The exercise does not validate trust against arbitrary plugins, concurrent shutdown, cross-bitness or packaged-app loading.

```bat
mkdir x1-loader-contract
cd x1-loader-contract
ver
cl /Bv
```

`plugin.cpp`:

```cpp
#include <windows.h>
#ifndef LAB_ABI
#define LAB_ABI 1
#endif
extern "C" __declspec(dllexport) DWORD WINAPI LabAbi() { return LAB_ABI; }
extern "C" __declspec(dllexport) DWORD WINAPI LabValue() { return 73; }
```

`contract.cpp`:

```cpp
#include <windows.h>
#include <cstdio>
#include <string>

class Module {
	HMODULE module_;
public:
	explicit Module(const std::wstring& path) : module_(LoadLibraryExW(path.c_str(),
		nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)) {}
	~Module() { if (module_) FreeLibrary(module_); }
	Module(const Module&) = delete;
	Module& operator=(const Module&) = delete;
	HMODULE get() const { return module_; }
};
bool Check(const std::wstring& path, bool shouldAccept) {
	Module module(path);
	if (!module.get()) {
		std::printf("load failure=%lu\n", GetLastError());
		return false;
	}
	bool weakAccepted = module.get() != nullptr;
	using Query = DWORD (WINAPI*)();
	auto abi = reinterpret_cast<Query>(GetProcAddress(module.get(), "LabAbi"));
	auto value = reinterpret_cast<Query>(GetProcAddress(module.get(), "LabValue"));
	FARPROC absent = GetProcAddress(module.get(), "MissingLabExport");
	DWORD absentError = absent ? ERROR_SUCCESS : GetLastError();
	bool fixedAccepted = abi && value && abi() == 1;
	DWORD observed = fixedAccepted ? value() : 0;
	std::printf("weak=%d fixed=%d value=%lu missing=%lu\n", weakAccepted,
				fixedAccepted, observed, absentError);
	return weakAccepted && fixedAccepted == shouldAccept &&
		(shouldAccept ? observed == 73 : observed == 0) &&
		!absent && absentError == ERROR_PROC_NOT_FOUND;
}
int wmain() {
	wchar_t image[32768]{};
	DWORD length = GetModuleFileNameW(nullptr, image, 32768);
	if (!length || length >= 32768) return 1;
	std::wstring directory(image, length);
	auto separator = directory.find_last_of(L'\\');
	if (separator == std::wstring::npos) return 2;
	directory.resize(separator + 1);
	bool good = Check(directory + L"Compatible.dll", true);
	bool rejected = Check(directory + L"Incompatible.dll", false);
	std::printf("compatible=%d rejected-incompatible=%d\n", good, rejected);
	return good && rejected ? 0 : 3;
}
```

### Objectives and Baseline

1. Build two distinct ABI variants and the consumer.
2. Predict the weak and fixed acceptance matrices.
3. Explain why these checks are insufficient for an arbitrary untrusted DLL.

```bat
cl /nologo /W4 /EHsc /std:c++17 /MT /LD /DLAB_ABI=1 plugin.cpp /Fo:compatible.obj /link /OUT:Compatible.dll /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
cl /nologo /W4 /EHsc /std:c++17 /MT /LD /DLAB_ABI=2 plugin.cpp /Fo:incompatible.obj /link /OUT:Incompatible.dll /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
cl /nologo /W4 /EHsc /std:c++17 /MT contract.cpp /Fe:contract.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
contract.exe
echo Exit=%ERRORLEVEL%
```

### Hints

The weak predicate says only that normal loading succeeded. The fixed predicate is evaluated before the value query, and the scoped owner survives both lookups and calls.

### Solution and Fixed Retest

Compatible should print `weak=1 fixed=1 value=73 missing=127`. Incompatible should print `weak=1 fixed=0 value=0 missing=127`. Final booleans are both 1 and exit is zero. Retest with the same executable: both positive and negative paths run every time. No export pointer escapes `Check`, and the destructor releases its module reference on every return. A failed destructor cleanup is not separately diagnosed by this minimal wrapper; a production shutdown path should report cleanup failures outside a throwing destructor.

### Verification, Troubleshooting, and Cleanup

- [ ] Record both compatibility decisions and retained value 73.
- [ ] Explain why missing-export detection occurs without an invalid function call.
- [ ] Record OS/compiler versions and identify the untested deployment assumptions.

On error 193, confirm every file was built for x64. On error 126, check the exact files and dependencies without widening search policy. If application control blocks the unsigned fixture, leave policy intact and record the missing lab prerequisite.

```bat
del contract.exe contract.obj Compatible.dll Compatible.lib Compatible.exp compatible.obj
del Incompatible.dll Incompatible.lib Incompatible.exp incompatible.obj
```

No machine configuration, DLL registration or service is changed. Remove the source directory when done.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Persistence]]
- [[Process Injection]]
- [[Loader and DLLs]]

## References

- [Dynamic-link library security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security)
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
- [DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
