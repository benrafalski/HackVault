---
title: "Loader and DLLs"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Loader and DLLs Security]]"
updated: 2026-11-03
---
# Loader and DLLs

> [!abstract] TL;DR
> Use safe loader APIs/flags and controlled directories; keep DllMain minimal. Distinguish module enumeration from trustworthy provenance.

> [!info] Agent scope
> PEB; module loading; search order; IAT/EAT; relocations; loader lock; initialization; DLL lifetime.

## Prerequisites

- [[PE Format]], C++ function pointers and ownership, and [[Windows Lab Setup]].
- Windows 11 x64, already installed VS 2022 MSVC v143 and Windows SDK 10.0.22621+, x64 Native Tools Command Prompt, standard user.

## Learn

```text
Teach the Windows user-mode loader and DLL lifetime at expert depth. Assume PE
headers, RVAs and C++ function pointers. Explain image mapping, import lookup/IAT
resolution, EAT forwarders, API sets, relocation delta, TLS/CRT initialization,
DllMain serialization and loader-lock constraints. Explain PEB loader bookkeeping
as version-sensitive observation, not an application traversal API. Compare
load-time and run-time linking, exact LoadLibraryExW/GetProcAddress/FreeLibrary
contracts, borrowed GetModuleHandle versus owned references, and unload races.
Explain packaged/unpackaged search policy and safe per-call directory flags without
redirection demonstrations. Build a harmless owned DLL loaded by explicit path;
prove two owned references keep one export usable until both release. Include
missing-export and architecture failures, build/run commands, expected checks and
cleanup. Use Microsoft primary docs; never invent runtime results. No injection,
hijacking, evasion, private data or debugger commands. Teach here, not file authoring.
```

## Cheatsheet

### Loading Is More Than Mapping

Load-time linking records dependencies and import thunks in a PE; loader initialization must satisfy them before application code normally runs. Run-time linking explicitly acquires a module and looks up exports. A raw file buffer is neither an initialized module nor a callable function collection.

Conceptually, loading selects an image under the applicable resolution policy, maps its sections, accounts for its actual base, resolves dependencies and imports, establishes TLS/runtime state, and runs initialization. Relocations adjust base-dependent fields by actual minus preferred image base; they do not mean every RVA in the file is rewritten. The ILT describes requested names/ordinals; the initialized IAT holds callable addresses. The EAT identifies exports, including data and forwarder strings. `GetProcAddress` can resolve forwarding; do not assume the returned address lies inside the named module. API-set names are contracts mapped to implementation hosts, not necessarily physical files with matching names.

The PEB contains process/loader bookkeeping and module-list information. These user-mode structures can change layout and change concurrently; they are neither stable public enumeration contracts nor authoritative provenance. Prefer documented module APIs such as `EnumProcessModulesEx` and `GetModuleFileNameW`. Module snapshots can race with load/unload, and cross-bitness observation has limits. Use [[WinDbg]] for debugger procedures only.

### Contracts and Ownership

| API | Contract |
| --- | --- |
| `LoadLibraryExW(path, NULL, flags)` | Returns `HMODULE` or `NULL`; capture last error on failure. `hFile` is reserved and must be null. Normal loads acquire an owned module reference; release with `FreeLibrary`, never `CloseHandle` |
| `GetProcAddress(module, "ExactName")` | Returns `FARPROC` or `NULL`; export names are case-sensitive narrow strings even in a Unicode program. Cast only to the **exact** ABI, including calling convention, argument widths and return type |
| `FreeLibrary(module)` | `BOOL`; drops the caller's reference. Final release can run detach and unmap the module. All cached pointers and callbacks must already be quiescent |
| `GetModuleHandleW(name)` | Borrowed module handle, no reference increment; do not `FreeLibrary` it. A concurrent unload/reload can make the observation stale |
| `GetModuleHandleExW(flags, nameOrAddress, &module)` | Normally acquires a reference; `UNCHANGED_REFCOUNT` does not. `FROM_ADDRESS` avoids ambiguous basename lookup. `PIN` keeps the module until process exit, not a reversible temporary acquisition |
| `GetModuleFileNameW(module, buffer, capacity)` | Length in UTF-16 characters excluding terminator on success; zero fails. A result equal to capacity means truncation on supported modern Windows |

A module reference and a function pointer are different resources. Keep an owned reference throughout **every** call, including callbacks and asynchronous work. The loader's reference count does not track arbitrary function-pointer use. Close workers, unregister callbacks, drain pending calls, then release the owning module. Returning memory across DLL boundaries needs an explicit allocator/release contract; independent static CRT heaps are not interchangeable. Stable plugin interfaces favor fixed-width values and caller-owned buffers over exported STL objects or exceptions.

### Search Policy Without Guesswork

For unpackaged applications under ordinary safe search behavior, loader factors such as redirection, API sets, side-by-side manifests, already-loaded modules and KnownDLLs precede ordinary directory lookup. Directory search traditionally includes the executable directory, system directories, Windows directory, current directory and PATH in the documented order. Package dependency graphs can also participate on current systems. Packaged apps use a different policy. Therefore, a single hardcoded list is not a universal model.

Prefer an absolute application-owned path and per-call flags. `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` requires a fully qualified target and searches its directory for dependencies, not arbitrary caller directories. Combine with `LOAD_LIBRARY_SEARCH_SYSTEM32` for a narrow dependency policy. `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS` additionally includes application and registered user directories; it is broader, not automatically a provenance check. `SetDefaultDllDirectories` changes process-wide policy; `AddDllDirectory` returns a cookie to remove with `RemoveDllDirectory`. Order among multiple added directories is unspecified. Do not mix `LOAD_WITH_ALTERED_SEARCH_PATH` with `LOAD_LIBRARY_SEARCH_*`.

Absolute paths constrain resolution but do not validate file ownership, signatures, transitive dependencies or all redirection mechanisms. Protect deployment directories and choose application-control policy separately. Current Windows supports these flags; older Windows versions require compatibility updates and are not this lab's target.

### Initialization and Locking

`DllMain` executes under loader synchronization, with process/thread attach/detach reasons. Keep it minimal: avoid loading libraries, COM initialization, waiting on threads, or taking locks that can invert with loader lock. CRT static constructors invoked during DLL initialization share these constraints. Put fallible heavy initialization in an explicit exported initialization function called after loading. Returning FALSE during process attach causes load failure; dependencies or CRT startup can fail before your export is reached.

During process termination, other threads may already be gone and shared state inconsistent. Do not perform complex teardown in process-detach under those conditions. The supplied DLL needs no custom `DllMain`; the compiler runtime supplies the normal entry machinery.

## Gotchas

- Successful load does not verify the interface version or export signature.
- `DONT_RESOLVE_DLL_REFERENCES` is not a safe halfway state for calling exports; do not use it for this purpose.
- Data/resource load flags do not prepare executable imports/initialization and are not equivalent to normal DLL loading.
- Missing target and missing transitive dependency can both surface as module-not-found; wrong machine commonly yields `ERROR_BAD_EXE_FORMAT`.

## Labs

### Environment and Complete Files

> [!warning] Unverified execution
> No build, DLL load, runtime inspection or VM test was performed during authoring. All results are expected. Search-order variants, package behavior, alternate architectures and concurrent unload remain untested. The exercise only loads its own compiled DLL by explicit path.

Create an empty folder in the developer prompt. Two complete files follow; no project or data files are needed. `/MT` avoids a separately deployed MSVC runtime DLL for this small fixture.

```bat
mkdir x1-loader
cd x1-loader
ver
cl /Bv
```

`labdll.cpp`:

```cpp
#include <windows.h>
extern "C" __declspec(dllexport) DWORD WINAPI LabValue() {
	return 73;
}
```

`load.cpp`:

```cpp
#include <windows.h>
#include <cstdio>
#include <string>

int wmain() {
	wchar_t image[32768]{};
	DWORD length = GetModuleFileNameW(nullptr, image, 32768);
	if (!length || length >= 32768) return 1;
	std::wstring path(image, length);
	auto separator = path.find_last_of(L'\\');
	if (separator == std::wstring::npos) return 2;
	path.resize(separator + 1);
	path += L"Lab.dll";
	DWORD flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
	HMODULE first = LoadLibraryExW(path.c_str(), nullptr, flags);
	if (!first) {
		std::printf("load error=%lu\n", GetLastError());
		return 3;
	}
	HMODULE second = LoadLibraryExW(path.c_str(), nullptr, flags);
	if (!second) { FreeLibrary(first); return 4; }
	using ValueFunction = DWORD (WINAPI*)();
	auto value = reinterpret_cast<ValueFunction>(GetProcAddress(second, "LabValue"));
	FARPROC missing = GetProcAddress(second, "NoSuchLabExport");
	DWORD missingError = missing ? ERROR_SUCCESS : GetLastError();
	bool passed = first == second && value && !missing &&
				  missingError == ERROR_PROC_NOT_FOUND;
	if (!FreeLibrary(first)) passed = false;
	first = nullptr;
	DWORD result = value ? value() : 0;
	passed = result == 73 && passed;
	std::printf("value-after-first-release=%lu missing-error=%lu\n", result, missingError);
	value = nullptr;
	if (!FreeLibrary(second)) passed = false;
	second = nullptr;
	std::printf("checks=%d\n", passed);
	return passed ? 0 : 5;
}
```

### Objectives and Steps

1. Build both files as x64 and inspect exports/imports without loading unknown files.
2. Predict why `LabValue` remains callable after the first `FreeLibrary`.
3. Identify the last point where using the function pointer would be valid.

```bat
cl /nologo /W4 /EHsc /std:c++17 /MT /LD labdll.cpp /link /OUT:Lab.dll /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
cl /nologo /W4 /EHsc /std:c++17 /MT load.cpp /Fe:load.exe /link /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 1
dumpbin /exports Lab.dll
dumpbin /imports Lab.dll
load.exe
echo Exit=%ERRORLEVEL%
```

### Hints

Equal HMODULE values do not mean the second load acquired no reference. `GetProcAddress` itself does not acquire a reference. A missing export is checked before any call.

### Solution and Expected Results

Two successful normal loads of the same module acquire two references. Releasing `first` leaves `second` alive, so the exact ABI function returns 73. The absent export returns null and error 127. Expected output ends `checks=1`, exit zero. The export list includes `LabValue`; exact compiler-runtime imports vary with toolchain. The function pointer is cleared before final release and never called afterward. This is a lifetime demonstration, not a proof of module trust.

### Verification, Troubleshooting, and Cleanup

- [ ] Record value 73, missing export error 127, and zero exit.
- [ ] Explain the ownership of both load results and the non-owning function pointer.
- [ ] Record Windows/compiler versions and actual import list.

Error 193 commonly indicates a machine mismatch; rebuild both in the x64 prompt. Error 126 may mean the target or a dependency is missing. Do not broaden search policy to fix deployment. Policy-blocked unsigned lab DLLs remain blocked; record the unmet prerequisite rather than disabling controls.

```bat
del load.exe load.obj Lab.dll Lab.lib Lab.exp labdll.obj
```

No registration, services or process-global search setting is changed. Remove the source directory when finished.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Persistence]]
- [[Process Injection]]
- [[Loader and DLLs Security]]

## References

- [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
- [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
- [DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- [GetModuleHandleExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)
