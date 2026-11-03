---
title: "C/C++ on Windows (MSVC)"
aliases: []
tags: [windows, x0]
domain: windows
phase: "X0"
type: tech
status: draft
pair: "[[C and CPP on Windows Security]]"
updated: 2026-11-03
---
# C/C++ on Windows (MSVC)

> [!abstract] TL;DR
> Use the Developer Command Prompt; enable high warnings and relevant analysis. Match allocator/deallocator families and check API return values before consuming outputs.

> [!info] Agent scope
> MSVC build pipeline; types and pointers; resource lifetime; linking; runtime libraries; diagnostics; native memory safety.

## Prerequisites

- C expressions, arrays and functions; ordinary filesystem use. [[Windows Lab Setup]] supplies the isolation model.
- Windows 11 x64 VM; Visual Studio 2022 Build Tools 17.10+ in the 17.x family, MSVC v143 and Windows SDK 10.0.22621.0+. Install Desktop development with C++ including x64 tools and AddressSanitizer. Record exact patches; these are assumed baselines, not executed version claims.

## Learn

```text
Teach me C and C++ on Windows using MSVC v143 at expert systems-engineering
depth. Assume basic C syntax. Explain preprocessing, translation units, COFF
objects, libraries, PE linking/loading, PDBs, CRT deployment and x64 LLP64.
Compare C explicit cleanup with C++ RAII; distinguish storage, lifetime,
ownership, aliasing, bounds, encoding, Win32 errors and C++ exceptions.
Work through a complete Unicode Win32 file reader with a strict size budget,
short-read/error handling, deterministic handle release and boundary tests.
Show exact x64 build/debug/optimized/sanitizer flags and common compile/link/
load failures. Explain MD versus MT and why extern C does not solve ownership
or ABI mismatches. Use supported Microsoft API contracts and benign synthetic
files. No debugger command duplication, exploit chains, page-table content,
confidential examples, or file/status edits. End with difficult worked questions.
```

## Cheatsheet

### Build Pipeline and Binary Contracts

| Stage | What it produces | Diagnostic / decision |
|---|---|---|
| Preprocess | Expanded translation unit; headers declare shared interfaces | `/P` for inspection. Macros/packing can silently change declarations. Do not mix generated output into ordinary sources. |
| Compile | COFF `.obj`, machine code and relocations | `/c`, `/std:c++20` or `/TC /std:c17`, `/W4 /WX`, `/Zi`. Match the target architecture across every object/library. |
| Static library | Archive of object files, normally `.lib` | `lib` packages objects. The linker generally extracts needed members; static libraries do not carry a runtime loader boundary. |
| Link | PE `.exe`/`.dll`, PDB with `/DEBUG`, optional import `.lib` | `link` resolves symbols, imports and relocations. An import library describes a DLL interface; it does not embed the DLL implementation. |
| Load | Mapped image with imported dependencies resolved | A successful build does not prove deployment dependencies exist. `dumpbin /dependents` lists direct imports, not all dynamically loaded plugins. |

`cl` is a driver that normally invokes the linker; options after `/link` are linker options. Use an x64 developer prompt so `PATH`, `INCLUDE`, and `LIB` are coherent. Do not copy arbitrary SDK DLLs into system directories to fix a build.

| Choice | Contract |
|---|---|
| `/MD` / `/MDd` | Dynamic release/debug CRT. Deploy the supported x64 VC Redistributable for release binaries; debug CRT is a developer dependency, not a redistributable product runtime. |
| `/MT` / `/MTd` | Static release/debug CRT. Larger binaries and separate runtime state in separately linked modules; do not pass ownership across mismatched runtimes. |
| `/Zi /Od /DEBUG` | Good initial source-level observation. `/DEBUG` can affect linker optimization defaults; choose `/INCREMENTAL:NO` for these reproducible teaching builds. |
| `/O2 /Zi /DEBUG` | Optimized code with symbols; variables may disappear and source order is not instruction order. |
| `/EHsc` | Standard synchronous C++ exception unwinding; not a promise to recover from memory faults. |
| `/GS /guard:cf`, linker `/guard:cf /DYNAMICBASE /NXCOMPAT` | Defense in depth. Keep enabled; they do not prove memory safety. |
| `/analyze` | Additional static diagnostics. Review warnings, not just return code. |
| `/fsanitize=address /Zi /INCREMENTAL:NO` | Instrumented memory-access checking; omit `/RTC` and `/ZI` (Edit and Continue). Install the matching ASan component/runtime. |

MSVC v14x binary compatibility has documented limits: the final linker should be at least as new as the newest input toolset; `/GL`/LTCG objects have tighter version requirements. Use matching build configurations rather than assuming any `.lib` is interchangeable. `extern "C"` controls language linkage; it does not make STL classes or exceptions into a stable C ABI.

### Types, Encoding, and Lifetime

| Type/resource | x64 Windows rule |
|---|---|
| `int`, `long`, `DWORD` | 32 bits; `DWORD` is unsigned. A pointer-to-`long` conversion truncates on x64. |
| pointer, `size_t`, `uintptr_t`, `SIZE_T` | 64 bits. Use `%zu` for `size_t`; use `%p` with `void*` for addresses. |
| `wchar_t`, `WCHAR` | 16-bit UTF-16 code units; one code unit is not necessarily one Unicode character. |
| `char` bytes | Not inherently UTF-8. `/utf-8` chooses source/execution charset for narrow literals; it does not change all Windows APIs. |
| `CreateFileW` | Returns `INVALID_HANDLE_VALUE` on failure, not null. `CloseHandle` releases a valid owned handle. |
| `CreateEventW` / `OpenProcess` | Return null on failure. Resource wrappers must match each API's sentinel and ownership rules. |
| `malloc` / `new[]` / `HeapAlloc` | Pair with `free` / `delete[]` / `HeapFree` on the same heap respectively. `LocalAlloc` pairs with `LocalFree`. |
| `GetCurrentProcess()` | Pseudo-handle; not an owned handle returned by `OpenProcess`. Do not generalize cleanup rules from numeric appearance. |

C++ `std::vector` owns contiguous elements; reallocation invalidates pointers into them. `std::span` is a borrowed view and cannot extend storage lifetime. Constness restricts access through a particular expression, not all aliases. C++ signed arithmetic overflow is undefined; unsigned arithmetic wraps, which is often still a size-validation bug. Before `count * stride`, require `stride != 0` and `count <= SIZE_MAX / stride` (or explicitly handle zero stride).

Use explicit `W` APIs and `wmain` for Windows paths. `UNICODE` selects generic Win32 aliases, `_UNICODE` selects CRT generic-text aliases, and neither converts an existing byte buffer. Error domains differ: `GetLastError` for a failed documented Win32 call, `errno` for CRT functions, `HRESULT` via `FAILED`/`SUCCEEDED` for COM-style results. Read last error immediately, only when the API says it is meaningful.

### Synchronous File I/O Contract

`CreateFileW` combines desired access, sharing, disposition and flags. Share flags specify which *other* opens may coexist; they do not grant rights. This lab uses `GENERIC_READ`, `FILE_SHARE_READ`, `OPEN_EXISTING`, ordinary synchronous disk I/O, and no inheritable security attributes. Writers/deleters can cause a sharing failure rather than a partial security bypass.

`ReadFile` accepts a `DWORD` byte count and a writable buffer of at least that size. TRUE plus zero bytes marks EOF for the synchronous disk-file case used here. Always use the actual transferred count; short reads need not satisfy the requested count. Overlapped I/O has a different lifetime/completion contract and is deliberately out of scope. File size obtained before reading is not a robust sole bound: enforce the cap while consuming data. Handles, mappings and data can outlive path-name changes; do not confuse a path with stable object identity.

## Gotchas

- `sizeof(pointer)` is not allocation size. `strlen` cannot validate an untrusted, unterminated buffer.
- LNK2019 usually means a missing definition/library or signature mismatch; LNK1112 means architecture mismatch; LNK2038 often exposes CRT/configuration mismatch. Fix the contract rather than ignoring default libraries.
- A safe destructor should not throw. `CloseHandle` cleanup failures can be logged separately; destructors must not overwrite the error you intend to report.

## Labs

### Environment and Complete Files

Use a standard user in the baseline VM; no elevation, WDK or network target. Budget 1 GiB workspace; the inputs below are under 20 KiB total. In **x64 Native Tools Command Prompt for VS 2022**:

```bat
mkdir "%USERPROFILE%\X0-CPP"
cd /d "%USERPROFILE%\X0-CPP"
where cl
cl /Bv
```

Create **reader.cpp** with this complete program. It accepts only local regular synthetic files for this exercise. Output is a byte count and additive checksum, not a decoding or cryptographic hash operation.

```cpp
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <new>
#include <vector>

class FileHandle {
	HANDLE value_;
public:
	explicit FileHandle(HANDLE value) noexcept : value_(value) {}
	~FileHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
	FileHandle(const FileHandle&) = delete;
	FileHandle& operator=(const FileHandle&) = delete;
	HANDLE get() const noexcept { return value_; }
};

int wmain(int argc, wchar_t** argv) {
	static_assert(sizeof(void*) == 8);
	static_assert(sizeof(long) == 4);
	if (argc != 2) {
		std::fputs("usage: reader PATH\n", stderr);
		return 64;
	}
	constexpr std::size_t limit = 4096;
	FileHandle file(CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (file.get() == INVALID_HANDLE_VALUE) {
		const DWORD error = GetLastError();
		std::fprintf(stderr, "open error=%lu\n", error);
		return 2;
	}
	try {
		std::vector<unsigned char> bytes(limit + 1);
		std::size_t used = 0;
		while (used < bytes.size()) {
			DWORD received = 0;
			const DWORD remaining = static_cast<DWORD>(bytes.size() - used);
			if (!ReadFile(file.get(), bytes.data() + used, remaining,
						  &received, nullptr)) {
				const DWORD error = GetLastError();
				std::fprintf(stderr, "read error=%lu\n", error);
				return 2;
			}
			if (received == 0) break;
			used += received;
		}
		if (used > limit) {
			std::fputs("reject: more than 4096 bytes\n", stderr);
			return 3;
		}
		std::uint64_t checksum = 0;
		for (std::size_t index = 0; index < used; ++index) checksum += bytes[index];
		std::printf("bytes=%zu checksum=%llu\n", used,
			static_cast<unsigned long long>(checksum));
		return 0;
	} catch (const std::bad_alloc&) {
		std::fputs("allocation failed\n", stderr);
		return 4;
	}
}
```

The cap makes the `size_t` to `DWORD` conversion provably safe. The extra byte detects oversize without allocating proportional to the input. Reading a device/pipe could block and is not authorized by this exercise; the program is not a general untrusted-path sandbox.

Create **types.c** to contrast C compilation and explicit cleanup (this creates only an unnamed event):

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(void) {
	_Static_assert(sizeof(void*) == 8, "requires x64");
	_Static_assert(sizeof(long) == 4, "Windows LLP64");
	HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (event == NULL) return 2;
	int result = 0;
	if (!SetEvent(event)) result = 3;
	if (result == 0 && WaitForSingleObject(event, 0) != WAIT_OBJECT_0) result = 4;
	if (!CloseHandle(event) && result == 0) result = 5;
	printf("pointer=%zu long=%zu result=%d\n", sizeof(void*), sizeof(long), result);
	return result;
}
```

### Objectives and Commands

Build in the developer **cmd** prompt:

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /utf-8 /Od /Zi /MD /GS /guard:cf reader.cpp /Fereader.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
cl /nologo /TC /std:c17 /W4 /WX /Od /Zi /MD types.c /Fetypes.exe /link /DEBUG /INCREMENTAL:NO
types.exe
dumpbin /headers reader.exe
dumpbin /dependents reader.exe
```

In Windows PowerShell 5.1+ or PowerShell 7, create deterministic seeds and run the acceptance matrix. This is the entire harness; no external fixture file is needed:

```powershell
Set-Location "$env:USERPROFILE\X0-CPP"
[IO.File]::WriteAllBytes("$PWD\empty.bin", [byte[]]@())
[IO.File]::WriteAllBytes("$PWD\marker.bin", [byte[]](65,66,67))
[IO.File]::WriteAllBytes("$PWD\boundary.bin", [byte[]](1..4096 | ForEach-Object { 65 }))
[IO.File]::WriteAllBytes("$PWD\oversize.bin", [byte[]](1..4097 | ForEach-Object { 65 }))
$cases = @(
	@{Name='empty.bin'; Code=0; Text='bytes=0 checksum=0'},
	@{Name='marker.bin'; Code=0; Text='bytes=3 checksum=198'},
	@{Name='boundary.bin'; Code=0; Text='bytes=4096 checksum=266240'},
	@{Name='oversize.bin'; Code=3; Text=''},
	@{Name='missing.bin'; Code=2; Text=''}
)
if (Test-Path .\missing.bin) { throw 'Use an empty lab directory; missing.bin must not exist' }
foreach ($case in $cases) {
	$output = & .\reader.exe $case.Name
	$code = $LASTEXITCODE
	if ($code -ne $case.Code) { throw "Wrong exit for $($case.Name): $code" }
	if ($case.Text -and "$output" -ne $case.Text) { throw "Wrong output: $output" }
	"PASS $($case.Name) exit=$code"
}
```

Explain RAII on every early return, why EOF and an API failure differ, and why the program reads 4097 bytes rather than trusting a prior size query. Inspect x64 PE machine type and direct CRT imports. An SDK can forward APIs through API-set contracts, so imported DLL names are not a complete runtime call trace.

### Hints

The second read after exactly 4096 bytes is allowed and necessary: it distinguishes EOF from an oversized file. The Win32 buffer length is a count in bytes; a path length is in UTF-16 code units. The C program has one explicit release; the C++ wrapper covers every return after construction.

### Solution and Expected Observations

The five cases produce the exit/status pairs in the harness; oversize reports rejection and missing reports an open error (normally `ERROR_FILE_NOT_FOUND`, 2). `types.exe` prints `pointer=8 long=4 result=0`. The valid maximum input sums to 4096 * 65 = 266240. The reader does not interpret NUL as EOF and does not append a terminator. All owned handles are closed; closing a handle does not necessarily immediately destroy an object that has other references.

For a sanitizer retest, rebuild the reader in the developer prompt with `/fsanitize=address /Zi /Od /MD`, retain `/EHsc /std:c++20 /W4`, and retain linker `/INCREMENTAL:NO`; do not add `/RTC` or `/ZI`. Rerun the same PowerShell matrix. Expected: identical results and no ASan report. Keep the matching ASan runtime on PATH by launching PowerShell from the developer environment when needed.

### Verification, Troubleshooting, and Cleanup

Author validation: **native builds, seeds and tests unexecuted**. Check exact exit codes and output, not merely whether a console opened. Error 32 suggests a sharing conflict; close your own writer and retry. Error 5 may be ACL policy or a non-file path; do not elevate reflexively. Missing CRT/ASan DLLs require the matching official runtime/tool component, not a downloaded loose DLL. A checksum mismatch can be a text editor adding a BOM/newline; regenerate the byte fixtures.

Close inspection tools and delete only `%USERPROFILE%\X0-CPP`, or restore the VM snapshot. Preserve the following original study checkboxes.

- [ ] Local C and CPP on Windows exercise: Build a small Unicode file reader with MSVC, explicit length checks, and deterministic cleanup. Test an empty file, missing file, and oversized input; inspect the PE and symbols.
- [ ] Boundary check: Run malformed and boundary-length inputs through the toy reader with supported AddressSanitizer settings. Expected result: clean rejection or a diagnostic that identifies the defect.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[C and CPP on Windows Security]]

## References

- [MSVC compiler options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options)
- [Runtime library options](https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library)
- [MSVC binary compatibility](https://learn.microsoft.com/en-us/cpp/porting/binary-compat-2015-2017)
- [CreateFileW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [ReadFile contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)
- [MSVC AddressSanitizer](https://learn.microsoft.com/en-us/cpp/sanitizers/asan)
- [Windows data types](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types)
