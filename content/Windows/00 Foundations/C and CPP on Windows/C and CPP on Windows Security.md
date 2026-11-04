---
title: "C/C++ on Windows (MSVC) Security"
aliases: []
tags: [windows, x0, security]
domain: windows
phase: "X0"
type: security
status: draft
pair: "[[C and CPP on Windows]]"
updated: 2026-11-03
---
# C/C++ on Windows (MSVC) Security

> [!abstract] TL;DR
> Buffer misuse, use-after-free, unchecked arithmetic, and mismatched ownership can turn input processing into memory corruption.

> [!info] Agent scope
> Security of: MSVC build pipeline; types and pointers; resource lifetime; linking; runtime libraries; diagnostics; native memory safety. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Native parsers convert untrusted byte counts into allocations, copies, indexes and API sizes. File lengths, terminators, signed-to-unsigned conversions and resource ownership are separate invariants.
- Only a self-authored command-line program and synthetic bytes are used here. The intentionally defective build demonstrates a sanitizer finding, not exploitation; keep it in a disposable development VM.

## Learn

```text
Teach me defensive C/C++ memory safety on Windows x64 with MSVC v143. Assume
basic pointers and RAII. Derive bounds including terminators, overflow-safe
size arithmetic, LLP64 narrowing, lifetime/alias invalidation, allocator pairing,
exception-safe cleanup and synchronous versus asynchronous Win32 ownership.
Use a fully specified synthetic-label parser: establish a safe baseline, detect
one off-by-one using MSVC AddressSanitizer, fix the root bound and rerun exact
valid/boundary/malformed cases. Explain the evidence and limits of W4/analyze,
GS, CFG, DEP/ASLR and ASan; separate contractual rejection from a crash.
Use official API/compiler sources and supported settings. No exploit chain,
bypass, injection, credential access, host-protection changes or page tables.
Do not edit files or status. Do not duplicate WinDbg commands. End with worked
review questions about integer, encoding and ownership edge cases.
```

## Cheatsheet

### Root Causes and Defensive Invariants

| Failure | Unsafe reasoning | Required invariant / fix |
|---|---|---|
| Terminator overflow | `count <= capacity` before copy followed by `dest[count]=0` | For a terminated byte string: `capacity > 0 && count < capacity`. For raw bytes: `count <= capacity`, with no implicit terminator write. |
| Allocation multiplication | Allocate `count * element_size` after multiplication wraps | Before multiplication, `element_size == 0 || count <= SIZE_MAX / element_size`; separately enforce an application resource budget. |
| Header plus payload | Check `offset + length <= total` after addition | First require `offset <= total`, then `length <= total - offset`. |
| Narrowing Win32 count | Cast `size_t` to DWORD then compare | Reject values above `MAXDWORD` before casting, or chunk I/O with correctly tracked progress. |
| Signedness | Negative length becomes huge `size_t` | Validate sign and range before conversion; reject trailing numeric junk and overflow in parsing. |
| Use-after-free | Keep a pointer after owner destruction or vector growth | Make the owner outlive every borrowed view; reacquire data pointers after reallocating operations. |
| Double release | Copy an owning HANDLE wrapper | Delete copying or implement explicit ownership transfer; do not close borrowed/pseudo handles. |
| Async lifetime | Free an OVERLAPPED/buffer after initiating I/O | Retain it until completion or confirmed cancellation completion. A cancel request is not immediate quiescence. |
| Text boundary | Treat UTF-16 code units, UTF-8 bytes and characters as equal lengths | Name units, use explicit conversions and validate errors. A byte cap is not a glyph cap. |

Bounded APIs do not infer correct sizes. Passing `sizeof(pointer)` to a so-called safe copy still supplies the wrong contract. `memcpy_s` has constraint-handling semantics that must be understood; it does not repair ownership or integer overflow. `std::span` carries a length but can still be dangling; unchecked indexing is not automatically safe in C++20. RAII handles cleanup, not bounds or data races.

### Concrete Arithmetic Pattern

The following is a standalone function fragment; the complete lab embeds the same function and compile-time checks. Division precedes multiplication, then a separate policy cap prevents a valid but unreasonable allocation:

```cpp
constexpr bool fits_budget(std::size_t count, std::size_t width,
						   std::size_t budget) noexcept {
	if (width == 0) return count == 0;
	if (count > (std::numeric_limits<std::size_t>::max)() / width) return false;
	return count * width <= budget;
}
```

For `count=SIZE_MAX,width=2`, the function rejects before arithmetic wraps. For `count=65537,width=1,budget=65536`, it rejects a resource-limit violation even though multiplication is representable. Zero-width items are deliberately rejected unless count is zero; that is application policy, not a C++ language requirement.

### Tool and API Contracts

- MSVC AddressSanitizer supports x86/x64 Windows instrumentation starting in VS 2019 16.9; this lab assumes VS 2022 17.10+ v143 with its matching ASan component. Runtime DLL packaging changed across VS releases, so keep runtime and compiler matched and record `/Bv` output.
- Build with `/fsanitize=address /Zi`, not `/ZI`; do not combine with `/RTC` or incremental linking. `/Od` keeps the example easy to attribute; optimized instrumented testing is also needed for production work.
- ASan can diagnose covered out-of-bounds/use-after-free accesses. It is not proof against all bugs, integer-overflow detection, a data-race detector, or an ABI verifier. Code in an uninstrumented binary/assembly region can escape coverage.
- `/GS` protects selected stack frames, not this heap bound; CFG constrains indirect call targets, not array indexes. DEP and ASLR make useful independent protections but do not validate input. Leave defenses enabled.
- `ReadFile` reports actual transferred bytes; a pre-read size is not a substitute for checking each accumulation. `CreateFileW` access/share failures must be handled without consuming invalid output. See the complete reader in [[C and CPP on Windows]].
- Exceptions are not a bounds-checking strategy. C++ `bad_alloc` may be handled at a resource boundary; continuing after an access violation or heap-corruption diagnostic is not a valid recovery plan.

## Detection and Defense

Record the sanitizer class, access size, stack, allocation size and input, not just "it crashed." Keep the exact EXE/PDB together; a PDB from a rebuild may not match the crashing image. Use [[WinDbg]] for any deeper triage. In reviews, trace length units from parser to arithmetic to allocation to final write. Tests need one-below/exact/one-above capacity, malformed numbers, empty input and permitted behavior after the fix. Memory-safety evidence is local to the instrumented build and exercised paths.

## Labs

### Environment and Complete File

Windows 11 x64 disposable VM; VS 2022 Build Tools 17.10+ (17.x), Desktop development with C++, v143 x64, Windows SDK 10.0.22621.0+, C++ AddressSanitizer component. Standard user; 1 GiB workspace budget. No WDK, Python, downloaded target or privileged operation. In **x64 Native Tools Command Prompt for VS 2022**, make `%USERPROFILE%\X0-Memory-Safety` and change into it. Create **label.cpp**:

```cpp
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <system_error>

constexpr bool fits_budget(std::size_t count, std::size_t width,
						   std::size_t budget) noexcept {
	if (width == 0) return count == 0;
	if (count > (std::numeric_limits<std::size_t>::max)() / width) return false;
	return count * width <= budget;
}
static_assert(sizeof(void*) == 8);
static_assert(fits_budget(8, 8, 64));
static_assert(!fits_budget(9, 8, 64));
static_assert(!fits_budget((std::numeric_limits<std::size_t>::max)(), 2, 64));
static_assert(!fits_budget(65537, 1, 65536));

int main(int argc, char** argv) {
	if (argc != 2) return 64;
	const std::string_view text(argv[1]);
	std::size_t count = 0;
	const auto parsed = std::from_chars(text.data(), text.data() + text.size(), count);
	if (text.empty() || parsed.ec != std::errc{} ||
		parsed.ptr != text.data() + text.size()) {
		std::fputs("reject: invalid count\n", stderr);
		return 64;
	}
	constexpr char source[] = "LABDATA!";
	constexpr std::size_t capacity = 8;
	if (count > sizeof(source) - 1) return 3;
#ifdef DEMONSTRATE_BUG
	if (count > capacity) return 3;
#else
	if (count >= capacity) return 3;
#endif
	try {
		auto output = std::make_unique<char[]>(capacity);
		std::memcpy(output.get(), source, count);
		output[count] = '\0';
		std::printf("count=%zu text=%s\n", count, output.get());
		return 0;
	} catch (const std::bad_alloc&) {
		return 4;
	}
}
```

All data is supplied above. The only input parameter is a decimal byte count; it selects a prefix of `LABDATA!`. There is no arbitrary external payload.

### Objectives and Baseline

Build two distinct binaries in the developer **cmd** prompt:

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /fsanitize=address /DDEMONSTRATE_BUG label.cpp /Felabel-bad.exe /Fdbad.pdb /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /fsanitize=address label.cpp /Felabel-fixed.exe /Fdfixed.pdb /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
label-bad.exe 7
label-bad.exe 8
```

Before running `8`, identify the allocation size, number of copied bytes and terminator index. The `7` case should succeed. Run the `8` case once and retain the ASan report: expected **heap-buffer-overflow**, a one-byte write immediately beyond an eight-byte allocation. Diagnostic wording, addresses and exit value are version-dependent; expect a nonzero failure, not a particular status number. Stop the defective process after the report; do not attempt to continue it or disable ASan.

### Hints

The copy of eight bytes itself fits. The following terminator write does not. A resource budget or stack cookie does not change that ninth write. A test that checks only `9` would miss the exact boundary defect because the source-length guard already rejects it.

### Solution and Fixed Retest

The fixed branch changes `>` to `>=`: reserve one byte for the terminator. For a raw binary copy, a different valid design would omit the terminator and retain the length, but mixing those interfaces is the root error here. Run this complete PowerShell 5.1+ acceptance matrix from the developer environment (enter `powershell -NoProfile` to inherit its PATH):

```powershell
Set-Location "$env:USERPROFILE\X0-Memory-Safety"
$cases = @(
	@{Arg='0'; Code=0; Text='count=0 text='},
	@{Arg='7'; Code=0; Text='count=7 text=LABDATA'},
	@{Arg='8'; Code=3; Text=''},
	@{Arg='9'; Code=3; Text=''},
	@{Arg='-1'; Code=64; Text=''},
	@{Arg='7x'; Code=64; Text=''},
	@{Arg='18446744073709551616'; Code=64; Text=''}
)
foreach ($case in $cases) {
	$output = & .\label-fixed.exe $case.Arg
	$code = $LASTEXITCODE
	if ($code -ne $case.Code) { throw "Wrong exit: $($case.Arg) => $code" }
	if ($case.Code -eq 0 -and "$output" -ne $case.Text) { throw "Wrong output: $output" }
	"PASS $($case.Arg) exit=$code"
}
```

The fixed `8` case rejects with 3 and no sanitizer finding; `0` and `7` still work. The out-of-range decimal is one greater than `UINT64_MAX`, so `from_chars` must reject it on this x64 build. No parsing uses unchecked `atoi`. The compile-time arithmetic checks verify the pre-multiplication guard. Also run `label-fixed.exe` with no arguments: expected 64.

### Verification, Troubleshooting, and Cleanup

Author validation: **unexecuted MSVC, ASan and acceptance matrix**. Required evidence is the original baseline, the single defect report, and all fixed retests without sanitizer findings. Static checks do not replace these observations. If ASan runtime DLLs are unavailable, repair the official C++ ASan installation and inherit the x64 developer PATH. Do not fetch runtime DLLs from third-party sites. If the negative test exits normally, verify the macro, executed filename and actual `/fsanitize=address` build before drawing conclusions.

Rebuild the fixed program with `/O2` instead of `/Od` and rerun before claiming optimized coverage. For the original file-reader checklist, [[C and CPP on Windows]] contains its complete independent source/fixtures; this page's label lab has no dependency on that exercise. Close processes, remove only `%USERPROFILE%\X0-Memory-Safety`, or restore the VM snapshot. Never mark the original study items complete from authoring alone.

- [ ] Local C and CPP on Windows exercise: Build a small Unicode file reader with MSVC, explicit length checks, and deterministic cleanup. Test an empty file, missing file, and oversized input; inspect the PE and symbols.
- [ ] Boundary check: Run malformed and boundary-length inputs through the toy reader with supported AddressSanitizer settings. Expected result: clean rejection or a diagnostic that identifies the defect.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[C and CPP on Windows]]

## References

- [MSVC AddressSanitizer overview](https://learn.microsoft.com/en-us/cpp/sanitizers/asan)
- [ASan known issues and limitations](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-known-issues)
- [Heap-buffer-overflow diagnostic](https://learn.microsoft.com/en-us/cpp/sanitizers/error-heap-buffer-overflow)
- [MSVC code analysis](https://learn.microsoft.com/en-us/cpp/code-quality/code-analysis-for-c-cpp-overview)
- [GS buffer security checks](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
- [Cancellation and pending I/O](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations)
