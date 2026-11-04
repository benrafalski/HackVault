---
title: "x64 Assembly and Windows x64 ABI Security"
aliases: []
tags: [windows, x0, security]
domain: windows
phase: "X0"
type: security
status: draft
pair: "[[x64 Assembly and Windows ABI]]"
updated: 2026-11-03
---
# x64 Assembly and Windows x64 ABI Security

> [!abstract] TL;DR
> Incorrect signatures, stack alignment, register preservation, or unwind metadata can corrupt state and make native interop exploitable or unreliable.

> [!info] Agent scope
> Security of: Registers; instruction semantics; flags; calling convention; stack alignment; shadow space; unwind metadata; disassembly exercises. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Native boundaries: separately compiled modules, callbacks, assembly stubs, FFI declarations, variadic formatting, and shared binary structures. Matching symbol names do not prove matching types.
- This page studies defensive ABI correctness in self-authored programs. No invalid indirect call is executed; the negative case is rejected by the compiler.

## Learn

```text
Teach me defensive Windows x64 ABI and native interop correctness. Assume I can
read C++ and simple x64 instructions. Use Windows 11 x64 and MSVC v143. Explain
how wrong prototypes change positional GPR/XMM arguments, hidden returns,
stack ownership, alignment, register preservation, and exception unwinding.
Cover callback typedefs, LLP64/BOOL/wchar_t layouts, packing, varargs, C linkage,
CRT ownership and C++ exception boundaries. Show harmless compile-negative
examples, correct alternatives, build flags, and an independently runnable
cleanup/unwind regression. Explain what CFG, GS, ASan and CET do not validate.
Do not execute undefined indirect calls or demonstrate exploitation. Use public
Microsoft contracts; distinguish implementation observations from guarantees.
Keep WinDbg commands in the dedicated reference, omit page tables, do not edit
files or status, and finish with difficult scenarios and worked answers.
```

## Cheatsheet

### Root Causes and Contracts

| Defect | Why it fails | Correct boundary |
|---|---|---|
| Declaring `double` as `int` in position 2 | Caller fills EDX; callee reads XMM1. The linker may accept matching C symbol names. | One shared header and a typed callback assignment; no function-pointer casts to silence diagnostics. |
| Wrong return type | Scalar FP returns use XMM0, integer returns RAX; a nontrivial aggregate can add a hidden result pointer. | Declare return type, packing and calling convention identically in all modules. |
| Assuming four independent FP slots | Positions are shared with integer parameters, not allocated independently. | Annotate every position, including hidden parameters. |
| Treating shadow space as saved caller locals | Callee owns those 32 bytes during the call. | Keep live locals outside that region; recompute offsets after every stack change. |
| Forgetting nonvolatile state | Caller expects RBX/RBP/RSI/RDI/R12-R15 and XMM6-XMM15 low halves unchanged. | Save/restore every modified nonvolatile register and describe saves in unwind metadata. |
| Storing below RSP | Windows x64 has no red zone; asynchronous activity can invalidate that storage. | Allocate an explicit frame, aligned at call sites. |
| Missing/inaccurate unwind records | Normal returns can work while exceptions and stack walking fail. | Compiler-generated frames, or legal MASM FRAME annotations matching instructions; inspect PE unwind entries. |
| Variadic format mismatch | No runtime type descriptor accompanies `...`; `%s`, `%ls`, `%zu`, `%p` consume different contracts. | Prefer typed formatting; use `%zu` for `size_t`, `%p` with `void*`, and check format warnings. |
| Foreign exceptions crossing a C interface | `extern "C"` changes linkage, not exception or allocator compatibility. | Catch expected C++ exceptions inside a `noexcept` boundary, return a documented status, and initialize outputs. |

**Layout example (not a wire format):** with default MSVC packing, `struct Record { unsigned char tag; unsigned long count; void* data; };` has offsets 0, 4, 8 and size 16 on x64. `long` is 32 bits; Windows `BOOL` is a 32-bit integer, C++ `bool` is not a substitute; Windows `wchar_t` is 16 bits, not UTF-8. `#pragma pack(1)` changes offsets to 0, 1, 5 and size 13. Copying that packed structure across an interface expecting the default layout is wrong even when both builds are x64. Use `sizeof`, `alignof`, and `offsetof` assertions, fixed-width fields, explicit byte order and length validation for serialization; never serialize pointers or padding.

An ABI also includes ownership and lifetime. A borrowed pointer must not outlive its owner; a callback cannot retain a stack buffer unless the API explicitly guarantees its lifetime. Each allocation must be released by the matching allocator, preferably through a destroy function exported by the allocating module. A successful call is not a lifetime proof.

### Build and Mitigation Limits

- `/W4 /WX` makes many local mistakes build failures; separate C translation units with incompatible declarations can still link. `/analyze` adds static reasoning but is not a complete verifier.
- `/GS` detects some overwritten stack control data, not incorrect FP arguments. `/guard:cf` plus linker `/guard:cf` checks supported indirect-call targets, not a universal full C++ type/ownership contract.
- `/DYNAMICBASE /NXCOMPAT` are useful PE protections, not ABI repair. CET-compatible image marking and actual OS/hardware shadow-stack policy are different facts; neither justifies a wrong prototype.
- `/fsanitize=address` detects covered memory accesses, not every register-preservation, alignment, or unwind error. External assembly and uninstrumented libraries leave coverage gaps.
- `/EHsc` provides normal C++ exception semantics. Do not treat access violations as recoverable input validation or switch to broader exception modes to hide corruption. `noexcept` terminates if an exception escapes; the wrapper must actually catch and translate its documented errors.
- The baseline is the ordinary Microsoft x64 ABI. `__vectorcall`, ARM64EC, compiler-specific C++ class ABI details, and foreign runtimes require their own contracts.

## Detection and Defense

Review headers, build architecture, packing, CRT selection, callback lifetime, unwind metadata, then error behavior in that order. Capture compiler version, matching binary/PDB hashes, the exact benign input and exit status. Diagnose frames through [[WinDbg]] without copying commands here. Do not infer wrongdoing from a truncated stack alone: mismatched symbols, optimization and a damaged frame are different explanations.

## Labs

### Environment and Complete Files

Assume a disposable Windows 11 x64 VM and VS 2022 Build Tools 17.10+ (17.x), Desktop development with C++, v143 and Windows SDK 10.0.22621.0+. Run as standard user in **x64 Native Tools Command Prompt for VS 2022**. No downloads, network target, driver or service is required after toolchain setup. Make `%USERPROFILE%\X0-ABI-Safety`, change into it, and create these three files.

**contract.h**:

```cpp
#pragma once
using MixFunction = double (*)(int, double, int, double, int);
extern "C" double mix(int first, double second, int third,
					  double fourth, int fifth);
extern "C" int checked_mix(int reject, double* output) noexcept;
extern "C" int live_guards() noexcept;
```

**contract.cpp**:

```cpp
#include "contract.h"
#include <stdexcept>

static int active_guards = 0;
struct Guard {
	Guard() { ++active_guards; }
	~Guard() { --active_guards; }
};

extern "C" __declspec(noinline) double mix(
	int first, double second, int third, double fourth, int fifth) {
	return first + second + third + fourth + fifth;
}

static __declspec(noinline) double calculate(int reject) {
	Guard guard;
	if (reject != 0) {
		throw std::invalid_argument("synthetic rejection");
	}
	return mix(1, 2.5, 3, 4.5, 5);
}

extern "C" int checked_mix(int reject, double* output) noexcept {
	if (output == nullptr) return 2;
	*output = 0.0;
	try {
		*output = calculate(reject);
		return 0;
	} catch (const std::invalid_argument&) {
		return 1;
	} catch (...) {
		return 3;
	}
}

extern "C" int live_guards() noexcept { return active_guards; }
```

**check.cpp**:

```cpp
#include "contract.h"
#include <cstddef>
#include <cstdio>
#include <type_traits>

struct Record { unsigned char tag; unsigned long count; void* data; };
static_assert(sizeof(void*) == 8);
static_assert(sizeof(unsigned long) == 4);
static_assert(offsetof(Record, count) == 4);
static_assert(offsetof(Record, data) == 8);
static_assert(sizeof(Record) == 16);
static_assert(std::is_same_v<decltype(&mix), MixFunction>);

int main() {
#ifdef BAD_SIGNATURE
	using WrongFunction = double (*)(int, int, int, int, int);
	WrongFunction callback = &mix;
#else
	MixFunction callback = &mix;
#endif
	const double direct = callback(1, 2.5, 3, 4.5, 5);
	double good = -1.0;
	double rejected = -1.0;
	const int good_status = checked_mix(0, &good);
	const int bad_status = checked_mix(1, &rejected);
	const int null_status = checked_mix(0, nullptr);
	const int remaining = live_guards();
	std::printf("direct=%.1f good=%d/%.1f reject=%d/%.1f null=%d live=%d\n",
		direct, good_status, good, bad_status, rejected, null_status, remaining);
	return direct == 16.0 && good_status == 0 && good == 16.0 &&
		bad_status == 1 && rejected == 0.0 && null_status == 2 &&
		remaining == 0 ? 0 : 1;
}
```

`output` is a caller-owned writable double or null, not an arbitrary untrusted address. This is a synchronous, single-threaded teaching interface; the counter is not thread-safe. The C-linkage header deliberately uses C++ syntax and is not a C-consumable SDK.

### Objectives and Baseline

All commands below use the x64 developer **cmd** prompt:

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf contract.cpp check.cpp /Fecheck.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
check.exe
echo %ERRORLEVEL%
dumpbin /unwindinfo check.exe > unwind.txt
cl /nologo /std:c++20 /EHsc /W4 /WX /c /DBAD_SIGNATURE check.cpp /Fonegative.obj
echo %ERRORLEVEL%
```

Record the successful baseline, then the **nonzero** negative compilation result. Do not run any stale executable as evidence of the failed build. Explain which slots would differ if the compiler error were forcibly cast away. Inspect nonleaf unwind entries; the presence of records alone does not establish semantic correctness.

### Hints

Look at the second and fourth arguments, not just the equal total count. A destructor must run for the guard both on return and during C++ exception propagation. The out-parameter is cleared before attempting the computation.

### Solution and Fixed Retest

Expected baseline: `direct=16.0 good=0/16.0 reject=1/0.0 null=2 live=0`, exit 0. The macro build should reject assignment of `&mix` to `WrongFunction` (diagnostic number/text varies). The fix is the `MixFunction` assignment already in the non-macro branch, not `reinterpret_cast`. Rebuild without `/DBAD_SIGNATURE` and rerun the identical positive, rejected, and null cases. Verify `live=0` after both normal and exceptional cleanup. This demonstrates compiler-supported C++ unwinding, not arbitrary asynchronous unwind correctness.

### Verification, Troubleshooting, and Cleanup

Compile once more with `/O2` replacing `/Od`; expected semantic output is unchanged. If layout assertions fail, check x64 tools and remove accidental nondefault packing in this lab, not the assertions. If no unwind names appear, retain the matching PDB and consult the binary's addresses; do not assume public symbols contain your private functions. No exception should escape `checked_mix`.

Author validation: **unexecuted native builds and negative compilation**. The assertions and expected observations are specifications, not measured evidence. Close tools and delete only `%USERPROFILE%\X0-ABI-Safety`, or revert the VM snapshot. Preserve the completion items below until personally verified.

- [ ] Local x64 Assembly and Windows ABI exercise: Compile a small function with mixed integer/floating arguments and one stack argument using MSVC. Inspect its disassembly and unwind information; annotate each argument location, stack adjustment, and preserved register.
- [ ] Boundary check: Call a toy function through the correct declared signature and compare with compiler diagnostics for a mismatched declaration. Use a disposable process; do not patch system code.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[x64 Assembly and Windows ABI]]

## References

- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [MSVC exception handling model](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model)
- [Control Flow Guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- [Potential errors passing CRT objects across DLL boundaries](https://learn.microsoft.com/en-us/cpp/c-runtime-library/potential-errors-passing-crt-objects-across-dll-boundaries)
