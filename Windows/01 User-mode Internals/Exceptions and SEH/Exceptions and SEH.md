---
title: "Exceptions and SEH"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Exceptions and SEH Security]]"
updated: 2026-11-03
---
# Exceptions and SEH

> [!abstract] TL;DR
> Record exception code, address, thread, first/second chance, and unwind context. Fix the cause rather than swallowing every exception.

> [!info] Agent scope
> Exception dispatch; vectored handlers; SEH; x64 unwind metadata; first/second chance; language exception interaction.

## Prerequisites

- Windows 10/11, preinstalled VS 2022 MSVC and Windows SDK, x64 Native Tools prompt. C, stack frames, ABI and error-code basics; standard user.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows exception dispatch, VEH, SEH and x64 unwinding at native depth.
Assume C/C++, x64 ABI and stack frames. Trace RaiseException and processor faults
through debugger first chance, vectored handlers, frame-handler search, unwind,
termination handlers, selected handler and unhandled/second-chance outcome.
Explain EXCEPTION_RECORD/CONTEXT lifetimes, continuability, filter return codes,
search versus unwind side effects, nested faults and vectored handler removal.
Contrast x86 linked SEH with x64 RUNTIME_FUNCTION/UNWIND_INFO and language
handlers; discuss leaf functions, prolog/epilog constraints and dynamic tables.
Explain /EHsc versus /EHa, C++ destructors, C2712, and why access-violation
suppression does not repair state. Provide a complete native C program using
only an application-defined exception to prove VEH/filter/finally/handler order.
Include build, expected results, an optional deliberately unhandled case and
metadata inspection; debugger commands belong in a separate WinDbg reference.
Use primary Microsoft sources and answered questions. No corruption payloads,
exploitation, evasion, confidential data, note edits or fabricated execution.
```

## Cheatsheet

### Dispatch Is a Search Followed by Unwind

For ordinary dispatch, an attached debugger gets first chance before application handling. VEH callbacks are process-wide and not tied to a stack frame; they run before frame-based handler selection/unwind. SEH filters are evaluated while searching outward. When a filter selects its handler, intervening frames unwind, termination handlers execute, and control enters the selected `__except` block. An unhandled exception can produce a debugger second-chance notification and process termination/reporting. A debugger that handles first chance can change the observed application path.

| Filter/VEH result | Value | Meaning |
|---|---|---|
| `EXCEPTION_CONTINUE_SEARCH` | 0 | This handler does not handle it; continue dispatch. |
| `EXCEPTION_EXECUTE_HANDLER` | 1 | Valid SEH filter choice: unwind to its `__except`; not a VEH return choice. |
| `EXCEPTION_CONTINUE_EXECUTION` | -1 | Resume only when the exception is continuable and state is valid; not a universal recovery mechanism. |

`RaiseException(code,flags,count,args)` supplies a software exception; reserve application-defined codes without colliding with system codes. Bit 28 is reserved. `EXCEPTION_NONCONTINUABLE` prohibits resumption but still permits handling via unwind. Attempts to resume a noncontinuable exception cause another exception. The lab uses `0xE0421001` as a private synthetic code, not a standardized Windows error.

`GetExceptionCode()` is valid in a filter or handler. `GetExceptionInformation()` is used in the filter expression and provides `EXCEPTION_POINTERS`; do not retain pointers to transient record/context storage beyond its valid lifetime. Capture only required scalar evidence. `__finally` runs during normal departure and supported unwind paths; `AbnormalTermination()` distinguishes unwinding from normal flow. It is not guaranteed after forced process termination or fail-fast.

### Architecture and Language Boundaries

On x64, exception directory entries describe `RUNTIME_FUNCTION` ranges and unwind information, normally in `.pdata` and `.xdata`. Unwind codes describe prolog effects and nonvolatile-register restoration; language-specific handlers supply SEH/C++ semantics. Leaf functions can be unwound without a table entry by simulating return; optimized layouts need not map one-to-one to source functions. JIT-generated code must provide valid lifetime-managed function tables through documented APIs such as `RtlAddFunctionTable`; this is not needed in ordinary compiler-generated code.

Do not transplant x86 stack-linked handler layouts or `/SAFESEH` assumptions to x64. x64 unwind metadata is essential for correctness but is not a memory-safety boundary. `/EHsc` provides normal C++ exception/destructor assumptions and does not promise C++ cleanup for every asynchronous Windows fault. `/EHa` changes compiler assumptions; it does not make corrupted state trustworthy. MSVC error C2712 warns against mixing `__try` with functions needing C++ object unwinding under incompatible settings; separate C-style SEH boundaries from RAII C++ functions.

`AddVectoredExceptionHandler(First,callback)` returns a registration token. `First` influences ordering; later registrations can affect precedence. Remove the registration with `RemoveVectoredExceptionHandler` before callback code unloads, and coordinate in-flight callbacks in multithreaded designs. A callback should avoid allocation, locks, reentrant logging and actions likely to fault. VEH is not a safe place for general application recovery.

## Gotchas

- Expected first-chance events are not automatically crashes. Report code, address, thread, module/version, chance and stack evidence separately.
- `SetUnhandledExceptionFilter` is not a reliable catch-all cleanup contract; debugger/runtime behavior can affect it. Fail-fast deliberately bypasses ordinary handlers.
- Never resume an access violation by merely advancing an instruction pointer or returning success.

## Labs

### Environment and Complete Files

One native C source in a new scratch directory; preinstalled MSVC/SDK only. Application-defined exception, no invalid memory access, admin rights or external data. The default run is fully handled. The optional unhandled mode intentionally terminates only this process and may cause Windows Error Reporting artifacts.

### File: dispatch.c

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define LAB_CODE ((DWORD)0xE0421001)
static LONG sequence[4];
static LONG count;
static BOOL abnormal;

static void record(LONG stage) {
	if (count < 4) sequence[count++] = stage;
}
static LONG CALLBACK observe(PEXCEPTION_POINTERS info) {
	if (info->ExceptionRecord->ExceptionCode == LAB_CODE) record(1);
	return EXCEPTION_CONTINUE_SEARCH;
}
static int select_handler(DWORD code) {
	if (code != LAB_CODE) return EXCEPTION_CONTINUE_SEARCH;
	record(2);
	return EXCEPTION_EXECUTE_HANDLER;
}
static void inner(void) {
	__try {
		RaiseException(LAB_CODE, EXCEPTION_NONCONTINUABLE, 0, NULL);
	} __finally {
		abnormal = AbnormalTermination();
		record(3);
	}
}
int main(int argc, char** argv) {
	PVOID registration = AddVectoredExceptionHandler(1, observe);
	if (!registration) return 1;
	if (argc == 2 && strcmp(argv[1], "unhandled") == 0) {
		puts("Deliberately unhandled application exception");
		fflush(stdout);
		RaiseException(LAB_CODE, EXCEPTION_NONCONTINUABLE, 0, NULL);
		return 2;
	}
	__try {
		inner();
	} __except(select_handler(GetExceptionCode())) {
		record(4);
	}
	if (!RemoveVectoredExceptionHandler(registration)) return 3;
	printf("order=%ld,%ld,%ld,%ld abnormal=%d\n",
		sequence[0], sequence[1], sequence[2], sequence[3], abnormal);
	return count == 4 && sequence[0] == 1 && sequence[1] == 2 &&
		sequence[2] == 3 && sequence[3] == 4 && abnormal ? 0 : 4;
}
```

### Objectives and Steps

Use an x64 Native Tools command prompt in the scratch directory:

```bat
cl /nologo /W4 /Od /Zi dispatch.c /link /debug
dispatch.exe
dumpbin /headers dispatch.exe
dumpbin /unwindinfo dispatch.exe
```

Predict the order before running. Find the exception directory in the PE headers and compiler-produced unwind entries; addresses vary. Optional, only in a disposable local lab: `dispatch.exe unhandled`. It has no selecting frame handler and is expected to terminate abnormally. Use [[WinDbg]] for debugger setup/operations; do not treat debugger-handled first chance as equivalent to an ordinary run.

### Hints and Solution

Filter evaluation happens **before** the intervening `__finally` executes. Expected default output is `order=1,2,3,4 abnormal=1` and exit 0. The optional unhandled mode has no successful exit; WER policy/debugger attachment determines visible reporting. The single-threaded callback writes only preallocated scalar state; it is not a production multithreaded logging implementation.

### Verification, Troubleshooting, and Cleanup

Require the exact default sequence and x64 unwind evidence; do not require stable addresses or first-chance UI. Compile as `.c` to avoid C++ destructor restrictions. Missing `dumpbin` means the tools environment is wrong. Delete only this lab's source/object/executable/PDB/ILK outputs; WER retention is OS-managed and must not be globally cleared. Source reviewed, not compiled/run; parent must validate default dispatch and metadata. Optional unhandled mode and x86 comparison remain unverified unless separately performed.

- [ ] Local Exceptions and SEH exercise: Observe benign VEH/filter/finally/handler ordering and x64 metadata.
- [ ] Boundary check: Explain handled versus unhandled outcomes and cleanup without corrupted-state recovery.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Stack and SEH Overflows]]
- [[WinDbg]]
- [[Exceptions and SEH Security]]

## References

- [Structured exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling)
- [Vectored exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [MSVC exception options](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model)
