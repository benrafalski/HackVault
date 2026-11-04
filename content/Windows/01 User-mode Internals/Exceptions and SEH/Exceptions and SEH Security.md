---
title: "Exceptions and SEH Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Exceptions and SEH]]"
updated: 2026-11-03
---
# Exceptions and SEH Security

> [!abstract] TL;DR
> Corrupted handler/control data, invalid unwind metadata, and broad exception suppression can hide memory corruption or redirect control in vulnerable binaries.

> [!info] Agent scope
> Security of: Exception dispatch; vectored handlers; SEH; x64 unwind metadata; first/second chance; language exception interaction. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Fail-open error paths, overbroad filters, incomplete cleanup, stale vectored callbacks, sensitive crash data, and invalid unwind/language assumptions.
- The regression program deliberately raises known software exceptions only. It neither corrupts memory nor performs protected actions.

## Learn

```text
Teach defensive Windows exception handling at native engineering depth.
Assume C, SEH filters, tokens, resource lifetime and x64 unwind metadata.
Explain why swallowing an error can convert failed validation into success,
why access violations are not business exceptions, and why broad catch/continue
does not restore invariants. Cover narrow filters, fail-closed return values,
finally cleanup, cleanup failures, fail-fast limits, VEH callback unload races,
and C++ /EHsc versus /EHa behavior. Compare x86 SafeSEH/SEHOP concepts with x64
table-based unwinding without exploitation or mitigation bypass procedures.
Provide a complete C regression program with benign application exception codes:
prove a synthetic fail-open result, fix it, retain valid success, verify cleanup
exactly once and ensure an unexpected code reaches an outer test harness.
Explain telemetry fields, first/second chance, dump privacy and release symbols.
Use primary documentation, expected traces and answered review questions. No
memory corruption, exploit payloads, privileged action, credential access,
evasion or file edits. Debugger commands belong only in the WinDbg reference.
```

## Cheatsheet

### Narrow Recovery, Explicit Invariants

| Pattern | Defect | Repair |
|---|---|---|
| Initialize result to success; handler only logs | Fault path returns a positive authorization/validation result | Default failure; commit success only after every required check. |
| `__except(EXCEPTION_EXECUTE_HANDLER)` at every boundary | Unexpected faults look like ordinary input errors | Handle only documented recoverable codes; propagate others to an isolation boundary. |
| VEH always resumes | Faulting state/instruction may remain invalid or noncontinuable | Observe and continue search unless recovery is explicitly proven by the component contract. |
| Cleanup only after risky call | Exception skips release | Use `__finally` for C-style SEH or appropriate language RAII with verified compiler semantics. |
| Log/allocate/lock heavily in exception callback | Reentrancy, recursion, deadlock, stack exhaustion | Minimal preallocated evidence; out-of-process reporting where appropriate. |
| Unload DLL before removing VEH | Callback address outlives code | Remove registration and coordinate in-flight callbacks before unload. |

`__finally` is an unwind construct, not a guarantee under process kill, fail-fast or every catastrophic failure. Do not retry a partially completed side-effecting operation without a transaction/idempotency design. A handler can report failure while state remains inconsistent; terminate or isolate the affected operation/process when invariants cannot be re-established.

For a narrow SEH filter, `code == EXPECTED ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH` preserves unexpected failures. A noncontinuable software exception can be handled by unwinding; it cannot safely be resumed. Do not use access-violation handlers as pointer-validity tests: even a successful probe is racy, and faults can occur after partial work.

### Compiler and Architecture Constraints

`/GS`, `/guard:cf`, ASLR and DEP options reduce particular corruption risks; they do not repair fail-open application logic. x86 SafeSEH depends on compatible image metadata and is not the x64 unwind scheme. SEHOP validates aspects of legacy handler-chain dispatch; x64 uses function-table unwind metadata. CFG, CET and unwind validation address different concerns. Do not present any one as proof of memory safety.

`/EHsc` does not promise C++ destructor unwinding for arbitrary asynchronous SEH faults; `/EHa` changes generated assumptions but does not permit continuing after corruption. Separate native SEH boundaries into functions without C++ destructible locals where required. `RtlAddFunctionTable`/dynamic-code unwind lifetimes matter for JIT runtimes; never fabricate metadata to suppress diagnostics.

## Detection and Defense

Capture exception code, module/build identity, instruction address, thread, chance, operation ID and termination outcome. Preserve matching symbols and crash artifacts with access controls; dumps can contain sensitive application data. First-chance frequency can be expected runtime behavior; recurring unhandled faults or missing expected error records need investigation. Event 1000/Application Error and WER records depend on reporting configuration and are not an exhaustive exception trace. Do not clear logs or disable reporting as a lab reset.

## Labs

### Environment and Complete Files

Windows 10/11, preinstalled MSVC/Windows SDK, x64 Native Tools prompt. One C file in a new scratch directory. Standard user, no dependencies beyond Windows APIs. A synthetic Boolean result is the only simulated business output; an unnamed event demonstrates real handle cleanup.

### File: fail-closed.c

```c
#include <windows.h>
#include <stdio.h>

#define EXPECTED_CODE ((DWORD)0xE0421001)
#define OTHER_CODE ((DWORD)0xE0421002)
static int closed_count;
static int close_failures;

static int narrow(DWORD code) {
	return code == EXPECTED_CODE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
static int check_request(int fixed_policy, DWORD fault) {
	int accepted = fixed_policy ? 0 : 1;
	HANDLE resource = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!resource) return -1;
	__try {
		__try {
			if (fault) RaiseException(fault, EXCEPTION_NONCONTINUABLE, 0, NULL);
			accepted = 1;
		} __finally {
			if (CloseHandle(resource)) ++closed_count;
			else ++close_failures;
		}
	} __except(narrow(GetExceptionCode())) {
		if (fixed_policy) accepted = 0;
	}
	return accepted;
}
int main(void) {
	int baseline = check_request(0, EXPECTED_CODE);
	int rejected = check_request(1, EXPECTED_CODE);
	int permitted = check_request(1, 0);
	int propagated = 0;
	__try {
		check_request(1, OTHER_CODE);
	} __except(GetExceptionCode() == OTHER_CODE ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		propagated = 1;
	}
	printf("baseline=%d fixed=%d valid=%d propagated=%d closed=%d close_failures=%d\n",
		baseline, rejected, permitted, propagated, closed_count, close_failures);
	return baseline == 1 && rejected == 0 && permitted == 1 && propagated == 1 &&
		closed_count == 4 && close_failures == 0 ? 0 : 1;
}
```

### Objectives and Baseline

```bat
cl /nologo /W4 /Od /Zi /GS fail-closed.c /link /debug /dynamicbase /nxcompat
fail-closed.exe
dumpbin /unwindinfo fail-closed.exe
```

Predict the returned value after the expected exception. The defective path starts at success and does not clear it when validation is interrupted. No privileged action follows it. Inspect the same filter under a second, unexpected application code.

### Hints and Fixed Retest

Default failure is necessary even when handlers log correctly. The fixed path commits success only after the operation returns normally. Expected output: `baseline=1 fixed=0 valid=1 propagated=1 closed=4 close_failures=0`, exit 0. The outer handler is a test harness catching one deliberate synthetic code, not a recommended broad production recovery boundary. Both failures and success execute cleanup exactly once; an unexpected exception is not swallowed by the inner filter.

### Verification, Troubleshooting, and Cleanup

Require all six reported fields; any allocation/close failure makes the test fail. Compile as C; C++ compilation can introduce C2712 constraints. Debugger first-chance stops are not failures if execution continues through the expected dispatch; consult [[WinDbg]] only for commands. Delete only scratch source/build artifacts. No WER/global settings need changing. Source reviewed, compilation and runtime unexecuted; parent must verify x64 native behavior and metadata. No corrupted-state recovery or mitigation effectiveness is certified.

- [ ] Local Exceptions and SEH exercise: Run the benign native fail-open/fail-closed regression program.
- [ ] Boundary check: Retain valid success, reject interrupted validation, propagate unexpected codes, and close four handles.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows Stack and SEH Overflows]]
- [[WinDbg]]
- [[Exceptions and SEH]]

## References

- [Structured exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling)
- [Termination handling](https://learn.microsoft.com/en-us/windows/win32/debug/termination-handling)
- [MSVC exception model](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model)
- [RaiseFailFastException](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raisefailfastexception)
