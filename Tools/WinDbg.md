---
title: "WinDbg"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# WinDbg

> [!abstract] TL;DR
> Confirm target and symbols, select the exception context, inspect stack/registers/memory, and test the causal hypothesis. All vault WinDbg commands belong on this page.

> [!info] Agent scope
> Canonical destination for WinDbg setup and commands. User already maintains a separate windbg.md; ask for its location before any future migration. Do not copy or invent that existing content during scaffolding.

## Prerequisites

- Windows 11 x64 disposable VM, current Microsoft WinDbg, Visual Studio 2022 Build Tools with Desktop development with C++ (MSVC v143 and a Windows SDK), and an x64 Native Tools Command Prompt. No driver, kernel connection, administrator token, or Python package is needed for the supplied lab.
- Record WinDbg build, OS build, compiler version printed by `cl`, architecture, executable SHA-256, and PDB provenance. Modern WinDbg and classic WinDbg share the engine but UI, TTD, and scripting availability differ. ARM64 and WOW64 targets require architecture-aware interpretation; this exercise is native x64 only.
- Use a writable local symbol cache. Public symbol downloads need permitted network access; self-authored PDBs remain local. The supplied lab works with its own symbols without downloading system symbols.
- This is a fresh reference. The user's separate windbg.md has not been searched for or imported. Any future migration needs its explicit location and permission.

## Learn

```text
Teach me WinDbg at expert debugging depth. Assume C/C++, PE, x64 registers,
calling conventions, and Windows process/thread basics. Establish exact WinDbg,
OS, target architecture, compiler, binary, PDB, and dump versions before analysis.
Explain debugger -> target -> thread -> frame -> register/exception context,
first versus second chance exceptions, live attach versus launch versus dump,
and the limits of small, full user-mode, and kernel dumps. Teach symbol GUID/age
matching, local PDBs versus public servers, caches, deferred loads, optimized
locals, unwind metadata, ASLR, and module-relative addresses. Give canonical
commands with their prerequisites for symbols, exceptions, stacks, registers,
types, memory, threads, breakpoints, logs, and dumps. Explain deferred versus
address breakpoints, stepping, and why automated analysis is only a hypothesis.
Build a complete self-authored x64 null-input crash with MSVC, trace the fault
back to an unchecked parameter, capture and reopen a dump, reject a mismatched
PDB, and compile a source-level guard that preserves valid behavior. Include
exact expected values and manual checks without fabricating observed addresses.
Explain kernel process context and extension limits conceptually; do not require
kernel configuration, verifier, or driver changes. Describe TTD and data-model
inspection as optional version-sensitive tools, including privacy costs.
Use Microsoft primary references. No confidential data, unrelated processes,
malware, protection bypass, page-table material, or import of existing personal
notes. Teach in this conversation; do not edit files or study status.
```

## Cheatsheet

### Establish the Evidence Context

Write down `(target type, architecture, process, thread, frame, time)` before interpreting a value. A stack is a reconstruction from saved state and unwind information, not an execution trace. A current register value may no longer be the original function argument after the prologue. A minidump may contain the stack but not the heap object a pointer refers to; an unreadable address alone does not distinguish omission from invalid memory.

| Target | Available operations | Main limit |
|---|---|---|
| Launched/attached user process | Break, step, inspect, capture dump | Debugging changes timing and exception delivery; attach observes a later point than launch. |
| User dump | Inspect captured state, symbols, and saved exception | No execution or new memory reads from the original process. |
| Kernel dump/live kernel session | Kernel extensions, process/thread context | Commands require appropriate dump contents/context; user PDBs do not symbolize the kernel. Not configured by this lab. |
| TTD recording | Replay recorded user-mode execution, query supported events | Build support, disk overhead, performance distortion, and sensitive captured memory. Not a complete system history. |

### Symbols and Modules

| Goal | Command | Check |
|---|---|---|
| Configure public symbols | `.symfix C:\Lab\SymbolCache` | Sets Microsoft symbol server plus local cache |
| Add private symbols | `.sympath+ C:\Lab\Symbols` | Use matching PDBs, not a nearby build |
| Reload symbols | `.reload /f` | May perform network requests |
| Inspect modules | `lm`; `lmvm toy` | Module identity, timestamps, symbol status |
| Automated crash triage | `!analyze -v` | Treat suggested cause as a hypothesis |
| Select saved exception | `.ecxr` | User-mode exception context must exist in the dump |
| Inspect registers/stack | `r`; `kv` | Interpret the selected thread/context |
| Disassemble symbol | `uf toy!main` | Substitute an actual module and function |
| Read memory | `db <address>`; `dq <address>` | Bytes versus 64-bit values; memory must be captured |
| Inspect a type | `dt toy!TypeName <address>` | Requires usable type symbols |
| List/select threads | `~`; `~0s` | User-mode thread index, not necessarily OS thread ID |
| Set/list/remove breakpoint | `bu toy!Function`; `bl`; `bc <id>` | Live target; deferred symbol breakpoint |
| Continue/step | `g`; `p`; `t` | Live target; over versus into calls |
| Kernel process/thread view | `!process 0 0`; `!thread` | Kernel target/dump only; preserve context |

PDB matching uses the executable's CodeView identity (GUID and age), not its filename, source path, or PE timestamp alone. Public PDBs can lack private locals/types. Copying an old PDB beside a new executable does not repair it. Never force-load mismatched symbols as evidence.

Additional canonical reference commands (angle-bracket operands are placeholders, not literal input):

| Question | Command | Interpretation |
|---|---|---|
| What symbol path/options are active? | `.sympath`; `.symopt` | Inspect before changing; network shares may leak private symbol queries. |
| Why did loading fail? | `!sym noisy`; `.reload /f toy.exe`; `!sym quiet` | Record mismatch/not-found versus successful private-symbol load. |
| What is the exception record? | `.exr -1`; `.ecxr` | Exception code/address and then saved register context; unavailable if dump lacks an exception stream. |
| What instruction faulted? | `u @rip L8`; `r rip,rcx,rax` | Determine read/write and effective address from actual instructions. |
| What frame/local is selected? | `.frame /r 0`; `dv /t` | Frame number must exist; optimized values can be unavailable or stale. |
| What symbols/types exist? | `x toy!*Score*`; `dt toy!Sample` | Type layout requires the matching private PDB. |
| What memory region is this? | `!address <address>`; `!heap -s` | User-mode region summary versus heap overview; heap extensions depend on heap implementation and capture. |
| What does the data model expose? | `dx @$curprocess`; `dx @$curthread` | Modern data-model surface; availability depends on target/provider/build. |
| Capture this stopped target | `.dump /ma C:\Lab\WinDbg\crash.dmp` | Full user-mode minidump: potentially sensitive memory; overwrite is not implicit. |
| Record commands/output | `.logopen C:\Lab\WinDbg\triage.txt`; `.logclose` | Contains paths and memory values; sanitize before sharing. |
| Break on access violation | `sxe av` | First-chance stop is an observation, not proof the application cannot handle it. |
| Address breakpoint | `bp toy!Score` | Requires a currently resolvable address; `bu` remains symbol-oriented/deferred. |
| Hardware data watch | `ba w4 <address>` | Aligned 4-byte write watch; few hardware slots, live target only. |
| Step out | `gu` | Runs until the current function returns; may hit another event first. |

Do not continue an unhandled failure merely to obtain a different stack. At first chance, identify whether a handler is expected; second chance means the exception remained unhandled. The supplied program has no such handler. `!analyze -v` may identify the access violation correctly without identifying the caller's missing guard; prove both independently.

Kernel references here are for existing authorized captures only. `!process` identifies candidate process contexts; `!thread` exposes a selected thread's kernel state. A kernel stack may not include pageable user memory. Do not copy user-mode assumptions about thread indices, available address spaces, or extension output into a kernel conclusion.

## Gotchas

- Cached symbols, embedded absolute PDB paths, and executable-directory lookup can mask a deliberately wrong symbol path. Verify actual symbol status with `lmvm`, not only the configured path.
- A source line can cover multiple instructions. Optimizations can fold functions, reorder loads, remove locals, and inline callers; instruction evidence takes priority.
- A full dump and a TTD recording can contain secrets even when the faulting function is harmless. Capture only this program, never an unrelated process.

## Labs

### Environment and Complete Files

Use a new `C:\Lab\WinDbg` directory; do not reuse an evidence directory. Put the source below in it. The program performs no network, registry, persistence, or external-process operations. Invalid input deliberately dereferences null only in the faulty build; the fixed build rejects it before dereference.

### File: toy.cpp

```cpp
#include <cstdio>
#include <cstring>

#ifndef GUARD_NULL
#define GUARD_NULL 0
#endif

struct Sample {
	int count;
	int price;
};

extern "C" __declspec(dllexport) __declspec(noinline)
int Score(const Sample* sample) {
	if (GUARD_NULL && sample == nullptr) {
		return -1;
	}
	return sample->count * sample->price;
}

int main(int argc, char** argv) {
	Sample sample{3, 7};
	const bool bad = argc == 2 && std::strcmp(argv[1], "--bad") == 0;
	const int result = Score(bad ? nullptr : &sample);
	std::printf("guard=%d result=%d\n", GUARD_NULL, result);
	return result < 0 ? 2 : 0;
}
```

In an **x64 Native Tools Command Prompt for VS 2022** (cmd syntax):

```bat
cd /d C:\Lab\WinDbg
mkdir original
mkdir fixed
cl /nologo /W4 /EHsc /Zi /Od /MD /Fdoriginal\compile.pdb /Fooriginal\toy.obj /Feoriginal\toy.exe toy.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:original\toy.pdb
cl /nologo /W4 /EHsc /Zi /Od /MD /DGUARD_NULL=1 /Fdfixed\compile.pdb /Fofixed\toy.obj /Fefixed\toy.exe toy.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:fixed\toy.pdb
original\toy.exe
fixed\toy.exe
fixed\toy.exe --bad
echo %ERRORLEVEL%
```

Expected valid results: `guard=0 result=21` and `guard=1 result=21`; fixed invalid result: `guard=1 result=-1`, exit code **2**. Do not run original `--bad` outside the debugger for this exercise. `/MD` requires the matching installed VC runtime; the development VM normally supplies it. Do not disable mitigations or remove compiler safety switches.

### Objectives and Steps

1. In WinDbg, Launch executable -> original executable above; set arguments `--bad` and working directory to the lab root. At the initial break, set local symbols and a deferred breakpoint:

```text
.sympath C:\Lab\WinDbg\original
.reload /f
bu toy!Score
sxe av
g
```

2. At `Score` entry, inspect `r rcx` and `uf toy!Score`. RCX should be zero at entry because the pointer is the first integer/pointer argument under the x64 ABI. Predict the first invalid load from the disassembly; do not assume one fixed opcode/address across compilers.
3. Use `g` to reach the access violation, then collect:

```text
.logopen C:\Lab\WinDbg\triage.txt
lmvm toy
.exr -1
.ecxr
r
kv
u @rip L8
!analyze -v
.dump /ma C:\Lab\WinDbg\crash.dmp
.logclose
```

4. End this debug target using the UI, open the saved dump, restore original local symbol path, reload, and repeat exception/context/stack inspection. Require the same faulting module-relative location and function; live execution commands are inapplicable to the dump.
5. Test symbol trust on the dump. Close WinDbg, temporarily rename only `original\toy.pdb` to `toy.pdb.saved` in Explorer, then reopen the dump in a fresh session with `.sympath C:\Lab\WinDbg\fixed`. Run `!sym noisy`, `.reload /f toy.exe`, and `lmvm toy`. Require a mismatch diagnostic or absence of original private symbols; an export-only `Score` label is not a private-symbol match. Do not use any ignore-mismatch option. Restore the original filename, restore the original symbol path, reload, and require private symbols again. If the original still loads, inspect the reported PDB path and remove that lab-only cache from this session's search path before repeating.
6. Launch the fixed executable with `--bad`. Set a breakpoint on `Score`, observe null at entry, and step over the guard to the rejected result. Repeat with no arguments to confirm valid result 21. Preserve exact EXE/PDB pairs for both builds.

### Hints

- Module names are `toy`, not the containing directory. The two PDBs share a basename but not identity.
- The unchecked pointer is the defect. Changing a register in the debugger would hide it for one run and would not fix the source.
- An instruction reading offset 4 from a null base can fault at address 4 rather than 0. Use the actual exception record and operand.

### Solution and Expected Results

Faulty `--bad` passes null to `Score`, which loads a field without validating the pointer. Expect exception `0xC0000005`, a read from a null-derived address, `toy!Score` in the selected exception stack, and a caller in `main`. The PDB identifies `Sample` as two 4-byte integers, offsets 0 and 4, size 8. The source guard returns -1 before either field load; the caller translates rejection to exit code 2 while a valid sample remains 21.

### Verification, Troubleshooting, and Cleanup

There are **6 manual gates**: valid original output; null-at-entry/fault correlation; dump/live context agreement; wrong-PDB rejection and recovery; fixed invalid rejection; unchanged valid output. No unit-test count is claimed. In PowerShell, record binary hashes with `Get-FileHash C:\Lab\WinDbg\original\toy.exe -Algorithm SHA256` and the corresponding fixed path.

Missing private symbols: confirm the PDB's exact build, absolute search path, and restored filename. Missing locals with correct symbols: inspect machine instructions and build flags. Missing system symbols do not prevent analysis of this local source. Save errors rather than force-loading symbols. Stop both toy targets, close debugger logs/dumps, restore any renamed PDB, and delete only this lab directory after recording sanitized observations. No kernel/registry settings were changed.

Author validation: source and workflow review only; **no compilation, execution, dump capture, or GUI checks performed**. Actual compiler instruction selection, symbol diagnostics, and UI wording remain unverified.

- [ ] Local WinDbg exercise: Create a harmless crashing toy program, capture its dump in a disposable VM, load matching symbols, and connect the faulting instruction to the source-level defect.
- [ ] Boundary check: Compare the same toy crash with correct and deliberately mismatched symbols, then confirm the corrected build no longer reproduces the fault.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]

## References

- [Install and understand WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [Debugger commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/)
- [Symbols](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols)
- [User-mode dump files](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/user-mode-dump-files)
- [Time Travel Debugging overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview)
- [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
