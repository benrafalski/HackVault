---
title: "x64dbg"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# x64dbg

> [!abstract] TL;DR
> Load the right architecture, set a meaningful breakpoint, inspect state, predict the next transition, then step and compare.

> [!info] Agent scope
> User-mode debugging; breakpoints; stepping; memory and registers; symbols; local educational binaries.

## Prerequisites

- Windows 11 x64 disposable development VM; official x64dbg build; MSVC v143/VS 2022 C++ tools and Windows SDK. Record debugger build/date, OS build, compiler version, and executable hash.
- Use x64dbg for the supplied native x64 PE; x32dbg is for x86 targets, including WOW64 processes. This is a user-mode debugger, not a kernel debugger. See [[WinDbg]] for the separate canonical Windows debugger reference.
- No administrator token, plugin, patch, network access, PDB server, or mitigation change is required. Local PDB support depends on debugger build; exports provide the lab's reliable symbol anchors.

## Learn

```text
Teach me x64dbg at expert user-mode debugging depth using only a self-authored
Windows x64 program. Assume C++, PE, registers, and the x64 ABI. Establish the
exact x64dbg build, matching x32dbg/x64dbg architecture, symbol capabilities,
module identity, and normal executable baseline. Explain initial system break,
CRT entry versus source main, ASLR/RVA translation, registers/flags, stack,
dump, memory map, modules, threads, and breakpoint state. Compare software INT3,
hardware data, and page-granular memory breakpoints, timing and exception side
effects, slot/alignment limits, and conditional/logging breakpoint pitfalls.
Give actual x64dbg commands and matching GUI fallbacks, carefully distinguishing
its expression language and number bases from other debuggers. Show a complete
MSVC-built bounds-checked array selector, break at an exported function, recover
the three arguments, predict both bounds outcomes, step and inspect the return,
then watch a global result write. Repeat using module-relative resolution across
restarts without assuming ASLR must change the base each time. Explain first-
chance versus unhandled exceptions, optimized locals, symbol provenance, and
why an observation under a debugger is not universal coverage. Include exact
inputs, outputs, manual acceptance checks, troubleshooting, evidence and cleanup.
No malicious samples, patching, protection bypass, evasion, or confidential data.
Use official x64dbg and Microsoft sources. Teach here; do not edit files or
study status.
```

## Cheatsheet

### Execution State and Navigation

Open the executable with File -> Open, configure its command line/working directory in the available debug settings, and wait for the initial system break. The CPU window describes the selected thread, not every thread. Follow code in Disassembly, arguments/data in Dump, return addresses in Stack, and permissions/module mapping in Memory Map. The Symbols view lists loaded modules and exports; resolve the exported lab function there before running.

Windows x64 integer/pointer arguments enter in RCX, RDX, R8, R9; our 32-bit count/index are read from EDX and R8D. Return `int` is in EAX. At function entry RSP points at the return address and caller-provided home space follows it; after a prologue the stack layout changes. Do not assume arguments remain in volatile registers after a call. Stack unwind views and guessed call stacks can disagree when metadata is missing.

### Commands and Breakpoint Mechanisms

The commands below are **x64dbg's language**, not WinDbg commands. Numeric expressions default to hexadecimal; `.10` denotes decimal 10 in its expression syntax. Use symbols rather than copying absolute addresses between runs.

| Action | x64dbg command | GUI fallback / constraint |
|---|---|---|
| Break at exported function | `bp inspect:SelectValue` | Symbols -> inspect -> SelectValue -> Toggle breakpoint. Verify the resolved address is in inspect's executable section. |
| Run | `run` | F9; can stop on another configured event first. |
| Step into / over | `sti` / `sto` | F7 / F8; step-over runs a callee, not a simulation of it. |
| Run until return | `rtr` | Debug -> Execute till return; inspect whether stopped before the return, then step over it to the caller. |
| Watch global write | `bphws inspect:g_result,w,4` | Hardware write breakpoint on aligned 4-byte global. Normally triggers after the write instruction. |
| Remove watch | `bphwc inspect:g_result` | Breakpoints view -> remove hardware breakpoint. |
| Remove code breakpoint | `bpc inspect:SelectValue` | Breakpoints view -> remove software breakpoint. |
| Inspect bytes | `dump rcx` | Follow RCX in Dump; valid at function entry in this fixture. |
| Inspect caller stack | `sdump rsp` | Follow RSP in Stack; use pointer-sized interpretation for return addresses. |

If export syntax differs in your build, select the exact export through Symbols, follow it, and toggle the breakpoint there. Do not guess a system API address. The `inspect:` qualifier resolves the module's export; use the module/RVA shown by the UI as corroboration.

| Breakpoint | Mechanism | Failure/evidence pitfall |
|---|---|---|
| Software | Temporarily replaces an instruction byte with a trap and restores execution around the hit | Changes target code in memory; self-checking code may behave differently. Not an on-disk patch. |
| Hardware execution/data | CPU debug registers; typically four address slots per thread | Supported sizes/alignment matter; watch addresses must remain valid; thread handling is debugger-dependent. |
| Memory | Page-protection/guard mechanisms implemented by debugger | Page granularity can catch unrelated accesses and alter exception/timing behavior. Not needed here. |
| Conditional/logging | Debugger evaluates expressions on hits and may resume | Wrong numeric base, stale pointers, or a costly condition can mislead or slow execution. Begin with an unconditional breakpoint. |

For the second run, use breakpoint Edit -> Break condition `r8d == 3` on `SelectValue` if desired; 3 has the same value in hex and decimal. Record hit counts and actual argument values. A log message is an observation at the breakpoint, not a history of all writes.

### Symbols, Exceptions, and Evidence

Exports expose names but not full source locals/types; private matching PDBs can add those. A function label alone is not proof that its PDB matched. Avoid automatic public-symbol lookup when it is unnecessary, and keep source/PDB identities with the original binary hash.

First-chance exceptions notify the debugger before normal application handling; unhandled exceptions are a different event. The initial breakpoint is expected and not a program defect. Do not globally ignore exceptions just to make a run continue. This fixture has no intentional exception path. If it faults, confirm binary, source, arguments, and runtime rather than changing registers or skipping instructions.

Record: exact command line, module base, function RVA, breakpoint type, selected thread, entry arguments, observed branch, EAX on return, global value after assignment, and stdout/exit status. A single breakpoint hit establishes reachability only for that input/run. ASLR may reuse a base; stable RVA with a resolved current base is the invariant, not mandatory base movement.

## Gotchas

- The entry breakpoint precedes the function body; a hardware write stop is usually after the write. Reading these as the same observation point creates off-by-one conclusions.
- Display `FFFFFFFF` in EAX means -1 as a signed 32-bit result; the full RAX can be zero-extended. Interpret the declared return width.
- Debugger databases retain labels and breakpoints; a stale absolute breakpoint from another build is not evidence. Start a fresh per-binary database or clear obsolete entries.

## Labs

### Environment and Complete File

Create a new `C:\Lab\X64dbg` directory, save the following source, and build it in the x64 Native Tools Command Prompt. It reads a fixed three-element array and writes one global result. It never writes outside the array, opens a socket, alters another process, or disables a mitigation.

### File: inspect.cpp

```cpp
#include <cstdio>
#include <cstring>

extern "C" {
	__declspec(dllexport) volatile int g_result = -99;
}

extern "C" __declspec(dllexport) __declspec(noinline)
int SelectValue(const int* values, unsigned count, unsigned index) {
	if (index >= count) {
		return -1;
	}
	return values[index];
}

int main(int argc, char** argv) {
	const int values[3] = {10, 20, 30};
	const unsigned index = argc == 2 && std::strcmp(argv[1], "--bad") == 0 ? 3u : 1u;
	g_result = SelectValue(values, 3, index);
	std::printf("index=%u result=%d\n", index, static_cast<int>(g_result));
	return g_result < 0 ? 2 : 0;
}
```

```bat
cd /d C:\Lab\X64dbg
cl /nologo /W4 /EHsc /Zi /Od /MD /Fdinspect_compile.pdb /Feinspect.exe inspect.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:inspect.pdb
dumpbin /exports inspect.exe
inspect.exe
echo %ERRORLEVEL%
inspect.exe --bad
echo %ERRORLEVEL%
```

Expected baseline: `index=1 result=20`, exit 0. Expected rejected input: `index=3 result=-1`, exit 2. Record SHA-256 with PowerShell `Get-FileHash C:\Lab\X64dbg\inspect.exe -Algorithm SHA256`.

### Objectives and Steps

1. Open this executable in x64dbg. Leave arguments empty for the first run; set working directory to the lab root. At the initial break, find `SelectValue` and `g_result` under inspect's exports.
2. Set the code breakpoint and hardware write watch from the table; confirm both in Breakpoints. Record `g_result=-99` as a signed 32-bit value before execution reaches the caller's assignment. It is statically initialized, not assigned by a special startup routine in this source.
3. Run to `SelectValue`. Record RCX, EDX=3, and R8D=1. Follow RCX in Dump and view three 32-bit values: 10, 20, 30. Record base and function RVA.
4. Step through the compare/conditional jump. Predict that index 1 is below count 3. Follow the indexed load, step through return, and require EAX=20. Do not edit registers, flags, memory, or code.
5. Continue to the hardware write stop. Require `g_result=20`; inspect the instruction immediately preceding the stop to find the write. Remove the watch and continue to normal exit.
6. Restart with `--bad`. Re-resolve the export breakpoint and global watch, record the new base/RVA, and require R8D=3. Predict rejection, step through the guard, and require signed EAX=-1 before the caller writes -1 and exits 2. The rejected branch must not execute the indexed array load.

### Hints

- If the code break never hits, check that the correct module is loaded and the breakpoint is enabled, then run past the initial system/entry breaks. Do not repeatedly step through all CRT initialization.
- The compiler may invert the branch or use stack spills at `/Od`. Read the actual operands and flags rather than searching for one fixed mnemonic.
- Hardware breakpoint failure can indicate an unaligned address, unavailable slot, or wrong module resolution. Remove unrelated lab breakpoints and use the exact exported global address; never change process protections to compensate.

### Solution and Expected Results

The first call has `(values pointer, count=3, index=1)` and reads the second integer, returning 20. The second has index equal to count, so `index >= count` is true and it returns -1 without accessing a fourth element. This validates the boundary check, not a bypass. The global changes once per process from -99 to its final result. Addresses may vary; RVAs for the same binary should not.

### Verification, Troubleshooting, and Cleanup

**6 manual gates**: both normal outputs/exit codes; export breakpoint identity; entry arguments/array contents; valid load and return; invalid guard with no indexed load; global write watch and stable RVA across two runs. Keep tool build and observations for each. No automated test count is claimed.

If output differs outside the debugger, fix the build/runtime/command line first. If only debugged execution differs, inspect breakpoints and retained database edits. On completion remove the two breakpoints, run the toy to exit, close x64dbg, and remove only this lab's binary/PDB/object/database files. Re-hash the executable: it must be unchanged. The source fix is already the bounds guard; no patched executable is part of the exercise.

Author validation: **not built or executed; GUI, breakpoint syntax against the installed build, and emitted instructions remain unverified**. The official command documentation supports the command families; use its current build-specific details if labels differ.

- [ ] Local x64dbg exercise: Debug a toy executable with known source, break at a marker function, inspect arguments and memory, then step through its bounds check.
- [ ] Boundary check: Verify the breakpoint resolves inside the expected module on two runs, recording load addresses and stable RVA, and that the unmodified toy follows the predicted branch.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]

## References

- [x64dbg official documentation](https://help.x64dbg.com/)
- [Software breakpoint command](https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetBPX.html)
- [Hardware breakpoint command](https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetHardwareBreakpoint.html)
- [Expression syntax](https://help.x64dbg.com/en/latest/introduction/Expressions.html)
- [Conditional breakpoints](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html)
- [Windows x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
