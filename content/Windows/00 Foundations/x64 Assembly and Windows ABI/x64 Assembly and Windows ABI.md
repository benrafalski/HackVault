---
title: "x64 Assembly and Windows x64 ABI"
aliases: []
tags: [windows, x0]
domain: windows
phase: "X0"
type: tech
status: draft
pair: "[[x64 Assembly and Windows ABI Security]]"
updated: 2026-11-03
---
# x64 Assembly and Windows x64 ABI

> [!abstract] TL;DR
> Argument position, not separate integer/float counters, selects the first four register slots. Track operand size, signedness, flags, shadow space, and alignment together.

> [!info] Agent scope
> Registers; instruction semantics; flags; calling convention; stack alignment; shadow space; unwind metadata; disassembly exercises.

## Prerequisites

- C++ scalar types, hexadecimal arithmetic, and pointers. Use [[Windows Lab Setup]] for isolation.
- Baseline: Windows 11 x64, Visual Studio 2022 Build Tools 17.10 or later in the 17.x family, MSVC v143 x64 tools, Windows SDK 10.0.22621.0 or later. These are compatibility assumptions, not a claim that a particular patch is current. Record the installed versions.

## Learn

```text
Teach me Windows x64 assembly and the Microsoft x64 ABI at expert depth. Assume
C++ pointers and hexadecimal arithmetic, but derive stack offsets explicitly.
Use Windows 11 x64, MSVC v143 and MASM ml64, not the System V ABI or x86 inline
assembly. Cover register widths, flags, signed/unsigned branches, LEA versus
loads, positional integer/FP arguments, varargs duplication, aggregate returns,
shadow space, stack alignment, volatile state, and legal prolog/epilog unwind
metadata. Work through a five-argument mixed-type call, a nonleaf MASM wrapper,
and optimized versus unoptimized compiler output. Provide complete benign
source, build flags, expected results, and ways to falsify each ABI assumption.
Explain compiler-version differences and why disassembly is evidence, not a
stable source mapping. Cite Microsoft primary contracts. Keep debugger commands
out of this lesson; do not edit files or study status. No exploit techniques,
page-table material, or confidential examples. End with worked hard questions.
```

## Cheatsheet

### Machine Semantics

| Operation/state | Meaning and common interpretation error |
|---|---|
| RAX / EAX / AX / AL | 64/32/16/8-bit views. Writing EAX zeroes the upper 32 bits of RAX; AX/AL writes preserve the other bits. |
| `mov`, `movzx`, `movsx`, `movsxd` | Copy, zero-extend, sign-extend, and sign-extend a 32-bit operand to 64 bits. A negative signed 32-bit value needs sign extension before signed 64-bit arithmetic. |
| `lea rax,[rcx+rdx*4+8]` | Computes an address expression without dereferencing or setting arithmetic flags. `mov rax,[rcx]` reads memory. |
| `cmp left,right` | Sets flags as `left-right` without storing the subtraction. Intel syntax puts the destination/left operand first. |
| `jb` / `jae` | Unsigned below / above-or-equal: test CF. |
| `jl` / `jge` | Signed less / greater-or-equal: test SF versus OF. Same bits can produce different signed and unsigned comparisons. |
| `test reg,reg` | AND for flags without a stored result; ZF reports zero. `jz` and `je` are the same condition. |
| `add`, `sub`, `inc` | CF describes unsigned carry/borrow; OF describes signed overflow. `inc` does not update CF. Do not reuse flags after an intervening flag-writing instruction. |
| `call` / `ret` | Pushes the next instruction address / pops it into RIP. The ordinary x64 convention makes the caller responsible for argument storage. |
| RIP-relative addressing | Usually addresses globals/constants relative to the next instruction; ASLR means an absolute address from one run is not an identity. |

Windows x64 uses little-endian storage and LLP64: pointers and `size_t` are 64 bits, `int` and `long` remain 32. `mov eax,-1` yields RAX = `00000000FFFFFFFF`, whereas sign-extending that EAX yields `FFFFFFFFFFFFFFFF`. CPU modular arithmetic is not permission to rely on C++ signed overflow, which is undefined behavior.

### Baseline Calling Contract

| Position | Integer/pointer | Scalar float/double | At callee entry |
|---|---|---|---|
| 1 | RCX | XMM0 | Home slot at `[rsp+8]` |
| 2 | RDX | XMM1 | Home slot at `[rsp+16]` |
| 3 | R8 | XMM2 | Home slot at `[rsp+24]` |
| 4 | R9 | XMM3 | Home slot at `[rsp+32]` |
| 5 | Stack | Stack | `[rsp+40]` |
| 6 | Stack | Stack | `[rsp+48]` |

Each argument consumes a position even if its register class is different. A normal prototyped `mix(int,double,int,double,int)` uses ECX, XMM1, R8D, XMM3, and a stack slot. The unused integer/FP counterparts need not contain meaningful values. Integer arguments are right-justified; upper unused bits are not an argument extension guarantee. Stack argument slots occupy eight bytes, but a 32-bit argument still has a 32-bit payload.

- The caller reserves **at least 32 bytes** of home/shadow space, even with no arguments. The callee may overwrite it. It is not necessarily initialized and is not durable caller storage across a call.
- Immediately before a call, RSP is 16-byte aligned; the pushed return address makes entry RSP congruent to 8 modulo 16. A common nonleaf allocation is `sub rsp,40`: 32 bytes for homes plus eight for alignment. More locals/arguments change the amount. There is no System V red zone.
- Volatile: RAX, RCX, RDX, R8-R11, XMM0-XMM5, arithmetic flags. Nonvolatile: RBX, RBP, RSI, RDI, R12-R15, RSP and the low 128 bits of XMM6-XMM15. Upper YMM/ZMM portions have separate volatility rules; do not extrapolate preservation from the XMM names.
- Integer/pointer returns usually use RAX; scalar FP returns use XMM0. Some small trivial aggregates fit RAX. Other returns use a hidden caller-provided pointer, shifting explicit parameter positions; use the documented restrictions, not a size-only guess.
- Ordinary structs of 1, 2, 4, or 8 bytes can be passed like integers; other sizes generally use caller-owned temporary storage passed by pointer. `__m128` arguments are ordinarily indirect in this convention. `__vectorcall` is a different contract.
- Varargs/unprototyped FP arguments in the first four positions must also be copied into corresponding general-purpose registers. Default argument promotions apply (`float` becomes `double`). A variadic callee cannot repair a mismatched format string.
- MSVC x64 accepts but generally ignores `__cdecl`/`__stdcall` annotations; that does not make different parameter types interchangeable. x86 conventions and ARM64/ARM64EC are not this ABI.

### Frames and Unwinding

The unwinder needs the actual stack allocation and saved nonvolatile state, not just an RBP chain. `.pdata` contains runtime function entries referring to unwind information conventionally in `.xdata` (the linker may merge sections). Compiler-generated nonleaf functions supply this automatically. A simple leaf that does not alter nonvolatile state can be unwound by simulating a return and need not have an entry.

MASM `PROC FRAME`, `.allocstack`, `.pushreg`/`.savereg`, and `.endprolog` describe operations; they do **not** perform the corresponding instructions. The executable instructions and annotations must agree. Legal epilogs use recognized forms so asynchronous unwinding can identify partial teardown. Large frames need appropriate stack probing; do not hand-roll a huge decrement. Dynamic stack allocation typically requires a frame pointer and further rules.

Use `dumpbin /disasm`, `dumpbin /unwindinfo`, and compiler `/FAs` output for structural evidence. PDBs provide names/source; PE unwind data is needed even without a PDB. Runtime debugging belongs in [[WinDbg]].

## Gotchas

- Optimization can fold calls, omit frames, and use tail calls. `/Od` is a teaching baseline, not a production security recommendation.
- An assembler accepting a file does not establish ABI correctness. A wrong home-space allocation may appear to work until a different callee spills registers.
- Never infer a private structure layout or syscall number from an instruction sequence and treat it as a Windows compatibility contract.

## Labs

### Environment and Complete Files

Use a standard user inside a disposable Windows 11 x64 development VM. Install the Visual Studio 2022 **Desktop development with C++** workload (MSVC v143 x64/x86, Windows SDK, C++ AddressSanitizer for later notes). No WDK, Python, driver, network service, or administrator runtime is needed. Open **x64 Native Tools Command Prompt for VS 2022** (`cmd.exe` syntax below). Create an empty work directory:

```bat
mkdir "%USERPROFILE%\X0-ABI"
cd /d "%USERPROFILE%\X0-ABI"
where cl
where ml64
cl /Bv
```

Record compiler/toolset and OS build from Settings > System > About. `cl /Bv` without a source may also emit a missing-source diagnostic; it is an inventory command, not the build. Create exactly these two files in this directory.

**abi.cpp**:

```cpp
#include <cstdio>

extern "C" __declspec(noinline) double mix(
	int first, double second, int third, double fourth, int fifth) {
	return first + second + third + fourth + fifth;
}
extern "C" double bridge();

int main() {
	const double direct = mix(1, 2.5, 3, 4.5, 5);
	const double wrapped = bridge();
	std::printf("direct=%.1f wrapped=%.1f\n", direct, wrapped);
	return direct == 16.0 && wrapped == 16.0 ? 0 : 1;
}
```

**bridge.asm**:

```asm
option casemap:none
EXTERN mix:PROC
PUBLIC bridge
.const
second REAL8 2.5
fourth REAL8 4.5
.code
bridge PROC FRAME
	sub rsp, 40
	.allocstack 40
	.endprolog
	mov ecx, 1
	movsd xmm1, QWORD PTR [second]
	mov r8d, 3
	movsd xmm3, QWORD PTR [fourth]
	mov DWORD PTR [rsp+32], 5
	call mix
	add rsp, 40
	ret
bridge ENDP
END
```

### Objectives and Steps

Predict every argument location, then build and inspect:

```bat
ml64 /nologo /Zi /Fo bridge.obj /c bridge.asm
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf /FAs /Faabi.cod abi.cpp bridge.obj /Feabi.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
abi.exe
echo %ERRORLEVEL%
dumpbin /headers abi.exe
dumpbin /disasm abi.exe > disassembly.txt
dumpbin /unwindinfo abi.exe > unwind.txt
```

1. Locate `mix` in the compiler listing and its call in the MASM/object disassembly. Identify conversions to double and the XMM0 return.
2. Derive why the wrapper writes `[rsp+32]` but the callee initially reads its fifth argument at `[rsp+40]`. If the callee subtracts another frame size, adjust again.
3. Find the wrapper's unwind record and reconcile its allocation with the instructions.
4. Repeat the `cl` command using `/O2` instead of `/Od`, `/Faabi-opt.cod`, and `/Feabi-opt.exe`. Run it and compare code, not exact addresses. Keep `__declspec(noinline)` so a call remains observable.

### Hints

The return address accounts for an eight-byte difference between caller and callee offsets. The wrapper's 40-byte area contains both the 32-byte homes and the fifth slot; its size also restores pre-call alignment. `mix` may home register arguments in a debug build but is not required to.

### Solution and Expected Results

Expected output is `direct=16.0 wrapped=16.0`, exit 0 for both builds. At the wrapper's call: ECX=1, XMM1=2.5, R8D=3, XMM3=4.5, DWORD at RSP+32=5. Entry RSP is 8 modulo 16; subtracting 40 makes it 0 modulo 16 before the nested call. No nonvolatile register is modified. The wrapper unwind allocation is 40 bytes. The exact encoding/name presentation varies with toolset and symbol availability; a merged `.xdata` section is not proof of missing unwind information.

### Verification, Troubleshooting, and Cleanup

Acceptance: both exit codes are zero; the PE machine is x64 (`8664`); you can account for all five positions and find the wrapper's unwind entry. A correct numeric result alone does not verify unwinding. If `ml64` is absent, modify the C++ workload in the VM. LNK1112 means architecture mismatch. An unresolved `bridge` means the object was omitted or the public name differs. Do not solve errors by disabling `/GS` or platform protections.

Author validation: **not executed**. Native compilation, optimized disassembly, and unwind inspection must be performed by the reader/parent validator. There are no measured results here. Close processes/tools, then remove only `%USERPROFILE%\X0-ABI` or restore the development snapshot. The following original completion items remain user-owned.

- [ ] Local x64 Assembly and Windows ABI exercise: Compile a small function with mixed integer/floating arguments and one stack argument using MSVC. Inspect its disassembly and unwind information; annotate each argument location, stack adjustment, and preserved register.
- [ ] Boundary check: Call a toy function through the correct declared signature and compare with compiler diagnostics for a mismatched declaration. Use a disposable process; do not patch system code.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[x64 Assembly and Windows ABI Security]]

## References

- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Microsoft x64 stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage)
- [Microsoft x64 software conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions)
- [Microsoft x64 exception handling and unwind records](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [MASM PROC](https://learn.microsoft.com/en-us/cpp/assembler/masm/proc)
- [ML/ML64 options and placement rules](https://learn.microsoft.com/en-us/cpp/assembler/masm/ml-and-ml64-command-line-reference)
