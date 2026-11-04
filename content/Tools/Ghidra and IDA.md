---
title: "Ghidra and IDA"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Ghidra and IDA

> [!abstract] TL;DR
> Load correctly, inspect imports/strings, follow cross-references, assign types, and verify important conclusions in disassembly.

> [!info] Agent scope
> Loading PE files; analysis; functions; cross-references; types; decompilation; symbols; legal training binaries; version and edition differences.

## Prerequisites

- Windows 11 x64 VM; MSVC v143/Visual Studio 2022 C++ tools and Windows SDK; Ghidra official release or a licensed IDA edition supporting PE x64; Python 3.12 stdlib for the supplied four native-output checks.
- Concrete Ghidra baseline: **12.2, 64-bit JDK 25**, and Python 3.12 (within its documented 3.9..3.15 range). Use that release's bundled Getting Started guide rather than whichever Java happens to be on PATH. Record `java -version`, Ghidra version, compiler version, and analysis options. Other releases can require different JDKs; no PyGhidra/debugger packages are needed for this static-analysis lab.
- Record IDA edition, exact version, processor/decompiler licenses, and local versus cloud execution. Current IDA Free advertises x86/x64 disassembly and **cloud-based** x86/x64 decompilation; licensing, scripting, and commercial-use terms must be checked for that release. Ghidra provides a local decompiler. Use Ghidra for the complete offline exercise if IDA would upload anything.
- Analyze only the self-authored PE below. No malware, packed samples, plugins from unknown sources, cloud analysis, or executable patching is needed.

## Learn

```text
Teach me Ghidra and IDA as evidence-driven native-code analysis tools. Assume
C/C++, Windows PE, x64 ABI, and basic assembly. Establish the exact versions,
Ghidra JDK, IDA edition/decompiler licensing, scripting runtime, and whether any
feature sends code or metadata to a cloud service. Use offline local analysis.
Trace PE loader selection, sections, file offset versus RVA versus VA, imports,
exports, entry point and CRT startup, function discovery, xrefs, CFGs, PDBs,
types, and decompiler dataflow. Compare concrete GUI operations in both tools.
Explain signedness, padding, pointer widths, calling convention recovery,
indirect calls, compiler idioms, jump tables, tail calls, inlining, and limits of
static reachability. Build a complete self-authored x64 PE with a structure and
two input checks, analyze debug and optimized builds, recover field offsets and
a function prototype, and validate pseudocode against instructions and known
source. Deliberately change one inferred signed type, explain why readable
pseudocode can be wrong, then restore it. Include exact build commands, test
inputs/outputs, version-aware headless options, evidence and cleanup. Separate
database annotations from binary patches and hash originals before/after.
Use official Ghidra, Hex-Rays and Microsoft sources. No malicious samples,
credential discovery, protection bypass, or confidential data. Teach in this
conversation; do not edit files or study status.
```

## Cheatsheet

### Loading and Address Identity

For a PE, a file offset is a location in the disk image; an RVA is relative to the image base; a VA is base + RVA. A file-backed section maps RVA to `PointerToRawData + (RVA - VirtualAddress)` only while the offset lies within that section's raw data. Zero-initialized memory has no corresponding raw bytes. Do not feed a runtime VA into a static database with a different image base without translating it.

Let the PE loader choose architecture and sections, then confirm PE32+ and Machine AMD64. Importing as a raw binary discards valuable loader metadata. The entry point is usually CRT startup, not `main`. An import names a dependency, not proof of a call in the observed run. Delay imports, indirect calls, and dynamically resolved symbols may not appear in the obvious call graph.

| Task | Ghidra CodeBrowser | IDA | Evidence requirement |
|---|---|---|---|
| Load | New non-shared project -> Import File -> verify PE language/compiler -> Analyze | Open binary -> verify PE and processor -> allow autoanalysis | Record loader, image base, architecture and analysis warnings. |
| Discover anchors | Symbol Tree: Imports/Exports; Search -> for Strings | Imports/Exports/Strings subviews | Follow references to code, not just string content. |
| Navigate xrefs | References -> Show References To; follow callers | X on selected symbol; jump to listed callers | Distinguish code call/jump from data/address reference. |
| Name | Edit Label; rename function in listing/decompiler | N for a selected name | Names are hypotheses; keep rationale in comments/bookmarks. |
| Prototype | Edit Function Signature | Y / Set type | Check RCX/RDX/R8/R9 usage and return width before assigning. |
| Structure | Data Type Manager -> structure; apply pointer type | Local Types/Structures (version-dependent); assign type | Verify size, alignment, field offsets, signedness. |
| Decompile | Decompiler window | Pseudocode/F5 when licensed and permitted | Cross-highlight statements and instructions; do not enable cloud for this lab. |
| Graph | Function Graph | Graph view (Space in common keymaps) | CFG is recovered structure, not a coverage record. |
| Save | Save project/program database | Save database, commonly .i64/.idb depending build | A saved database is not an exported patched executable. |

Key bindings assume standard maps; menu actions are the fallback. Ghidra PDB import can use its bundled analyzer; IDA PDB support depends on build/configuration. Decline external symbol lookup for the first pass, then load only the matching locally built PDB. PDB identity matching matters more than a familiar basename.

### Types, Dataflow, and Trust

The fixture's structure is 16 bytes: `units` at 0 (unsigned 32-bit), `unit_price` at 4 (signed 32-bit), `label` at 8 (8 bytes). The first pointer argument arrives in RCX on Windows x64; EAX carries an `int` return. A 32-bit register write zero-extends the corresponding 64-bit register; it does not prove a source value was unsigned. Signed branch predicates (`jl`, `jg`) and unsigned ones (`jb`, `ja`) are stronger evidence, but optimized compilers may invert, combine, or replace branches.

An analyst assigning `unsigned int` to `unit_price` can make the negative-price check nonsensical or misrendered without changing any machine instruction. Reset the type and check the load width, sign-sensitive comparison, source, and runtime `--negative` case. Never accept a cleaner decompiler expression as independent confirmation of the type you just supplied.

Optimization changes the observable model: `/O2` may inline callers, fold constants, eliminate temporary variables, and replace branches with conditional moves. `__declspec(noinline)` stabilizes the exported teaching function, but does not freeze its instruction sequence. Unwind metadata helps identify x64 functions; it is not a universal proof of all function boundaries. Unreferenced data can look like code, and indirect targets can be missed.

### Reproducible Tool Workflows

Record SHA-256, file size, EXE/PDB pair, tool edition/build, analysis options, prototype before/after, field offsets, function RVA, and a few decisive instructions. Keep original bytes read-only by convention and save annotations in the analysis database. Exported pseudocode is a derived artifact, not recovered original source.

Optional Ghidra headless import for an already provisioned release (PowerShell; set `GHIDRA_HOME` to its actual installation and use a new project directory):

```powershell
& "$env:GHIDRA_HOME\support\analyzeHeadless.bat" C:\Lab\RE\projects InvoiceHeadless -import C:\Lab\RE\invoice.exe -analysisTimeoutPerFile 120
```

Inspect the exit status and log; timeout or a saved project does not mean all analysis succeeded. Headless analysis does not execute the PE. IDA batch/headless automation and IDAPython APIs vary with edition/version; check that build's SDK/docs before depending on them. This lab requires neither script plugins nor paid automation.

## Gotchas

- Public Lumina, cloud decompilers, plugin telemetry, and symbol servers can transmit hashes, metadata, or binaries. Leave external integrations off, even though this fixture is public and synthetic.
- A matching display name does not prove binary identity. Rebuilding changes PDB identity and may change RVAs even with unchanged source.
- Do not run a binary merely because static analysis looks harmless. Here source provenance and the limited self-authored build establish the exercise boundary.

## Labs

### Environment and Complete Files

Create a new `C:\Lab\RE` directory and save both files below. Work in a development VM with the compiler and chosen analysis tool already provisioned. The C++ program only computes a small invoice value and prints it; no files, network connections, or registry changes occur during execution.

### File: invoice.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

struct Invoice {
	std::uint32_t units;
	std::int32_t unit_price;
	char label[8];
};

static_assert(sizeof(Invoice) == 16);
static_assert(offsetof(Invoice, unit_price) == 4);
static_assert(offsetof(Invoice, label) == 8);

extern "C" __declspec(dllexport) __declspec(noinline)
int Evaluate(const Invoice* invoice) {
	if (invoice->units > 8) {
		return -1;
	}
	if (invoice->unit_price < 0 || invoice->unit_price > 100) {
		return -2;
	}
	return static_cast<int>(invoice->units) * invoice->unit_price;
}

int main(int argc, char** argv) {
	Invoice invoice{3, 7, "LAB"};
	if (argc == 2 && std::strcmp(argv[1], "--many") == 0) {
		invoice.units = 9;
	}
	if (argc == 2 && std::strcmp(argv[1], "--negative") == 0) {
		invoice.unit_price = -1;
	}
	if (argc == 2 && std::strcmp(argv[1], "--zero") == 0) {
		invoice.units = 0;
	}
	const int total = Evaluate(&invoice);
	std::printf("%s total=%d\n", invoice.label, total);
	return total < 0 ? 2 : 0;
}
```

### File: test_example.py

```python
from pathlib import Path
import subprocess
import unittest


class ExampleTests(unittest.TestCase):
	def check_case(self, argument, expected, code):
		for name in ("invoice.exe", "invoice_opt.exe"):
			executable = Path(__file__).resolve().parent / name
			self.assertTrue(executable.is_file(), f"Build {name} first")
			with self.subTest(binary=name):
				result = subprocess.run([str(executable), *argument],
										capture_output=True, text=True, timeout=5)
				self.assertEqual(result.returncode, code)
				self.assertEqual(result.stdout.strip(), expected)
				self.assertEqual(result.stderr, "")

	def test_valid(self):
		self.check_case([], "LAB total=21", 0)

	def test_many(self):
		self.check_case(["--many"], "LAB total=-1", 2)

	def test_negative(self):
		self.check_case(["--negative"], "LAB total=-2", 2)

	def test_zero(self):
		self.check_case(["--zero"], "LAB total=0", 0)


if __name__ == "__main__":
	unittest.main(verbosity=2)
```

Build in the x64 Native Tools Command Prompt (cmd):

```bat
cd /d C:\Lab\RE
cl /nologo /W4 /EHsc /std:c++17 /Zi /Od /MD /Fdinvoice_compile.pdb /Foinvoice.obj /Feinvoice.exe invoice.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:invoice.pdb
cl /nologo /W4 /EHsc /std:c++17 /Zi /O2 /MD /Fdinvoice_opt_compile.pdb /Foinvoice_opt.obj /Feinvoice_opt.exe invoice.cpp /link /DEBUG:FULL /INCREMENTAL:NO /PDB:invoice_opt.pdb
dumpbin /headers invoice.exe
dumpbin /exports invoice.exe
py -3.12 test_example.py
```

### Objectives and Steps

1. Record hashes with PowerShell `Get-FileHash C:\Lab\RE\invoice*.exe -Algorithm SHA256`. Confirm AMD64/PE32+ and the `Evaluate` export from the two dumpbin reports.
2. Import the unoptimized executable in one tool, declining PDB/external symbol retrieval initially. Follow the export to `Evaluate`. Record its RVA; find at least one caller and the `LAB` string use. Startup/main names may be inferred or absent.
3. Before reading source, write the inferred prototype and three field offsets. Define the structure above in the tool's type manager and apply `int Evaluate(const Invoice *invoice)` through its signature editor. Name the fields and mark the rejection blocks.
4. Compare the disassembly and decompiler for units 3, 9, and 0, and price -1. Explain which operand/predicate distinguishes signed negative price from too many units.
5. Deliberately assign the wrong unsigned type to `unit_price`. Record how the display changes or fails to improve. Restore the signed type. Load the matching PDB and compare its layout with the manual one.
6. Import the optimized executable into a separate program/database. Locate the same export, compare its CFG/instructions, and verify that the four outputs remain unchanged. An optimized unsigned range check can represent `price < 0 || price > 100`; explain this using the actual instructions, not a guessed compiler pattern.

### Hints

- The exported function is the stable anchor, not an absolute VA. Use caller xrefs to connect it to argument construction and printed output.
- A structure's layout does not imply every field is used by every function: `Evaluate` never reads `label`; `main` prints it.
- If no local decompiler is licensed in IDA, complete disassembly/xref/type tasks there and the pseudocode comparison in Ghidra. Do not turn on cloud analysis to satisfy a checkbox.

### Solution and Expected Results

Recover a 16-byte structure with fields at 0, 4, and 8. `Evaluate` rejects units >8 with -1 and a price outside 0..100 with -2, otherwise multiplies units by price; accepted product is at most 800, so the chosen bounds avoid signed multiplication overflow. The caller always passes a valid object; this function's null-pointer contract is not established by its body. Outputs are 21, -1, -2, and 0 for the four supplied modes, with exit codes 0, 2, 2, and 0.

### Verification, Troubleshooting, and Cleanup

Expected **4 unittest tests**, each exercising **2 binaries** (8 subprocess invocations). Static gates: correct loader/architecture, export/caller xref, structure offsets, branch explanation, corrected signed type, and optimized/unoptimized equivalence. Hashes before and after analysis must match; renaming symbols should only change databases.

If imports look empty, verify the PE loader and that you opened the executable rather than the object/PDB. If types do not appear, confirm PDB identity and analyzer support. If `/MD` execution fails, provision the matching runtime in the development VM rather than editing the binary. Close tools and delete only this lab's executables, PDBs, objects, databases, and project directory. Keep sanitized notes separate from auto-upload integrations.

Author validation: **no compiler, native tests, headless analysis, or GUI execution performed**. Edition/JDK availability and exact instruction selection must be checked locally; the four tests are supplied, not reported passing.

- [ ] Local Ghidra and IDA exercise: Compile a small PE with known source, analyze it with one installed tool, rename key functions, and compare a branch and structure access against the original source.
- [ ] Boundary check: Change one inferred type and verify the resulting pseudocode against the actual instructions rather than accepting the more readable output automatically.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]

## References

- [Ghidra official repository and release requirements](https://github.com/NationalSecurityAgency/ghidra)
- [Ghidra 12.2 Getting Started and exact prerequisites](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md)
- [Ghidra beginner course](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)
- [Hex-Rays documentation](https://docs.hex-rays.com/)
- [IDA Free features and license boundaries](https://hex-rays.com/ida-free)
- [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MSVC compiler options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options)
