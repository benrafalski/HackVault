---
title: "PE Format"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[PE Format Security]]"
updated: 2026-11-03
---
# PE Format

> [!abstract] TL;DR
> Validate signatures, bounds, architecture, alignment, and directory ranges before parsing. Treat all file-provided offsets and counts as untrusted.

> [!info] Agent scope
> Headers; sections; imports and exports; relocations; resources; data directories; loader-facing validation.

## Prerequisites

- Little-endian integers, checked offsets, the difference between file bytes and a loaded image, and [[Windows Lab Setup]].
- Lab: already installed CPython 3.12+ standard library, Windows PowerShell 5.1+ or PowerShell 7. No compiler, packages, administrator rights, or real executable samples required.

## Learn

```text
Teach the Windows PE image format at expert binary-analysis depth. Assume basic
little-endian integer parsing. Explain DOS e_lfanew, signature, COFF header,
PE32 versus PE32+ optional headers, sections, file alignment, image alignment,
RVA/VA/file-offset conversion and zero-filled virtual tails. Work through imports,
ILT/IAT, named and ordinal exports, forwarders, base relocation blocks, resources,
and the data directories including the certificate file-offset exception, TLS
VA fields and x64 unwind metadata. Explain loader-facing checks without writing
a loader. Use bounded self-authored byte fixtures only, never executing images.
Supply exact parsing contracts, limits, complete code, hand-computed offsets,
negative tests and worked results. Distinguish parseability, loadability, signature
verification and benignness. Cite the Microsoft PE specification and label its
version limitations. No injection, loader redirection, exploit primitives, private
data or debugger commands. Teach in chat; do not author files or mark progress.
```

## Cheatsheet

### Header Coordinates

PE is a file format, not a C struct pointer graph. Read little-endian fields only after validating their complete byte ranges. Avoid casting unaligned external bytes to native structures; host architecture and compiler packing are not the file's architecture. A COFF object is not a PE image and does not start with the image's DOS header.

| Location | Field / rule |
| --- | --- |
| File offset `0` | DOS `MZ`; require enough bytes to read `e_lfanew` at `0x3c` |
| File offset `e_lfanew` | Four-byte `PE\0\0`; reject negative/suspicious or out-of-bounds offset before adding |
| PE + `4` | 20-byte COFF header: machine at +0, section count +2, optional-header size +16, characteristics +18 |
| PE + `24` | Optional header; magic `0x10b` is PE32, `0x20b` PE32+. It is required for images despite its name |
| Optional + `24` (PE32+) / `28` (PE32) | ImageBase: 8 / 4 bytes |
| Optional + `32`, `36`, `56`, `60` | SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders, each 4 bytes |
| Optional + `108` / `92` | NumberOfRvaAndSizes for PE32+ / PE32 |
| Optional + `112` / `96` | First 8-byte data-directory entry; validate both count and optional-header extent |
| Optional + SizeOfOptionalHeader | Section table: `NumberOfSections * 40` bytes; specification documents a Windows limit of 96 sections |

Machine `0x8664` is AMD64 and `0x14c` is x86. PE32+ is not an alias for every possible 64-bit instruction set; inspect Machine separately. Section names are eight-byte labels, potentially without a terminator. Characteristics describe intended code/data/read/write/execute attributes; names such as `.text` are not proof of content or provenance.

Normal image FileAlignment is a power of two from 512 to 65,536. SectionAlignment must be at least FileAlignment; low section-alignment images have special rules requiring equal file/memory placement. SizeOfImage is section-aligned; SizeOfHeaders includes the complete header/table region rounded to file alignment. A strict educational subset may reject unusual but legal layouts; say so rather than calling every rejection a Windows loader verdict.

### RVA Conversion and Directories

For a file-backed section with RVA `0x1000`, raw offset `0x200`, raw size `0x400`, RVA `0x1180` maps to file offset `0x380`. Compute `delta = rva - section.VirtualAddress`, then `offset = PointerToRawData + delta`, but only after proving the whole requested range fits the section's raw extent **and** the actual file. VirtualSize can exceed SizeOfRawData: that tail exists as zeros in a loaded image but has no corresponding raw bytes. Header RVAs map to file offsets only within validated SizeOfHeaders. Reject ambiguous overlapping ranges for deterministic analysis.

| Directory | Structure and exact parsing boundary |
| --- | --- |
| Import (index 1) | 20-byte descriptors until an all-zero descriptor, within the declared table budget. Name and thunk pointers are RVAs, not offsets into the directory. ILT/IAT entries are 4 bytes for PE32 or 8 for PE32+; high bit selects ordinal, otherwise hint/name RVA. Names are bounded ASCII NUL-terminated strings. Loaded IAT entries are addresses, not raw-file name RVAs |
| Export (0) | 40-byte directory; EAT contains 32-bit RVAs. Name pointers and 16-bit ordinal **indexes** are parallel arrays. Check index < NumberOfFunctions; public ordinal = index + Base. An EAT RVA inside the export directory range denotes a bounded forwarder string, not code |
| Base relocation (5) | Block begins with 4-byte page RVA and 4-byte SizeOfBlock; require size >= 8, even payload size and forward progress. Each 16-bit entry is type in high 4 bits, offset in low 12. `ABSOLUTE=0` is padding; x64 `DIR64=10` adjusts an eight-byte field by actual base minus preferred base |
| Resource (2) | Tree convention is type/name/language. Directory-relative offsets are based at the resource root, not image base. High bits tag names and subdirectories. Leaf data entry holds a **data RVA**, size, codepage and reserved field. Bound depth, entry count and cycles |
| Certificate (4) | Address field is a **file offset**, not an RVA; certificates are not mapped image contents. Validate entry lengths and eight-byte alignment separately |
| Exception (3), TLS (9), load config (10) | Architecture/size-dependent metadata. x64 runtime functions hold begin/end/unwind RVAs; TLS contains some VAs, not just RVAs; load config grows across versions |

For a relocation target initially `0x140001234`, moving the preferred base from `0x140000000` to `0x140100000` gives delta `0x100000` and target `0x140101234`. This is arithmetic on a fixture, not a manual mapping implementation. Imports can be delayed; export forwarding and API sets mean a DLL name does not necessarily identify the final code module. Resources and timestamps are untrusted metadata. An Authenticode trust decision needs the platform verification API and a trust policy; checking `MZ`, a checksum, or the certificate-directory presence is insufficient.

## Gotchas

- Directory contents need not begin at a section boundary or reside in a section with a conventional name.
- A zero directory means absent in this fixture; malformed partial zero pairs should be rejected under its strict policy.
- Raw section padding can exceed VirtualSize. A general parser must distinguish format rules from its chosen subset.
- PE documentation is not a complete promise of loader acceptance on every Windows version. Do not execute a file to answer a static format question.

## Labs

### Environment and Complete Files

> [!warning] Validation status
> No Python runtime or VM was executed during authoring. All output is expected, not observed. This bounded fixture is deliberately non-executable and is not certified loadable by Windows. Full PE parser compatibility and trust verification remain outside the lab.

Create an empty directory in PowerShell, then place the complete source below in `pe-fixture.py`. It constructs all data in memory and writes no PE file. Python's standard `struct` module is the only parser dependency.

```powershell
New-Item -ItemType Directory x1-pe
Set-Location x1-pe
py -3 --version
```

### File: pe-fixture.py

```python
import struct

data = bytearray(0x600)
def put(offset, fmt, *values):
	struct.pack_into("<" + fmt, data, offset, *values)

data[:2] = b"MZ"
put(0x3C, "I", 0x80)
data[0x80:0x84] = b"PE\0\0"
put(0x84, "HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)
optional = 0x98
put(optional, "H", 0x20B)
put(optional + 24, "Q", 0x140000000)
put(optional + 32, "II", 0x1000, 0x200)
put(optional + 56, "II", 0x2000, 0x200)
put(optional + 68, "H", 3)
put(optional + 108, "I", 16)
for index, address, length in [(0, 0x1000, 0x80), (1, 0x1080, 40),
							   (2, 0x1140, 0x90), (5, 0x1100, 12)]:
	put(optional + 112 + index * 8, "II", address, length)
section = optional + 240
data[section:section + 8] = b".fixture"
put(section + 8, "IIII", 0x400, 0x1000, 0x400, 0x200)
put(section + 36, "I", 0x40000040)
put(0x200, "IIHHIIIIIII", 0, 0, 0, 0, 0x1050, 1, 1, 1,
	0x1028, 0x102C, 0x1030)
put(0x228, "IIH", 0x1300, 0x1040, 0)
data[0x240:0x249] = b"LabValue\0"
data[0x250:0x25C] = b"fixture.dll\0"
put(0x280, "IIIII", 0x10B0, 0, 0, 0x10D0, 0x10C0)
put(0x2B0, "QQ", 0x10E0, 0)
put(0x2C0, "QQ", 0x10E0, 0)
data[0x2D0:0x2DD] = b"kernel32.dll\0"
put(0x2E0, "H", 0)
data[0x2E2:0x2EF] = b"GetTickCount\0"
put(0x300, "IIHH", 0x1000, 12, 0xA300, 0)
put(0x500, "Q", 0x140001234)
for relative, identifier, child in [(0, 10, 0x80000018),
									 (24, 1, 0x80000030), (48, 1033, 72)]:
	put(0x340 + relative, "IIHHHH", 0, 0, 0, 0, 0, 1)
	put(0x350 + relative, "II", identifier, child)
put(0x388, "IIII", 0x11A0, 4, 0, 0)
data[0x3A0:0x3A4] = b"LAB!"
blob = bytes(data)

def span(offset, length):
	if offset < 0 or length < 0 or offset > len(blob) or length > len(blob) - offset:
		raise ValueError("file range")
	return blob[offset:offset + length]

def read(offset, fmt):
	return struct.unpack("<" + fmt, span(offset, struct.calcsize("<" + fmt)))

if span(0, 2) != b"MZ":
	raise ValueError("DOS signature")
pe, = read(0x3C, "I")
if span(pe, 4) != b"PE\0\0":
	raise ValueError("PE signature")
machine, count = read(pe + 4, "HH")
optional_size, = read(pe + 20, "H")
optional = pe + 24
if (machine, count, optional_size) != (0x8664, 1, 240):
	raise ValueError("outside fixture subset")
span(optional, optional_size)
if read(optional, "H")[0] != 0x20B:
	raise ValueError("not PE32+")
section = optional + optional_size
span(section, 40)
virtual_size, section_rva, raw_size, raw_offset = read(section + 8, "IIII")
header_size, = read(optional + 60, "I")
directory_count, = read(optional + 108, "I")
if directory_count > (optional_size - 112) // 8:
	raise ValueError("directory count")

def rva(address, length):
	if length <= 0:
		raise ValueError("empty requested span")
	if 0 <= address < header_size and length <= header_size - address:
		span(address, length)
		return address
	delta = address - section_rva
	if delta < 0 or delta > min(raw_size, virtual_size):
		raise ValueError("RVA")
	if length > min(raw_size, virtual_size) - delta:
		raise ValueError("no raw bytes")
	span(raw_offset + delta, length)
	return raw_offset + delta

def ascii_name(address):
	output = bytearray()
	for step in range(128):
		value = span(rva(address + step, 1), 1)[0]
		if value == 0:
			return output.decode("ascii")
		output.append(value)
	raise ValueError("unterminated name")

print(f"RVA 0x1180 -> file {rva(0x1180, 4):#x}")
descriptor = read(rva(0x1080, 20), "IIIII")
thunk, = read(rva(descriptor[0], 8), "Q")
print("import", ascii_name(descriptor[3]), ascii_name(thunk + 2))
export_name_rva, = read(rva(0x102C, 4), "I")
ordinal_index, = read(rva(0x1030, 2), "H")
target, = read(rva(0x1028 + ordinal_index * 4, 4), "I")
print("export", ascii_name(export_name_rva), "ordinal", 1 + ordinal_index,
	  f"data RVA={target:#x}")
page_rva, block_size, entry, padding = read(rva(0x1100, 12), "IIHH")
if block_size != 12 or entry >> 12 != 10 or padding != 0:
	raise ValueError("relocation fixture")
value, = read(rva(page_rva + (entry & 0xFFF), 8), "Q")
print(f"relocated scalar={value + 0x100000:#x}")
resource_rva, resource_size = read(rva(0x1140 + 72, 16), "II")
print("resource", span(rva(resource_rva, resource_size), resource_size))
if rva(0x1180, 4) != 0x380 or value + 0x100000 != 0x140101234:
	raise ValueError("acceptance")
print("PASS fixture coordinates")
```

### Objectives and Steps

1. Compute the section table offset (`0x188`) and `0x1180` conversion before running.
2. Identify why the import thunk points to a two-byte hint followed by a string.
3. Decode the three resource directory entries by hand; distinguish root-relative offsets from the leaf data RVA.

```powershell
py -3 pe-fixture.py
if ($LASTEXITCODE -ne 0) { throw 'Fixture check failed' }
```

### Hints

The synthetic export denotes **data**, not executable code. The resource tree uses root offsets 0, 24 and 48; its data entry is at root +72. The relocation block's `0xA300` denotes type 10 at page offset `0x300`.

### Solution and Expected Results

Expect file offset `0x380`, import `kernel32.dll GetTickCount`, export `LabValue ordinal 1 data RVA=0x1300`, relocated scalar `0x140101234`, resource `b'LAB!'`, then `PASS fixture coordinates`. Header + optional-header arithmetic yields `0x80 + 24 + 240 = 0x188`. Resource traversal is type 10, name 1, language 1033, then leaf RVA `0x11a0` maps to `0x3a0`. The program deliberately inspects known directory records, not arbitrary images; a production parser requires broader structure validation.

### Verification, Troubleshooting, and Cleanup

- [ ] Reproduce each printed value with hand arithmetic.
- [ ] Explain which fields use raw offsets, RVAs, root-relative offsets and VAs.
- [ ] Record Python version and actual output; no image-load conclusion is warranted.

No output file or cache is required. If Python is missing, the prerequisite is unmet; do not execute the fixture through Windows to compensate. A `ValueError` or `struct.error` is a failed check, not a pass. Cleanup from this lab directory:

```powershell
Remove-Item -LiteralPath .\pe-fixture.py
Set-Location ..
Remove-Item -LiteralPath .\x1-pe
```

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[PE Format Security]]

## References

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
