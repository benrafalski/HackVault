---
title: "PE Format Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[PE Format]]"
updated: 2026-11-03
---
# PE Format Security

> [!abstract] TL;DR
> Malformed PE parsing, unsafe analysis tooling, or misplaced trust in metadata can cause analyzer defects or misclassification.

> [!info] Agent scope
> Security of: Headers; sections; imports and exports; relocations; resources; data directories; loader-facing validation. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Every count, length, offset, RVA, string and recursive directory edge is untrusted input to an analyzer.
- Parseability, Windows loadability, verified signing identity and acceptable behavior are different judgments. A parser must not execute a file to inspect it.

## Learn

```text
Teach defensive PE parsing at expert depth. Assume little-endian binary parsing
and basic PE headers. Walk through length-before-read, checked subtraction instead
of overflowing addition, optional-header bounds and directory counts, section
overlaps, RVA-to-raw mapping, virtual zero tails, bounded import/export names,
forwarders, relocation block progress, and resource cycle/depth budgets. Explain
certificate file offsets, architecture-specific metadata and version limitations.
Use only self-authored non-executable byte fixtures. Demonstrate a weak signature-
only validator accepting malformed lengths, a strict bounded fix rejecting them,
and retained acceptance of the valid fixture. Include all code, mutations, expected
results and cleanup. No malicious samples, image execution, loader manipulation,
exploit primitives or bypasses. Use primary Microsoft docs and distinguish safe
parsing from signature policy and loader equivalence. Teach here, not file authoring.
```

## Cheatsheet

### Validate Before Following

For a span `[offset, offset + length)` in a buffer of `size`, first prove `offset <= size`, then `length <= size - offset`. In fixed-width arithmetic, `offset + length <= size` alone can wrap. For a table, prove `count <= remaining / elementSize` before multiplying. Impose file-size, section-count, string-length, traversal-depth and total-work budgets even in languages with arbitrary-precision integers.

| Boundary | Required checks / common mistake |
| --- | --- |
| DOS and PE signature | Check all 64 DOS bytes needed for `e_lfanew`, then full PE/COFF range. Finding `MZ` is not validation |
| Optional header | Select PE32/PE32+ by magic, validate minimum size, then bound NumberOfRvaAndSizes by declared optional size. Never use host `sizeof(IMAGE_NT_HEADERS)` on an unknown format |
| Section table | Check count and `40 * count`; reject raw and virtual overlaps under a documented strict policy. Names do not authorize execution or establish type |
| RVA | Validate the entire requested extent, not only its first byte. Distinguish header bytes, raw-backed data and zero-filled virtual tail. Reject ambiguous mapping |
| Imports | Bound descriptor and thunk loops; require terminators within budgets; bound hint/name strings separately; never dereference IAT data as host pointers |
| Exports | Validate three table lengths independently; ordinal table values are indexes, not public ordinals; check forwarder strings within export directory bounds |
| Relocations | Require block >= 8, even payload and bounded forward progress. Decode type by machine; do not write to mapped executable memory to validate a record |
| Resources | Track visited root-relative offsets, depth and entry budget; validate leaf RVA separately. A length-prefixed UTF-16 resource name is not a C string |
| Certificates / TLS | Certificate directory uses a file offset; some TLS fields use VAs. One universal RVA conversion function is wrong for these fields |

The complete lab below fixes a permissive validator without ever issuing an out-of-bounds memory access. Its weak mode recognizes signatures but ignores header extents; its fixed mode checks a deliberately narrow AMD64/PE32+ subset. An unsupported format is not automatically malicious. Report rejection reason and scope rather than claiming Windows would reject the same file.

### Trust, Lifetimes, and Race Boundaries

Read a bounded immutable byte buffer and parse that buffer throughout. Reopening a pathname between hash, parse and action creates a replacement race; a stable file handle and protected deployment are separate requirements. A read-only mapping prevents writes through that view, not all other writers or file truncation hazards. Untrusted file parsing does not require elevation, debug privileges or executable mapping.

Prefer maintained tooling for general PE analysis; educational parsers are not drop-in security scanners. Separate parser failures from operating-system I/O errors, policy blocks and signature failures. `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` returns a `LONG` for which **zero only** means success; it is not an HRESULT to pass to `SUCCEEDED`. Trust chain, revocation mode, timestamp and catalog policy influence the decision. Merely containing certificates proves nothing. Do not weaken trust policy to obtain a favorable result.

Analyze import names, resources and timestamps as data, not commands or HTML. Escape them in reports and cap output length. Inspection must not call `LoadLibrary` on an unknown image: normal DLL loading can run initialization. This page's fixtures contain no instructions and never reach a loader.

## Detection and Defense

Record parser version, input hash when applicable, declared machine/magic, validation subset, rejected offset/count and maximum budget reached. Treat crashes or hangs as analyzer defects. Rejection counts may flag malformed inputs but also unsupported legitimate formats. Defense is a bounded parser plus limited analysis privileges and regression fixtures; a filename extension, a signature prefix or a section label is not an authorization decision.

## Labs

### Environment and Complete Files

Already installed CPython 3.12+ and PowerShell 5.1+ or 7, standard user. Only `pe-bounds.py` is needed. It constructs synthetic data in memory; no other page, package, PE sample or project file is required.

> [!warning] Unverified execution
> No Python run, VM run, fuzzing campaign or Windows-loader comparison was performed in this authoring session. Results are predictions. The parser accepts only the educational subset stated in code, not all valid PE files.

```powershell
New-Item -ItemType Directory x1-pe-bounds
Set-Location x1-pe-bounds
py -3 --version
```

### File: pe-bounds.py

```python
import struct

def fixture():
	blob = bytearray(0x400)
	blob[:2] = b"MZ"
	struct.pack_into("<I", blob, 0x3C, 0x80)
	blob[0x80:0x84] = b"PE\0\0"
	struct.pack_into("<HHIIIHH", blob, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
	struct.pack_into("<H", blob, 0x98, 0x20B)
	struct.pack_into("<II", blob, 0x98 + 32, 0x1000, 0x200)
	struct.pack_into("<II", blob, 0x98 + 56, 0x2000, 0x200)
	struct.pack_into("<I", blob, 0x98 + 108, 16)
	blob[0x188:0x190] = b".data\0\0\0"
	struct.pack_into("<IIII", blob, 0x190, 0x300, 0x1000, 0x200, 0x200)
	struct.pack_into("<I", blob, 0x188 + 36, 0x40000040)
	blob[0x200:0x204] = b"LAB!"
	return blob

def weak(blob):
	return blob[:2] == b"MZ" and blob[0x80:0x84] == b"PE\0\0"

def validate(blob):
	if len(blob) > 1024 * 1024:
		raise ValueError("budget")
	def span(offset, length):
		if offset < 0 or length < 0 or offset > len(blob) or length > len(blob) - offset:
			raise ValueError("file range")
		return blob[offset:offset + length]
	def read(offset, fmt):
		return struct.unpack("<" + fmt, span(offset, struct.calcsize("<" + fmt)))
	span(0, 64)
	pe, = read(0x3C, "i")
	if pe < 64 or span(0, 2) != b"MZ" or span(pe, 4) != b"PE\0\0":
		raise ValueError("signature/offset")
	span(pe + 4, 20)
	machine, count = read(pe + 4, "HH")
	optional_size, = read(pe + 20, "H")
	optional = pe + 24
	if machine != 0x8664 or not 1 <= count <= 96 or optional_size < 112:
		raise ValueError("unsupported header")
	span(optional, optional_size)
	if read(optional, "H")[0] != 0x20B:
		raise ValueError("unsupported magic")
	directories, = read(optional + 108, "I")
	if directories > 16 or directories > (optional_size - 112) // 8:
		raise ValueError("directory extent")
	for index in range(directories):
		if read(optional + 112 + index * 8, "II") != (0, 0):
			raise ValueError("nonempty directories outside this fixture subset")
	alignment, file_alignment = read(optional + 32, "II")
	image_size, headers = read(optional + 56, "II")
	if (alignment, file_alignment) != (0x1000, 0x200):
		raise ValueError("alignment subset")
	table = optional + optional_size
	span(table, count * 40)
	if headers < table + count * 40 or headers % file_alignment or headers > len(blob):
		raise ValueError("headers extent")
	if image_size == 0 or image_size % alignment:
		raise ValueError("image alignment")
	sections = []
	for index in range(count):
		virtual, address, raw, offset = read(table + index * 40 + 8, "IIII")
		if not virtual or not raw or address < alignment or address % alignment:
			raise ValueError("section subset")
		if offset < headers or offset % file_alignment or raw % file_alignment:
			raise ValueError("raw alignment")
		if address > image_size or max(virtual, raw) > image_size - address:
			raise ValueError("image extent")
		span(offset, raw)
		for prior_address, prior_virtual, prior_offset, prior_raw in sections:
			if address < prior_address + max(prior_virtual, prior_raw) and prior_address < address + max(virtual, raw):
				raise ValueError("virtual overlap")
			if offset < prior_offset + prior_raw and prior_offset < offset + raw:
				raise ValueError("raw overlap")
		sections.append((address, virtual, offset, raw))
	def map_rva(address, length):
		if address < 0 or length <= 0:
			raise ValueError("request")
		if address < headers and length <= headers - address:
			return span(address, length)
		for start, virtual, offset, raw in sections:
			delta = address - start
			if 0 <= delta < max(virtual, raw):
				if delta >= raw or length > raw - delta:
					raise ValueError("virtual-only tail")
				return span(offset + delta, length)
		raise ValueError("unmapped RVA")
	return map_rva

good = fixture()
cases = {"valid": good, "truncated": good[:0x210]}
for name, offset, fmt, value in [
	("short-optional", 0x94, "H", 8),
	("excess-directories", 0x98 + 108, "I", 17),
	("raw-beyond-file", 0x188 + 20, "I", 0x800),
	("negative-pe", 0x3C, "i", -1),
]:
	changed = bytearray(good)
	struct.pack_into("<" + fmt, changed, offset, value)
	cases[name] = changed
for name, blob in cases.items():
	try:
		mapper = validate(bytes(blob))
		accepted = mapper(0x1000, 4) == b"LAB!"
	except ValueError:
		accepted = False
	print(name, "weak=", weak(blob), "fixed=", accepted)
	if accepted != (name == "valid") or not weak(blob):
		raise RuntimeError("regression mismatch")
mapper = validate(bytes(good))
for address, length in [(0x1200, 1), (0x11FF, 2), (0xFFFFFFFF, 4)]:
	try:
		mapper(address, length)
	except ValueError:
		print(f"rejected span {address:#x}+{length}")
	else:
		raise RuntimeError("invalid span accepted")
print("PASS valid retained; malformed headers and spans rejected")
```

### Objectives and Baseline

1. Explain why all six files satisfy the weak check even though five violate the fixed subset.
2. Run the exact regression cases and identify the first invalid boundary in each.
3. Explain why `0x1200` lies inside VirtualSize but has no raw byte.

```powershell
py -3 pe-bounds.py
if ($LASTEXITCODE -ne 0) { throw 'Regression failed' }
```

### Hints

The weak function intentionally does not follow `e_lfanew`. It is a safe demonstration of false acceptance, not unsafe pointer code. The valid section has virtual size `0x300` and raw size `0x200`.

### Solution and Fixed Retest

Only `valid` should show `fixed=True`; every case shows `weak=True`. Truncation invalidates the raw extent; optional size 8 cannot hold required fields; 17 directories exceed the optional header; offset `0x800` is outside the buffer; negative `e_lfanew` fails before a read. Spans `0x1200+1`, `0x11ff+2` and `0xffffffff+4` are rejected. The valid marker remains readable. The final PASS line and exit zero are acceptance criteria, not author-run evidence.

### Verification, Troubleshooting, and Cleanup

- [ ] Record all six verdicts and three rejected spans.
- [ ] Explain how fixed-width C arithmetic would need additional overflow prevention.
- [ ] State the supported subset and avoid claiming full PE compatibility.

Unexpected `struct.error` means a range proof was missed or the fixture was transcribed incorrectly; do not catch all exceptions and count them as expected rejection. The script intentionally catches only explicit validation failures. It does not recursively parse arbitrary resources or verify signatures; those broader requirements remain untested.

```powershell
Remove-Item -LiteralPath .\pe-bounds.py
Set-Location ..
Remove-Item -LiteralPath .\x1-pe-bounds
```

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[PE Format]]

## References

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [WinVerifyTrust return contract](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
