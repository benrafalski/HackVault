---
title: "NTFS and Alternate Data Streams Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[NTFS]]"
updated: 2026-11-03
---
# NTFS and Alternate Data Streams Security

> [!abstract] TL;DR
> Reparse/link races, permissive ACLs, alternate-stream blind spots, and path confusion can bypass intended file boundaries.

> [!info] Agent scope
> Security of: Files and metadata; ADS; reparse points; hard links; ACLs; sharing modes; path normalization; filesystem observations. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Untrusted names, mutable directories, alternate streams, shared hard-link identity, object/parent ACLs, sharing and stale path evidence.
- Every test below is confined to a fresh user-owned temporary directory. No reparse points, privileged writers, system paths, hiding workflows or security-control changes.

## Learn

```text
Teach defensive NTFS file-boundary design with real Windows semantics.
Assume handles, DACLs, streams and Unicode paths. Explain stream-blind hashing,
hard-link shared identity, parent delete/replace rights, share-delete behavior,
intermediate reparse traversal, file-ID reuse and check/open races. Contrast
lexical normalization with handle-bound object identity and controlled-directory
ownership. Explain why final-component OPEN_REPARSE_POINT is not a complete
tree-traversal defense and why changing an ACL may not revoke existing handles.
Use benign fixtures in a new own temporary directory: show unchanged unnamed
data hash after adding a known ADS, enumerate streams with documented APIs,
and test an allowlisted leaf-name policy plus exclusive creation. Supply all
code, checks, expected results and cleanup, preserving permitted ordinary files.
No privileged writer, system reparse manipulation, exploitation, persistence,
credential access, bypass or evasion workflows. Cover version/filesystem limits,
detection false positives and residual concurrency risk. Use primary sources,
answered questions, no note edits and no fabricated execution claims.
```

## Cheatsheet

### File Policy Must Specify the Object

| Policy goal | Insufficient check | Required evidence/design |
|---|---|---|
| Integrity of content | Hash only `file.txt` | Define whether ADS/security/metadata are in scope; enumerate/hash permitted streams and report unsupported enumeration. |
| Containment | `path.startswith(root)` | Component-aware lexical checks plus controlled directory ownership and handle-bound object checks; reject unexpected namespaces/stream syntax. |
| Stable target | Normalize, check ACL, reopen later | Operate through the validated handle; protect intermediate directories and account for rename/reparse races. |
| No replacement | File DACL only | Parent create/delete-child/rename authority and existing handles also matter. |
| Unique object | Unique pathname | Hard links can alias the same file; compare volume/file identity where required. |
| No final reparse traversal | `FILE_FLAG_OPEN_REPARSE_POINT` | Inspect tag/attributes; intermediate path traversal still needs a design. |

A legitimate `Zone.Identifier`, search-index metadata, or application stream is not proof of wrongdoing. The defect in a stream-blind audit is its overclaim: "unchanged file" when only the unnamed stream was measured. Document the measurement scope, enumerate actual streams with `FindFirstStreamW`/`FindNextStreamW`, and preserve their names and sizes. An audit that cannot enumerate must report incomplete coverage, not an empty set.

For a flat upload/output namespace, a strict leaf allowlist can reject separators, colons, rooted paths, dot components, reserved devices and trailing spaces/dots. This is intentionally narrower than legal NTFS naming. It is **not** a general sandbox for arbitrary nested paths. `CREATE_NEW`/exclusive creation prevents silently replacing an existing final name; it does not protect an attacker-controlled parent tree or prove absence of all link races.

Use `GetFileInformationByHandleEx(FileIdInfo/FileAttributeTagInfo)` for opened-object evidence. `GetFinalPathNameByHandleW` is useful for diagnostics, not a permanent authorization token. Request minimal access, restrict directory mutation, and retain the handle for the operation. File IDs require volume identity and can be reused after deletion. If an operation requires stronger concurrent containment than documented application APIs readily provide, redesign around preopened trusted objects or an isolated broker; do not advertise string filtering as complete protection.

Windows default case folding is not universal: case-sensitive directories, extended path syntax, DOS devices, UNC namespaces and long-path opt-in differ by API/platform. Local NTFS tests do not certify ReFS, FAT, SMB or cloud-filter behavior. Streams share the file's security descriptor; no separate ordinary ADS DACL repairs an overbroad base-file policy.

## Detection and Defense

Log resolved object identity, operation, stream name when relevant, access/share flags and Win32 status. Distinguish access denied (5) from sharing violation (32). Correlate changes with authorized application behavior and deployment activity; stream/reparse presence alone is noisy. USN/other filesystem telemetry is not a full content history or actor-attribution source. Preserve ACL evidence and collection gaps. Do not disable scanning or remove provenance metadata to make a test pass.

## Labs

### Environment and Complete Files

Windows 10/11, Python 3.11+ stdlib, local NTFS `%TEMP%`, standard user. One file, no compiler/packages. Tests generate all fixtures inside `TemporaryDirectory`; no input paths are accepted. The API wrapper enumerates actual NTFS stream names/sizes, not a generic model. Non-Windows is explicitly skipped and is **not** a passing Windows validation.

### File: test_example.py

```python
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import re
import tempfile
import unittest

def streams(path):
	kernel = ctypes.WinDLL("kernel32", use_last_error=True)
	class StreamData(ctypes.Structure):
		_fields_ = [("size", ctypes.c_longlong), ("name", wintypes.WCHAR * 296)]
	first = kernel.FindFirstStreamW
	first.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(StreamData), wintypes.DWORD]
	first.restype = wintypes.HANDLE
	next_stream = kernel.FindNextStreamW
	next_stream.argtypes = [wintypes.HANDLE, ctypes.POINTER(StreamData)]
	next_stream.restype = wintypes.BOOL
	close = kernel.FindClose
	close.argtypes = [wintypes.HANDLE]
	close.restype = wintypes.BOOL
	data = StreamData()
	handle = first(str(path), 0, ctypes.byref(data), 0)
	if handle == ctypes.c_void_p(-1).value:
		raise ctypes.WinError(ctypes.get_last_error())
	result = {}
	try:
		while True:
			result[data.name] = data.size
			if not next_stream(handle, ctypes.byref(data)):
				error = ctypes.get_last_error()
				if error != 38:
					raise ctypes.WinError(error)
				return result
	finally:
		close(handle)

def valid_leaf(name):
	if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\.txt", name):
		return False
	stem = name[:-4].upper()
	return stem not in {"CON", "PRN", "AUX", "NUL", *(f"COM{num}" for num in range(1, 10)),
						*(f"LPT{num}" for num in range(1, 10))}

@unittest.skipUnless(os.name == "nt", "requires Windows and local NTFS temp storage")
class NtfsReview(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory(prefix="HV-NTFS-review-")
		self.addCleanup(self.temp.cleanup)
		self.root = Path(self.temp.name)
		self.file = self.root / "marker.txt"
		self.file.write_bytes(b"BASE")

	def add_stream(self):
		with open(str(self.file) + ":note", "wb") as stream:
			stream.write(b"STREAM")

	def test_baseline_hash_is_stream_blind(self):
		before = hashlib.sha256(self.file.read_bytes()).digest()
		self.add_stream()
		self.assertEqual(hashlib.sha256(self.file.read_bytes()).digest(), before)
		self.assertIn(":note:$DATA", streams(self.file))

	def test_fixed_inventory_detects_change(self):
		before = streams(self.file)
		self.assertEqual(before, {"::$DATA": 4})
		self.add_stream()
		after = streams(self.file)
		self.assertEqual(after, {"::$DATA": 4, ":note:$DATA": 6})
		self.assertNotEqual(before, after)

	def test_leaf_policy_keeps_permitted_names(self):
		self.assertTrue(valid_leaf("report_01.txt"))
		for name in ("../out.txt", r"..\out.txt", "marker.txt:note", "CON.txt",
					 r"C:\out.txt", "report.txt ", "report.txt."):
			with self.subTest(name=name):
				self.assertFalse(valid_leaf(name))
		name = "report_01.txt"
		self.assertTrue(valid_leaf(name))
		with (self.root / name).open("xb") as output:
			output.write(b"OK")
		self.assertEqual((self.root / name).read_bytes(), b"OK")

	def test_exclusive_create_preserves_existing_file(self):
		with self.assertRaises(FileExistsError):
			with self.file.open("xb"):
				pass
		self.assertEqual(self.file.read_bytes(), b"BASE")

if __name__ == "__main__":
	unittest.main()
```

### Objectives, Baseline, and Hints

Run `python -m unittest -v test_example`. Predict why the first test succeeds despite the new stream: it deliberately proves the old audit's blind spot. The fixed inventory includes both `::$DATA` and `:note:$DATA`. Hint: file size and stream sizes measure different scopes. The last two tests reject ambiguous leaf syntax while permitting an ordinary file and preventing overwrite.

### Solution and Fixed Retest

Expected four passing tests on Windows/NTFS, zero skips. Baseline unnamed bytes remain `BASE`; adding `note` changes the stream inventory from one entry to two. The correction is to report and enforce the intended stream set, not to label all ADS suspicious. These inventory tests check names/sizes, not cryptographic integrity of same-length stream changes; a full integrity policy must hash each included stream and address concurrent mutation.

### Verification, Troubleshooting, and Cleanup

Enumeration failure or unsupported streams means the filesystem prerequisite is unmet, not that no extra data exists. A mismatched stream set may indicate external software adding metadata; investigate rather than deleting unrelated metadata. All fixture directories auto-clean after handles close. Delete only the scratch test and local `__pycache__` afterward. No reparse or system paths are modified. Source reviewed, tests unexecuted; parent must run on Windows/NTFS and confirm four non-skipped tests. Cross-user effective access and adversarial concurrent containment are explicitly not tested.

- [ ] Local NTFS exercise: Observe actual stream-blind hashing and stream enumeration in own temporary paths.
- [ ] Boundary check: Detect the extra stream, preserve permitted leaf files, reject ambiguous names and prevent overwrite.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[NTFS]]

## References

- [File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw)
- [File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Naming files, paths and namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
