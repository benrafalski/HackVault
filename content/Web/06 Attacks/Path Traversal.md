---
title: "Path Traversal"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Path Traversal

> [!abstract] TL;DR
> Path traversal lets a caller escape an intended resource root because path parsing, normalization, or filesystem resolution is not constrained correctly.

> [!info] Agent scope
> Path joining and normalization; decoding; absolute paths; symlinks; archive extraction; containment checks.

## Learn

```text
Teach path traversal as a mismatch between resource authorization and filesystem
resolution. Assume paths, HTTP decoding, files, and permissions. Trace URL decode,
normalization, joining, canonical resolution, open, and object authorization.
Explain absolute versus relative paths, separators, Windows drives/reparse points,
symlinks, archive members, and check/open races without traversal payloads.
Compare server-selected IDs, component-aware containment, descriptor-relative
opens, no-follow semantics, and OS-specific limitations. Review safe resource
mapping and explicit ZIP-member selection with ordinary synthetic files. Explain
what lexical checks cannot establish, extraction resource limits, and Python 3.12
tar-filter version differences. Include primary sources and questions/answers.
Defensive code review/hardening only: no outside-file retrieval, bypasses, theft,
RCE, scanning, or chains. Do not edit files or claim tests were executed.
```

## Cheatsheet

> [!important] Defensive scope
> Only authorized synthetic files are opened. No traversal strings, out-of-root reads, or unsafe archive extraction are demonstrated.

### Mechanisms and Preconditions

The caller influences a resource name, the application interprets it as a path, and the filesystem resolves it under the service identity. Escaping an intended namespace matters only when the resolved object is reachable with relevant permissions. Reads, writes, deletes, and extraction have different consequences. Authorization must bind actor, object, and operation, not merely a path prefix.

| Stage | Review question | Defense |
|---|---|---|
| Decode | Which layer decodes, and how often? | One documented decoding contract before validation |
| Join | Can a component replace the root? | Avoid user paths; reject unsupported path classes |
| Normalize | Are comparisons component-aware? | `Path.relative_to`/`is_relative_to`, not string prefixes |
| Resolve | Can links/reparse points change the target? | Resolve against trusted storage; restrict writers |
| Open | Can the target change after validation? | Handle/descriptor-based confinement where supported |
| Archive | Who chooses output paths and member types? | Explicit member mapping, no links, bounded expansion |

`Path.resolve()` accounts for symlinks present at resolution time, but a later open can see a different tree. Lexical normalization does not resolve links. Windows drive-relative paths, device namespaces, case rules, and reparse points are not interchangeable with POSIX semantics. Python `dir_fd`/`O_NOFOLLOW` support is platform-specific; a final-component no-follow flag alone does not secure every ancestor. Linux `openat2` resolution flags offer stronger kernel-enforced constraints, but are not a portable Python 3.12 API.

### Secure Design and Version Details

Prefer a resource table mapping opaque IDs to server-owned paths, with object authorization before open. Store uploads under generated names in directories callers cannot modify. The lab combines ID mapping and resolved containment; its directory is private and stable. It is not a race-safe solution for an attacker-writable tree.

Python 3.12 added tar extraction filters; explicitly request `filter="data"` where applicable rather than relying on a default. Python 3.14 changes the default to `data`. Even a data filter is not a complete untrusted-archive sandbox or decompression quota. For ZIP, selecting and reading a known member avoids choosing filesystem destinations from archive names. Bound compressed input, member count, and actual uncompressed bytes; do not rely only on declared sizes.

Evidence should identify the trusted root, resolved target classification, storage permissions, actual operation, and whether a link/race was possible. A rejected path or error is not proof of unauthorized file access. Log resource IDs and denial reasons rather than sensitive full paths.

## Defense

Reduce the interface to resource IDs. Keep filesystem privileges narrow and storage nonexecutable. Use secure OS-specific opening primitives for mutable untrusted trees, and validate archives before publication with generated output names. Do not attempt to secure a path language by deleting substrings. Test ordinary nested resources, unknown IDs, containment decisions, and archive allowlists independently.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no services/packages. All filesystem fixtures are created under `TemporaryDirectory`. Review a design that accepts download paths and extracts every archive member; explain why the supplied ID map and explicit member selection reduce authority. No malicious paths or archives are needed.

### File: test_example.py

```python
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import unittest


RESOURCES = {"guide": "docs/guide.txt"}


def read_resource(root, resource_id):
	if resource_id not in RESOURCES:
		raise PermissionError("unknown resource")
	base = Path(root).resolve(strict=True)
	target = (base / RESOURCES[resource_id]).resolve(strict=True)
	if not target.is_relative_to(base) or not target.is_file():
		raise PermissionError("storage containment")
	return target.read_text(encoding="utf-8")


def read_approved_archive(blob):
	if len(blob) > 4096:
		raise ValueError("compressed input limit")
	with ZipFile(BytesIO(blob)) as archive:
		members = archive.infolist()
		if len(members) != 1 or members[0].filename != "summary.txt":
			raise ValueError("archive contract")
		with archive.open(members[0]) as source:
			content = source.read(1025)
		if len(content) > 1024:
			raise ValueError("expanded size limit")
		return content.decode("utf-8")


def make_archive(name, text):
	output = BytesIO()
	with ZipFile(output, "w") as archive:
		archive.writestr(name, text)
	return output.getvalue()


class StorageTests(unittest.TestCase):
	def test_selected_file(self):
		with TemporaryDirectory() as directory:
			root = Path(directory)
			(root / "docs").mkdir()
			(root / "docs" / "guide.txt").write_text("Synthetic guide", encoding="utf-8")
			self.assertEqual(read_resource(root, "guide"), "Synthetic guide")
			with self.assertRaises(PermissionError):
				read_resource(root, "unlisted")

	def test_component_containment(self):
		base = Path("storage")
		self.assertTrue((base / "docs").is_relative_to(base))
		self.assertFalse(Path("storage-copy").is_relative_to(base))

	def test_archive_contract(self):
		self.assertEqual(read_approved_archive(make_archive("summary.txt", "Ready")),
						 "Ready")
		with self.assertRaises(ValueError):
			read_approved_archive(make_archive("notes.txt", "Unapproved member"))
		with self.assertRaises(ValueError):
			read_approved_archive(make_archive("summary.txt", "A" * 1025))


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: which function ever receives a caller-selected filesystem destination? Why is the sibling-name check separate from file opening? Why is the expanded-size limit checked after bounded reading?

Solution: a caller chooses only an approved ID; archive data is read, not extracted, and only from one named member. Expected: three tests pass, known content is returned, unlisted IDs/members fail, and oversized expanded content fails. The archive is synthetic and tiny; this is not a comprehensive ZIP parser sandbox. Symlink/reparse races and authorization integration are explicitly untested.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file. Filesystem permission errors indicate the temporary directory is unavailable; choose a standard writable temporary location, not elevated privileges. Context managers close archives and remove temporary files automatically. Remove the exercise directory afterward; no outside files are created or read.

- [ ] Local Path Traversal exercise: Review ID mapping, containment, and archive member selection.
- [ ] Boundary check: Run the secure file and bounded archive regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python pathlib](https://docs.python.org/3.12/library/pathlib.html)
- [Python tarfile extraction filters](https://docs.python.org/3.12/library/tarfile.html#extraction-filters)
- [Python zipfile](https://docs.python.org/3.12/library/zipfile.html)
- [Linux openat2](https://man7.org/linux/man-pages/man2/openat2.2.html)
