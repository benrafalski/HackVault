---
title: "File Upload Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# File Upload Attacks

> [!abstract] TL;DR
> An upload crosses several boundaries: filename, stored bytes, processing pipeline, and later serving context. Safety must hold at each stage.

> [!info] Agent scope
> Content and extension validation; storage and serving boundaries; parser risks; filenames; isolated processing; execution prevention.

## Learn

```text
Teach upload security across admission, storage, processing, publication, and
download authorization. Assume HTTP multipart handling, files, MIME types, and
browser origins. Explain extension and claimed MIME versus actual parsing,
filename authority, parser vulnerabilities, active formats, archive expansion,
size/count quotas, quarantine, asynchronous publication, and storage identities.
Review a secure narrow text import with generated names and attachment headers.
Explain why magic bytes, antivirus, successful decoding, and attachment alone
are incomplete; cover format-specific re-encoding and isolated processors.
Provide synthetic safe-file regressions, evidence criteria, primary sources,
and review questions. No executable uploads, parser exploit files, bypasses,
shells, RCE, theft, scanning, or chains. Teach rather than edit files; no invented
validation results or claims that one parser makes all formats safe.
```

## Cheatsheet

> [!important] Defensive scope
> The exercise stores only bounded UTF-8 text with a narrow character contract. It does not host uploads, run processors, or demonstrate execution.

### Boundary Map

| Stage | Authority at risk | Required control |
|---|---|---|
| Admission | Memory/disk and parser work | Streaming byte limits, count/rate quotas, authentication and CSRF as applicable |
| Classification | Content interpreted as trusted format | Closed format list, maintained parser, semantic validation |
| Storage | Filename/path and object ownership | Generated names, nonpublic quarantine, least-privilege storage identity |
| Processing | Decoder/transcoder capabilities | Isolated worker, CPU/memory/time/output limits, patched libraries |
| Publication | Trust state and race ordering | Publish only validated outputs; bind validation to exact bytes/digest |
| Serving | Browser context and access | Authorization, fixed MIME, attachment where appropriate, separate origin |

The original filename and multipart Content-Type are claims, not evidence. A valid extension with invalid content must fail, but valid content is not necessarily safe to render inline. Active formats and documents can contain behavior beyond their visible appearance. A parser accepting a file establishes syntax acceptance under that parser/version, not benign semantics. Image re-encoding can reduce unsupported features but introduces a decoder attack surface and may lose metadata or fidelity.

Store uploaded bytes outside application code and static execution mappings. An object-storage bucket is not safe merely because it does not execute server scripts: public access, browser rendering, and signed-URL authorization remain relevant. Generated object keys prevent filename control, not cross-user access. Signed URLs are bearer capabilities with a lifetime, not a substitute for checking ownership before issuing them.

### Worked Serving Contract

For a validated text export:

```http
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="report.txt"
X-Content-Type-Options: nosniff
Cache-Control: private, no-store
```

Use the framework's Content-Disposition builder for dynamic internationalized filenames; do not concatenate an upload name into a response header. `nosniff` has specific Fetch/browser semantics and is not a universal sandbox. Attachment behavior depends on the consumer; separating uploaded content onto a dedicated origin adds a distinct boundary. Antivirus can be a supplementary signal but may miss unknown or context-dependent behavior.

### Evidence and Versions

Record format/parser version, size, generated object ID, validation decision, processing job identity, publication state, and download authorization decision. Hashes can bind evidence to bytes; avoid logging file content. Serving an unusual extension does not establish server execution. Check framework multipart limits and reverse-proxy body limits in the exact deployed versions, including when buffering happens before application validation. Python 3.12 is the fixture runtime, not a general media processing stack.

## Defense

Minimize formats and transformations. Keep incoming files quarantined, verify exact bytes before promotion, and publish generated outputs under restricted identities. Authorize every retrieval and deletion. Bound compressed and expanded sizes separately for archives. Prevent the processing worker from contacting unrelated networks or reading application secrets. Retain safe failures and clear rejection reasons without leaking parser internals.

## Labs

### Environment and Objectives

Python 3.12 standard library only. One file, temporary storage, no services or upload requests. Review a proposal that stores the original name and trusts the claimed MIME. The secure replacement supports only a small text-report format, generates a storage key, and returns fixed serving metadata. All bytes are synthetic.

### File: test_example.py

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4
import unittest


def store_report(root, original_name, claimed_type, content):
	if type(original_name) is not str or not original_name.endswith(".txt"):
		raise ValueError("text extension required")
	if claimed_type != "text/plain":
		raise ValueError("unsupported media claim")
	if type(content) is not bytes or not 1 <= len(content) <= 1024:
		raise ValueError("size")
	text = content.decode("utf-8", errors="strict")
	if any(not (character.isprintable() or character in "\r\n\t") for character in text):
		raise ValueError("text contract")
	object_id = uuid4().hex
	target = Path(root) / (object_id + ".txt")
	with target.open("xb") as output:
		output.write(text.encode("utf-8"))
	headers = {
		"Content-Type": "text/plain; charset=utf-8",
		"Content-Disposition": 'attachment; filename="report.txt"',
		"X-Content-Type-Options": "nosniff",
		"Cache-Control": "private, no-store",
	}
	return object_id, headers


class UploadTests(unittest.TestCase):
	def test_safe_storage_and_serving_metadata(self):
		with TemporaryDirectory() as directory:
			object_id, headers = store_report(directory, "November.txt", "text/plain",
											  b"Synthetic report\nTotal: 7\n")
			target = Path(directory) / (object_id + ".txt")
			self.assertEqual(target.read_bytes(), b"Synthetic report\nTotal: 7\n")
			self.assertFalse((Path(directory) / "November.txt").exists())
			self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
			self.assertTrue(headers["Content-Disposition"].startswith("attachment;"))

	def test_reject_before_write(self):
		cases = [("report.bin", "text/plain", b"Report"),
				 ("report.txt", "image/png", b"Report"),
				 ("report.txt", "text/plain", b"\x00"),
				 ("report.txt", "text/plain", b"\xff"),
				 ("report.txt", "text/plain", b"A" * 1025)]
		with TemporaryDirectory() as directory:
			for name, media, content in cases:
				with self.subTest(name=name, media=media), self.assertRaises(ValueError):
					store_report(directory, name, media, content)
			self.assertEqual(list(Path(directory).iterdir()), [])

	def test_names_are_unique(self):
		with TemporaryDirectory() as directory:
			first, _ = store_report(directory, "report.txt", "text/plain", b"One")
			second, _ = store_report(directory, "report.txt", "text/plain", b"Two")
			self.assertNotEqual(first, second)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: verify that no client-selected name appears in the destination or headers. Which checks happen before the first write? Why does a valid `.txt` suffix not prove valid UTF-8?

Solution: content is bounded and decoded before writing; keys and download names are server-generated/fixed. Expected: three tests pass, rejection creates no files, duplicate original names produce distinct keys, and all stored bytes match the validated report. This does not implement multipart streaming, object authorization, antivirus, media parsing, or browser serving. The text contract intentionally does not cover CSV/spreadsheet formulas or rich documents.

### Verification, Troubleshooting, and Cleanup

No tests were run during authoring. Run beside the named file; no dependency install is needed. A `UnicodeDecodeError` is a `ValueError` and is expected for invalid UTF-8 in the rejection test. Temporary directories clean themselves on completion; remove the disposable exercise directory afterward. Production disk-full and interrupted-write handling need staging/rollback beyond this small fixture.

- [ ] Local File Upload Attacks exercise: Review admission, storage, and serving boundaries.
- [ ] Boundary check: Run secure content, no-write-on-rejection, and generated-name tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [RFC 6266: Content-Disposition](https://www.rfc-editor.org/rfc/rfc6266)
- [Fetch Standard: X-Content-Type-Options](https://fetch.spec.whatwg.org/#x-content-type-options-header)
- [Python pathlib file operations](https://docs.python.org/3.12/library/pathlib.html)
