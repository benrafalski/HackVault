---
title: "Sysinternals"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Sysinternals

> [!abstract] TL;DR
> Define a question, choose the tool, narrow filters, reproduce once, preserve evidence, and verify cleanup. Avoid indiscriminate capture of unrelated application data.

> [!info] Agent scope
> Process Explorer; Process Monitor; Autoruns; access and handle inspection; signatures; Sysmon links; evidence capture.

## Prerequisites

- Windows 11 x64 disposable VM, Python 3.12, official Process Explorer, Process Monitor, Autoruns, Handle, AccessChk, and Sigcheck. The fixture uses only stdlib `winreg`, filesystem APIs, and unittest; it is Windows-only.
- Record each utility's own version and signature; Sysinternals is a suite of independently versioned tools. The current Process Monitor download page lists Windows 11+ clients and Server 2019+; an older Windows tutorial is not a compatibility guarantee.
- Place verified utilities in `C:\Tools\Sysinternals` for the printed commands. Accept license prompts interactively. Process Monitor normally needs an elevated launch/driver; Process Explorer/Handle may need elevation for visibility. Use only a disposable VM and retain platform protections. If blocked by policy, record the limitation rather than disable policy.
- Use a fresh temporary working directory for the supplied file. No Sysmon installation, boot logging, autostart creation, service configuration, or external upload is part of this exercise.

## Learn

```text
Teach me the Windows Sysinternals suite at expert observation and evidence depth.
Assume Windows processes, handles, registry, access masks, tokens, and basic
PowerShell. Establish OS compatibility and each utility's exact version, source,
signature, required elevation/driver, and privacy boundary. Compare Process
Explorer snapshots, Process Monitor event capture, Handle object references,
AccessChk permission interpretation, Autoruns inventory, and Sigcheck identity.
Explain PID reuse/start time, trees versus causal ancestry, handles versus paths,
module signature limits, desired/granted access, DACL versus live-token behavior,
Procmon filter OR/AND/exclude semantics, drop-filtered versus display filtering,
PML versus CSV, event stacks, and benign failure results such as NAME NOT FOUND.
Give real commands and a complete Python 3.12 stdlib Windows fixture that holds
a file and writes a unique non-autostart HKCU value. Capture its create/write/
close lifecycle, correlate identity and handles, and prove a second same-name
Python process is excluded by PID. Include expected events without promising
exact counts, four automated fixture checks, manual gates, hints, solution,
cleanup on normal exit and interrupted runs, and evidence retention limits.
Treat Autoruns read-only; explain why an unsigned file is not a malware verdict
and why online reputation checks/uploads require separate consent. Link Sysmon
conceptually as persistent telemetry, without installing or configuring it.
Use official Microsoft references. No unrelated process capture, credentials,
malware, handle-closing tricks, persistence, or protection bypass. Teach here,
not by editing files or study status.
```

## Cheatsheet

### Choose the Evidence Source

| Question | Tool/workflow | What it cannot establish alone |
|---|---|---|
| Which image/token/parent is this process using now? | Process Explorer -> Properties -> Image, Security; show PID, start time, image path, user | Parent relationships are not an execution history; PID can be reused. Command lines can contain secrets. |
| Which open object explains this resource? | Process Explorer lower pane -> Handles; Find -> Find Handle or DLL; Handle CLI | A named handle is a reference, not proof of a later read/write. Object names may be native device paths. |
| Which operation happened and with what result? | Process Monitor -> event Properties -> Event/Process/Stack | Uncaptured or filtered-out events are unknown, not absent. File/registry activity does not prove malicious intent. |
| Which principals have rights? | AccessChk against one lab file/key | DACL-derived account access is not a complete simulation of a live restricted/impersonating token, mandatory integrity, sharing, or remote policy. |
| What is configured to start? | Autoruns read-only tabs and saved snapshot | Inventory differs from executed activity; unchecked entries are not proof no prior execution occurred. |
| Which file is this? | Sigcheck version/hash/signature; hash comparison | A valid signature authenticates signing provenance under a trust policy, not benignness or vulnerability status. |
| What historical telemetry exists? | [[Sysmon]] and authorized event logs | Sysmon is separately installed persistent telemetry, not enabled by launching Process Explorer. |

### Process Monitor Capture Discipline

1. Launch only in the lab VM, immediately stop capture (Ctrl+E), and clear initial events (Ctrl+X). Record whether boot logging or backing files were previously enabled; do not enable boot logging here.
2. Set `PID is <fixture PID> Include`, after the fixture prints its PID and before releasing its start prompt. Filters on the same field generally OR; different fields generally AND; an exclusion can remove an otherwise included event. Check active filters rather than relying on remembered defaults.
3. Use Drop Filtered Events for this tightly scoped run to avoid retaining unrelated events, understanding that excluded events cannot be recovered later. With ordinary nondestructive filtering, hidden rows may still exist in the backing PML and exports.
4. Capture, release the fixture, observe the hold interval, release closure, then stop capture. Select only lab events when saving. Keep native PML for detailed properties/stacks and a filtered CSV/text summary for review; CSV is not a lossless PML substitute.
5. Correlate PID **and start time/image path**. Optionally add an operation filter after capture to focus on `CreateFile`, `WriteFile`, `RegCreateKey`, `RegSetValue`, and close operations. Do not demand identical counts across Python/Windows/tool builds.

`NAME NOT FOUND` can be a normal probe; `BUFFER OVERFLOW` in a metadata query often means a caller should retry with a larger buffer; `ACCESS DENIED` needs desired access and identity context. Procmon's `CreateFile` includes opens of existing files. Successful `WriteFile` does not alone prove durable storage; the fixture flushes its Python stream but does not promise power-loss durability. Stack addresses require matching symbols; keep debugger commands in [[WinDbg]].

### Scoped CLI Reference

PowerShell commands for the learner after the fixture prints its PID/path:

```powershell
$targetPid = [int](Read-Host 'Fixture PID')
$markerPath = Read-Host 'Full marker.txt path printed by fixture'
& C:\Tools\Sysinternals\handle64.exe -p $targetPid marker.txt
& C:\Tools\Sysinternals\accesschk64.exe -v "$env:USERDOMAIN\$env:USERNAME" $markerPath
& C:\Tools\Sysinternals\sigcheck64.exe -nobanner -a -h C:\Tools\Sysinternals\procexp64.exe
Get-FileHash C:\Tools\Sysinternals\procexp64.exe -Algorithm SHA256
```

Handle command is read-only: do not add `-c` to close another process's handle. AccessChk's default object type is filesystem; `-k` selects a registry key and `-p` selects a process. Do not add broad recursive/system-wide searches. `-v` requests detail, not write access. Confirm switches using the exact installed tool's help.

Sigcheck's `-h` prints hashes; it is not a reputation submission. Avoid VirusTotal-related options and disable reputation integration in the GUIs. Ordinary signature validation can still retrieve certificate/revocation data depending on policy; record online/offline verification status. A revoked, unavailable, catalog-signed, or unsigned result needs interpretation, not a binary good/bad label.

### Autoruns and Evidence Handling

Open Autoruns, leave all checkboxes and context-menu actions unchanged, and review Logon, Services, Scheduled Tasks, and other categories. Search for the fixture's unique key prefix/path only. It writes under a non-autostart HKCU key, so no new autostart entry is expected. Hiding Microsoft/Windows entries is a display filter, not evidence that excluded entries cannot matter. An Autoruns snapshot may expose installed software and account paths; do not publish it from a real workstation.

An evidence record needs UTC time, tool version, PID/start time, synthetic key/path, operation/result, relevant detail fields, handle lifetime, and capture/filter settings. Avoid dumps and unrelated command lines. Preserve original PML/hash locally; redact a derived summary rather than editing the original evidence invisibly.

## Gotchas

- Python launcher PID is not necessarily the interpreter PID. Use `os.getpid()` from the fixture, not the terminal host or `py.exe`.
- A closed file may still exist; an existing file does not imply an open handle. Refresh Process Explorer after closure and distinguish file deletion from handle release.
- A kernel driver can be blocked even in an elevated process. Record visibility limits; do not weaken HVCI or other controls.

## Labs

### Environment and Complete File

This program creates one unique temporary directory and one unique HKCU key, holds real file/registry handles, and removes both on normal exit. The registry value is ordinary data, not an autostart. The tests use fresh resources per case.

### File: test_example.py

```python
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import winreg


@contextmanager
def resources():
	key_path = "Software\\HackVaultToolLab-" + uuid.uuid4().hex
	created = False
	with tempfile.TemporaryDirectory(prefix="hv-sysinternals-") as directory:
		marker = Path(directory) / "marker.txt"
		try:
			with marker.open("w+", encoding="utf-8") as stream:
				with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
										winreg.KEY_READ | winreg.KEY_WRITE) as key:
					created = True
					winreg.SetValueEx(key, "Marker", 0, winreg.REG_SZ, "synthetic-only")
					stream.write("synthetic-only\n")
					stream.flush()
					yield marker, stream, key_path, key
		finally:
			if created:
				winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)


class ExampleTests(unittest.TestCase):
	def test_file_content(self):
		with resources() as (marker, stream, key_path, key):
			self.assertFalse(stream.closed)
			stream.seek(0)
			self.assertEqual(stream.read(), "synthetic-only\n")

	def test_registry_value(self):
		with resources() as (marker, stream, key_path, key):
			self.assertEqual(winreg.QueryValueEx(key, "Marker"),
							 ("synthetic-only", winreg.REG_SZ))

	def test_file_cleanup(self):
		with resources() as (marker, stream, key_path, key):
			self.assertTrue(marker.exists())
		self.assertTrue(stream.closed)
		self.assertFalse(marker.parent.exists())

	def test_registry_cleanup(self):
		with resources() as (marker, stream, key_path, key):
			pass
		with self.assertRaises(FileNotFoundError):
			winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)


def observe():
	print(f"PID={os.getpid()}", flush=True)
	input("Configure PID capture; Enter to create resources: ")
	with resources() as (marker, stream, key_path, key):
		print(f"FILE={marker}\nKEY=HKCU\\{key_path}", flush=True)
		input("Resources held; inspect now, then Enter to close: ")
	print("Resources closed and removed", flush=True)
	input("Refresh views; Enter to exit: ")


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--observe", action="store_true")
	options = parser.parse_args()
	if options.observe:
		observe()
	else:
		unittest.main(argv=[__file__], verbosity=2)
```

### Objectives and Steps

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 test_example.py --observe
```

1. Require four passing fixture tests. Start observation and leave it at the first prompt. Record the printed PID, Process Explorer start time, image path, and user.
2. Launch a second `py -3.12 test_example.py --observe` in another terminal. Leave that decoy at its first prompt. It shares the interpreter name but has a different PID. Do not include it in capture.
3. Configure Process Monitor as above with only the first PID. Start capture, release only the first process, and record its synthetic file/key paths.
4. In Process Explorer select the first PID, enable lower-pane handles, and locate `marker.txt` and the unique registry key. Run the scoped Handle and AccessChk commands. Record handle type and access details, not just its numeric value.
5. Review Autoruns read-only and Sigcheck for the tool binary. Keep reputation/upload features off. Document that the fixture created no autostart location.
6. Release the first process's close prompt. Confirm close/delete events and disappearance of its handles while it remains alive at the final prompt. Stop capture, save only filtered synthetic evidence, then let both fixture processes exit (Ctrl+C is sufficient for the untouched decoy).

### Hints

- Registry paths can appear as `HKCU` or the underlying `HKU\<SID>` path. Match the unique suffix, not an assumed display prefix.
- No marker events often means capture began too late or the launcher PID was selected. Repeat from a new fixture run rather than broadening capture to all processes.

### Solution and Expected Results

The first PID creates/opens a unique marker, writes `synthetic-only`, creates a key, sets `Marker` as REG_SZ, and holds both handles until Enter. Closing the context releases handles and deletes key/directory; the interpreter remains alive for refresh. The decoy's PID should contribute **zero retained events** under the configured destructive PID filter. Exact event counts and names around Python cleanup can vary; require semantic create/write/close/delete evidence instead.

### Verification, Troubleshooting, and Cleanup

Expected **4 unittest tests**. Manual gates: correct PID/start identity, held file/key, expected Procmon operations, absent decoy events, handle disappearance before process exit, and no new Autoruns entry for the fixture. Tool visibility denied by policy is an explicit incomplete manual gate, not a passed test.

Normal Enter/Ctrl+C inside the resource context executes cleanup; forced termination may leave artifacts. In that case, use Explorer and Registry Editor to remove only the **exact printed** temporary directory and unique `HKCU\Software\HackVaultToolLab-...` key after confirming the fixture has exited. Never remove an entire Software tree or use wildcard key deletion. Close Process Monitor to stop capture, remove only lab evidence/backing files, and restore changed display/filter settings if retaining the VM. No Sysmon or boot-log cleanup should be necessary.

Author validation: **no fixture tests, elevation, driver load, or GUI capture performed**. Command syntax is grounded in official references; installed versions and event sequences remain to be verified.

- [ ] Local Sysinternals exercise: Run a toy program that opens a file and writes a test registry value. Filter Process Monitor to that process and correlate its handle and identity in Process Explorer.
- [ ] Boundary check: Confirm the expected marker is captured and that a similarly named unrelated process is excluded by the selected identity/filter.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]
- [[Sysmon]]

## References

- [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
- [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle)
- [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)
