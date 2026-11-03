---
title: "Linux CLI Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[Linux CLI]]"
updated: 2026-11-03
---
# Linux CLI Security

> [!abstract] TL;DR
> Treat arguments as data, give processes only required privileges and environment, and create private files atomically. Quoting, option parsing, filesystem ownership, and process lifetime are separate safety decisions.

## Attack Surface

Automation consumes filenames, environment variables, input streams and executable paths. Writable working directories, inherited descriptors, predictable temporary names, broad mode bits and unbounded child processes can expose data even without a shell. Least privilege must include files, sockets and child processes, not only the parent user's name.

## Learn

```text
Teach me defensive Linux CLI automation, assuming Bash and POSIX permissions.
Explain shell versus argv boundaries, option injection prevention, executable
lookup and environment, subprocess time/output limits, safe temporary files,
symlink/race considerations, umask/ACLs, directory permissions, inherited file
descriptors, privilege minimization, process signals and listener inventory.
Provide a complete nonprivileged Linux/WSL lab with harmless labels, private
temporary files and before/after permission checks. Do not execute unsafe shell
strings or demonstrate exploitation. Show permitted data survives unchanged,
and explain test limits under root, ACLs and Windows-mounted filesystems.
Use official manuals, exact commands and worked answers. Teach here without
editing files or claiming execution; no global or privileged changes.
```

## Cheatsheet

### Process Invocation

Use structured argument APIs such as `subprocess.run([executable, argument], shell=False, ...)`. A fixed executable path reduces PATH ambiguity, but the path and its parent directories still need trusted ownership. Input data passed as arguments can still be interpreted as options by the target program; use a supported `--` terminator or another safe API. `shell=False` is not a universal sanitizer.

| Input boundary | Control | Residual risk |
|---|---|---|
| Shell command text | Avoid concatenating untrusted text; use argv | Target's own option/language grammar |
| Executable lookup | Known path, minimal PATH and trusted parents | Modified binary or interpreter |
| Environment | Explicit required variables; exclude secrets/unneeded loader settings | Tool-specific configuration outside environment |
| Working directory | Dedicated trusted directory | Relative resources and symlinks inside it |
| Output | Bound size or stream to controlled files | `capture_output` can accumulate unbounded data |
| Runtime | Timeout and documented termination policy | Descendants may survive a parent's timeout |

POSIX `shlex.quote` quotes one shell word for compatible shells; it is not PowerShell or Windows command-line quoting. Prefer not to invoke a shell. Never put secrets into command arguments merely because shell=False is used; process inspection and logs can still reveal them. Use appropriate secret input channels with restrictive access and avoid dumping environment values.

### Files and Permissions

Use `tempfile.TemporaryDirectory`/`mkstemp` rather than choosing a predictable filename in a shared directory. Create atomically with restrictive mode; opening an existing path and then chmod can leave a race or temporary exposure. `O_CREAT|O_EXCL` rejects an existing path; `O_NOFOLLOW` on Linux can reject a final symlink but does not secure every ancestor. Prefer directory-relative descriptor operations for complex sensitive workflows. A pre-check followed by open is not atomic.

```python
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
	output.write("synthetic\n")
```

This fragment assumes `path` is inside a private owned directory. Umask can only remove requested permission bits, so 0600 never grants group/other access through basic mode creation. ACL inheritance and security modules still require inspection. File write permission and directory delete permission are different: removing a name is controlled mainly by its parent directory. Sticky bit on shared temporary directories restricts deletion but is not a replacement for private files.

Read-only inspection on an authorized lab host:

```bash
id
stat --format='%a %U:%G %n' -- ./lab-file
namei -l -- ./lab-file
ps -eo pid,ppid,user,stat,args
ss -lntup
```

`namei` is from util-linux and may be absent on minimal systems. Do not collect command lines containing real secrets. Directory execute/search permissions must be checked along the complete path. A file mode of 0600 alone does not prove only one principal can read it: root, ACLs, capabilities, backups and open descriptors matter.

### Pipelines, Privilege, and Cleanup

Quote expansions, preserve NUL-delimited filenames and check command statuses. `grep` no-match is not a processing failure; an upstream failure hidden by a final successful command is different. Use explicit pipeline policy and handle expected SIGPIPE. The shell performs `>` redirection before starting a command, so privilege on the executable does not automatically grant privilege to the shell's redirection.

Avoid broad sudo, chmod 777, writable executable directories, or granting container runtime access as routine fixes. Container daemon access can be equivalent to extensive host control. Restrict service binds and maintain both IPv4/IPv6 inventories. Stop only processes created by the lab, using owned handles/PIDs with appropriate lifetime checks; never terminate all processes matching a generic name. Close descriptors and remove only the known temporary directory.

## Detection and Defense

Record expected executable, argument schema, parent/child relationship, exit status, duration and synthetic file mode transitions. Alert on unexpected executable paths, broad permission changes and new wildcard listeners. Missing access can be legitimate ACL/mount policy rather than an application defect. Log semantic labels rather than raw secrets or unbounded user input.

## Labs

### Environment and Complete Files

Linux/WSL Python 3.12+, standard library; use the Linux filesystem, no root/network. The permission baseline exposes only a synthetic marker within a private temporary directory. The argument test invokes Python directly, never a shell.

### File: test_example.py

```python
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


def private_mode(path):
	return stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


class CLISecurityTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		if os.name != "posix":
			raise RuntimeError("Linux/WSL POSIX filesystem required")

	def test_permission_baseline_and_fix(self):
		with tempfile.TemporaryDirectory() as directory:
			target = pathlib.Path(directory) / "synthetic.txt"
			target.write_text("not a secret\n", encoding="utf-8")
			target.chmod(0o644)
			self.assertFalse(private_mode(target))
			target.chmod(0o600)
			self.assertTrue(private_mode(target))
			self.assertEqual(target.read_text(encoding="utf-8"), "not a secret\n")

	def test_argument_is_data(self):
		label = "report one; synthetic label"
		result = subprocess.run([sys.executable, "-I", "-c",
								 "import json,sys; print(json.dumps(sys.argv[1:]))", label],
								shell=False, check=True, capture_output=True,
								text=True, timeout=5, close_fds=True)
		self.assertEqual(json.loads(result.stdout), [label])

	def test_atomic_private_creation(self):
		with tempfile.TemporaryDirectory() as directory:
			target = pathlib.Path(directory) / "new-marker.txt"
			flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
			descriptor = os.open(target, flags, 0o600)
			with os.fdopen(descriptor, "w", encoding="utf-8") as output:
				output.write("synthetic\n")
			self.assertTrue(private_mode(target))
			with self.assertRaises(FileExistsError):
				os.open(target, flags, 0o600)
			self.assertEqual(target.read_text(encoding="utf-8"), "synthetic\n")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run `python3 -m unittest -v test_example` in Linux/WSL. Explain why the 0644 baseline fails the private-mode contract and 0600 passes.
2. Change the fixed chmod back to 0644; observe the regression test fail, then restore 0600.
3. Explain why the semicolon in the harmless label remains part of one argument; no shell receives it.
4. Explain why a second exclusive create fails instead of truncating the existing marker, and why this does not prove security of an untrusted parent directory.

### Hints

Mode tests inspect configured mode bits rather than attempting to impersonate another user. Running as root is unnecessary and would make many access-probe tests misleading. The bitmask tests group/other permission bits only.

### Solution and Fixed Retest

Expected: three tests pass. Marker content survives hardening, the complete label round-trips unchanged, and exclusive creation refuses an existing file. The permission mutation fails `test_permission_baseline_and_fix`. The fixture proves argument preservation and file-mode/creation behavior; it does not certify ACLs, privileged-user isolation or descendant-process cleanup.

### Verification, Troubleshooting, and Cleanup

Author execution prohibited. Optional runner: `python3 -m pytest -q test_example.py`. Native Windows is an explicit prerequisite failure; Windows ACLs are not POSIX mode bits. Use a Linux temporary directory if mounted-drive mode behavior differs. Fixtures remove their own files; delete the test and caches afterward. No listeners, accounts or system permissions change.

- [ ] Record permission baseline/fix and unchanged legitimate data.
- [ ] Explain argv, atomic creation, privilege and process-lifetime boundaries.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Linux CLI]]

## References

- [Python subprocess security considerations](https://docs.python.org/3.12/library/subprocess.html#security-considerations)
- [Python tempfile](https://docs.python.org/3.12/library/tempfile.html)
- [Linux open semantics](https://man7.org/linux/man-pages/man2/open.2.html)
- [Linux credentials](https://man7.org/linux/man-pages/man7/credentials.7.html)
