---
title: "Linux CLI"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[Linux CLI Security]]"
updated: 2026-11-03
---
# Linux CLI

> [!abstract] TL;DR
> The shell constructs argument vectors and connects file descriptors before the program runs. Know which shell parses a command, which identity executes it, and which namespace contains its files and sockets.

## Prerequisites

Linux or a disposable WSL Linux distribution, Bash 5.x, GNU coreutils and Python 3.12+ for the lab. Read-only networking examples use iproute2. PowerShell and Windows ACLs are different interfaces; do not paste Bash syntax into PowerShell. See [[Web Lab Setup]].

## Learn

```text
Teach me Linux CLI engineering from shell parsing to process and filesystem
behavior. Explain argv, quoting, expansion, globbing, pipelines, descriptors,
redirection order, exit statuses and Bash versus POSIX sh. Cover inode/directory
permissions, umask, symlinks, ACL caveats, processes/signals/jobs, environment,
working directory, text tools, NUL-delimited filenames, ip/ss and local lab
administration. Give exact nonprivileged commands and complete temporary-dir
tests for permissions, pipes and arguments. Distinguish Linux/WSL from Windows
and GNU from BSD utilities. Include failure diagnosis and safe cleanup without
global changes. Cite manuals; teach here without editing files or claiming
execution, and finish with worked descriptor and permission questions.
```

## Cheatsheet

### Parsing and Argument Boundaries

Bash reads syntax, expands words, sets up redirections and then invokes a builtin or executable. Quote variable expansions unless splitting/globbing is intentional. Single quotes preserve literal text; double quotes still allow parameter/command/arithmetic expansion but suppress ordinary word splitting and globbing. `"$@"` preserves positional arguments separately; `"$*"` combines them using IFS. Arrays preserve a command argument list in Bash; they are not POSIX sh syntax.

```bash
name='report one.txt'
printf '%s\n' "$name"
files=("report one.txt" "report two.txt")
printf '<%s>\n' "${files[@]}"
printf '%s\0' "${files[@]}" | xargs -0 printf 'file=%s\n'
```

Quotes are shell syntax removed before execution; the program receives the value, not protective quote characters. `--` ends options only for programs that support it. Use `./-name` or a safe API when option-looking filenames must be treated as data. Avoid parsing `ls`; filenames may contain whitespace and newlines. Use `find ... -print0` with NUL-aware consumers, or `find ... -exec command -- {} +` when supported.

### Files, Permissions, and Paths

| Object / operation | Required permission concept |
|---|---|
| Read regular file | File read permission plus directory traversal along path |
| Modify existing file | File write permission; may not require directory write |
| List directory names | Directory read; metadata lookup often also needs execute/search |
| Traverse directory | Directory execute/search |
| Create/delete/rename entry | Parent directory write + execute; sticky bit can add restrictions |
| Run executable | Execute permission, usable format/interpreter and mount/security policy |

Mode `0640` means owner read/write, group read, other none. Mode `0750` on a directory gives owner full access, group list/traverse, other none. Requested new-file mode is reduced by umask: typical file request 0666 with umask 0027 yields 0640; directory request 0777 yields 0750. Umask does not retroactively fix existing files. ACLs, Linux security modules, mount flags and capabilities can add constraints or change effective access. `stat` shows modes; `getfacl` is optional and may require an extra package.

```bash
pwd -P
id
stat --format='%A %a %U:%G %n' -- .
find . -maxdepth 1 -type f -print0
```

Inodes hold metadata/content references; directories map names to inodes. Hard links share an inode, symlinks store a path. Removing one filename does not necessarily remove data if another hard link or open descriptor remains. Relative symlink resolution is relative to its containing directory, not the caller's current directory.

### Descriptors, Pipelines, and Status

Descriptors 0/1/2 conventionally mean stdin/stdout/stderr. `>` truncates before the program executes; `>>` appends. A pipeline connects stdout only unless stderr is explicitly redirected. Redirections apply left-to-right:

| Command shape | Result |
|---|---|
| `command >out 2>err` | Separate files |
| `command >out 2>&1` | Both descriptors point to out |
| `command 2>&1 >out` | Stderr keeps the old stdout destination |
| `first \| second` | Second receives first's stdout, not stderr |

Bash normally returns the last pipeline command's status; `set -o pipefail` returns the rightmost nonzero status, if any. `set -e` has context-dependent exceptions and is not comprehensive error handling. Inspect return values deliberately. `grep` status 1 means no match, while status 2 usually means an error. SIGPIPE can be expected when a downstream consumer stops early; pipefail may surface it.

### Text, Processes, and Networking

```bash
LC_ALL=C sort names.txt | uniq -c
grep -n -- 'marker' report.txt
awk -F, '{print $1}' records.csv
ps -eo pid,ppid,user,stat,args
jobs -l
ss -lntup
ip -brief address
ip route show
```

The awk fragment handles simple delimiter-separated text, not general quoted CSV; use a CSV parser for that. `uniq` combines adjacent equal lines, hence sort first when order is irrelevant. Locale changes sorting and character classes. Binary data, encodings and embedded delimiters need appropriate parsers.

Processes inherit environment, current directory and selected open descriptors. Environment changes in a child cannot directly change its parent. PID identifies a process only during its lifetime; avoid stale PID assumptions. SIGTERM requests graceful termination; SIGKILL prevents cleanup and should not be routine. `jobs`, `fg`, `bg` concern the current shell's jobs, not every system process. `ss -p` may omit other users' process details without privilege. A listener is not proof of end-to-end reachability; inspect bind family and route separately.

## Gotchas

GNU and BSD `stat`/`sed` flags differ. `/bin/sh` need not be Bash. WSL files on Windows-mounted drives can have different permission behavior; use the Linux filesystem for this lab. Do not repair a permissions error with blanket sudo or chmod 777. Shell history, environment and command lines can disclose secrets.

## Labs

### Environment and Complete Files

Run inside Linux/WSL with Python 3.12+, Bash 5.x and GNU coreutils installed. No root needed, no network. Fixtures use temporary directories and fixed shell scripts; supplied labels remain positional data.

### File: test_example.py

```python
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest


class CLITests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		if os.name != "posix" or shutil.which("bash") is None:
			raise RuntimeError("Run in Linux/WSL with Bash and Python 3.12+")
		cls.bash = shutil.which("bash")

	def shell(self, script, *arguments, cwd=None):
		return subprocess.run([self.bash, "--noprofile", "--norc", "-c", script,
							   "lab", *arguments], cwd=cwd,
							  env={"PATH": os.defpath, "LC_ALL": "C"},
							  text=True, capture_output=True, timeout=5)

	def test_argument_and_streams(self):
		result = self.shell('printf "out=<%s>\\n" "$1"; printf "err\\n" >&2',
							"report one.txt")
		self.assertEqual(result.returncode, 0)
		self.assertEqual(result.stdout, "out=<report one.txt>\n")
		self.assertEqual(result.stderr, "err\n")

	def test_pipeline_status(self):
		ordinary = self.shell("false | true")
		checked = self.shell("set -o pipefail; false | true")
		self.assertEqual(ordinary.returncode, 0)
		self.assertEqual(checked.returncode, 1)
		sorted_text = self.shell("printf 'b\\na\\nb\\n' | sort | uniq -c")
		self.assertEqual(sorted_text.returncode, 0)
		self.assertEqual(sorted_text.stdout.split(), ["1", "a", "2", "b"])

	def test_umask_and_filename(self):
		with tempfile.TemporaryDirectory() as directory:
			result = self.shell('umask 077; printf "synthetic\\n" > "$1"',
								"report one.txt", cwd=directory)
			self.assertEqual(result.returncode, 0)
			target = pathlib.Path(directory) / "report one.txt"
			self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
			self.assertEqual(target.read_text(), "synthetic\n")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. In Linux/WSL, record `bash --version` and `python3 --version`, then run `python3 -m unittest -v test_example`.
2. Predict the two pipeline statuses before running. Explain why stderr is absent from the stdout assertion.
3. Change only the lab shell's umask from 077 to 022; observe the mode assertion fail, then restore 077.
4. Explain why the filename with a space remains one argument and one directory entry.

### Hints

The word `lab` after `-c` supplies `$0`; the filename becomes `$1`. The child-only umask cannot alter the parent shell. A TemporaryDirectory removes only its own contents.

### Solution and Expected Results

Expected: three tests pass. Stream outputs are separate, ordinary pipeline returns 0, pipefail returns 1, sorted counts are one `a` and two `b`, and the file mode is 0600. The mutation produces 0644 on an ordinary POSIX filesystem and fails the mode assertion. No user-owned files or global shell configuration change.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional `python3 -m pytest -q test_example.py` requires pytest. Native Windows intentionally raises a setup error; use a Linux filesystem in WSL, not a Windows-mounted path whose mode emulation differs. Missing sort/uniq indicates incomplete coreutils. Temporary fixture files clean themselves up; delete the saved test and caches afterward.

- [ ] Record argument, descriptor, pipeline and permission results.
- [ ] Explain process identity and local listener diagnostics.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[Linux CLI Security]]

## References

- [Bash reference manual](https://www.gnu.org/software/bash/manual/bash.html)
- [GNU coreutils manual](https://www.gnu.org/software/coreutils/manual/coreutils.html)
- [Linux path resolution](https://man7.org/linux/man-pages/man7/path_resolution.7.html)
- [Linux ss manual](https://man7.org/linux/man-pages/man8/ss.8.html)
