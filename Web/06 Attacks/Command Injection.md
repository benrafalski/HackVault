---
title: "Command Injection"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Command Injection

> [!abstract] TL;DR
> Command injection occurs when untrusted input changes shell syntax or an executable's intended arguments.

> [!info] Agent scope
> Shell versus argument injection; quoting; command construction; blind signals in labs; safe process APIs.

## Learn

```text
Teach command injection as a process-construction boundary failure. Assume
operating-system processes, argv, HTTP input, and environment variables.
Distinguish shell interpretation from an executable's option/argument grammar;
explain platform quoting, Windows command lines and batch-file caveats, executable
selection, cwd/PATH/environment trust, response files, timeouts, and output limits.
Compare library APIs with fixed executables and structured arguments. Explain
visible versus blind evidence through code review and synthetic process records,
without commands or payloads that cause unintended execution. Work through a
mocked subprocess regression and safe in-process alternative. Discuss privilege
and containment limits, official Python documentation, and review questions.
No shells, RCE, bypasses, theft, scanning, live exploitation, or chains. Do not
edit files or claim unexecuted process tests ran.
```

## Cheatsheet

> [!important] Defensive scope
> No process is launched by this lab. It uses `unittest.mock` to inspect a safe API contract and an in-process hashing implementation. No shell strings or execution payloads are supplied.

### Two Different Interpreters

A shell can interpret command source before a target program sees arguments. Direct process APIs remove that shell boundary, but the selected program still interprets its own options, filenames, formats, and configuration. Injection requires untrusted influence over a meaningful interpretation boundary, not merely a string appearing in a process log.

| Boundary | Defense | Residual risk |
|---|---|---|
| Operation selection | Closed map to library functions or reviewed executables | A legitimate operation may still be overprivileged |
| Shell grammar | Avoid shell construction; use structured arguments | Target program retains its own grammar |
| Argument grammar | Fixed switches, enum values, validated data | `--` works only for tools that document it |
| Executable lookup | Deployment-owned absolute executable path | File replacement and writable directories remain relevant |
| Environment/cwd | Minimal explicit environment and trusted directory | Some programs load configuration implicitly |
| Resource use | Time, input, and output bounds; least privilege | A timeout may not terminate all descendants automatically |

Prefer library APIs for hashing, compression, and filesystem operations. Quoting is shell- and platform-specific; `shlex.quote` is not a Windows quoting solution. On Windows, `subprocess` ultimately forms a command-line string; target parsing conventions matter. Python documents that batch files may be launched through a system shell even when a caller does not explicitly request one. This note's design excludes batch/shell executables entirely.

Python 3.12 changed Windows `shell=True` search behavior, but that is not permission to construct shell source. `shell=False` is necessary for many wrappers, not a complete safety argument. Never let a request choose an interpreter, arbitrary executable, script, or plugin path.

### Evidence and Worked Alternative

The `digest` function below performs a fixed computation without any process boundary. The mocked renderer adapter demonstrates the required argv shape, input channel, timeout, and error checking. In a real deployment, review the renderer's documented grammar and output behavior before using an adapter of this shape.

For incident analysis record parent/child executable identities, operation IDs, exit categories, duration, and expected versus unexpected descendants. Redact arguments containing user data. A timeout is not proof of blind command execution; correlate with process telemetry and code paths. Process identity limits impact, but a low-privilege application still has resources worth protecting.

## Defense

Remove unnecessary subprocesses first. For unavoidable tools, pin their identity and options, validate values against their actual grammar, use stdin for data where supported, isolate processing, and bound resources. Do not rely on punctuation removal. Review deployment permissions and inherited handles. Treat process output as untrusted data at its next consumer.

## Labs

### Environment and Objectives

Python 3.12 stdlib only; no external executable required or invoked. Review a proposed web hashing feature that builds a command string. Replace it with `hashlib`. Separately review a hypothetical renderer whose documented interface accepts `--format text` and input on stdin; the fake executable below exists only as a mock expectation.

### File: test_example.py

```python
import hashlib
import unittest
from unittest.mock import Mock


REVIEWED_EXECUTABLE = "/deployment-owned/renderer"


def digest(data):
	if type(data) is not bytes or len(data) > 4096:
		raise ValueError("bounded bytes required")
	return hashlib.sha256(data).hexdigest()


def render_with_adapter(runner, text, output_format="text"):
	if output_format != "text":
		raise ValueError("unsupported format")
	if type(text) is not str or len(text) > 4096:
		raise ValueError("bounded text required")
	return runner(
		[REVIEWED_EXECUTABLE, "--format", "text"],
		input=text, text=True, shell=False, check=True,
		timeout=2, capture_output=True, env={},
	)


class ProcessBoundaryTests(unittest.TestCase):
	def test_library_result(self):
		self.assertEqual(digest(b"abc"),
						 "ba7816bf8f01cfea414140de5dae2223"
						 "b00361a396177a9cb410ff61f20015ad")

	def test_fixed_argv_data_on_stdin(self):
		runner = Mock(return_value="synthetic result")
		self.assertEqual(render_with_adapter(runner, 'Report "November"'),
						 "synthetic result")
		runner.assert_called_once_with(
			[REVIEWED_EXECUTABLE, "--format", "text"],
			input='Report "November"', text=True, shell=False, check=True,
			timeout=2, capture_output=True, env={},
		)

	def test_rejected_operation_never_calls_runner(self):
		runner = Mock()
		with self.assertRaises(ValueError):
			render_with_adapter(runner, "Report", "unreviewed")
		with self.assertRaises(ValueError):
			render_with_adapter(runner, "A" * 4097)
		runner.assert_not_called()


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: compare what crosses argv with what crosses stdin. Why is selecting an arbitrary format different from passing text data? Why is the library implementation the stronger simplification?

Solution: hashing needs no subprocess; the adapter owns executable and options and rejects unreviewed operations before calling the mock. Expected: three tests pass and no child process starts. The mock intentionally does not certify a real renderer, Windows quoting, output bounds, or process-tree cleanup. `capture_output=True` buffers output, so a real unbounded renderer needs a streaming size cap or sandbox resource limit, not this fragment alone.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run in the named file's directory; `Mock` is standard library, not an installation requirement. Do not replace the mock with a real runner for this exercise. Remove the disposable directory afterward. The synthetic executable is not a missing dependency and must not be created.

- [ ] Local Command Injection exercise: Review the library replacement and fixed process contract.
- [ ] Boundary check: Verify invalid operations never invoke the mocked runner.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python 3.12 subprocess security considerations](https://docs.python.org/3.12/library/subprocess.html#security-considerations)
- [Python shlex limitations](https://docs.python.org/3.12/library/shlex.html)
- [Python hashlib](https://docs.python.org/3.12/library/hashlib.html)
- [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
