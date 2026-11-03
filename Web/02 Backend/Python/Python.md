---
title: "Python"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Python Security]]"
updated: 2026-11-03
---
# Python

> [!abstract] TL;DR
> `python -m venv .venv`; `python -m pip --version`; use pathlib, subprocess argument lists, and context managers instead of string-built operations.

> [!info] Agent scope
> Python runtime; environments and dependencies; modules; exceptions; async; web server interfaces; input and serialization boundaries.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me CPython 3.12-3.14 for backend engineering given programming and HTTP.
Explain interpreter execution, object identity, refcounts/cyclic GC, imports,
venv/pip resolution, packaging, exception chaining and context-manager cleanup.
Contrast GIL builds with optional free-threaded builds, threads/processes,
asyncio tasks, cancellation, TaskGroup and blocking adapters. Trace WSGI and
ASGI request/response/lifespan contracts. Work through bounded JSON decoding,
strict schemas, decimal/date serialization, database transaction ownership,
authentication boundaries and safe process invocation. Supply runnable standard-
library examples, unittest checks and exact expected results; use primary public
sources and label unexecuted claims. Teach in this conversation, not by editing.
```

## Cheatsheet

### Interpreter, Imports and Environments

CPython compiles source to bytecode and executes it in an interpreter; `.pyc` is a cache, not a confidentiality control. Reference counting usually releases objects promptly, but cyclic GC and alternate implementations mean finalizers are not a resource-management contract. Use `with`/`async with` for files, locks, transactions and client sessions. `is` compares identity; `==` compares values. Mutable default arguments are created once at function definition and can leak state between calls.

`import` executes module top-level code once per interpreter and stores the module in `sys.modules`. A circular import can observe a partially initialized module. Use a package entry point (`python -m package`) and avoid startup side effects such as opening a database during import. A local file named `json.py` can shadow the standard library. Inspect `sys.executable`, `sys.prefix` and `module.__file__` when dependencies appear wrong.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip --version
.\.venv\Scripts\python.exe -c "import sys,json; print(sys.executable); print(json.__file__)"
```

Bind pip to the intended interpreter with `python -m pip`. A venv is dependency selection, not OS isolation. Pin transitive dependencies in a reviewed lock/requirements artifact; hash-check installations when reproducing a deployment. Build systems can execute code during installation. Keep production dependencies distinct from test tooling.

### Concurrency and Cleanup

| Mechanism | Fits | Important boundary |
|---|---|---|
| Threads | Blocking I/O and libraries releasing the GIL | Default GIL builds do not execute Python CPU bytecode in parallel. Shared state still needs synchronization across multi-step operations. |
| Processes | CPU work and fault separation | Serialization, startup and separate memory have costs. Windows spawn requires an import-safe main guard. |
| `asyncio` | Many cooperative network waits | Calling `time.sleep`, synchronous drivers or CPU loops blocks the event loop. `await` is a possible interleaving point, not an OS thread. |
| `to_thread` | Adapting bounded synchronous I/O | Cancelling the awaiting task does not forcibly stop the worker function. |
| `TaskGroup` (3.11+) | Structured concurrent subtasks | Failures cancel siblings and can raise `ExceptionGroup`. Await cleanup; do not swallow `CancelledError`. |

Optional free-threaded CPython began in 3.13; support and extension compatibility differ from ordinary builds. Do not rely on the GIL as a transaction lock or assume an installed interpreter is free-threaded. `asyncio.run()` owns a loop at a program boundary; do not call it inside an already-running server loop.

### Server and Data Boundaries

WSGI calls `application(environ, start_response)` and consumes an iterable of bytes. Headers are strings; body chunks are bytes; call `start_response` before body delivery. ASGI calls an async application with `scope`, `receive`, `send`, supporting HTTP/WebSocket messages and lifespan events. Both are server interfaces, not authentication, routing or schema libraries. A WSGI worker remains occupied while its request executes, even if a framework adapts an async view.

`json.loads` accepts duplicate object names (last wins) and nonfinite numeric tokens by default; override hooks when strict interoperable input is required. `bool` is a subclass of `int`: use `type(value) is int` when booleans must not count as quantities. Bound raw bytes before decoding; bound nested structures and work after parsing. Serialize money as integer minor units or explicit decimal strings, and timestamps with offsets.

Use parameterized SQL and transaction context managers. Commit belongs to the unit of work, not every helper. Roll back on failure, close connections separately, and do not share a connection across tasks unless its driver explicitly supports that. Derive resource ownership from authenticated server state, never from a JSON `owner` field. Catch narrow domain exceptions, chain causes with `raise DomainError(...) from error`, and keep internal traces out of HTTP responses.

## Gotchas

Virtual environments isolate package selection, not operating-system privileges. Async functions can still block if they call synchronous I/O.

## Labs

- [ ] Local Python exercise: Create a virtual environment and a small JSON-processing function with explicit validation and tests for empty, malformed, and oversized input. Confirm dependencies resolve from the intended environment.
- [ ] Boundary check: Pass a harmless shell-metacharacter string through subprocess with an argument list and shell disabled. Verify it stays data and no additional command runs.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. Standard GIL CPython 3.12-3.14, standard library only. Use a new directory and the venv commands above (POSIX: `python3 -m venv .venv`, then `.venv/bin/python`). No requirements file or external server is required.

### File: example.py

```python
import json
from wsgiref.simple_server import make_server


def unique_object(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise ValueError("duplicate key")
		result[key] = value
	return result


def reject_constant(value):
	raise ValueError("nonfinite number")


def decode_order(raw):
	if not raw or len(raw) > 1024:
		raise ValueError("body size")
	order = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
					   parse_constant=reject_constant)
	if type(order) is not dict or set(order) != {"quantity"}:
		raise ValueError("schema")
	quantity = order["quantity"]
	if type(quantity) is not int or not 1 <= quantity <= 10:
		raise ValueError("quantity")
	return {"quantity": quantity, "total_cents": quantity * 125}


def application(environ, start_response):
	status = "200 OK"
	if environ["PATH_INFO"] != "/quote":
		status, result = "404 Not Found", {"error": "not_found"}
	elif environ["REQUEST_METHOD"] != "POST":
		status, result = "405 Method Not Allowed", {"error": "method"}
	elif environ.get("CONTENT_TYPE", "").split(";")[0] != "application/json":
		status, result = "415 Unsupported Media Type", {"error": "media_type"}
	else:
		try:
			length = int(environ.get("CONTENT_LENGTH") or "0")
			if not 0 < length <= 1024:
				raise ValueError("length")
			result = decode_order(environ["wsgi.input"].read(length))
		except (ValueError, UnicodeError, RecursionError):
			status, result = "400 Bad Request", {"error": "invalid_order"}
	body = json.dumps(result, allow_nan=False).encode("utf-8")
	headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
	if status.startswith("405"):
		headers.append(("Allow", "POST"))
	start_response(status, headers)
	return [body]


if __name__ == "__main__":
	with make_server("127.0.0.1", 8000, application) as server:
		server.serve_forever()
```

### File: test_example.py

```python
import io
import json
import unittest
from example import application, decode_order


class RuntimeTests(unittest.TestCase):
	def test_strict_input(self):
		self.assertEqual(decode_order(b'{"quantity":2}')["total_cents"], 250)
		for raw in [b"", b"{", b"{}", b'{"quantity":true}',
					b'{"quantity":1,"quantity":2}', b'{"quantity":NaN}', b"x" * 1025]:
			with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
				decode_order(raw)

	def test_wsgi(self):
		body = b'{"quantity":3}'
		captured = {}
		def start(status, headers):
			captured.update(status=status, headers=dict(headers))
		response = b"".join(application({"PATH_INFO": "/quote", "REQUEST_METHOD": "POST",
			"CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body)),
			"wsgi.input": io.BytesIO(body)}, start))
		self.assertEqual(captured["status"], "200 OK")
		self.assertEqual(json.loads(response)["total_cents"], 375)
		self.assertEqual(int(captured["headers"]["Content-Length"]), len(response))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

Run `.\.venv\Scripts\python.exe -m unittest -v`, then `.\.venv\Scripts\python.exe example.py`. Save `{"quantity":2}` in a file named body.json and run `curl.exe -i http://127.0.0.1:8000/quote -H "Content-Type: application/json" --data-binary "@body.json"`. Trace bytes -> decode -> validation -> cents -> response bytes. Explain why `true` must be rejected despite `isinstance(True, int)` being true.

### Hints

Schema validity is stricter than JSON validity. WSGI does not automatically consume a request stream safely: this exercise requires a bounded declared length. Production ingress must also bound slow/incomplete bodies and handle transfer framing.

### Solution and Expected Results

The hooks reject duplicate names and nonfinite constants; explicit type/range checks enforce the business schema. Expected: two passing unittest methods, HTTP 200 and `{"quantity": 2, "total_cents": 250}`. The sample intentionally rejects unknown-length input rather than implementing HTTP framing itself. The standard-library server is a local demonstration, not production deployment.

### Troubleshooting and Reset

An import resolving to the wrong file indicates an incorrect working directory or a module shadowing a standard library name. A 415 means the JSON media type is missing. A 400 may mean malformed/oversized input or no Content-Length. Stop Ctrl+C; no persistent state exists. Remove only the disposable venv/project when finished. Process-boundary regression is supplied independently in [[Python Security]].

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Python Security]]

## References

- [Python data model](https://docs.python.org/3/reference/datamodel.html)
- [asyncio tasks](https://docs.python.org/3/library/asyncio-task.html)
- [JSON](https://docs.python.org/3/library/json.html)
- [WSGI specification](https://peps.python.org/pep-3333/)
- [ASGI specification](https://asgi.readthedocs.io/en/latest/specs/main.html)
