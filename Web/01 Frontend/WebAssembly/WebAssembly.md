---
title: "WebAssembly"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[WebAssembly Security]]"
updated: 2026-11-03
---
# WebAssembly

> [!abstract] TL;DR
> A compiled Module is reusable code; an Instance binds imports and owns execution state. Linear memory is bytes, not JavaScript objects. Types and bounds protect the engine boundary, but application ranges, encodings and authority remain your responsibility.

> [!info] Agent scope
> Modules and instantiation; linear memory; imports and exports; JavaScript boundary; sandbox guarantees and limitations.

## Prerequisites

- JavaScript typed arrays/promises, binary integers and UTF-8. Node 22.x/npm 10.x, Python 3.11+, current Chromium/Firefox.
- WABT npm package 1.0.37 compiles the printed WebAssembly text (WAT). This is an example pin, not a newest-release claim. The lab uses baseline wasm32, not memory64, threads or WASI.

## Learn

```text
Teach WebAssembly at expert engineering depth, assuming JavaScript, typed arrays,
integer arithmetic and UTF-8. Trace WAT/toolchain output through validation,
compilation, import linking, instantiation, exports and runtime traps. Distinguish
Module from Instance, streaming MIME/CSP requirements, wasm32 memory/pages,
tables/globals, start functions, i32 coercion/wraparound, i64 BigInt and float
semantics. Explain pointer/length ABIs, strings, little-endian DataView access,
memory growth and stale views, imported capabilities and sandbox limitations.
Provide a complete WABT-built module, native JS tests and visible browser demo,
with missing-import, invalid-input and out-of-bounds checks. Cover workers and
execution/resource limits without dangerous examples. State feature/version
boundaries, cite primary sources, do not edit files or fabricate test results.
End with difficult questions and worked answers.
```

## Cheatsheet

### Compilation and Instantiation

| API | Result and boundary |
|---|---|
| `WebAssembly.validate(bytes)` | Boolean validation for supported module features; not safety/termination proof |
| `WebAssembly.compile(bytes)` | Promise of reusable Module; no instance execution |
| `WebAssembly.instantiate(bytes, imports)` | Promise of `{module, instance}` |
| `WebAssembly.instantiate(module, imports)` | Promise of Instance, not the same wrapper object |
| `WebAssembly.instantiateStreaming(fetch(url), imports)` | Streams compile/instantiate; requires a valid successful response with `application/wasm` MIME |
| `WebAssembly.Module.imports(module)` | Import names/modules/kinds, not a full signature or code audit |
| `WebAssembly.Module.exports(module)` | Export names/kinds; API availability is not authorization |

A Module can instantiate multiple times with different imports/state. Imported memory or globals may intentionally share state. A start function executes during instantiation, before the promise resolves, and may call imports. Supply only needed capabilities and consider initialization failure/side effects.

| Error | Typical cause |
|---|---|
| `CompileError` | Invalid binary, unsupported feature, validation failure |
| `LinkError` | Missing/incompatible import within a provided namespace |
| `TypeError` | Bad JS API argument/import namespace, streaming MIME or related API mismatch |
| `RuntimeError` | Wasm trap such as out-of-bounds access or integer division by zero |
| Host exception | Imported JavaScript function throws; not necessarily a Wasm RuntimeError |

Do not silently re-fetch after every streaming error: compilation and linking failures are not solved by a byte-buffer fallback. Diagnose response status/MIME first. CSP may restrict compilation: a policy can permit `'wasm-unsafe-eval'` without broadly allowing JavaScript `'unsafe-eval'`, subject to browser support.

### Numbers, Memory, and ABI

Wasm32 memory is addressed by byte offsets and grows in 64 KiB pages. Memory load/store bounds protect the whole linear memory, not individual allocations inside it. Two source-language objects can still overlap through a bug. Wasm integer memory accesses are little-endian; use `DataView` with explicit `true` for little-endian when decoding multibyte values.

| Boundary | Behavior |
|---|---|
| JS Number to `i32` | Integer conversion/coercion, not schema validation; fractional input is not automatically rejected |
| `i32.add` | Wraps modulo 2^32; JS sees signed i32 result |
| `i64` to/from JS | BigInt at the standard JS boundary; do not silently convert large integers to Number |
| `f32` | Rounds to single precision; NaN/Infinity require domain decisions |
| JS string to module | No implicit pointer/length encoding; choose UTF-8 and an allocation/ownership contract |
| `memory.grow(pages)` in JS | Returns old page count or throws RangeError; Wasm `memory.grow` instead returns -1 on failure |

With the traditional fixed-length non-shared buffer used here, memory growth detaches the old ArrayBuffer; recreate views after any call that may grow memory. Newer resizable-buffer APIs have different view behavior and require explicit feature detection; do not generalize this lab to them. Shared memory differs too: old fixed-length shared views do not automatically enlarge. Shared memory/threads need appropriate browser cross-origin isolation and toolchain support; memory64 and other extensions must be feature-detected rather than assumed.

Safe pointer-range fragment for a trusted ABI:

```javascript
function range(memory, pointer, length) {
	if (!Number.isInteger(pointer) || !Number.isInteger(length) ||
			pointer < 0 || length < 0 || pointer > memory.buffer.byteLength ||
			length > memory.buffer.byteLength - pointer) throw new RangeError('range');
	return new Uint8Array(memory.buffer, pointer, length);
}
```

The subtraction prevents overflow-style reasoning mistakes; application maximums and ownership checks still belong above it. `TextDecoder('utf-8', {fatal: true})` rejects invalid UTF-8 rather than quietly substituting characters. Avoid retaining a view across growth or copying a length merely because it fits the global memory.

### Sandbox Decisions

Wasm has no built-in DOM/filesystem/network access. Imports grant host capabilities; WASI is a separate host interface, not automatic browser authority. Validation and bounds checks do not prove algorithmic correctness, safe native-language object handling, authorization, constant-time behavior or bounded runtime. Run expensive work in a Worker and terminate it from the host if needed. A main-thread timer cannot interrupt a synchronous main-thread Wasm call.

## Gotchas

- Compiled code is inspectable; do not embed secrets and expect obscurity to protect them.
- Debug names/source maps improve debugging but do not change sandbox permissions.
- A module can pass validation yet trap during initialization or execution.

## Labs

### Environment and Complete Files

Use an empty disposable directory with Node 22/npm 10, Python 3.11+ and free port 8871. WABT is the only dependency. Create all files below; `build.mjs` produces the binary consumed by both JS tests and browser. No binary download or missing companion file is needed.

### File: package.json

```json
{
	"name": "wasm-mechanics-lab",
	"version": "1.0.0",
	"private": true,
	"type": "module",
	"dependencies": {"wabt": "1.0.37"}
}
```

### File: module.wat

```text
(module
	(import "env" "report" (func $report (param i32)))
	(memory (export "memory") 1 2)
	(data (i32.const 16) "Hi")
	(func (export "add") (param $left i32) (param $right i32) (result i32)
		local.get $left
		local.get $right
		i32.add)
	(func (export "peek") (param $pointer i32) (result i32)
		local.get $pointer
		i32.load8_u)
	(func (export "report") (param $value i32)
		local.get $value
		call $report))
```

### File: build.mjs

```javascript
import wabtFactory from 'wabt';
import {readFile, writeFile} from 'node:fs/promises';
const wabt = await wabtFactory();
const parsed = wabt.parseWat('module.wat', await readFile('module.wat', 'utf8'));
try {
	parsed.resolveNames();
	parsed.validate();
	const {buffer} = parsed.toBinary({write_debug_names: true});
	await writeFile('module.wasm', buffer);
	console.log('Built module.wasm');
} finally { parsed.destroy(); }
```

### File: checks.mjs

```javascript
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const bytes = await readFile('module.wasm');
assert.equal(WebAssembly.validate(bytes), true);
const bad = Uint8Array.from(bytes);
bad[0] = 1;
assert.equal(WebAssembly.validate(bad), false);
const module = await WebAssembly.compile(bytes);
assert.deepEqual(WebAssembly.Module.imports(module), [{module: 'env', name: 'report', kind: 'function'}]);
await assert.rejects(WebAssembly.instantiate(module, {env: {}}), WebAssembly.LinkError);
const reports = [];
const instance = await WebAssembly.instantiate(module, {env: {report: value => reports.push(value)}});
const {add, peek, report, memory} = instance.exports;
assert.equal(add(20, 22), 42);
assert.equal(add(2147483647, 1), -2147483648);
assert.equal(peek(16), 72);
assert.throws(() => peek(65536), WebAssembly.RuntimeError);
report(42);
assert.deepEqual(reports, [42]);
const old = new Uint8Array(memory.buffer);
assert.equal(memory.grow(1), 1);
assert.equal(old.byteLength, 0);
assert.equal(memory.buffer.byteLength, 131072);
assert.throws(() => memory.grow(1), RangeError);
console.log('PASS imports, arithmetic, wraparound, memory, trap, growth');
```

### File: server.py

```python
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class Handler(SimpleHTTPRequestHandler):
		extensions_map = {**SimpleHTTPRequestHandler.extensions_map, ".wasm": "application/wasm"}

if __name__ == "__main__":
		print("http://127.0.0.1:8871/index.html", flush=True)
		ThreadingHTTPServer(("127.0.0.1", 8871), Handler).serve_forever()
```

### File: index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Wasm memory and linking</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>Wasm memory and linking</h1>
<button id="run">Run fresh instance</button>
<pre id="log" aria-live="polite"></pre>
<script>
const log = text => document.querySelector('#log').textContent += text + '\n';
document.querySelector('#run').onclick = async () => {
	document.querySelector('#log').textContent = '';
	try {
		const {module, instance} = await WebAssembly.instantiateStreaming(fetch('./module.wasm'), {
			env: {report: value => log('HOST report=' + value)}
		});
		log('IMPORTS ' + JSON.stringify(WebAssembly.Module.imports(module)));
		const {add, peek, report, memory} = instance.exports;
		function checkedAdd(left, right) {
			for (const value of [left, right]) {
				if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
					throw new RangeError('expected signed i32');
				}
			}
			return add(left, right);
		}
		log('ADD ' + checkedAdd(20, 22));
		report(42);
		log('STRING ' + new TextDecoder('utf-8', {fatal: true}).decode(new Uint8Array(memory.buffer, 16, 2)));
		try { checkedAdd(1.5, 2); } catch (error) { log('INPUT ' + error.name); }
		try { peek(65536); } catch (error) { log('BOUNDS ' + error.name); }
		try { await WebAssembly.instantiate(module, {env: {}}); }
		catch (error) { log('MISSING IMPORT ' + error.name); }
		const old = new Uint8Array(memory.buffer);
		memory.grow(1);
		log('GROW old view=' + old.byteLength + ' new buffer=' + memory.buffer.byteLength);
	} catch (error) { log(error.name + ': ' + error.message); }
};
</script>
```

### Objectives and Steps

```powershell
npm install --ignore-scripts --no-audit --no-fund
node build.mjs
node checks.mjs
python server.py
```

Open the printed URL and click Run fresh instance. Inspect `module.wasm` response MIME and the visible output. Run again to confirm each instance starts with fresh memory. The printed module has no loops and all test accesses are bounded or intentionally trigger a single safe engine trap.

### Hints

`Hi` is UTF-8 bytes 72/105 at offsets 16/17. Offset 65536 is one past a single-page memory, not its final valid byte. After growing, recreate views; the old view's zero length is expected for non-shared memory.

### Solution and Expected Results

Node prints PASS. Browser: one `env.report` import, ADD 42, HOST report=42, STRING Hi, INPUT RangeError, BOUNDS RuntimeError, MISSING IMPORT LinkError, GROW old view=0/new buffer=131072. The arithmetic wrap test in Node proves input validation does not eliminate i32 result wraparound. Define whether callers want wrapping or checked arithmetic rather than silently relying on it.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must install/build, run `node checks.mjs`, inspect browser output/MIME and record runtime/browser versions. Compile error: verify WAT and tool version. Streaming TypeError: verify server root, response status and MIME before changing APIs. Stop only the lab server, close tabs and delete the disposable directory. No browser storage, permissions, service workers or existing-site configuration are changed.

- [ ] Local WebAssembly exercise: Compile a tiny arithmetic function with an established toolchain and call its export from JavaScript. Inspect memory and test invalid input and an out-of-bounds access in the toy module.
- [ ] Boundary check: Instantiate the lab module with a minimal import object and verify that an undeclared or missing privileged import cannot be used. Bound execution/input size to avoid a frozen page.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[WebAssembly Security]]

## References

- [WebAssembly core specification](https://webassembly.github.io/spec/core/)
- [Published WebAssembly JavaScript interface 2.0](https://www.w3.org/TR/wasm-js-api-2/)
- [JavaScript interface editor's draft, including evolving buffer APIs](https://webassembly.github.io/spec/js-api/)
- [WebAssembly web embedding](https://webassembly.github.io/spec/web-api/)
- [Memory.grow](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/grow)
- [WABT tooling](https://github.com/WebAssembly/wabt)
