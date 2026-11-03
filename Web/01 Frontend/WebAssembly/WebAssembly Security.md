---
title: "WebAssembly Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[WebAssembly]]"
updated: 2026-11-03
---
# WebAssembly Security

> [!abstract] TL;DR
> WebAssembly validates code and bounds linear-memory access; it does not authorize host calls, validate application objects or guarantee termination. Review imports as capabilities, validate every ABI boundary and isolate costly execution from the UI.

> [!info] Agent scope
> Security of: Modules and instantiation; linear memory; imports and exports; JavaScript boundary; sandbox guarantees and limitations. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Module provenance, compiler/toolchain, start functions, host imports, pointer/length ABI, shared state and resource limits. This note uses a tiny readable module and synthetic `SAFE` bytes; no memory-corruption exploitation, secret access or sandbox bypass techniques.

## Learn

```text
Teach defensive WebAssembly embedding at expert depth. Assume typed arrays,
UTF-8, browser workers and integer arithmetic. Separate validation, linking,
runtime bounds, application object safety, host authorization and resource limits.
Explain import capabilities, start-function effects, pointer/length contracts,
i32 signedness, memory growth/view invalidation, copying versus aliases, strict
text decoding, reentrancy, shared-memory races and CSP feature boundaries.
Provide a complete WAT/WABT/JavaScript fixture with minimal imports, strict range
and content checks, rejected missing imports, bounded memory and a worker deadline.
Use a harmless no-reply fixture to test timeout, never an unbounded workload.
Include exact files, commands, synthetic inputs, weak/fixed comparison, native JS
regression tests, browser evidence and cleanup. Cite primary sources and explain
control limits. No exploitation, bypass, secrets, file edits or fabricated runs.
End with difficult questions and worked answers.
```

## Cheatsheet

### Guarantees and Non-Guarantees

| Mechanism | What it provides | What remains your job |
|---|---|---|
| Module validation | Well-typed supported instruction structure | Algorithm correctness, provenance and termination |
| Linear-memory bounds | Trap on access outside that memory | Per-allocation bounds and logical object integrity |
| Import linking | Required names/types/limits bind to supplied host values | Least authority and semantic checks inside each callback |
| Memory maximum | Upper bound on that memory's pages | Total engine, compiled code, JS heap and worker resource budget |
| Worker isolation | Separate execution thread; host can terminate | Workers may still have browser capabilities such as fetch |
| CSP Wasm control | Restricts compilation under applicable policy | Safety of allowed modules and their host functions |

The engine sandbox is not a replacement for application authorization. A callback that performs an operation on behalf of a module must check its own permitted operation/resource; Wasm cannot infer that policy. Do not provide a generic command dispatcher or unrestricted host object when a narrow pure function is enough. An unused extra import is not called magically, but exposing unnecessary callback closures increases review and future-change risk.

`WebAssembly.Module.imports()` lists module/name/kind, not full function signatures, maximum memory consumption or hidden intent. Review source/artifact provenance and use an import allowlist; actual instantiation performs compatibility checks. A start function can call imports during instantiation, so host state and permission checks must already be valid. Exceptions may occur after partial host side effects; design idempotent/narrow callbacks.

### ABI Validation

At a wasm32 import, an i32 may arrive as a signed JavaScript Number. If the ABI defines unsigned offsets, normalize with `>>> 0` and then validate against memory size and application maximums. Do not normalize arbitrary unvalidated JS API arguments to make them seem valid. Use `length <= size - pointer` after `pointer <= size`, and decide whether zero length and one-past-end pointers are allowed.

Weak fragment:

```javascript
const bytes = new Uint8Array(memory.buffer).subarray(pointer, pointer + length);
```

`subarray` clamps indexes; it does not prove the requested range exists. Negative indexes have their own semantics. The lab's fixed host rejects bad ranges rather than accepting a shortened or shifted result. Decode UTF-8 with `{fatal: true}`, bound decoded length, and validate the application content separately. Use copies for records that must not change after a callback; views alias mutable memory.

Recreate views after any growth-capable call. For the fixed-length non-shared buffers used here, growth detaches the old buffer; newer resizable-buffer APIs require a separate view-lifetime analysis and feature detection. A validation check followed by shared-memory mutation has race considerations: the lab intentionally uses non-shared memory and synchronous copies, not a purported general solution for concurrent shared buffers. Imported callbacks can also reenter exports; avoid surprising reentrant state changes or explicitly guard them.

### Execution and Deployment Decisions

| Condition | Defensive response |
|---|---|
| Unsupported/invalid module | Fail closed at compile; do not treat it as a valid empty module |
| Missing or incompatible import | Reject instantiation; never supply a broad fallback dispatcher |
| Input outside ABI domain | Reject before export invocation where possible |
| Trap or host exception | Report bounded error category; discard uncertain instance state |
| Deadline exceeded | Terminate dedicated Worker; start fresh only for an explicitly authorized retry |
| Need external effects | Prefer validated messages to an authorizing host; constrain worker CSP/network policy too |

`Promise.race` cannot interrupt synchronous Wasm already blocking the main thread. A timer in that same thread also cannot preempt it. The lab places execution in a Worker and runs the watchdog in the page; termination is coarse, not cooperative rollback. Browser resource guarantees are not hard real-time. WASI is a separate host interface with its own capabilities, not automatically enabled for browser modules.

Downloaded binaries/constants remain inspectable. Do not embed secrets, rely on obscurity, or assume Wasm is inherently constant-time. Build dependencies, generated glue and source maps also belong in the software inventory. Pin reviewed builds and keep independent artifact provenance records.

## Detection and Defense

Track approved module digest/release, import allowlist outcome, compile/link/trap categories, rejected length/range counts, execution duration and worker termination counts. Do not log arbitrary memory contents. Differentiate malformed input from a regression in the host ABI or feature support. Run positive and negative checks after compiler, browser and glue changes, including memory growth and missing imports.

## Labs

### Environment and Complete Files

Node 22.x/npm 10.x, WABT 1.0.37, Python 3.11+, current Chromium/Firefox and free port 8881. Use an empty disposable directory; all files are printed below. No WASI, threads, memory64, external requests or privileged imports. WABT's pin is an example baseline, not a latest-version statement.

### File: package.json

```json
{
	"name": "wasm-host-policy-lab",
	"version": "1.0.0",
	"private": true,
	"type": "module",
	"dependencies": {"wabt": "1.0.37"}
}
```

### File: module.wat

```text
(module
	(import "env" "memory" (memory 1 2))
	(import "env" "emit" (func $emit (param i32 i32)))
	(data (i32.const 16) "SAFE")
	(func (export "emit") (param $pointer i32) (param $length i32)
		local.get $pointer
		local.get $length
		call $emit)
	(func (export "peek") (param $pointer i32) (result i32)
		local.get $pointer
		i32.load8_u))
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
	await writeFile('module.wasm', parsed.toBinary({write_debug_names: true}).buffer);
	console.log('Built module.wasm');
} finally { parsed.destroy(); }
```

### File: host.mjs

```javascript
export function checkImports(module) {
	const actual = WebAssembly.Module.imports(module)
		.map(item => `${item.module}:${item.name}:${item.kind}`).sort();
	const expected = ['env:emit:function', 'env:memory:memory'];
	if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('import policy');
}
export function createHost() {
	const memory = new WebAssembly.Memory({initial: 1, maximum: 2});
	const records = [];
	function read(pointerValue, lengthValue) {
		const pointer = pointerValue >>> 0;
		const length = lengthValue >>> 0;
		const size = memory.buffer.byteLength;
		if (length === 0 || length > 64 || pointer > size || length > size - pointer) {
			throw new RangeError('ABI range');
		}
		const copy = new Uint8Array(memory.buffer, pointer, length).slice();
		return new TextDecoder('utf-8', {fatal: true}).decode(copy);
	}
	function emit(pointer, length) {
		const text = read(pointer, length);
		if (text !== 'SAFE') throw new Error('content policy');
		if (records.length >= 8) throw new Error('record budget');
		records.push(text);
	}
	return {memory, records, read, imports: {env: {memory, emit}}};
}
```

`read` is an internal i32 ABI helper; it is not a public validator for arbitrary Numbers. The public browser selects only fixed test cases, and tests call the Wasm export so conversion semantics are explicit.

### File: checks.mjs

```javascript
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {checkImports, createHost} from './host.mjs';
const module = await WebAssembly.compile(await readFile('module.wasm'));
checkImports(module);
const host = createHost();
await assert.rejects(WebAssembly.instantiate(module, {env: {memory: host.memory}}), WebAssembly.LinkError);
const instance = await WebAssembly.instantiate(module, host.imports);
const {emit, peek} = instance.exports;
const weak = new Uint8Array(host.memory.buffer).subarray(65535, 65539);
assert.equal(weak.byteLength, 1);
assert.throws(() => emit(65535, 4), RangeError);
assert.throws(() => emit(-1, 4), RangeError);
assert.throws(() => emit(16, 65), RangeError);
assert.throws(() => emit(16, 0), RangeError);
new Uint8Array(host.memory.buffer)[32] = 255;
assert.throws(() => emit(32, 1), TypeError);
assert.throws(() => peek(65536), WebAssembly.RuntimeError);
assert.deepEqual(host.records, []);
emit(16, 4);
assert.deepEqual(host.records, ['SAFE']);
const old = new Uint8Array(host.memory.buffer);
host.memory.grow(1);
assert.equal(old.byteLength, 0);
emit(16, 4);
assert.deepEqual(host.records, ['SAFE', 'SAFE']);
assert.throws(() => host.memory.grow(1), RangeError);
console.log('PASS weak-range discrepancy, strict ABI, imports, trap, growth, allowed data');
```

### File: worker.mjs

```javascript
import {checkImports, createHost} from './host.mjs';
self.onmessage = async event => {
	if (event.data === 'no-reply') return;
	try {
		const response = await fetch('./module.wasm');
		if (!response.ok) throw new Error('module HTTP ' + response.status);
		const module = await WebAssembly.compile(await response.arrayBuffer());
		checkImports(module);
		const host = createHost();
		const instance = await WebAssembly.instantiate(module, host.imports);
		if (event.data === 'valid') instance.exports.emit(16, 4);
		else if (event.data === 'bad-range') instance.exports.emit(65535, 4);
		else throw new Error('unknown fixture');
		self.postMessage({ok: true, records: host.records});
	} catch (error) {
		self.postMessage({ok: false, error: error.name, reason: error.message});
	}
};
```

### File: index.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Wasm host boundary</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>pre { white-space: pre-wrap; overflow-wrap: anywhere; }</style>
<h1>Wasm host boundary</h1>
<button data-case="valid">Allowed SAFE record</button>
<button data-case="bad-range">Reject incomplete range</button>
<button data-case="no-reply">Test no-reply deadline</button>
<pre id="log" aria-live="polite"></pre>
<script>
const log = text => document.querySelector('#log').textContent += text + '\n';
let active = null;
for (const button of document.querySelectorAll('button')) {
	button.onclick = () => {
		if (active) return log('One worker at a time');
		const worker = new Worker('./worker.mjs', {type: 'module'});
		active = worker;
		const finish = text => {
			clearTimeout(timer);
			worker.terminate();
			active = null;
			log(text);
		};
		const timer = setTimeout(() => finish('TIMEOUT: worker terminated'), 3000);
		worker.onmessage = event => finish(JSON.stringify(event.data));
		worker.onerror = event => finish('WORKER ERROR ' + event.message);
		worker.postMessage(button.dataset.case);
		log('START ' + button.dataset.case);
	};
}
</script>
```

### File: server.py

```python
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class Handler(SimpleHTTPRequestHandler):
		extensions_map = {
				**SimpleHTTPRequestHandler.extensions_map,
				".wasm": "application/wasm",
				".mjs": "text/javascript",
		}

if __name__ == "__main__":
		print("http://127.0.0.1:8881/index.html", flush=True)
		ThreadingHTTPServer(("127.0.0.1", 8881), Handler).serve_forever()
```

### Objectives and Baseline

```powershell
npm install --ignore-scripts --no-audit --no-fund
node build.mjs
node checks.mjs
python server.py
```

The native test first proves that the weak slice accepts a truncated one-byte result for a four-byte request. It then requires the fixed host to reject the same range and all other invalid cases without recording data. The server/module never uses that weak slice for an operation. Open the printed browser URL and click each case separately.

### Hints

Engine bounds and host ABI checks are different: the export calling `emit` can pass numbers without doing a Wasm memory load, so only host validation prevents a bad host interpretation. The no-reply fixture intentionally returns without posting a result; it uses no busy loop and tests only the supervisor's deadline/termination path.

### Solution and Fixed Retest

Expected Node PASS with no assertion failures. Browser Allowed returns `{"ok":true,"records":["SAFE"]}`. Reject incomplete range returns `ok:false`, RangeError, ABI range. No-reply produces TIMEOUT after roughly three seconds while the page remains responsive. Click Allowed again: a fresh worker must still succeed. This proves lifecycle recovery after a denied request/timeout, not a hard CPU quota or network sandbox.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must install/build, run `node checks.mjs`, exercise all browser cases, inspect module/script MIME and record versions. Worker import errors usually mean wrong server root or MIME. A timeout on valid input may be slow startup or a broken load, not excessive Wasm computation: inspect Network/console before changing budgets. Stop only the lab server, close tabs (terminating workers) and delete the disposable directory. No registration, storage, permissions, VPN or existing-site settings are changed.

- [ ] Local WebAssembly exercise: Compile a tiny arithmetic function with an established toolchain and call its export from JavaScript. Inspect memory and test invalid input and an out-of-bounds access in the toy module.
- [ ] Boundary check: Instantiate the lab module with a minimal import object and verify that an undeclared or missing privileged import cannot be used. Bound execution/input size to avoid a frozen page.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[WebAssembly]]

## References

- [WebAssembly security model](https://webassembly.org/docs/security/)
- [Core validation and execution specification](https://webassembly.github.io/spec/core/)
- [Published JavaScript API 2.0](https://www.w3.org/TR/wasm-js-api-2/)
- [JavaScript API editor's draft, evolving features](https://webassembly.github.io/spec/js-api/)
- [Worker.terminate](https://developer.mozilla.org/en-US/docs/Web/API/Worker/terminate)
- [WABT](https://github.com/WebAssembly/wabt)
