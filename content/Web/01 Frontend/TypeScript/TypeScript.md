---
title: "TypeScript"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[TypeScript Security]]"
updated: 2026-11-03
---
# TypeScript

> [!abstract] TL;DR
> Run `tsc --noEmit`; enable strict and consider noUncheckedIndexedAccess. Use a runtime schema at HTTP, storage, and message boundaries.

> [!info] Agent scope
> Type system; narrowing; generics; compiler options; emitted JavaScript; compile-time types versus runtime input validation.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me TypeScript at expert compiler/application depth. I know JavaScript
closures, prototypes, modules and async code. Cover structural assignability,
literal inference, unions/intersections, control-flow narrowing, never/unknown/
any, generics and keyof, mapped/conditional types, variance, discriminated
results, optional/indexed values, assertions and runtime schemas. Trace source
through checking, module resolution and JavaScript emission. Explain target,
lib, NodeNext versus bundler, type-only imports, strict options and source maps.
Provide complete projects, compiler-negative checks, runtime tests and emitted
code inspection. Distinguish erasable types from features with runtime output,
and record compiler-dependent behavior. Use TypeScript primary documentation.
Teach here without editing files or claiming unperformed tests.
```

## Cheatsheet

### Type Relationships and Narrowing

TypeScript is structurally typed: compatible shapes can be assigned without an explicit implements relationship. Excess-property checking is strongest on fresh object literals; it does not make object types exact at runtime. `any` suppresses useful checking and propagates; `unknown` requires evidence before use. `never` represents an impossible value and supports exhaustive checking.

```ts
// Fragments: these declarations do not validate external data.
type Result<Value> = {ok: true; value: Value} | {ok: false; error: string};
function property<Value, Key extends keyof Value>(value: Value, key: Key): Value[Key] {
	return value[key];
}
type Optional<Value> = {[Key in keyof Value]?: Value[Key]};
type ElementOf<Value> = Value extends readonly (infer Element)[] ? Element : never;
const config = {mode: 'preview'} satisfies {mode: 'preview' | 'publish'};
```

Generics express a relationship between inputs and outputs, not a way to ask JSON parsing for an arbitrary trusted type. Conditional types distribute over a naked union type parameter; wrapping the compared type in tuples changes that behavior. Intersections require both contracts and can reduce incompatible properties to `never`; they are not object-spread semantics. `satisfies` checks assignability without replacing the expression's inferred type as an annotation would; it performs no runtime check.

Narrow using discriminants, `typeof`, null checks, membership and validated predicates. `typeof null` is `object`, arrays are objects, and a truthiness check excludes valid empty strings or zero. User-defined `value is Type` predicates are trusted assertions about their implementation: an incorrect predicate can make checked code unsafe. Narrowing may become stale when mutable aliases, callbacks or external state change; take a validated immutable snapshot at the boundary.

`readonly` and `as const` are static restrictions, not a deep runtime freeze. Brands can prevent accidental mixing of identifiers in checked code but can be asserted or erased; only a validating constructor establishes their intended meaning. Function parameter variance has deliberate exceptions, notably method bivariance; do not assume the type system is a proof of all runtime behavior.

### Compiler Decisions

| Setting | Meaning / limitation |
|---|---|
| `strict` | Enables the strict family; new compiler releases can add checks |
| `noUncheckedIndexedAccess` | Indexed reads may be undefined; not implied by every strict setup |
| `exactOptionalPropertyTypes` | Omitted property differs from explicitly present undefined |
| `noEmitOnError` | Prevents new emission on errors; does not delete stale output |
| `target` | Controls syntax lowering; does not install runtime polyfills |
| `lib` | Available declaration environment, not APIs installed in the runtime |
| `module` / `moduleResolution` | Must model the real host/bundler; mismatches can pass checks and fail execution |
| `verbatimModuleSyntax` | Makes type-only versus value imports explicit and catches module-mode mismatches |
| `paths` | Checker lookup mapping; does not rewrite runtime imports by itself |

`NodeNext` models evolving Node behavior; use explicit `.js` relative specifiers in TypeScript intended to emit Node ESM. `bundler` accepts resolution patterns that native Node may reject. `import type` is erased. Interfaces/type aliases/assertions disappear, while ordinary enums, parameter properties and some decorator transformations emit runtime code. Native type-stripping runtimes do not perform type checking and may reject nonerasable syntax; this lab deliberately uses `tsc` then Node.

Compiler defaults differ by release. The lab sets its important options explicitly, uses features available in TypeScript 5.0+, and records the actual resolved compiler instead of prescribing an unverified patch release. Do not mix a framework's constrained compiler peer range with an arbitrary latest compiler.

## Gotchas

A successful typecheck does not prove memory safety in native dependencies, correct authorization, or safe HTML rendering.

## Labs

### Environment and Complete Files

Supported Node LTS (22+ sufficient), npm, TypeScript 5.0+ compatible with that Node release. Create `typescript-result-lab` with all four files below. The package install records an exact resolved compiler in the manifest/lockfile; retain those files for reproducibility. No server or browser is required.

### File: package.json

```json
{"name":"typescript-result-lab","private":true,"type":"module",
 "scripts":{"check":"tsc --noEmit","build":"tsc","test":"node test.mjs"}}
```

### File: tsconfig.json

```json
{
	"compilerOptions": {
		"target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext",
		"lib": ["ES2022"], "types": [], "strict": true,
		"noUncheckedIndexedAccess": true, "exactOptionalPropertyTypes": true,
		"verbatimModuleSyntax": true, "noEmitOnError": true,
		"rootDir": "src", "outDir": "dist"
	},
	"include": ["src/**/*.ts"]
}
```

### File: src/result.ts

```ts
export type Result<Value> =
	| {kind: 'ok'; value: Value}
	| {kind: 'invalid'; reason: string};

export function parseQuantity(text: string): Result<number> {
	let value: unknown;
	try { value = JSON.parse(text); }
	catch { return {kind: 'invalid', reason: 'json'}; }
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 10) {
		return {kind: 'invalid', reason: 'quantity'};
	}
	return {kind: 'ok', value};
}
function unreachable(value: never): never {
	throw new Error('Unrecognized result');
}
export function describe(result: Result<number>): string {
	switch (result.kind) {
		case 'ok': return `quantity=${result.value}`;
		case 'invalid': return `invalid=${result.reason}`;
		default: return unreachable(result);
	}
}
export function mapResult<Input, Output>(
	result: Result<Input>, transform: (value: Input) => Output
): Result<Output> {
	return result.kind === 'ok' ? {kind: 'ok', value: transform(result.value)} : result;
}
```

### File: test.mjs

```js
import assert from 'node:assert/strict';
import { parseQuantity, describe, mapResult } from './dist/result.js';
assert.equal(describe(parseQuantity('2')), 'quantity=2');
for (const text of ['"2"', 'null', '[]', '{}', '0', '11', '1.5']) {
	assert.equal(describe(parseQuantity(text)), 'invalid=quantity');
}
assert.equal(describe(parseQuantity('{')), 'invalid=json');
assert.deepEqual(mapResult(parseQuantity('2'), value => value * 3), {kind: 'ok', value: 6});
assert.deepEqual(mapResult(parseQuantity('0'), value => value * 3),
	{kind: 'invalid', reason: 'quantity'});
console.log('PASS typed result and runtime boundary');
```

### Objectives and Commands

```powershell
npm install --save-dev --save-exact typescript
npx tsc --version
node --version
npm run check
npm run build
npm test
```

Run only in the disposable directory. Inspect `dist/result.js`: the union, generics, parameter types and `never` annotation should be absent, while the actual validation and switch remain. Add `| {kind: 'pending'}` to Result and run check again. Then restore the original or implement a pending case before building.

### Hints

The default arm consumes `never`, not `Result<number>`. A new variant must become visible in both `describe` and any other operation whose return contract it changes. Parsing a numeric string JSON value yields a string, not a number.

### Solution and Expected Results

Original check/build should exit zero; test prints `PASS typed result and runtime boundary`. Adding pending should produce a type error at `unreachable(result)` because pending is not never. One complete handler is `case 'pending': return 'pending';`; retain the original two-variant model after the exercise. A successful build alone is insufficient: runtime tests reject syntactically valid but wrongly typed JSON.

### Verification, Troubleshooting, and Cleanup

Do not run a stale dist directory after a failed build; clean it before rebuilding when comparing output. Missing output usually means wrong `include`, wrong working directory or a preceding type error. An import error may mean package type or `.js` specifiers disagree with Node. Record compiler/runtime versions and lockfile, then remove only the lab directory when finished. Commands and expected outputs are supplied but have not been executed in this revision.

- [ ] Local TypeScript exercise: Define a discriminated result type and handle every case. Parse malformed JSON into unknown and validate it before use; confirm both compiler exhaustiveness and runtime rejection.
- [ ] Boundary check: Send a string where the API expects a numeric quantity despite the client's type definitions. Verify the server rejects it without relying on the client compiler.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[TypeScript Security]]

## References

- [Official documentation or primary training reference](https://www.typescriptlang.org/docs/handbook/intro.html)
- [Compiler options reference](https://www.typescriptlang.org/tsconfig/)
- [Narrowing](https://www.typescriptlang.org/docs/handbook/2/narrowing.html)
- [Module theory](https://www.typescriptlang.org/docs/handbook/modules/theory.html)
