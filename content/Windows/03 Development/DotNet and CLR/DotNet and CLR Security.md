---
title: ".NET/C# and CLR Security"
aliases: []
tags: [windows, x3, security]
domain: windows
phase: "X3"
type: security
status: draft
pair: "[[DotNet and CLR]]"
updated: 2026-11-03
---
# .NET/C# and CLR Security

> [!abstract] TL;DR
> Unsafe deserialization, dynamic assembly loading, reflection-driven dispatch, and incorrect interop can execute unintended code or corrupt native memory.

> [!info] Agent scope
> Security of: Assemblies; IL; JIT; GC; reflection; interop; loading; managed/unmanaged boundaries; C# resource lifetime. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Data-to-type selection, reflection dispatch, assembly/native library resolution, interop sizes, handle ownership, and resource exhaustion. A loading context and strong name are not privilege isolation.
- Lab: .NET 10 SDK, Windows 11 x64, PowerShell 7, standard user, synthetic JSON and a three-byte local file. No web API, external dependencies, or untrusted assemblies.

## Learn

```text
Teach me defensive .NET 10/CLR engineering at expert depth. Assume C# and Win32
basics. Trace JSON input through DTO binding, validation, explicit dispatch,
reflection/loading, P/Invoke and deterministic disposal. Distinguish type safety
from authorization and ALC/strong-name identity from sandboxing. Explain modern
BinaryFormatter restrictions, data-only serialization, reflection allowlists,
trusted dependency resolution, trimming/AOT, GC roots and resource quotas.
Show harmless baseline/fix regressions using known methods and synthetic data;
cover integer bounds, UTF-16/NUL handling, SafeHandle, ABI widths, errors and
exception cleanup. Explain appropriate assembly-load and rejection telemetry
without secrets. Use official versioned sources. No untrusted code execution,
offensive payloads, endpoints or host-policy changes. Teach in conversation,
not by editing files; include worked failure analyses and verification limits.
```

## Cheatsheet

### Mechanisms and Defensive Contracts

| Boundary | Root cause | Concrete rule |
|---|---|---|
| JSON -> object | Input chooses runtime type or has ambiguous fields | Fixed DTO, reject duplicate/unknown fields, bound total bytes/depth and values |
| Operation -> method | Reflection exposes every public method | Explicit switch/table of allowed operations; visibility is not authorization |
| Name -> assembly | Caller supplies path/type/assembly identity | Do not accept loader identifiers in this API; deployment owns dependencies |
| Managed -> native | Signedness/width/layout/termination mismatch | Match ABI, validate before call, use owned SafeHandle and explicit lengths |
| Integer -> allocation | Overflow or huge request | Bound first, checked arithmetic, quotas before allocation |
| GC -> cleanup | Reachable wrapper gets disposed concurrently or unreachable wrapper waits for finalization | Scoped ownership; do not share raw handles across asynchronous work |

Modern `System.Text.Json` does not instantiate arbitrary types from a `$type` field by default; enabling custom polymorphic converters changes the contract. Starting in .NET 9, the in-box BinaryFormatter implementation throws on use; do not re-enable legacy behavior for this lab. An allowlist of types is still more complexity than a data-only DTO when only two operations are needed.

`AssemblyLoadContext` isolates resolution/type identity, not authority. Plugin code runs with process permissions. Strong names and package hashes do not substitute for reviewed deployment and OS ACLs. Use an OS process boundary with minimum rights for components requiring genuine isolation; this note does not build a plugin sandbox.

Windows system-library P/Invokes should resolve trusted system DLLs, not caller-controlled paths. The lab declares `DefaultDllImportSearchPaths(System32)` and uses `SafeFileHandle`. `Marshal.GetLastPInvokeError()` is meaningful only on a documented failure path with `SetLastError = true`. Catch known validation errors, not every exception as success. Out parameters may be undefined after failure and must not be consumed.

### Baseline Versus Fix

The baseline below reflects only on a local teaching class, yet still exposes `InternalLabel`, a public method meant for internal workflow. It returns only a synthetic string. The fixed path accepts `echo` and `size`, rejects all CLR type/assembly identifiers, and validates before opening the fixed fixture. No example loads an untrusted assembly or runs supplied code.

For native strings, a managed string can contain NUL while a native `LPCWSTR` consumer stops at NUL. Validate where this matters; a safe managed type alone does not establish native semantics. The lab rejects NUL even in echo data as an explicit API contract. Byte counts and UTF-16 character counts are not interchangeable.

## Detection and Defense

- Record stable outcome codes and operation identifiers, not full user JSON or exception objects containing data. Count validation rejections separately from native I/O failures.
- AssemblyLoad events can support diagnostics, but occur after a load; they are not preventive controls. A process may lazily load framework assemblies during legitimate operations. Filter by the specific forbidden identity instead of asserting no loads ever occur.
- Monitor handle counts over repeated success/error paths, GC allocation rate and exception rate with approved runtime diagnostics. High GC pressure is not proof of a leak; stable managed heap size is not proof that native handles are released.

## Labs

### Environment and Complete Files

Create `$env:TEMP\X3-ClrSecurity`, containing these two files. No companion project required.

`Boundary.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
	<OutputType>Exe</OutputType>
	<TargetFramework>net10.0-windows</TargetFramework>
	<Nullable>enable</Nullable>
	<ImplicitUsings>enable</ImplicitUsings>
	<PlatformTarget>x64</PlatformTarget>
  </PropertyGroup>
</Project>
```

`Program.cs`:

```csharp
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

string fixture = Path.Combine(Path.GetTempPath(), "X3-boundary-" + Guid.NewGuid() + ".txt");
int forbiddenLoads = 0;
AppDomain.CurrentDomain.AssemblyLoad += (_, eventArgs) =>
{
	if (eventArgs.LoadedAssembly.GetName().Name == "Unapproved.Plugin")
		Interlocked.Increment(ref forbiddenLoads);
};
try
{
	File.WriteAllBytes(fixture, new byte[] { 65, 66, 67 });
	string baseline = (string)typeof(Operations).GetMethod("InternalLabel")!.Invoke(null, null)!;
	Require(baseline == "synthetic-private", "baseline");
	Console.WriteLine("baseline=" + baseline);
	Require(Dispatch("""{"op":"echo","text":"hello","count":2}""", fixture) == "hellohello", "echo");
	Require(Dispatch("""{"op":"size","text":"","count":1}""", fixture) == "3", "native size");
	string[] rejected =
	{
		"""{"op":"InternalLabel","text":"","count":1}""",
		"""{"op":"echo","text":"x","count":65}""",
		"""{"op":"echo","text":"x","count":-1}""",
		"""{"op":"echo","text":"a\u0000b","count":1}""",
		"""{"op":"echo","text":"x","count":1,"assembly":"Unapproved.Plugin"}""",
		"""{"op":"echo","text":"x","count":1,"type":"System.String"}""",
		"""{"op":"echo","op":"size","text":"","count":1}""",
		"""{"op":"echo","text":null,"count":1}""",
		"""{"op":"size","text":"","count":2147483648}""",
		"{}", "null", "[1]"
	};
	foreach (string input in rejected)
	{
		bool denied = false;
		try { Dispatch(input, fixture); }
		catch (JsonException) { denied = true; }
		catch (ArgumentException) { denied = true; }
		Require(denied, "accepted invalid input: " + input);
	}
	for (int attempt = 0; attempt < 100; attempt++)
		Require(Dispatch("""{"op":"size","text":"","count":1}""", fixture) == "3", "repeat");
	using (FileStream exclusive = new(fixture, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
		Require(exclusive.Length == 3, "disposed handles");
	bool missingFailed = false;
	try { Dispatch("""{"op":"size","text":"","count":1}""", fixture + ".absent"); }
	catch (FileNotFoundException) { missingFailed = true; }
	Require(missingFailed, "missing file failure");
	Require(forbiddenLoads == 0, "forbidden assembly load");
	Console.WriteLine("PASS: fixed dispatch, JSON bounds, native ownership, zero forbidden loads");
}
finally { File.Delete(fixture); }

static string Dispatch(string json, string fixture)
{
	if (Encoding.UTF8.GetByteCount(json) > 1024) throw new ArgumentException("INPUT_SIZE");
	using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
	if (document.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("OBJECT_REQUIRED");
	var fields = new HashSet<string>(StringComparer.Ordinal);
	foreach (JsonProperty property in document.RootElement.EnumerateObject())
		if (!fields.Add(property.Name)) throw new ArgumentException("DUPLICATE_FIELD");
	var options = new JsonSerializerOptions
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
		MaxDepth = 4
	};
	Request request = JsonSerializer.Deserialize<Request>(json, options)
		?? throw new ArgumentException("REQUEST_REQUIRED");
	if (request.Text is null || request.Text.Length > 128 || request.Text.Contains('\0'))
		throw new ArgumentException("TEXT_INVALID");
	if (request.Count is < 1 or > 64) throw new ArgumentException("COUNT_INVALID");
	return request.Op switch
	{
		"echo" => Repeat(request.Text, request.Count),
		"size" when request.Count == 1 && request.Text.Length == 0 => Size(fixture).ToString(System.Globalization.CultureInfo.InvariantCulture),
		_ => throw new ArgumentException("OP_NOT_ALLOWED")
	};
}

static string Repeat(string text, int count)
{
	int capacity = checked(text.Length * count);
	var result = new StringBuilder(capacity);
	for (int index = 0; index < count; index++) result.Append(text);
	return result.ToString();
}

static long Size(string fixture)
{
	using SafeFileHandle handle = File.OpenHandle(fixture, FileMode.Open, FileAccess.Read, FileShare.Read);
	if (!Native.GetFileSizeEx(handle, out long size))
		throw new Win32Exception(Marshal.GetLastPInvokeError());
	return size;
}

static void Require(bool condition, string message)
{
	if (!condition) throw new InvalidOperationException(message);
}

sealed record Request
{
	public required string Op { get; init; }
	public required string Text { get; init; }
	public required int Count { get; init; }
}

static class Operations
{
	public static string InternalLabel() => "synthetic-private";
}

static class Native
{
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool GetFileSizeEx(SafeFileHandle handle, out long size);
}
```

### Objectives and Baseline

```powershell
Set-Location "$env:TEMP\X3-ClrSecurity"
dotnet --info
dotnet build .\Boundary.csproj -c Release
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
dotnet run --project .\Boundary.csproj -c Release --no-build
if ($LASTEXITCODE -ne 0) { throw 'Checks failed' }
```

Explain why the baseline's public method is not necessarily a public operation. Trace every rejection to the layer enforcing it. Show that `size` operates only on the harness-owned fixture, not a caller path. No malformed pointer or unsafe native access is attempted; malformed inputs are rejected on the managed side.

### Hints

Unknown JSON properties must be rejected before anyone interprets them as CLR identifiers. `required` checks presence, not a nonnull value; hence explicit value validation. Duplicate-field behavior can be ambiguous across consumers, so the pre-pass rejects it. A native error is not an allowed empty result.

### Solution and Fixed Retest

The complete fixed solution is `Dispatch`: bounded parsing, exact DTO, value validation, explicit operations, fixed-file SafeHandle interop. Expected output includes `baseline=synthetic-private`, then PASS after twelve negative inputs, two permitted operations, 100 native reads, exclusive reopen, missing-file rejection, and no `Unapproved.Plugin` load. The load counter is narrowly scoped evidence, not proof that no code anywhere can load an assembly.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Run the exact source under the declared SDK; capture build/runtime results and review null/overflow/duplicate-field tests. This is a console boundary lab, not a claim of cross-user authorization or hostile-code containment. AOT/trimming, asynchronous interop and concurrent disposal require separate tests before production use.

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-ClrSecurity" -Recurse -Force
```

Normal execution deletes its uniquely named fixture in `finally`; retain a crash artifact only deliberately and remove the recorded file afterward.

- [ ] Local DotNet and CLR exercise: Build a small C# app using a disposable file handle and a benign native call with a correct signature. Inspect assembly metadata and verify cleanup on success and exception paths.
- [ ] Boundary check: Reject an unapproved type/assembly name from synthetic input and verify no dynamic load occurs. Test malformed interop inputs in a disposable process.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[DotNet and CLR]]

## References

- [BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [Reject unmapped JSON members](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/missing-members)
- [Required JSON properties](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/required-properties)
- [AssemblyLoadContext](https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/understanding-assemblyloadcontext)
- [Native interoperability best practices](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)
- [SafeHandle](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.safehandle)
