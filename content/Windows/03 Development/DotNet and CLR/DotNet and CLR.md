---
title: ".NET/C# and CLR"
aliases: []
tags: [windows, x3]
domain: windows
phase: "X3"
type: tech
status: draft
pair: "[[DotNet and CLR Security]]"
updated: 2026-11-03
---
# .NET/C# and CLR

> [!abstract] TL;DR
> Use using/IDisposable and SafeHandle; validate interop layouts and lengths; avoid untrusted assembly/type loading. GC is not a resource-ownership strategy.

> [!info] Agent scope
> Assemblies; IL; JIT; GC; reflection; interop; loading; managed/unmanaged boundaries; C# resource lifetime.

## Prerequisites

- Windows 11 x64, .NET 10 SDK x64 (LTS), PowerShell 7, standard user. No NuGet libraries or ASP.NET workloads. Commands assume SDK 10.0.x is already installed; record the exact SDK/runtime from `dotnet --info`.
- C# classes, exceptions, basic native ABI concepts, and [[Windows Lab Setup]]. .NET Framework 4.x is not this runtime; its AppDomain/loading/security behavior must not be inferred from this lab.

## Learn

```text
Teach me C#/.NET 10 and CLR internals at expert depth, assuming native Windows
and C# basics. Trace C# -> metadata/IL -> assembly resolution -> tiered JIT ->
machine code; compare ReadyToRun, Native AOT, trimming and reflection limits.
Explain type identity across AssemblyLoadContext, dependency resolution,
collectible unloading and GC roots. Derive generational GC, LOH/pinning costs,
finalization, using/IDisposable/IAsyncDisposable and SafeHandle ownership.
Work through a complete plugin plus host, metadata/IL inspection, a correct
Unicode P/Invoke, exception cleanup and unload evidence. Distinguish managed
reachability from native resource validity, HRESULT/Win32 errors, ABI widths,
delegate rooting and buffer lifetimes. Include failure tests and debugging
observations without assuming exact GC/JIT timings. Use official sources; no
untrusted-code execution or security-boundary claims for loading contexts.
Teach here, not by authoring notes/files; end with worked reasoning questions.
```

## Cheatsheet

### Compilation, Loading, and Execution

| Stage | Contract | Common incorrect inference |
|---|---|---|
| Assembly | PE contains metadata, manifest, references and usually IL; resources and native code may also exist | Filename alone identifies a trusted assembly |
| Type identity | Defined by assembly identity and load context, not just namespace/type text | Two loaded copies of the same interface necessarily cast to one another |
| Resolution | Default context resolves app/framework dependencies; custom contexts control their own resolution policy | Returning null from `Load` means reject every dependency; it can permit fallback |
| JIT | Compiles reachable methods, with tiering/PGO potentially replacing code later | A single disassembly is the permanent implementation |
| ReadyToRun | Precompiled code can reduce startup JIT work; runtime may still JIT | R2R means no runtime compilation |
| Native AOT/trimming | Closed-world analysis limits dynamic code and removes unused metadata/code | Arbitrary reflection/plugin loading works unchanged |
| Collectible ALC | `Unload()` requests unload; roots must disappear before collection | `Unload()` synchronously destroys objects |

Metadata tokens are scoped to a module. `MethodBody.GetILAsByteArray()` exposes IL bytes, not native JIT instructions; debug/release and compiler/runtime versions change the bytes. Strong names support identity, not a complete publisher trust policy. A custom ALC is dependency isolation, never a sandbox. Only load trusted code: executing a constructor/module initializer/reflected method can run arbitrary application logic.

### Memory and Resource Lifetime

- GC traces managed roots (stacks, statics, handles) and collects unreachable objects; generations optimize expected survival. Long-lived roots promote objects. Large objects (normally >=85,000 bytes including overhead) go on the LOH; do not make a correctness rule from collection timing.
- Pinning inhibits movement; it does not stop disposal of a separately owned native handle. Use the shortest native borrow possible. Async native calls need buffers, callbacks and handles alive until completion, not just until the initial P/Invoke returns.
- `using` lowers to exception-safe `finally`; it does not catch errors. `await using` awaits asynchronous disposal. Do not mix owning/nonowning wrappers over the same raw handle.
- `SafeHandle` provides critical-finalizer fallback and keeps the handle alive during supported P/Invoke marshaling. Prefer passing `SafeFileHandle` directly. `DangerousGetHandle()` loses those guarantees unless paired with carefully balanced dangerous references.
- Finalizers are nondeterministic, add lifetime/queue costs, and are not guaranteed at abrupt termination. A type owning only managed `IDisposable` objects usually needs disposal, not its own finalizer.
- `GC.KeepAlive(owner)` can extend managed reachability across a native use; it does not repair ownership races. Forced `GC.Collect()` belongs in the unload experiment below, not normal request processing.

### ABI and Errors

| Native declaration | C# choice | Why |
|---|---|---|
| `HANDLE` file ownership | `SafeFileHandle` | `INVALID_HANDLE_VALUE`/null invalidity and `CloseHandle` ownership |
| Win32 `BOOL` | `bool` with `[return: MarshalAs(UnmanagedType.Bool)]` | Windows BOOL is 32 bits; C++ bool is different |
| `DWORD` | `uint` | Windows unsigned 32-bit even on x64 |
| `SIZE_T`, pointer | `nuint`, `nint` as appropriate | Pointer-sized; Windows `long` is not pointer-sized |
| `LPCWSTR` | Unicode string/UTF-16 marshalling | Explicit `W` API avoids ANSI-codepage dependence |
| Last-error API | `SetLastError = true`, then `Marshal.GetLastPInvokeError()` immediately on failure | Other calls may overwrite thread error state |

Source-generated `LibraryImport` is a modern alternative for compatible signatures and AOT; it requires partial methods/types and has different supported marshaling. The lab uses explicit `DllImport` to make the classic contract visible. Do not set `Pack = 1` unless the native layout actually requires it; verify sizes/offsets and x86/x64 builds when structures cross the ABI.

## Gotchas

- A plugin's event subscriptions, task continuations, cached `Type`/`MethodInfo`, and thread stacks can root its ALC. Removing one reference is not proof of unload.
- Reflection wraps invoked method failures in `TargetInvocationException`; inspect `InnerException` while preserving the original cause. An exception object from a plugin can itself keep types alive.
- `FileShare.None` checks deterministic release of this handle, not global absence of races. A different process can still contend for the file.

## Labs

### Environment and Complete Files

Create `$env:TEMP\X3-Clr` with `Plugin` and `Host` subdirectories and the four files below. The host loads only the locally built trusted DLL; no downloads, remote inputs, registry changes, or elevation.

`Plugin/Plugin.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
	<TargetFramework>net10.0</TargetFramework>
	<Nullable>enable</Nullable>
	<ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
```

`Plugin/Calculator.cs`:

```csharp
namespace LabPlugin;
public static class Calculator
{
	public static int Add(int left, int right) => checked(left + right);
}
```

`Host/Host.csproj`:

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

`Host/Program.cs`:

```csharp
using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using Microsoft.Win32.SafeHandles;

if (args.Length != 1) throw new ArgumentException("Supply trusted Plugin.dll path");
string fixture = Path.Combine(Path.GetTempPath(), "X3-clr-" + Guid.NewGuid() + ".txt");
try
{
	File.WriteAllBytes(fixture, new byte[] { 65, 66, 67 });
	ProbeFile(fixture, false);
	try { ProbeFile(fixture, true); }
	catch (InvalidOperationException failure) when (failure.Message == "synthetic") { }
	using (FileStream exclusive = new(fixture, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
		Console.WriteLine($"exclusive-length={exclusive.Length}");
	WeakReference context = LoadAndRelease(Path.GetFullPath(args[0]));
	for (int attempt = 0; attempt < 10 && context.IsAlive; attempt++)
	{
		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();
	}
	Console.WriteLine($"unloaded={!context.IsAlive}");
	if (context.IsAlive) throw new InvalidOperationException("ALC still rooted; inspect debugger/roots");
	Console.WriteLine("PASS: native contract, exception disposal, metadata, plugin result, unload");
}
finally { File.Delete(fixture); }

static void ProbeFile(string path, bool fail)
{
	using SafeFileHandle handle = Native.CreateFileW(path, 0x80000000, 1, 0, 3, 0x80, 0);
	if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastPInvokeError());
	if (!Native.GetFileSizeEx(handle, out long length))
		throw new Win32Exception(Marshal.GetLastPInvokeError());
	if (length != 3) throw new InvalidOperationException("Unexpected length");
	Console.WriteLine($"native-length={length}");
	if (fail) throw new InvalidOperationException("synthetic");
}

[MethodImpl(MethodImplOptions.NoInlining)]
static WeakReference LoadAndRelease(string path)
{
	var context = new PluginContext(path);
	var weak = new WeakReference(context, trackResurrection: true);
	try
	{
		Assembly assembly = context.LoadFromAssemblyPath(path);
		MethodInfo method = assembly.GetType("LabPlugin.Calculator", throwOnError: true)!
			.GetMethod("Add", BindingFlags.Public | BindingFlags.Static)!;
		Console.WriteLine($"assembly={assembly.GetName().Name}; context={AssemblyLoadContext.GetLoadContext(assembly)!.Name}");
		Console.WriteLine($"IL={Convert.ToHexString(method.GetMethodBody()!.GetILAsByteArray()!)}");
		object? answer = method.Invoke(null, new object[] { 20, 22 });
		if (answer is not int value || value != 42) throw new InvalidOperationException("Plugin result");
		Console.WriteLine($"answer={answer}");
	}
	finally { context.Unload(); }
	return weak;
}

sealed class PluginContext : AssemblyLoadContext
{
	private readonly AssemblyDependencyResolver resolver;
	public PluginContext(string path) : base("trusted-lab", isCollectible: true)
		=> resolver = new AssemblyDependencyResolver(path);
	protected override Assembly? Load(AssemblyName name)
	{
		string? path = resolver.ResolveAssemblyToPath(name);
		return path is null ? null : LoadFromAssemblyPath(path);
	}
}

static class Native
{
	[DllImport("kernel32.dll", EntryPoint = "CreateFileW", ExactSpelling = true,
		CharSet = CharSet.Unicode, SetLastError = true)]
	internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
		nint security, uint creation, uint flags, nint template);
	[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool GetFileSizeEx(SafeFileHandle file, out long length);
}
```

### Objectives and Steps

```powershell
Set-Location "$env:TEMP\X3-Clr"
dotnet --info
dotnet build .\Plugin\Plugin.csproj -c Release
if ($LASTEXITCODE -ne 0) { throw 'Plugin build failed' }
dotnet build .\Host\Host.csproj -c Release
if ($LASTEXITCODE -ne 0) { throw 'Host build failed' }
dotnet run --project .\Host\Host.csproj -c Release --no-build -- `
	"$PWD\Plugin\bin\Release\net10.0\Plugin.dll"
if ($LASTEXITCODE -ne 0) { throw 'Runtime checks failed' }
```

Identify each metadata observation, native access mask, sharing mode, and disposal boundary. Explain why the plugin is built separately rather than project-referenced by the host. A missing DLL is an expected load failure, not a reason to search arbitrary directories.

### Hints

The host's no-inline helper prevents its temporary reflection locals from remaining on the caller's stack. `Unload()` goes in `finally`; the weak reference must be the only reference escaping the helper. The default framework assemblies can be shared even though the plugin itself lives in a separate context.

### Solution and Expected Results

The provided files are the complete solution. Expected: two `native-length=3` lines, `exclusive-length=3`, plugin name `Plugin`, context `trusted-lab`, version-dependent IL hex, `answer=42`, `unloaded=True`, then PASS. A debugger can retain roots and alter unload observations; repeat outside the debugger before diagnosing a runtime defect. The bounded GC loop is diagnostic, not a real-time guarantee.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent validation should capture build output, SDK/runtime, architecture, expected values, and unload result. A compile error about the target framework means the SDK prerequisite is unmet. A native open failure reports the original Win32 code. No native buffers or unmanaged delegates are involved, so this lab does not certify their asynchronous lifetime handling.

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-Clr" -Recurse -Force
```

The fixture is deleted in `finally`; after abrupt termination remove only files matching this lab's `X3-clr-<GUID>.txt` names that you recorded, not unrelated temporary files.

- [ ] Local DotNet and CLR exercise: Build a small C# app using a disposable file handle and a benign native call with a correct signature. Inspect assembly metadata and verify cleanup on success and exception paths.
- [ ] Boundary check: Reject an unapproved type/assembly name from synthetic input and verify no dynamic load occurs. Test malformed interop inputs in a disposable process.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[DotNet and CLR Security]]

## References

- [Managed execution process](https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process)
- [AssemblyLoadContext](https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/understanding-assemblyloadcontext)
- [Assembly unloadability](https://learn.microsoft.com/en-us/dotnet/standard/assembly/unloadability)
- [GC fundamentals](https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/fundamentals)
- [Native interoperability best practices](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)
- [Dispose pattern](https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose)
