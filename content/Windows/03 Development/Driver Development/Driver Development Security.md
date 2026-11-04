---
title: "Driver Development Security"
aliases: []
tags: [windows, x3, security]
domain: windows
phase: "X3"
type: security
status: draft
pair: "[[Driver Development]]"
updated: 2026-11-03
---
# Driver Development Security

> [!abstract] TL;DR
> Unsafe request handling or deployment shortcuts can expose kernel authority and destabilize the host if isolation is inadequate.

> [!info] Agent scope
> Security of: WDK; KMDF sample; build/sign/deploy in a disposable VM; IOCTL validation; Driver Verifier; cleanup; WinDbg links only. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Device namespace/DACL, handle access, IOCTL selection, length/schema interpretation, IRQL, request ownership, output initialization, deployment provenance and teardown. Kernel code must validate even requests from administrators.
- This independent lab exposes only a constant query through a restricted KMDF control device. It contains no arbitrary memory/process access, execution, address disclosure, or hardware manipulation. The baseline defect is harmless schema acceptance, not memory corruption.

## Learn

```text
Teach me defensive KMDF driver engineering at expert depth, assuming C, Win32
I/O, IRQL and ACL knowledge. Trace a request through device DACL, handle rights,
IOCTL access bits, queue dispatch, buffer retrieval, schema checks, output
initialization and exactly-once completion. Explain METHOD_BUFFERED aliasing,
direct-I/O ownership, why neither-I/O is avoided here, fixed-width ABI/version
rules, integer/length checks, quotas, cancellation races and unload ordering.
Show complete memory-safe baseline/fix source and project for a constant-query
driver, plus a bounded native regression client. Cover least privilege,
signing/deployment provenance, compiler/static checks, Driver Verifier and
snapshot recovery. Distinguish source inspection from actual VM evidence.
Use official public sources. No offensive capabilities, policy workarounds,
host controls/VPN changes or debugger commands. Do not assume a VM exists.
Teach here, not by authoring notes, and give worked failure/ownership analyses.
```

## Cheatsheet

### Layered Contract

| Layer | Lab enforcement | Failure and limit |
|---|---|---|
| Device open | Protected DACL: SYSTEM full, Administrators generic read only | Standard-user read and administrator read/write opens denied; existing handles remain capabilities |
| Namespace | Named control device, `FILE_DEVICE_SECURE_OPEN` | Applies security to namespace opens; does not validate any payload |
| IOCTL access | `FILE_READ_DATA`, not `FILE_ANY_ACCESS` | A zero-access handle cannot issue the read query |
| Routing | One exact IOCTL, vendor function 0x801 | Unknown code rejected; do not route by partially masked bits |
| Length | Exact 8-byte input; output capacity >=8 | Short/oversized input rejected before dereference; short output rejected |
| Schema | Version 1, Reserved 0 in fixed build | Unknown format rejected, not silently interpreted as current version |
| Buffer ownership | Copy input fields before output write; complete once | Buffered views may alias; pointers die at completion |
| Output | Initialize both ULONG fields; information =8 | Never return buffer capacity, kernel addresses or uninitialized padding |

`WdfRequestRetrieveInputBuffer` guarantees a minimum accessible length for a supported I/O transfer method, not semantic validity. A caller passing 12 bytes for an 8-byte schema is rejected here even if those bytes are accessible. Future extension requires an explicit version/size design, not accidental acceptance. Use fixed-width fields and static size assertions; do not put pointers, compiler-sized enums, `size_t` or architecture-dependent layouts in a public wire format.

With buffered I/O, the I/O manager supplies a system buffer and copies completion bytes back. Clearing output before reading input can destroy the input because both pointers may refer to that buffer. Direct I/O provides an MDL-backed buffer but still needs semantic/range validation. Neither I/O is not used: user pointers can be invalidated and their validity depends on context/lifetime. Kernel-mode request origin is not permission to ignore invariants.

### Ownership, IRQL, and Concurrency

- The queue dispatch callback owns completion of the delivered request. After `WdfRequestComplete*`, neither request nor retrieved buffer may be used. Returning after every error makes the single-completion invariant visible.
- A sequential queue serializes dispatched work on that queue, not callbacks from other queues, timer/DPC activity or arbitrary worker threads. This driver has no mutable device state, so parallel clients cannot alter the constant.
- Deferred requests require a cancellation design: decide whether the framework queue or driver owns the pending request, synchronize cancellation/unmarking with normal completion, and never free resources merely because cancellation was requested. This synchronous lab cannot prove that design.
- Passive execution permits passive-level DDIs but does not authorize blocking indefinitely. Avoid holding spinlocks across pageable/blocking operations; never infer IRQL from the user-mode caller.
- WDF parent ownership handles framework objects, not arbitrary allocations or outstanding references. A future timer/work item must stop/drain before deleting the context it uses. `EvtCleanupCallback` and `EvtDestroyCallback` occur at different lifetime stages.

### Build and Deployment Correctness

Driver signing identifies an artifact under target policy; it is not a safety certificate. Bind review, SYS hash, PDB, source revision, toolchain and test evidence. Rebuilding after signing changes the artifact and invalidates the association. An accepted test certificate does not authorize production deployment.

The project below selects the desktop KMDF toolset, x64, KMDF 1.33 and SDK/WDK 10.0.26100.0. Its non-PnP SCM service uses the target's inbox framework and embedded signature; there is no INF/CAT or PnP installation. A production PnP package needs its own INF/catalog validation and approved signing lifecycle. Static analysis and Verifier supplement code review; neither establishes complete safety or correct authorization by itself.

## Detection and Defense

- Record requested operation, input/output lengths, version, stable status and final byte count; avoid raw buffer dumps or addresses. This lab uses client-side diagnostics so no telemetry provider or sensitive kernel logging is introduced.
- Inspect target System/Service Control Manager and Code Integrity Operational logs for load failures. A signature-policy failure is not an IOCTL bug. Do not weaken policy to resolve it.
- Select only the lab SYS in Driver Verifier, preserve a snapshot/recovery console, and capture any crash through the approved VM workflow. Link [[WinDbg]] for debugger work; keep its command reference separate.
- No violation over this bounded suite means only that these paths survived these conditions. It does not certify PnP/power, pending cancellation, low-memory exhaustion or hostile concurrent workloads.

## Labs

### Environment and Complete Files

Build prerequisites: Windows x64, VS 2022/MSVC v143 C++ tools, Windows SDK and WDK 10.0.26100.0 with WDK integration, x64 developer environment, PowerShell 7. Target prerequisites: a **separate disposable Windows 11 24H2-or-later x64 VM**, snapshot and recovery console, approved signing policy and certificate trust already provisioned, and a VM administrator plus non-elevated test console. Signing requires an approved existing code-signing certificate with private-key access in CurrentUser My on the signing machine.

These prerequisites were not established during authoring. If absent, do not deploy. Never run driver/Verifier commands on the host, create trust roots here, disable protections, or change VPN. Create a dedicated `X3-DriverSecurity` build directory and all four files below; no companion note source is needed.

`Protocol.h`:

```c
#pragma once
#define IOCTL_X3_GUARD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
typedef struct _GUARD_INPUT {
	ULONG Version;
	ULONG Reserved;
} GUARD_INPUT;
typedef struct _GUARD_OUTPUT {
	ULONG Version;
	ULONG Value;
} GUARD_OUTPUT;
```

`Guard.c`:

```c
#include <ntddk.h>
#include <wdf.h>
#include "Protocol.h"
#ifndef X3_STRICT
#define X3_STRICT 1
#endif
C_ASSERT(sizeof(GUARD_INPUT) == 8);
C_ASSERT(sizeof(GUARD_OUTPUT) == 8);
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD GuardUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL GuardControl;

VOID GuardUnload(WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);
}

VOID GuardControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputLength,
				  size_t InputLength, ULONG Code)
{
	NTSTATUS status;
	GUARD_INPUT* input;
	GUARD_OUTPUT* output;
	ULONG version;
	ULONG reserved;
	UNREFERENCED_PARAMETER(Queue);
	if (Code != IOCTL_X3_GUARD) {
		WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST); return;
	}
	if (InputLength != sizeof(GUARD_INPUT)) {
		WdfRequestComplete(Request, STATUS_INVALID_PARAMETER); return;
	}
	if (OutputLength < sizeof(GUARD_OUTPUT)) {
		WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL); return;
	}
	status = WdfRequestRetrieveInputBuffer(Request, sizeof(GUARD_INPUT), (PVOID*)&input, NULL);
	if (!NT_SUCCESS(status)) { WdfRequestComplete(Request, status); return; }
	version = input->Version;
	reserved = input->Reserved;
#if X3_STRICT
	if (version != 1 || reserved != 0) {
		WdfRequestComplete(Request, STATUS_INVALID_PARAMETER); return;
	}
#else
	UNREFERENCED_PARAMETER(version);
	UNREFERENCED_PARAMETER(reserved);
#endif
	status = WdfRequestRetrieveOutputBuffer(Request, sizeof(GUARD_OUTPUT), (PVOID*)&output, NULL);
	if (!NT_SUCCESS(status)) { WdfRequestComplete(Request, status); return; }
	RtlZeroMemory(output, sizeof(*output));
	output->Version = 1;
	output->Value = 42;
	WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	WDF_DRIVER_CONFIG config;
	WDFDRIVER driver;
	PWDFDEVICE_INIT initialization;
	WDFDEVICE device;
	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_IO_QUEUE_CONFIG queue;
	NTSTATUS status;
	DECLARE_CONST_UNICODE_STRING(security, L"D:P(A;;GA;;;SY)(A;;GR;;;BA)");
	DECLARE_CONST_UNICODE_STRING(name, L"\\Device\\X3Guard");
	DECLARE_CONST_UNICODE_STRING(link, L"\\DosDevices\\X3Guard");
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = GuardUnload;
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
	if (!NT_SUCCESS(status)) return status;
	initialization = WdfControlDeviceInitAllocate(driver, &security);
	if (initialization == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	WdfDeviceInitSetCharacteristics(initialization, FILE_DEVICE_SECURE_OPEN, TRUE);
	WdfDeviceInitSetExclusive(initialization, FALSE);
	status = WdfDeviceInitAssignName(initialization, &name);
	if (!NT_SUCCESS(status)) { WdfDeviceInitFree(initialization); return status; }
	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.ExecutionLevel = WdfExecutionLevelPassive;
	status = WdfDeviceCreate(&initialization, &attributes, &device);
	if (!NT_SUCCESS(status)) {
		if (initialization != NULL) WdfDeviceInitFree(initialization);
		return status;
	}
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue, WdfIoQueueDispatchSequential);
	queue.PowerManaged = WdfFalse;
	queue.EvtIoDeviceControl = GuardControl;
	status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
	if (NT_SUCCESS(status)) status = WdfDeviceCreateSymbolicLink(device, &link);
	if (!NT_SUCCESS(status)) { WdfObjectDelete(device); return status; }
	WdfControlFinishInitializing(device);
	return STATUS_SUCCESS;
}
```

`X3Guard.vcxproj`:

```xml
<Project DefaultTargets="Build" ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
	<ProjectConfiguration Include="Release|x64">
	  <Configuration>Release</Configuration><Platform>x64</Platform>
	</ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
	<ProjectGuid>{7A940E7E-5831-4629-96AD-199F56CB688B}</ProjectGuid>
	<WindowsTargetPlatformVersion>10.0.26100.0</WindowsTargetPlatformVersion>
	<RootNamespace>X3Guard</RootNamespace>
	<StrictSchema Condition="'$(StrictSchema)'==''">1</StrictSchema>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration">
	<ConfigurationType>Driver</ConfigurationType>
	<PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
	<DriverType>KMDF</DriverType><DriverTargetPlatform>Desktop</DriverTargetPlatform>
	<TargetVersion>Windows10</TargetVersion><UseDebugLibraries>false</UseDebugLibraries>
	<KMDF_VERSION_MAJOR>1</KMDF_VERSION_MAJOR><KMDF_VERSION_MINOR>33</KMDF_VERSION_MINOR>
	<SignMode>Off</SignMode>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup>
	<TargetName>X3Guard</TargetName><OutDir>$(ProjectDir)out\$(StrictSchema)\</OutDir>
	<IntDir>$(ProjectDir)obj\$(StrictSchema)\</IntDir><RunInf2Cat>false</RunInf2Cat>
  </PropertyGroup>
  <ItemDefinitionGroup>
	<ClCompile>
	  <WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError>
	  <PreprocessorDefinitions>X3_STRICT=$(StrictSchema);%(PreprocessorDefinitions)</PreprocessorDefinitions>
	</ClCompile>
	<Link><GenerateDebugInformation>true</GenerateDebugInformation></Link>
  </ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="Guard.c" /><ClInclude Include="Protocol.h" /></ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
```

`GuardClient.cpp`:

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winioctl.h>
#include <cstdio>
#include <cwchar>
#include <initializer_list>
#include "Protocol.h"
static_assert(sizeof(GUARD_INPUT) == 8 && sizeof(GUARD_OUTPUT) == 8);

bool Query(HANDLE device, DWORD code, ULONG version, ULONG reserved,
		   DWORD inputLength, DWORD outputLength, DWORD expectedError) {
	ULONG input[3] = {version, reserved, 0};
	ULONG output[3] = {};
	DWORD returned = 0;
	BOOL success = DeviceIoControl(device, code, input, inputLength, output, outputLength, &returned, nullptr);
	DWORD error = success ? ERROR_SUCCESS : GetLastError();
	std::printf("version=%lu reserved=%lu in=%lu out=%lu error=%lu bytes=%lu\n",
		version, reserved, inputLength, outputLength, error, returned);
	if (error != expectedError) return false;
	return !success || (returned == 8 && output[0] == 1 && output[1] == 42);
}

HANDLE Open(DWORD access) {
	return CreateFileW(L"\\\\.\\X3Guard", access, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) return 64;
	bool baseline = std::wcscmp(argv[1], L"baseline") == 0;
	bool denied = std::wcscmp(argv[1], L"deny-open") == 0;
	if (!baseline && !denied && std::wcscmp(argv[1], L"fixed") != 0) return 64;
	HANDLE device = Open(GENERIC_READ);
	if (device == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::printf("open-error=%lu\n", error);
		return denied && error == ERROR_ACCESS_DENIED ? 0 : 1;
	}
	if (denied) { CloseHandle(device); return 1; }
	bool passed = true;
	passed &= Query(device, IOCTL_X3_GUARD, 1, 0, 8, 8, 0);
	passed &= Query(device, IOCTL_X3_GUARD, 1, 0, 8, 12, 0);
	DWORD schemaError = baseline ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
	passed &= Query(device, IOCTL_X3_GUARD, 2, 0, 8, 8, schemaError);
	passed &= Query(device, IOCTL_X3_GUARD, 1, 1, 8, 8, schemaError);
	for (DWORD length : {0UL, 4UL, 12UL})
		passed &= Query(device, IOCTL_X3_GUARD, 1, 0, length, 8, ERROR_INVALID_PARAMETER);
	for (DWORD length : {0UL, 4UL})
		passed &= Query(device, IOCTL_X3_GUARD, 1, 0, 8, length, ERROR_INSUFFICIENT_BUFFER);
	passed &= Query(device, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA),
		1, 0, 8, 8, ERROR_INVALID_FUNCTION);
	for (int attempt = 0; attempt < 100; ++attempt)
		passed &= Query(device, IOCTL_X3_GUARD, 1, 0, 8, 8, 0);
	CloseHandle(device);
	HANDLE broad = Open(GENERIC_READ | GENERIC_WRITE);
	if (broad != INVALID_HANDLE_VALUE) { CloseHandle(broad); passed = false; }
	else if (GetLastError() != ERROR_ACCESS_DENIED) { passed = false; }
	HANDLE noAccess = Open(0);
	if (noAccess == INVALID_HANDLE_VALUE) return 1;
	passed &= Query(noAccess, IOCTL_X3_GUARD, 1, 0, 8, 8, ERROR_ACCESS_DENIED);
	CloseHandle(noAccess);
	std::puts(passed ? "PASS: schema, lengths, rights, repeatability" : "FAIL");
	return passed ? 0 : 1;
}
```

### Build, Sign, and Preserve Evidence

In the configured WDK build directory, build both modes into separate outputs. `StrictSchema=0` is the synthetic baseline; default/1 is the fixed implementation. The same length/ownership checks remain active in both.

```powershell
msbuild .\X3Guard.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:StrictSchema=0 /bl:baseline.binlog
if ($LASTEXITCODE -ne 0) { throw 'Baseline build failed' }
msbuild .\X3Guard.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:StrictSchema=1 /bl:fixed.binlog
if ($LASTEXITCODE -ne 0) { throw 'Fixed build failed' }
cl /nologo /std:c++17 /EHsc /W4 /WX /sdl GuardClient.cpp /Fe:GuardClient.exe
if ($LASTEXITCODE -ne 0) { throw 'Client build failed' }
$thumbprint = Read-Host 'Approved existing certificate thumbprint (CurrentUser My)'
if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid certificate selector' }
foreach ($mode in @('0','1')) {
	$binary = ".\out\$mode\X3Guard.sys"
	signtool sign /fd SHA256 /s My /sha1 $thumbprint $binary
	if ($LASTEXITCODE -ne 0) { throw "Signing failed: $mode" }
	signtool verify /v /pa $binary
	if ($LASTEXITCODE -ne 0) { throw "Signature verification failed: $mode" }
	Get-FileHash $binary -Algorithm SHA256
}
```

`/sha1` selects the certificate; the signature uses SHA-256. `/pa` is Authenticode validation, not kernel-load-policy certification. No trust store or boot policy is changed. Missing approved signing access or rejected signature means stop, not weaken policy. Static code analysis can be requested on the fixed project with `/p:RunCodeAnalysis=true`; record exact tool diagnostics rather than asserting zero findings without running it.

### Baseline Deployment in the Disposable VM

After confirming the VM identity, clean snapshot, recovery access, existing signing policy and no unrelated Verifier settings, copy artifacts through an approved channel into:

```text
C:\X3GuardLab\GuardClient.exe
C:\X3GuardLab\baseline\X3Guard.sys
C:\X3GuardLab\baseline\X3Guard.pdb
C:\X3GuardLab\fixed\X3Guard.sys
C:\X3GuardLab\fixed\X3Guard.pdb
```

The PDBs must match their respective builds. Verify hashes against the build record. In the **VM's** elevated console:

```powershell
Set-Location C:\X3GuardLab
Get-FileHash .\baseline\X3Guard.sys, .\fixed\X3Guard.sys -Algorithm SHA256
Get-AuthenticodeSignature .\baseline\X3Guard.sys, .\fixed\X3Guard.sys
sc.exe query X3Guard
verifier /querysettings
```

Require service-not-found (1060) and no unrelated Verifier configuration before continuing. Never overwrite an existing unknown service. Then:

```powershell
sc.exe create X3Guard type= kernel start= demand binPath= C:\X3GuardLab\baseline\X3Guard.sys
if ($LASTEXITCODE -ne 0) { throw 'Create failed' }
sc.exe start X3Guard
if ($LASTEXITCODE -ne 0) { throw 'Load failed; inspect evidence without weakening policy' }
.\GuardClient.exe baseline
if ($LASTEXITCODE -ne 0) { throw 'Baseline checks failed' }
```

### Objectives, Hints, and Fixed Retest

Explain why the baseline's accepted Version 2 and Reserved 1 are format-contract failures even though they cannot read/write arbitrary memory. Identify independent device-open and handle-right gates. Verify output capacity 12 still produces only 8 returned bytes. Never consume output fields after a failed IOCTL.

Hint: fixing schema acceptance must not change the DACL, transfer method, lengths or constant result. Stop the old driver before selecting the new signed binary; do not overwrite a loaded SYS.

VM elevated console, after all baseline clients exit:

```powershell
sc.exe stop X3Guard
if ($LASTEXITCODE -ne 0) { throw 'Stop failed' }
sc.exe config X3Guard binPath= C:\X3GuardLab\fixed\X3Guard.sys
if ($LASTEXITCODE -ne 0) { throw 'Config failed' }
sc.exe start X3Guard
if ($LASTEXITCODE -ne 0) { throw 'Fixed load failed' }
.\GuardClient.exe fixed
if ($LASTEXITCODE -ne 0) { throw 'Fixed regression failed' }
```

In a separate **non-elevated VM** console:

```powershell
C:\X3GuardLab\GuardClient.exe deny-open
if ($LASTEXITCODE -ne 0) { throw 'Device ACL regression' }
```

Expected: baseline schema cases succeed; fixed returns error 87 for those same cases. Both reject input sizes 0/4/12 with 87, output sizes 0/4 with 122, unknown IOCTL with 1, administrator read/write open with 5, and query on a zero-access handle with 5. Valid requests still return Version 1, Value 42, exactly 8 bytes through 100 repetitions. Non-elevated read open returns 5 before dispatch. The printed strict build is the complete solution; expected values are not recorded execution.

### Verifier and Cleanup

Take a new snapshot before stress verification. In the disposable VM elevated console only:

```powershell
verifier /standard /driver X3Guard.sys
verifier /querysettings
```

Reboot through the VM console, start X3Guard, rerun the fixed suite and standard-user denial. Stop/start and rerun once more with all handles closed. Preserve Verifier settings, driver hash, OS version, client output and any crash evidence. If recovery is needed, restore the VM snapshot; refer to [[WinDbg]] for debugger procedures. Do not modify the host or enable Verifier for unrelated drivers.

With clients closed, VM elevated cleanup:

```powershell
sc.exe stop X3Guard
sc.exe query X3Guard
verifier /reset
```

Require STOPPED (or already stopped), reboot the VM, confirm no lab Verifier selection remains, then:

```powershell
sc.exe delete X3Guard
if ($LASTEXITCODE -ne 0) { throw 'Delete failed' }
Set-Location C:\
Remove-Item -LiteralPath C:\X3GuardLab -Recurse -Force
```

Restore the original snapshot. Delete only the dedicated build directory when evidence retention is complete; no host certificates or settings were added by these steps.

### Execution Limits

No build, static analyzer, signing tool, installation, client or Verifier command was executed during authoring; no disposable VM was available or claimed. Exact project/toolset compatibility, signature acceptance, status mappings and unload behavior require parent validation. This is a bounded synchronous control-device exercise, not PnP/hardware/power coverage or a pending-cancellation stress suite. A build or signature failure leaves that gate incomplete; do not reinterpret it as a pass.

- [ ] Local Driver Development exercise: Build a benign Microsoft sample, deploy it to a snapshot-backed VM, exercise a fixed query IOCTL, then unload and restore. Use [[WinDbg]] for debugger setup/commands.
- [ ] Boundary check: Run bounded malformed-buffer tests and appropriate Verifier checks only on the disposable target; require clean errors and no leaked requests/resources.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[Windows Kernel Exploitation]]
- [[WinDbg]]
- [[Driver Development]]

## References

- [Security issues for I/O control codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes)
- [Controlling device access](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/controlling-device-access-in-kmdf-drivers)
- [WDF buffer access](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/accessing-data-buffers-in-wdf-drivers)
- [Completing I/O requests](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/completing-i-o-requests)
- [Non-PnP KMDF requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-kernel-mode-driver-framework-with-non-pnp-drivers)
- [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
- [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
