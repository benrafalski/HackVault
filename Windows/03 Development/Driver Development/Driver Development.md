---
title: "Driver Development"
aliases: []
tags: [windows, x3]
domain: windows
phase: "X3"
type: tech
status: draft
pair: "[[Driver Development Security]]"
updated: 2026-11-03
---
# Driver Development

> [!abstract] TL;DR
> Record WDK/OS/build/signing state; minimize device access and IOCTL capabilities; test malformed requests, cancellation, and teardown before expanding functionality.

> [!info] Agent scope
> WDK; KMDF sample; build/sign/deploy in a disposable VM; IOCTL validation; Driver Verifier; cleanup; WinDbg links only.

## Prerequisites

- Build machine: Visual Studio 2022 C++ tools/MSVC v143 with matching Windows SDK and WDK 10.0.26100.0, WDK Visual Studio integration, x64 build environment. The project selects KMDF 1.33 and Windows 11 24H2-or-later x64 as its lab target. Record exact installed revisions; do not silently retarget.
- Target: a separate disposable Windows 11 x64 VM with a clean snapshot, console/recovery access, an approved signing policy already configured to accept the lab certificate, that certificate already trusted, and no production data. An approved signing certificate/private-key access must already exist on the signing machine. No VM, certificate, or tool installation is assumed available here.
- If any prerequisite is missing, stop at source review/build planning. Never install this driver on the host; never change Secure Boot, memory integrity, signature enforcement, host controls, or VPN to make it load. Use [[Windows Lab Setup]] and [[WinDbg]] for the corresponding setup/reference, with debugger commands only in the latter.

## Learn

```text
Teach me Windows driver development at expert depth, assuming C, Win32 I/O,
IRQL basics and Windows security descriptors. Compare UMDF, KMDF and WDM and
explain why a kernel driver is unnecessary for most automation. Trace a KMDF
non-PnP control driver from DriverEntry through device security, queue creation,
buffered IOCTL validation, completion, unload and framework object deletion.
Contrast this with real PnP/power callbacks, cancellation and pending requests.
Use a complete fixed-query driver, MSBuild project and native client with exact
build/sign/deploy/check/cleanup steps, gated on a disposable preprovisioned VM.
Explain ABI layout, input/output aliasing, IRQL, parent lifetimes, completion
byte counts, access bits, signing versus trust, WDK/runtime versions and Verifier.
Use official public sources; no dangerous capabilities or host-control changes.
Do not assume a VM exists or fabricate results. Keep debugger commands out of
the lesson and refer to a dedicated debugger reference. Teach in conversation,
not by editing files; include worked request-ownership and failure analyses.
```

## Cheatsheet

### Model and Lifecycle

| Decision | Contract |
|---|---|
| Driver model | Prefer a supported user-mode API or UMDF when possible. This KMDF program is a teaching control device, not hardware support or a production service. |
| Non-PnP | Set `WdfDriverInitNonPnpDriver`, supply `EvtDriverUnload`, and create control devices only; no `EvtDriverDeviceAdd`. |
| Initialization | Allocate `WDFDEVICE_INIT`, name/configure it, create WDFDEVICE, queue and symbolic link, then call `WdfControlFinishInitializing`. No requests before readiness. |
| Queue | Sequential dispatch limits callbacks concurrently dispatched from this queue; it does not synchronize every callback/thread in the driver. Control-device queues are not power managed. |
| IRQL | DDI-specific limits still apply. The lab selects passive execution; no pageable operations are introduced at elevated IRQL. |
| Completion | Complete each delivered request exactly once; request buffers become invalid immediately after completion. Never touch them afterward. |
| Teardown | No manually allocated resources, timers, work items, or pended requests here. For a control-only non-PnP driver, KMDF deletes control devices after `EvtDriverUnload` returns. |

A real PnP device has prepare/release-hardware, D0 entry/exit, queue stop/resume and surprise-removal paths. This control device deliberately has none: it cannot substitute for testing hardware PnP/power transitions. For long-running requests, choose framework-owned queues or a cancellation protocol with unambiguous ownership; cancellation callback and normal completion must never both complete the same request. The lab completes synchronously and therefore does not demonstrate a pending cancellation race.

### IOCTL and ABI Contract

`CTL_CODE(DeviceType, Function, Method, Access)` encodes routing, vendor function number, transfer method and required file-handle access. Here function 0x800 is in the vendor range, method is buffered, and access requires read data. The device DACL is an additional gate, not a replacement for IOCTL access bits. `FILE_ANY_ACCESS` would remove that handle-right check.

| Field | Contract |
|---|---|
| Input | Exactly 8 bytes: `ULONG Version = 1`, `ULONG Reserved = 0` |
| Output | At least 8 bytes capacity; returns exactly 8 bytes: Version 1, Value 42 |
| Unknown code | `STATUS_INVALID_DEVICE_REQUEST`, no output |
| Wrong input length/schema | `STATUS_INVALID_PARAMETER`, no output |
| Short output | `STATUS_BUFFER_TOO_SMALL`, no output |
| Success | Fully initialized fixed output; no addresses, handles, variable arrays or memory access capabilities |

For `METHOD_BUFFERED`, input and output views can alias the same system buffer. Copy required input fields to locals before initializing output. `WdfRequestRetrieveInputBuffer` validates a minimum buffer size, not message semantics; separately enforce exact version/length/reserved rules. The maximum system-buffer allocation depends on supplied lengths, so a real service also needs quotas before accepting large requests. The lab client sends only 0..12 bytes.

`METHOD_IN_DIRECT`/`OUT_DIRECT` use an MDL-backed secondary buffer with distinct access semantics; `METHOD_NEITHER` exposes user addresses requiring much more careful context/probing/lifetime treatment. None are necessary for this fixed query. An MDL or buffered copy does not validate logical contents. Avoid pointers and native `size_t` in a public cross-bitness wire structure; fixed-width fields keep the ABI stable.

### Build, Signing, and Deployment

WDK build tools supply kernel headers/libraries, the KMDF stub and framework version binding. Match SDK/WDK versions and architecture; preserve the SYS/PDB/build log together. The project is a desktop, non-PnP legacy service, so there is no INF/CAT or PnP device installation in this lab. It relies on the target's inbox compatible KMDF runtime, not a redistributed coinstaller. An actual PnP package needs its INF, catalog, package validation and supported production signing workflow.

Signing establishes provenance/integrity under policy, not correctness. A test signature is not production approval. The existing VM policy must accept the exact artifact; if it does not, stop. Do not copy old documentation's signature-enforcement workarounds. The project's `SignMode=Off` means build an unsigned artifact for a separate authorized signing step, not permission to load an unsigned driver.

## Gotchas

- Kernel C does not have user-mode CRT/exception semantics. Return NTSTATUS, check every allocation/framework call, and use SAL callback declarations.
- A WDF handle is not a WDM pointer; use the documented accessor when crossing that boundary. Parent ownership does not keep a completed request buffer usable.
- An administrator-only DACL still requires input validation. Administrators can accidentally send malformed structures, and future access policy can change.
- Driver Verifier can intentionally crash the target. Select only the lab driver in a recoverable VM; never select all drivers on a host.

## Labs

### Environment and Complete Files

Create a build directory `X3-Driver` containing these four files. The source is an original minimal implementation following the documented Microsoft KMDF control-device pattern, not a claim that a Microsoft sample binary was executed.

`Protocol.h`:

```c
#pragma once
#define IOCTL_X3_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
typedef struct _X3_INPUT {
	ULONG Version;
	ULONG Reserved;
} X3_INPUT;
typedef struct _X3_OUTPUT {
	ULONG Version;
	ULONG Value;
} X3_OUTPUT;
```

`Driver.c`:

```c
#include <ntddk.h>
#include <wdf.h>
#include "Protocol.h"
C_ASSERT(sizeof(X3_INPUT) == 8);
C_ASSERT(sizeof(X3_OUTPUT) == 8);
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD X3Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL X3Control;

VOID X3Unload(WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);
}

VOID X3Control(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputLength,
			   size_t InputLength, ULONG Code)
{
	NTSTATUS status;
	X3_INPUT* input;
	X3_OUTPUT* output;
	ULONG version;
	ULONG reserved;
	UNREFERENCED_PARAMETER(Queue);
	if (Code != IOCTL_X3_QUERY) {
		WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST); return;
	}
	if (InputLength != sizeof(X3_INPUT)) {
		WdfRequestComplete(Request, STATUS_INVALID_PARAMETER); return;
	}
	if (OutputLength < sizeof(X3_OUTPUT)) {
		WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL); return;
	}
	status = WdfRequestRetrieveInputBuffer(Request, sizeof(X3_INPUT), (PVOID*)&input, NULL);
	if (!NT_SUCCESS(status)) { WdfRequestComplete(Request, status); return; }
	version = input->Version;
	reserved = input->Reserved;
	if (version != 1 || reserved != 0) {
		WdfRequestComplete(Request, STATUS_INVALID_PARAMETER); return;
	}
	status = WdfRequestRetrieveOutputBuffer(Request, sizeof(X3_OUTPUT), (PVOID*)&output, NULL);
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
	DECLARE_CONST_UNICODE_STRING(security, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	DECLARE_CONST_UNICODE_STRING(name, L"\\Device\\X3Query");
	DECLARE_CONST_UNICODE_STRING(link, L"\\DosDevices\\X3Query");
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = X3Unload;
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
	queue.EvtIoDeviceControl = X3Control;
	status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
	if (NT_SUCCESS(status)) status = WdfDeviceCreateSymbolicLink(device, &link);
	if (!NT_SUCCESS(status)) { WdfObjectDelete(device); return status; }
	WdfControlFinishInitializing(device);
	return STATUS_SUCCESS;
}
```

`X3Query.vcxproj`:

```xml
<Project DefaultTargets="Build" ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
	<ProjectConfiguration Include="Release|x64">
	  <Configuration>Release</Configuration><Platform>x64</Platform>
	</ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
	<ProjectGuid>{CDB96A67-A26E-4C5F-953F-588068236107}</ProjectGuid>
	<WindowsTargetPlatformVersion>10.0.26100.0</WindowsTargetPlatformVersion>
	<RootNamespace>X3Query</RootNamespace>
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
	<TargetName>X3Query</TargetName><OutDir>$(ProjectDir)out\</OutDir>
	<IntDir>$(ProjectDir)obj\</IntDir><RunInf2Cat>false</RunInf2Cat>
  </PropertyGroup>
  <ItemDefinitionGroup>
	<ClCompile><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError></ClCompile>
	<Link><GenerateDebugInformation>true</GenerateDebugInformation></Link>
  </ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="Driver.c" /><ClInclude Include="Protocol.h" /></ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
```

`Client.cpp`:

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winioctl.h>
#include <cstdio>
#include <cwchar>
#include "Protocol.h"
static_assert(sizeof(X3_INPUT) == 8 && sizeof(X3_OUTPUT) == 8);

bool Check(HANDLE device, DWORD code, ULONG version, ULONG reserved,
		   DWORD inputLength, DWORD outputLength, DWORD expectedError) {
	ULONG input[3] = {version, reserved, 0};
	ULONG output[3] = {};
	DWORD returned = 0;
	BOOL success = DeviceIoControl(device, code, input, inputLength, output, outputLength, &returned, nullptr);
	DWORD error = success ? ERROR_SUCCESS : GetLastError();
	std::printf("in=%lu out=%lu error=%lu bytes=%lu\n", inputLength, outputLength, error, returned);
	if (error != expectedError) return false;
	if (success) return returned == 8 && output[0] == 1 && output[1] == 42;
	return true;
}

int wmain(int argc, wchar_t** argv) {
	bool denied = argc == 2 && std::wcscmp(argv[1], L"deny-open") == 0;
	if (argc != 2 || (!denied && std::wcscmp(argv[1], L"suite") != 0)) return 64;
	HANDLE device = CreateFileW(L"\\\\.\\X3Query", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (device == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::printf("open-error=%lu\n", error);
		return denied && error == ERROR_ACCESS_DENIED ? 0 : 1;
	}
	if (denied) { CloseHandle(device); return 1; }
	bool passed = true;
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 8, 8, 0);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 8, 12, 0);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 0, 8, ERROR_INVALID_PARAMETER);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 4, 8, ERROR_INVALID_PARAMETER);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 12, 8, ERROR_INVALID_PARAMETER);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 8, 4, ERROR_INSUFFICIENT_BUFFER);
	passed &= Check(device, IOCTL_X3_QUERY, 2, 0, 8, 8, ERROR_INVALID_PARAMETER);
	passed &= Check(device, IOCTL_X3_QUERY, 1, 1, 8, 8, ERROR_INVALID_PARAMETER);
	passed &= Check(device, CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA),
		1, 0, 8, 8, ERROR_INVALID_FUNCTION);
	for (int attempt = 0; attempt < 100; ++attempt)
		passed &= Check(device, IOCTL_X3_QUERY, 1, 0, 8, 8, 0);
	CloseHandle(device);
	HANDLE noAccess = CreateFileW(L"\\\\.\\X3Query", 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (noAccess == INVALID_HANDLE_VALUE) return 1;
	passed &= Check(noAccess, IOCTL_X3_QUERY, 1, 0, 8, 8, ERROR_ACCESS_DENIED);
	CloseHandle(noAccess);
	std::puts(passed ? "PASS: query, sizes, schema, rights" : "FAIL");
	return passed ? 0 : 1;
}
```

### Build and Sign

In the already configured x64 WDK developer environment, from the directory containing these files:

```powershell
msbuild .\X3Query.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /bl:X3Query.binlog
if ($LASTEXITCODE -ne 0) { throw 'Driver build failed' }
cl /nologo /std:c++17 /EHsc /W4 /WX /sdl Client.cpp /Fe:Client.exe
if ($LASTEXITCODE -ne 0) { throw 'Client build failed' }
$thumbprint = Read-Host 'Approved existing signing certificate thumbprint (CurrentUser My)'
if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid certificate selector' }
signtool sign /fd SHA256 /s My /sha1 $thumbprint .\out\X3Query.sys
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
signtool verify /v /pa .\out\X3Query.sys
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed' }
Get-FileHash .\out\X3Query.sys -Algorithm SHA256
```

`/sha1` selects a certificate by thumbprint; `/fd SHA256` selects the signature digest. Private-key prompts belong in the signing tool, never in notes/logs. `/pa` checks Authenticode trust, not whether kernel policy will load the driver; the VM's actual load and Code Integrity evidence are separate gates. Timestamping for distributed artifacts requires the organization's approved service and is outside this disposable lab. No certificate or trust-root creation occurs here.

### Deployment and Acceptance

Only after explicit VM identity/snapshot/signing checks, copy the signed SYS, matching PDB and Client.exe to `C:\X3QueryLab` **inside the VM**, using an approved transfer channel. Compare the target SYS SHA-256 with the build record. In the VM's elevated console:

```powershell
Set-Location C:\X3QueryLab
Get-FileHash .\X3Query.sys -Algorithm SHA256
Get-AuthenticodeSignature .\X3Query.sys
sc.exe query X3Query
```

Require service-not-found (1060) before creating this lab service; if it already exists, stop and inspect ownership rather than overwriting it. Then:

```powershell
sc.exe create X3Query type= kernel start= demand binPath= C:\X3QueryLab\X3Query.sys
if ($LASTEXITCODE -ne 0) { throw 'Create failed' }
sc.exe start X3Query
if ($LASTEXITCODE -ne 0) { throw 'Load failed; inspect signature/framework evidence without weakening policy' }
sc.exe query X3Query
.\Client.exe suite
if ($LASTEXITCODE -ne 0) { throw 'IOCTL suite failed' }
```

In a separate **non-elevated VM** console, run `C:\X3QueryLab\Client.exe deny-open`; require exit 0 with `open-error=5`. This checks the device ACL, not an IOCTL handler error. Back in the elevated console, stop/start once and repeat suite to test unload/recreation with all client handles closed:

```powershell
sc.exe stop X3Query
if ($LASTEXITCODE -ne 0) { throw 'Stop failed' }
sc.exe start X3Query
if ($LASTEXITCODE -ne 0) { throw 'Restart failed' }
.\Client.exe suite
if ($LASTEXITCODE -ne 0) { throw 'Restart suite failed' }
```

### Verifier, Hints, and Solution

After a clean baseline, take another VM snapshot. In the VM only, first inspect `verifier /querysettings`; proceed only if no unrelated verifier configuration is present. Select just this driver:

```powershell
verifier /standard /driver X3Query.sys
verifier /querysettings
```

Reboot the VM through its console, start X3Query, run the same suite, test non-elevated denial, then stop the service. Record OS build, driver hash, Verifier settings, result and any crash evidence. Use [[WinDbg]] for debugging; no debugger commands are duplicated here. If the VM cannot boot, restore the snapshot through the hypervisor rather than modifying the host.

Hints: input/output may alias, so validation must finish before output initialization. A larger output buffer does not justify returning its full size. The complete printed source is the solution: expected Value 42, exact 8-byte success, errors 87/122/1 for schema/short-output/unknown-code cases, and error 5 for access failures. No output fields are consumed on failure. Verifier should find no violation in the exercised paths; this is an acceptance goal, not an observed result.

### Cleanup and Execution Limits

In the disposable VM elevated console, with clients closed:

```powershell
sc.exe stop X3Query
sc.exe query X3Query
verifier /reset
```

Require STOPPED (or already stopped), reboot the VM, confirm `verifier /querysettings` no longer selects the lab driver, then:

```powershell
sc.exe delete X3Query
if ($LASTEXITCODE -ne 0) { throw 'Service cleanup failed' }
Set-Location C:\
Remove-Item -LiteralPath C:\X3QueryLab -Recurse -Force
```

Restore the pre-lab snapshot to remove all target changes. Do not reset unrelated Verifier settings; the prerequisite was a clean verifier configuration. Retain build artifacts only as approved, otherwise delete the dedicated build directory after leaving it.

No driver build, signing, installation, client execution, Verifier run or VM access occurred during authoring. Source/project completeness is not build certification. Parent validation owns exact WDK integration, signature acceptance and VM results. Missing VM/signing infrastructure is an explicit execution blocker, not evidence of success. This control-only lab does not cover hardware PnP/power or pending-request cancellation.

- [ ] Local Driver Development exercise: Build a benign Microsoft sample, deploy it to a snapshot-backed VM, exercise a fixed query IOCTL, then unload and restore. Use [[WinDbg]] for debugger setup/commands.
- [ ] Boundary check: Run bounded malformed-buffer tests and appropriate Verifier checks only on the disposable target; require clean errors and no leaked requests/resources.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[Windows Kernel Exploitation]]
- [[WinDbg]]
- [[Driver Development Security]]

## References

- [Non-PnP KMDF requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-kernel-mode-driver-framework-with-non-pnp-drivers)
- [Control device objects](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-control-device-objects)
- [Framework object lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/framework-object-life-cycle)
- [WdfRequestRetrieveInputBuffer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nf-wdfrequest-wdfrequestretrieveinputbuffer)
- [Defining I/O control codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)
- [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
- [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
- [Microsoft Windows driver samples](https://github.com/microsoft/Windows-driver-samples)
