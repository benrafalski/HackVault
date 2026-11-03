---
title: "Windows Tooling Setup"
aliases: []
tags: [windows, x0]
domain: windows
phase: "X0"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Tooling Setup

> [!abstract] TL;DR
> Keep a version inventory, clean baseline, symbol-cache location, and known-good test executable. Compare observations from at least two tools before inferring hidden behavior.

> [!info] Agent scope
> Install and verify Sysinternals, System Informer, x64dbg, Ghidra/IDA; configure symbols; link WinDbg only; tool provenance and isolation.

## Prerequisites

- A disposable Windows 11 x64 development VM with a clean powered-off checkpoint and synthetic local account. Do not join it to a corporate domain or sign in with production credentials. [[Windows Lab Setup]] describes the network/reset model.
- Approved software acquisition while keeping the host's corporate VPN and protections unchanged. If policy blocks a tool, stop that branch; do not disable endpoint security, certificate checks or the VPN.
- Allow 8 GiB guest RAM, 2-4 vCPU, a 96 GiB virtual disk, at least 30 GiB free before installation, and 10 GiB initially for symbols/projects. These are planning budgets, not measured requirements; stop before exhausting host disk/RAM.

## Learn

```text
Teach me a reproducible Windows x64 native-analysis toolchain workflow. Assume
basic Win32/C++ and an approved disposable Windows 11 VM. Cover MSVC/SDK/ASan,
Sysinternals, System Informer, x64dbg and Ghidra with an IDA alternative. Explain
official distribution provenance, Authenticode versus hashes, version inventory,
runtime prerequisites, matching PDB identity, symbol caches, least privilege and
kernel-backed tool risk. Build one complete harmless MSVC executable with a
known function and open synthetic file, then correlate process/handle/module,
disassembly and source evidence across tools. Supply exact commands and UI
steps, acceptance checks, troubleshooting, storage budgets and snapshot reset.
Never disable corporate VPN or host protections, upload samples, install an
unnecessary driver, or edit notes/status. Keep all WinDbg commands in its own
reference. Use public primary sources and explicitly label unexecuted steps.
```

## Cheatsheet

### Tool Roles and Trust

| Tool | What to use here | What it does not prove |
|---|---|---|
| MSVC v143 + Windows SDK | Produce known x64 PE/PDB files, disassemble with DUMPBIN | A clean build does not prove memory safety or runtime compatibility. |
| Process Explorer | Own process, modules, file/event handles, token overview | Missing visibility may be access policy or timing, not concealment. |
| Process Monitor | Narrow file/registry/process activity capture for the sample | Events are not a complete trace of CPU execution; capture/filtering can omit evidence. |
| System Informer | Independent own-process/module/handle view | Optional kernel-driver access expands trust and is unnecessary for the core exercise. |
| x64dbg | User-mode stepping in the self-authored x64 executable | Attaching changes timing; it cannot establish normal scheduling from one run. |
| Ghidra / IDA | Static PE import, exported function, cross-references, decompilation | Recovered pseudocode is a hypothesis; types and names can be inferred incorrectly. |
| WinDbg | Canonical Windows debugging/symbol reference | Use [[WinDbg]] for its commands; do not copy them into this page. |

Authenticode validates signed content and a certificate chain under the verifier's policy. Check **Status**, publisher identity, timestamp and the original source; an expired signing certificate can still validate with a valid timestamp. A valid signature is not a security review. A SHA-256 digest fingerprints bytes; it proves provenance only when compared to an independently trusted publisher value. An unsigned ZIP is common and not itself proof of compromise, but its source and contained executables still need review. A local hash of an untrusted download cannot authenticate itself.

No "download everything and run as administrator" shortcut: retrieve official artifacts, verify, extract without executing, inventory, then run only the required feature. Plugins, Java runtimes, debugger extensions and inspection drivers are additional executable dependencies. Do not enable cloud sample submission, VirusTotal uploads or shared project servers for this lab.

### Symbols and Build Identity

- Preserve the exact EXE, PDB, source and compiler version together. PDB matching is based on signature/GUID and age, not just basename, timestamp or proximity in a directory.
- Public Microsoft symbols primarily cover Microsoft binaries; they do not supply your private locals/types. Private PDBs may expose source paths and must remain in the VM/private evidence, not the public vault.
- Use a writable **guest-only** cache, for example `%USERPROFILE%\X0Tools\Symbols`. The standard symbol-server path syntax is `srv*C:\LabSymbolCache*https://msdl.microsoft.com/download/symbols`; substitute your actual guest cache path in each tool's symbol settings. This is a path value, not a WinDbg command.
- In Process Explorer's symbol configuration, select the x64 `dbghelp.dll` from the official Debugging Tools for Windows installation if richer stack symbols are needed; the OS copy can have reduced capabilities. Keep its matching `symsrv.dll` alongside it. Do not replace system DLLs.
- In x64dbg's symbol settings, configure the same guest cache and official server when the selected build supports that format; otherwise use its documented cache/server fields separately. Local exported names are sufficient for the required lab, so public-symbol download failure does not block the function exercise.
- Acquire symbols only over approved connectivity, then disconnect the guest's staging NIC before isolated work. Offline cache misses are expected. Never turn off TLS validation to fix a proxy issue.

### Version and Installation Matrix

| Component | Reproducible selection and steps inside the VM |
|---|---|
| MSVC | Official VS 2022 Build Tools 17.10+ in the 17.x family; Desktop development with C++, v143 x64/x86, Windows SDK 10.0.22621.0+ and C++ AddressSanitizer. Record selected component/tool versions; install via the signed Visual Studio Installer, then open its x64 Native Tools prompt. |
| Sysinternals | Official Microsoft Suite ZIP. Preserve the original filename and SHA-256 in inventory, extract into `Sysinternals`, verify `procexp64.exe`/`Procmon64.exe` Microsoft signatures, run their x64 executables and accept the license. No third-party repackaging. |
| System Informer | Official stable x64 installer/portable release from the project. Preserve release identifier and hash; verify the publisher against the project's release information. Use standard-user mode for your sample; decline optional driver/service features when available. If the chosen package requires them, leave that feature unperformed rather than altering host policy. |
| x64dbg | Official project download/snapshot linked from x64dbg.com. Snapshots are date/build identified: freeze the exact archive and SHA-256, extract the complete package, run `release\x64\x64dbg.exe` (package layout may expose `x64` directly). Do not use the x32 debugger for this binary. No plugins required. |
| Ghidra | Reference selection: official Ghidra 12.2 release asset, with 64-bit JDK 25 as specified by the current official installation guidance. Review that release's advisories/Getting Started before installing. Use the prebuilt `ghidra_<version>_<release>_<date>.zip`, not Source Code. Extract into a fresh versioned directory; launch `ghidraRun.bat`. No Gradle, Python or source build is needed for this GUI lab. |
| JDK | Official Eclipse Temurin JDK 25 x64 Windows package linked by Ghidra. Verify the MSI signature or archive's publisher checksum. Install only in the VM; record the exact patch and `java -version`. Set Ghidra's requested Java home to this JDK if another Java wins PATH. |
| IDA alternative | Obtain the licensed/free Windows x64-capable edition directly from Hex-Rays; record edition/version and verify its publisher. Use local static analysis only. Decompiler/architecture/PDB features vary by license and release; Ghidra is the complete default path here. |

Release status changes: the matrix defines an explicit reference configuration, not a claim that every named release remains the newest or vulnerability-free. If advisories require a newer release, record the replacement and its required JDK rather than silently mixing prerequisites. Reproducibility requires the actual immutable artifact inventory, not merely "latest."

## Gotchas

- Process Monitor uses a capture driver and may need elevation in the **disposable VM**. This optional capture is not justification for disabling HVCI or security software. The core program/process/disassembly checks remain usable without it.
- Internet-enabled symbol lookups, update checks, licensing and cloud analysis are different network uses. Authorize each explicitly; do not assume "offline tool" means no outbound behavior.
- Keep ASLR enabled. Compare image-relative addresses/function identity, not absolute addresses across runs. `/Od` and exported names make a learning sample easier to locate, not more representative of optimized production software.

## Labs

### Environment, Acquisition and Inventory

No host installation is required by this workflow. Use the baseline VM above and its console, with no host shares, clipboard/device redirection or saved production credentials. Obtain approved installers/media through official HTTPS sources, then transfer via a read-only ISO or equivalent approved offline medium; temporarily connected guest staging is allowed only when policy explicitly permits it and before any sensitive lab exists. Do not bridge to corporate networking.

In guest PowerShell 5.1+ create the workspace:

```powershell
$root = Join-Path $env:USERPROFILE 'X0Tools'
New-Item -ItemType Directory -Force -Path $root,"$root\Downloads","$root\Tools","$root\Symbols","$root\Sample","$root\Evidence" | Out-Null
```

Place original downloaded artifacts in `Downloads` without renaming them. Install/extract the selected tools from the matrix. For each artifact record official source URL, release/version, acquisition date, published digest if available, local digest and disposition (accepted/rejected/unverified). Generate the local-byte portion without executing the artifacts:

```powershell
Get-ChildItem "$root\Downloads" -File | ForEach-Object {
	$signature = Get-AuthenticodeSignature -LiteralPath $_.FullName
	[pscustomobject]@{
		Name = $_.Name
		SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
		SignatureStatus = $signature.Status
		Signer = $signature.SignerCertificate.Subject
	}
} | Export-Csv "$root\Evidence\artifacts.csv" -NoTypeInformation
Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture |
	Format-List | Out-File "$root\Evidence\os.txt"
```

Append the source/release information manually to a private inventory; do not treat an unsigned ZIP as automatically rejected or accepted. Check extracted EXEs using `Get-AuthenticodeSignature -LiteralPath 'full-path-to-selected-exe'` with the actual path from Explorer. If any digest/signature disagrees with publisher evidence, quarantine the artifact and stop; do not run it to find out what it is.

### Complete Native Sample

Create **probe.cpp** in `%USERPROFILE%\X0Tools\Sample`:

```cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

extern "C" __declspec(dllexport) __declspec(noinline)
int weighted(int left, int right) {
	return left * 3 + right;
}

int main() {
	static_assert(sizeof(void*) == 8);
	HANDLE file = CreateFileW(L"tool-marker.txt", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) return 2;
	constexpr char marker[] = "X0OK\r\n";
	DWORD written = 0;
	if (!WriteFile(file, marker, static_cast<DWORD>(sizeof(marker) - 1),
				   &written, nullptr) || written != sizeof(marker) - 1) {
		CloseHandle(file);
		return 3;
	}
	const int value = weighted(7, 11);
	std::printf("pid=%lu weighted=%d bytes=%lu\n", GetCurrentProcessId(), value, written);
	std::puts("Press Enter after inspecting the sample.");
	(void)std::getchar();
	if (!CloseHandle(file)) return 4;
	return value == 32 ? 0 : 1;
}
```

This program overwrites only `tool-marker.txt` in the working directory. Arguments are compile-time small integers, so its arithmetic cannot overflow in this exercise. In **x64 Native Tools Command Prompt for VS 2022**:

```bat
cd /d "%USERPROFILE%\X0Tools\Sample"
cl /Bv
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf probe.cpp /Feprobe.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
dumpbin /headers probe.exe > headers.txt
dumpbin /exports probe.exe > exports.txt
dumpbin /disasm probe.exe > disassembly.txt
probe.exe
```

### Objectives and Tool Steps

1. **Process view:** while the program waits, open Process Explorer as the same standard user, select the printed PID, inspect image path/command line and DLLs; enable the lower pane in Handles mode and locate `tool-marker.txt`. Repeat with System Informer, using only own-process visibility. Record which view supplied each fact and any denied feature.
2. **User-mode debugging:** close the first sample with Enter. Open its exact EXE in x64dbg. Use the Symbols/exports view to locate `weighted`, follow it in the disassembly and set a breakpoint through the UI. Run the new process to that breakpoint. At function entry, ECX=7 and EDX=11. Step over the function or execute until return; the scalar result in EAX should be 32. Continue and use the sample console's Enter prompt for normal cleanup. Do not attach to system or unrelated processes.
3. **Static analysis:** launch Ghidra with the selected JDK. Create a **non-shared** project under `X0Tools\Evidence`, import the exact `probe.exe`, accept PE x86 little-endian 64-bit analysis and run default analysis. Locate export `weighted`, inspect listing and decompiler, and identify multiplication/addition and callers. Load the adjacent matching PDB if the selected analyzer supports it, but the export is enough. An IDA alternative is File > Open on the same PE, local automatic analysis, then Exports > `weighted`; local edition capabilities may differ.
4. **Optional file trace:** in Process Monitor inside the VM, set filter **Process Name is probe.exe**, clear old events and capture only one new sample run. Expect a create/open, write and close for the marker; exact operation names/coalescing vary. Stop capture and save the filtered evidence privately. If the capture driver is blocked, mark this step unperformed.
5. **Symbols:** record whether `weighted` came from the export table or PDB. Configure the guest cache in an approved symbol-aware tool; record one system-module match or explicit offline cache miss. Use [[WinDbg]] exclusively for its console commands if doing additional symbol checks.

### Hints

The known result is 7 * 3 + 11 = 32. At entry the ordinary x64 integer argument positions use RCX/RDX; only the 32-bit values matter for `int`. A compiler may use `lea` rather than `imul`; do not require one exact instruction spelling. The on-disk export and live function correspond by module-relative address despite ASLR.

### Solution and Expected Observations

Expected native output: `pid=<variable> weighted=32 bytes=6`, then the Enter prompt, exit 0. `tool-marker.txt` contains `X0OK` plus CRLF. DUMPBIN reports machine `8664` and an exported `weighted`. The process owns the file handle while waiting; after exit that process and its handles are gone but the file persists. Ghidra/IDA should recover behavior equivalent to `left * 3 + right`, not necessarily the original names or formatting.

Acceptance evidence is an artifact inventory, build/OS versions, matching EXE/PDB hashes, runtime output, one live handle/module observation, one static function annotation and the debugger argument/return observation. Keep tool feature failures distinct from sample failures. For a symbol mismatch control, analyze a second build in a separate project and observe a stale PDB being rejected if the tool checks identity; never force a mismatched PDB and call the resulting names reliable.

### Verification, Troubleshooting, and Cleanup

Author validation: **all installations, builds, GUI/debugging, signature checks and symbol downloads unexecuted**. Official Ghidra installation guidance was consulted, but no selected artifact was downloaded or authenticated. Editor diagnostics do not validate native examples.

If Java is missing/wrong, inspect `java -version` inside the VM and select the required JDK, not an arbitrary JRE. If the breakpoint is not hit, confirm the x64 executable, exported function and current run, and that `/Od`/`noinline` were retained. If the live handle is missing, keep the program at its Enter prompt and check the PID. If symbols fail, check binary identity, cache permissions and approved connectivity; do not disable TLS, the firewall or VPN. Stop immediately for signature mismatch, unexpected external traffic, disk-budget breach or a request to weaken protections.

Exit the sample/debugger, stop captures, close tools, retain only the necessary private evidence, then delete `X0Tools\Sample`/projects or restore the pre-tool checkpoint. Remove optional guest-only drivers/tools through their supported uninstallers if retaining the VM. Enforce the 10 GiB cache budget by deleting only the guest cache while tools are closed. Do not delete system caches or host tools. Keep these original completion boxes unchanged until personally verified.

- [ ] Local Windows Tooling Setup exercise: Build a harmless executable and inspect its process, open file handle, loaded modules, and one function in the chosen disassembler. Record which tool supplied each observation and whether symbols matched.
- [ ] Boundary check: Verify signatures or published hashes for downloaded tools and run only the self-authored sample. Confirm the analysis VM has no shared production credentials or writable sensitive mounts.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[Sysinternals]]
- [[System Informer]]
- [[x64dbg]]
- [[Ghidra and IDA]]
- [[WinDbg]]

## References

- [Visual Studio C++ installation](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation)
- [Microsoft Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [System Informer official project](https://systeminformer.sourceforge.io/)
- [x64dbg official downloads and documentation](https://x64dbg.com/)
- [Ghidra official installation and releases](https://github.com/NationalSecurityAgency/ghidra)
- [Ghidra 12.2 release-specific JDK contract](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/README.md)
- [Ghidra security advisories](https://github.com/NationalSecurityAgency/ghidra/security/advisories)
- [Eclipse Temurin JDK releases](https://adoptium.net/temurin/releases/)
- [Hex-Rays IDA](https://hex-rays.com/ida-free)
- [Microsoft public symbol server](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols)
- [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
