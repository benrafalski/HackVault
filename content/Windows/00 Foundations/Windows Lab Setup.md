---
title: "Windows Lab Setup"
aliases: []
tags: [windows, x0]
domain: windows
phase: "X0"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Lab Setup

> [!abstract] TL;DR
> Record host/guest boundary, network mode, synthetic identities, snapshot dependency order, debugger transport, and cleanup. Keep the corporate VPN connected and unchanged.

> [!info] Agent scope
> Isolated AD lab; kernel-debug VM; host-only networking; snapshots; symbols; safe test signing in disposable VMs; reset and cleanup.

## Prerequisites

- An explicitly authorized lab hypervisor, separate from production workloads. This recipe assumes an **already enabled** Hyper-V installation on Windows 11 Pro/Enterprise x64 or Windows Server, supported hardware virtualization and administrative rights on that lab host. Do not enable/reconfigure Hyper-V on a managed corporate workstation without approval.
- Official licensed/evaluation Windows 11 Enterprise x64 media and Windows Server 2022 Desktop Experience x64 media. Record edition, build, source URL, ISO hash, license/evaluation expiry and patch date. Evaluation media must not become production infrastructure.
- A guest-only VS 2022 Build Tools 17.10+ (17.x), Desktop development with C++, v143 x64 and Windows SDK 10.0.22621.0+ package for native exercises. An approved WinDbg installation on the **lab hypervisor/debugger host** is required only for the serial-debug branch; no host kernel-debug setting is needed.
- Keep the corporate VPN connected and all host protections unchanged. If permissions, media, hardware or policy are unavailable, record the affected branch as blocked. Do not work around the restriction.

## Learn

```text
Teach me reproducible Windows lab engineering at expert depth. Assume an approved
Hyper-V lab host, public Windows media, basic PowerShell and no production data.
Design separate Windows 11 native-development, two-VM Server 2022/Windows 11 AD,
and disposable kernel-debug environments. Explain private versus host-only versus
NAT/bridged networking, device/share redirection, synthetic identities, RAM/disk/
checkpoint budgets, dependency-consistent reset and AD restore limitations.
Give complete UI/PowerShell setup, static addresses without a gateway, a minimal
synthetic domain, native MSVC x64 smoke test, isolation checks and cleanup.
Use a serial-pipe debugger target so no network debug service is exposed; keep
WinDbg console commands in the dedicated reference. Explain test-signing scope
only inside a dedicated disposable VM, never on a host. Never disable corporate
VPN, host protections or certificate checks. Distinguish prerequisites, expected
results and unexecuted requirements. No exploit chain, credential collection,
injection or page tables; no file/status edits. End with failure/reset scenarios.
```

## Cheatsheet

### Separation and Resource Budget

| Environment | VM / specification | Connectivity / purpose |
|---|---|---|
| Native development | `X0-DEV`, Win11 Enterprise x64 Gen 2, 8 GiB RAM, 4 vCPU, 96 GiB disk | Disconnected during labs; self-authored programs and trusted tools only. Secure Boot/vTPM enabled as required by supported Windows installation. |
| AD controller | `X0-DC`, Server 2022 Desktop Experience x64 Gen 2, 4 GiB RAM, 2 vCPU, 80 GiB disk | Only `X0-AD-Private`; static `172.29.50.10/24`, DNS itself, no gateway. |
| AD member | `X0-CLIENT`, Win11 Enterprise x64 Gen 2, 4 GiB RAM, 2 vCPU, 80 GiB disk | Only `X0-AD-Private`; `172.29.50.20/24`, DNS `.10`, no gateway. |
| Kernel target | `X0-KD`, Server 2022 Desktop Experience x64 **Gen 1**, 4 GiB RAM, 2 vCPU, 64 GiB disk | No virtual NIC; COM1 named pipe to approved debugger on the lab hypervisor. No drivers needed for the connection exercise. |

A 32 GiB host can run these in **stages**, not all tools/VMs at once; reserve at least 8 GiB for host operations. Plan 400 GiB free disk for the listed virtual-disk ceilings, installation media and checkpoint growth; actual allocation varies. Stop if host free disk falls below 50 GiB, any checkpoint grows beyond a planned 20 GiB budget, or the host starts sustained paging. Keep at most a clean baseline and one working checkpoint per environment. No cloud resources or billing are required; if a remote lab is chosen instead, set hard budget/expiry controls separately.

The Gen 1 kernel target intentionally models a legacy BIOS test target and **does not demonstrate Secure Boot/vTPM/HVCI parity with a modern Gen 2 host**. It is not a template for normal Windows 11 or production security. The modern development and AD guests keep their supported boot protections. A later protected-kernel exercise requires a separately designed supported target, not weakening the host to make this lab work.

### Network Boundary Table

| Hyper-V network | Reachability | Use here |
|---|---|---|
| Private | Attached guests only; no host virtual adapter | Default for AD. Verify every guest has exactly one intended NIC and no other route. |
| Internal / host-only | Guests and host can communicate | Not equivalent to isolation from host services. Use only if an explicit workflow needs it, with approved host firewall policy; not needed in this recipe. |
| NAT / Default Switch | Usually outbound via host plus host reachability | Not an isolated AD or vulnerable-target network. Never attach domain/debug guests to it. |
| External / bridged | Guests reach the physical network | Prohibited for these labs, especially corporate networks. |
| Disconnected / no NIC | No network through that adapter | Native/debug work after offline setup; does not remove shared folders, clipboard, serial or host-integration channels. |

Use a private switch instead of creating host routes or altering VPN adapters. No internet reachability probe to corporate/public addresses is necessary to verify the intended topology. Check switch attachment, guest adapters/routes, and authorized peer service reachability. A failed ping alone proves little: ICMP may be blocked while TCP is open. Do not disable guest or host firewalls to "make isolation tests pass."

Disable **session-level** clipboard, drive, printer and device redirection for lab VM connections; use basic console mode. Do not map host home directories, source repositories, password managers or corporate shares into guests. Import approved installers with a read-only ISO, detach it afterward, and export only reviewed synthetic evidence. Hypervisor integration/time synchronization are separate from file/clipboard sharing; document rather than indiscriminately disable them.

### State, Symbols and Signing

- Record VM generation/ID, OS build, NIC/switch/MAC/IP, disk locations, checkpoint set/time, local accounts, license expiry and tool versions. Keep recovery material private; never publish passwords, DSRM secrets, product keys or debugger transport secrets.
- A checkpoint is a local rollback mechanism, not a backup or malware boundary. Offline copies/exports and tested recovery are separate controls. Checkpoints also consume disk and may contain secrets.
- AD state spans machines. For this single-DC disposable forest, shut down and checkpoint/restore **both DC and member as one labeled set**. Do not mix an old DC with a newer member and assume passwords, clocks, DNS and secure channels agree. VM-Generation ID helps supported virtualized DC safeguards but does not make arbitrary snapshots equivalent to production AD recovery.
- Public symbols must match the target build; a warm cache is useful offline but cannot substitute a wrong PDB. Keep private PDBs local. [[Windows Tooling Setup]] explains provenance/cache setup; [[WinDbg]] is the sole location for WinDbg commands.
- Test-signing mode affects kernel code-integrity policy and is not required for native programs or the serial connection lab. Use it only in an explicitly disposable target for a later self-authored test-signed driver. A test signature is still required under applicable policy; HVCI can impose additional requirements. Do not disable signature enforcement or HVCI as a workaround.
- Secure Boot can prevent test-signing configuration changes. Do not override that restriction on the host or ordinary development VM; retain protections and use an approved dedicated test configuration or leave driver work blocked. No signing certificates belong in host/enterprise trust stores for this phase.

## Gotchas

- The debugger's **host** is not the kernel **target**. Boot/debug settings below belong solely to `X0-KD`; running them on the hypervisor would violate this lab.
- Do not clone a live installed domain controller as a shortcut. Build the disposable forest explicitly, or use documented AD-aware cloning in a different exercise.
- GOAD is optional later practice with a substantially different footprint and intentionally insecure configuration. This X0 lab supplies its own minimal defensive forest and does not deploy GOAD or require its automation.

## Labs

### A. Media, VMs and Isolation

All steps are a reader-run procedure, **not actions already performed**. Use official media and hash inventory, patched offline images or approved update media. Windows setup must follow the edition's supported licensing/account flow; if managed enrollment or online-only setup blocks the planned offline VM, obtain approved evaluation/enterprise media rather than bypassing enrollment. Create synthetic local administrator accounts during guest setup, with unique passwords kept locally; add a separate standard `labuser` for native programs through Settings/Computer Management.

On the **approved lab hypervisor**, create a new private switch in Hyper-V Manager > Virtual Switch Manager > New > Private, named `X0-AD-Private`. Do not select any physical NIC. Equivalent host PowerShell (requires approved administrative rights):

```powershell
if (Get-VMSwitch -Name 'X0-AD-Private' -ErrorAction SilentlyContinue) {
	throw 'Name already exists; inspect ownership before proceeding'
}
New-VMSwitch -Name 'X0-AD-Private' -SwitchType Private
Get-VMSwitch -Name 'X0-AD-Private' | Select-Object Name,SwitchType
```

In Hyper-V Manager > New Virtual Machine, create each VM using the table's exact name/generation/RAM/disk sizes and a dedicated `C:\X0Lab` storage directory on the lab host (choose a different dedicated volume only after recording it and its budget). Use fixed startup memory for predictable capacity. Configure processor counts in Settings after creation. Attach **only** the AD machines to the private switch; choose **Not Connected** for development and kernel machines. For Gen 2 guests, keep Microsoft Windows Secure Boot and enable supported vTPM as required for Windows 11. If the hypervisor cannot provide supported guest requirements, stop that branch.

Attach the appropriate ISO, boot, install the stated edition and rename the guests to match the VM names. Install approved patches/tools inside the guests from offline media, then detach media. For the Gen 1 kernel target, remove its unused network adapter in VM Settings after installation. Keep enhanced-session drive/clipboard/device redirection off per connection. Shut down and create a Hyper-V checkpoint called `X0-clean-os` for each VM before role/debug changes.

On the hypervisor verify only these lab objects, with no external reachability tests:

```powershell
$names = 'X0-DEV','X0-DC','X0-CLIENT','X0-KD'
Get-VM -Name $names | Select-Object Name,Generation,State,MemoryStartup,ProcessorCount
Get-VMNetworkAdapter -VMName $names | Select-Object VMName,Name,SwitchName,MacAddress
Get-VMSwitch -Name 'X0-AD-Private' | Select-Object Name,SwitchType
```

Expected: Private switch; DC/client connected only to it; DEV disconnected; KD has no NIC. The host should have no adapter created by this private switch. Do not change unrelated adapter/switch settings. Record the evidence before booting the AD pair.

### B. Minimal Synthetic AD Forest

Scope: one DC and one client, no trusts, no enterprise connectors, no real users, no internet route. Use elevated **Windows PowerShell 5.1 inside each guest** for setup. First check that there is exactly one active virtual Ethernet adapter and select it; this stops instead of guessing on a multihomed guest.

On **X0-DC** only:

```powershell
if ($env:COMPUTERNAME -ne 'X0-DC') { throw 'Wrong guest' }
$adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
if ($adapters.Count -ne 1) { throw 'Expected one active lab NIC' }
$index = $adapters[0].ifIndex
New-NetIPAddress -InterfaceIndex $index -IPAddress 172.29.50.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 172.29.50.10
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

These address commands assume a fresh NIC without a previous static address; inspect `Get-NetIPAddress` if rerunning instead of appending duplicate addresses. There is deliberately **no default gateway**. Promote the DC in the same guest:

```powershell
Import-Module ADDSDeployment
$dsrmPassword = Read-Host 'Unique synthetic DSRM password (keep privately)' -AsSecureString
Install-ADDSForest -DomainName 'x0.test' -DomainNetbiosName 'X0' -InstallDns `
	-SafeModeAdministratorPassword $dsrmPassword -Force
```

The guest restarts. `x0.test` is a reserved test namespace, not a corporate domain. An unavailable parent DNS delegation in this standalone forest can be expected; record warnings and do not point it at corporate DNS. After restart, sign in with the synthetic forest administrator, open DNS Manager and verify there are no configured external forwarders. No gateway means root-hint lookups cannot leave this private network; do not add a router to cure external resolution failures.

Create one unprivileged user on the DC, with no special group memberships:

```powershell
Import-Module ActiveDirectory
$userPassword = Read-Host 'Unique synthetic lab-reader password' -AsSecureString
New-ADUser -Name 'lab-reader' -SamAccountName 'lab-reader' `
	-UserPrincipalName 'lab-reader@x0.test' -AccountPassword $userPassword -Enabled $true
Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode
Get-ADUser 'lab-reader' | Select-Object SamAccountName,Enabled
Resolve-DnsName -Type SRV '_ldap._tcp.dc._msdcs.x0.test' -Server 172.29.50.10
```

On **X0-CLIENT** only, elevated Windows PowerShell:

```powershell
if ($env:COMPUTERNAME -ne 'X0-CLIENT') { throw 'Wrong guest' }
$adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
if ($adapters.Count -ne 1) { throw 'Expected one active lab NIC' }
$index = $adapters[0].ifIndex
New-NetIPAddress -InterfaceIndex $index -IPAddress 172.29.50.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 172.29.50.10
Resolve-DnsName 'x0.test' -Server 172.29.50.10
Add-Computer -DomainName 'x0.test' -Credential (Get-Credential 'X0\Administrator') -Restart
```

Enter only the synthetic lab administrator credential locally in the guest prompt. After restart, sign in interactively as `X0\lab-reader` to confirm ordinary logon, then use an appropriately authorized guest administrator session for the secure-channel check below. No RDP/WinRM listener or extra firewall exception is required for console-based administration.

Acceptance, in the client:

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,PartOfDomain
Get-NetRoute | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','::/0' }
Get-SmbMapping
Test-NetConnection 172.29.50.10 -Port 389 -InformationLevel Detailed
Test-ComputerSecureChannel -Verbose
w32tm /query /status
```

Expected: `Domain=x0.test`, domain membership true, no default route, no mapped host shares, TCP 389 reachable on **your DC only**, secure-channel true in a permitted context. Time-source/stratum output varies; record it and ensure guest clocks are reasonably aligned before diagnosing authentication. Do not disable firewalls when a probe fails; inspect the AD role installation, DNS, interface and supported role-created firewall rules. A successful port check is not proof of authorization or directory security.

### C. Native Smoke Test and Reset Proof

On **X0-DEV**, use the standard account and x64 Native Tools Command Prompt for VS 2022. Create `%USERPROFILE%\X0Smoke`, change into it, and create **smoke.cpp** with the entire source below:

```cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

int main() {
	static_assert(sizeof(void*) == 8);
	static_assert(sizeof(long) == 4);
	HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (event == nullptr) return 2;
	if (!SetEvent(event)) { CloseHandle(event); return 3; }
	const DWORD result = WaitForSingleObject(event, 0);
	const BOOL closed = CloseHandle(event);
	std::printf("pointer=%zu long=%zu wait=%lu\n", sizeof(void*), sizeof(long), result);
	return result == WAIT_OBJECT_0 && closed ? 0 : 4;
}
```

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /Od /Zi /MD /GS /guard:cf smoke.cpp /Fesmoke.exe /link /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /guard:cf
smoke.exe
echo %ERRORLEVEL%
dumpbin /headers smoke.exe
```

Expected: `pointer=8 long=4 wait=0`, exit 0, PE machine `8664`. No network or elevated runtime is needed. This is native MSVC/x64 verification, not a substitute interpreter exercise.

In guest PowerShell, create the reset marker:

```powershell
Set-Content -LiteralPath "$env:USERPROFILE\X0Smoke\reset.txt" -Value 'baseline' -Encoding ASCII
```

Shut down X0-DEV, checkpoint it as `X0-native-baseline`, boot, change the marker value to `changed`, then shut down and apply **that exact checkpoint** in Hyper-V Manager. Boot and read the marker with `Get-Content`; expected `baseline`, and `smoke.exe` must still run. Do not delete the marker manually and call that a snapshot test. Applying a checkpoint intentionally discards subsequent guest work; export needed private evidence first.

### D. Disposable Serial Kernel-Debug Target

This branch uses **X0-KD only**, not the development VM, domain guests or hypervisor kernel. Keep its NIC absent. On the approved lab hypervisor with X0-KD powered off, Hyper-V Manager > Settings > COM1 > Named pipe: enter `X0-KD-Pipe`. The equivalent hypervisor configuration is:

```powershell
if ((Get-VM -Name 'X0-KD').State -ne 'Off') { throw 'Shut down the disposable target first' }
Set-VMComPort -VMName 'X0-KD' -Number 1 -Path '\\.\pipe\X0-KD-Pipe'
Get-VMComPort -VMName 'X0-KD' | Select-Object VMName,Number,Path
```

The pipe is on the lab hypervisor, not inside the guest. Restrict its use to that approved local debugging session; do not expose it through remote shares. Start X0-KD. The following are **Windows boot-configuration commands, not WinDbg commands**, and belong only in an elevated PowerShell console **inside the disposable X0-KD guest**:

```powershell
if ($env:COMPUTERNAME -ne 'X0-KD') { throw 'STOP: these settings are guest-only' }
bcdedit.exe /dbgsettings serial debugport:1 baudrate:115200
if ($LASTEXITCODE -ne 0) { throw 'Serial configuration failed; do not change host settings' }
bcdedit.exe /debug on
if ($LASTEXITCODE -ne 0) { throw 'Guest debug enable failed' }
Restart-Computer
```

Before doing this, preserve the clean powered-off `X0-clean-os` checkpoint. Launch the approved **lab-host WinDbg UI as administrator**, as required for this serial-pipe connection; this does not enable host kernel debugging. Choose the kernel-debug attach workflow, COM transport, enable **Pipe** and **Reconnect**, use port `\\.\pipe\X0-KD-Pipe`, baud 115200 and Resets 0 where requested. Connect and boot/reboot the target if the debugger is waiting. UI labels differ between supported WinDbg editions, but transport/pipe values must match. Do not type a debugger launch command copied from another note. If elevation is not approved, mark the connection requirement blocked.

Once connected, use [[WinDbg]] for the canonical module/stack/symbol and resume commands. Required observations: debugger identifies the **target's** Server build, a break pauses the target, matching kernel symbols load or an explicit offline cache miss is recorded, and resuming lets the target console respond again. No deliberate crash or driver load is needed. A kernel break can stall all target execution; never attach this session to a work host or domain controller.

Symbol downloads occur on the debugger machine using approved connectivity; the guest remains NIC-free. Preserve the target build and symbol status. The central WinDbg note supplies console syntax, while this page supplies the full serial transport/VM setup; that is the intentional canonical-command dependency.

**Optional signing-state exercise, not needed for the connection:** make a powered-off checkpoint named `X0-before-signing` of this disposable target. Verify its VM identity in Hyper-V and its guest console; the name check alone is not proof of isolation. In an elevated PowerShell console **inside X0-KD only**, the following enables the documented test-signing boot option:

```powershell
if ($env:COMPUTERNAME -ne 'X0-KD') { throw 'STOP: disposable kernel target only' }
bcdedit.exe /set '{current}' testsigning on
if ($LASTEXITCODE -ne 0) { throw 'Policy refused test signing; stop without weakening protections' }
Restart-Computer
```

After restart, inspect `bcdedit.exe /enum '{current}'` **in that guest** and record whether `testsigning` is Yes. A Test Mode watermark can be secondary evidence, not the sole check. This permits testing appropriately test-signed kernel images under applicable policy; it is not permission to load unsigned/arbitrary code. No driver, certificate or trust-store change is required for this state-only exercise. A complete driver signing/build/deployment procedure belongs to a later driver lab.

Undo in the same disposable guest and reboot:

```powershell
if ($env:COMPUTERNAME -ne 'X0-KD') { throw 'STOP: disposable kernel target only' }
bcdedit.exe /set '{current}' testsigning off
if ($LASTEXITCODE -ne 0) { throw 'Restore the pre-signing guest checkpoint before reuse' }
Restart-Computer
```

Verify the option is No (or absent after checkpoint restore), then restore `X0-before-signing` if the baseline is uncertain. Never apply boot/signing settings or trust certificates to the hypervisor/corporate host. If protected-boot policy blocks configuration, stop and obtain an approved target rather than disabling host controls. This optional state exercise does not establish that any driver would load under HVCI or production signing policy.

### Hints

No default gateway plus a private switch is deliberate, not a networking fault. Domain join depends on the lab DNS, not a public resolver. The serial pipe lives on the hypervisor, so configuring the same text inside a second guest does not automatically connect the two VMs. Checkpoints taken while peers disagree in time/state are not a coherent AD reset.

### Solution, Reset and Acceptance

Acceptance consists of topology evidence, all native smoke checks, the `baseline -> changed -> baseline` reset proof, the minimal AD membership/secure-channel observations, and the kernel-target break/resume/symbol record. Expected values are described above; none is a measured result from authoring. Isolation evidence must include switch/NIC/route configuration, not just failed external pings.

For AD baseline creation, shut down client then DC and verify both are Off. On the approved lab host:

```powershell
$adNames = 'X0-DC','X0-CLIENT'
if (@(Get-VM -Name $adNames | Where-Object State -ne 'Off').Count -ne 0) {
	throw 'Both AD VMs must be off'
}
Checkpoint-VM -Name $adNames -SnapshotName 'X0-ad-coherent-baseline'
```

To reset, shut down both, apply that same named checkpoint to **each** through Hyper-V Manager, then boot DC first and wait for its DNS/AD services before starting the client. Rerun DNS, clock and secure-channel checks. If state is inconsistent, discard and rebuild this disposable forest from clean images; do not treat domain rejoin or password repair as proof that an inconsistent rollback was safe. Production AD uses its own supported backup/recovery procedures.

For X0-KD, disconnect the debugger, shut down the target and restore its pre-debug checkpoint. Recheck that the intended normal boot state was restored and no experimental driver/certificate remains. A checkpoint of the guest disk does not necessarily undo host-side VM hardware/pipe changes; remove the target's COM pipe through VM settings when the branch is finished.

### Troubleshooting and Cleanup

| Symptom | Investigate without weakening controls |
|---|---|
| No toolchain / wrong machine type | Confirm the installed C++ workload and x64 developer prompt; `8664` is required. |
| Domain join fails | Check single private NIC, static IP/mask, DNS `.10`, DC role readiness, credentials entered locally and time. No public DNS/gateway fix. |
| Peer port blocked | Confirm intended role/service and its scoped firewall rules inside the guest. Do not disable firewalls or scan unrelated addresses. |
| Kernel debugger waits forever | Match COM1/pipe spelling, guest boot-debug configuration and target reboot; confirm debugger runs on the hypervisor owning that pipe. |
| Symbols unavailable | Verify target build, correct cache and approved network access on the debugger side. Record offline miss; do not fake a successful symbol match. |
| Checkpoint ballooning / host pressure | Stop guests safely, preserve needed evidence, consolidate only known lab checkpoints through Hyper-V. Never delete AVHDX files by hand. |

Close sessions/captures, shut down lab guests and retain only reviewed synthetic evidence. Remove the four named lab VMs through Hyper-V Manager only after confirming ownership and retention needs; VM removal does not automatically delete all virtual disks. Delete only their recorded `C:\X0Lab` files after verifying no other VM references them. Remove `X0-AD-Private` only after no retained VM uses it. Detach media, remove disposable exports containing synthetic credentials, and retain host/VPN/security settings unchanged. For continuing study, powered-off clean snapshots are usually preferable to repeated installation.

Author validation: **no VM provisioning, networking, installs, native builds, AD operations, debugger connection, signing change, reset or tests executed**. Hypervisor availability, licensing, resource budgets, actual UI/version compatibility and all expected observations require local parent/reader validation. The native/AD labs are fully specified here; WinDbg console syntax intentionally remains in [[WinDbg]]. The following original completion items remain user-owned.

- [ ] Local Windows Lab Setup exercise: Create clean snapshots for one ordinary Windows VM and one dedicated debug target. Verify isolation and restore a deliberately changed harmless file; document how an AD lab would be separately provisioned and reset.
- [ ] Boundary check: From each lab VM, verify only explicitly intended lab peers are reachable and sensitive host shares are absent. Use harmless connectivity checks against your own endpoints only.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X0 Foundations|X0 Foundations]]
- [[WinDbg]]

## References

- [Hyper-V virtual switch configuration](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/connect-to-network)
- [Hyper-V checkpoints](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/checkpoints)
- [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/)
- [Install a new AD forest with PowerShell](https://learn.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest)
- [Virtualized domain-controller safeguards](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-technical-reference)
- [Set-VMComPort](https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmcomport)
- [Kernel debugging a Hyper-V virtual machine](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-)
- [BCDEdit debug settings](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--dbgsettings)
- [Test-signing policy and limitations](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
