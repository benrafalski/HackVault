---
title: "Windows Roadmap"
aliases: []
tags: [windows, roadmap]
domain: windows
phase: ""
type: moc
status: draft
pair: ""
updated: 2026-11-02
---
# Windows Roadmap

[[index|Home]] | [[Windows Labs]] | [[Tools Index]]

Work in phase order. Check each note only after meeting its learning and lab goals; complete both sides of every pair. Status progression: stub -> draft -> learning -> practiced -> mastered.

## X0 Foundations

### Phase Goal

Read x64 code and the Windows ABI, build small native programs, and prepare isolated user-mode, AD, and kernel-debug labs.

### Notes

- [ ] [[x64 Assembly and Windows ABI]]
- [ ] [[x64 Assembly and Windows ABI Security]]
- [ ] [[C and CPP on Windows]]
- [ ] [[C and CPP on Windows Security]]
- [ ] [[Windows Architecture Overview]]
- [ ] [[Windows Architecture Overview Security]]
- [ ] [[Windows Tooling Setup]]
- [ ] [[Windows Lab Setup]]

### Labs

- [ ] [Microsoft C++ documentation](https://learn.microsoft.com/cpp/): local MSVC exercises
- [ ] [GOAD](https://github.com/Orange-Cyberdefense/GOAD): isolated AD lab
- [ ] [Windows debugging setup](https://learn.microsoft.com/windows-hardware/drivers/debugger/): dedicated debug VMs

### Exit Criteria

- [ ] Build and inspect a native executable, explain a call at the ABI level, and verify snapshots, isolation, symbols, and a kernel-debug connection using the central WinDbg note.

## X1 User-mode Internals

### Phase Goal

Explain user-mode objects, process state, security decisions, system interfaces, and telemetry without revisiting page tables.

### Notes

- [ ] [[Processes and Threads]]
- [ ] [[Processes and Threads Security]]
- [ ] [[Virtual Memory]]
- [ ] [[Virtual Memory Security]]
- [ ] [[PE Format]]
- [ ] [[PE Format Security]]
- [ ] [[Loader and DLLs]]
- [ ] [[Loader and DLLs Security]]
- [ ] [[Win32 Native API and Syscalls]]
- [ ] [[Win32 Native API and Syscalls Security]]
- [ ] [[Objects and Handles]]
- [ ] [[Objects and Handles Security]]
- [ ] [[Windows Security Model]]
- [ ] [[Windows Security Model Security]]
- [ ] [[Registry]]
- [ ] [[Registry Security]]
- [ ] [[Services and SCM]]
- [ ] [[Services and SCM Security]]
- [ ] [[Scheduled Tasks]]
- [ ] [[Scheduled Tasks Security]]
- [ ] [[Windows IPC]]
- [ ] [[Windows IPC Security]]
- [ ] [[COM and DCOM]]
- [ ] [[COM and DCOM Security]]
- [ ] [[Exceptions and SEH]]
- [ ] [[Exceptions and SEH Security]]
- [ ] [[NTFS]]
- [ ] [[NTFS Security]]
- [ ] [[WMI]]
- [ ] [[WMI Security]]
- [ ] [[ETW and Event Log]]
- [ ] [[ETW and Event Log Security]]

### Labs

- [ ] [Sysinternals](https://learn.microsoft.com/sysinternals/): local observation exercises
- [ ] Small self-authored Win32 programs in a snapshot-backed VM
- [ ] [HTB Academy](https://academy.hackthebox.com/): Windows internals and security modules

### Exit Criteria

- [ ] Complete each pair's observation exercise; trace a process, module load, handle access check, IPC exchange, and event record using documented evidence.

## X2 Kernel and Platform

### Phase Goal

Understand kernel execution constraints, driver interfaces, boot trust, virtualization protections, and supported extension points.

### Notes

- [ ] [[Kernel Architecture]]
- [ ] [[Kernel Architecture Security]]
- [ ] [[Windows Drivers]]
- [ ] [[Windows Drivers Security]]
- [ ] [[Kernel Callbacks and Minifilters]]
- [ ] [[Kernel Callbacks and Minifilters Security]]
- [ ] [[WFP]]
- [ ] [[WFP Security]]
- [ ] [[Windows Boot Process]]
- [ ] [[Windows Boot Process Security]]
- [ ] [[Windows Virtualization Security]]
- [ ] [[Windows Virtualization Security Security]]
- [ ] [[PatchGuard]]
- [ ] [[PatchGuard Security]]

### Labs

- [ ] [Windows driver samples](https://github.com/microsoft/Windows-driver-samples): benign sample drivers
- [ ] Dedicated kernel-debug VM with snapshots
- [ ] [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver): interface study in an isolated VM

### Exit Criteria

- [ ] Trace a benign driver's I/O path, explain IRQL and callback constraints, and verify boot and virtualization protections in a disposable VM.

## X3 Development

### Phase Goal

Build observable Windows automation, managed applications, native programs, COM components, and drivers.

### Notes

- [ ] [[PowerShell]]
- [ ] [[PowerShell Security]]
- [ ] [[DotNet and CLR]]
- [ ] [[DotNet and CLR Security]]
- [ ] [[Win32 Programming]]
- [ ] [[Win32 Programming Security]]
- [ ] [[COM Programming]]
- [ ] [[COM Programming Security]]
- [ ] [[Driver Development]]
- [ ] [[Driver Development Security]]

### Labs

- [ ] Local PowerShell, .NET, Win32, and COM exercises
- [ ] [Windows driver samples](https://github.com/microsoft/Windows-driver-samples): disposable development VM

### Exit Criteria

- [ ] Complete each pair's build exercises, test input and privilege boundaries, and explain the relevant runtime, resource-lifetime, and deployment rules.

## X4 Enterprise

### Phase Goal

Trace enterprise identity, remote administration, directory, certificate, and policy protocols across trust boundaries.

### Notes

- [ ] [[SMB]]
- [ ] [[SMB Security]]
- [ ] [[RDP]]
- [ ] [[RDP Security]]
- [ ] [[WinRM]]
- [ ] [[WinRM Security]]
- [ ] [[LDAP]]
- [ ] [[LDAP Security]]
- [ ] [[NTLM]]
- [ ] [[NTLM Security]]
- [ ] [[Kerberos]]
- [ ] [[Kerberos Security]]
- [ ] [[Active Directory]]
- [ ] [[Active Directory Security]]
- [ ] [[Group Policy]]
- [ ] [[Group Policy Security]]
- [ ] [[AD CS]]
- [ ] [[AD CS Security]]
- [ ] [[LAPS]]
- [ ] [[LAPS Security]]
- [ ] [[Entra ID and Hybrid]]
- [ ] [[Entra ID and Hybrid Security]]
- [ ] [[Windows SQL Server]]
- [ ] [[Windows SQL Server Security]]

### Labs

- [ ] [GOAD](https://github.com/Orange-Cyberdefense/GOAD): isolated enterprise lab
- [ ] [HTB Academy](https://academy.hackthebox.com/): AD and enterprise modules
- [ ] [HTB Pro Labs](https://www.hackthebox.com/hacker/pro-labs): authorized practice

### Exit Criteria

- [ ] In a disposable AD lab, trace logon and service authentication, inspect directory and certificate permissions, and verify remote-management and policy hardening.

## X5 Offensive

### Phase Goal

Understand Windows and AD attack prerequisites and observable behavior using explicitly authorized disposable labs.

### Notes

- [ ] [[Windows Local Privilege Escalation]]
- [ ] [[Windows Credential Access]]
- [ ] [[Windows Lateral Movement]]
- [ ] [[Windows Persistence]]
- [ ] [[AD Attacks]]
- [ ] [[Windows Evasion]]
- [ ] [[Process Injection]]

### Labs

- [ ] [HTB Academy](https://academy.hackthebox.com/): relevant CPTS/CAPE path modules where available
- [ ] [GOAD](https://github.com/Orange-Cyberdefense/GOAD): isolated AD practice
- [ ] [HTB Pro Labs](https://www.hackthebox.com/hacker/pro-labs): authorized targets

### Exit Criteria

- [ ] Complete a controlled lab for every technique, identify prerequisite permissions and telemetry, and demonstrate a relevant mitigation or detection with cleanup.

## X6 Exploit Dev

### Phase Goal

Analyze memory-corruption primitives, mitigations, and exploitability in isolated educational binaries and drivers.

### Notes

- [ ] [[Windows Exploit Mitigations]]
- [ ] [[Windows Stack and SEH Overflows]]
- [ ] [[Windows Heap Exploitation]]
- [ ] [[ROP on Windows]]
- [ ] [[Windows Kernel Exploitation]]
- [ ] [[Malware Analysis and RE]]

### Labs

- [ ] [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver): isolated kernel lab
- [ ] [Exploit Education](https://exploit.education/) and [Corelan](https://www.corelan.be/): relevant fundamentals and Windows exercises
- [ ] [pwn.college](https://pwn.college/): CSE466 fundamentals where available
- [ ] Dedicated offline malware-analysis VM using vetted training samples

### Exit Criteria

- [ ] Document reproducible user-mode and HEVD lab cases, explain the primitive and applicable mitigations, and complete a static/dynamic analysis writeup without handling production targets.

## X7 Defense

### Phase Goal

Deploy Windows prevention and telemetry controls, understand their limitations, and verify detection and hardening outcomes.

### Notes

- [ ] [[Defender and EDR Architecture]]
- [ ] [[Defender and EDR Architecture Security]]
- [ ] [[Sysmon]]
- [ ] [[Sysmon Security]]
- [ ] [[ETW-TI]]
- [ ] [[ETW-TI Security]]
- [ ] [[AppLocker and WDAC]]
- [ ] [[AppLocker and WDAC Security]]
- [ ] [[ASR Rules]]
- [ ] [[ASR Rules Security]]
- [ ] [[Detection Engineering]]
- [ ] [[Detection Engineering Security]]
- [ ] [[Windows Hardening Baselines]]
- [ ] [[Windows Hardening Baselines Security]]

### Labs

- [ ] [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon): local telemetry lab
- [ ] [Microsoft security documentation](https://learn.microsoft.com/windows/security/): policy and baseline exercises
- [ ] [Sigma](https://github.com/SigmaHQ/sigma): rule validation against lab logs

### Exit Criteria

- [ ] Apply a test baseline, collect representative telemetry, validate Sigma/KQL detections, and document a controlled limitation test and compensating control for each pair.
