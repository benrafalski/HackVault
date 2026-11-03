---
title: "COM and DCOM"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[COM and DCOM Security]]"
updated: 2026-11-03
---
# COM and DCOM

> [!abstract] TL;DR
> Separate activation permission from method authorization; use explicit COM security configuration and supported interface contracts.

> [!info] Agent scope
> Activation; CLSID and IID; apartments; marshaling; proxies; local and remote activation security; registration.

## Prerequisites

- Windows 10/11 desktop, preinstalled VS 2022 MSVC/Windows SDK, x64 Native Tools prompt, C++ pointers/HRESULTs and Windows tokens. Standard user.
- [[Windows Lab Setup]]

## Learn

```text
Teach COM/DCOM at ABI and lifecycle depth for Windows 10/11 desktop applications.
Assume C++ vtables, HRESULT, GUIDs, reference counting, threads, tokens and DACLs.
Distinguish CLSID, IID, AppID, ProgID and object identity; trace CoCreateInstance
through class factory, server context and QueryInterface. Explain in-process,
local-server and remote activation; registry views and registration-free COM.
Teach IUnknown invariants, AddRef/Release ownership, output allocator contracts,
STA/MTA initialization, S_FALSE balancing, RPC_E_CHANGED_MODE, message pumping,
reentrancy, synchronization, proxies/stubs and apartment marshaling.
Give a complete in-memory Shell Link client, unsupported-interface check and
apartment mismatch check without saving a shortcut or changing registrations.
Explain CoInitializeSecurity versus CoSetProxyBlanket, launch/access permissions,
method authorization and current DCOM hardening requirements conceptually.
Use official primary sources, precise failure traces and answered questions.
No registration, remote activation experiment, persistence, exploitation,
privilege escalation, credential access, bypass/evasion or confidential data.
Teach in the conversation, not by editing notes, and label unexecuted examples.
```

## Cheatsheet

### Activation and Identity

| Identifier/API | Contract |
|---|---|
| CLSID | Class identity used for activation; not an interface or a live object address. |
| IID | Binary interface contract including vtable/signatures; a new incompatible interface needs a new IID. |
| AppID | Groups activation/security configuration for an application/server; not necessarily one-to-one with CLSID. |
| ProgID | Human-readable registry mapping to a CLSID, optional and mutable. |
| `CoCreateInstance` | Class-factory lookup plus instance creation for requested `CLSCTX` and IID. `CLSCTX_INPROC_SERVER` confines the requested server context, not its behavior. |
| `QueryInterface` | Returns another owned interface reference or `E_NOINTERFACE`; support is stable for the object's lifetime. Querying `IID_IUnknown` from interfaces of the same object yields canonical identity. |

In-process servers load a DLL into the caller, inheriting its process trust and failure boundary. Local-server EXEs use marshaled calls, separate lifetime and activation. DCOM adds remote transport/authentication and machine policy; a registered CLSID alone proves none of remote activation, reachability or permission.

Registration commonly maps `CLSID\{...}\InprocServer32` (path and threading model) or `LocalServer32` (server command line); AppID holds applicable security/identity settings. `HKCR` is a merged classes view, with per-user/machine and 32/64-bit view effects. Registration-free activation contexts can redirect eligible in-process components using manifests. Do not equate inspecting one registry view with proving actual activation resolution.

### Apartments and Ownership

`CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)` enters an STA; `COINIT_MULTITHREADED` enters the process MTA. Both `S_OK` and `S_FALSE` require a matching `CoUninitialize` on that thread; `RPC_E_CHANGED_MODE` does not. Release interface references before uninitializing COM. In an STA, incoming calls require pumping messages and may reenter code while an outbound call waits. Do not hold non-reentrant locks across external calls. An MTA permits concurrent calls; objects must synchronize their own state.

Never copy a non-agile raw interface pointer across apartments. `CoMarshalInterThreadInterfaceInStream` plus `CoGetInterfaceAndReleaseStream`, or the Global Interface Table, establishes proper marshaling. Proxies/stubs and NDR implement calls across boundaries; a proxy is not the server object itself. `[in]`/`[out]`, `BSTR`, `VARIANT`, SAFEARRAY and `CoTaskMemFree` contracts determine ownership, not a universal `delete` rule. Cyclic strong references leak; reference counting is not cycle collection.

### Security and Errors

`CoInitializeSecurity` sets process-wide defaults once, before implicit security initialization; a late call returns `RPC_E_TOO_LATE`. `CoSetProxyBlanket` adjusts authentication/impersonation on an applicable proxy, not arbitrary local vtable calls. Activation permission and call access are distinct from application method authorization.

| HRESULT | First diagnostic question |
|---|---|
| `0x800401F0` `CO_E_NOTINITIALIZED` | Did this thread initialize COM? |
| `0x80040154` `REGDB_E_CLASSNOTREG` | Correct context, bitness, registration/activation manifest? |
| `0x80004002` `E_NOINTERFACE` | Does the object actually implement that IID? |
| `0x80010106` `RPC_E_CHANGED_MODE` | Did earlier initialization choose a different apartment? |
| `0x80070005` `E_ACCESSDENIED` | Which activation/call/resource policy denied access? |

Use `FAILED`/`SUCCEEDED`, not `hr == 0`, for general success classification. DCOM activation hardening is enforced on updated Windows; old clients using inadequate authentication may fail even when an ACL allows them. Fix clients and patch compatibility, not the hardening requirement.

## Gotchas

- `AddRef` is ownership, not thread synchronization or permission.
- An STA without incoming/outgoing marshaled traffic can perform a short synchronous local call without a full UI loop; this does not justify blocking message pumping in a real STA server.
- Shell APIs require an appropriate Windows desktop installation; Server Core availability differs.

## Labs

### Environment and Complete Files

One file in a new scratch directory, Windows desktop and preinstalled MSVC/SDK. No registration, files written by COM, saved shortcuts, network access or elevation. This creates a Shell Link object and sets only its in-memory description.

### File: com-memory.cpp

```cpp
#include <windows.h>
#include <shobjidl.h>
#include <objbase.h>
#include <cstdio>
#include <cwchar>

int wmain() {
	HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	if (FAILED(init)) { std::printf("init=%08lX\n", static_cast<unsigned long>(init)); return 1; }
	HRESULT repeated = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	HRESULT changed = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	bool good = repeated == S_FALSE && changed == RPC_E_CHANGED_MODE;
	if (SUCCEEDED(changed)) CoUninitialize();
	if (SUCCEEDED(repeated)) CoUninitialize();
	IShellLinkW* link = nullptr;
	HRESULT created = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&link));
	if (SUCCEEDED(created)) {
		wchar_t description[64]{};
		HRESULT set = link->SetDescription(L"HackVault memory only");
		HRESULT get = link->GetDescription(description, 64);
		good = good && SUCCEEDED(set) && SUCCEEDED(get) &&
			std::wcscmp(description, L"HackVault memory only") == 0;
		IUnknown* first = nullptr;
		IPersistFile* persist = nullptr;
		IUnknown* second = nullptr;
		HRESULT identity = link->QueryInterface(IID_PPV_ARGS(&first));
		HRESULT persistence = link->QueryInterface(IID_PPV_ARGS(&persist));
		HRESULT other = persist ? persist->QueryInterface(IID_PPV_ARGS(&second)) : E_FAIL;
		good = good && SUCCEEDED(identity) && SUCCEEDED(persistence) &&
			SUCCEEDED(other) && first == second;
		IStream* unsupported = nullptr;
		HRESULT absent = link->QueryInterface(IID_PPV_ARGS(&unsupported));
		good = good && absent == E_NOINTERFACE && unsupported == nullptr;
		if (unsupported) unsupported->Release();
		if (second) second->Release();
		if (persist) persist->Release();
		if (first) first->Release();
		link->Release();
	} else {
		std::printf("activation=%08lX\n", static_cast<unsigned long>(created));
		good = false;
	}
	CoUninitialize();
	std::puts(good ? "PASS: description, identity, unsupported IID, apartment checks" : "FAIL");
	return good ? 0 : 2;
}
```

### Objectives and Steps

In the scratch directory in an x64 Native Tools command prompt:

```bat
cl /nologo /W4 /EHsc /std:c++17 com-memory.cpp /link Ole32.lib Uuid.lib
com-memory.exe
```

Predict why two different interface pointers yield the same `IUnknown` identity and why the second successful initialization needs balancing. Locate the absence of `IPersistFile::Save`; merely obtaining that interface writes nothing.

### Hints and Solution

Repeated STA initialization returns `S_FALSE`, attempting MTA on the same thread returns `RPC_E_CHANGED_MODE`, and querying `IStream` on this documented Shell Link object is expected to return `E_NOINTERFACE`. Every successful query owns one reference, including both equal `IUnknown` pointers, so both must be released. Expected PASS and exit 0; no `.lnk` file exists.

### Verification, Troubleshooting, and Cleanup

Require all four checks and no shortcut output. Class-not-registered or unsupported Shell functionality on non-desktop Windows is a platform limitation, not permission to register a replacement. Link failures require the listed SDK libraries. Delete only the source, object and executable in the scratch directory. Source reviewed, not compiled/run; parent must validate MSVC and the documented Shell component on the target Windows version. DCOM security and cross-apartment marshaling are explained, not exercised by this local in-memory lab.

- [ ] Local COM and DCOM exercise: Activate the in-memory Shell Link object and inspect interface/apartment behavior.
- [ ] Boundary check: Distinguish activation context, interface support, object identity, and method/resource authorization.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[COM and DCOM Security]]

## References

- [COM apartments](https://learn.microsoft.com/en-us/windows/win32/com/processes--threads--and-apartments)
- [CoInitializeEx](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex)
- [IUnknown::QueryInterface](https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void))
- [IShellLinkW](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ishelllinkw)
