---
title: "COM Programming Security"
aliases: []
tags: [windows, x3, security]
domain: windows
phase: "X3"
type: security
status: draft
pair: "[[COM Programming]]"
updated: 2026-11-03
---
# COM Programming Security

> [!abstract] TL;DR
> Reference-count errors, unsafe marshaling, writable registration, and overtrusted callers can corrupt memory or misuse a privileged server.

> [!info] Agent scope
> Security of: Interface implementation; IUnknown; reference counting; apartments; marshaling; activation; registration; HRESULT handling. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- CLSID resolution, binary/registry ownership, activation permissions, proxy security, operation authorization, VARIANT/BSTR contracts, reference cycles and cross-apartment state.
- Lab boundary: a standard-user local server and separate same-user client with fixed synthetic records. No elevation, other-user targeting, registration modification, custom marshal packets or privileged impersonation.

## Learn

```text
Teach me defensive native COM engineering at expert depth. Assume IUnknown,
apartments and Win32 ACL knowledge. Separate activation/access security from
per-method authorization, proxy blanket settings, caller identity and server
execution identity. Explain secure registration/deployment, authentication and
impersonation levels, dynamic cloaking caveats, reentrancy, reference cycles,
HRESULT/out-parameter contracts, VARIANT/BSTR validation and trusted marshaling.
Use a genuine local IDispatch server/client with harmless baseline/fix requests,
strict argument validation, packet privacy, and cleanup tests. State precisely
which cross-process checks do not prove cross-user authorization. Explain how
an actual privileged service would derive authorization from authenticated
caller context rather than user-supplied role strings. Use official sources;
no offensive operations, host policy changes, or untrusted marshaling streams.
Teach in this conversation rather than authoring notes, with worked reviews.
```

## Cheatsheet

### Distinct Security Decisions

| Layer | What it establishes | What it does not establish |
|---|---|---|
| Registration and binary ACLs | Approved CLSID resolves to expected executable/DLL | Caller may use every operation |
| Launch/activation permissions | A caller may activate a server/class | Per-record authorization |
| COM access policy | Authenticated calls may enter the process | Business meaning of a record identifier |
| Proxy blanket | Authentication service/level and impersonation level for that proxy | A malicious server becomes trustworthy |
| Method validation | Correct VARIANT types, counts, length and domain | User-supplied role strings are genuine identities |
| Method authorization | Authenticated principal/capability permits an operation | Resource invariants survive reentrant callbacks |

`CoInitializeSecurity` runs once before implicit security initialization. Packet privacy requests integrity/confidentiality at the RPC layer, but local authorization still needs an explicit policy. `CoSetProxyBlanket` applies to a proxy; querying a different interface may yield another proxy whose policy must be checked. `RPC_C_IMP_LEVEL_IDENTIFY` allows identity inspection, not acting with the client's authority. Avoid requesting delegation for local read-only work.

An actual privileged server must derive identity from COM/RPC caller context, perform the required access checks, and keep impersonation tightly scoped with guaranteed reversion before unrelated work. Do not accept a string such as `role=admin` as proof. This lab intentionally does not impersonate and runs without privilege: it tests a fixed operation allowlist across a real process boundary, not a multiuser broker.

### ABI, Marshaling, and Lifetime

- `IDispatch::Invoke` arguments are reversed in `rgvarg`; named arguments require separate handling. This interface accepts exactly one positional BSTR, rejects BYREF/array variants and embedded NUL, and initializes result before any failure.
- `SysStringLen` gives BSTR length including embedded NUL characters in the data; `wcslen` stops at the first NUL and is not sufficient validation. `VariantClear` releases an owned BSTR/interface inside a VARIANT.
- QI availability must remain static; authorization should return a method HRESULT such as `E_ACCESSDENIED`, not hide/reveal interfaces based on the caller. `DISP_E_TYPEMISMATCH`, `DISP_E_BADPARAMCOUNT`, and `E_INVALIDARG` distinguish contracts.
- Do not unmarshal streams received from untrusted storage/network sources. Marshaling can activate code; treating an OBJREF as passive data is unsafe. The lab lets COM perform trusted local activation and system `IDispatch` marshaling.
- Releasing one interface does not guarantee a server exits: class factories, other clients, connection points, marshaling packets and server locks can retain references. The example uses explicit console-controlled server lifetime, not a production idle-shutdown algorithm.

### Baseline and Fixed Policy

Baseline accepts any syntactically valid known record, including `private`, and returns only `synthetic-private`. Fixed mode permits only `alpha`; the same request for `private` returns `E_ACCESSDENIED`. Both modes validate type/length. The difference is authorization, not parser hardening or authentication, and neither mode touches real private information.

## Detection and Defense

- Audit expected CLSID, server path/hash/signature, registry view, deployment owner and application HRESULTs. DCOM activation diagnostics can explain startup denial but do not prove a method allowed the right record.
- Track rejected operation names without logging BSTR contents indiscriminately. Count live objects and outstanding operations; combine logs with stress/reentrancy tests, not just a successful activation.
- Per-user registration is not suitable as a trusted dependency for an elevated broker. Keep production binaries and registration under appropriate administrative ownership; this lab writes neither.

## Labs

### Environment and Complete File

Windows 11 x64, MSVC v143, Windows SDK 10.0.26100.x, PowerShell 7, two standard-user terminals under the same test account. Create `$env:TEMP\X3-ComSecurity` and `Records.cpp`. System Automation marshaling handles `IDispatch`; no custom proxy DLL, IDL, installation, or registry file is required. Start the server manually before the client; runtime registration is not an auto-launch installation.

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wrl/client.h>
#include <atomic>
#include <cstdio>
#include <cwchar>
#include <new>
using Microsoft::WRL::ComPtr;
const CLSID CLSID_Records = {0xf6a354dc,0x0c73,0x4de5,{0x99,0xf9,0x89,0x76,0x16,0x2a,0x1e,0x33}};
std::atomic<long> liveObjects{0};
struct Failure { HRESULT code; };
void Check(HRESULT result) { if (FAILED(result)) throw Failure{result}; }
struct Apartment {
	Apartment() { Check(CoInitializeEx(nullptr, COINIT_MULTITHREADED)); }
	~Apartment() { CoUninitialize(); }
};
struct Variant {
	VARIANT value;
	Variant() { VariantInit(&value); }
	~Variant() { VariantClear(&value); }
	Variant(const Variant&) = delete;
	Variant& operator=(const Variant&) = delete;
};

class Records final : public IDispatch {
	std::atomic<ULONG> references{1};
	const bool baseline;
public:
	explicit Records(bool mode) : baseline(mode) { ++liveObjects; }
	~Records() { --liveObjects; }
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override {
		if (!output) return E_POINTER;
		*output = nullptr;
		if (iid != IID_IUnknown && iid != IID_IDispatch) return E_NOINTERFACE;
		*output = static_cast<IDispatch*>(this); AddRef(); return S_OK;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
	ULONG STDMETHODCALLTYPE Release() override {
		ULONG remaining = --references; if (!remaining) delete this; return remaining;
	}
	HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override {
		if (!count) return E_POINTER; *count = 0; return S_OK;
	}
	HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo** output) override {
		if (!output) return E_POINTER; *output = nullptr; return DISP_E_BADINDEX;
	}
	HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID iid, LPOLESTR* names, UINT count,
											LCID, DISPID* ids) override {
		if (iid != IID_NULL) return DISP_E_UNKNOWNINTERFACE;
		if (!names || !ids) return E_POINTER;
		for (UINT index = 0; index < count; ++index) ids[index] = DISPID_UNKNOWN;
		if (count != 1 || !names[0] || _wcsicmp(names[0], L"Read") != 0) return DISP_E_UNKNOWNNAME;
		ids[0] = 1; return S_OK;
	}
	HRESULT STDMETHODCALLTYPE Invoke(DISPID member, REFIID iid, LCID, WORD flags,
		DISPPARAMS* parameters, VARIANT* result, EXCEPINFO*, UINT* argumentError) override {
		if (result) VariantInit(result);
		if (argumentError) *argumentError = 0;
		if (iid != IID_NULL) return DISP_E_UNKNOWNINTERFACE;
		if (member != 1 || flags != DISPATCH_METHOD) return DISP_E_MEMBERNOTFOUND;
		if (!parameters || !result) return E_POINTER;
		if (parameters->cArgs != 1 || parameters->cNamedArgs != 0) return DISP_E_BADPARAMCOUNT;
		if (!parameters->rgvarg) return E_POINTER;
		const VARIANT& input = parameters->rgvarg[0];
		if (input.vt != VT_BSTR) return DISP_E_TYPEMISMATCH;
		UINT length = SysStringLen(input.bstrVal);
		if (length == 0 || length > 16) return E_INVALIDARG;
		for (UINT index = 0; index < length; ++index)
			if (input.bstrVal[index] < L'a' || input.bstrVal[index] > L'z') return E_INVALIDARG;
		bool publicRecord = std::wcscmp(input.bstrVal, L"alpha") == 0;
		bool privateRecord = std::wcscmp(input.bstrVal, L"private") == 0;
		if (!baseline && !publicRecord) return E_ACCESSDENIED;
		if (!publicRecord && !privateRecord) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
		BSTR text = SysAllocString(publicRecord ? L"public-a" : L"synthetic-private");
		if (!text) return E_OUTOFMEMORY;
		result->vt = VT_BSTR; result->bstrVal = text;
		return S_OK;
	}
};

class Factory final : public IClassFactory {
	std::atomic<ULONG> references{1};
	const bool baseline;
public:
	explicit Factory(bool mode) : baseline(mode) {}
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override {
		if (!output) return E_POINTER;
		*output = nullptr;
		if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
		*output = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
	ULONG STDMETHODCALLTYPE Release() override {
		ULONG remaining = --references; if (!remaining) delete this; return remaining;
	}
	HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** output) override {
		if (!output) return E_POINTER;
		*output = nullptr;
		if (outer) return CLASS_E_NOAGGREGATION;
		Records* records = new (std::nothrow) Records(baseline);
		if (!records) return E_OUTOFMEMORY;
		HRESULT result = records->QueryInterface(iid, output);
		records->Release(); return result;
	}
	HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return E_NOTIMPL; }
};

void TestCall(IDispatch* proxy, DISPID member, VARTYPE type, const wchar_t* text,
			  UINT length, UINT count, HRESULT expected, const wchar_t* expectedText) {
	Variant input;
	input.value.vt = type;
	if (type == VT_BSTR) {
		input.value.bstrVal = SysAllocStringLen(text, length);
		if (!input.value.bstrVal) throw Failure{E_OUTOFMEMORY};
	} else { input.value.lVal = 7; }
	DISPPARAMS parameters{&input.value, nullptr, count, 0};
	Variant output;
	UINT argumentError = 0;
	HRESULT result = proxy->Invoke(member, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
		&parameters, &output.value, nullptr, &argumentError);
	std::printf("result=0x%08lX\n", static_cast<unsigned long>(result));
	if (result != expected) throw Failure{E_UNEXPECTED};
	if (SUCCEEDED(result)) {
		if (output.value.vt != VT_BSTR || !output.value.bstrVal ||
			std::wcscmp(output.value.bstrVal, expectedText) != 0) throw Failure{E_UNEXPECTED};
	} else if (output.value.vt != VT_EMPTY) { throw Failure{E_UNEXPECTED}; }
}

int wmain(int argc, wchar_t** argv) {
	if (argc != 3) return 64;
	bool server = std::wcscmp(argv[1], L"server") == 0;
	if (!server && std::wcscmp(argv[1], L"client") != 0) return 64;
	bool baseline = std::wcscmp(argv[2], L"baseline") == 0;
	if (!baseline && std::wcscmp(argv[2], L"fixed") != 0) return 64;
	try {
		Apartment apartment;
		Check(CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_DISABLE_AAA, nullptr));
		if (server) {
			ComPtr<IClassFactory> factory;
			factory.Attach(new (std::nothrow) Factory(baseline));
			if (!factory) throw Failure{E_OUTOFMEMORY};
			DWORD cookie = 0;
			Check(CoRegisterClassObject(CLSID_Records, factory.Get(), CLSCTX_LOCAL_SERVER,
				REGCLS_MULTIPLEUSE, &cookie));
			std::puts("READY: run matching client; press Enter only AFTER client exits");
			std::fflush(stdout);
			std::getchar();
			Check(CoRevokeClassObject(cookie));
			std::printf("live-objects=%ld\n", liveObjects.load());
			return liveObjects.load() == 0 ? 0 : 1;
		}
		ComPtr<IDispatch> proxy;
		Check(CoCreateInstance(CLSID_Records, nullptr, CLSCTX_LOCAL_SERVER,
			IID_IDispatch, reinterpret_cast<void**>(proxy.GetAddressOf())));
		Check(CoSetProxyBlanket(proxy.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_NONE));
		wchar_t name[] = L"Read";
		LPOLESTR names[] = {name};
		DISPID member = DISPID_UNKNOWN;
		Check(proxy->GetIDsOfNames(IID_NULL, names, 1, LOCALE_USER_DEFAULT, &member));
		TestCall(proxy.Get(), member, VT_BSTR, L"alpha", 5, 1, S_OK, L"public-a");
		TestCall(proxy.Get(), member, VT_BSTR, L"private", 7, 1,
			baseline ? S_OK : E_ACCESSDENIED, L"synthetic-private");
		TestCall(proxy.Get(), member, VT_I4, nullptr, 0, 1, DISP_E_TYPEMISMATCH, nullptr);
		TestCall(proxy.Get(), member, VT_BSTR, L"alpha", 5, 0, DISP_E_BADPARAMCOUNT, nullptr);
		TestCall(proxy.Get(), member, VT_BSTR, L"a\0b", 3, 1, E_INVALIDARG, nullptr);
		TestCall(proxy.Get(), member, VT_BSTR, L"abcdefghijklmnopq", 17, 1, E_INVALIDARG, nullptr);
		proxy.Reset();
		std::puts("PASS: local RPC, operation policy, VARIANT/BSTR contracts");
		return 0;
	} catch (const Failure& error) {
		std::fprintf(stderr, "HRESULT=0x%08lX\n", static_cast<unsigned long>(error.code));
		return 1;
	}
}
```

### Objectives and Baseline

Build in the x64 developer environment:

```powershell
Set-Location "$env:TEMP\X3-ComSecurity"
cl /nologo /std:c++17 /EHsc /W4 /WX /sdl /guard:cf Records.cpp /Fe:Records.exe /link ole32.lib oleaut32.lib uuid.lib
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
```

Terminal A, same standard account:

```powershell
Set-Location "$env:TEMP\X3-ComSecurity"
.\Records.exe server baseline
```

Wait for READY, then terminal B:

```powershell
Set-Location "$env:TEMP\X3-ComSecurity"
.\Records.exe client baseline
if ($LASTEXITCODE -ne 0) { throw 'Baseline failed' }
```

Only after client exit, press Enter in A and require `live-objects=0` and exit 0. Start `.\Records.exe server fixed` in A; after READY run `.\Records.exe client fixed` in B with the same exit check. Press Enter in A after B exits. Do not run both server modes simultaneously under the same CLSID.

### Hints

`GetIDsOfNames` discovers a stable method; it does not authorize the argument. `Invoke` validates ABI and record policy separately. A same-user client is still outside the server process, so treat its parameters as untrusted; this is not evidence that a different user's token would be admitted or denied correctly.

### Solution and Fixed Retest

The fix is the `!baseline && !publicRecord` check, evaluated before data lookup. Expected per client: alpha `0x00000000`; private baseline `0x00000000`, fixed `0x80070005`; wrong type `0x80020005`; bad count `0x8002000E`; both invalid strings `0x80070057`; then PASS. Result VARIANT stays empty on failure. Server reports zero live objects after client release. These are expected values, not captured output.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring, including local COM activation. Parent validation must verify system `IDispatch` marshaling on the target Windows build, proxy security calls, all HRESULTs and object cleanup. If activation fails, check server READY, account/session, CLSID and HRESULT; do not weaken DCOM policy. A policy-restricted machine is an unmet prerequisite.

The lab deliberately leaves cross-identity and privileged-service authorization unexecuted and does not claim to implement that deployment. No persistent registration is needed; exiting A revokes the running factory. Stop clients before pressing Enter, then:

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-ComSecurity" -Recurse -Force
```

- [ ] Local COM Programming exercise: Implement or consume a harmless local COM interface using smart pointers. Test failed QueryInterface, reference cleanup, and a correctly marshaled cross-apartment call.
- [ ] Boundary check: Call a protected toy method from a lower-trust client and verify explicit authorization, then exercise failure paths and confirm object references are released.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[COM Programming]]

## References

- [Security in COM](https://learn.microsoft.com/en-us/windows/win32/com/security-in-com)
- [CoInitializeSecurity](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity)
- [CoSetProxyBlanket](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket)
- [IDispatch Invoke](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-idispatch-invoke)
- [SysStringLen](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysstringlen)
- [Marshaling details](https://learn.microsoft.com/en-us/windows/win32/com/marshaling-details)
