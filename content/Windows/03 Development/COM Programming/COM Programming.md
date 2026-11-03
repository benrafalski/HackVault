---
title: "COM Programming"
aliases: []
tags: [windows, x3]
domain: windows
phase: "X3"
type: tech
status: draft
pair: "[[COM Programming Security]]"
updated: 2026-11-03
---
# COM Programming

> [!abstract] TL;DR
> Balance initialization and ownership; use HRESULT-aware checks and RAII COM pointers. Configure security before relying on defaults.

> [!info] Agent scope
> Interface implementation; IUnknown; reference counting; apartments; marshaling; activation; registration; HRESULT handling.

## Prerequisites

- Windows 11 x64, MSVC v143/Visual Studio 2022 C++ tools, Windows SDK 10.0.26100.x, x64 developer environment and PowerShell 7. Standard user; WRL headers ship with the SDK, no ATL/NuGet package required.
- C++ virtual interfaces, atomics, HRESULTs, RAII and [[Windows Lab Setup]]. This lab uses native COM, not .NET COM interop or WinRT activation.

## Learn

```text
Teach me native COM at expert depth, assuming C++/Win32 and atomic ownership
knowledge. Derive IUnknown identity and QueryInterface invariants, AddRef/Release
ownership, class factories, CLSID versus IID, aggregation and HRESULT contracts.
Compare STA/MTA/neutral apartments, reentrancy, message pumping, standard and
free-threaded marshaling, proxy/stub registration and Automation marshaling.
Trace activation through registration, class-object registration and factory
creation. Implement a thread-safe reference-counted object with an aggregated
free-threaded marshaler, activate it, marshal between MTA and STA, and prove
identity, E_NOINTERFACE and final destruction. Explain why this does not make
arbitrary STA dependencies agile or establish authorization. Include exact
build/run checks, lifetime diagrams and failure paths. Use official sources;
no offensive actions or host configuration changes. Teach here rather than
editing files, with worked answers to difficult reentrancy/lifetime questions.
```

## Cheatsheet

### Binary and Ownership Contracts

| Contract | Required behavior |
|---|---|
| `IUnknown` | First three vtable slots are `QueryInterface`, `AddRef`, `Release`; compatible calling convention and IID determine the ABI |
| Identity | Querying `IID_IUnknown` from any interface on an object yields the same physical identity pointer |
| QI reachability | Supported interface set is static; reflexive, symmetric and transitive. Authorization belongs in methods, not changing QI availability by caller |
| Successful QI | Returns an owned reference; caller must Release. Failure returns `E_NOINTERFACE` and null output |
| Parameter pointers | Borrowed for the duration unless documented; storing an interface pointer generally requires AddRef |
| Factory | `CreateInstance` checks output, handles aggregation policy, creates initial reference, QIs, releases construction reference |
| HRESULT | `SUCCEEDED`/`FAILED` test sign; `S_FALSE` is success. Only use GetLastError when a called Win32 API says so |
| Memory | BSTR -> `SysFreeString`; task memory -> `CoTaskMemFree`; interface -> `Release`; VARIANT -> `VariantClear` |

`ComPtr::Attach` adopts an existing owned reference; assigning a raw pointer normally AddRefs. `Get()` borrows; `Detach()` transfers ownership. Use `ReleaseAndGetAddressOf()` when an out call replaces an existing pointer; overwriting a nonempty raw pointer leaks the old reference. Reference counts are not cycle collection: connection points and callbacks need explicit disconnect rules.

### Apartments and Marshaling

- Every participating thread initializes COM. Balance each successful `CoInitializeEx`, including `S_FALSE`, with `CoUninitialize`. Do not uninitialize on `RPC_E_CHANGED_MODE`; the thread was already initialized incompatibly.
- STA serializes incoming COM calls through its dispatch machinery, not all code in the object. Outgoing COM calls can pump and reenter, so never assume a call cannot reenter an invariant. An STA serving ordinary marshaled calls must pump messages.
- MTA permits concurrent calls; the object owns synchronization. Copying an STA interface pointer into another apartment is not marshaling.
- `CoMarshalInterThreadInterfaceInStream` produces a one-use marshaling stream; `CoGetInterfaceAndReleaseStream` consumes/releases it, even on failure. If never consumed, the origin must `CoReleaseMarshalData` and release the stream.
- The free-threaded marshaler (FTM) can provide direct in-process access across apartments. Its outer object must be thread-safe and must not keep raw apartment-bound interface dependencies. FTM is not a custom cross-process proxy/stub for an arbitrary IID.
- Custom cross-process interfaces normally require MIDL-generated proxy/stub or another supported marshaling design. `IDispatch` and `IStream` have system-supported marshaling. See the independent `IDispatch` server in [[COM Programming Security]].

### Activation, Registration, and Security

`CoCreateInstance` combines class lookup, class factory and `CreateInstance`; specify intended `CLSCTX` instead of allowing unnecessary contexts. `InprocServer32` maps a CLSID to a DLL and threading model; `LocalServer32` maps to an EXE; per-user and machine registrations have different ownership/trust implications, and x86/x64 views matter. A registration-free manifest is another deployment option, not a way to ignore binary trust.

`CoRegisterClassObject` publishes a running factory and returns a cookie; `CoRevokeClassObject` withdraws it but existing objects remain alive. The lab uses runtime registration only, with no registry writes or auto-launch installation. Its unique CLSID is a lab identifier, not a production deployment contract.

`CoInitializeSecurity` is process-wide and should run before marshaling/activation implicitly initializes security. `RPC_E_TOO_LATE` means that window has passed; do not silently assume requested settings took effect. Activation/access policy and per-method authorization remain distinct. A proxy blanket configures calls on a proxy, not the identity or trustworthiness of a local raw pointer.

## Gotchas

- Do not hold an application lock across external COM calls without considering reentrancy and deadlock.
- AddRef being atomic does not make object fields thread-safe. The lab counter uses an atomic compare/exchange independently of its reference count.
- C++ exceptions must not escape COM ABI methods; map allocation and validation failures to HRESULTs and initialize out parameters before failure.

## Labs

### Environment and Complete File

Create `$env:TEMP\X3-Com` and `Counter.cpp` below. No IDL is needed because the custom interface is marshaled only in process by its aggregated FTM. The factory is registered while the program runs, then revoked.

```cpp
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <objbase.h>
#include <wrl/client.h>
#include <atomic>
#include <cstdio>
#include <new>
#include <thread>
using Microsoft::WRL::ComPtr;

struct Failure { HRESULT code; };
void Check(HRESULT result) { if (FAILED(result)) throw Failure{result}; }
struct Apartment {
	explicit Apartment(DWORD model) { Check(CoInitializeEx(nullptr, model)); }
	~Apartment() { CoUninitialize(); }
};
const CLSID CLSID_LabCounter = {0x8c4c7b65,0xf092,0x4ea0,{0x8e,0x21,0x87,0x61,0xb5,0xfa,0x83,0x40}};
struct __declspec(uuid("5D88B831-AC62-409D-BA42-915CA8CA63A1")) ICounter : IUnknown {
	virtual HRESULT STDMETHODCALLTYPE Add(LONG delta, LONG* value) = 0;
};
std::atomic<long> liveObjects{0};

class Counter final : public ICounter {
	std::atomic<ULONG> references{1};
	std::atomic<LONG> value{0};
	ComPtr<IUnknown> marshaler;
public:
	Counter() { ++liveObjects; }
	~Counter() { --liveObjects; }
	HRESULT Initialize() { return CoCreateFreeThreadedMarshaler(this, marshaler.GetAddressOf()); }
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override {
		if (!output) return E_POINTER;
		*output = nullptr;
		if (iid == IID_IUnknown || iid == __uuidof(ICounter)) {
			*output = static_cast<ICounter*>(this); AddRef(); return S_OK;
		}
		if (iid == IID_IMarshal) return marshaler->QueryInterface(iid, output);
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
	ULONG STDMETHODCALLTYPE Release() override {
		ULONG remaining = --references;
		if (!remaining) delete this;
		return remaining;
	}
	HRESULT STDMETHODCALLTYPE Add(LONG delta, LONG* output) override {
		if (!output) return E_POINTER;
		*output = 0;
		LONG current = value.load();
		for (;;) {
			long long next = static_cast<long long>(current) + delta;
			if (next < 0 || next > 1000) return E_INVALIDARG;
			LONG desired = static_cast<LONG>(next);
			if (value.compare_exchange_weak(current, desired)) { *output = desired; return S_OK; }
		}
	}
};

class Factory final : public IClassFactory {
	std::atomic<ULONG> references{1};
public:
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
		Counter* counter = new (std::nothrow) Counter;
		if (!counter) return E_OUTOFMEMORY;
		HRESULT result = counter->Initialize();
		if (SUCCEEDED(result)) result = counter->QueryInterface(iid, output);
		counter->Release();
		return result;
	}
	HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return E_NOTIMPL; }
};
struct Registration {
	DWORD cookie = 0;
	~Registration() { if (cookie) CoRevokeClassObject(cookie); }
};

int wmain() {
	try {
		Apartment mainApartment(COINIT_MULTITHREADED);
		Check(CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_DISABLE_AAA, nullptr));
		ComPtr<IClassFactory> factory;
		factory.Attach(new (std::nothrow) Factory);
		if (!factory) throw Failure{E_OUTOFMEMORY};
		Registration registration;
		Check(CoRegisterClassObject(CLSID_LabCounter, factory.Get(), CLSCTX_LOCAL_SERVER,
			REGCLS_MULTIPLEUSE, &registration.cookie));
		{
			ComPtr<ICounter> counter;
			Check(CoCreateInstance(CLSID_LabCounter, nullptr, CLSCTX_LOCAL_SERVER,
				__uuidof(ICounter), reinterpret_cast<void**>(counter.GetAddressOf())));
			ComPtr<IUnknown> identity;
			Check(counter.As(&identity));
			ComPtr<ICounter> again;
			Check(identity.As(&again));
			ComPtr<IUnknown> identityAgain;
			Check(again.As(&identityAgain));
			if (identity.Get() != identityAgain.Get()) throw Failure{E_UNEXPECTED};
			ComPtr<IDispatch> absent;
			if (counter.As(&absent) != E_NOINTERFACE || absent) throw Failure{E_UNEXPECTED};
			LONG value = 0;
			Check(counter->Add(1, &value));
			if (value != 1) throw Failure{E_UNEXPECTED};
			IStream* packet = nullptr;
			Check(CoMarshalInterThreadInterfaceInStream(__uuidof(ICounter), counter.Get(), &packet));
			HRESULT workerResult = E_UNEXPECTED;
			bool consumed = false;
			try {
				std::thread worker([&] {
					HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
					if (FAILED(initialized)) { workerResult = initialized; return; }
					{
						ComPtr<ICounter> remote;
						consumed = true;
						workerResult = CoGetInterfaceAndReleaseStream(packet, __uuidof(ICounter),
							reinterpret_cast<void**>(remote.GetAddressOf()));
						if (SUCCEEDED(workerResult)) {
							LONG observed = 0;
							workerResult = remote->Add(2, &observed);
							if (SUCCEEDED(workerResult) && observed != 3) workerResult = E_UNEXPECTED;
						}
					}
					CoUninitialize();
				});
				worker.join();
			} catch (...) {
				if (!consumed) { CoReleaseMarshalData(packet); packet->Release(); }
				throw;
			}
			if (!consumed) { CoReleaseMarshalData(packet); packet->Release(); }
			Check(workerResult);
			if (counter->Add(1001, &value) != E_INVALIDARG || value != 0) throw Failure{E_UNEXPECTED};
			Check(counter->Add(0, &value));
			if (value != 3) throw Failure{E_UNEXPECTED};
			std::printf("identity=stable; cross-apartment-value=%ld\n", value);
		}
		if (liveObjects.load() != 0) throw Failure{E_UNEXPECTED};
		std::puts("PASS: QI, marshaling, range checks, final Release");
		return 0;
	} catch (const Failure& error) {
		std::fprintf(stderr, "HRESULT=0x%08lX\n", static_cast<unsigned long>(error.code));
	} catch (...) { std::fputs("C++ host failure\n", stderr); }
	return 1;
}
```

### Objectives and Steps

```powershell
Set-Location "$env:TEMP\X3-Com"
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 Counter.cpp /Fe:Counter.exe /link ole32.lib oleaut32.lib uuid.lib
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
.\Counter.exe
if ($LASTEXITCODE -ne 0) { throw 'COM checks failed' }
```

Trace reference ownership at creation, QI, marshaling, unmarshaling and final scope exit. Explain why the worker can finish without pumping an STA message loop in this specific FTM design, but an ordinary STA server could not use this as a general recipe. Confirm unsupported QI clears its output and invalid Add leaves state unchanged.

### Hints

The FTM owns its own inner identity; the outer delegates only `IMarshal`, not its public identity. Atomics protect counter updates separately from lifetime. Runtime class registration and object activation are distinct actions. The sample intentionally rejects factory `LockServer` rather than pretending to implement a server-lifetime protocol; its host owns a fixed run lifetime.

### Solution and Expected Results

Expected: stable identity, cross-apartment value 3, rejected unsupported IID and out-of-range update, then zero live Counter objects and PASS. `CoRevokeClassObject` occurs before factory release and COM uninitialization through reverse local destruction. This demonstrates in-process activation and marshaling; it does not install a server, generate a cross-process proxy for `ICounter`, or authorize another identity.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent validation must compile and run the printed file; no COM registration or marshaling was tested here. `RPC_E_CHANGED_MODE` means an existing host initialized the thread differently; use the standalone EXE rather than changing ambient host settings. `REGDB_E_CLASSNOTREG` implies failed/missing registration or wrong context; do not register an unrelated DLL to compensate.

```powershell
Set-Location $env:TEMP
Remove-Item -LiteralPath "$env:TEMP\X3-Com" -Recurse -Force
```

No persistent registry entries are created. A crash ends the process and its runtime class registration; do not claim clean object destruction after a crash.

- [ ] Local COM Programming exercise: Implement or consume a harmless local COM interface using smart pointers. Test failed QueryInterface, reference cleanup, and a correctly marshaled cross-apartment call.
- [ ] Boundary check: Call a protected toy method from a lower-trust client and verify explicit authorization, then exercise failure paths and confirm object references are released.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X3 Development|X3 Development]]
- [[COM Programming Security]]

## References

- [Rules for QueryInterface](https://learn.microsoft.com/en-us/windows/win32/com/rules-for-implementing-queryinterface)
- [Managing object lifetimes](https://learn.microsoft.com/en-us/windows/win32/learnwin32/managing-the-lifetime-of-an-object)
- [Processes, threads and apartments](https://learn.microsoft.com/en-us/windows/win32/com/processes--threads--and-apartments)
- [CoCreateFreeThreadedMarshaler](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreatefreethreadedmarshaler)
- [CoMarshalInterThreadInterfaceInStream](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-comarshalinterthreadinterfaceinstream)
- [CoRegisterClassObject](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coregisterclassobject)
