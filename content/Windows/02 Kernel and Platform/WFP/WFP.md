---
title: "Windows Filtering Platform"
aliases: []
tags: [windows, x2]
domain: windows
phase: "X2"
type: tech
status: draft
pair: "[[WFP Security]]"
updated: 2026-11-03
---
# Windows Filtering Platform

> [!abstract] TL;DR
> Match the layer to the policy goal; review filter ordering and management ACLs. Keep packet manipulation out of initial observation exercises.

> [!info] Agent scope
> Filtering layers; filters and callouts; classification; injection APIs conceptually; policy; permissions; network inspection.

## Prerequisites

- TCP/UDP, IPv4/IPv6, process identity, and C++. Offline fixture: Python 3.11+ standard library. Optional genuine observer: existing VS 2022 x64 C++ tools and Windows SDK 10.0.26100, Windows 11 VM with Base Filtering Engine already running.
- Native observation belongs in an authorized disposable VM. No filter creation/deletion, service changes, network traffic generation, host protection changes, or VPN disruption are required.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows Filtering Platform at expert systems/networking depth. Assume
TCP/IP and C/C++; target Windows 11 and SDK/WDK 10.0.26100 while identifying
Vista-era APIs versus newer versioned DDIs. Trace socket authorization, flow,
transport, packet, and stream classification. Explain providers, sublayers,
conditions, weights, action rights, filter arbitration, management ACLs,
transactions, and dynamic/persistent lifetimes. Separate BFE policy objects from
kernel callout registration. Explain classify IRQL, absent metadata, NBL and
flow lifetime, asynchronous decisions, and injection-loop prevention conceptually.
Give a complete read-only API program and offline fixtures, expected outputs,
and limits; do not modify live firewall policy. Use Microsoft/WDF documentation.
No exploitation or host protection/VPN changes. Teach here without file edits.
```

## Cheatsheet

### Layer Selection

WFP is a filtering platform, not a single firewall. Windows Firewall and other products install policy using it. User-mode `Fwpm*` APIs manage BFE objects; kernel `Fwps*` APIs implement callout behavior. A simple block/permit policy often needs only management filters, not a kernel driver. WFP starts with Vista/Server 2008; later layers, flags, and `0/1/2/...` structure versions have their own minimum OS requirements.

| Layer family | Decision/evidence | Not equivalent to |
|---|---|---|
| ALE_AUTH_CONNECT_V4/V6 | Outbound connection authorization with available application/user identity and endpoint data | Inspecting every byte or every later packet |
| ALE_AUTH_RECV_ACCEPT_V4/V6 | Inbound accept/authorization | A policy covering all outbound connections |
| ALE_FLOW_ESTABLISHED_V4/V6 | Flow lifecycle/context association | Initial authorization for all protocols |
| INBOUND/OUTBOUND_TRANSPORT | Transport data and protocol/ports where supplied | Guaranteed process identity or decrypted application payload |
| INBOUND/OUTBOUND_IPPACKET | IP packet information | Reassembled TCP application records |
| STREAM_V4/V6 | TCP byte-stream indications with stream-specific contracts | UDP datagrams or arbitrary plaintext from TLS |

Layers expose typed fields and metadata, not one universal packet structure. Check metadata presence flags before using optional fields. Layer direction affects local/remote interpretation; a remote destination port for connect is not the local listening port for receive/accept. IPv4 and IPv6 are separate coverage surfaces. ALE can reauthorize on policy or network changes; one process can have many flows, and PID reuse makes PID-only policy unsafe.

### Policy and Arbitration

A provider groups related objects; a sublayer supplies ordering within a layer; a filter binds layer, sublayer, typed conditions, weight, and action. Filters are ordered within a sublayer; a matching terminating action ends evaluation there. Layer-wide arbitration combines sublayer decisions with action-write rights. A soft permit can be overridden; hard permits/blocks and documented callout veto behavior require explicit reasoning. A permit at one layer does not guarantee delivery through other layers.

`FWPS_RIGHT_ACTION_WRITE` describes whether ordinary action replacement is allowed; do not blindly set PERMIT and clear another provider's decision. A terminating callout that blocks must follow the documented rights protocol. An inspection callout should not accidentally turn observation into a terminal allow. `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` changes action override behavior and is not a generic priority boost.

Management ACLs determine who can add/delete/read filters, providers, and sublayers. They are distinct from the user/application identity matched in traffic conditions. Use transactions for related policy updates and check every result. Dynamic sessions scope added objects to session lifetime; persistent objects survive session closure and can survive restart. Boot-time filters are a separate policy lifecycle. Losing a management process may remove dynamic protection, while forgotten persistent filters can outlive their owner.

### Callout Lifetime and Injection

Registering a kernel callout does not itself install a matching BFE filter. Registration, management objects, and filter references must agree before the callout sees intended traffic. Unload must remove policy references and drain outstanding flow/packet/asynchronous work before freeing state. Fail-open/fail-closed behavior depends on filter action and flags; an absent callout is not universally a permit.

`classifyFn` can execute at DISPATCH_LEVEL depending on the layer; resident state and bounded work are essential. `layerData` may be NULL and may refer to an NBL or layer-specific structure. Do not retain borrowed pointers after classify returns. Reference/clone only through the applicable DDI, check allocation failures, and release at the documented completion point.

Injection APIs operate at particular layers/directions and transfer ownership according to their asynchronous completion contracts. Use `FwpsQueryPacketInjectionState` to recognize traffic previously injected by that injection handle; otherwise the callout can repeatedly process its own traffic. Recognizing self-injection is a lifetime/loop control, not a universal authorization rule. This course lab performs no injection.

### Complete Read-Only Native Program

`layers.cpp` enumerates genuine WFP layers and frees API-owned allocations. API version 0 is intentionally used for compatibility. It creates only an enumeration handle, not a filter or policy object.

### File: layers.cpp

```cpp
#include <windows.h>
#include <fwpmu.h>
#include <cstdio>

int wmain()
{
	HANDLE engine = nullptr;
	HANDLE enumeration = nullptr;
	DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
	if (status != ERROR_SUCCESS) {
		std::printf("open-error=%lu\n", status);
		return 1;
	}
	status = FwpmLayerCreateEnumHandle0(engine, nullptr, &enumeration);
	if (status == ERROR_SUCCESS) {
		for (;;) {
			FWPM_LAYER0 **entries = nullptr;
			UINT32 count = 0;
			status = FwpmLayerEnum0(engine, enumeration, 32, &entries, &count);
			if (status != ERROR_SUCCESS) {
				if (entries != nullptr) FwpmFreeMemory0(reinterpret_cast<void **>(&entries));
				break;
			}
			for (UINT32 index = 0; index < count; ++index) {
				std::printf("layer=%u fields=%lu\n",
					static_cast<unsigned>(entries[index]->layerId),
					static_cast<unsigned long>(entries[index]->numFields));
			}
			if (entries != nullptr) FwpmFreeMemory0(reinterpret_cast<void **>(&entries));
			if (count == 0) break;
		}
		FwpmLayerDestroyEnumHandle0(engine, enumeration);
	}
	FwpmEngineClose0(engine);
	if (status != ERROR_SUCCESS) std::printf("enum-error=%lu\n", status);
	return status == ERROR_SUCCESS ? 0 : 1;
}
```

## Gotchas

Enumeration proves API visibility, not effective policy. Counts vary by build and installed components; do not hardcode a total. A single observed allow/deny does not prove which provider decided it. IPsec, firewall profiles, service restrictions, routing, and remote endpoint state can all affect a connection.

## Labs

### Files, Commands, and Objectives

Save `layers.cpp` and `classify_test.py` in an empty scratch directory. The offline fixture models only one filter with no competing sublayers; it is deliberately not a replacement WFP engine. All addresses are documentation ranges, and no sockets are opened.

### File: classify_test.py

```python
from pathlib import Path
from ipaddress import ip_address

def classify(flow):
	address = ip_address(flow["remote"])
	expected_layer = f"ALE_AUTH_CONNECT_V{address.version}"
	if flow["layer"] != expected_layer:
		return "NOT_APPLICABLE"
	if flow["protocol"] == "TCP" and flow["port"] == 8443 and flow["app"] == "LabClient":
		return "BLOCK"
	return "CONTINUE"

base = dict(layer="ALE_AUTH_CONNECT_V4", remote="192.0.2.10",
			protocol="TCP", port=8443, app="LabClient")
cases = [
	(base, "BLOCK"),
	({**base, "port": 8444}, "CONTINUE"),
	({**base, "protocol": "UDP"}, "CONTINUE"),
	({**base, "app": "OtherClient"}, "CONTINUE"),
	({**base, "layer": "ALE_AUTH_CONNECT_V6", "remote": "2001:db8::10"}, "BLOCK"),
	({**base, "layer": "INBOUND_TRANSPORT_V4"}, "NOT_APPLICABLE"),
]
for flow, expected in cases:
	assert classify(flow) == expected, flow
source = Path("layers.cpp").read_text(encoding="utf-8")
for api in ("FwpmEngineOpen0", "FwpmLayerEnum0", "FwpmFreeMemory0",
			"FwpmLayerDestroyEnumHandle0", "FwpmEngineClose0"):
	assert api in source, api
assert "FwpmFilterAdd" not in source and "FwpmFilterDelete" not in source
print("PASS: 6 classifications and read-only enumeration source")
```

1. Run `python classify_test.py` with Python 3.11+. Identify exactly which fields produce each decision.
2. Optional native build in an existing VS x64 tools prompt: `cl /nologo /EHsc /W4 /WX layers.cpp /link Fwpuclnt.lib`.
3. Optional VM-only read-only execution: `.\layers.exe`. Expect lines such as `layer=<numeric ID> fields=<count>` and exit 0, not a predetermined inventory. Do not start BFE or alter policy to force success.

### Hints and Worked Solution

The wrong layer must be reported as not applicable, not permitted. A CONTINUE result means this filter makes no final denial; other policy can still block. Correct coverage requires both connect families. The native program's open/enum/close sequence is genuine API usage; its output says nothing about whether the toy policy exists, because the program never installs it.

### Verification, Troubleshooting, and Cleanup

No author execution. Missing SDK/tools means use offline fixture only. Access denied or BFE unavailable is an explicit observation failure, not an empty healthy inventory; record the numeric error and stop. No service changes or installations. Real multi-provider arbitration, reauthorization, callout IRQL, asynchronous lifetime, and packet injection remain unexecuted VM-only scope. Delete files, executable, and object output. No WFP policy cleanup is needed because none was added.

### Existing Study Checklist

- [ ] Local WFP exercise: Use a documented benign WFP sample or local firewall policy to allow one toy connection and deny another. Record the layer and identity information supporting the decision.
- [ ] Boundary check: Verify the denied toy connection fails for the intended application/protocol while unrelated permitted traffic still works; test IPv4/IPv6 where applicable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[WFP Security]]

## References

- [WFP overview and minimum versions](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
- [FwpmLayerEnum0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmlayerenum0)
- [WFP callout drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/windows-filtering-platform-callout-drivers2)
- [FwpsQueryPacketInjectionState0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsquerypacketinjectionstate0)
