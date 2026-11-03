---
title: "Windows Filtering Platform Security"
aliases: []
tags: [windows, x2, security]
domain: windows
phase: "X2"
type: security
status: draft
pair: "[[WFP]]"
updated: 2026-11-03
---
# Windows Filtering Platform Security

> [!abstract] TL;DR
> Incorrect layer selection, permissive policy management, and unsafe callout handling can bypass intended network controls or corrupt kernel state.

> [!info] Agent scope
> Security of: Filtering layers; filters and callouts; classification; injection APIs conceptually; policy; permissions; network inspection. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Incorrect layer selection, permissive policy management, and unsafe callout handling can bypass intended network controls or corrupt kernel state.
- Review management-plane permissions separately from traffic conditions. Gaps include missing address families, direction/layer mistakes, broad application matching, policy lifetime, and unsafe classify/asynchronous ownership.

## Learn

```text
Teach defensive WFP policy and callout review at expert depth. Assume TCP/IP,
C, Windows access control, and IRQL. Target Windows 11 with SDK/WDK 10.0.26100;
identify versioned DDI requirements. Explain layer/direction/family coverage,
application identity, sublayer arbitration and action rights, policy management
ACLs, dynamic versus persistent filters, reauthorization, metadata validity,
NBL lifetime, callout absence, and self-injection handling conceptually.
Supply complete synthetic traffic fixtures that prove a precise policy defect,
fix it, and retain allowed behavior. Include genuine benign callback source and
read-only diagnostic commands. Distinguish model evidence from real enforcement.
Use Microsoft sources; no evasion, injection implementation, host firewall/VPN
changes, exploitation, or file-edit requests. Teach in conversation.
```

## Cheatsheet

### Policy Failure Matrix

| Failure | Evidence to collect | Fix and regression |
|---|---|---|
| V4-only policy | Intended V4 denial, matching V6 decision absent | Explicit V4/V6 policies and paired tests |
| Wrong ALE direction | Local/remote port confusion | Define connect versus receive/accept; test both intended and unrelated ports |
| Identity too broad | Same port denied for all applications | Match documented application/user conditions, test other app |
| Permit treated as universal allow | Other sublayer/layer still blocks | Inspect full arbitration and action rights, not just one filter |
| Dynamic object loss | Policy disappears when owner session closes | Explicit lifecycle and monitoring; choose persistence intentionally |
| Unrestricted management | Unintended principal can change policy | Least-privilege object ACLs and narrow management service |
| Borrowed data retained | Worker accesses expired classify input | Use documented reference/copy/pend APIs for that layer |

WFP application IDs are opaque blobs obtained by the management APIs, not a trustworthy self-reported executable basename. Service identity and app-container conditions can matter independently of executable path. DNS names are not stable endpoint identities; address changes, proxies, and encrypted traffic change what a chosen layer can observe. Do not classify a missing optional field as a favorable value.

`classifyFn` must respect the filter's action type and `FWPS_RIGHT_ACTION_WRITE`. Routine permit replacement without rights can conflict with earlier providers. Documented veto semantics are specialized arbitration behavior, not an invitation to override everything. A missing registered callout and `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` require explicit review; never assume a uniform fail-open default.

### Genuine Observation Callback

Complete translation unit `observe.c`, using `FWPS_CALLOUT_CLASSIFY_FN0` shape. It changes no data and does not permit traffic. Only use with a correctly configured inspection callout; this file is not a registered driver. No borrowed pointer is retained.

### File: observe.c

```c
#include <ntddk.h>
#include <fwpsk.h>

VOID LabClassify(const FWPS_INCOMING_VALUES0 *values,
	const FWPS_INCOMING_METADATA_VALUES0 *metadata, VOID *layerData,
	const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *output)
{
	UNREFERENCED_PARAMETER(values);
	UNREFERENCED_PARAMETER(metadata);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	if ((output->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
		output->actionType = FWP_ACTION_CONTINUE;
	}
}
```

Later classify versions add parameters and must match the registration structure used. Mixing signatures is an ABI bug, not just a compile warning. Real inspection should copy bounded telemetry only and preserve earlier decisions. If asynchronous classification is necessary, select the exact layer's pend/complete model; not every layer permits the same approach. Injection requires matching handle/family/direction and completion ownership, plus self-injection state checks; it is out of this lab's operational scope.

## Detection and Defense

Collect provider/sublayer/filter IDs, layer, action, weight, policy origin, lifetime, effective application identity, endpoint family, protocol, and status. A failed connect alone is ambiguous: route failure, listener absence, remote firewall, TLS failure, and local filtering differ.

Read-only commands for an authorized VM, not the physical host:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name, Enabled, Direction, Action, PolicyStoreSourceType
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5156,5157} -MaxEvents 20 |
	Select-Object TimeCreated, Id, ProviderName
```

Firewall cmdlets do not enumerate every third-party WFP callout/filter. Security 5152/5156/5157 availability depends on audit policy and retention; absence is not evidence of no filtering. Do not enable auditing or start services merely to complete this read-only exercise. Correlate timestamps and runtime filter IDs with contemporaneous WFP state rather than treating IDs as stable across boots.

## Labs

### Environment and Complete Files

Offline lab: Python 3.11+ standard library, ordinary user, no sockets or firewall changes. Save `observe.c` above, `flows.json` and `coverage.py` below in an empty scratch directory. Synthetic addresses use documentation ranges.

### File: flows.json

```json
[
  {"id":"blocked-v4","app":"LabClient","remote":"192.0.2.10","protocol":"TCP","port":8443,"expected":"BLOCK"},
  {"id":"blocked-v6","app":"LabClient","remote":"2001:db8::10","protocol":"TCP","port":8443,"expected":"BLOCK"},
  {"id":"other-port","app":"LabClient","remote":"192.0.2.10","protocol":"TCP","port":8444,"expected":"CONTINUE"},
  {"id":"other-app","app":"OtherClient","remote":"2001:db8::10","protocol":"TCP","port":8443,"expected":"CONTINUE"},
  {"id":"other-protocol","app":"LabClient","remote":"192.0.2.10","protocol":"UDP","port":8443,"expected":"CONTINUE"}
]
```

### File: coverage.py

```python
import json
from ipaddress import ip_address
from pathlib import Path

def decision(flow, families):
	family = ip_address(flow["remote"]).version
	matched = (family in families and flow["app"] == "LabClient"
			   and flow["protocol"] == "TCP" and flow["port"] == 8443)
	return "BLOCK" if matched else "CONTINUE"

def mismatches(flows, families):
	return [flow["id"] for flow in flows
			if decision(flow, families) != flow["expected"]]

flows = json.loads(Path("flows.json").read_text(encoding="utf-8"))
assert mismatches(flows, {4}) == ["blocked-v6"]
assert mismatches(flows, {4, 6}) == []

def observe(previous, can_write):
	return "CONTINUE" if can_write else previous

assert observe("BLOCK", False) == "BLOCK"
assert observe("PERMIT", False) == "PERMIT"
assert observe("PERMIT", True) == "CONTINUE"
source = Path("observe.c").read_text(encoding="utf-8")
assert source.index("FWPS_RIGHT_ACTION_WRITE") < source.index("FWP_ACTION_CONTINUE")
assert "FWP_ACTION_PERMIT" not in source
print("PASS: IPv6 gap detected and fixed; 5 flows; observation rights preserved")
```

### Objectives, Hints, and Worked Solution

Run `python coverage.py`. Identify the single baseline mismatch; fix the address-family set without widening application/protocol/port matching. Hint: CONTINUE means this modeled filter makes no decision, not that the whole machine must allow the traffic.

The initial `{4}` policy omits the IPv6 denial. `{4, 6}` corrects it, retaining all three unrelated flows. The rights tests preserve prior decisions when modification is not allowed. The fixture models one noncompeting policy at the appropriate ALE connect layers, not full WFP arbitration or authenticated identity resolution. Expected result is the PASS line.

### Build, Troubleshooting, and Cleanup

No author execution. Optional object compilation requires an existing x64 WDK developer prompt: `cl /nologo /c /W4 /WX /kernel /D_AMD64_ /D_WIN64 /I "%WDKContentRoot%Include\10.0.26100.0\km" /I "%WDKContentRoot%Include\10.0.26100.0\shared" observe.c`. Missing kit is a prerequisite issue. No complete registration/package is supplied and no installation is implied.

Runtime arbitration, actual callout rights, ALE reauthorization, management ACLs, and shutdown races remain unexecuted VM-only scope. Such tests need a snapshot-backed VM, local console, and isolated synthetic endpoints; never alter host firewall, protections, or corporate VPN. JSON errors usually mean trailing commas or wrong working directory. Delete the scratch directory and object file; no live filters require removal.

### Existing Study Checklist

- [ ] Local WFP exercise: Use a documented benign WFP sample or local firewall policy to allow one toy connection and deny another. Record the layer and identity information supporting the decision.
- [ ] Boundary check: Verify the denied toy connection fails for the intended application/protocol while unrelated permitted traffic still works; test IPv4/IPv6 where applicable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X2 Kernel and Platform|X2 Kernel and Platform]]
- [[WFP]]

## References

- [Filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
- [WFP access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)
- [FWPS_CALLOUT_CLASSIFY_FN0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0)
- [FWPM_FILTER0 flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
