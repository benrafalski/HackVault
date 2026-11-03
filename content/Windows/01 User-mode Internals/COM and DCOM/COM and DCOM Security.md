---
title: "COM and DCOM Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[COM and DCOM]]"
updated: 2026-11-03
---
# COM and DCOM Security

> [!abstract] TL;DR
> Writable registrations, permissive activation/access policy, and unsafe impersonation can redirect or misuse a more privileged COM server.

> [!info] Agent scope
> Security of: Activation; CLSID and IID; apartments; marshaling; proxies; local and remote activation security; registration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Activation resolution/registry views, server files, AppID launch/access policy, authentication blankets, method authorization, marshaled input, and impersonation lifetime.
- Offline policy evidence only: no registration edits, remote activation, privileged server, or persistence demonstration.

## Learn

```text
Teach defensive COM/DCOM security with exact Windows security contracts.
Assume COM interfaces, apartments, tokens, registry views and DACLs. Separate
class resolution, activation/launch, call authentication, impersonation and
method/resource authorization. Explain AppID versus CLSID, per-user/machine
views, server file protection, launch/access masks and machine restrictions.
Compare CoInitializeSecurity, proxy blankets, authentication levels, cloaking,
identification/impersonation/delegation and explicit per-method checks. Cover
RPC_E_TOO_LATE, callback/reentrancy lifetime and unsafe untrusted marshaled data.
Explain current DCOM activation hardening and why lowering defenses is not a
compatibility fix. Use offline normalized evidence with actual COM constants:
detect overbroad remote rights and weak authn, repair the profile and retain
allowed local calls. Include counterexamples and missing-evidence tests.
Use Microsoft sources, detection limits and false-positive analysis. No remote
activation experiments, registration changes, persistence, escalation,
credential access, exploitation, bypass or evasion. Do not edit files or claim
runtime validation; finish with difficult answered evidence-review questions.
```

## Cheatsheet

### Activation Is Not Authorization

Activation locates/starts a server and obtains an interface. Calls still need authentication, applicable access policy and application authorization. In-process DLLs execute with caller-process authority; DCOM ACLs do not sandbox a loaded DLL. Out-of-process identity may depend on AppID configuration, service hosting and activation context. Review those facts rather than assuming the activating user and server user are identical.

| COM right | Value | Meaning in applicable descriptors |
|---|---|---|
| `COM_RIGHTS_EXECUTE` | `0x1` | Required base bit for COM execute rights. |
| `COM_RIGHTS_EXECUTE_LOCAL` | `0x2` | Local execution/access. |
| `COM_RIGHTS_EXECUTE_REMOTE` | `0x4` | Remote execution/access. |
| `COM_RIGHTS_ACTIVATE_LOCAL` | `0x8` | Local activation, launch descriptor context. |
| `COM_RIGHTS_ACTIVATE_REMOTE` | `0x10` | Remote activation, launch descriptor context. |

Launch/activation and access descriptors are distinct, and machine-wide restriction policy can further constrain application policy. A local-only launch example uses `0xB` (1+2+8); local access uses `0x3` (1+2). These are not filesystem or SCM masks. Legacy `COM_RIGHTS_EXECUTE`-only ACL semantics require version-aware interpretation; do not synthesize effective permission by bitwise OR across raw ACEs. The lab accepts already-normalized synthetic evidence, not raw descriptors.

`CoInitializeSecurity` is process-wide and must precede implicit COM security initialization; inspect `RPC_E_TOO_LATE`, do not ignore it. `CoSetProxyBlanket` configures one applicable proxy's authentication services, level, impersonation and credentials/capabilities. It does not authorize an application operation or secure a local in-process interface.

An AppID `AccessPermission` registry value is not proof of effective call policy when the server initializes security programmatically. Establish whether the server uses registry/default policy, explicitly selects AppID policy, or supplies its own descriptor/callback policy; inspect machine restrictions as well. A registry-only audit can otherwise report the wrong boundary.

`RPC_C_AUTHN_LEVEL_CONNECT=2`, `PKT_INTEGRITY=5`, `PKT_PRIVACY=6`. Integrity authenticates/protects messages from modification; privacy additionally encrypts. `RPC_C_IMP_LEVEL_IDENTIFY=2`, `IMPERSONATE=3`, `DELEGATE=4` express different authority. Choose the minimum supported level; permitting impersonation does not force the server to do it. Static/dynamic cloaking can change which caller token a proxy presents; thread-token lifetime and asynchronous work must be designed explicitly. Server-side impersonation must be checked, bounded to the operation, and reverted on every path.

On updated Windows, DCOM activation authentication hardening became enforced in March 2023 (KB5004442 rollout); minimum packet integrity for activation is not a recommendation to weaken call confidentiality. Update incompatible callers/components. Do not infer safety from the absence of DCOM errors, and do not treat common DistributedCOM 10016 events as a reason to broaden ACLs blindly.

### Concrete Review Evidence

Read-only registration inspection for the harmless Shell Link class, if authorized:

```powershell
reg.exe query 'HKCR\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32' /reg:64
reg.exe query 'HKCR\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32' /reg:32
```

Compare path/threading model and view; absence in a view is evidence, not an instruction to register it. Review registry-key and server-file permissions separately. Never deserialize untrusted OBJREF/marshaled interface data just to inspect it: unmarshaling can invoke component behavior. Parse only the offline JSON below.

## Detection and Defense

Correlate CLSID/AppID, server image, bitness, principal, activation context and error code with approved installation changes. DCOM hardening events 10036/10037/10038 can identify incompatible authentication paths; inspect the documented event meaning on the actual OS. Capture per-method authorization decisions in the application, not only activation success. Protect registration and binary dependencies, minimize remote exposure, patch endpoints, bound input and reject unknown methods/resources. No universal COM event proves that every method call was authorized.

## Labs

### Environment and Complete Files

Python 3.11+ stdlib, any OS, one file in a new scratch directory. No build, registration, server binary or network. The fixture embeds all input. It describes a fictional local-only application review, not importable COM configuration or a Windows access-check simulator.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"clsid": "{5F7B219A-C99F-4BA2-82C2-86EE33C30EA9}",
	"launch_effective_mask": 0x1F,
	"access_effective_mask": 0x3,
	"authn_level": 2,
	"impersonation_level": 2,
	"registration_writable": False,
	"server_file_writable": False,
	"methods": ["ReadStatus"],
}

def review(record):
	problems = set()
	if record.get("launch_effective_mask") != 0xB:
		problems.add("launch policy")
	if record.get("access_effective_mask") != 0x3:
		problems.add("access policy")
	if record.get("authn_level") not in (5, 6):
		problems.add("authentication")
	if record.get("impersonation_level") != 2:
		problems.add("impersonation policy")
	for key in ("registration_writable", "server_file_writable"):
		if record.get(key) is not False:
			problems.add(key)
	if record.get("methods") != ["ReadStatus"]:
		problems.add("method policy")
	return problems

def fixed():
	record = copy.deepcopy(BASELINE)
	record.update(launch_effective_mask=0xB, authn_level=5)
	return record

class ComReview(unittest.TestCase):
	def test_baseline(self):
		self.assertEqual(review(BASELINE), {"launch policy", "authentication"})

	def test_fixed_keeps_local_read(self):
		record = fixed()
		self.assertEqual(review(record), set())
		self.assertEqual(record["launch_effective_mask"] & 0xB, 0xB)
		self.assertIn("ReadStatus", record["methods"])

	def test_integrity_does_not_authorize_methods(self):
		record = fixed()
		record["methods"].append("UnknownOperation")
		self.assertEqual(review(record), {"method policy"})

	def test_missing_file_evidence_and_privacy(self):
		record = fixed()
		record["authn_level"] = 6
		self.assertEqual(review(record), set())
		del record["server_file_writable"]
		self.assertEqual(review(record), {"server_file_writable"})

if __name__ == "__main__":
	unittest.main()
```

### Objectives, Hints, and Fixed Retest

Run `python -m unittest -v test_example`. Decode `0x1F` before running: it includes both remote bits, contrary to the approved local-only profile. Authentication level 2 also violates this profile. Hint: correcting launch rights does not correct authentication. The fixed evidence sets launch `0xB` and authn 5, retains local access and `ReadStatus`, and still rejects unauthorized methods or missing evidence. Expected four passing tests; the baseline is intentionally defective and stays reproducible.

### Verification, Troubleshooting, and Cleanup

Tests verify policy reasoning over actual COM constants only. They do not prove DCOM access checks, remote reachability, patch level, effective registration resolution, or actual per-method enforcement. No administrative action is needed. Remove only the scratch file and `__pycache__`. Source reviewed; parent must run the four tests. Windows authorization/activation validation remains explicitly outside this offline lab and unexecuted.

- [ ] Local COM and DCOM exercise: Decode and review the offline COM policy evidence.
- [ ] Boundary check: Repair launch/authentication findings while retaining permitted local reads.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[COM and DCOM]]

## References

- [COM security](https://learn.microsoft.com/en-us/windows/win32/com/security-in-com)
- [CoInitializeSecurity](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity)
- [CoSetProxyBlanket](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket)
- [COM AccessPermission configuration](https://learn.microsoft.com/en-us/windows/win32/com/accesspermission)
- [DCOM hardening KB5004442](https://support.microsoft.com/help/5004442)
