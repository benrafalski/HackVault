---
title: "WinRM Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[WinRM]]"
updated: 2026-11-03
---
# WinRM Security

> [!abstract] TL;DR
> Authenticate the intended host, protect messages, authorize endpoint entry and constrain each exposed operation. A JEA endpoint is only as narrow as its role capabilities, parameter constraints, writable configuration and execution identity.

> [!info] Agent scope
> Security of: WS-Management; listeners; authentication; PowerShell remoting; endpoint permissions; transport; constrained administration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Client destination trust, listener exposure, authentication configuration, endpoint ACLs, role mappings, command parameters, run-as identity, module/configuration file permissions and transcripts.
- Excessive authority requires reachable management access and overbroad authorization or trusted configuration. Delegation changes which host receives authority. Explain those risks conceptually only; no remote execution, credential collection or movement exercises.

## Learn

```text
Teach defensive WinRM/JEA security at expert depth. Assume WS-Management, PSRP,
Windows tokens and PowerShell parameter binding. Separate listener transport,
server authentication, message protection, endpoint SDDL, role capabilities,
parameter restrictions, run-as identity and downstream resource authority.
Explain TrustedHosts limits, HTTP message encryption versus HTTPS, disabled
Basic/unencrypted policy, delegation risks, JEA role union, and configuration
file integrity. Give exact read-only commands and documented lab-only secure
settings without enabling listeners or executing remotely. Build a complete
offline Python 3.12 stdlib policy lab with an unsafe baseline, fixed decision
function and negative/positive regressions; clearly not a JEA implementation.
Use primary Microsoft sources and version caveats. Explain threat prerequisites
without credential theft, relay, movement, bypass, exploitation or persistence
instructions. No production targets, real credentials or invented results.
Teach here, do not edit files or study status; include worked diagnosis cases.
```

## Cheatsheet

### Controls by Decision Point

| Decision | Unsafe assumption | Secure contract |
|---|---|---|
| Destination | TrustedHosts `*` authenticates a server | Prefer Kerberos service identity or validated HTTPS; keep trust exceptions narrow and reviewed. |
| Protection | 5985 is always plaintext, or 5986 guarantees authorization | Kerberos/NTLM can protect WSMan messages over HTTP. TLS protects transport; neither grants endpoint permissions. |
| Mechanism | Enable every auth scheme for compatibility | Keep Basic, unencrypted traffic and CredSSP disabled unless a separately reviewed design requires them. |
| Endpoint | Authenticated means entitled to any plugin | Inspect endpoint SDDL and JEA RoleDefinitions. Default unrestricted endpoints may still exist beside a narrow endpoint. |
| Operation | A visible cmdlet name is enough restriction | Constrain parameters and values; avoid wildcards, arbitrary paths and general-purpose interpreters in delegated roles. |
| Execution identity | Caller and run-as identity have the same rights | Virtual accounts or gMSAs can have greater/local/network authority; explicitly design and audit it. |
| Configuration | A safe capability stays safe | Protect module paths, role capability files, session configuration and transcript destinations from unauthorized modification. |

JEA is not just a language mode. Role capability sets can be combined for a user in multiple matching roles; review the resulting union. Command restrictions need argument-level policy: allowing a status command for one synthetic service is different from exposing every service or arbitrary script arguments. JEA virtual accounts and domain-controller behavior need special review; use no DC for this lab. Downstream access depends on execution identity and delegation design, not just successful first-hop authentication.

### Local Observation and Secure Settings

Only on an owned snapshot-backed Windows VM with Windows PowerShell 5.1/WSMan provider. These are documented, runtime-unverified fragments, not lab prerequisites. If the service/provider is unavailable, stop; do not enable remoting to inspect it.

```powershell
Get-ChildItem WSMan:\localhost\Service\Auth
Get-ChildItem WSMan:\localhost\Client\Auth
Get-Item WSMan:\localhost\Service\AllowUnencrypted
Get-Item WSMan:\localhost\Client\AllowUnencrypted
Get-Item WSMan:\localhost\Client\TrustedHosts
Get-PSSessionConfiguration | Select-Object Name,Permission,PSVersion
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 20
```

Lab-only hardening of an already configured VM; administrator rights and retained console access required. Capture original values and restore the snapshot after evaluation. These do not create a listener, install a certificate or prove Kerberos use; Group Policy may take precedence.

```powershell
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Client\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false
Set-Item WSMan:\localhost\Client\Auth\CredSSP -Value $false
```

Illustrative JEA role-capability hashtable fragment, not a complete deployable endpoint; do not register it as part of this offline lab:

```powershell
@{
	VisibleCmdlets = @(
		@{ Name = 'Get-Service'; Parameters = @(
			@{ Name = 'Name'; ValidateSet = 'WinRM' }
		) }
	)
}
```

A real deployment also needs a protected module/RoleCapabilities location, session configuration, RoleDefinitions, endpoint ACL, selected execution identity, transcripts and tests under the exact runtime. Do not infer that the fragment restricts other existing endpoints or built-in JEA commands. Windows PowerShell 5.1 and PowerShell 7 endpoints are separately registered; SSH remoting uses other controls.

### Errors and Limits

HTTP 401 may be an initial authentication challenge; repeated 401, TLS failure and endpoint access denied are different stages. A JEA "command not recognized" for a prohibited command can be the correct result. A second-resource denial may be the intended absence of delegated authority. `AllowUnencrypted=False` alone does not validate server identity. An HTTPS certificate mismatch must not be repaired by disabling certificate checking.

## Detection and Defense

Correlate WinRM Operational records with PowerShell Operational, endpoint name, host, user, time and runspace/pipeline identifiers where present. Script block logging (4104) and module logging (4103) require appropriate policy and differ by runtime/provider; no event does not imply no operation. JEA transcripts support command/output review but can contain sensitive data and require access control, retention and tamper-resistant collection. A legitimate inventory job can create high management volume; compare role, endpoint, arguments and destination rather than flagging every WinRM event.

Review endpoint registration/configuration changes, broadening role membership, wildcard capabilities and newly enabled delegation. Keep network paths narrow, use separate administrative roles, and avoid returning secrets through a permitted inventory command. This is defensive configuration diagnosis, not a recipe to exercise unauthorized authority.

## Labs

### Environment and Complete Files

New empty `winrm-security-offline` directory; single file below, embedded fixtures, Python 3.12 standard library only. No packages, WinRM/AD/Windows, network, elevation, services or credentials. Every operation returns a synthetic string; nothing invokes PowerShell. This is an authorization specification model, not JEA, parameter binding or cryptographic enforcement. Runtime unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Request:
	identity: str = "inventory-reader@example.invalid"
	peer_verified: bool = True
	protected: bool = True
	endpoint: str = "InventoryOnly"
	operation: str = "Get-Service"
	service: str = "WinRM"
	delegated: bool = False
	parameters: tuple = ("Name",)


def baseline(request):
	return request.identity == "inventory-reader@example.invalid"


def hardened(request):
	if not baseline(request) or not request.peer_verified or not request.protected:
		return False
	if request.endpoint != "InventoryOnly" or request.delegated:
		return False
	return (request.operation == "Get-Service" and request.service == "WinRM"
			and request.parameters == ("Name",))


def execute_model(request):
	if not hardened(request):
		raise PermissionError("outside inventory contract")
	return {"Name": "WinRM", "Status": "SyntheticRunning"}


class ExampleTests(unittest.TestCase):
	def test_permitted_inventory(self):
		self.assertTrue(baseline(Request()))
		self.assertEqual(execute_model(Request())["Status"], "SyntheticRunning")

	def test_identity_and_endpoint(self):
		for request in (replace(Request(), identity="other@example.invalid"),
						replace(Request(), endpoint="GeneralShell")):
			with self.assertRaises(PermissionError):
				execute_model(request)

	def test_operation_and_parameters(self):
		for request in (replace(Request(), operation="Set-Service"),
						replace(Request(), service="OtherSyntheticService"),
						replace(Request(), parameters=("Name", "ComputerName"))):
			self.assertTrue(baseline(request))
			self.assertFalse(hardened(request))

	def test_peer_and_message_protection(self):
		for field in ("peer_verified", "protected"):
			request = replace(Request(), **{field: False})
			self.assertTrue(baseline(request))
			self.assertFalse(hardened(request))

	def test_no_delegation(self):
		request = replace(Request(), delegated=True)
		self.assertTrue(baseline(request))
		with self.assertRaises(PermissionError):
			execute_model(request)


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Verify Python 3.12 with `python --version`; run `python -m unittest -v test_example` from the directory (`py -3.12` is an alternative launcher).
2. Identify why the baseline admits a different endpoint and an extra parameter. Explain which decision must remain separate from endpoint access.
3. Temporarily remove `and request.parameters == ("Name",)` from the fixed predicate, retaining valid parentheses. Rerun to detect the extra-parameter regression, then restore and rerun.

### Hints

An authenticated role is not a grant for every command, target and argument. `delegated` is a synthetic policy fact, not actual credentials. All execution here is a dictionary return.

### Solution and Fixed Retest

The baseline checks only identity. The fixed predicate also requires peer verification, protected messages, the inventory endpoint, no delegation, one operation, one synthetic service and an exact parameter set. The known-good query still returns `SyntheticRunning`. Five tests should pass after restoration; the temporary edit fails the operation/parameter test. No test establishes that an actual JEA endpoint is configured correctly.

### Verification, Troubleshooting, and Cleanup

Acceptance: five tests pass, parameter regression detected, and the difference between caller/endpoint/execution identity explained. Wrong directory causes import failures; an edit with unmatched parentheses is a fixture syntax error. Delete the exercise directory and cache. If optional VM settings were changed, restore its snapshot rather than guessing defaults.

### Retained Study Checklist

- [ ] Local WinRM exercise: Configure a constrained remoting endpoint between isolated lab VMs and expose one harmless inventory command. Verify a denied command and unauthorized user fail.
- [ ] Boundary check: Connect with a synthetic limited role and verify it cannot invoke arbitrary commands or access a second resource with unintended delegated authority.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[WinRM]]

## References

- [WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security)
- [JEA security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations)
- [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities)
- [JEA session configurations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/session-configurations)
- [WinRM installation and configuration reference](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
