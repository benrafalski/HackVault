---
title: "WinRM"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[WinRM Security]]"
updated: 2026-11-03
---
# WinRM

> [!abstract] TL;DR
> WinRM implements WS-Management. Listener reachability, peer authentication, message protection, endpoint access and command authority are distinct gates; PowerShell remoting is one consumer, not a synonym for all WinRM traffic.

> [!info] Agent scope
> WS-Management; listeners; authentication; PowerShell remoting; endpoint permissions; transport; constrained administration.

## Prerequisites

- HTTP/TLS, XML namespaces, authentication versus authorization, Windows identities and basic PowerShell.
- Required lab uses Python 3.12 standard library only. Optional local observations use Windows PowerShell 5.1 on an owned disposable VM; no listener or domain is required for the offline lab.

## Learn

```text
Teach WinRM and PowerShell remoting at expert engineering depth. Assume HTTP,
TLS, XML namespaces and Windows tokens. Trace WS-Management SOAP envelopes,
WS-Addressing Action/MessageID/RelatesTo, ResourceURI, selectors, quotas,
WS-Transfer/Enumeration, and WinRS shell/command/receive/signal/delete state.
Distinguish WSMan transport from PSRP serialization, runspaces and endpoint
configuration. Explain 5985/5986, Kerberos/Negotiate/NTLM, Basic, certificate
mapping, CredSSP, peer identity, message encryption, TrustedHosts, second-hop
constraints, endpoint ACLs and JEA. Compare Windows PowerShell 5.1, PowerShell 7
WSMan endpoints and SSH remoting. Give exact read-only observations, failure
diagnosis, and a complete Python 3.12 stdlib offline namespace/framing lab with
tests; no service, credentials, network or remote commands. Distinguish the
model from actual WSMan, PSRP and cryptographic enforcement. Use primary
Microsoft sources, never fabricate results or provide offensive procedures.
Teach here, not by editing files; finish with worked troubleshooting questions.
```

## Cheatsheet

### Protocol Layers and Fields

| Layer | Concrete state | Boundary |
|---|---|---|
| Listener | HTTP 5985 or HTTPS 5986, usually `/wsman`; address and certificate binding | A listener is not an allowed endpoint or user. Compatibility/custom ports exist. |
| HTTP authentication | 401 challenge then Kerberos/Negotiate, Basic or other configured mechanism | A 401 can be a normal challenge; repeated 401s need package/identity diagnosis. |
| SOAP/WS-Addressing | Envelope/Header/Body; To, Action, MessageID, ReplyTo; response RelatesTo | Namespaces identify fields; prefixes do not. RelatesTo associates a response with a request. |
| WS-Management | ResourceURI, SelectorSet, OptionSet, OperationTimeout, MaxEnvelopeSize | Resource and instance selection; timeout/size quotas do not grant rights. |
| Operations | WS-Transfer Get/Put/Create/Delete; Enumerate/Pull/Release; Identify | Namespace-qualified action dispatch, separate from a shell command string. |
| WinRS shell | ShellId, CommandId, stdin/stdout/stderr streams, command state, exit code | Create shell, command, receive output, signal if needed, delete shell. IDs are scoped handles, not credentials. |
| PowerShell remoting | PSRP messages, runspace/pipeline state, serialized objects | Usually hosted through a PowerShell WSMan plugin. Deserialized objects generally do not retain original live methods. |

Shell success is not command completion: output can arrive in multiple Receive responses and stream end markers matter. A SOAP Fault may carry useful WSMan error details even when an HTTP status is generic. Operations timing out are not necessarily cancelled on the server; explicit lifecycle and cleanup are necessary. Shell quotas, concurrency, idle timeout, envelope size and process output limits can each fail independently.

### Identity and Protection

Kerberos authenticates a service principal, commonly `HTTP/hostname` for WinRM, despite SMB using `cifs/hostname`. Negotiate may choose NTLM when Kerberos cannot be used; name, DNS, domain/trust, SPN and time affect selection. HTTPS validates the server certificate independently of Windows authentication. HTTP with Kerberos/NTLM message encryption is not equivalent to plaintext SOAP; HTTP headers and transport metadata are not thereby all confidential. Inspect the negotiated mechanism and policy rather than making a port-based claim.

Basic carries reusable credentials in base64 and needs validated TLS; this reference's recommended profile leaves it disabled. Certificate authentication is configured certificate-to-account mapping, not automatic trust in any client certificate. CredSSP delegates credentials to the remote host and creates a different trust exposure; do not enable it as a generic second-hop fix.

TrustedHosts is a client trust exception for situations without normal mutual authentication, not an inbound server ACL, authorization list or certificate trust store. A wildcard does not establish server identity. Remote authenticated identity, endpoint ACL and endpoint execution identity can differ. JEA can map a permitted role to narrowly exposed functions under a controlled run-as identity; its policy must constrain commands and parameters, not just endpoint entry.

### Endpoints and Versions

Windows PowerShell 5.1 commonly exposes `Microsoft.PowerShell` when remoting is configured. PowerShell 7 uses separate versioned/named endpoints when WSMan remoting is enabled; installing it alone does not prove which runtime a session uses. SSH remoting has a different transport/subsystem configuration, not the WinRM listener/TrustedHosts controls. Non-Windows WSMan support has additional limitations and dependencies; the required lab avoids them.

### Read-only Local Observations

Owned disposable Windows VM only, Windows PowerShell with WSMan provider; elevation may be required to inspect endpoints. No service is enabled, no remote session is created. If WinRM is stopped or unavailable, report that rather than starting it. Runtime unverified here.

```powershell
Get-Service WinRM
Get-ChildItem WSMan:\localhost\Listener
Get-ChildItem WSMan:\localhost\Service\Auth
Get-Item WSMan:\localhost\Service\AllowUnencrypted
Get-ChildItem WSMan:\localhost\Client\Auth
Get-Item WSMan:\localhost\Client\TrustedHosts
Get-PSSessionConfiguration | Select-Object Name,PSVersion,Permission
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 20
```

| Failure | Diagnose before changing policy |
|---|---|
| Connection refused/timeout | Service, listener binding, firewall/route; not a password error. |
| TLS certificate failure | Name, chain, time, EKU and certificate binding; never suppress validation. |
| Persistent HTTP 401 | Auth mechanism and intended service identity; a first challenge is normal. |
| Access denied after authentication | Endpoint SDDL, role mapping, user token and endpoint execution identity. |
| Command absent in JEA | Capability restriction may be the intended outcome, not a broken shell. |
| Second resource denied | First-hop success does not imply delegation or downstream authority. |
| Serialization/size/timeout failure | PSRP object limits, WSMan envelope/quota, output streaming and operation lifetime. |

## Gotchas

A valid SOAP Action is not permission to execute a command. An endpoint can permit connection but expose only a narrow command set. A command string is never safe merely because it arrived through an authenticated channel.

## Labs

### Environment and Complete Files

Create an empty `winrm-tech-offline` directory with the one file below. Python 3.12 standard library only; seed XML is embedded. No WinRM/AD/Windows/packages/network/elevation/credentials. This restricted educational parser checks namespaces, action and correlation; it does not implement SOAP comprehensively, WSMan auth, PSRP, shell execution or a hardened Internet XML parser. It accepts only the tiny generated fixture vocabulary. Runtime unverified.

### File: test_example.py

```python
import unittest
import xml.etree.ElementTree as ET


SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDRESS = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
RESOURCE = "urn:example:inventory"


def fixture(prefix="s", action=GET_RESPONSE, resource=RESOURCE, relation="urn:uuid:demo"):
	root = ET.Element(f"{{{SOAP}}}Envelope")
	header = ET.SubElement(root, f"{{{SOAP}}}Header")
	ET.SubElement(header, f"{{{ADDRESS}}}Action").text = action
	ET.SubElement(header, f"{{{ADDRESS}}}RelatesTo").text = relation
	ET.SubElement(header, f"{{{WSMAN}}}ResourceURI").text = resource
	ET.SubElement(root, f"{{{SOAP}}}Body")
	ET.register_namespace(prefix, SOAP)
	return ET.tostring(root, encoding="utf-8")


def inspect_envelope(data, expected_relation):
	if len(data) > 4096 or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
		raise ValueError("fixture outside size/DTD contract")
	root = ET.fromstring(data)
	if root.tag != f"{{{SOAP}}}Envelope":
		raise ValueError("wrong SOAP namespace")
	headers = root.findall(f"{{{SOAP}}}Header")
	if len(headers) != 1 or len(root.findall(f"{{{SOAP}}}Body")) != 1:
		raise ValueError("one header and body required")

	def field(namespace, name):
		matches = headers[0].findall(f"{{{namespace}}}{name}")
		if len(matches) != 1 or not matches[0].text:
			raise ValueError("missing or duplicate field")
		return matches[0].text

	if field(ADDRESS, "Action") != GET_RESPONSE:
		raise ValueError("unsupported action")
	if field(ADDRESS, "RelatesTo") != expected_relation:
		raise ValueError("correlation mismatch")
	if field(WSMAN, "ResourceURI") != RESOURCE:
		raise ValueError("unknown resource")
	return "inventory metadata only"


class ExampleTests(unittest.TestCase):
	def test_namespace_prefix_independence(self):
		for prefix in ("s", "soap"):
			self.assertEqual(inspect_envelope(fixture(prefix), "urn:uuid:demo"),
							 "inventory metadata only")

	def test_action_and_resource(self):
		for data in (fixture(action="urn:example:other"),
					 fixture(resource="urn:example:other")):
			with self.assertRaises(ValueError):
				inspect_envelope(data, "urn:uuid:demo")

	def test_correlation(self):
		with self.assertRaisesRegex(ValueError, "correlation"):
			inspect_envelope(fixture(), "urn:uuid:different")

	def test_duplicate_field(self):
		root = ET.fromstring(fixture())
		header = root.find(f"{{{SOAP}}}Header")
		ET.SubElement(header, f"{{{ADDRESS}}}Action").text = GET_RESPONSE
		with self.assertRaisesRegex(ValueError, "duplicate"):
			inspect_envelope(ET.tostring(root), "urn:uuid:demo")

	def test_size_and_namespace(self):
		for data in (b" " * 4097, b"<Envelope><Header/><Body/></Envelope>"):
			with self.assertRaises(ValueError):
				inspect_envelope(data, "urn:uuid:demo")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Verify `python --version` is 3.12 and run `python -m unittest -v test_example` in the directory. `py -3.12` can replace `python` on Windows.
2. Explain why changing a namespace prefix succeeds but removing the namespace fails. Explain why correlation mismatch is separate from authentication.
3. Temporarily change `expected_relation` in `test_correlation` to `urn:uuid:demo`; the expected-error assertion should fail. Restore and rerun.

### Hints

XML identity is the expanded namespace URI plus local name. This synthetic response uses the WS-Transfer `GetResponse` action and a `RelatesTo` field; its empty body and custom inventory resource are for parsing practice, not a complete exchange to transmit to WinRM. Real resource representations, WS-Addressing versions and required headers must follow the negotiated protocol.

### Solution and Expected Results

Five tests should pass. Prefixes `s` and `soap` resolve to the same expanded name. Unknown actions/resources, ambiguous headers, wrong correlation and wrong namespace are rejected. RelatesTo matches a message identifier, not a user. The size/DTD checks are a narrow fixture contract, not a production XML security recipe; never expose this parser as a network service.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoring the correlation experiment, with no network or shell activity. `ModuleNotFoundError` indicates filename/directory trouble. The parser is not intended for arbitrary captured WinRM traffic. Delete the directory and its `__pycache__`; no host configuration was changed.

### Retained Study Checklist

- [ ] Local WinRM exercise: Configure a constrained remoting endpoint between isolated lab VMs and expose one harmless inventory command. Verify a denied command and unauthorized user fail.
- [ ] Boundary check: Connect with a synthetic limited role and verify it cannot invoke arbitrary commands or access a second resource with unintended delegated authority.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[WinRM Security]]

## References

- [WinRM security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security)
- [WinRM protocol support](https://learn.microsoft.com/en-us/windows/win32/winrm/protocol-support)
- [MS-WSMV WS-Management extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/)
- [MS-PSRP PowerShell remoting protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
- [JEA overview](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)
