---
title: "RDP"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[RDP Security]]"
updated: 2026-11-03
---
# RDP

> [!abstract] TL;DR
> RDP separates transport negotiation, server identity, pre-session authentication, interactive logon authorization, and session/channel state. NLA is not MFA; disconnect is not logoff.

> [!info] Agent scope
> Connection and authentication; NLA; TLS; sessions; redirection; gateway; permissions; exposure controls.

## Prerequisites

- TLS certificate validation, Windows tokens and user rights, TCP/UDP, and the difference between authentication and authorization.
- Required exercise: Python 3.12 standard library, offline. Optional read-only Windows observations require an owned disposable VM; no AD or RDP service is needed for the exercise.

## Learn

```text
Teach me RDP at expert protocol and Windows administration depth. Assume TLS,
TCP/UDP, tokens and logon rights. Trace X.224/RDP negotiation, selectedProtocol,
TLS server validation, CredSSP/NLA, MCS/GCC channels, capabilities, interactive
logon and session reconnect. Explain virtual channels, clipboard/device/drive
redirection, session identifiers versus logon IDs, disconnect versus logoff,
gateway CAP/RAP and separate gateway/host identity. Compare direct TCP/UDP,
RD Gateway, and supported Windows editions/builds without assuming defaults.
Provide exact read-only observations, failure-stage diagnosis, and a complete
offline Python 3.12 stdlib session-state lab. Clearly distinguish modeled
decisions from TLS, CredSSP and Windows enforcement. Use MS-RDPBCGR, MS-CSSP
and Microsoft administration sources. No real credentials, production hosts,
offensive procedures, service enabling or fabricated results. Teach in this
conversation, do not edit files or study status. End with worked hard questions.
```

## Cheatsheet

### Connection and Session Flow

| Stage | Mechanism/fields | What it establishes |
|---|---|---|
| Initial transport | Direct TCP 3389 normally; UDP transport can supplement it | Reachability only. Configurable ports are not an access-control mechanism. |
| Negotiation | X.224 connection request/confirm, `RDP_NEG_REQ`, `requestedProtocols`, `RDP_NEG_RSP.selectedProtocol` or failure | `PROTOCOL_SSL` selects TLS; `PROTOCOL_HYBRID` selects CredSSP with TLS; `HYBRID_EX` adds early user authorization behavior. Selection is not a successful user logon. |
| TLS | Certificate chain, hostname/SAN, validity, key possession | Server/transport trust if validation is enforced. Clicking through a certificate warning destroys the intended identity check. |
| NLA/CredSSP | SPNEGO authentication inside TLS, public-key binding, protected credential exchange | Authenticates before allocating the full interactive desktop. NLA can use Kerberos or NTLM and is not MFA. Credential delegation semantics depend on client mode. |
| RDP setup | MCS connect/GCC user data, channel joins, licensing where applicable, Demand Active/Confirm Active capabilities | Graphics, input and channels are negotiated. Licensing failures can occur after authentication. |
| Interactive logon | Token, user rights and applicable session-host policy | Requires logon permission; a valid password alone is insufficient. |
| Active session | Session ID, windows/processes, input/output and virtual channels | Reconnection can reattach existing state rather than create a new logon. |

Traditional RDP security, TLS-only negotiation and NLA are not interchangeable. This note's secure profile requires validated TLS plus NLA. The wire flow has conditional branches; a conceptual diagram must not imply all clients exchange the same PDUs in the same security mode.

### Identity, Rights and Lifecycle

`SeRemoteInteractiveLogonRight` grants "Allow log on through Remote Desktop Services"; `SeDenyRemoteInteractiveLogonRight` denies it and takes precedence for affected identities. Remote Desktop Users membership often contributes to permission but does not override deny rights, GPO, disabled accounts, session-host restrictions or licensing. Administrators are not exempt from an explicit deny right.

A Windows session ID identifies a local interactive session. A Security event logon ID identifies an authentication/logon context on that computer; do not join the two as if they were the same field. Disconnected sessions can retain running applications, open files and tokens. Logoff ends the interactive session and terminates its applications; a network interruption is normally a disconnect, not automatic cleanup. Idle, active and disconnected-session limits are separate policy settings.

Virtual channels extend the trust boundary beyond pixels and keystrokes. `cliprdr` carries clipboard functions; `rdpdr` supports device redirection such as drives and printers; dynamic virtual channels use `drdynvc`. Redirection must be supported by both ends and permitted by effective policy. A client preference cannot override a server prohibition; some finer directional clipboard controls require newer clients/hosts.

### Gateway and Transport Boundaries

RD Gateway commonly uses HTTPS TCP 443 and may use UDP 3391 for its UDP transport. Its certificate is a different identity from the final session host's certificate. A Connection Authorization Policy (CAP) decides who may use the gateway and under what authentication conditions; a Resource Authorization Policy (RAP) decides which resources they may reach. Neither grants host logon rights. MFA at a gateway protects that path, not an independently reachable direct RDP listener. Restrict direct paths accordingly.

Windows Home is not a general inbound Remote Desktop host; Pro/Enterprise and Windows Server roles have different capabilities. Administrative remote sessions and a multi-user RDS deployment have different licensing requirements. UDP unavailability may degrade performance while TCP still succeeds. Remote Credential Guard and Restricted Admin are specialized credential-handling modes with domain, client and service requirements, not synonyms for ordinary NLA.

### Read-only Observation and Diagnosis

Optional local-only commands on an owned disposable Windows VM, runtime unverified. CIM class availability and permissions vary; no command below connects to another host or changes policy.

```powershell
Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" | Select-Object TerminalName,UserAuthenticationRequired,SecurityLayer,SSLCertificateSHA1Hash
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue | Select-Object UserAuthentication,SecurityLayer,fDisableClip,fDisableCdm
quser
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 20
```

`SecurityLayer`: 0 = RDP security, 1 = negotiate, 2 = SSL/TLS in the Windows provider's terminology. It does not report a specific TLS version. A policy registry key can be absent while effective settings exist elsewhere; absence is not evidence that a control is off. `quser` shows local session state, not a cryptographic transcript.

| Failure | Distinguishing check |
|---|---|
| No connection | Listener/firewall/route before credentials; no need to change authentication policy. |
| Certificate warning | Intended hostname, issuing chain and validity; do not suppress validation. |
| NLA/CredSSP error | Client/server updates, time, identity package and credentials; not proof of missing host rights. |
| "Requested session access is denied" | Allow/deny user rights, memberships and resultant policy; a successful NLA event can precede this. |
| Black screen after authentication | Session initialization, graphics, profile or resource issue; authentication success is not desktop readiness. |
| Clipboard unavailable | Client setting, server policy, channel support and session reconnect. |

## Gotchas

An authentication event is not proof of an authorized desktop. A reconnect is not necessarily a new session. Client drive redirection exposes local resources to the remote session, even when the network transport is encrypted.

## Labs

### Environment and Complete Files

Create an empty `rdp-tech-offline` directory with the one file below. Python 3.12, standard library only; all seed identities and state are embedded. No RDP service, Windows, AD, credentials, elevation, packages or sockets. Commands are for the reader/parent validator; author runtime execution is unverified. This state machine is not an RDP or CredSSP implementation.

### File: test_example.py

```python
import unittest


class Desktop:
	def __init__(self):
		self.state = "new"
		self.identity = None
		self.processes = []

	def establish(self, certificate_valid, nla_ok):
		if self.state != "new":
			raise RuntimeError("wrong transport state")
		if not certificate_valid or not nla_ok:
			raise PermissionError("pre-session authentication failed")
		self.state = "authenticated"
		self.identity = "learner@example.invalid"

	def logon(self, allow, deny):
		if self.state != "authenticated":
			raise RuntimeError("authenticate first")
		if not allow or deny:
			raise PermissionError("remote interactive logon denied")
		self.state = "active"
		self.processes = ["synthetic-editor"]

	def disconnect(self):
		if self.state != "active":
			raise RuntimeError("active session required")
		self.state = "disconnected"

	def reconnect(self, identity):
		if self.state != "disconnected" or identity != self.identity:
			raise PermissionError("cannot reattach")
		self.state = "active"

	def logoff(self):
		if self.state not in {"active", "disconnected"}:
			raise RuntimeError("live session required")
		self.processes.clear()
		self.identity = None
		self.state = "ended"


def channels(client, server):
	return set(client) & set(server)


class ExampleTests(unittest.TestCase):
	def test_pre_session_boundary(self):
		for certificate_valid, nla_ok in ((False, True), (True, False)):
			desktop = Desktop()
			with self.assertRaises(PermissionError):
				desktop.establish(certificate_valid, nla_ok)
			self.assertEqual(desktop.processes, [])

	def test_deny_overrides_allow(self):
		desktop = Desktop()
		desktop.establish(True, True)
		with self.assertRaises(PermissionError):
			desktop.logon(True, True)
		self.assertEqual(desktop.state, "authenticated")

	def test_disconnect_and_logoff(self):
		desktop = Desktop()
		desktop.establish(True, True)
		desktop.logon(True, False)
		desktop.disconnect()
		self.assertEqual(desktop.processes, ["synthetic-editor"])
		desktop.reconnect("learner@example.invalid")
		desktop.logoff()
		self.assertEqual((desktop.state, desktop.processes), ("ended", []))

	def test_reconnect_identity(self):
		desktop = Desktop()
		desktop.establish(True, True)
		desktop.logon(True, False)
		desktop.disconnect()
		with self.assertRaises(PermissionError):
			desktop.reconnect("other@example.invalid")

	def test_redirection_intersection(self):
		self.assertEqual(channels({"audio", "clipboard", "drive"},
								  {"audio"}), {"audio"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Verify Python is 3.12 with `python --version`; run `python -m unittest -v test_example` in the fixture directory (`py -3.12` may replace `python` on Windows).
2. Explain why the deny-right test remains `authenticated` with no desktop. Explain which state and processes survive disconnect.
3. Temporarily remove `or deny` from `logon` and rerun. The deny regression must fail; restore and rerun.

### Hints

Authentication proves an identity; authorization decides whether to allocate its interactive session. A channel's availability is the intersection of client request and host allowance, not a unilateral client decision.

### Solution and Expected Results

Five tests should pass in the original fixture. A deny right wins even when allow is true. Disconnect retains `synthetic-editor`; logoff clears it and identity. The wrong reconnect identity is rejected. Only `audio` survives redirection policy. The temporary defect lets logon succeed and fails the expected exception assertion.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoration and a detected deny-right regression. Wrong-directory import errors are unrelated to RDP. No event log or desktop is expected: this is an offline model, including its simplified reconnect identity check, not a reauthentication implementation. Delete only the exercise directory and `__pycache__`. Optional Windows observations need no rollback because they are read-only.

### Retained Study Checklist

- [ ] Local RDP exercise: Use two isolated Windows VMs to connect to a permitted synthetic account with NLA. Test denied logon rights and disable unnecessary redirection.
- [ ] Boundary check: Attempt a connection with a valid account lacking RDP logon permission and require denial; verify prohibited drive/clipboard redirection is unavailable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[RDP Security]]

## References

- [MS-RDPBCGR basic connectivity and graphics remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-CSSP CredSSP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)
- [Remote Desktop Services](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)
- [RD Gateway role](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/role-remote-desktop-gateway)
- [Allow log on through Remote Desktop Services](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)
