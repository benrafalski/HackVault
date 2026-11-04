---
title: "RDP Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[RDP]]"
updated: 2026-11-03
---
# RDP Security

> [!abstract] TL;DR
> Protect the whole path: gateway policy, validated host identity, NLA, host logon rights, redirection and session lifetime. A strong gateway does not protect an independently reachable direct listener.

> [!info] Agent scope
> Security of: Connection and authentication; NLA; TLS; sessions; redirection; gateway; permissions; exposure controls. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Listener reachability, certificate validation, CredSSP, gateway CAP/RAP, host allow/deny rights, virtual channels, session reconnect and disconnected state.
- Unauthorized access requires a reachable permitted path and failure of authentication or authorization controls; excessive data exposure can occur inside an otherwise legitimate session. Exercises only diagnose synthetic policy, never probe hosts or collect credentials.

## Learn

```text
Teach defensive RDP security at expert depth. Assume TLS, CredSSP/NLA, Windows
tokens and RDS sessions. Analyze gateway CAP/RAP versus host logon rights,
certificate identity, NLA versus MFA, direct-path exposure, clipboard/drive
channels, reconnect, idle/disconnected limits and credential-handling modes.
Explain root causes and threat prerequisites conceptually; give no credential
theft, movement, exploitation, bypass, evasion or persistence procedures.
Provide exact read-only observation and lab-only secure policy semantics,
version/edition caveats, event correlation and false-positive analysis. Supply
a complete Python 3.12 stdlib offline policy lab showing a permissive baseline,
a concrete fix, unchanged allowed sessions and negative regressions. Label
policy models as non-enforcement. Use primary Microsoft sources, no real
accounts or production targets, no execution claims or file edits. Finish with
worked diagnosis questions, including authentication success without a desktop.
```

## Cheatsheet

### Defensive Contracts

| Boundary | Required evidence | Limitation |
|---|---|---|
| Network path | Host firewall permits only designated lab gateway/management sources | Changing a port is not source restriction; gateway MFA does not cover direct access. |
| Gateway | CAP authorizes identity/authentication; RAP authorizes target | These do not grant the host's Remote Interactive logon right. |
| Server identity | Intended hostname, trusted certificate chain and validity | Encryption with an unvalidated peer is insufficient. Gateway and host have distinct identities. |
| NLA | CredSSP pre-session authentication required, patched clients/hosts | Not MFA, not host authorization, and not a universal guarantee of no delegated credentials. |
| Host authorization | Effective allow right and no applicable deny right | Membership alone is insufficient; deny takes precedence. |
| Channels | Explicitly permitted redirection only | Encryption protects transit, not misuse of an allowed clipboard/drive channel. |
| Lifecycle | Idle/disconnected time limits and controlled reconnect | Disconnect can leave processes and resources live. Logoff can lose unsaved work. |

CredSSP binds authentication to the TLS server exchange; patch state matters. Do not solve an authentication failure by weakening the Encryption Oracle Remediation policy or accepting certificate warnings. Remote Credential Guard and Restricted Admin change credential exposure and available authentication flows, have compatibility requirements and are not blanket replacements for access control. This note does not configure alternate credential modes.

### Exact Lab-only Policy Semantics

On an owned snapshot-backed Windows Pro/Enterprise/Server VM only, use Local Group Policy or the lab domain GPO. Administrative Templates path prefix: `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host`.

| Policy below that prefix | Lab setting | Meaning |
|---|---|---|
| Security > Require user authentication for remote connections by using Network Level Authentication | Enabled | Require NLA. |
| Security > Require use of specific security layer for remote (RDP) connections | Enabled: SSL (TLS) | Require TLS security layer; this label does not pin TLS 1.0 or any specific TLS version. |
| Device and Resource Redirection > Do not allow clipboard redirection | Enabled | Deny clipboard channel use according to host policy. |
| Device and Resource Redirection > Do not allow drive redirection | Enabled | Deny redirected client drives. |
| Session Time Limits > Set time limit for disconnected sessions | Enabled: 15 minutes | End disconnected sessions after this lab limit; choose production values through owner review. |

User-right policy path: `Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment`. "Allow log on through Remote Desktop Services" should name only the intended lab group; "Deny log on through Remote Desktop Services" overrides applicable allows. Do not replace rights on a real machine or remove emergency console access. Restore the VM snapshot afterward. Policies, edition support, precedence and re-logon requirements are version-dependent; examples are not runtime-verified here.

Read-only local observation, no remote connections:

```powershell
Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" | Select-Object UserAuthenticationRequired,SecurityLayer,SSLCertificateSHA1Hash
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue | Select-Object UserAuthentication,SecurityLayer,fDisableClip,fDisableCdm,MaxDisconnectionTime
gpresult /Scope Computer /r
quser
```

`gpresult /r` identifies applied GPOs, not every effective setting. A missing registry value is not proof of a permissive effective configuration. The certificate hash identifies a configured certificate; separately inspect its chain, SAN, lifetime and private-key availability in the VM. Never publish real policy or session output.

### Evidence and Failure Interpretation

NLA success followed by denied interactive logon is expected for a valid identity lacking rights. TLS failures occur before that decision. A disconnected session can still consume resources; a timeout that merely disconnects is not equivalent to ending it. Granular clipboard-direction controls and RDP client behavior differ by release; test the actual supported client/host pair before declaring a channel blocked.

## Detection and Defense

Security 4624 type 10 indicates RemoteInteractive logon; 4625 provides failure status/substatus but must be interpreted with the logon stage. TerminalServices-RemoteConnectionManager Operational 1149 commonly indicates successful authentication, not proof of a usable desktop. LocalSessionManager Operational events such as 21/24/25 support logon/disconnect/reconnect analysis. Security 4778/4779 support reconnect/disconnect auditing where enabled. Event availability and exact fields depend on build and audit policy.

Read-only lab query: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4778,4779; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 30`. Correlate by host, identity, time, session/logon fields as appropriate; never equate session ID and logon ID numerically. Gateway/proxy source addresses can obscure the original endpoint. Helpdesk reconnects and network instability are common benign causes of repeated events. Missing events can be an audit/retention gap.

## Labs

### Environment and Complete Files

Use a new empty `rdp-security-offline` directory, Python 3.12, and the single file below. Standard library only, fixtures embedded, no Windows/AD/network/services/elevation/credentials. This model consumes synthetic trusted facts; it cannot validate TLS, perform MFA, implement CredSSP, or enforce Windows rights. The permissive baseline is never applied to a machine. Author execution unverified.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Request:
	authenticated: bool = True
	tls_valid: bool = True
	nla: bool = True
	path: str = "gateway"
	cap: bool = True
	rap: bool = True
	mfa: bool = True
	allow_logon: bool = True
	deny_logon: bool = False
	requested_channels: frozenset = frozenset({"audio", "clipboard", "drive"})


def baseline(request):
	return request.authenticated


def hardened(request):
	checks = (request.authenticated, request.tls_valid, request.nla,
			  request.path == "gateway", request.cap, request.rap,
			  request.mfa, request.allow_logon, not request.deny_logon)
	if not all(checks):
		return False, frozenset()
	return True, request.requested_channels & frozenset({"audio"})


class ExampleTests(unittest.TestCase):
	def test_permitted_session_and_channels(self):
		request = Request()
		self.assertTrue(baseline(request))
		self.assertEqual(hardened(request), (True, frozenset({"audio"})))

	def test_host_authorization(self):
		for request in (replace(Request(), allow_logon=False),
						replace(Request(), deny_logon=True)):
			self.assertTrue(baseline(request))
			self.assertEqual(hardened(request), (False, frozenset()))

	def test_gateway_decisions(self):
		for field in ("cap", "rap", "mfa"):
			with self.subTest(field=field):
				request = replace(Request(), **{field: False})
				self.assertTrue(baseline(request))
				self.assertFalse(hardened(request)[0])

	def test_direct_path(self):
		request = replace(Request(), path="direct")
		self.assertTrue(baseline(request))
		self.assertFalse(hardened(request)[0])

	def test_transport_and_authentication(self):
		for field in ("tls_valid", "nla", "authenticated"):
			with self.subTest(field=field):
				self.assertFalse(hardened(replace(Request(),
											 **{field: False}))[0])


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Confirm `python --version` reports 3.12; run `python -m unittest -v test_example` from the directory. All five tests should pass, including assertions that document the baseline's weakness.
2. Identify the synthetic request that has all gateway decisions but is denied by the host. Explain why a direct path is rejected even with `mfa=True` in this gateway-only profile.
3. Temporarily change `not request.deny_logon` to `True`; rerun to detect the authorization regression. Restore and rerun.

### Hints

CAP, RAP and host logon rights answer different questions. Requested channels must be filtered after the session is authorized. A claimed MFA fact is not meaningful outside its verified access path.

### Solution and Fixed Retest

`deny_logon=True` rejects the session despite successful authentication and gateway decisions. The baseline erroneously accepts it. The fixed gateway-only contract also rejects direct traffic and omits clipboard/drive from allowed channels while retaining audio and the permitted session. Five tests should pass after restoration; the temporary edit fails the host-authorization test. The model's gateway-only choice is a lab policy, not a universal Windows default.

### Verification, Troubleshooting, and Cleanup

Acceptance: five tests pass, the regression is detected, and the reader can separate TLS, NLA, gateway and host decisions. A missing module means the wrong directory/file; no actual RDP event is expected. Delete the directory and `__pycache__`. Optional policy changes require snapshot restoration and are not prerequisites for this offline lab.

### Retained Study Checklist

- [ ] Local RDP exercise: Use two isolated Windows VMs to connect to a permitted synthetic account with NLA. Test denied logon rights and disable unnecessary redirection.
- [ ] Boundary check: Attempt a connection with a valid account lacking RDP logon permission and require denial; verify prohibited drive/clipboard redirection is unavailable.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[RDP]]

## References

- [Remote Desktop Services](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)
- [Deny log on through Remote Desktop Services](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services)
- [Remote Desktop Services policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver)
- [Remote Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
