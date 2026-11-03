---
title: "SMB Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[SMB]]"
updated: 2026-11-03
---
# SMB Security

> [!abstract] TL;DR
> Protect SMB identity, message integrity, confidentiality, and object authorization independently. A secure capability is not evidence it was required or negotiated; a protected connection can still expose an over-permitted file.

> [!info] Agent scope
> Security of: Dialects; negotiation; sessions; shares; permissions; signing; encryption; authentication; client/server configuration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Client-selected destinations and server names; SPNEGO authentication; negotiation; share policy; filesystem ACLs; guest fallback; administrative shares; caching and existing handles.
- Network interception risk requires a relevant network position and insufficient peer/message binding. Excessive access requires reachable services and an identity whose effective rights are too broad. Discuss these prerequisites only; no interception, credential collection, or relay exercise is supplied.

## Learn

```text
Teach me defensive SMB security at expert depth. Assume SMB2/3 negotiation,
Windows tokens and DACLs. Trace client destination identity, SPNEGO session,
tree/share, file handle, and transport protection as separate trust boundaries.
Explain SMB1 removal, guest restrictions, signing requirements, SMB3 encryption,
3.1.1 preauthentication integrity, share/NTFS rights, existing handles, and QUIC.
Contrast supported defaults by Windows edition/build with effective policy and
observed sessions. Explain threat prerequisites conceptually, never give
credential theft, relay, movement, exploitation, bypass or evasion procedures.
Give exact read-only observations, narrowly scoped lab-only hardening settings,
event interpretation with false positives, and a complete Python 3.12 stdlib
offline policy regression lab preserving permitted reads. Distinguish model
assertions from Windows enforcement and cryptographic verification. Use primary
Microsoft sources, synthetic identities only, no execution claims or file edits.
End with hard diagnosis questions and worked answers.
```

## Cheatsheet

### Controls and Their Limits

| Boundary | Unsafe assumption | Defensive contract |
|---|---|---|
| Dialect | "SMB2 enabled" excludes SMB1 | Inspect SMB1 separately. SMB2 and SMB3 share the SMB2 server switch; disabling it breaks modern SMB too. |
| Authentication | A successful connection is a named authenticated user | Reject insecure guest use; verify the negotiated package, intended service identity and effective user. An IP or alias can change Kerberos availability. |
| Integrity | Signing supported means signing required | Require signing at the appropriate client/server boundaries; inspect connection state. Authenticated encryption also supplies integrity. |
| Confidentiality | Signed file traffic is confidential | Require SMB3 encryption for sensitive lab shares; signing alone leaves contents readable on the transport. |
| Authorization | Share `Read` is the only access decision | Check share DACL and filesystem DACL, requested access, group memberships and existing handles. |
| Namespace | All paths to a file use the same policy | Review alternate shares, DFS referrals and administrative shares as separate routes with distinct policy. |

For SMB 3.1.1, transcript-derived keys bind negotiation/session setup; a transcript hash is not an ACL and does not make an untrusted destination safe. A server may support encryption without requiring it. `RejectUnencryptedAccess` matters for encryption-required shares; it does not itself designate all shares as confidential. Guest sessions lack normal authenticated session key protections and conflict with signing/encryption requirements.

Windows 11 24H2 Enterprise/Pro/Education require signing in both directions by default; Server 2025 requires outbound signing by default. Do not infer settings for Home, upgraded machines, older systems, appliances or policy-managed hosts. Encryption-required client configuration and dialect bounding options also vary by release. Read installed cmdlet help before selecting newer parameters.

### Observation and Lab-only Hardening

Optional commands require an owned snapshot-backed Windows VM, Windows PowerShell/SmbShare, and elevation for changes. They are documented examples, not executed or runtime-verified here. `LabShare` must be a pre-existing synthetic share; do not create or target a production share. Record settings and snapshot before any change.

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableInsecureGuestLogons
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess
Get-SmbShare -Name 'LabShare' | Select-Object Name,Path,EncryptData
Get-SmbShareAccess -Name 'LabShare'
Get-Acl -LiteralPath 'C:\LabShare' | Format-List AccessToString
Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted
```

Lab-only hardening fragment; these affect more than the one share except the final line. Assess compatibility first, retain console access and restore the VM snapshot afterward. Group Policy can override local choices.

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -RejectUnencryptedAccess $true -Confirm:$false
Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableInsecureGuestLogons $false -Confirm:$false
Set-SmbShare -Name 'LabShare' -EncryptData $true -Confirm:$false
```

Reconnection is necessary to evaluate changed negotiation policy; existing sessions/handles are not evidence of fresh enforcement. Observe the actual test connection from the isolated client's console, without terminating unrelated sessions. Do not relax signing, enable guest or turn on SMB1 to solve a compatibility error.

### Diagnosis and Evidence

`STATUS_LOGON_FAILURE` points toward authentication, `STATUS_BAD_NETWORK_NAME` toward namespace, `STATUS_ACCESS_DENIED` needs the failing command/stage, and `STATUS_SHARING_VIOLATION` can be incompatible open handles. An encryption-required share can deny an older client even when password and file ACLs are correct. Conversely, encrypted traffic can carry an authorized but overbroad read.

## Detection and Defense

Security 5140 records share access; 5145 records detailed share access checks when the corresponding audit policy is enabled. 4663 requires object-access auditing and an applicable SACL and concerns object operations, not just network connection. 4624 logon type 3 can support session correlation but does not prove SMB specifically or that a file was read. Correlate logon ID, source, share, relative path, requested rights and time; IDs are host-scoped.

Read-only local log fragment, elevated if required: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140,5145,4663; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 30`. No matches can mean auditing is absent, not absence of access. Backup jobs, scanners, software distribution and administrators produce legitimate bursts; baseline expected identities and paths. Keep names and paths synthetic in exported evidence. Segment access, minimize write permissions, patch clients/servers, and track exceptions with owners and expiry.

## Labs

### Environment and Complete Files

New empty directory `smb-security-offline`; one file below, embedded fixtures, Python 3.12 standard library only. No network, AD, credentials, Windows changes or packages. This evaluates declared policy and synthetic session observations, not signatures, encryption or Windows ACL algorithms. The unsafe baseline is a pure function; it is never deployed. Runtime unverified by the author.

### File: test_example.py

```python
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Observation:
	dialect: int = 0x0311
	guest: bool = False
	signed: bool = True
	encrypted: bool = True
	operation: str = "read"
	share_rights: frozenset = frozenset({"read"})
	file_rights: frozenset = frozenset({"read"})


def baseline(observation):
	return observation.operation in observation.share_rights


def hardened(observation):
	if observation.dialect not in {0x0300, 0x0302, 0x0311}:
		return False
	if observation.guest or not observation.encrypted:
		return False
	integrity = observation.signed or observation.encrypted
	allowed = observation.share_rights & observation.file_rights
	return integrity and observation.operation in allowed


class ExampleTests(unittest.TestCase):
	def test_allowed_read_survives(self):
		observation = Observation()
		self.assertTrue(baseline(observation))
		self.assertTrue(hardened(observation))

	def test_confidentiality_regression(self):
		observation = replace(Observation(), encrypted=False)
		self.assertTrue(baseline(observation))
		self.assertFalse(hardened(observation))

	def test_guest_and_old_dialect(self):
		for observation in (replace(Observation(), guest=True),
							replace(Observation(), dialect=0x0210)):
			with self.subTest(observation=observation):
				self.assertTrue(baseline(observation))
				self.assertFalse(hardened(observation))

	def test_filesystem_boundary(self):
		observation = replace(Observation(), operation="write",
							  share_rights=frozenset({"read", "write"}))
		self.assertTrue(baseline(observation))
		self.assertFalse(hardened(observation))
		self.assertTrue(hardened(replace(observation,
							file_rights=frozenset({"read", "write"}))))

	def test_authenticated_encryption_integrity(self):
		self.assertTrue(hardened(replace(Observation(), signed=False)))
		self.assertFalse(hardened(replace(Observation(), signed=False,
										 encrypted=False)))


if __name__ == "__main__":
	unittest.main()
```

### CTF Objectives and Baseline

1. Run `python -m unittest -v test_example` in the directory. All five tests should pass because they assert both the unsafe baseline's behavior and the fix.
2. Identify why a signed, unencrypted read passes the baseline but fails this particular confidential-share contract. Find the case where the baseline ignores filesystem policy.
3. Temporarily replace the last line of `hardened` with `return True`; rerun and identify the failed filesystem regression. Restore it and rerun.

### Hints

Signing is not confidentiality. The test with `signed=False` is deliberately encrypted: integrity need not appear as a separate ordinary signature. The synthetic allowed write requires explicit permission at both layers.

### Solution and Fixed Retest

The baseline checks only share rights. The fixed function rejects guest, older dialects, missing encryption, and operations absent from either rights set. The known-good read remains accepted; an explicitly permitted write also remains possible. Five tests should pass after restoration. These booleans are trusted fixture facts, not values an actual server should accept from a remote claimant.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests, explained confidentiality/authorization failures, and the deliberate regression detected. A wrong interpreter or directory is a setup error; no live SMB events should appear. Delete this directory and its cache. Optional VM observations/configuration are a separate unverified exercise; restore its snapshot, not an assumed universal default.

### Retained Study Checklist

- [ ] Local SMB exercise: Create a synthetic share in an isolated Windows lab and test read/write access with two users. Inspect negotiated dialect, signing/encryption, and both share and NTFS permissions.
- [ ] Boundary check: Require signing/encryption according to lab policy and verify a restricted user cannot write or access an unrelated share.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Windows Lateral Movement]]
- [[AD Attacks]]
- [[Impacket]]
- [[SMB]]

## References

- [SMB security](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Set-SmbServerConfiguration](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration)
- [Set-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbshare)
- [Event 5145](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)
