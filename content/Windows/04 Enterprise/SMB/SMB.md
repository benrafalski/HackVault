---
title: "SMB"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[SMB Security]]"
updated: 2026-11-03
---
# SMB

> [!abstract] TL;DR
> SMB negotiates a dialect and transport capabilities, authenticates a session, connects that session to a share, then authorizes file operations. Those are different decisions; successful authentication does not grant file access.

> [!info] Agent scope
> Dialects; negotiation; sessions; shares; permissions; signing; encryption; authentication; client/server configuration.

## Prerequisites

- TCP, Windows access tokens, share permissions, NTFS DACLs, and basic Kerberos/NTLM vocabulary.
- Required lab: Python 3.12 standard library only, no Windows server, AD, network, elevation, packages, or credentials. Optional administrative observations require an owned disposable Windows VM.

## Learn

```text
Teach me SMB 2/3 at protocol and Windows file-server engineering depth. Assume
TCP, access tokens, DACLs, and basic Kerberos/NTLM knowledge. Trace NEGOTIATE,
SESSION_SETUP/SPNEGO, TREE_CONNECT, CREATE, READ/WRITE, CLOSE, and LOGOFF.
Explain dialects, SMB2 header fields, credits, compound requests, async IDs,
session/tree/file identifiers, leases, durable versus persistent handles,
multichannel, preauthentication integrity, signing, and encryption. Separate
authentication, share authorization, and filesystem access checks. Work through
an access-denied case and a reconnect case with synthetic evidence. Compare
Windows client/server versions, SMB over TCP and QUIC, and policy versus actual
negotiated protection. Supply read-only Windows observations and a complete
Python 3.12 stdlib offline state-machine lab with tests; label every abstraction
that is not wire-format or cryptographic enforcement. Use MS-SMB2 and Microsoft
administration documentation. No production targets, real credentials, offensive
procedures, or fabricated results. Teach here, do not edit files or study status.
Finish with difficult troubleshooting questions and worked answers.
```

## Cheatsheet

### Negotiation, Identity, and Objects

| Stage | Important fields/state | Decision and boundary |
|---|---|---|
| Transport | TCP 445; SMB over QUIC uses UDP 443 | Reachability is not authentication. Legacy NetBIOS transport is separate; do not enable SMB1 for compatibility experiments. |
| NEGOTIATE | Dialects, SecurityMode, Capabilities, ClientGuid; server-selected DialectRevision, ServerGuid | Highest mutually supported dialect; policy can still reject the connection. SMB 3.1.1 uses negotiate contexts for preauthentication hash, encryption and other capabilities. |
| SESSION_SETUP | SPNEGO security buffer, SessionId, SessionFlags | Kerberos or NTLM establishes identity and session key material. `STATUS_MORE_PROCESSING_REQUIRED` can be a normal multi-leg authentication continuation. Guest/null flags are not normal authenticated identities. |
| TREE_CONNECT | UNC share path; response TreeId, ShareFlags, Capabilities, MaximalAccess | A share is a namespace and policy boundary. Share encryption can require SMB3 even after successful session authentication. |
| CREATE | DesiredAccess, ShareAccess, CreateDisposition, CreateOptions, contexts | Resolve file; evaluate access and sharing compatibility; return FileId with persistent/volatile components. FileId is scoped state, not a reusable credential. |
| READ/WRITE/CLOSE | FileId, offset, length, credits | Granted handle rights and live object state control operations. A fresh ACL change does not necessarily revoke already-open handles. |

The 64-byte SMB2 header carries Command, Status in responses, Flags, MessageId, CreditCharge, credit request/response, NextCommand, SessionId and a signature. Synchronous headers include TreeId; asynchronous form uses AsyncId. MessageId correlates a request/response, not a user. Credits bound outstanding work; CreditCharge accounts for larger operations. `NextCommand` links aligned compound messages, not independent TCP records.

SMB 2.0.2/2.1 support signing but not SMB3 encryption. SMB 3.0/3.0.2 introduce encryption and multichannel; 3.1.1 adds preauthentication integrity and algorithm negotiation. SMB2 signing uses HMAC-SHA256; SMB3 uses AES-CMAC or newer negotiated algorithms such as AES-GMAC where supported. Encryption uses negotiated authenticated encryption, not a TLS tunnel over TCP 445. SMB 3.1.1 hashes negotiation/session-setup transcripts into key derivation; it does not replace identity verification.

Kerberos normally targets a `cifs/hostname` SPN; aliases, IP addressing, duplicate SPNs, DNS, and trust availability affect authentication selection. Do not equate SPNEGO/Negotiate with proof of Kerberos. A session establishes a token, a tree selects a share, and a handle records granted access. A user can authenticate yet be denied a share or file.

### Access and Availability

For a simple read request, both share policy and the NTFS access check must grant the required rights. Saying "the most restrictive wins" is only shorthand: real DACL evaluation considers ordered ACEs, group SIDs, inheritance, requested masks and privileges. Read, directory traversal, delete, and delete-child are different rights. `ShareAccess` is a handle-sharing contract, not the share's DACL; incompatible existing opens can yield `STATUS_SHARING_VIOLATION` despite correct permissions.

Leases/oplocks let clients cache data, handles, and metadata subject to break notifications. A durable handle supports reconnect after a transient disruption; a persistent handle additionally supports continuously available share failover on appropriate server/cluster deployments. Neither means "keep a file forever." Multichannel binds additional connections to an authenticated session and can improve throughput/fault tolerance; it is not multiple independent user logons.

### Read-only Windows Observations

Only on an owned disposable VM, Windows PowerShell with the SmbShare module; some server observations need elevation. These commands do not initiate access to another machine. Outputs depend on OS/build, current connections, and installed roles; runtime unverified here.

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableInsecureGuestLogons
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess
Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted,NumOpens
Get-SmbSession | Select-Object SessionId,ClientComputerName,ClientUserName,Dialect,NumOpens
Get-SmbShare | Select-Object Name,Path,EncryptData,ContinuouslyAvailable
Get-SmbShareAccess -Name 'LabShare'
Get-Acl -LiteralPath 'C:\LabShare' | Format-List Owner,AccessToString
```

`LabShare` and its path must already exist solely in the optional VM; absent objects produce errors, not proof of denial. Client connection state is stronger evidence of negotiated protection than a server capability setting. A blank `Signed` property on older tooling is unknown, not false. Do not export user/session output from a real environment.

| Symptom | Discriminating evidence |
|---|---|
| `STATUS_NOT_SUPPORTED` | Dialect/protection compatibility and exact failing stage; do not fall back to SMB1. |
| `STATUS_LOGON_FAILURE` | Authentication package, identity format, time/DNS/trust; not an NTFS diagnosis. |
| `STATUS_BAD_NETWORK_NAME` | Share name and server namespace, including DFS referrals. |
| `STATUS_ACCESS_DENIED` | Which stage? Tree policy, encryption requirement, CREATE access mask, or filesystem DACL. |
| `STATUS_SHARING_VIOLATION` | Existing handle sharing flags; retrying with administrator rights need not help. |
| Reconnect loses open | Durable timeout, lease/handle support, target identity, cluster continuity; not just TCP health. |

Windows 11 24H2 Enterprise/Pro/Education require inbound and outbound SMB signing by default; Windows Server 2025 requires outbound signing by default. Editions, effective policy and updates matter. SMB over QUIC availability is OS/edition dependent; its TLS 1.3 transport does not eliminate share ACLs or SMB identity checks.

## Gotchas

Signing supplies integrity, not confidentiality. SMB encryption also supplies integrity, so the absence of an ordinary SMB signature on encrypted traffic is not automatically a failure. A successful read does not prove write rights; a new connection can reuse an existing session, obscuring which identity was tested.

## Labs

### Environment and Complete Files

Use a new empty directory named `smb-tech-offline`. Put the single file below in it. All seed state is embedded. Requires Python 3.12; `python --version` must identify that interpreter (`py -3.12` is an alternative on Windows). No installation, services, sockets, AD, credentials or administrator access. The model covers ordering and rights intersection only: no packets, cryptography, NTFS ACE ordering, DFS or live SMB enforcement. Author runtime validation has not been performed.

### File: test_example.py

```python
import unittest


class Session:
	def __init__(self):
		self.dialect = None
		self.identity = None
		self.tree = None
		self.rights = set()

	def negotiate(self, offered, supported=(0x0210, 0x0302, 0x0311)):
		common = set(offered).intersection(supported)
		if not common:
			raise ValueError("STATUS_NOT_SUPPORTED")
		self.dialect = max(common)
		return self.dialect

	def authenticate(self, identity):
		if self.dialect is None:
			raise RuntimeError("negotiate first")
		if identity != "reader@example.invalid":
			raise PermissionError("STATUS_LOGON_FAILURE")
		self.identity = identity

	def connect(self, share, share_rights, file_rights, encrypt=False):
		if self.identity is None:
			raise RuntimeError("authenticate first")
		if share != "LabShare":
			raise FileNotFoundError("STATUS_BAD_NETWORK_NAME")
		if encrypt and self.dialect < 0x0300:
			raise PermissionError("encryption unavailable")
		self.tree = share
		self.rights = set(share_rights).intersection(file_rights)

	def open(self, requested):
		if self.tree is None:
			raise RuntimeError("connect tree first")
		if not set(requested).issubset(self.rights):
			raise PermissionError("STATUS_ACCESS_DENIED")
		return frozenset(requested)


def ready(dialects=(0x0311,)):
	session = Session()
	session.negotiate(dialects)
	session.authenticate("reader@example.invalid")
	return session


class ExampleTests(unittest.TestCase):
	def test_dialect_selection(self):
		self.assertEqual(Session().negotiate((0x0210, 0x0311)), 0x0311)
		with self.assertRaisesRegex(ValueError, "NOT_SUPPORTED"):
			Session().negotiate((0x0100,))

	def test_order_and_identity(self):
		with self.assertRaises(RuntimeError):
			Session().authenticate("reader@example.invalid")
		session = Session()
		session.negotiate((0x0311,))
		with self.assertRaises(PermissionError):
			session.authenticate("other@example.invalid")

	def test_rights_intersection(self):
		session = ready()
		session.connect("LabShare", {"read", "write"}, {"read"})
		self.assertEqual(session.open({"read"}), frozenset({"read"}))
		with self.assertRaisesRegex(PermissionError, "ACCESS_DENIED"):
			session.open({"write"})

	def test_encryption_dialect_boundary(self):
		with self.assertRaisesRegex(PermissionError, "encryption"):
			ready((0x0210,)).connect("LabShare", {"read"}, {"read"}, True)
		ready().connect("LabShare", {"read"}, {"read"}, True)

	def test_tree_scope(self):
		session = ready()
		with self.assertRaises(RuntimeError):
			session.open({"read"})
		with self.assertRaisesRegex(FileNotFoundError, "BAD_NETWORK_NAME"):
			session.connect("OtherShare", {"read"}, {"read"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. In that directory run `python -m unittest -v test_example`. Predict the stage of each rejection before reading the assertions.
2. Explain why adding `write` to share rights alone cannot repair the denied write. Identify the two pieces of model state that must exist before `open`.
3. In `test_rights_intersection`, temporarily add `write` to the file rights. Run the same command: the expected-denial assertion should fail. Restore the original fixture and rerun.

### Hints

The highest common dialect is a numeric intersection, not the last client offer. The model's rights sets are deliberately simpler than Windows security descriptors. A deny at CREATE is not evidence that SESSION_SETUP failed.

### Solution and Expected Results

The original file has five tests and should end with `OK`. The write is denied because only `read` is common to both policies; authentication and a connected tree are required first. The temporary permission expansion makes `open({'write'})` succeed and therefore causes the negative test to fail. SMB 2.1 cannot satisfy this lab's encryption requirement; SMB 3.1.1 can in the model, not as proof of encryption on a network.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoring the fixture, a deliberately failed regression during the permission experiment, and an explanation of the model limits. `ModuleNotFoundError` usually means the wrong directory or filename. No live SMB output is expected. Delete only the exercise directory and its `__pycache__`; no host configuration was changed.

### Retained Study Checklist

- [ ] Local SMB exercise: Create a synthetic share in an isolated Windows lab and test read/write access with two users. Inspect negotiated dialect, signing/encryption, and both share and NTFS permissions.
- [ ] Boundary check: Require signing/encryption according to lab policy and verify a restricted user cannot write or access an unrelated share.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[Windows Lateral Movement]]
- [[AD Attacks]]
- [[Impacket]]
- [[SMB Security]]

## References

- [MS-SMB2 protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [SMB security](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Get-SmbConnection](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbconnection)
- [SMB over QUIC](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic)
