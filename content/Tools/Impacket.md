---
title: "Impacket"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Impacket

> [!abstract] TL;DR
> Separate protocol serialization from network operations and authentication. Build and parse a benign SMB2 ECHO fixture offline, validate framing independently, and record exactly what the bytes do and do not prove.

> [!info] Agent scope
> Protocol library and examples; environment setup; authentication concepts; version-aware APIs; logging; protocol links. Executable scope is offline benign protocol construction/parsing only, with no remote execution, credential dumping, relay, credential forgery, or bypass procedures.

## Prerequisites

- Required offline track: Python 3.12 stdlib, a plain text editor, and an empty temporary directory. Eight core tests run without Impacket; two integration tests require the library and are explicitly skipped if absent.
- Integration baseline: official Fortra Impacket **0.12.0** packet APIs, selected because the referenced tag's structures were inspected. This is a reproducibility pin for a synthetic offline exercise, **not a claim that this historical release is the latest or a recommendation for deployment**. Review current project advisories/releases before provisioning; a newer release must pass the same interoperability checks and have its exact version recorded.
- Use a dedicated interpreter/venv with dependencies provisioned by the lab owner. No administrator access, Windows domain, SMB server, account, packet capture driver, or network route is needed. The supplied program creates no sockets and reads no credential stores.
- Python packaging helpers and example command wrappers vary across pip, distro packages, and source installs. The library version and imported module path, not an example filename alone, define what will execute.

## Learn

```text
Teach me Impacket at expert protocol-library and defensive-analysis depth using
only offline self-authored bytes. Assume Python 3.12, struct, TCP framing, SMB,
and authentication versus authorization basics. Establish package version,
module provenance, dependency isolation, historical API baseline versus current
security support, and differences between library structures and example clients.
Trace an SMB2 synchronous header, 4-byte ECHO body, and direct-TCP length prefix;
explain little-endian fields versus big-endian transport length, offsets, message
IDs, request/response flags, session/tree identifiers, compound offsets, and why
parsing a signed flag does not verify a signature. Compare Impacket Structure
getData/parsing APIs with an independent Python stdlib byte-layout oracle.
Provide a complete program with deterministic bytes, round trips, truncation/
length/type/body checks, optional actual Impacket interoperability tests, exact
expected counts, and cleanup. Restrict its validator explicitly to this fixture;
do not present it as a general SMB security validator or cryptographic verifier.
Explain SMB/RPC/LDAP/Kerberos/NTLM layering and defensive log interpretation
conceptually, including hostname/SPN/time, authentication failure versus access
denied, signing versus encryption, parser success versus server acceptance, and
the privacy implications of debug output. Do not construct authentication
messages, read credentials, start listeners, connect to hosts, or demonstrate
remote execution, dumping, relay, forgery, or protection bypass. Use official
Fortra source and Microsoft protocol specifications. Teach in this conversation,
not by editing files or changing study status.
```

## Cheatsheet

### Library Surface and Side Effects

| Surface | Purpose | Boundary |
|---|---|---|
| `impacket.structure.Structure` | Declarative field serialization/parsing; `getData()` emits bytes | A field layout is not complete protocol-state or input-security validation. |
| `impacket.smb3structs.SMB2Packet` | SMB2 synchronous header plus raw Data | Header class selection must match flags/format; no signature verification from parsing alone. |
| `SMB2Echo` | Fixed 4-byte ECHO body | Contains StructureSize=4 and reserved=0; not an authentication message. |
| `impacket.nmb.NetBIOSSessionPacket` | Length-prefixed session-message framing | Uses `rawData()` and `get_trailer()`, not the same method names as Structure. It is not a TCP stream reassembler. |
| Connection/client classes | Negotiate, authenticate, send and receive | Construction can open sockets; not used in this lab. Do not substitute a connection class for a packet class. |
| Installed example wrappers | Combine library calls into workflows | Names/options/side effects vary. Read source/help for the exact release before any separately authorized use. No operational client workflow is included here. |

A successful import of `impacket` proves only that Python resolved a module. Record distribution metadata and filesystem origin to detect environment confusion or a local file shadowing the package. Avoid naming the lab file `impacket.py`, `struct.py`, or `socket.py`.

Read-only environment checks for an already provisioned interpreter:

```powershell
py -3.12 --version
py -3.12 -m pip show impacket
py -3.12 -c "import impacket; from importlib.metadata import version; print(version('impacket')); print(impacket.__file__)"
```

Use the dedicated venv's Python executable instead of `py` for every command when integration dependencies live there. Never infer that a globally installed command uses that same interpreter.

### Byte Layout of the Offline Record

The fixture is a **single direct-TCP framed, synchronous, unsigned, non-compound SMB2 ECHO request-shaped record**. It is a serialization exercise, not a live negotiated session; session/tree IDs are zero and it is never sent. SMB2's header remains the base structure for several SMB3 operations, but the selected protocol state cannot be inferred merely from magic bytes.

| Offset from SMB2 header | Width | Fixture field/value | Interpretation |
|---|---|---|---|
| 0 | 4 | `fe 53 4d 42` | SMB2 magic, distinct from SMB1 and SMB3 transform headers. |
| 4 | 2 | 64 | Header StructureSize, little-endian. |
| 6 | 2 | 0 | CreditCharge; fixed teaching value, not credit negotiation. |
| 8 | 4 | 0 | Request reserved/channel-sequence area represented by the baseline class's Status slot; no response status is inferred. |
| 12 | 2 | 13 (`0x000d`) | ECHO command. |
| 14 | 2 | 1 | CreditRequestResponse field. |
| 16 | 4 | 0 | Request flags; no signed/server-to-client/async flags. |
| 20 | 4 | 0 | NextCommand: no compound record. |
| 24 | 8 | 7 | Synthetic MessageID; not a user or process ID. |
| 32 / 36 | 4 / 4 | 0 / 0 | Reserved and TreeID for this layout. |
| 40 | 8 | 0 | SessionID; no authenticated session exists. |
| 48 | 16 | all zero | Signature storage; not a computed authenticator. |
| 64 | 4 | `04 00 00 00` | ECHO body's StructureSize=4, reserved=0. |

Prefix the 68-byte SMB2 message with `00 00 00 44`: a zero message-type byte and a **three-byte big-endian** length. Total record length is **72 bytes**. Header offsets above exclude that four-byte prefix; MessageID therefore begins at record offset 28. TCP receive boundaries are unrelated to record boundaries; a general receiver must reassemble, enforce length bounds, and handle multiple records. This offline parser intentionally accepts exactly one record and rejects trailing data.

### Protocol and Defensive Interpretation

SMB negotiation chooses dialect and capabilities; session setup establishes an authenticated context; tree/file operations have separate authorization. RPC adds interface/binding and operation semantics over a transport, with NDR representation and authentication levels; decoding an RPC header does not prove a procedure was accepted. LDAP distinguishes transport security, bind authentication, and directory access checks. These are separate layers, not a universal Impacket permission model.

Kerberos depends on the intended service identity/SPN, realm, name resolution, clock validity, and ticket context; NTLM is a different challenge/response mechanism. This note provides no credential formats, authentication-message builders, or credential-cache operations. A network timeout, negotiation mismatch, authentication rejection, and authorized-session access denial must not be collapsed into one diagnosis.

Signing supplies integrity/authenticity under session keys; encryption adds confidentiality under negotiated algorithms. A set signed flag or a nonzero signature field is not evidence that verification succeeded. SMB3 encryption/compression transforms are not the plain `SMB2Packet` layout; reject them in this fixture instead of trying to interpret ciphertext as headers. Zero IDs/signatures here explicitly limit conclusions to layout, not service acceptance or policy security.

For authorized defensive evidence outside this offline lab, correlate timestamps, endpoint identity, dialect, command, status, message/session IDs, and server-side events. Debug logging and packet captures can contain names, paths, authentication material, or application data; never enable broad capture merely to get a parser example. Here record only generated bytes, package version, SHA-256, expected lengths, and test results. No real protocol logs are needed.

## Gotchas

- Impacket parsing can accept a length-framed trailer without proving its declared length matches the complete input. The lab checks that independently before calling its packet parser.
- Parsing and reserializing with the same library can preserve the same mistake. The independently packed stdlib reference supplies a second oracle.
- An exception from a local parser is not an SMB server error. This lab has no server and cannot report successful authentication, signing negotiation, or authorization.

## Labs

### Environment and Complete Files

The standalone file below needs only Python 3.12. Integration imports are optional; incompatible installed dependencies cause a visible error, not a silent fallback. The `--require-impacket` gate prevents skipped integration checks from being mistaken for completion. The historical package pin below is for a lab owner who elects to provision that isolated baseline separately; nothing in this note has been installed or executed by the author.

### File: requirements.txt

```text
impacket==0.12.0
```

Dependency provisioning, only when separately permitted by the lab owner: create a dedicated venv with `py -3.12 -m venv .venv`, then use `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` in an approved setup environment. This may download transitive dependencies; the single top-level pin is **not** a full dependency lock or integrity manifest. For an air-gapped run, the owner must pre-provision the environment or an approved complete wheel set. No installation is needed for the eight stdlib checks.

### File: test_example.py

```python
import argparse
import hashlib
import importlib.util
from importlib.metadata import version
from pathlib import Path
import struct
import unittest


HEADER = struct.Struct("<4sHHIHHIIQIIQ16s")
ECHO = struct.Struct("<HH")
HAS_IMPACKET = importlib.util.find_spec("impacket") is not None
if HAS_IMPACKET:
	from impacket.nmb import NetBIOSSessionPacket
	from impacket.smb3structs import SMB2Packet, SMB2Echo, SMB2_ECHO


def build_record(message_id=7):
	payload = HEADER.pack(b"\xfeSMB", 64, 0, 0, 13, 1, 0, 0,
						  message_id, 0, 0, 0, bytes(16)) + ECHO.pack(4, 0)
	return b"\x00" + len(payload).to_bytes(3, "big") + payload


def parse_record(record):
	if len(record) < 4:
		raise ValueError("Truncated prefix")
	if record[0] != 0:
		raise ValueError("Unexpected message type")
	declared = int.from_bytes(record[1:4], "big")
	if declared != len(record) - 4:
		raise ValueError("Length mismatch")
	if declared != HEADER.size + ECHO.size:
		raise ValueError("Only one fixed ECHO record is supported")
	fields = HEADER.unpack_from(record, 4)
	(magic, size, charge, status, command, credits, flags, next_command,
	 message_id, reserved, tree_id, session_id, signature) = fields
	if magic != b"\xfeSMB" or size != 64:
		raise ValueError("Wrong plain SMB2 header")
	if command != 13 or flags != 0 or next_command != 0:
		raise ValueError("Not the fixture's synchronous ECHO request")
	if (charge, status, credits, reserved, tree_id, session_id, signature) != (
			0, 0, 1, 0, 0, 0, bytes(16)):
		raise ValueError("Not the fixture's unsigned zero-session fields")
	if ECHO.unpack_from(record, 4 + HEADER.size) != (4, 0):
		raise ValueError("Wrong ECHO body")
	return {"length": declared, "command": command, "message_id": message_id}


class ExampleTests(unittest.TestCase):
	def test_sizes_and_prefix(self):
		self.assertEqual((HEADER.size, ECHO.size), (64, 4))
		record = build_record()
		self.assertEqual(len(record), 72)
		self.assertEqual(record[:8], bytes.fromhex("00000044fe534d42"))

	def test_roundtrip(self):
		for message_id in (0, 7, 0x0102030405060708):
			self.assertEqual(parse_record(build_record(message_id)),
							 {"length": 68, "command": 13, "message_id": message_id})

	def test_truncation(self):
		record = build_record()
		for length in (0, 3, 4, 63, 71):
			with self.subTest(length=length), self.assertRaises(ValueError):
				parse_record(record[:length])

	def test_declared_length(self):
		record = bytearray(build_record())
		record[3] = 67
		with self.assertRaisesRegex(ValueError, "Length"):
			parse_record(record)

	def test_wrong_protocol(self):
		record = bytearray(build_record())
		record[4] = 0xFD
		with self.assertRaisesRegex(ValueError, "header"):
			parse_record(record)

	def test_wrong_body(self):
		record = bytearray(build_record())
		record[68:72] = ECHO.pack(5, 0)
		with self.assertRaisesRegex(ValueError, "body"):
			parse_record(record)

	def test_wrong_command(self):
		record = bytearray(build_record())
		record[16:18] = struct.pack("<H", 0)
		with self.assertRaisesRegex(ValueError, "ECHO"):
			parse_record(record)

	def test_trailing_record(self):
		with self.assertRaisesRegex(ValueError, "Length"):
			parse_record(build_record() + build_record())


@unittest.skipUnless(HAS_IMPACKET, "Optional Impacket integration not provisioned")
class IntegrationTests(unittest.TestCase):
	def test_impacket_build_matches_reference(self):
		packet = SMB2Packet()
		packet["Command"] = SMB2_ECHO
		packet["CreditRequestResponse"] = 1
		packet["MessageID"] = 7
		packet["Signature"] = bytes(16)
		packet["Data"] = SMB2Echo().getData()
		envelope = NetBIOSSessionPacket()
		envelope.set_type(0)
		envelope.set_trailer(packet.getData())
		self.assertEqual(envelope.rawData(), build_record())

	def test_impacket_parse_matches_reference(self):
		record = build_record()
		self.assertEqual(parse_record(record)["message_id"], 7)
		envelope = NetBIOSSessionPacket(record)
		self.assertEqual(envelope.get_length(), 68)
		packet = SMB2Packet(envelope.get_trailer())
		self.assertEqual(packet["Command"], SMB2_ECHO)
		self.assertEqual(packet["MessageID"], 7)
		self.assertEqual(packet["Flags"], 0)
		self.assertEqual(SMB2Echo(packet["Data"])["StructureSize"], 4)
		self.assertEqual(packet.getData(), record[4:])


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--require-impacket", action="store_true")
	parser.add_argument("--write", action="store_true")
	options = parser.parse_args()
	if options.require_impacket and not HAS_IMPACKET:
		parser.error("Impacket integration is required but the package is absent")
	print("impacket=" + (version("impacket") if HAS_IMPACKET else "absent"), flush=True)
	if options.write:
		record = build_record()
		parse_record(record)
		with Path("echo.bin").open("xb") as output:
			output.write(record)
		print("bytes=", len(record), "sha256=", hashlib.sha256(record).hexdigest())
		print(record.hex(" "))
	else:
		unittest.main(argv=[__file__], verbosity=2)
```

### Objectives and Steps

Offline stdlib track:

```powershell
py -3.12 test_example.py
py -3.12 test_example.py --write
Format-Hex -Path echo.bin
Get-FileHash echo.bin -Algorithm SHA256
```

Already provisioned integration track, using its dedicated interpreter:

```powershell
.\.venv\Scripts\python.exe -m pip show impacket
.\.venv\Scripts\python.exe test_example.py --require-impacket
```

1. Inspect the source: no client/session connection object, hostname, credential input, or socket operation exists. The byte mutations are local negative parser tests; do not transmit the records.
2. Run the tests and record the actual package version plus passed/skipped counts. Require all ten tests for the integration claim; eight pass/two skip establishes only the stdlib track.
3. Generate `echo.bin` once and compare its byte count, first eight bytes, body, and hash between Python and PowerShell. No expected hash is fabricated here; two independently computed hashes must match for the same file.
4. Trace MessageID=7 through wire offset 28, stdlib parsing, and the optional Impacket parser. Explain why the four-byte prefix is excluded from SMB-relative offsets.
5. Inspect the truncated/incorrect-length/body/command checks. Explain why exact-length and semantic checks occur before library parsing and why this deliberately strict parser rejects other legitimate SMB messages too.
6. If integration is available, compare library-generated bytes with the independent struct-packed reference and then parse the reference through the library. Do not relax comparisons merely to make a newer release pass; identify the changed field/API and record it.

### Hints

- The prefix is not a four-byte little-endian payload length. `00 00 00 44` declares 68 bytes, not 0x44000000.
- `getData()` belongs to SMB structures; the envelope uses `rawData()`. Constructing `NetBIOSSessionPacket` is offline; constructing a similarly named TCP session class is not this exercise.
- Optional tests marked skipped are not executed library checks. `--require-impacket` makes missing integration a visible error.

### Solution and Expected Results

Expected test discovery: **10 tests**. Without Impacket: **8 pass, 2 skip**, assuming the fixture works as designed. With the provisioned compatible library: **10 pass, 0 skip**. These are expected results, not author observations. Expected generated artifact: one **72-byte** file, a 68-byte SMB2 payload, command 13, MessageID 7, and final bytes `04 00 00 00`. Its contents do not prove a server would accept it or that a session is authorized.

The defensive lesson is layered validation: transport size/type, selected header format, fixed command/body contract, and only then field interpretation. A round trip plus independent byte oracle detects layout disagreement; it still does not verify authentication, cryptography, protocol state, stream reassembly, or arbitrary hostile inputs.

### Verification, Troubleshooting, and Cleanup

Missing module: use the intended environment; do not install globally as a workaround. A package that imports but fails at runtime is a dependency/API failure and must remain visible. Different serialization: compare first differing field with the layout table and exact tagged source. Existing `echo.bin`: choose a new temporary directory or remove only that synthetic file after saving observations; exclusive-create mode prevents silent overwrite.

Delete only the temporary fixture directory and its `echo.bin`, plus the dedicated venv if one was created solely for this exercise. No account, ticket cache, registry state, listener, remote service, or server policy was touched. Retain only the synthetic bytes/hash and version/check summary.

Author validation: **API definitions inspected in official tagged source; no installation, Python execution, library tests, packet transmission, or service startup performed**. Transitive dependency compatibility on Python 3.12 and newer Impacket releases remains unverified.

- [ ] Local Impacket exercise: Build and parse the offline SMB2 ECHO fixture; record stdlib and actual-library results separately.
- [ ] Boundary check: Reject malformed/truncated local records while preserving valid serialization, without any network operation or authentication material.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]
- [[SMB]]
- [[NTLM]]
- [[Kerberos]]
- [[LDAP]]

## References

- [Fortra Impacket official repository and releases](https://github.com/fortra/impacket)
- [Baseline SMB2 structures, tag impacket_0_12_0](https://github.com/fortra/impacket/blob/impacket_0_12_0/impacket/smb3structs.py)
- [Baseline session framing APIs](https://github.com/fortra/impacket/blob/impacket_0_12_0/impacket/nmb.py)
- [Baseline Structure implementation](https://github.com/fortra/impacket/blob/impacket_0_12_0/impacket/structure.py)
- [Microsoft SMB2 protocol specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Microsoft RPC specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)
