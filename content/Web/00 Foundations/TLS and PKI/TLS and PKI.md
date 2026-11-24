---
title: "TLS and PKI"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[TLS and PKI Security]]"
updated: 2026-11-03
---
# TLS and PKI

> [!abstract] TL;DR
> TLS negotiates traffic keys and authenticates a peer; PKI supplies the identity-to-key trust chain. Chain trust, hostname matching, certificate purpose, and application authorization are separate checks.

## Prerequisites

TCP byte streams, public/private keys, hashes, and [[Web Lab Setup]]. The lab needs Python 3.12+ linked to an OpenSSL with TLS 1.3, and an OpenSSL 3.x CLI on PATH. It opens no sockets and changes no OS trust store.

## Learn

```text
Teach me TLS and PKI at protocol-engineering depth, assuming TCP and asymmetric
cryptography basics. Trace TLS 1.2 ECDHE and TLS 1.3 handshakes, transcript
authentication, traffic-key derivation, Finished, resumption and early data.
Explain X.509 path building versus validation, SAN hostname/IP checks, EKU,
validity, roots/intermediates, trust-store differences, revocation limitations,
SNI and ALPN. Cover mTLS client authentication versus authorization and every
hop at a terminating proxy. Give exact Python SSLContext and OpenSSL examples,
including an in-memory real handshake, expected failures and cleanup. Separate
API defaults by Python/OpenSSL version, cite primary sources, and explain what
an in-memory test cannot verify. Teach here without editing files or inventing
execution evidence; end with worked failure-diagnosis questions.
```

## Cheatsheet
### Overview
#### Security goals
1. **Confidentiality:** encryption (_AES_ or _RSA_) and key exchanges (_DHE_ or _ECDHE_)
2. **Integrity:** hash functions (_SHA-2_ or _SHA-3_)
3. **Authenticity:** MACs (_HMAC_) or authenticated encryption (_GCM_)
4. **Non-Repudiation:** digital signatures (_RSA-PSS_, *ECDSA*, or _Ed25519_)
#### History

| Year | What    | Who      | Status                                   |
| :--- | :------ | :------- | :--------------------------------------- |
| 1994 | SSL 1.0 | Netscape | Never publicly released (security flaws) |
| 1995 | SSL 2.0 | Netscape | Deprecated (security flaws)              |
| 1996 | SSL 3.0 | Netscape | Deprecated (security flaws)              |
| 1999 | TLS 1.0 | IETF     | Deprecated (security flaws)              |
| 2006 | TLS 1.1 | IETF     | Deprecated (security flaws)              |
| 2008 | TLS 1.2 | IETF     | Active support                           |
| 2018 | TLS 1.3 | IETF     | Recommended / Active support             |
#### Protocol structure
1. **Handshake**: peers are authenticated and agree on a shared master secret and cipher suite
2. **Application Data**: information transmitted is symmetrically encrypted and authenticated using keys derived from the master secret
3. **Connection Closure**: used to close the connection

> [!warning] Errors
Any errors are treated as fatal errors (error message and the connection is closed)
#### Cipher Suites
##### TLS 1.2 Example 
`TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256`
*   **ECDHE** → master secret
*   **RSA:** → authenticate peers
*   **AES_256_CBC:** → encrypt application data
*   **SHA256:** → authenticate application data (HMAC) and key derivation from master secret (PRF)
##### **TLS 1.3 Example**
`TLS_AES_256_GCM_SHA384`
*   **AES_256_GCM:** → encrypt and authenticate application data (AEAD)
*   **SHA384:** → key derivation from master secret (HKDF)

> [!tip] Key Differences
TLS 1.3 cipher suites are significantly simplified since authentication and key exchange methods are often implied or derived from certificates (no longer explicitly bundled into the cipher suite string like TLS 1.2)
### Handshake and Record Layer
#### TLS Record Layer
| Byte Offset | Field Name         | Size    | Description / Common Values                                                                                                                                                                                                 |
| ----------- | ------------------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`0`**     | **Content Type**   | 1 Byte  | Identifies the higher-level protocol. Can be: <br><br>Change Cipher Spec (`0x14`)<br>Alert (`0x15`)<br>Handshake (`0x16`)<br>Application Data (`0x17`)<br>Heartbeat (`0x18`)                                                |
| **`1 - 2`** | **Legacy Version** | 2 Bytes | Identifies the TLS version. For TLS 1.3, this is locked at `0x0303` (TLS 1.2) for compatibility. Can be: <br><br>`0x0300` (SSL 3.0)<br>`0x0301` (TLS 1.0)<br>`0x0302` (TLS 1.1)<br>`0x0303` (TLS 1.2)<br>`0x0304` (TLS 1.3) |
| **`3 - 4`** | **Length**         | 2 Bytes | The length (in bytes) of the following payload/fragment. Max value is 2¹⁴ (16,384) bytes.                                                                                                                                   |
> [!note] TLS 1.3 Encrypted Record Changes
> In TLS 1.3, to protect user privacy and obscure metadata, the record structure changes after encryption is activated:
> - *Obfuscated Content Type*: The header's Content Type field is hardcoded to 0x17 (Application Data) for all encrypted records, hiding whether the payload is a handshake, alert, or actual application data.
> - *Inner Plaintext*: The real Content Type byte is appended to the end of the plaintext payload before encryption.
> - *Zero Padding*: Zero bytes can be appended after the real Content Type to pad the packet length and hide the true payload size from eavesdroppers.
#### TLS 1.2 Handshake
![[Pasted image 20261118164513.png]]

```
 Client                                                Server

   |                                                     |
   | ------------ 1. Client Hello (RTT 1) -------------> |
   |                                                     |
   | <----------- 2. Server Hello ---------------------- |
   | <----------- 3. Certificate ----------------------- |
   | <----------- 4. Server Key Exchange (ECDHE) ------- |
   | <----------- 5. Server Hello Done ----------------- |
   |                                                     |
   | ------------ 6. Client Key Exchange (RTT 2) ------> |
   | ------------ 7. [Change Cipher Spec] -------------> |
   | ------------ 8. Finished -------------------------> |
   |                                                     |
   | <----------- 9. [Change Cipher Spec] -------------- |
   | <---------- 10. Finished -------------------------- |
   |                                                     |
  [=== Handshake Complete. Encrypted Session Begins ===]
```
##### RTT 1
1. **Client Hello**: client sends its highest supported **TLS Version** (`0x0303` for 1.2), a 32-byte **Client Random** string, a list of supported **Cipher Suites** (200+ to choose from), and optional extensions.
2. **Server Hello**: server replies with the **Selected TLS Version**, its own 32-byte **Server Random** string, and the **Chosen Cipher Suite** from the client's list.
3. **Certificate**: server sends its TLS certificate chain.
4. **Server Key Exchange**: _(Optional, but used for DH/ECDHE)_ The server sends its public key parameters (e.g., EC Curve info) signed with its private key to enable Forward Secrecy.
5. **Server Hello Done**: server signals it is finished for this phase.
##### RTT 2
6. **Client Key Exchange**: The client validates the server's certificate, then generates a **Pre-Master Secret** and shares its own public key parameters (or encrypts the secret using the server's public key if using RSA). 
> [!note] Derivation 
> Both parties independently combine the **Client Random**, **Server Random**, and **Pre-Master Secret** using a Pseudo-Random Function (PRF) to calculate the identical **Master Secret** and session keys.
7. **Change Cipher Spec**: A 1-byte notification signaling that all subsequent data sent by the client will be encrypted using the newly derived session keys.
8. **Finished**: An encrypted hash of all previous handshake messages, ensuring no tamper or man-in-the-middle downgrade occurred.
9. **Change Cipher Spec**: The server switches its transmission status to encrypted
10. **Finished**: The server sends its encrypted verification hash
##### Session Resumption
- Client sends ID of previous session in their Client Hello and if the server validates the ID, the master secret from the previous session will be reused (reduces the handshake to RTT 1)
- **Security implications**: If the master secret from the previous session is compromised then session resumption is insecure (puts forward secrecy at risk). If session resumption is needed to be enabled at all, then session IDs should have a short lifetime (<= 24h) closed parentheses.
##### Debug Commands
```bash
# Test a TLS 1.2 connection
openssl s_client -connect google.com:443 -tls1_2 -brief
# View the full handshake
openssl s_client -connect google.com:443 -tls1_2 -msg
```
#### TLS 1.3 Handshake
![[Pasted image 20261118165825.png]]

```
Client                                                    Server

  |                                                           |
  |--- ClientHello ------------------------------------------>|
  |    (Supported versions, Cipher suites, Key Share [X25519])|
  |                                                           |
  |<-- ServerHello -------------------------------------------|
  |    (Selected version, Cipher suite, Key Share)            |
  |<-- EncryptedExtensions -----------------------------------|
  |<-- Certificate (Server auth) -----------------------------|
  |<-- CertificateVerify (Signature over handshake) ----------|
  |<-- Finished (MAC of transcript) --------------------------|
  |    [Handshake keys active]                                |
  |                                                           |
  |--- Finished (MAC of transcript) ------------------------->|
  |    [Application keys active]                              |
  |                                                           |
  |<== Encrypted Application Data (1-RTT reached) ===========>|
```
##### RTT 1
1. **Client Hello**: client sends its highest supported **TLS Version** (via the `supported_versions` extension), a 32-byte **Client Random** string, a list of supported **AEAD Cipher Suites** (only five to choose from), and a guessing **Key Share** extension (e.g., its public ephemeral `X25519` key).
2. **Server Hello**: server replies with the **Selected TLS Version** (`0x0304`), its own 32-byte **Server Random** string, the **Chosen Cipher Suite**, and its matching **Key Share** extension to complete the cryptographic key exchange.

> [!note] Derivation  
> Both parties immediately combine the **Client Key Share** and **Server Key Share** via HKDF to derive the **Handshake Secret** and initial encryption keys. All subsequent server messages below are sent fully encrypted.

3. **Encrypted Extensions**: server sends its configuration options and extensions (like ALPN or SNI confirmations) securely under the new handshake encryption.
4. **Certificate**: server sends its TLS certificate chain, completely hidden from cleartext eavesdroppers.
5. **Certificate Verify**: server sends a digital signature over the entire handshake transcript up to this point, proving ownership of the private key matching the certificate.
6. **Finished**: server sends a MAC verifying the cryptographic integrity of its flight and the handshake transcript.
7. **Finished**: client validates the server's certificate and signature, then sends its own MAC of the entire transcript to confirm successful, untampered key derivation.
##### Pre-Shared Key (PSK)
- Client sends a label corresponding to a previously established PSK along with its second message to the server -> both client and server use an HKDF to derive an early secret from this shared key (reduces the handshake to RTT 0, i.e. immediate encryption)
- **Security implications**: If a PSK is used without DHE key exchange means application data encrypted with keys derived from the PSK and non-confidential randomness -> no forward secrecy and no replay protection
##### Debug Commands
```bash
# Test a TLS 1.3 connection
openssl s_client -connect google.com:443 -tls1_3 -brief
# View the full handshake
openssl s_client -connect google.com:443 -tls1_3 -msg
```
### X.509 certificates
### TLS 1.2 master secret, PSK, encryption keys & PRF
### TLS 1.3 master secret, PSK, encryption keys & HKDF

### Attacks
#### Logjam
#### LUCKY13
#### Sweet32
#### CRIME
#### Heartbleed





## Cheatsheetv1

### Handshake and Record Layer

TLS 1.3 typically sends ClientHello with supported versions, key share, SNI and ALPN; ServerHello selects version/key share, after which handshake messages are encrypted. EncryptedExtensions, Certificate, CertificateVerify and Finished authenticate the server and transcript. Client Finished completes its side; optional client Certificate/CertificateVerify authenticate the client. Traffic keys use HKDF and transcript hashes; the certificate key signs proof of possession, it does not directly encrypt each HTTP request.

TLS 1.2 ECDHE also offers forward secrecy but has a different handshake and cipher-suite naming. TLS 1.3 removes static RSA key exchange and legacy record ciphers; its suite specifies AEAD and hash, not the certificate authentication type. Do not infer the TLS version from legacy record-version fields in a packet capture. TLS records do not align with HTTP messages or TCP segments.

| Feature | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Full handshake | Commonly 2 RTT before client application data | Commonly 1 RTT; extra round trip if HelloRetryRequest |
| Cipher configuration | `SSLContext.set_ciphers` affects pre-1.3 suites | That Python API does not configure 1.3 suites |
| Resumption | Session IDs/tickets | PSK tickets; optional fresh key exchange |
| 0-RTT | Not TLS 1.3 early data | Replayable; never assume ordinary anti-replay guarantees |
| Renegotiation | Exists in protocol; support/policy varies | Removed; post-handshake mechanisms differ |

TLS 1.0/1.1 are deprecated. Prefer maintained library defaults and TLS 1.2 minimum, or 1.3-only for a controlled compatible fleet. Python 3.12 `create_default_context()` enables certificate verification and hostname checking, but concrete algorithms depend on linked OpenSSL/security policy. Python 3.13 adds stricter default verification flags; lab certificates and production chains must have correct extensions, not just signatures.

### Identity and Path Validation

Servers normally send the leaf and required intermediates, not the root. The client builds a path to a locally trusted anchor; an omitted intermediate may fail for one client even if another cached or fetched it. Verify signatures, validity, basic constraints/path length, key usage, extended key usage and applicable name constraints. Match the requested DNS name against SAN DNS entries; an IP literal requires an IP SAN. Do not rely on Common Name fallback. Wildcard matching is limited, not arbitrary suffix matching.

SNI selects a server certificate/site and is not itself authentication. ALPN selects an application protocol such as `h2` or `http/1.1`; negotiation does not implement that protocol for your application. TLS 1.3 alone does not hide ClientHello metadata. ECH deployment and support are separate. Trust stores differ between browsers, OS tools, Python builds and packaged HTTP clients; installing a CA into one does not prove all clients trust it. Revocation checks are not uniformly enabled in every client; OCSP/stapling and short-lived certificates need explicit operational design.

Python client fragment:

```python
context = ssl.create_default_context(cafile="lab-ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.set_alpn_protocols(["http/1.1"])
```

mTLS server fragment, after loading a server key/certificate:

```python
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile="client-ca.pem")
```

The application still maps validated client identity to allowed actions; any certificate from the CA is not an administrator. A reverse proxy terminates one TLS channel and starts another. Configure backend certificate trust, hostname/SNI and optionally client authentication independently. Client-certificate identity forwarded as a header is trustworthy only when the backend authenticates and exclusively trusts the proxy path.

### Failure Decisions

| Error | Likely layer | Correct next check |
|---|---|---|
| Unable to get issuer | Chain building / trust | Intermediate delivery and exact client trust store |
| Hostname mismatch | Identity binding | Original requested name and SAN; not the resolved IP alone |
| Expired / not yet valid | Certificate or clock | UTC time, leaf and intermediate validity |
| No shared cipher / unsupported protocol | Negotiation | Library versions, security level, key type, TLS bounds |
| Handshake OK, HTTP parse fails | Application protocol | Selected ALPN and actual bytes |
| Client certificate required | mTLS | Client chain/key, EKU, server client-CA trust |

## Gotchas

`curl -k` suppresses a security decision; it is not a chain repair. Certificate pinning creates rotation obligations. Session resumption can avoid a new certificate exchange, so capture interpretation must identify full versus resumed handshakes. A successful handshake cannot prove backend encryption or end-user authorization.

## Labs

### Environment and Complete Files

Python 3.12+, OpenSSL CLI 3.x, no Python packages. Save this complete file in a disposable directory. It creates a short-lived self-signed lab certificate, explicitly trusts only that certificate, and performs a genuine TLS 1.3 handshake through memory BIOs. This is a private trust anchor for a test, not a public CA deployment. All temporary key files are removed by the fixture.

### File: test_example.py

```python
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import unittest


def exchange(client, server, client_in, client_out, server_in, server_out):
	done = [False, False]
	for attempt in range(100):
		for index, peer in enumerate((client, server)):
			if not done[index]:
				try:
					peer.do_handshake()
					done[index] = True
				except ssl.SSLWantReadError:
					pass
		for outgoing, incoming in ((client_out, server_in), (server_out, client_in)):
			data = outgoing.read()
			if data:
				incoming.write(data)
		if all(done):
			return
	raise AssertionError("handshake did not converge")


class TLSTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		if shutil.which("openssl") is None:
			raise RuntimeError("OpenSSL 3.x CLI is required")
		cls.temp = tempfile.TemporaryDirectory()
		cls.addClassCleanup(cls.temp.cleanup)
		cls.root = pathlib.Path(cls.temp.name)
		cls.cert = cls.root / "cert.pem"
		cls.key = cls.root / "key.pem"
		subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
						"-noenc", "-days", "1", "-subj", "/CN=localhost",
						"-addext", "subjectAltName=DNS:localhost",
						"-addext", "basicConstraints=critical,CA:TRUE",
						"-keyout", str(cls.key), "-out", str(cls.cert)],
					   check=True, capture_output=True, timeout=30)

	def peers(self, hostname, trust=True):
		client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		client_context.minimum_version = ssl.TLSVersion.TLSv1_3
		if trust:
			client_context.load_verify_locations(cafile=str(self.cert))
		client_context.set_alpn_protocols(["http/1.1"])
		server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		server_context.minimum_version = ssl.TLSVersion.TLSv1_3
		server_context.load_cert_chain(str(self.cert), str(self.key))
		server_context.set_alpn_protocols(["http/1.1"])
		client_in, client_out, server_in, server_out = [ssl.MemoryBIO() for _ in range(4)]
		client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
		server = server_context.wrap_bio(server_in, server_out, server_side=True)
		return client, server, client_in, client_out, server_in, server_out

	def test_handshake_and_data(self):
		peers = self.peers("localhost")
		exchange(*peers)
		client, server, client_in, client_out, server_in, server_out = peers
		self.assertEqual(client.version(), "TLSv1.3")
		self.assertEqual(client.selected_alpn_protocol(), "http/1.1")
		client.write(b"synthetic-data")
		encrypted = client_out.read()
		self.assertNotIn(b"synthetic-data", encrypted)
		server_in.write(encrypted)
		self.assertEqual(server.read(), b"synthetic-data")

	def test_wrong_name(self):
		with self.assertRaises(ssl.SSLCertVerificationError):
			exchange(*self.peers("other.test"))

	def test_untrusted(self):
		with self.assertRaises(ssl.SSLCertVerificationError):
			exchange(*self.peers("localhost", trust=False))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Record `python --version`, `openssl version`, and `python -c "import ssl; print(ssl.OPENSSL_VERSION)"`; CLI and Python may use different libraries.
2. Run `python -m unittest -v test_example`. Identify which context owns hostname checking and which certificate is trusted.
3. Change the advertised client ALPN list to `["h2"]`; the ALPN assertion should fail because no shared protocol is selected. Restore it. No HTTP/2 implementation is present.
4. Explain why a wrong hostname fails despite trusting the signing key.

### Hints

BIO output must be transferred to the opposite input; the SSL objects perform the protocol, not the Python pump. Empty BIO output is not necessarily a completed handshake.

### Solution and Expected Results

Expected: three tests pass. `localhost` with explicit trust negotiates TLS 1.3 and `http/1.1`, and the server recovers the plaintext only through TLS decryption. Wrong name and absent trust each raise certificate verification errors. The plaintext search is an illustration, not a cryptographic security proof. No routing, packet loss, TCP behavior, full intermediate chain, revocation or proxy hop is tested.

### Verification, Troubleshooting, and Cleanup

Not executed during authoring. `python -m pytest -q test_example.py` is optional with pytest installed. Missing CLI is a prerequisite error, not a skipped success. `unsupported protocol` means Python's TLS build lacks the required capability. A `CalledProcessError` includes OpenSSL stderr in the exception object; inspect it locally. Temporary files clean up automatically; delete the saved test and caches afterward. No root CA was installed.

- [ ] Observe a real in-memory handshake and encrypted application record.
- [ ] Explain trusted-chain versus hostname failures and proxy hop boundaries.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[TLS and PKI Security]]

## References

- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- [Service identity, RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
- [Python 3.12 ssl](https://docs.python.org/3.12/library/ssl.html)
- [OpenSSL verification](https://docs.openssl.org/3.0/man1/openssl-verify/)
