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
