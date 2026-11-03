---
title: "TLS and PKI Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[TLS and PKI]]"
updated: 2026-11-03
---
# TLS and PKI Security

> [!abstract] TL;DR
> Keep identity validation enabled on every TLS hop. Narrow trust, protect private keys, automate rotation, and authorize the identity after mTLS. An encrypted connection to the wrong peer is still the wrong connection.

## Attack Surface

Trust anchors, leaf/intermediate deployment, certificate names and purposes, private-key storage, resumption state, and TLS-terminating proxies each change who can speak for a service. TLS authenticates transport peers; it does not authorize requests or protect data after decryption.

## Learn

```text
Teach me TLS/PKI hardening assuming handshake basics. Explain path validation,
SAN hostname/IP identity, EKU and validity, trust-store scope, TLS version and
cipher policy, key rotation, revocation limitations, mTLS principal mapping,
early-data replay risk and frontend/backend termination. Give concrete Python
and reverse-proxy settings and an independent offline OpenSSL chain-validation
lab using disposable generated keys. Compare chain-only validation with full
identity validation, then retest positive and negative policy cases. Do not
intercept anyone's traffic, disable a real client's verification, or provide
impersonation/bypass exercises. Include detection, operational false positives,
and primary references. Teach in conversation, not by editing files; distinguish
unexecuted examples from measured evidence.
```

## Cheatsheet

### Required Checks

| Check | Failure when omitted | Remediation / limitation |
|---|---|---|
| Trusted path | Arbitrary issuer accepted | Explicit appropriate CA roots; do not trust a presented root automatically |
| SAN identity | Valid certificate for a different service accepted | Match original service name, not merely an IP from DNS |
| Validity and purpose | Expired or wrong-use credential accepted | Correct clocks, EKU, KU and chain constraints |
| Proof of possession | Certificate treated as bearer text | Actual TLS handshake; a PEM file alone proves nothing about peer |
| Backend validation | Frontend HTTPS hides unprotected backend | Authenticate backend name and issuer; encrypt that hop |
| mTLS authorization | Every trusted client receives all privileges | Map stable approved identity to least-privilege actions |

Chain-only `openssl verify -CAfile ca.pem leaf.pem` does not enforce the application's expected hostname. Add `-verify_hostname service.example.test -purpose sslserver`. For literal IP endpoints use an IP SAN and `-verify_ip`. Certificate verification in a CLI is not a live proof of private-key possession; handshake validation is also required in deployment.

Python configuration fragment, with an explicit private trust bundle:

```python
context = ssl.create_default_context(cafile="service-ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
```

Python 3.12 uses OpenSSL; installed trust and algorithm restrictions vary by build. Python 3.13 tightened default X.509 verification flags. Maintain valid SAN, critical basic constraints for CAs, and correct key usage rather than weakening verification to accommodate malformed certificates. TLS 1.0/1.1 are deprecated. `set_ciphers` does not configure TLS 1.3 suites. Pinning can reduce trust scope but needs planned backup/rotation and an outage recovery process.

### Terminating Proxy Boundary

NGINX HTTPS-upstream fragment for a maintained build, assuming these files and backend already exist. It is not a runnable lab config:

```nginx
location / {
	proxy_pass https://backend.example.test:8443;
	proxy_ssl_server_name on;
	proxy_ssl_name backend.example.test;
	proxy_ssl_verify on;
	proxy_ssl_trusted_certificate /etc/nginx/backend-ca.pem;
	proxy_ssl_verify_depth 3;
}
```

Upstream verification is an explicit setting; `https://` alone is not sufficient evidence. If backend mTLS is required, configure `proxy_ssl_certificate` and `proxy_ssl_certificate_key` for the proxy's client identity as well. Keep backend authorization independent of the client certificate used on the public-facing hop. Strip or overwrite client-supplied identity headers and prevent direct backend access before trusting forwarded identity.

TLS 1.3 0-RTT data can be replayed across connections. Reject early data for state-changing endpoints unless the application has a deliberately designed replay-safe contract; ordinary session cookies do not solve replay. Resumption tickets are credentials: limit lifetime, rotate encryption keys and coordinate rotation among instances. Do not log session secrets or private keys.

## Detection and Defense

Inventory leaf and intermediate expiry, issuing CA, SAN set, deployment location, owner and renewal method. Alert before expiry, on unexpected trust-store changes, validation failures by reason, and certificate/key mismatch. A deployment missing an intermediate, a skewed clock, or an intentional CA rollover can create benign-looking spikes; investigate instead of adding bypass flags. Protect keys with restrictive ACLs or a managed key service, limit export, and rotate/revoke compromised credentials. Revocation behavior differs across clients, so do not claim universal immediate revocation enforcement.

## Labs

### Environment and Complete Files

Python 3.12+, OpenSSL CLI 3.x on PATH; no packages, network, OS trust installation or external certificates. The test generates a private CA and a short-lived server leaf, then invokes real OpenSSL path/name/purpose validation. It does not perform a handshake or emulate a proxy.

### File: test_example.py

```python
import pathlib
import shutil
import subprocess
import tempfile
import unittest


class CertificateTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		if shutil.which("openssl") is None:
			raise RuntimeError("OpenSSL 3.x CLI required")
		cls.temp = tempfile.TemporaryDirectory()
		cls.addClassCleanup(cls.temp.cleanup)
		cls.root = pathlib.Path(cls.temp.name)
		cls.run_ssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
					"-subj", "/CN=Lab Root", "-keyout", "ca.key", "-out", "ca.pem",
					"-addext", "basicConstraints=critical,CA:TRUE",
					"-addext", "keyUsage=critical,keyCertSign,cRLSign")
		cls.run_ssl("req", "-new", "-newkey", "rsa:2048", "-noenc",
					"-subj", "/CN=service.example.test", "-keyout", "leaf.key",
					"-out", "leaf.csr")
		(cls.root / "leaf.ext").write_text(
			"basicConstraints=critical,CA:FALSE\n"
			"keyUsage=critical,digitalSignature,keyEncipherment\n"
			"extendedKeyUsage=serverAuth\n"
			"subjectAltName=DNS:service.example.test\n", encoding="ascii")
		cls.run_ssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem",
					"-CAkey", "ca.key", "-set_serial", "2", "-days", "1",
					"-extfile", "leaf.ext", "-out", "leaf.pem")

	@classmethod
	def run_ssl(cls, *arguments, check=True):
		return subprocess.run(["openssl", *arguments], cwd=cls.root,
							  capture_output=True, text=True, timeout=30, check=check)

	def verify(self, *arguments):
		return self.run_ssl("verify", "-CAfile", "ca.pem", *arguments,
							"leaf.pem", check=False)

	def test_chain_only_baseline_and_identity_fix(self):
		self.assertEqual(self.verify().returncode, 0)
		self.assertEqual(self.verify("-verify_hostname", "service.example.test",
									 "-purpose", "sslserver").returncode, 0)
		self.assertNotEqual(self.verify("-verify_hostname", "other.example.test",
										"-purpose", "sslserver").returncode, 0)

	def test_wrong_purpose(self):
		self.assertNotEqual(self.verify("-purpose", "sslclient").returncode, 0)

	def test_application_authorization(self):
		permissions = {"device-a": {"read"}, "operator-a": {"read", "approve"}}
		self.assertIn("read", permissions["device-a"])
		self.assertNotIn("approve", permissions["device-a"])
		self.assertEqual(permissions.get("unlisted", set()), set())


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Record `openssl version`; run `python -m unittest -v test_example`.
2. Explain why the chain-only baseline succeeds without answering whether `other.example.test` is the intended peer.
3. Compare the same certificate under correct name, wrong name, and client-auth purpose. No TLS connection is made.
4. Remove the wrong-hostname verification argument locally and observe the negative assertion fail; restore it. This changes only an offline command test, not a live client.

### Hints

Issuer trust and identity matching are conjunctive requirements. A certificate with serverAuth EKU should not satisfy sslclient purpose. The final test is a deliberately separate authorization policy, not certificate parsing.

### Solution and Fixed Retest

Expected: three tests pass. Chain-only and correct-name server-purpose verification return zero. Wrong name and wrong purpose return nonzero. `device-a` retains read but not approve permission. The corrective action is adding identity/purpose validation, not replacing the trust bundle with the peer-provided chain. Real termination acceptance must test both actual hops; this lab validates the certificate policy building block only.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Pytest alternative: `python -m pytest -q test_example.py` when installed. CLI absence or generation failure is a setup failure, not a passing skip. OpenSSL error text varies; tests assert outcomes, not localized strings. Temporary key/certificate files are automatically deleted; delete the test directory afterward. Never install this CA globally or reuse its keys.

- [ ] Record chain-only and name/purpose validation differences.
- [ ] Explain mTLS authentication versus authorization and both proxy hops.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[TLS and PKI]]

## References

- [TLS recommendations, RFC 9325](https://www.rfc-editor.org/rfc/rfc9325)
- [Service identity, RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
- [OpenSSL verify options](https://docs.openssl.org/3.0/man1/openssl-verify/)
- [NGINX upstream TLS directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify)
