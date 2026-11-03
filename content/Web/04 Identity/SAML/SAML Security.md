---
title: "SAML Security"
aliases: []
tags: [web, w4, security]
domain: web
phase: "W4"
type: security
status: draft
pair: "[[SAML]]"
updated: 2026-11-03
---
# SAML Security

> [!abstract] TL;DR
> Signature-wrapping errors, incomplete conditions, weak request correlation, and unsafe XML parsing can make a service consume an assertion it did not validly trust.

> [!info] Agent scope
> Security of: Assertions; bindings; metadata; signatures; audience and recipient validation; identity-provider and service-provider trust. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Trust crosses partner registration, metadata refresh, XML parsing, signature/reference resolution, protocol context, browser correlation and local account mapping. A valid IdP signature establishes only what that IdP signed; it does not automatically establish the intended SP, current browser, fresh authentication, allowed account or action. Encryption is confidentiality, not replacement issuer authentication.

## Learn

```text
Teach defensive SAML 2.0 integration at expert depth. Assume XML, HTTP and signatures.
Explain metadata trust, signature/reference ambiguity, unsafe parsing, context gaps,
unsolicited SSO and account-mapping mistakes as root causes, not bypass recipes.
Give an ordered secure acceptance pipeline covering Response and Assertion signatures,
exact signed-node consumption, issuer, audience, destination, recipient, time, request
and browser binding, AuthnContext, replay and atomic session creation. Explain how
Redirect/POST bindings protect different bytes and why RelayState needs its own binding.
Include real signed synthetic fixtures and independent regression files with trusted
certificate rejection, wrong context, expiry and one-use database transactions plus
positive controls. State precisely which slice is not full SSO. Cover rollover versus
compromise, stale metadata, cache outages, account disable, logout and diagnostic limits.
Use OASIS/W3C/library sources; no credential theft, forgery, exploit XML or bypass
walkthroughs. No invented results. Finish with worked questions, not file edits.
```

## Cheatsheet

### Secure Acceptance Order

1. Select the trusted partner from server-owned transaction/route configuration. Enforce HTTPS, expected binding, body/decompression limits, one value per form parameter, exact ACS and short transaction deadline. Invalid inputs must not trigger arbitrary metadata/URI fetches.
2. Parse with a hardened maintained toolkit: no DTD/external entity resolution, no network resolution or unbounded trees. Validate against pinned local SAML schemas with strict cardinality and unique ID handling. Schema validation alone does not establish trust.
3. Enforce the agreed signature profile (Response, Assertion, or both), allowed algorithms and reference/transform policy. Verify using accepted keys for this IdP. Do not trust an embedded certificate just because its signature is mathematically valid. Accept only the exact signed element returned by the verifier.
4. Validate Response success/version/issuer, protected destination and request correlation. Validate Assertion issuer, subject, conditions, audience and supported bearer confirmation; independently check Recipient and InResponseTo. Do not read unsigned envelope values as authority merely because the Assertion was signed.
5. Enforce `NotBefore <= now < NotOnOrAfter`, bounded skew, maximum acceptance age and authentication freshness. Every supported condition must be enforced; reject unsupported mandatory semantics instead of ignoring them. Multiple audience restrictions are ANDed; alternatives inside a restriction are ORed.
6. Bind the request and opaque RelayState to the initiating browser/action. Atomically claim request and assertion IDs in shared storage, apply account/assurance policy and create a rotated local session. Losing a race must create no session. A consumed request or replay-cache outage cannot fall back to unsolicited login.

| Failure mechanism | Secure decision and evidence |
|---|---|
| Application selects a different node after verification | Consume `signed_xml` only; constrain signature location and references; regression-test library upgrades |
| Metadata authorizes unreviewed partner/key | Pin entity, role, key use and trust source; authenticated configuration changes and bounded rollover |
| Certificate accepted from arbitrary KeyInfo | Supply trusted certificate set independently; wrong configured certificate fails even for well-formed XML |
| Audience/recipient confused | Entity ID authorizes SP; Recipient/Destination authorize endpoints; check each exactly |
| NameID/email used across partners | Map issuer + agreed NameID Format/qualifiers/value to internal ID; no email-only linking |
| Time checked only on Conditions | Check bearer confirmation expiry and authentication/session policy too |
| Replay cache per worker or check-then-insert | Unique constraints/conditional writes in shared transaction; fail closed on storage uncertainty |
| RelayState used as a URL | Store opaque route identifier with transaction; allowlist eventual local navigation |

### Configuration and Lifecycle

Illustrative acceptance policy, **not a library configuration file**:

```json
{
  "idp_entity": "https://idp.example.test/entity",
  "sp_entity": "https://sp.example.test/entity",
  "acs": "https://sp.example.test/saml/acs",
  "unsolicited_sso": false,
  "require_signed_assertion": true,
  "allowed_signature_algorithms": ["rsa-sha256"],
  "allowed_digest_algorithms": ["sha256"],
  "max_assertion_age_seconds": 120,
  "clock_skew_seconds": 0,
  "replay_store_failure": "deny"
}
```

Map every field to the chosen maintained SAML toolkit's documented option or application check; an unused JSON field enforces nothing. Decide Response signing separately with the partner. Never deploy a policy file merely because it looks strict.

Metadata signing keys, IdP assertion-signing keys, SP decryption keys and TLS keys have different purposes and renewal processes. Refresh only from approved sources; validate metadata identity/signature/expiry before replacing a last-known-good trust set. Planned rollover can accept old/new keys for a bounded interval. Emergency compromise removal must override caches and overlap. Never extend stale trust indefinitely because the feed is down. Test new-key acceptance and retired-key rejection, not just metadata download success.

Bearer SAML assertions are sensitive despite being signed. Avoid persistent assertion dumps, URLs, analytics and broad support access. Attribute minimization and encryption may be required across the federation; still enforce signatures and conditions after decryption. Keep local session revocation independent of IdP availability. Single Logout delivery is not guaranteed global revocation; document local session bounds and account-disable enforcement.

## Detection and Defense

Log configured partner, internal reason class, pseudonymous request ID, key version and elapsed time, not raw assertions, NameID, attributes or RelayState. Distinguish parse/signature failures, wrong context, expiry, replay and account denial. Clock skew, stale tabs, duplicate form submission and ordinary certificate rollover are common benign causes. Correlate spikes with metadata deployment and clock monitoring before declaring compromise. Generic browser errors should not disclose the assertion or partner keys.

Regression gates include known-good SSO after rejection, multi-worker races, signed-node selection, metadata expiry/outage, old/new key overlap and emergency retirement. Do not test unsafe XML payloads on live services; hardening here uses bounded synthetic policy cases and trusted issuer fixtures.

## Labs

### Environment and Complete Files

Python 3.12; SignXML 5.2.0 with its lxml/cryptography dependencies. Exact-file execution is recorded below; fresh installation was not retested. The two files below are sufficient in a new disposable directory. This is a real XML signature check plus a real SQLite atomic request/replay transaction. It is **not a complete ACS**: no Response/binding parser, XML encryption, metadata downloader, IdP login or browser transport is supplied. Synthetic server-owned request rows represent already established browser transactions. All assertions are issued by the test issuer without modifying signed messages.

### File: requirements.txt

```text
signxml==5.2.0
```

### File: test_example.py

```python
import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, XMLVerifier, SignatureConfiguration, SignatureMethod, DigestAlgorithm
from signxml.exceptions import InvalidInput, InvalidSignature


NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
IDP, SP, ACS = "urn:lab:idp", "urn:lab:sp", "https://sp.example.test/acs"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
CONFIG = SignatureConfiguration(location="./", expect_references=1,
	signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
	digest_algorithms=frozenset({DigestAlgorithm.SHA256}))


def stamp(seconds):
	return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def seconds(text):
	value = datetime.fromisoformat(text)
	if value.tzinfo is None:
		raise ValueError("timezone")
	return value.timestamp()


def one(root, path):
	nodes = root.findall(path, namespaces={"s": NS})
	if len(nodes) != 1:
		raise ValueError("cardinality")
	return nodes[0]


class TestIssuer:
	def __init__(self):
		self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic federation")])
		now = datetime.now(timezone.utc)
		cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
			.public_key(self.key.public_key()).serial_number(x509.random_serial_number())
			.not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
			.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
			.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
				key_encipherment=False, data_encipherment=False, key_agreement=False,
				key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
				critical=True).sign(self.key, hashes.SHA256()))
		self.cert = cert.public_bytes(serialization.Encoding.PEM)

	def issue(self, now, request, recipient=ACS, name_attributes=None):
		root = etree.Element("{" + NS + "}Assertion", nsmap={"saml": NS, "ds": DS},
			ID="_" + uuid.uuid4().hex, Version="2.0", IssueInstant=stamp(now))
		def child(parent, name, text=None, **attributes):
			node = etree.SubElement(parent, "{" + NS + "}" + name, **attributes)
			node.text = text
			return node
		child(root, "Issuer", IDP)
		etree.SubElement(root, "{" + DS + "}Signature", Id="placeholder")
		subject = child(root, "Subject")
		child(subject, "NameID", "alice", Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			**(name_attributes or {}))
		child(child(subject, "SubjectConfirmation", Method=BEARER), "SubjectConfirmationData",
			Recipient=recipient, InResponseTo=request, NotOnOrAfter=stamp(now + 120))
		conditions = child(root, "Conditions", NotBefore=stamp(now - 5), NotOnOrAfter=stamp(now + 120))
		child(child(conditions, "AudienceRestriction"), "Audience", SP)
		statement = child(root, "AuthnStatement", AuthnInstant=stamp(now))
		child(child(statement, "AuthnContext"), "AuthnContextClassRef",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
		return etree.tostring(XMLSigner().sign(root, key=self.key, cert=self.cert,
			reference_uri="#" + root.get("ID"), id_attribute="ID"))


class Consumer:
	def __init__(self, trusted_cert):
		self.cert = trusted_cert
		self.db = sqlite3.connect(":memory:")
		self.db.executescript("""
			CREATE TABLE pending (id TEXT PRIMARY KEY, browser TEXT, expires INTEGER);
			CREATE TABLE seen (issuer TEXT, assertion TEXT, expires REAL, PRIMARY KEY (issuer, assertion));
			CREATE TABLE sessions (id TEXT PRIMARY KEY, subject TEXT);
		""")

	def begin(self, browser, now):
		request = "_" + uuid.uuid4().hex
		with self.db:
			self.db.execute("INSERT INTO pending VALUES (?, ?, ?)", (request, browser, now + 120))
		return request

	def consume(self, data, browser, request, now):
		if not isinstance(data, bytes) or len(data) > 65536:
			raise ValueError("size")
		parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
		root = XMLVerifier().verify(data, x509_cert=self.cert, parser=parser,
			expect_config=CONFIG, id_attribute="ID").signed_xml
		if root.tag != "{" + NS + "}Assertion" or root.get("Version") != "2.0":
			raise ValueError("assertion")
		if one(root, "s:Issuer").text != IDP or not root.get("ID"):
			raise ValueError("issuer or id")
		if not 0 <= now - seconds(root.get("IssueInstant")) <= 120:
			raise ValueError("issue time")
		subject = one(root, "s:Subject")
		name = one(subject, "s:NameID")
		if not name.text or name.get("Format") != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":
			raise ValueError("subject")
		if set(name.attrib) - {"Format"}:
			raise ValueError("unsupported NameID attributes")
		confirmation = one(subject, "s:SubjectConfirmation")
		delivery = one(confirmation, "s:SubjectConfirmationData")
		if confirmation.get("Method") != BEARER or delivery.get("Recipient") != ACS:
			raise ValueError("recipient")
		if delivery.get("InResponseTo") != request or now >= seconds(delivery.get("NotOnOrAfter")):
			raise ValueError("confirmation")
		conditions = one(root, "s:Conditions")
		restriction = one(conditions, "s:AudienceRestriction")
		if len(conditions) != 1 or len(restriction) != 1 or one(restriction, "s:Audience").text != SP:
			raise ValueError("audience")
		start, end = seconds(conditions.get("NotBefore")), seconds(conditions.get("NotOnOrAfter"))
		if not start <= now < end or not 0 < end - start <= 180:
			raise ValueError("expiry")
		statement = one(root, "s:AuthnStatement")
		if not 0 <= now - seconds(statement.get("AuthnInstant")) <= 300:
			raise ValueError("authentication age")
		context = one(one(statement, "s:AuthnContext"), "s:AuthnContextClassRef").text
		if context != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport":
			raise ValueError("context")
		with self.db:
			self.db.execute("BEGIN IMMEDIATE")
			deleted = self.db.execute("DELETE FROM pending WHERE id = ? AND browser = ? AND expires > ?",
				(request, browser, now))
			if deleted.rowcount != 1:
				raise PermissionError("transaction")
			self.db.execute("INSERT INTO seen VALUES (?, ?, ?)", (IDP, root.get("ID"), end))
			session = uuid.uuid4().hex
			self.db.execute("INSERT INTO sessions VALUES (?, ?)", (session, name.text))
		return session


class SecurityTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.issuer, cls.other = TestIssuer(), TestIssuer()

	def setUp(self):
		self.now = int(datetime.now(timezone.utc).timestamp())
		self.consumer = Consumer(self.issuer.cert)
		self.addCleanup(self.consumer.db.close)

	def test_browser_one_use_and_positive_control(self):
		request = self.consumer.begin("browser-a", self.now)
		data = self.issuer.issue(self.now, request)
		with self.assertRaises(PermissionError):
			self.consumer.consume(data, "browser-b", request, self.now)
		self.consumer.consume(data, "browser-a", request, self.now)
		with self.assertRaises(PermissionError):
			self.consumer.consume(data, "browser-a", request, self.now)
		with self.consumer.db:
			self.consumer.db.execute("INSERT INTO pending VALUES (?, ?, ?)",
				(request, "browser-a", self.now + 120))
		with self.assertRaises(sqlite3.IntegrityError):
			self.consumer.consume(data, "browser-a", request, self.now)
		fresh = self.consumer.begin("browser-a", self.now)
		self.consumer.consume(self.issuer.issue(self.now, fresh), "browser-a", fresh, self.now)
		self.assertEqual(self.consumer.db.execute("SELECT count(*) FROM sessions").fetchone()[0], 2)

	def test_nameid_profile(self):
		request = self.consumer.begin("browser-a", self.now)
		qualifiers = {"NameQualifier": IDP, "SPNameQualifier": SP, "SPProvidedID": "sp-alice"}
		cases = [{attribute: value} for attribute, value in qualifiers.items()]
		cases += [{attribute: ""} for attribute in qualifiers]
		cases.append(qualifiers)
		for attributes in cases:
			with self.subTest(attributes=attributes):
				data = self.issuer.issue(self.now, request, name_attributes=attributes)
				with self.assertRaisesRegex(ValueError, "^unsupported NameID attributes$"):
					self.consumer.consume(data, "browser-a", request, self.now)
				self.assertEqual(self.consumer.db.execute("SELECT count(*) FROM sessions").fetchone()[0], 0)
				self.assertEqual(self.consumer.db.execute("SELECT count(*) FROM seen").fetchone()[0], 0)
				self.assertEqual(self.consumer.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
		session = self.consumer.consume(self.issuer.issue(self.now, request), "browser-a", request, self.now)
		self.assertEqual(self.consumer.db.execute("SELECT id, subject FROM sessions").fetchall(),
			[(session, "alice")])

	def test_trust_recipient_and_expiry(self):
		request = self.consumer.begin("browser-a", self.now)
		self.consumer.cert = self.other.cert
		with self.assertRaises((InvalidSignature, InvalidInput)):
			self.consumer.consume(self.issuer.issue(self.now, request), "browser-a", request, self.now)
		self.consumer.cert = self.issuer.cert
		with self.assertRaises(ValueError):
			self.consumer.consume(self.issuer.issue(self.now, request, ACS + "/other"),
				"browser-a", request, self.now)
		with self.assertRaises(ValueError):
			self.consumer.consume(self.issuer.issue(self.now, request), "browser-a", request, self.now + 120)
		self.consumer.consume(self.issuer.issue(self.now, request), "browser-a", request, self.now)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_example
.venv\Scripts\python -m pip freeze
```

Identify where each decision becomes authoritative: pinned certificate, returned signed node, context fields, browser-bound pending row, unique assertion ID and session insertion. The baseline is the permitted synthetic Alice acceptance. Negative tests change configuration or normally issued fixture policy, never construct bypass XML. The controlled reinsertion of the pending row tests the replay database independently of request consumption; it is not an endpoint or a supported request-reset action.

### Hints

Check-then-insert outside a transaction does not establish one-use behavior across workers. An exception in the transaction rolls back request deletion and session creation. If the unique assertion constraint rejects, there must be no extra session. A wrong browser must not consume the legitimate browser's pending request.

This fixed IdP/SP profile accepts only persistent NameID with nonempty text and no attributes except `Format`. It rejects `NameQualifier`, `SPNameQualifier` and `SPProvidedID`, including empty values or qualifiers matching the configured entities. Storing only subject text is local to this single agreement; qualified or multi-partner identities require explicit semantic validation and scoped account mapping before session creation. Do not silently strip qualifiers.

### Solution and Fixed Retest

Expected: **three tests pass**; wrong browser, reused request, repeated assertion, wrong trusted certificate, wrong Recipient and expiry all reject. Exactly two sessions exist after the first test's permitted completions. Seven normally signed qualified-identifier cases reject without consuming the pending request, recording replay state or creating sessions; the unqualified baseline then succeeds with that request. A fresh request succeeds after the other rejection cases. The fix is exact signed-node/context checking plus transactional consumption; a signature-only or cookie-only baseline would not meet these acceptance criteria. No failing insecure implementation is shipped. Run the unchanged tests after persistence or certificate-policy edits.

### Verification, Troubleshooting, and Cleanup

Validation (2026-11-03): exact named files extracted with `Test-FastAPIExamples.ps1 -ExtractOnly`; `python -m unittest -v test_example` passed all three tests on Python 3.12.10, SignXML 5.2.0, lxml 6.1.3 and cryptography 50.0.2 in an existing venv. The test uses one connection and serial calls, not measured concurrency; multi-connection isolation remains a deployment gate. Production needs bounded replay cleanup after the latest acceptance time including skew, account policy, logout, durable browser sessions and full SAML Response/schema/binding validation. Keep clocks correct; record exception classes on dependency upgrades instead of disabling verification. Remove the disposable directory/venv/caches. All data and keys exist only in process memory. The original study checklist is preserved, not certified complete; this exercise uses safe rejection fixtures instead of assertion editing.

- [ ] Local SAML exercise: Use a local test IdP/SP pair and inspect one synthetic login assertion. Test expired conditions, wrong audience, and an untrusted signing certificate.
- [ ] Boundary check: Modify a signed assertion's harmless attribute and require rejection. Replay an already consumed response where the deployment expects single-use correlation and verify its policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[SAML]]

## References

- [OASIS SAML security and privacy considerations](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- [OASIS SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [W3C XML Signature best practices](https://www.w3.org/TR/xmldsig-bestpractices/)
- [SignXML verification and trust API](https://xml-security.github.io/signxml/)
- [SQLite transactions](https://www.sqlite.org/lang_transaction.html)
- [OWASP SAML Security](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
