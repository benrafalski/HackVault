---
title: "SAML"
aliases: []
tags: [web, w4]
domain: web
phase: "W4"
type: tech
status: draft
pair: "[[SAML Security]]"
updated: 2026-11-03
---
# SAML

> [!abstract] TL;DR
> Use a maintained SAML library; validate signatures and protocol context together. Do not hand-roll XML signature verification or trust arbitrary embedded certificates.

> [!info] Agent scope
> Assertions; bindings; metadata; signatures; audience and recipient validation; identity-provider and service-provider trust.

## Prerequisites

- XML namespaces, HTTPS, browser redirects/forms, public-key signatures, UTC and [[Web Lab Setup]].
- Python 3.12. All subjects, entity IDs and certificates below are disposable fixtures.

## Learn

```text
Teach SAML 2.0 federation at expert implementation depth. Assume HTTP, XML namespaces,
TLS and digital signatures. Trace SP-initiated Web Browser SSO through AuthnRequest,
Redirect binding, IdP authentication, POST Response, signed Assertion validation and
local session creation. Explain entity IDs, metadata trust/rollover, ACS selection,
RelayState, InResponseTo, Destination, Recipient, AudienceRestriction, SubjectConfirmation,
NameID formats/qualifiers, AuthnStatement, AuthnContext and exclusive time boundaries.
Explain XML canonicalization, reference resolution and why applications must consume
exactly the signed node. Contrast response/assertion signing, encryption and TLS;
cover Artifact binding and unsolicited responses without pretending they are identical.
Provide complete library-backed synthetic fixtures, secure verification code, negative
policy tests and positive controls. Label assertion-only tests versus full SSO. Cover
replay, browser correlation, session/logout lifetimes, metadata expiry and recovery.
Use OASIS/W3C/library sources, no forged assertions or bypass walkthroughs. Do not
invent execution results. End with worked design questions. Teach here, not file edits.
```

## Cheatsheet

### Protocol and Binding Order

SAML separates **assertions** (issuer statements about a subject), **protocols** (request/response exchanges), **bindings** (wire transport) and **profiles** (rules combining them). An IdP authenticates; an SP accepts assertions under a preconfigured federation agreement, then applies local authorization. Entity IDs are exact identifiers, not necessarily fetchable URLs.

1. SP creates an unpredictable request ID and stores the selected IdP, browser session, expected ACS, deadline and return route. AuthnRequest carries `ID`, `Version="2.0"`, `IssueInstant`, IdP `Destination`, SP `Issuer`, and registered ACS URL or index. Sign requests when the agreement requires it.
2. HTTP-Redirect binding encodes the request as raw DEFLATE, base64, then URL encoding. A Redirect signature covers the prescribed encoded query-string values (`SAMLRequest`, optional `RelayState`, `SigAlg`), not an arbitrarily decoded/reordered XML document. Let the binding library construct and verify it.
3. IdP validates the SP registration and ACS, authenticates the synthetic user and returns a Response. HTTP-POST binding sends base64 XML in the `SAMLResponse` form field; unlike Redirect it does not apply DEFLATE. RelayState is separately carried opaque state, not automatically protected by an assertion signature.
4. SP receives at its registered ACS, enforces body/parameter limits and correlation, validates the configured response/signature profile, then the assertion and subject-confirmation conditions. It atomically consumes request/replay state and creates a fresh local session.

```http
POST /saml/acs HTTP/1.1
Host: sp.example.test
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<url-encoded-base64-XML>&RelayState=<opaque-browser-transaction>
```

This wire fragment is not a running endpoint. Browser POSTs can omit a Lax correlation cookie on cross-site navigation; use the SAML toolkit's documented correlation design. Do not weaken the whole session policy to repair one callback. A replay cache without browser binding does not establish that the current browser initiated this login.

### Fields and Acceptance Rules

| Object/field | What the SP must establish |
|---|---|
| Response `Status` | Success at the expected protocol layer; an error must not create a session |
| Response `Destination`, `InResponseTo` | Exact ACS and outstanding request under the configured profile; assertions alone cannot authenticate unsigned envelope fields |
| Assertion `ID`, `Version`, `IssueInstant` | Valid structure/version, bounded age, nonreplayed ID in issuer namespace |
| `Issuer` | Exact trusted IdP entity ID, bound to accepted metadata keys |
| `Subject/NameID` | Stable identity according to agreed Format and qualifiers, not display name/email alone |
| `SubjectConfirmation` | Method supported by this profile, normally bearer for browser SSO |
| `SubjectConfirmationData` | Exact `Recipient`, matching `InResponseTo`, exclusive `NotOnOrAfter`; validate Address only under an explicitly supported policy |
| `Conditions` | Enforce `NotBefore <= now < NotOnOrAfter` with bounded skew and maximum accepted lifetime |
| `AudienceRestriction` | SP entity ID is an intended audience; restrictions combine with AND, audiences within one restriction with OR |
| `AuthnStatement` | Authentication instant/context meet required assurance and freshness; `SessionIndex` is not a bearer login credential |
| `AttributeStatement` | Only mapped, typed, permitted attributes; multi-valued values need an explicit policy, not first-value wins |

Transient NameIDs are not durable account keys. Persistent identifiers remain scoped to issuer/SP and qualifiers. Map to an immutable local account; subject equality from an unrelated IdP is not account equality. AuthnContextClassRef expresses agreed semantics, not an arbitrary universal MFA flag. `ForceAuthn` requests fresh authentication; verify returned evidence. Local session expiry, assertion acceptance expiry and IdP session expiry are distinct.

### XML Signature and Metadata Trust

An enveloped XML signature references the signed element ID, transforms/canonicalizes it, hashes that result, then signs canonicalized SignedInfo. Whitespace/namespace context and supported canonicalization rules matter; never pretty-print a signed message and expect identical verification. A valid signature somewhere in the document is insufficient. Constrain signature location/reference count and algorithms, then consume the verifier's returned signed element, not a second broad XPath search of the original document.

| Metadata/configuration | Decision |
|---|---|
| `EntityDescriptor entityID` | Exact partner identity; select configuration before trusting incoming claims |
| `IDPSSODescriptor/KeyDescriptor use="signing"` | Trusted signing certificates; an omitted `use` can denote both uses under metadata rules |
| `SingleSignOnService Binding/Location` | Supported binding and configured destination; do not discover from request input |
| `SPSSODescriptor/AssertionConsumerService` | Binding, Location and index must match registration |
| `validUntil`, `cacheDuration` | Bound metadata freshness; define outage behavior and emergency revocation |
| `WantAssertionsSigned`, `AuthnRequestsSigned` | Interoperability declarations; enforce actual agreed local acceptance policy |

Obtain metadata through authenticated administration or a validated metadata signature anchored in an independently trusted key. HTTPS alone does not turn an arbitrary URL into an approved IdP. Do not select the first certificate from a multi-entity document. Verify exact entity, role, key use and validity policy. Embedded KeyInfo is a hint, not a new trust anchor. Federation signing certificates are often pinned self-signed certificates; TLS hostname validation is a separate trust system.

Publish new signing keys before use, accept only the planned current/next set during rollover, retain old verification keys for the bounded assertion acceptance window, then retire. A compromised key requires immediate removal and cache invalidation. Encryption protects assertion confidentiality to the SP but does not replace issuer signature validation. Artifact binding sends a short reference through the browser and resolves it using the configured authenticated back channel; artifact one-use and resolution trust remain necessary.

### Operational Decisions

Prefer solicited SP-initiated SSO. Unsolicited IdP-initiated responses lack the same request correlation and need a deliberate separately reviewed policy, not a fallback when a request ID is absent. Replay storage must be shared, atomic and retained through the latest accepted deadline including skew. Fail closed if it is unavailable. Single Logout is a separate signed/correlated protocol using session context; local logout alone does not end IdP or other SP sessions.

## Gotchas

- Audience is usually the SP entity ID; Recipient and Destination are endpoint URLs. They are not interchangeable.
- Assertion signatures do not necessarily cover the enclosing Response or RelayState. Enforce the agreed signature profile rather than assuming inherited coverage.
- XMLDSig schema validation is not full SAML schema/profile validation. Use maintained SAML middleware for deployed ACS endpoints.

## Labs

### Environment and Complete Files

Python 3.12; SignXML 5.2.0 with its lxml/cryptography dependencies. Exact-file execution is recorded below; fresh installation was not retested. Use a new disposable directory with the two files below; no other page, server, certificate file or real identity is required. This is a real signed SAML Assertion round trip with a deliberately narrow validation profile, **not an IdP/SP SSO implementation**. It does not process a Response, metadata network fetch, browser session, XML encryption or logout. The test issuer owns its private key and issues all fixtures normally; no message manipulation is required.

### File: requirements.txt

```text
signxml==5.2.0
```

### File: test_example.py

```python
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, XMLVerifier, SignatureConfiguration
from signxml import SignatureMethod, DigestAlgorithm


SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
IDP = "https://idp.example.test/entity"
SP = "https://sp.example.test/entity"
ACS = "https://sp.example.test/saml/acs"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
POLICY = SignatureConfiguration(location="./", expect_references=1,
	signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
	digest_algorithms=frozenset({DigestAlgorithm.SHA256}))


def stamp(value):
	return value.isoformat().replace("+00:00", "Z")


def instant(value):
	result = datetime.fromisoformat(value)
	if result.tzinfo is None:
		raise ValueError("timezone required")
	return result


def one(parent, path):
	found = parent.findall(path, namespaces={"s": SAML})
	if len(found) != 1:
		raise ValueError("profile cardinality")
	return found[0]


class Issuer:
	def __init__(self):
		self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic IdP")])
		now = datetime.now(timezone.utc)
		certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
			.public_key(self.key.public_key()).serial_number(x509.random_serial_number())
			.not_valid_before(now - timedelta(minutes=1))
			.not_valid_after(now + timedelta(days=1))
			.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
			.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
				key_encipherment=False, data_encipherment=False, key_agreement=False,
				key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
				critical=True).sign(self.key, hashes.SHA256()))
		self.cert = certificate.public_bytes(serialization.Encoding.PEM)

	def issue(self, now, request="_request", audience=SP, recipient=ACS, name_attributes=None):
		root = etree.Element("{" + SAML + "}Assertion", nsmap={"saml": SAML, "ds": DS},
			ID="_" + uuid.uuid4().hex, Version="2.0", IssueInstant=stamp(now))
		def child(parent, name, text=None, **attributes):
			element = etree.SubElement(parent, "{" + SAML + "}" + name, **attributes)
			element.text = text
			return element
		child(root, "Issuer", IDP)
		etree.SubElement(root, "{" + DS + "}Signature", Id="placeholder")
		subject = child(root, "Subject")
		child(subject, "NameID", "subject-alice", Format=PERSISTENT, **(name_attributes or {}))
		confirmation = child(subject, "SubjectConfirmation", Method=BEARER)
		child(confirmation, "SubjectConfirmationData", Recipient=recipient,
			InResponseTo=request, NotOnOrAfter=stamp(now + timedelta(seconds=120)))
		conditions = child(root, "Conditions", NotBefore=stamp(now - timedelta(seconds=5)),
			NotOnOrAfter=stamp(now + timedelta(seconds=120)))
		child(child(conditions, "AudienceRestriction"), "Audience", audience)
		statement = child(root, "AuthnStatement", AuthnInstant=stamp(now), SessionIndex="_session")
		child(child(statement, "AuthnContext"), "AuthnContextClassRef",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
		signed = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256").sign(
			root, key=self.key, cert=self.cert, reference_uri="#" + root.get("ID"), id_attribute="ID")
		return etree.tostring(signed)


def accept(data, trusted_cert, now, request, seen):
	if not isinstance(data, bytes) or len(data) > 65536:
		raise ValueError("size")
	parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
	root = XMLVerifier().verify(data, x509_cert=trusted_cert, id_attribute="ID",
		parser=parser, expect_config=POLICY).signed_xml
	if root.tag != "{" + SAML + "}Assertion" or root.get("Version") != "2.0":
		raise ValueError("assertion profile")
	if one(root, "s:Issuer").text != IDP:
		raise ValueError("issuer")
	identifier = root.get("ID")
	if not identifier or (IDP, identifier) in seen:
		raise ValueError("replay")
	if not 0 <= (now - instant(root.get("IssueInstant"))).total_seconds() <= 120:
		raise ValueError("issue time")
	subject = one(root, "s:Subject")
	name = one(subject, "s:NameID")
	if name.get("Format") != PERSISTENT or not name.text:
		raise ValueError("identity")
	if set(name.attrib) - {"Format"}:
		raise ValueError("unsupported NameID attributes")
	confirmation = one(subject, "s:SubjectConfirmation")
	delivery = one(confirmation, "s:SubjectConfirmationData")
	if confirmation.get("Method") != BEARER or delivery.get("Recipient") != ACS:
		raise ValueError("recipient")
	if delivery.get("InResponseTo") != request or now >= instant(delivery.get("NotOnOrAfter")):
		raise ValueError("request or confirmation expiry")
	conditions = one(root, "s:Conditions")
	if len(conditions) != 1:
		raise ValueError("unsupported conditions")
	restriction = one(conditions, "s:AudienceRestriction")
	if len(restriction) != 1 or one(restriction, "s:Audience").text != SP:
		raise ValueError("audience")
	start, end = instant(conditions.get("NotBefore")), instant(conditions.get("NotOnOrAfter"))
	if not start <= now < end or not 0 < (end - start).total_seconds() <= 180:
		raise ValueError("conditions time")
	statement = one(root, "s:AuthnStatement")
	if not 0 <= (now - instant(statement.get("AuthnInstant"))).total_seconds() <= 300:
		raise ValueError("authentication age")
	context = one(one(statement, "s:AuthnContext"), "s:AuthnContextClassRef").text
	if context != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport":
		raise ValueError("authentication context")
	seen.add((IDP, identifier))
	return IDP, name.text


class AssertionTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.issuer = Issuer()

	def test_round_trip_and_replay(self):
		now = datetime.now(timezone.utc)
		data, seen = self.issuer.issue(now), set()
		self.assertEqual(accept(data, self.issuer.cert, now, "_request", seen),
			(IDP, "subject-alice"))
		with self.assertRaises(ValueError):
			accept(data, self.issuer.cert, now, "_request", seen)

	def test_nameid_profile(self):
		now, seen = datetime.now(timezone.utc), set()
		qualifiers = {"NameQualifier": IDP, "SPNameQualifier": SP, "SPProvidedID": "sp-alice"}
		cases = [{attribute: value} for attribute, value in qualifiers.items()]
		cases += [{attribute: ""} for attribute in qualifiers]
		cases.append(qualifiers)
		for attributes in cases:
			with self.subTest(attributes=attributes):
				data = self.issuer.issue(now, name_attributes=attributes)
				with self.assertRaisesRegex(ValueError, "^unsupported NameID attributes$"):
					accept(data, self.issuer.cert, now, "_request", seen)
				self.assertEqual(seen, set())
		self.assertEqual(accept(self.issuer.issue(now), self.issuer.cert, now, "_request", seen),
			(IDP, "subject-alice"))
		self.assertEqual(len(seen), 1)

	def test_context_and_expiry(self):
		now = datetime.now(timezone.utc)
		for changes in ({"audience": "urn:other:sp"}, {"recipient": ACS + "/other"},
						{"request": "_other"}):
			with self.subTest(changes=changes), self.assertRaises(ValueError):
				accept(self.issuer.issue(now, **changes), self.issuer.cert, now, "_request", set())
		with self.assertRaises(ValueError):
			accept(self.issuer.issue(now), self.issuer.cert, now + timedelta(seconds=120),
				"_request", set())


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest -v test_example
.venv\Scripts\python -m pip freeze
```

Trace the real signature reference to the Assertion ID, the trusted certificate supplied out of band, and the node returned by verification. Distinguish the three different identifiers: IdP entity, SP audience and ACS recipient. Explain why the tests can reject correctly signed fixtures without changing a signature. No sockets or enrollment are used; all seed data and keys are generated by the file.

### Hints

The single restriction/single audience rule is a strict local profile, not all of SAML. The function receives an expected outstanding request ID; it does not implement its browser session. `seen` proves serial replay behavior only. `NotOnOrAfter` excludes equality; no clock skew is allowed in this lab.

NameID supports only persistent Format and nonempty text, with no other attributes. `NameQualifier`, `SPNameQualifier` and `SPProvidedID` are rejected even when empty or matching the configured entities; their semantics are not implemented. The `(IDP, text)` result is local to this fixed IdP/SP agreement, not a general federation account key. Supporting qualified identifiers requires explicit validation and account mapping that preserves their semantics, not stripping attributes or reusing this tuple across SPs.

### Solution and Expected Results

The code is the reference solution. Expected: **three tests pass**, the first returns `(IDP, "subject-alice")`, repeat acceptance rejects, and wrong audience, recipient, request and exact expiry reject. Seven normally signed qualified-identifier cases reject without consuming replay state; an unqualified baseline still succeeds. Signature checking occurs before identity extraction. The fix for signature-only acceptance is complete context checking, not additional base64 decoding or accepting any certificate embedded in XML.

### Verification, Troubleshooting, and Cleanup

Validation (2026-11-03): exact named files extracted with `Test-FastAPIExamples.ps1 -ExtractOnly`; `python -m unittest -v test_example` passed all three tests on Python 3.12.10, SignXML 5.2.0, lxml 6.1.3 and cryptography 50.0.2 in an existing venv. Do not disable schema/signature checking to repair an API mismatch; record installed versions. Certificate validity uses the current wall clock even though assertion time is injected, so run with a correct system clock. Do not reformat signed XML. Delete the disposable directory, venv and caches; keys are memory-only. Production still requires full SAML schemas/profile, Response validation, trusted metadata, browser correlation, atomic shared request/replay storage, account policy and TLS integration. The retained checklist describes broader study goals, not completed validation or instructions to manipulate tokens.

- [ ] Local SAML exercise: Use a local test IdP/SP pair and inspect one synthetic login assertion. Test expired conditions, wrong audience, and an untrusted signing certificate.
- [ ] Boundary check: Modify a signed assertion's harmless attribute and require rejection. Replay an already consumed response where the deployment expects single-use correlation and verify its policy.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W4 Identity|W4 Identity]]
- [[SAML Security]]

## References

- [OASIS SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OASIS SAML bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [OASIS SAML profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [OASIS SAML metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [SignXML API and signed-node guidance](https://xml-security.github.io/signxml/)
- [OWASP SAML Security](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
