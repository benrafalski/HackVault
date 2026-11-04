---
title: "AD CS Security"
aliases: []
tags: [windows, x4, security]
domain: windows
phase: "X4"
type: security
status: draft
pair: "[[AD CS]]"
updated: 2026-11-03
---
# AD CS Security

> [!abstract] TL;DR
> Treat template authors, CA administrators, enrollment endpoints and certificate-to-account mapping as separate trust authorities. Secure issuance does not eliminate the need for revocation, key protection and relying-party validation.

> [!info] Agent scope
> Security of: Certificate authorities; templates; enrollment; EKUs; mapping; enrollment services; permissions; audit and lifecycle. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- CA keys/database/configuration/backups, template and publication ACLs, enrollment/approval roles, endpoint authentication, certificate mapping, revocation distribution and privileged administration.
- Defensive review only: no enrollment-abuse taxonomy recipes, relay, identity impersonation, forged certificates/tickets, key extraction or weakened mapping controls.

## Learn

```text
Teach defensive AD CS security at expert depth. Assume AD ACLs and X.509. Map
each trust boundary: template author, enroller, CA manager, certificate manager,
endpoint, key storage, publication and relying-party identity mapping. Give
precise safe configuration for a directory-derived authentication template and
a separate TLS-server template; distinguish requester fields from issued fields.
Explain current KDC strong mapping, SID binding, NTAuth/chain/revocation checks,
CA/template replication and caching, renewal approval differences and lifecycle.
Use KB5014754's 2025 milestones, not obsolete compatibility-mode workarounds.
Show evidence-led correlation of CA 4886/4887/4888/4889, template changes and
Kdcsvc 39/40/41, with audit/SACL prerequisites, false positives and limits.
Provide a complete synthetic issuance/mapping review with baseline, repair,
allowed case, negative regression and cleanup. No certificate issuance, ESC
abuse, relay, forged artifacts, real-user data, secrets or bypass instructions.
Use primary Microsoft documentation. Teach here; do not edit notes or status.
```

## Cheatsheet

### Review the Complete Issuance Path

| Boundary | Evidence | Secure target and caveat |
|---|---|---|
| Template ownership/editing | Owner/DACL, attribute values, schema/revision, recent changes | Only PKI policy maintainers can change it; narrow Enroll cannot compensate for broad template write rights. |
| Enrollment | Read/Enroll/Autoenroll, CA Request Certificates permission, published-template list | Dedicated workload group, necessary permissions only, supported CA/client compatibility. |
| Subject identity | Directory-derived subject/SAN policy versus request-supplied values | Authentication profiles derive identity from the authenticated account; separate exceptional server-name workflows. |
| Purpose | Issued EKU/application policies and key usage | Separate server TLS from user/device authentication; avoid unrestricted purpose for narrow workloads. |
| Approval | Manager approval/authorized signatures and renewal settings | Approvers cannot silently broaden template policy; check initial and renewal paths separately. |
| CA administration | Manage CA versus Issue and Manage Certificates, service/host administration | Distinct responsibilities with audited access; host or key custody remains highly privileged even when CA console roles are split. |
| Endpoint | Installed role services, TLS binding, authentication and supported extended protection | Remove unused services; harden required endpoints according to Microsoft guidance and current patches. HTTPS alone is not every authentication protection. |
| Key custody | Key ACL, nonexportability, HSM/TPM policy, backup access | Separate key protection from certificate-publication access; a public certificate is not a secret. |

A certificate must satisfy chain trust, time, constraints/purpose, revocation and identity mapping before service authorization. Some services use local certificate mappings rather than KDC mappings. Record the actual authentication path, not just "certificate auth enabled." An untrusted-root error cannot be repaired by changing the account's UPN; a missing strong mapping cannot be repaired by broadening enrollment rights.

### Concrete Configuration Review

Synthetic authentication profile `TrainingDeviceAuth`: duplicate a compatible device template, build subject from AD, use only required authentication purpose(s), use a supported key provider/size and nonexportable private key where supported, and delegate Read+Enroll to `TrainingDevices` only. Add Autoenroll only if the workflow uses it. Restrict template editing to `PKIPolicyMaintainers`; publish on the intended enterprise CA only. Keep the SID-binding behavior required by current patched DCs. Capture the actual issued certificate's identity binding; a console checkbox is not final evidence.

Synthetic TLS profile `TrainingServerTLS`: Server Authentication EKU only, named workload enrollment group, reviewed DNS-name authorization and separate approval where supplied names are necessary. Do not reuse the broad name-supply workflow for account-authentication certificates. Restrict which server may request which name through the supported issuance process; a narrow group alone does not bind every requested name to its owner.

For both: document validity/renewal overlap, allowed algorithm/provider, revocation locations and their update SLA, recovery ownership, template revision and CA publication. A usable template is an intersection of template availability, permissions, policy and compatibility. Denial is an expected result for out-of-scope requests, not a reason to grant Authenticated Users blanket enrollment.

### Mapping and Version Discipline

On patched contemporary DCs, use strong binding under KB5014754. The SID extension OID is `1.3.6.1.4.1.311.25.2`; the account match and actual mapping path matter, not merely extension presence. February 2025 updates changed default enforcement; September 9, 2025 updates remove the documented compatibility fallback. Do not recommend disabling enforcement for a 2026 deployment. Reissue an appropriate certificate or use a reviewed supported strong mapping for the intended identity; never reuse an old certificate for a newly created same-named account.

| Symptom | Correct investigation |
|---|---|
| Kdcsvc 39 | No strong mapping found: inspect issuing path, certificate/account binding and relevant patch state. |
| Kdcsvc 40 | Certificate/account creation-time relationship is invalid for the evaluated mapping path; verify lifecycle, not just names. |
| Kdcsvc 41 | Certificate SID and account SID differ; stop approval and identify stale/wrong binding. |
| CA `0x80094012` | Template permission denied; inspect intended membership/ACL and replication rather than mapping policy. |
| Revocation offline | Publication/network/cache problem, not an authorization grant. Verify CRL validity and relying-party failure behavior. |

Template changes replicate through AD's configuration partition, then reach CA/client caches. CA security/configuration and HTTP endpoint configuration may be local to a server. Inventory all issuing CAs/DCs; a successful test through one path does not certify every path. Preserve old template revision and issued-certificate evidence during a rollout.

### Lifecycle and Remediation

Removing enrollment permission prevents future eligible issuance; it does not revoke already issued certificates. A complete retirement change includes affected serial+issuer inventory, key owner notification, revocation where appropriate, current CRL/OCSP publication, service retest and retained audit evidence. CA compromise/recovery has broader requirements than a single leaf revocation. Do not delete certificate databases or key history to "clean up" a review.

Backups must include the supported CA database/key/configuration set and publication dependencies; protect restoration credentials outside the same failure domain. Validate CRL NextUpdate/overlap under offline-root operations. A nonexportable key policy reduces ordinary export but is not a substitute for protecting the issuing host and its administrators.

## Detection and Defense

Configure the CA's audit categories and Advanced Audit Policy Object Access -> Audit Certification Services. Both must align for expected CA Security events. AD template-object changes also need Directory Service Changes auditing and suitable SACLs. KDC mapping events are on DCs, not necessarily in the CA's log.

| Event | Use and limitation |
|---|---|
| 4886 | CA received request; request receipt is not issuance. |
| 4887 | Request approved/certificate issued; correlate CA identity + request ID and certificate serial. |
| 4888 / 4889 | Request denied / set pending; denial may be healthy enforcement or operational misconfiguration. |
| 4882 | CA security permissions changed; validate actor/change authorization. |
| 5136 | Directory template/publication object changed, subject to SACL/audit settings. |
| Kdcsvc 39/40/41 | Mapping evidence; absence of these records does not prove a successful sign-in. |

Safe local log inspection on an authorized CA/DC with Event Log read permission (possibly elevation):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4886,4887,4888,4889,4882} -MaxEvents 30 |
	Select-Object TimeCreated, Id, MachineName, Message
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id=39,40,41} -MaxEvents 30 |
	Select-Object TimeCreated, Id, MachineName, Message
```

Do not export unredacted requester identities into public notes. Correlate with approval records and expected workload volumes. Bulk renewals, autoenrollment retries and changes in CRL availability are common operational explanations; they require evidence rather than blanket suppression.

## Labs

### Offline Issuance-to-Mapping Evidence Case

Dependencies: Python 3.12 standard library only. Create the single file in an empty exercise directory. Records are synthetic normalized exports, not literal Windows Event XML schemas. The parser correlates evidence and checks a binding invariant; it does not verify signatures, issue certificates, contact a CA/KDC or authenticate.

### File: test_example.py

```python
import unittest
import xml.etree.ElementTree as ET

EVIDENCE = """<Case>
  <CA name="issuing-a" request="42" event="4887" serial="A142"/>
  <CA name="issuing-b" request="42" event="4888" serial=""/>
  <Certificate issuer="issuing-a" request="42" serial="A142"
	  accountSid="S-1-5-21-111-222-333-1200" boundSid="S-1-5-21-111-222-333-1199"/>
  <KDC event="41" serial="A142"/>
</Case>"""


def review(text):
	root = ET.fromstring(text)
	certificate = root.find("Certificate")
	if certificate is None:
		raise ValueError("missing certificate evidence")
	issued = [record for record in root.findall("CA")
			  if record.attrib["name"] == certificate.attrib["issuer"]
			  and record.attrib["request"] == certificate.attrib["request"]
			  and record.attrib["serial"] == certificate.attrib["serial"]
			  and record.attrib["event"] == "4887"]
	result = set()
	if len(issued) != 1:
		result.add("issuance-not-corroborated")
	if certificate.attrib["accountSid"] != certificate.attrib["boundSid"]:
		result.add("binding-mismatch")
	for record in root.findall("KDC"):
		if record.attrib["serial"] == certificate.attrib["serial"]:
			result.add("mapping-event-" + record.attrib["event"])
	return result


def corrected_evidence():
	root = ET.fromstring(EVIDENCE)
	certificate = root.find("Certificate")
	certificate.set("boundSid", certificate.attrib["accountSid"])
	root.remove(root.find("KDC"))
	return ET.tostring(root, encoding="unicode")


class CertificateEvidenceTests(unittest.TestCase):
	def test_baseline(self):
		self.assertEqual(review(EVIDENCE), {"binding-mismatch", "mapping-event-41"})

	def test_corrected_binding_is_not_a_signin_claim(self):
		self.assertEqual(review(corrected_evidence()), set())

	def test_request_number_is_not_global(self):
		root = ET.fromstring(corrected_evidence())
		root.find("Certificate").set("issuer", "issuing-b")
		self.assertEqual(review(ET.tostring(root, encoding="unicode")),
						 {"issuance-not-corroborated"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Identify why issued request 42 is insufficient evidence of a usable authentication certificate. Do not change account SIDs or modify any certificate.
2. Run `py -3.12 -m unittest -v test_example.py`. Three tests should pass: baseline detected, corrected synthetic evidence accepted, cross-CA miscorrelation rejected.
3. Write a remediation plan: verify intended account identity and authoritative enrollment source, correct issuance configuration, reissue through the approved lifecycle, retire the old credential as required, then collect fresh mapping and sign-in evidence.
4. State the positive result still missing even after the second test: a real authorized sign-in and resource access with proper validation. Also require denial for an unrelated synthetic identity in a separately authorized live test.

### Hints and Solution

Request IDs are CA-local. CA 4887 proves issuance, not successful KDC mapping. Baseline certificate metadata binds SID ending 1199 while intended account ends 1200, matching event 41 evidence. The fixed fixture represents a separate corrected evidence collection, not editing a certificate or erasing an event from operational records. Keep originals in any real investigation.

### Verification, Troubleshooting, and Cleanup

Author execution not performed. Parser errors or missing certificate records mean incomplete evidence, not a clean case. No-event fixed evidence alone cannot prove successful authentication or full audit coverage; the test name makes that limitation explicit. Remove only the local exercise directory/cache. There are no keys, issued certificates, trust anchors or services to revoke/remove. The optional live checklist below remains uncompleted.

- [ ] Local AD CS exercise: Use a disposable AD CS lab to issue a harmless test certificate from a restricted template. Inspect EKUs, subject rules, enrollment ACLs, mapping policy, and revocation behavior.
- [ ] Boundary check: Verify a low-privilege test user cannot supply another identity or enroll through an unapproved template, and that strong mapping policy rejects mismatched identities.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[AD CS]]

## References

- [AD CS documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
- [KB5014754: certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [KB5005413: protections for AD CS enrollment endpoints](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
