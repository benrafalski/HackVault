---
title: "AD Attacks"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# AD Attacks

> [!abstract] TL;DR
> AD risk spans identity, directory authorization, delegation, and certificate issuance/mapping. Evaluate each boundary and its effective version/policy; a ticket event, replication right, or ESC label is not a demonstrated compromise.

> [!info] Agent scope
> Kerberoasting, AS-REP roasting, delegation, DCSync, NTLM relay, and AD CS ESC1 through ESC15 as defensive mechanisms and version-qualified risk/control analysis. The lab is offline synthetic policy review, not a disposable-domain attack exercise. No credential retrieval/guessing, coercion, relay, enrollment abuse, directory modification, or escalation procedures.

## Learn

```text
Teach AD attack classes at expert depth strictly as defensive trust-boundary
analysis. Assume Kerberos, NTLM, LDAP, directory ACLs, PKI, and Windows tokens.
Explain Kerberoasting/AS-REP risk without ticket acquisition or cracking steps;
contrast service/user key strength, preauthentication, AES/RC4, and gMSAs. Compare
unconstrained, constrained, and resource-based delegation; distinguish service
identity, delegated identity, allowed resources, protocol transition, and protected
accounts. Explain replication authorization and why non-DC activity needs context.
Analyze NTLM relay as failure to bind authentication to its intended channel/service,
with protocol-specific signing, EPA/channel binding, and RPC privacy controls.
Give an ESC1-ESC15 risk/control matrix, not abuse procedures. For each, state the
relevant issuance/ACL/mapping condition, additional prerequisites, exact version
dependencies where known, evidence to request, control, and a counterexample.
Explain KB5014754's 2022 introduction, 2023 change, February 2025 default enforcement,
and September 2025 removal of fallback. Separate KDC, Schannel and application
mapping. Do not claim strong binding fixes unsafe issuance, enrollment-agent
authority, writable mappings, or policy-linked group authorization. Qualify ESC12
by HSM/KSP deployment and ESC15 by CA patch/product, not just template version.
Provide a complete offline Python 3.12 stdlib policy-review challenge with synthetic
records, unknown values, legitimate enrollment retained, separate hints/solution,
tests, and honest model limits. No live AD/DC/CA access, requests, credential theft,
relay/coercion, certificate forging, account changes, or attack chains, even toy ones.
Use public vendor/discoverer primary references, resolve conflicting guidance in
favor of current vendor semantics, and distinguish risk from demonstrated impact.
No confidential data, page-table material, or WinDbg commands. Teach without vault
access, note edits, or changing study status; include questions and reasoned answers.
```

## Cheatsheet

### Kerberos, Delegation, Replication, and Relay

| Class | Mechanism and prerequisites | Defensive evidence and controls |
|---|---|---|
| Kerberoasting risk | Service-ticket material includes data protected with the service account's long-term key. Offline guessing feasibility depends on obtaining suitable material, key derivation/algorithm, secret entropy and lifetime | Review 4769 patterns, requesting identities, services and encryption types; long managed secrets/gMSAs and least-privilege service identities reduce consequence. AES is not a cure for weak secrets |
| AS-REP roasting risk | An account with preauthentication not required can expose an offline password-guessing opportunity; this is not the normal preauthenticated case | Inventory exceptions and owners; require preauthentication, use strong secrets, monitor appropriate 4768 activity. A no-preauth event alone is not proof of recovered credentials |
| Unconstrained delegation | A trusted service may receive reusable delegated authentication authority under permitted logons | Minimize such services and privileged logons to them; review delegation flags, service hosts, and account restrictions. Not every authentication carries a delegated TGT |
| Classic constrained delegation | Delegating account policy limits target services; protocol-transition capability changes the identity-assertion trust boundary | Review allowed services, service-account control, user restrictions, and configuration changes; a service list alone does not establish a usable delegated session |
| Resource-based constrained delegation | The resource's policy defines trusted delegating principals; introduced with Windows Server 2012-era capabilities | Protect resource-object ACLs and delegation attributes, review effective principals and KDC behavior. Do not assume classic delegation checks/configuration translate unchanged |
| DCSync risk | Directory replication protocols can return sensitive replicated attributes to principals with the requisite effective extended rights on the naming context | Review Replicating Directory Changes and Changes All, plus filtered-set rights where relevant; non-DC identity/source combinations and 4662 with suitable auditing warrant review. Legitimate synchronization products are counterexamples |
| NTLM relay risk | Authentication is accepted in a different context because required channel/service/message binding is absent; needs compatible authentication and an accepting endpoint with useful authorization | Require protocol-appropriate integrity/binding; reduce NTLM after inventory. Signing, LDAP channel binding, HTTP EPA, and RPC packet privacy are not interchangeable settings |

Kerberos service-ticket volume can reflect inventory software or normal service fan-out. RC4 use can identify legacy risk but is neither necessary nor sufficient for a compromise verdict. Event schemas and encryption-related fields have changed in newer updates; bind parsers to event version and DC patch level. gMSAs reduce human-password weakness but still require restricted retrieval permissions, secure hosts, and lifecycle ownership.

Delegation is a grant of authority to a service, not a synonym for remote access. The service's identity, the represented user's restrictions, the permitted resource, and the receiving service's authorization all matter. Protected Users and "sensitive and cannot be delegated" controls have compatibility and account-type limitations; test intended authentication through the owning teams rather than assuming a single flag protects every path.

DCSync is a protocol/authorization risk, not a filesystem requirement to access the AD database directly. A narrow, deliberate replication grant can be dangerous even without broad administrative group membership. Conversely, observing replication traffic from a documented synchronization service is not sufficient to label it theft. Compare effective rights, naming context, source role, scheduled activity, and audited access scope.

### Certificate Trust Has Several Independent Decisions

Certificate issuance asks **who may request which claims under which approval**. Chain validation asks **which issuers/policies and validity/revocation state are trusted**. Mapping asks **which account the certificate identifies**. Authorization asks **what that account or certificate-derived group/claim may do**. Strong mapping does not retroactively constrain an overpowered issuer or repair template/OID/CA ACLs.

Record CA and DC product/build/cumulative update independently, template schema and publication, effective CA/template enrollment permissions, issuance gates, EKU/application policies, certificate identity fields, SID-extension behavior, accepting protocol, and explicit mapping rules. "Fully patched" without evidence/date is not a usable field. An unissued template can be an ACL exposure without being a presently available enrollment path.

### Strong Binding Timeline and Mapping Semantics

| Version/policy boundary | Interpretation for a 2026 review |
|---|---|
| May 10, 2022 updates | Introduced strong-binding changes and SID security extension for applicable enterprise CA online templates; old certificate populations still require review |
| April 11, 2023 updates | Disabled-mode setting no longer provides the earlier opt-out; do not copy old registry-based demonstrations as current behavior |
| February 11, 2025 updates | Full Enforcement becomes the default unless the then-supported compatibility override was configured |
| September 9, 2025 updates and later | Compatibility fallback is no longer supported for updated DCs; a stale registry value does not establish active weak KDC behavior |
| Schannel server mapping | Separate effective method selection at the accepting service; documented defaults enable S4U-based methods, not legacy direct UPN/issuer mapping |
| Application-local mapping | IIS/application mapping can have its own semantics; do not infer them solely from the KDC setting |

Microsoft classifies issuer+serial, subject-key-identifier, and public-key-hash explicit mappings as **strong**; issuer+subject, subject-only, and RFC822-name mappings are **weak**. This is a mapping-specific classification, not a statement that SHA-1 is preferred for new certificate signatures. A valid strong explicit mapping may support a certificate without the SID extension; absence of that extension alone is not automatic rejection in every configuration. Writable mapping attributes remain an authority problem even when the allowed mapping format is strong.

### ESC1-ESC15 Risk and Control Matrix

These are review categories, not an attack checklist or complete contemporary taxonomy. Every row still requires trustworthy issuance, applicable relying-party behavior, and relevant rights; no row asserts blanket exploitability. Labels and scanner coverage vary by version.

| Class | Risk and specific prerequisites | Version/limitation and control |
|---|---|---|
| ESC1 | Authentication-capable published template permits requester-controlled subject/SAN and accessible enrollment without effective approval/signature gates | Evaluate actual issued identity binding and accepting service; strong mapping alone is not proof of safe issuance. Derive identities from trusted directory data or tightly approve exceptional subjects; restrict enrollment and purposes |
| ESC2 | Broadly enrollable template with Any Purpose or no EKU creates excessive certificate purpose authority | Does not by itself identify another account; downstream purposes, key usage/basic constraints and enrollment-agent acceptance still govern. Specify narrow EKUs, protect enrollment, review agent-capable consumers |
| ESC3 | Accessible enrollment-agent authority and a compatible target enrollment policy permit excessive representation of other identities | Agent restrictions, target enrollment rights, template schema and issuance signatures matter; V1 and V2+ policies differ. Limit agents, represented populations and target templates; audit approvals |
| ESC4 | Unapproved effective control/write rights over security-relevant template attributes or ACL/ownership | Unpublished template control is not immediate issuance; CA publication/refresh and replication matter. Protect template owners/ACLs and monitor critical attribute changes |
| ESC5 | Excessive control of PKI trust/configuration containers, CA infrastructure, or associated objects beyond individual templates | Object-specific consequence may be trust change, unauthorized issuance or denial of service; not every PKI write has the same impact. Treat forest PKI and CA hosts as high-trust assets; monitor NTAuth/AIA/CDP/OID governance |
| ESC6 | CA-wide request-attribute SAN acceptance overrides intended template identity restrictions | Since 2022 SID-binding changes, a supplied name alone is not a universal different-account mapping. Evaluate identity provenance and extension/mapping behavior together without assuming either safety or compromise. Remove unnecessary CA-wide override; scope approved identity issuance |
| ESC7 | Excessive Manage CA or Manage Certificates authority over CA configuration/issuance | These are different roles; host administration, remote service control and individual operations have separate checks. Do not equate Manage CA with unrestricted host control. Separate roles, restrict delegations, review policy/approval audit |
| ESC8 | NTLM-accepting HTTP enrollment service lacks required effective EPA/binding, with compatible authentication and enrollment authorization | HTTPS alone is insufficient. New versus upgraded deployments and reverse-proxy/TLS termination behavior can differ. Require HTTPS plus effective EPA where applicable, remove unused endpoints, reduce NTLM; inspect actual endpoint policy |
| ESC9 | Template suppresses SID security extension, weakening intended binding provenance | Old name-based mapping assumptions do not hold automatically on post-September-2025 DCs. Other accepted bindings and issuer-controlled identity fields still require independent review. Retain appropriate SID binding, constrain subjects, use validated strong mappings for justified exceptions |
| ESC10 | Weak certificate-to-account mapping on the actual accepting path, with relevant controllable identity attributes and usable certificates | Historical KDC-disabled scenarios differ from current Schannel legacy mapping. Current KDC enforcement does not prove every TLS service uses strong mapping. Review effective Schannel/application methods and protect identity attributes; avoid legacy fallbacks |
| ESC11 | AD CS RPC enrollment fails to require packet privacy, with compatible NTLM/authentication and enrollment conditions | Inspect effective `IF_ENFORCEENCRYPTICERTREQUEST` policy; Server 2012+ defaults are not evidence an upgraded/modified CA retained it. Require RPC packet privacy and restrict legacy enrollment exposure |
| ESC12 | Published YubiHSM2 KSP integration allowed insufficiently restricted local callers/authentication material to use CA signing capability | Specific 2023 research configuration, not all HSMs/firmware and not proof of key extraction. Verify exact KSP/firmware, host credential ACLs, caller isolation, connector access and vendor guidance; no universal fixed-version claim is made here |
| ESC13 | Enrollable authentication certificate carries an issuance-policy OID linked to an authorization group via `msDS-OIDToGroupLink` | Authentication Mechanism Assurance requires applicable domain/KDC support; linked group constraints include an empty universal security group, whose nesting/rights still matter. This can change group authority without changing mapped identity. Restrict enrollment, OID links, nested rights and policy ownership |
| ESC14 | Unapproved write access to explicit mappings, or satisfiable weak existing mappings accepted by the relying party | Strong enforcement rejects weak KDC mappings, but does not repair writable `altSecurityIdentities`; strong mapping syntax alone is not safe ownership. Protect mapping ACLs, use Microsoft-classified strong mappings, retire name-only dependencies |
| ESC15 | CVE-2024-49019: affected unpatched CA accepts unintended application policies for suitable V1 templates; published research includes requester-supplied-subject and enrollment prerequisites | November 2024 CA security fix is central; V1 alone is not a vulnerability verdict, nor is a DC-only patch sufficient. Match the exact CA product/update against MSRC, patch, restrict/migrate affected templates, inspect issued policy consistency |

Do not treat a matrix finding as a reproducible procedure. In particular, a missing SID extension, broad EKU, privileged CA role, or HSM product name is not enough to conclude that an unauthorized identity can authenticate. Conversely, a current DC patch does not close unsafe administrative ACLs, excessive enrollment-agent authority, or unintended certificate-derived authorization.

### Detection and Failure Analysis

| Evidence | Defensive use and uncertainty |
|---|---|
| 4768 / 4769 | Authentication/service-ticket patterns with account, source, service and algorithm; schema/build and legitimate service fan-out matter |
| 4662 | Directory-service access including relevant extended rights when auditing/SACLs cover it; correlate principal/source and replication role |
| 5136 | Directory attribute changes, including delegation, template, OID and mapping policy where audited; retain object GUID and old/new context |
| 4886 / 4887 / 4888 | CA request receipt, issuance, denial with CA auditing enabled; request IDs are CA-scoped, issuance is not later authentication |
| Kdcsvc 39 / 40 / 41 | Mapping/age/SID mismatch diagnostics described in KB5014754; exact event semantics depend on update/mode |
| IIS, RPC and identity telemetry | Enrollment endpoint/identity/source context; absence can reflect collection gaps, not successful prevention |

Correlate requester versus certificate subject, template/policy snapshot, CA/request ID, serial/thumbprint metadata, mapped account, and authorization outcome without collecting private keys. Failure can occur at chain trust, revocation availability, EKU, enrollment authorization, mapping, time, or downstream authorization. Keep these separate: a mapping failure is not proof that issuance policy was safe.

## Defense

Use managed high-entropy service secrets, require preauthentication, reduce delegation and replication grants, separate privileged administration, and harden accepting protocols. Patch **both** CA and DC roles, constrain certificate purposes and identities, protect templates/OIDs/mappings/CA roles, and retain issuance/audit provenance. Plan certificate renewal, smart-card, device and legacy-client compatibility before changes; do not restore obsolete weak mapping to hide a failure.

Remediation may require revocation/reissuance and review of already issued certificates as well as policy repair. Directory or template edits do not automatically invalidate existing certificates/tickets or remove all authorized group effects. PKI compromise requires an incident plan appropriate to the trust anchor and key-use boundary; password rotation alone is not a complete response.

## Labs

### Environment and Complete Files

Defensive policy-review challenge only. Python **3.12**, standard library `unittest`, offline empty directory, ordinary account. No domain, CA, certificates, keys, tickets, network, or third-party tool is required. All configuration facts are synthetic. The program reports control gaps, **not ESC exploitability** or actual certificate acceptance.

### File: test_example.py

```python
import unittest


BASE = {
	"ca_release": "synthetic-server", "dc_epoch": "post-2025-enforcement",
	"published": True, "enrollment_enabled": True, "broad_enrollment": True,
	"auth_purpose": True, "requester_identity": True, "approval_gate": False,
	"sid_extension": True, "ca_fix_49019": True, "template_v1": False,
	"web_ntlm": False, "epa_required": True, "schannel_legacy": False,
}
BOOL_FIELDS = tuple(field for field in BASE if type(BASE[field]) is bool)


def review(record):
	for field in BOOL_FIELDS:
		value = record.get(field)
		if value is not None and type(value) is not bool:
			raise ValueError("invalid boolean: " + field)
	findings = []
	missing = [field for field in BOOL_FIELDS if record.get(field) is None]
	if missing:
		findings.append("unknown:" + ",".join(missing))
	issuance = all(record.get(field) is True for field in
				   ("published", "enrollment_enabled", "broad_enrollment",
					"auth_purpose", "requester_identity"))
	if issuance and record.get("approval_gate") is False:
		findings.append("unconstrained-identity-issuance-review")
	if record.get("web_ntlm") is True and record.get("epa_required") is False:
		findings.append("http-enrollment-binding-gap")
	if record.get("schannel_legacy") is True:
		findings.append("accepting-service-mapping-review")
	if record.get("sid_extension") is False:
		findings.append("binding-provenance-review-not-automatic-rejection")
	if record.get("template_v1") is True and record.get("ca_fix_49019") is False:
		findings.append("affected-ca-template-policy-review")
	return findings


def repaired(record):
	return dict(record, broad_enrollment=False, requester_identity=False,
				sid_extension=True, ca_fix_49019=True,
				epa_required=True, schannel_legacy=False)


class ADPolicyTests(unittest.TestCase):
	def test_strong_dc_epoch_does_not_fix_issuance(self):
		self.assertEqual(review(BASE), ["unconstrained-identity-issuance-review"])

	def test_service_mapping_and_http_binding_are_independent(self):
		record = dict(BASE, requester_identity=False, web_ntlm=True,
					  epa_required=False, schannel_legacy=True)
		self.assertEqual(review(record), ["http-enrollment-binding-gap",
										 "accepting-service-mapping-review"])

	def test_unknown_patch_not_assumed_safe_or_affected(self):
		record = dict(BASE, requester_identity=False, template_v1=True,
					  ca_fix_49019=None)
		self.assertEqual(review(record), ["unknown:ca_fix_49019"])
		self.assertEqual(review(dict(record, ca_fix_49019=False)),
						 ["affected-ca-template-policy-review"])

	def test_missing_extension_not_universal_authentication_denial(self):
		record = dict(BASE, requester_identity=False, sid_extension=False)
		self.assertEqual(review(record),
						 ["binding-provenance-review-not-automatic-rejection"])

	def test_repair_keeps_legitimate_enrollment_and_schema_is_strict(self):
		fixed = repaired(BASE)
		self.assertEqual(review(fixed), [])
		self.assertTrue(fixed["published"] and fixed["enrollment_enabled"])
		self.assertTrue(BASE["requester_identity"])
		with self.assertRaises(ValueError):
			review(dict(BASE, ca_fix_49019="yes"))


if __name__ == "__main__":
	print("Baseline:", review(BASE))
	print("Repaired:", review(repaired(BASE)))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

Refute "post-2025 DCs imply safe PKI" using `BASE`. Explain the independent HTTP binding and Schannel mapping findings. Distinguish an unknown CA patch from a confirmed missing patch. Propose a policy repair retaining legitimate enrollment, then use the in-memory repaired record. Finally, select ESC12, ESC13 and ESC14 from the matrix and name one missing prerequisite that the model cannot assess for each.

### Hints

`dc_epoch` is provenance, not a simulator of KDC behavior. `ca_fix_49019` must come from CA product/update evidence, not the domain functional level or calendar. `sid_extension=False` does not model all accepted strong mappings. Broad enrollment removal is not equivalent to disabling all enrollment.

### Solution and Fixed Retest

The baseline reports only `unconstrained-identity-issuance-review`. The repaired record derives identity from a trusted source and narrows enrollment, while keeping publication/enrollment enabled; its review list is empty for this limited rule set. HTTP and Schannel defects produce separate findings despite the modern DC label. Unknown CA fix status remains unknown and does not become an ESC15 verdict. ESC12 needs actual KSP/host authorization evidence; ESC13 needs the real OID/group link and effective authorization; ESC14 needs mapping-attribute ACLs and accepting-service semantics. None is evaluated by this small program.

### Evidence, Troubleshooting, and Cleanup

Expected: two summaries and **5 passing tests**. Preserve original/fixed policy records, per-finding prerequisites, unknown fields, and source/version evidence requirements. Invalid string Booleans are rejected; do not coerce `"false"` to true. A zero-finding result means only the modeled checks found no gaps; it is not PKI certification or proof of a working legitimate enrollment path.

Tests were not executed during authoring. KB5014754, Schannel mapping documentation, the taxonomy author's reference, and original ESC12 research were consulted; MSRC's dynamic product table was not readable through the text fetch, so exact product/KB applicability remains a required external check. No current CA/HSM deployment was validated. Remove the exercise directory only; there are no domain changes, issued certificates, or secrets to revoke. These defensive exercises do not complete execution-based roadmap objectives.

- [ ] Local AD Attacks exercise: Review synthetic identity/PKI controls and qualify ESC1-ESC15 risks without interacting with AD.
- [ ] Boundary check: Preserve intended enrollment while rejecting blanket mapping/patch assumptions and recording unknown prerequisites.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [Microsoft KB5014754: binding timeline and mapping types](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Schannel mapping methods](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings#certificatemappingmethods)
- [MSRC CVE-2024-49019](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019)
- [Original ESC12 research, 2023](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [Certipy author's ESC taxonomy: risk context, not lab instructions](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Group managed service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Security event 4662](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [Security event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
