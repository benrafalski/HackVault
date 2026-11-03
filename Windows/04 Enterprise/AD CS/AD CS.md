---
title: "AD CS"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[AD CS Security]]"
updated: 2026-11-03
---
# AD CS

> [!abstract] TL;DR
> Enrollment authorizes issuance; a relying party separately checks chain, purpose, validity, revocation and identity mapping. A valid certificate is not automatically an authorized identity or a usable credential.

> [!info] Agent scope
> Certificate authorities; templates; enrollment; EKUs; mapping; enrollment services; permissions; audit and lifecycle.

## Prerequisites

- X.509, public/private keys, AD ACLs, DNS and TLS. Reference baseline: patched Server 2022/2025 enterprise CA and DCs; record exact cumulative updates, template compatibility and client builds.
- Required offline lab: Windows PowerShell 5.1/.NET Framework, no CA/domain/modules/admin access. No key, certificate or certificate request is submitted or installed.

## Learn

```text
Teach Active Directory Certificate Services at expert engineering depth. Assume
X.509/TLS/AD ACL knowledge. Explain offline root and online issuing CA roles,
enterprise versus standalone policy, template storage/replication/publication,
template versions, key providers, subject/SAN construction, key usage and EKUs.
Trace request generation, authenticated enrollment, CA/template authorization,
pending/denied/issued disposition, delivery, private-key association and renewal.
Compare RPC enrollment, Web Enrollment, CEP/CES and NDES without deploying them.
Distinguish certificate chain trust, application purpose, NTAuth, KDC strong
mapping and service authorization. Explain KB5014754's February/September 2025
enforcement milestones, SID extension and mapping failure evidence without
teaching impersonation or weakening mapping. Work through CRL/AIA/OCSP, validity,
CA key renewal, revocation latency and recovery dependencies.
Give safe inspection commands, a complete harmless request specification and
offline native EKU encoding exercise, with all files and expected results.
No issuance, forged artifacts, ESC recipes, relay, secrets or real-user data.
Use Microsoft sources, state unverified/version-sensitive details, and finish
with difficult questions and worked answers. Teach here; do not edit files.
```

## Cheatsheet

### CA Topology and State

| Component | Purpose and boundary |
|---|---|
| Offline standalone root | Trust anchor signs issuing CAs and publishes root revocation information; normally kept offline with protected key/backup procedures. Root trust distribution is a separate administrative act. |
| Enterprise issuing CA | Online AD-integrated policy/issuance service. Template data lives in the forest configuration partition; the CA must also publish a template before issuing from it. |
| Standalone CA | Does not use AD certificate templates as an enterprise CA does. Request approval, subject handling and distribution need explicit policy. |
| CA database | Request IDs, disposition and issued/revoked certificate records. Protect and back up with key/configuration; a certificate store export is not a CA backup. |
| AIA/CDP/OCSP | AIA can locate issuer certificates/OCSP; CDP identifies CRL distribution. Publication availability is required after issuance, including while a root is offline. |

AD configuration replication, CA template caching, publication on each issuing CA and client policy refresh are distinct delays. A new template visible in the console on one DC does not imply every CA can issue it. A two-tier hierarchy limits routine root-key exposure but adds CRL scheduling, overlap and recovery responsibilities.

### Template and Enrollment Decisions

Version 1 templates are legacy built-ins with limited editing; duplicating a suitable template creates a separately named policy object. Later template schema versions/compatibility levels support additional features and require compatible CAs/clients. Compatibility settings are functional requirements, not proof of patch currency. Use internal template names/OIDs in evidence, not localized display names alone; capture major/minor revision.

| Template field | Mechanism | Conservative design |
|---|---|---|
| Subject/SAN | Built from authenticated directory identity or supplied in request, according to template/policy | For account-authentication templates derive identity from directory; restrict workflows that genuinely need supplied names. |
| Key usage | Cryptographic operations such as Digital Signature and Key Encipherment | Match algorithm/protocol; it is not the application authorization list. |
| EKU/application policy | Purpose OIDs, e.g. Server Authentication `1.3.6.1.5.5.7.3.1`, Client Authentication `.2` | Only needed purposes; absent/unrestricted EKUs must not be interpreted as "no use allowed." |
| Private-key policy | Provider, algorithm/size, exportability, optional archival/attestation | Nonexportable where compatible; key ACL/HSM/TPM policy still matters. Exportability is not a promise against host administrator compromise. |
| Enrollment DACL | Read, Enroll and Autoenroll are different rights | Specific workload groups; Autoenroll does not replace Enroll. Review template write/owner rights separately. |
| Issuance requirements | Manager approval and authorized signatures may gate issuance | Document approver independence; approval is not automatically required on every renewal path. |
| Validity/renewal | Template request bounded by CA policy and issuer validity | Plan overlap; renewal is a new certificate, not an extension of the old serial's lifetime. |

Enrollment sequence: client generates/protects key -> forms signed request -> authenticates to endpoint -> CA applies request permission plus template availability/ACL/policy -> request is denied, pending or issued -> client obtains certificate and associates it with its existing private key. A CSR's self-signature proves possession of a key, not entitlement to a requested name. A requested EKU is not proof the CA will issue it. CA-wide settings and the policy module can affect the decision in addition to the template.

### Enrollment Transports

RPC/DCOM enrollment uses authenticated Windows infrastructure and its network dependencies. Web Enrollment is an IIS request interface, not the same service as CEP/CES. Certificate Enrollment Policy Web Service supplies policy; Certificate Enrollment Web Service handles enrollment over HTTPS. NDES adapts SCEP for device enrollment and adds registration-authority keys/challenge/lifecycle controls. Install only required services, use valid TLS, constrain authentication and maintain supported endpoint protections. Autoenrollment is client policy-driven and can fail independently of interactive enrollment.

### Chain, Purpose, Mapping and Authorization

1. Build a chain to a trusted root using supplied/cached/retrieved intermediates; verify signatures and constraints.
2. Check validity time, key usage/EKU/application policy and the relying party's requirements, including algorithm support.
3. Check revocation according to application policy. A reachable CRL must also be current and applicable; cached CRLs and delta/base relationships affect results. Unreachable revocation data can fail or be tolerated depending on the relying party, so test the actual service.
4. For AD certificate authentication, evaluate appropriate enterprise trust/NTAuth and strong certificate-to-account mapping. TLS hostname matching is not AD account mapping.
5. Apply service/resource authorization to the authenticated identity. Mapping an account does not grant application roles.

KB5014754 introduced the noncritical SID security extension `1.3.6.1.4.1.311.25.2` on supported enterprise issuance and strengthened KDC mapping. February 2025 updates moved DCs toward Full Enforcement by default; installing the September 9, 2025 update removes the compatibility rollback path described in that KB. For a November 2026 baseline, do not teach compatibility mode as a supported remediation. Record DC patch state and reissue/fix the intended identity binding instead. Strong explicit mappings exist for managed exceptions; ordinary subject/email-name matching is not equivalent. Schannel/IIS mapping paths have their own settings and must not be inferred solely from KDC behavior.

### Safe Inspection

On a Windows workstation, inspect only approved public lab certificate files. These commands do not export keys, submit requests or authenticate as a certificate subject. `-verify` may use cached/network chain resources depending on environment; offline use can report revocation unavailable, which is not the same as revoked.

```powershell
certutil.exe -dump .\lab-server.cer
certutil.exe -verify .\lab-server.cer
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
	(Join-Path $PWD 'lab-server.cer'))
$certificate | Select-Object Subject, Issuer, SerialNumber, NotBefore, NotAfter, HasPrivateKey
$certificate.Extensions | ForEach-Object {
	[pscustomobject]@{ Oid = $_.Oid.Value; Critical = $_.Critical; Value = $_.Format($false) }
}
$certificate.Dispose()
```

No certificate file is required for the offline lab below. The commands above are examples for an independently obtained authorized public certificate, not an incomplete lab dependency.

### Errors and Lifecycle

| Evidence | Likely layer to inspect |
|---|---|
| `0x80094800` CERTSRV_E_UNSUPPORTED_CERT_TYPE | Requested template name/publication/CA support; do not solve by publishing all templates. |
| `0x80094012` CERTSRV_E_TEMPLATE_DENIED | Template permissions; read/Enroll/identity scope rather than TLS trust. |
| Pending request | Approval/signature policy; not necessarily transport failure. |
| `0x800B0109` CERT_E_UNTRUSTEDROOT | Chain terminates at an untrusted root; do not import an arbitrary root simply to clear the error. |
| `0x80092013` CRYPT_E_REVOCATION_OFFLINE | Revocation service/data unavailable; not positive evidence of revocation or of validity. |
| Kdcsvc 39 / 40 / 41 | Missing strong mapping / certificate predates account / certificate SID mismatch respectively; inspect exact event and patch/mapping context. |

Track certificate serial plus issuer, template/revision, request ID, key owner, endpoint, validity, renewal overlap and revocation publication. Serial numbers are not globally unique across CAs. Disabling/deleting an AD account is not a complete certificate retirement workflow. CA key renewal may create multiple chain paths; retain old revocation coverage until all dependent certificates expire. Recovery needs CA key/database/configuration, publication paths and tested access to protected backups.

## Gotchas

- A server-authentication certificate is not an AD login credential just because its chain is trusted.
- Importing a root changes trust, not merely display formatting. The lab installs no trust anchors.
- Template ACLs, CA permissions and endpoint controls are cumulative boundaries; passing one is not passing all.

## Labs

### Offline Request and Native EKU Inspection

Dependencies: Windows PowerShell 5.1 and .NET Framework only. In an empty exercise directory create both files below. The INF is a complete illustrative PKCS#10 request specification for a synthetic TLS endpoint; it is inspected as text, never submitted. Do not run `certreq` or install a CA for this exercise. The PowerShell file uses the real .NET DER encoder/decoder for an EKU extension, not a certificate generator.

### File: request.inf

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=training.lab.example"
KeyAlgorithm = RSA
KeyLength = 3072
HashAlgorithm = SHA256
MachineKeySet = TRUE
Exportable = FALSE
ProviderName = "Microsoft Software Key Storage Provider"
RequestType = PKCS10
KeyUsage = 0xa0

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=training.lab.example"

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1
```

### File: inspect.ps1

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$specification = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'request.inf') -Raw
foreach ($required in @('KeyLength = 3072', 'Exportable = FALSE', 'RequestType = PKCS10')) {
	if (-not $specification.Contains($required)) { throw "Missing expected request setting: $required" }
}
$oids = [System.Security.Cryptography.OidCollection]::new()
[void]$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
$encoded = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false)
$asn = [System.Security.Cryptography.AsnEncodedData]::new($encoded.Oid, $encoded.RawData)
$decoded = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($asn, $false)
$values = @($decoded.EnhancedKeyUsages | ForEach-Object { $_.Value })
if ($values.Count -ne 1 -or $values[0] -ne '1.3.6.1.5.5.7.3.1') { throw 'Unexpected purpose' }
if ($values -contains '1.3.6.1.5.5.7.3.2') { throw 'Client authentication unexpectedly present' }
$hex = [BitConverter]::ToString($encoded.RawData)
if ($hex -ne '30-0A-06-08-2B-06-01-05-05-07-03-01') { throw 'Unexpected DER bytes' }
"EKU extension: $($encoded.Oid.Value)"
"Purpose: $($values[0])"
"DER: $hex"
'PASS: server-purpose encoding round-trips; no certificate, key or trust was created'
```

### Objectives and Steps

1. Run `powershell.exe -NoProfile -File .\inspect.ps1` in the exercise directory under existing execution policy. It reads only the local INF and constructs an extension in memory.
2. Explain `0xa0`: Digital Signature (`0x80`) plus Key Encipherment (`0x20`); contrast with EKU Server Authentication. These are separate extensions/purposes.
3. Decode the output: `30` is ASN.1 SEQUENCE, `06` is OID, and the final `.1` distinguishes server from client authentication. The extension's OID is `2.5.29.37`; its content contains the allowed-purpose OID.
4. Change only the OID in the PowerShell collection to client authentication. The positive assertion must now fail. Restore the printed file and repeat. No network operation is involved.

### Hints and Solution

The requested SAN is a DNS name, not a directory identity mapping. A real enterprise CA may reject or replace request contents under its template policy; the INF has no entitlement by itself. Expected output includes `2.5.29.37`, `1.3.6.1.5.5.7.3.1`, the asserted DER bytes and PASS. The negative mutation fails because the narrow server-purpose invariant no longer holds.

### Verification, Troubleshooting, and Cleanup

Not executed by the author. A missing INF is a setup error; use the exact filename beside the script. Do not change execution policy to bypass restrictions. Remove the exercise directory to reset. No certificate, CSR, key container, CA, trust store entry or enrollment exists to clean up. This proves native extension encoding only, not CA issuance, chain trust, revocation or AD account mapping.

Original optional live checklist remains uncompleted; no issuance is part of the required offline exercise.

- [ ] Local AD CS exercise: Use a disposable AD CS lab to issue a harmless test certificate from a restricted template. Inspect EKUs, subject rules, enrollment ACLs, mapping policy, and revocation behavior.
- [ ] Boundary check: Verify a low-privilege test user cannot supply another identity or enroll through an unapproved template, and that strong mapping policy rejects mismatched identities.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[AD CS Security]]

## References

- [AD CS overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
- [certreq command and INF syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1)
- [certutil inspection reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [X509EnhancedKeyUsageExtension](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509enhancedkeyusageextension)
- [KB5014754: certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
