---
title: "Windows Credential Access"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Credential Access

> [!abstract] TL;DR
> Credential exposure is a failure of a specific secret's storage, use, or authority boundary. A verifier, bearer token, Kerberos ticket, and encrypted blob have different properties; access telemetry is not evidence that a usable secret was obtained.

> [!info] Agent scope
> LSASS; SAM; DPAPI; credential storage boundaries; prerequisite rights; synthetic telemetry; protection and cleanup. No credential retrieval, dumping, decryption, cracking, or reuse procedures; the lab contains metadata only.

## Learn

```text
Teach Windows credential protection at expert depth. Assume tokens, authentication
protocols, process access checks, and basic cryptography. Separate LSASS logon
sessions/security packages, SAM local verifiers, domain cached-logon verifiers,
LSA secrets, DPAPI user/machine scope, Credential Manager, and application tokens.
For each, explain what is protected, who legitimately needs access, protection at
rest versus in use, prerequisite rights, logon-type effects, and residual risk.
Explain LSA protected-process restrictions versus Credential Guard isolation;
neither is a blanket promise about all secrets. Cover DPAPI master-key lifecycle,
optional entropy, recovery/trust considerations, machine scope and same-user risk
without explaining key recovery or decryption. Distinguish exposure, attempted
access, successful OS access, and demonstrated disclosure. Work through synthetic
process-access/file-audit records and missing telemetry; discuss false positives,
sensor coverage, rotation sequencing, LAPS, and reduced privileged logons.
Supply safe offline Python 3.12 stdlib metadata classification tests, including
denied access, an approved security tool, and an unknown source. No real secrets,
memory reads/dumps, hive access, credential extraction, cracking, replay, or live
account changes. Use public primary sources and build-qualified claims. No
page-table content or confidential data; link WinDbg rather than giving commands.
Include challenge questions with answers; do not edit files or mark labs complete.
```

## Cheatsheet

### Store, Artifact, and Trust Boundary

| Store or component | Contents and legitimate use | Boundary and residual risk |
|---|---|---|
| LSASS | Authentication packages and logon-session state; available material depends on package/logon and configuration | Process access, LSA protection, and isolated secrets are separate checks; not every logon leaves a plaintext password |
| SAM | Local account metadata and password verifiers | Local-account store, not the AD database; backups and offline media require protection too |
| Cached domain logon | A local verifier supporting offline domain-user logon | Not the same artifact as an NTLM password hash; do not assume interchangeability |
| LSA secrets | Machine/service-related secrets used by Windows components | Different store from SAM and different from all LSASS runtime data |
| DPAPI user scope | Protected application data tied to user context and master-key protection | Typically the same user on the same machine; profile/roaming behavior can matter; not isolation from hostile code already running as that user |
| DPAPI machine scope | Protected data associated with the machine | Any user on that machine may be able to unprotect a blob they can read; application ACLs remain critical |
| Credential Manager / applications | Application-specific credentials, tokens, cookies, or protected blobs | Storage provider and application behavior determine protection; browser tokens are not all protected by Credential Guard |
| Backup/recovery infrastructure | Copies of protected stores, recovery material, configuration | Encryption, separate authority, retention, and audit must survive host compromise |

A password proves knowledge through a protocol; a verifier supports checking a guess; a bearer token often authorizes whoever presents it until expiry/revocation. A Kerberos ticket's service, lifetime, encryption, and session context constrain use. A DPAPI blob is ciphertext with associated protection metadata, not necessarily a credential. Never infer reuse properties from a filename or hash-like string.

DPAPI's optional entropy is an additional input that must be managed separately if used; hardcoding it beside the blob is not a new trust boundary. Encryption at rest cannot protect plaintext after an authorized application decrypts it. Scope choice, application file permissions, identity separation, and limiting plaintext lifetime solve different problems. "Machine protected" does not mean "administrator only."

### Protection Layers and Version Caveats

| Control | Protects against | Does not establish |
|---|---|---|
| LSA protection (PPL) | Unsupported access/code loading into LSASS under protected-process rules | That the caller is harmless or every credential is isolated |
| Credential Guard | Selected domain credentials isolated using virtualization-based security | Protection of all local accounts, application secrets, input capture, or every active-session action |
| LSASS ASR rule | Certain credential-stealing process-access behavior where the rule applies | Universal detection; applicability and interaction with LSA protection matter |
| Windows LAPS | Shared/stale local administrator password risk through managed uniqueness/rotation | Isolation of an already authorized administrator or all domain credentials |
| BitLocker and backup controls | Offline disk/backup disclosure | Protection from an authorized application on an unlocked host |
| Privileged-logon separation | Exposure of high-value identities on lower-trust machines | Prevention of every endpoint compromise |

Windows 11 22H2-era default enablement of Credential Guard/LSA protection is conditional on eligibility, edition, installation history, policy, and platform. Later server/client behavior must be checked against the exact release. Configured, running, and successfully protecting a particular secret are different claims. Do not disable controls to "confirm" a hypothesis.

### Evidence Without Collecting Secrets

For process-access metadata, decode the **granted** mask, not just the requested mask. `PROCESS_VM_READ` is `0x0010`; `PROCESS_QUERY_LIMITED_INFORMATION` is `0x1000`. The presence of the former is a review signal, not proof that memory was read or that data was valuable. Sysmon event 10 can provide source/target identifiers and granted access when collected; it does not report every failed open, every memory operation, or a credential-disclosure verdict. A synthetic denial below is a normalized access-audit fact, not a purported native Sysmon event.

File/registry audit evidence needs appropriate SACLs and audit policy. Process creation (4688/Sysmon 1), security-tool policy/health, and subsequent authentication can add context, but correlating by time alone is insufficient. Use host, stable process identity, identity, result, and source provenance. Separate an approved security product's documented access from an unsigned-name heuristic: signatures and filenames alone are weak allowlists.

Record only metadata necessary for triage: logical store, access category, result, actor ID, policy state, and confidence. Do not acquire a dump or credential database merely to make a report more persuasive. A missing collection interval is `unknown`, not `clean`.

## Defense

Combine supported LSA protection/Credential Guard, reduced privileged logons, unique managed local passwords, service-account lifecycle management, application isolation, and encrypted restricted backups. Avoid broadly excluding security-sensitive processes from monitoring. Validate normal smart-card, authentication-provider, and service compatibility during deployment.

For a real exposure, contain the compromised system and identify the affected secret classes before rotating/revoking them through approved administration. Password changes alone do not revoke all issued tickets or application tokens. Preserve sanitized audit evidence, evaluate scope and retention, and verify clean endpoints before restoring privileged use. This note supplies no secret-access or rotation commands.

## Labs

### Environment and Complete Files

Defensive metadata triage only. Python **3.12**, standard library `unittest`, ordinary account, offline empty directory. All seeds are embedded; no LSASS handle, DPAPI call, registry operation, password, or token is used. This is not a DPAPI/LSA emulator and cannot validate the protection state of Windows.

### File: test_example.py

```python
import unittest


VM_READ = 0x0010
KNOWN_STORES = {"lsass", "sam", "dpapi-user", "dpapi-machine"}
EVENTS = [
	{"id": "query", "store": "lsass", "result": "allowed",
	 "mask": 0x1000, "actor": "inventory", "approved": False},
	{"id": "review", "store": "lsass", "result": "allowed",
	 "mask": 0x1010, "actor": "unclassified", "approved": False},
	{"id": "blocked", "store": "lsass", "result": "denied",
	 "mask": 0, "actor": "unclassified", "approved": False},
	{"id": "sensor", "store": "lsass", "result": "allowed",
	 "mask": 0x0010, "actor": "managed-sensor", "approved": True},
	{"id": "machine-blob", "store": "dpapi-machine", "result": "allowed",
	 "mask": 0, "actor": "app-user", "approved": False},
]


def triage(event):
	if event.get("store") not in KNOWN_STORES:
		return "unknown-store"
	if event.get("result") == "denied":
		return "blocked-attempt"
	if event.get("result") != "allowed":
		return "unknown-outcome"
	if event["store"] == "lsass":
		mask = event.get("mask")
		if type(mask) is not int or mask < 0:
			return "unknown-rights"
		if not mask & VM_READ:
			return ("query-only-in-this-model" if mask == 0x1000
					else "other-rights-review")
		return "approved-review" if event.get("approved") is True else "investigate"
	if event["store"] == "dpapi-machine":
		return "review-blob-acl-and-app-boundary"
	return "review-store-specific-access"


def flawed_rule(event):
	return event.get("store") == "lsass"


class CredentialMetadataTests(unittest.TestCase):
	def test_baseline_rule_overstates_query_and_denial(self):
		self.assertTrue(flawed_rule(EVENTS[0]))
		self.assertTrue(flawed_rule(EVENTS[2]))
		self.assertEqual(triage(EVENTS[0]), "query-only-in-this-model")
		self.assertEqual(triage(EVENTS[2]), "blocked-attempt")

	def test_unapproved_and_approved_reads_remain_distinct(self):
		self.assertEqual(triage(EVENTS[1]), "investigate")
		self.assertEqual(triage(EVENTS[3]), "approved-review")

	def test_machine_scope_is_not_user_isolation(self):
		self.assertEqual(triage(EVENTS[4]), "review-blob-acl-and-app-boundary")

	def test_no_read_right_does_not_imply_query_only(self):
		for mask in (0, 0x0020, 0x1008):
			with self.subTest(mask=mask):
				self.assertEqual(triage(dict(EVENTS[0], mask=mask)),
								 "other-rights-review")

	def test_missing_and_invalid_evidence_stays_unknown(self):
		self.assertEqual(triage({}), "unknown-store")
		self.assertEqual(triage({"store": "sam"}), "unknown-outcome")
		for mask in (None, "0x10", -1, True):
			with self.subTest(mask=mask):
				self.assertEqual(triage(dict(EVENTS[1], mask=mask)), "unknown-rights")


if __name__ == "__main__":
	for event in EVENTS:
		print(event["id"], triage(event))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

First explain why the baseline LSASS-name rule overstates four different observations. Classify each record, identify which ones need follow-up, and write one sentence stating what evidence is still missing. Correct the interpretation rather than suppressing all access by an approved actor. Explain why the machine-scoped blob requires an application/ACL review rather than a cryptographic verdict.

### Hints

A successful access check establishes a granted capability, not its use. A denied attempt is valuable evidence but cannot prove disclosure. `approved` is supplied by a synthetic inventory; it is not derived from a friendly process name. Missing rights must not become zero rights.

### Solution and Fixed Retest

Expected classes, in order: `query-only-in-this-model`, `investigate`, `blocked-attempt`, `approved-review`, `review-blob-acl-and-app-boundary`. The first test demonstrates the baseline rule's false equivalence; the remaining tests require useful distinctions and explicit uncertainty. The sensor still gets a review classification, so approval does not erase its evidence. No record proves credential theft, and there is no real secret to remediate.

### Evidence, Troubleshooting, and Cleanup

Expected: five classification lines and **5 passing tests**. Only the exact `0x1000` mask is labeled query-only; other non-read masks remain `other-rights-review`, since absence of read permission does not identify the other granted capabilities. Retain the supplied event ID, original result, classified result, review rationale, and exact Python version. A string access mask is rejected intentionally; a real ingest adapter would need schema validation and explicit base conversion. This toy rule omits handle duplication, kernel activity, protected-process details, and event loss; it cannot measure detection sensitivity in production.

Authoring did not execute the tests. Delete only the exercise directory when finished. There are no protected blobs, keys, credential caches, or live account changes to clean up.

- [ ] Local Windows Credential Access exercise: Classify synthetic store-access metadata without accessing any credential store.
- [ ] Boundary check: Distinguish denied/query-only/approved access from investigation candidates and preserve unknown outcomes.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [Credential Guard overview and limitations](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Additional LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [CryptProtectData scope and behavior](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
