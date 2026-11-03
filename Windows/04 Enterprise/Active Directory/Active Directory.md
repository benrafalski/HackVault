---
title: "Active Directory"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[Active Directory Security]]"
updated: 2026-11-03
---
# Active Directory

> [!abstract] TL;DR
> AD DS is a replicated authorization database, not just a login server. Trace the naming context, authoritative object identity, originating change, token, and object-specific access check separately.

> [!info] Agent scope
> Domains; forests; trusts; domain controllers; objects; replication; ACLs; administrative tiers; identity lifecycle.

## Prerequisites

- DNS, Kerberos, LDAP, SIDs, security descriptors, and [[Windows Lab Setup]]. Examples use the reserved forest `lab.example`, two writable DCs, and synthetic objects only.
- Reference baseline: patched Windows Server 2022/2025. Forest schema version, domain/forest functional levels, and DC OS version are different inputs; installing a newer DC does not automatically raise functional levels.
- The required offline lab needs Python 3.12 standard library only. RSAT examples are optional read-only observations, not lab prerequisites.

## Learn

```text
Teach Active Directory Domain Services at expert engineering depth. Assume I
know DNS, LDAP, Kerberos and Windows access tokens. Use a public, synthetic
two-site lab.example forest with two writable DCs and a branch RODC; no setup
of real infrastructure is required. Explain domain/forest/trust boundaries,
schema/configuration/domain/application naming contexts, GC partial replicas,
FSMO roles, DC locator, KCC topology and site schedules. Work through objectGUID
versus SID versus DN, group scopes, object-specific inherited ACEs, protected
accounts, and a narrowly delegated description-attribute edit.
Trace an attribute change across DCs using version, originating invocation ID,
originating USN/time, local USN, high-watermarks and up-to-dateness vectors.
Show stale replication, concurrent changes, deletion/recycle and supported
restore behavior without suggesting forced replication or snapshot rollback.
Connect joiner/mover/leaver workflows to token refresh, existing sessions,
trust direction and selective authentication. Explain administrative tiers and
the modern enterprise access model. Distinguish Server 2022/2025 OS, schema and
functional levels. Supply read-only diagnostic commands with prerequisites,
worked evidence, counterexamples and difficult questions with answers. Cite
Microsoft sources. No exploitation, secrets, ticket creation, confidential
data, or file edits. Teach here; do not alter study status.
```

## Cheatsheet

### Topology and Boundaries

| Component | Mechanism and consequence |
|---|---|
| Forest | Shared schema/configuration and transitive intra-forest trust. Treat forest-wide administration as the security boundary; child domains are not isolation from forest administrators. |
| Domain | Domain naming context, SID namespace and writable replicas on that domain's DCs. Domain password/account policy is not the same thing as an OU policy. |
| OU | Delegation and GPO scope, not an authentication boundary. A move changes DN, inherited ACLs and policy scope, but not objectGUID. |
| Site/subnet | IP subnet-to-site mapping drives DC selection and replication cost/schedule. A site may contain multiple domains; a domain may span sites. A site link describes logical connectivity, not a tunnel. |
| Global catalog | Full local-domain replica plus partial attribute sets for other domains. A successful GC search does not imply that every requested attribute is replicated there. |
| RODC | Read-only directory, inbound replication and explicit password-replication policy. Cached credentials and branch administration still require inventory; it is not a writable peer. |
| Trust | If resource domain A trusts identity domain B, B identities may authenticate to A resources; resource ACLs still authorize. A one-way trust does not authorize the reverse direction. |

Schema and configuration naming contexts replicate forest-wide. Domain contexts replicate within their domain; application partitions have their own replica membership, for example AD-integrated DNS zones. LDAP referrals and GC searches are different ways to cross naming contexts. Trust transitivity, name-suffix routing, SID filtering and selective authentication are separate controls. Selective authentication adds an Allowed-to-Authenticate decision at target computers; it does not replace share, service or directory ACLs.

The five FSMO roles serialize particular operations, not ordinary directory writes: schema master and domain naming master are forest-wide; RID master, PDC emulator and infrastructure master are per-domain. The PDC emulator participates in password-change convergence, lockout handling and the domain time hierarchy. Infrastructure-master placement depends on GC topology and enabled features; do not apply old placement rules without checking the design.

### Objects, Tokens and Permissions

`objectGUID` survives rename/move within the forest. DN is a location, not a stable key. `objectSid` identifies a security principal; deleting and recreating an identically named account creates a new identity. Store object GUID/SID and naming context in evidence, not display names alone. A UPN suffix is a sign-in name and need not equal the domain DNS name.

Use accounts -> global groups -> domain-local resource groups -> permissions for a simple single-domain design; universal groups support forest-wide composition. Group scope controls membership possibilities and placement, not automatic permission. A token contains a membership snapshot; a new AD membership value does not rewrite an existing process token or terminate sessions.

A directory DACL contains allow/deny ACEs, inherited/explicit flags, rights masks, and possibly an attribute/property-set/extended-right GUID. `WriteProperty` for `description` on descendant user objects is narrower than all-property writes, `GenericWrite`, `WriteDacl`, or `GenericAll`. An inherited-object GUID limits eligible child classes. `SELF` is a special principal evaluated in context. Owners and DACL modification rights matter independently of group membership. Inspect effective membership, ACE ordering, object class, inheritance protection and requested access; a textual ACE match is not a complete access check.

### Replication Invariants

Writable DCs accept originating updates. A destination pulls changes over inbound connection objects; KCC calculates topology from sites, links, schedules and replica membership. Local USNs order changes in one database only. The originating invocation ID identifies a particular database incarnation, not merely a server hostname. High-watermarks track progress from a replication partner; up-to-dateness vectors suppress already-seen originating changes arriving through another route.

For a single attribute, compare originating metadata, not `uSNChanged` across servers. Conflict resolution considers attribute version, originating timestamp and a deterministic originating-DSA tie-breaker. Do not decide a tie by alphabetically sorting displayed GUID strings. Linked-value replication gives individual group membership values their own metadata; an object's aggregate change timestamp is insufficient evidence of each member change.

Worked case: DC-A has description version 7, origin A/900; DC-B has version 6, origin A/880. DC-B is behind for this attribute even if its local USN is 24000 and DC-A's is 1500. If both show version 7 but different originating writes, investigate concurrency; a stale timestamp alone cannot identify the winning value. Successful replication of one naming context does not certify DNS application partitions or SYSVOL.

### Read-Only Diagnostic Sequence

On an authorized RSAT workstation with the ActiveDirectory module and rights to read the named synthetic objects, use Windows PowerShell 5.1. Server names must be replaced only with owned lab endpoints. These commands do not change replication or retrieve secrets.

```powershell
Import-Module ActiveDirectory
Get-ADForest -Server dc-a.lab.example |
	Select-Object RootDomain, ForestMode, Domains, GlobalCatalogs
Get-ADDomain -Server dc-a.lab.example |
	Select-Object DNSRoot, DomainMode, PDCEmulator, RIDMaster
Get-ADTrust -Filter * -Server dc-a.lab.example |
	Select-Object Name, Direction, TrustType, ForestTransitive, SelectiveAuthentication
Get-ADReplicationPartnerMetadata -Target dc-b.lab.example -Scope Server |
	Select-Object Partition, Partner, LastReplicationSuccess, LastReplicationResult
Get-ADReplicationAttributeMetadata `
	-Object 'CN=Casey,OU=Training,DC=lab,DC=example' -Server dc-b.lab.example |
	Where-Object AttributeName -eq 'description' |
	Select-Object AttributeName, Version, LastOriginatingChangeTime,
		LastOriginatingChangeDirectoryServerInvocationId, LastOriginatingChangeUsn, LocalChangeUsn
```

Interpret 1722 as an RPC reachability/name-resolution investigation, 8453 as replication access denied, and 8524 as DNS lookup failure in replication diagnostics. Preserve the actual error, partner and partition before remediation. DNS SRV records, time, firewall/RPC dependencies and the computer's secure channel are prerequisites, not reasons to immediately reset accounts or seize roles.

### Lifecycle and Recovery

| Stage | Required evidence |
|---|---|
| Joiner | Stable owner, unique identity, approved OU/group assignment, account expiry where appropriate, narrow delegated creator. |
| Mover | Remove old access as well as add new; examine inherited ACL/GPO changes and refreshed sign-in context. |
| Leaver | Disable at the authoritative source, remove privileged assignments, address active sessions and downstream synchronization, retain required records. |
| Deletion | Deleted-object retention, Recycle Bin availability and backups determine restore options; restoring an object is not proof every dependent entitlement is correct. |
| DC recovery | Use supported system-state/forest-recovery procedures. VM-Generation ID support reduces certain virtualization risks; a snapshot is not a forest recovery plan. |

Protect DCs, PKI, identity synchronization and their backup/admin systems as control-plane assets. Separate privileged administration from everyday endpoints. Traditional tier-0/1/2 terminology is useful for on-premises reasoning; Microsoft's enterprise access model extends this to cloud control, management and workload planes.

## Gotchas

- `lastLogon` is per-DC; `lastLogonTimestamp` is replicated with deliberate update lag. Neither alone proves that an account is unused.
- `adminCount=1` is historical evidence, not a full current protected-membership calculation. Protected objects may not inherit a delegated OU ACE.
- Recreating an account or changing a DN does not repair stale ACLs, tokens, certificates or synchronized object relationships automatically.

## Labs

### Offline Replication Evidence Case

Scope: two synthetic replicas of one attribute. This is an evidence classifier, not an AD replication emulator or proof of real replication health. Python 3.12, standard library, no network/administrator/RSAT requirements. Create a separate empty exercise directory and place the single file below in it. All seed data is embedded; no downloads or companion note are needed.

### File: test_example.py

```python
import csv
import io
import unittest

EVIDENCE = """dc,object_guid,attribute,version,origin,origin_usn,local_usn,value
dc-a,casey-guid,description,7,invocation-a,900,1500,Reviewed
dc-b,casey-guid,description,6,invocation-a,880,24000,Pending
"""


def rows():
	return list(csv.DictReader(io.StringIO(EVIDENCE)))


def compare(left, right):
	for field in ("object_guid", "attribute"):
		if left[field] != right[field]:
			raise ValueError("different comparison scope")
	if int(left["version"]) != int(right["version"]):
		return "different-version"
	origin_fields = ("origin", "origin_usn")
	if any(left[field] != right[field] for field in origin_fields):
		return "different-origin-investigate-conflict"
	if left["value"] != right["value"]:
		return "inconsistent-evidence"
	return "same-originating-write"


class ReplicationEvidenceTests(unittest.TestCase):
	def test_baseline_is_stale_despite_larger_local_usn(self):
		source, destination = rows()
		self.assertGreater(int(destination["local_usn"]), int(source["local_usn"]))
		self.assertEqual(compare(source, destination), "different-version")

	def test_convergence_does_not_require_equal_local_usns(self):
		source, destination = rows()
		repaired = dict(source, dc=destination["dc"], local_usn="24001")
		self.assertEqual(compare(source, repaired), "same-originating-write")

	def test_same_version_is_not_enough(self):
		source, _ = rows()
		concurrent = dict(source, origin="invocation-b", origin_usn="23")
		self.assertEqual(compare(source, concurrent), "different-origin-investigate-conflict")

	def test_scope_and_consistency(self):
		source, _ = rows()
		with self.assertRaises(ValueError):
			compare(source, dict(source, attribute="displayName"))
		self.assertEqual(compare(source, dict(source, value="Other")), "inconsistent-evidence")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Label forest/domain/site boundaries for `lab.example`, DC-A in HQ and DC-B in Branch. Both host the same domain partition; no trust is involved.
2. Before running anything, identify which replica has the newer attribute version and explain why local USN 24000 does not win.
3. Run `py -3.12 -m unittest -v test_example.py` inside this exercise directory. A baseline test passes by detecting the bad evidence, not by accepting it as healthy.
4. Read the repaired fixture and explain why its different local USN is correct. Add a changed invocation-ID case and require investigation, not an automatic winner.
5. Write a three-line incident conclusion: observation, plausible cause, missing evidence. The missing evidence must include partition/partner health and the change's originating time.

### Hints

An originating write keeps its origin metadata as it travels. A destination assigns local bookkeeping numbers. Matching version alone does not establish convergence.

### Solution and Expected Results

DC-B is one version behind for `description`; connectivity/schedule delay is plausible but not proven. The repaired row copies the originating write while retaining a destination-local USN. Four tests are expected to pass. The concurrency test deliberately refuses to implement incomplete conflict resolution. A healthy permitted state, two replicas carrying the same originating value, still passes.

### Verification, Troubleshooting, and Cleanup

Author execution: not performed; shell/tests prohibited for this revision. An absent `py` launcher is an environment prerequisite failure, not a replication result; use an existing Python 3.12 executable instead. A CSV edit must retain all eight headers. Remove only the exercise directory and its `__pycache__` after practice. No directory objects or services were created.

The original live-practice checklist below remains user-owned and optional; the offline case does not satisfy its real-directory claims.

- [ ] Local Active Directory exercise: Use GOAD or a small isolated test forest to map synthetic users, groups, OUs, delegated ACLs, and one trust relationship. Validate one permission path manually rather than relying only on a graph.
- [ ] Boundary check: Delegate only a harmless test-OU task and verify the operator cannot modify protected groups or replication-related rights.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[AD Attacks]]
- [[BloodHound]]
- [[Active Directory Security]]

## References

- [AD DS replication concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts)
- [Get-ADReplicationAttributeMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationattributemetadata)
- [How security descriptors are set on new directory objects](https://learn.microsoft.com/en-us/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects)
- [AD forest recovery guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide)
- [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
