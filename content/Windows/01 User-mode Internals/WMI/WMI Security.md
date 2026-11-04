---
title: "WMI Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[WMI]]"
updated: 2026-11-03
---
# WMI Security

> [!abstract] TL;DR
> Overbroad namespace rights, unsafe providers, and unreviewed permanent subscriptions can enable privileged operations or persistence.

> [!info] Agent scope
> Security of: Namespaces; classes; providers; queries; remote access; permissions; event subscriptions; telemetry. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Namespace DACLs, provider methods/hosting, remote transport, query input, repository configuration, filter/consumer/binding inventory and telemetry completeness.
- Security lab is entirely offline. No WMI consumer, filter, binding, remote connection, process-launch method or autostart object is installed or invoked.

## Learn

```text
Teach defensive WMI/CIM security with provider-specific authorization reasoning.
Assume Windows tokens, ACLs, namespaces, WQL and management transports. Explain
WBEM_ENABLE, METHOD_EXECUTE, write rights, REMOTE_ACCESS, descriptor rights,
inheritance and provider checks. Compare local COM, remote DCOM and WS-Man;
include UAC, authentication/encryption and callback limitations without setup
or bypass procedures. Separate enumeration, property reads and action methods.
Review permanent subscription evidence as a graph of filters, consumers and
bindings, including EventNamespace, creator/security metadata, orphan objects
and approval provenance. Use only normalized offline fixtures, not installable
MOF or consumer commands. Detect an overbroad read-only role and dangling
binding, repair the approved evidence, and retain permitted local queries.
Cover WMI-Activity/Sysmon correlation, PID reuse, missing logs, provider failures
and false positives. Provide exact masks, tests and primary-source limits.
No persistence, exploitation, escalation, credential access, bypass/evasion,
note edits or fabricated validation. End with answered defensive review cases.
```

## Cheatsheet

### Namespace Rights and Additional Gates

| Right | Mask | Review significance |
|---|---|---|
| `WBEM_ENABLE` | `0x1` | Read access to namespace data, subject to provider checks. |
| `WBEM_METHOD_EXECUTE` | `0x2` | Method invocation authority, not a read-only query right. |
| `WBEM_FULL_WRITE_REP` | `0x4` | Repository class/instance writes. |
| `WBEM_PARTIAL_WRITE_REP` | `0x8` | More limited repository writes. |
| `WBEM_WRITE_PROVIDER` | `0x10` | Writes through providers, with provider-specific semantics. |
| `WBEM_REMOTE_ACCESS` | `0x20` | Remote namespace access; does not configure transport/firewall. |
| `READ_CONTROL` / `WRITE_DAC` | `0x20000` / `0x40000` | Read/change namespace security; separate from WMI method rights. |

Other rights, including event publish/subscribe rights, have object/version-specific significance. Do not reduce all WMI security to `0x1` versus admin. Actual access depends on inherited ACEs, token groups, privileges, namespace and provider checks. A normalized effective mask in the lab is supplied evidence for one fictional subject, not a raw DACL calculation.

`__SystemSecurity` exposes descriptor-related methods; invoking a read-oriented method still differs from a property query and needs its documented permissions. Do not broadly grant execute-method or write rights to solve a property-read failure. Local COM, DCOM remote activation and WS-Man have different policy paths. Encryption requirements can be expressed by namespace qualifiers; clients/callbacks must meet them. Authentication alone does not authorize underlying provider resources.

### Subscription Evidence Is a Graph

| Node/edge | Required review fields |
|---|---|
| `__EventFilter` | Object path/key, query language/text, EventNamespace, creator/security data. |
| Consumer instance | Concrete consumer class/key, approved owner/purpose and configuration; class existence alone does not establish safety. |
| `__FilterToConsumerBinding` | Fully resolved filter and consumer references, namespace context and delivery/security settings. |

Permanent objects can outlive the creating process. Temporary observers have a client-owned lifetime. A dangling binding may indicate partial collection, stale configuration or corruption; it is not proof of an executed action. An unreferenced consumer is still inventory, not automatically irrelevant. Preserve raw paths and resolve references consistently; lowercasing arbitrary values or splitting object paths on punctuation can corrupt keys.

For a separately authorized read-only inventory, these commands enumerate configuration without changing it:

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
	Select-Object Name,EventNamespace,QueryLanguage,Query
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer |
	Select-Object CimClass,Name
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
	Select-Object Filter,Consumer
```

Do not treat inaccessible inventory as empty. A complete audit also needs security/provenance, provider-specific configuration and namespace coverage; these projections are an initial view only. Query text is untrusted data and must not be evaluated as code. No inventory output from real machines is needed for this lab.

## Detection and Defense

Use WMI-Activity/Operational records with namespace, operation, client PID, time, host and result. Event 5858 commonly reports client-operation errors; it is not a comprehensive successful-query audit. Sysmon 19/20/21, when configured and supported, describe filter/consumer/binding activity; absence does not prove absence of subscriptions. Legitimate management/monitoring software creates similar objects. Correlate with approved deployments, provider hosting and observed results; avoid labeling all WMI usage hostile. Minimize remote exposure, grant narrowly scoped namespace rights, protect providers and review graph changes through configuration management.

## Labs

### Environment and Complete Files

Python 3.11+ stdlib, any OS. Two files in a new scratch directory; no Windows access, build or dependency download. The fixture is synthetic normalized inventory, **not importable WMI configuration**. Consumer entries contain identity only, no executable/script or delivery payload. Approval status is supplied review evidence, not inferred from a familiar name.

### File: inventory.json

```json
{
  "namespace": "root/cimv2",
  "effective_mask": 35,
  "permitted_query": "SELECT ProcessId,Name FROM Win32_Process WHERE ProcessId = 1234",
  "filters": [{"id": "filter-1", "class": "__EventFilter", "approved": true}],
  "consumers": [{"id": "consumer-1", "class": "LogFileEventConsumer", "approved": true}],
  "bindings": [
	{"filter": "filter-1", "consumer": "consumer-1", "approved": true},
	{"filter": "filter-1", "consumer": "missing", "approved": false}
  ]
}
```

### File: test_example.py

```python
import copy
import json
from pathlib import Path
import unittest

def review(record):
	problems = set()
	if record.get("namespace") != "root/cimv2" or record.get("effective_mask") != 1:
		problems.add("local read-only namespace policy")
	filters = {item["id"] for item in record["filters"]}
	consumers = {item["id"] for item in record["consumers"]}
	if len(filters) != len(record["filters"]) or len(consumers) != len(record["consumers"]):
		problems.add("duplicate identity")
	for item in record["filters"] + record["consumers"] + record["bindings"]:
		if item.get("approved") is not True:
			problems.add("unapproved evidence")
	for binding in record["bindings"]:
		if binding["filter"] not in filters or binding["consumer"] not in consumers:
			problems.add("dangling binding")
	return problems

class WmiReview(unittest.TestCase):
	def setUp(self):
		self.record = json.loads(Path(__file__).with_name("inventory.json").read_text())

	def fixed(self):
		record = copy.deepcopy(self.record)
		record["effective_mask"] = 1
		record["bindings"] = record["bindings"][:1]
		return record

	def test_baseline(self):
		self.assertEqual(review(self.record), {"local read-only namespace policy",
			"unapproved evidence", "dangling binding"})

	def test_fixed_preserves_read_query_and_approved_graph(self):
		record = self.fixed()
		self.assertEqual(review(record), set())
		self.assertEqual(record["permitted_query"], self.record["permitted_query"])
		self.assertEqual(len(record["bindings"]), 1)

	def test_approval_is_not_inferred(self):
		record = self.fixed()
		del record["consumers"][0]["approved"]
		self.assertEqual(review(record), {"unapproved evidence"})

	def test_partial_inventory_is_not_clean(self):
		record = self.fixed()
		record["consumers"] = []
		self.assertIn("dangling binding", review(record))

if __name__ == "__main__":
	unittest.main()
```

### Objectives, Hints, and Fixed Retest

Run `python -m unittest -v test_example`. Decode 35 (`0x23`): enable + execute methods + remote access, exceeding this fictional local read-only role. The second binding lacks a known consumer and approval. Hint: an approved filter does not automatically approve every binding to it.

The solution is an **in-memory corrected review fixture**: mask 1 and only the approved complete binding. Nothing is removed from WMI. Expected four passing tests; the query remains byte-for-byte unchanged and the approved graph is retained. The test does not execute WQL or validate all possible consumer classes; it demonstrates evidence/authorization review over actual WMI rights and object relationships.

### Verification, Troubleshooting, and Cleanup

Four `OK` tests, no network/Windows calls and no subscribers created. Missing JSON means files are not colocated. Remove only the two scratch files and local `__pycache__`. Source reviewed; Python tests unexecuted for parent validation. Actual namespace DACL evaluation, provider authorization, remote transports, subscription delivery and telemetry remain unverified and are not certified by these fixtures.

- [ ] Local WMI exercise: Review offline namespace rights and filter/consumer/binding evidence.
- [ ] Boundary check: Repair the synthetic policy/inventory findings while preserving approved local reads.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[WMI]]

## References

- [Securing WMI namespaces](https://learn.microsoft.com/en-us/windows/win32/wmisdk/securing-wmi-namespaces)
- [WMI namespace access rights](https://learn.microsoft.com/en-us/windows/win32/wmisdk/namespace-access-rights-constants)
- [Receiving WMI events](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event)
- [Tracing WMI activity](https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity)
- [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
