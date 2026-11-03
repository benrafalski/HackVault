---
title: "Windows Lateral Movement"
aliases: []
tags: [windows, x5, technique]
domain: windows
phase: "X5"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Windows Lateral Movement

> [!abstract] TL;DR
> Remote reachability, authentication, authorization, and action completion are four distinct facts. Investigate unexpected identity/source/destination relationships without treating every remote logon as compromise.

> [!info] Agent scope
> SMB/WinRM/RDP authentication and administration boundaries, prerequisites, logging, and segmentation. Validation uses offline synthetic events only; no remote execution, credential reuse, or live protocol probing.

## Learn

```text
Teach Windows lateral-movement risk as defensive remote-access analysis. Assume
TCP, Kerberos/NTLM, access tokens, and Windows audit basics. Trace name resolution,
reachability, service identity, authentication, logon rights, endpoint authorization,
and the requested action separately for SMB, WinRM, and RDP. Explain share versus
NTFS access; WinRM transport/authentication versus endpoint/command authorization;
RDP NLA versus interactive-logon rights and session lifecycle. Cover delegation,
local-account filtering, SPN/time/trust failures, identity tiers, and the difference
between encryption, signing, channel binding, and authorization. Explain relevant
event IDs, audit prerequisites, destination-local logon IDs, PID reuse, timestamp
skew, and legitimate administration baselines. Show a complete offline synthetic
correlation exercise in Python 3.12 stdlib with denied actions, reused logon IDs
on different hosts, and a permitted administration path preserved after repair.
No remote commands, connections, credential capture/reuse, authentication coercion,
relay, service/task creation, or attack execution. Use primary sources and qualify
OS defaults by release/edition. Include failure analysis, evidence confidence,
controls and tradeoffs, hints and separate solutions. No confidential data or
page-table content; no WinDbg commands. Teach without editing notes or study state.
```

## Cheatsheet

### Protocol Boundaries

| Path | Identity and authorization | Evidence and failure modes |
|---|---|---|
| SMB | Session authentication, share permissions, then filesystem/object permissions; neither share access nor authentication means host administration | Network logon, share/object audit, server policy; distinguish session denial from file denial |
| WinRM | WS-Management listener/transport, authentication, endpoint ACLs, constrained session capabilities | WinRM/PowerShell logs plus logon/process context; listener reachable does not imply endpoint access |
| RDP | TLS/server identity, NLA where configured, remote-interactive logon rights, session policy | Remote-interactive logon and Terminal Services channels; NLA success is not proof of desktop use |
| Remote management services | Per-interface authentication and authorization beyond transport | Service/task configuration events need a causal link, not merely a nearby network logon |

SMB signing provides message integrity; encryption adds confidentiality for the covered traffic. Neither grants or removes file permissions. WinRM over HTTP can use authentication-provided message encryption under supported configurations; HTTP alone does not determine the full security posture. Conversely, TLS without correct server identity validation and endpoint authorization is insufficient. RDP NLA reduces pre-session exposure but does not replace patching, access policy, or identity separation.

Kerberos depends on service naming/SPNs, account keys, time, and trust. NTLM fallback may reflect configuration or naming issues; it is not proof of abuse. A logon token's rights, local-account filtering, and remote restrictions can differ from an interactive administrator's expectations. Do not "repair" diagnosis by weakening authentication, filtering, or endpoint policy. First determine which boundary rejected the operation.

Credential delegation extends where an identity can act; avoid assuming a successful first connection permits a second hop. Remote Credential Guard and Restricted Admin have different requirements and threat models for RDP; availability and behavior must be verified for the client, server, and authentication path. Keep privileged identities off general-purpose workstations and distinguish interactive session exposure from service-ticket use.

### Correlation Contract

| Event/context | Supports | Does not prove |
|---|---|---|
| Security 4624 type 3 | Successful network logon | Which remote-management protocol or whether an action completed |
| Security 4624 type 10 | Remote-interactive logon | Malicious intent, full session history, or every reconnect |
| Security 4625 | Failed logon with status/substatus | Network segmentation worked or every credential was invalid |
| 4648 | Explicit credentials supplied in a recorded context | That remote authentication succeeded |
| 4768/4769 on a DC | Kerberos authentication/service-ticket activity | Destination authorization or execution |
| 5140/5145 | Share access / detailed share access checking | Every filesystem operation without its own auditing |
| 4697/7045, 4698/4702, 4688 | Service/task/process changes | That a neighboring 4624 caused them |

Join host plus logon ID, include a bounded interval and account identity, and retain boot/session context in real data. Logon IDs are not globally unique. Source IP can be absent, translated, or a gateway; process IDs are reused. Normalize times to UTC, retain event time versus ingest time, and distinguish a lost interval from no activity. Audit subcategories, SACLs, collection of operational channels, and retention affect visibility.

An authorization baseline should be a set of approved **source, destination, account, protocol, operation** tuples with owner and expiry, not a blanket allowlist of administrator usernames. The complete lab below implements a small example and demonstrates a false join caused by ignoring the host. A finding remains a review candidate, not an attribution verdict.

### Bounded Log-Correlation Query

**Fragment / prerequisites:** SQLite over deduplicated, normalized exported logs, not native Windows tables. `logon_events` requires `event_id`, `host`, `boot_id`, `logon_id`, `account_sid`, and `event_time`; `action_events` requires the same columns plus `result`. IDs must be non-null, action event IDs unique, and times integer UTC epoch seconds. Map the destination logon's target ID/SID to the action's actual acting session ID/SID; never substitute a nearby username. Boot identity must come from trusted inventory/session tracking, not an assumed field in every event.

```sql
SELECT action.event_id, action.result,
			 COUNT(auth.event_id) AS candidate_sessions,
			 CASE WHEN COUNT(auth.event_id) = 1 THEN 'correlated-review'
						ELSE 'unknown-correlation' END AS finding
FROM action_events AS action
LEFT JOIN logon_events AS auth
	ON auth.host = action.host
 AND auth.boot_id = action.boot_id
 AND auth.logon_id = action.logon_id
 AND auth.account_sid = action.account_sid
 AND action.event_time BETWEEN auth.event_time AND auth.event_time + 60
GROUP BY action.event_id, action.result;
```

**Interpretation:** zero or multiple candidates stay unknown; one candidate supports a bounded relationship, not causation or maliciousness. Keep denied versus allowed action outcomes separate, then compare the matched source/destination/account/protocol/operation against an approved baseline. Authentication alone supplies neither protocol nor action success.

**Limits / false positives:** legitimate administration can produce the same relationship. The 60-second window is a triage choice, not session lifetime; long-lived sessions, missing logs, clock skew, or unavailable boot identity produce unknowns. Validate audit coverage and normalization before use; this query has not been executed and does not replace session-end tracking.

## Defense

Segment management paths, require approved administrative workstations, use unique managed local passwords, constrain WinRM endpoints to necessary operations, and minimize delegation. Keep SMB/RDP/WinRM exposed only where justified and patched. Restrict NTLM through staged auditing and compatibility review; disabling it indiscriminately can break legacy dependencies. SMB signing defaults differ across Windows releases and editions, so verify effective policy on both endpoints rather than assuming a product-wide default.

Detect unusual administrative relationships and protect the telemetry pipeline. Evaluate both permitted routine administration and unapproved combinations. During response, a denied action and a successful unexpected action deserve different urgency, but a denial may still reveal an attempted misuse of a valid identity.

## Labs

### Environment and Complete Files

Python **3.12**, stdlib only, offline ordinary-user directory. This is a defensive log-correlation challenge, not lateral movement. The integer times are synthetic seconds on one timeline; `auth` and `action` are normalized fixture records, not verbatim Windows event schemas. No sockets, credentials, or remote hosts are used.

### File: test_example.py

```python
import unittest


AUTH = [
	{"host": "server-a", "logon": "42", "account": "ops",
	 "source": "admin-ws", "protocol": "WinRM", "time": 10},
	{"host": "server-b", "logon": "42", "account": "reader",
	 "source": "user-ws", "protocol": "SMB", "time": 12},
]
ACTIONS = [
	{"id": "routine", "host": "server-a", "logon": "42", "account": "ops",
	 "time": 20, "operation": "inventory", "result": "allowed"},
	{"id": "denial", "host": "server-b", "logon": "42", "account": "reader",
	 "time": 25, "operation": "config-change", "result": "denied"},
	{"id": "unexpected", "host": "server-b", "logon": "42", "account": "reader",
	 "time": 30, "operation": "config-change", "result": "allowed"},
]
APPROVED = {("admin-ws", "server-a", "ops", "WinRM", "inventory")}


def correlate(auth, action):
	matches = [record for record in auth
			   if all(record[field] == action[field]
					  for field in ("host", "logon", "account"))
			   and 0 <= action["time"] - record["time"] <= 60]
	return matches[0] if len(matches) == 1 else None


def classify(auth, action):
	session = correlate(auth, action)
	if session is None:
		return "unknown-correlation"
	if action["result"] == "denied":
		return "denied-action"
	if action["result"] != "allowed":
		return "unknown-outcome"
	relationship = (session["source"], session["host"], session["account"],
					session["protocol"], action["operation"])
	return "approved" if relationship in APPROVED else "review"


class CorrelationTests(unittest.TestCase):
	def test_baseline_id_only_join_crosses_hosts(self):
		wrong = next(record for record in AUTH
					 if record["logon"] == ACTIONS[1]["logon"])
		self.assertEqual(wrong["host"], "server-a")
		self.assertEqual(correlate(AUTH, ACTIONS[1])["host"], "server-b")

	def test_approved_denied_and_unexpected(self):
		self.assertEqual([classify(AUTH, action) for action in ACTIONS],
						 ["approved", "denied-action", "review"])

	def test_stale_future_and_account_mismatch(self):
		for changes in ({"time": 100}, {"time": 5}, {"account": "other"}):
			with self.subTest(changes=changes):
				self.assertEqual(classify(AUTH, dict(ACTIONS[0], **changes)),
								 "unknown-correlation")

	def test_ambiguous_evidence_is_not_silently_selected(self):
		self.assertEqual(classify(AUTH + [dict(AUTH[0])], ACTIONS[0]),
						 "unknown-correlation")


if __name__ == "__main__":
	for action in ACTIONS:
		print(action["id"], classify(AUTH, action))
	unittest.main()
```

### Objectives and Baseline

```powershell
py -3.12 -B test_example.py -v
```

Explain how an ID-only join wrongly attributes `server-b` activity to `ops`. Repair the interpretation with the supplied host/account/time-aware join. Identify the approved relationship, the denied operation, and the unexpected allowed operation. State why none independently establishes compromise, then recommend a narrowly scoped authorization review for `server-b`.

### Hints

The protocol is supplied by the synthetic session inventory; 4624 type 3 alone cannot supply it. Do not reuse the first match when multiple candidate sessions remain. A success at authentication and a denial at action authorization are consistent observations.

### Solution and Fixed Retest

The fixed classifications are `routine approved`, `denial denied-action`, and `unexpected review`. The baseline chooses `server-a` for an event on `server-b`; the corrected predicate selects the matching destination and account. A real repair would restrict the unexpected authorization through the owning team, but this exercise changes only correlation logic and makes no live policy claim. The approved inventory action remains recognized, while stale, future, mismatched, or ambiguous joins return unknown.

### Evidence, Troubleshooting, and Cleanup

Expected: three classifications and **4 passing tests**. Retain matched record IDs, host/account/time evidence, the approved tuple, and unknown cases. The 60-second window is an exercise choice, not a Windows session lifetime. A production pipeline needs session-end/boot tracking, deduplication, gateway context, and delayed-log handling. Missing channels cannot be repaired by expanding a time window indefinitely.

Tests were not executed during authoring. Remove the exercise file/directory after retaining synthetic evidence. No connection or session was opened, so there is no remote cleanup or credential rotation.

- [ ] Local Windows Lateral Movement exercise: Analyze the supplied offline authentication/action timeline and correct the host-correlation defect.
- [ ] Boundary check: Preserve the approved administration relationship while separating denied and unexpected allowed actions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X5 Offensive|X5 Offensive]]

## References

- [WinRM security](https://learn.microsoft.com/en-us/windows/win32/winrm/security-for-winrm)
- [Security event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [SMB signing overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
- [Remote Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [Just Enough Administration overview](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)
