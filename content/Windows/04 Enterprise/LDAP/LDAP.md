---
title: "LDAP"
aliases: []
tags: [windows, x4]
domain: windows
phase: "X4"
type: tech
status: draft
pair: "[[LDAP Security]]"
updated: 2026-11-03
---
# LDAP

> [!abstract] TL;DR
> LDAP searches a directory naming context using a base DN, scope, filter and attribute projection. Bind identity, connection protection and directory authorization remain separate; neither a successful bind nor a successful search grants write access.

> [!info] Agent scope
> Directory tree; distinguished names; searches; filters; binds; TLS; signing and channel binding; authorization.

## Prerequisites

- Trees, Unicode/UTF-8, TCP/TLS and authentication/authorization. AD-specific extensions are identified separately from LDAPv3.
- Required exercise: Python 3.12 standard library only, no LDAP server, AD, network, credentials, elevation or packages.

## Learn

```text
Teach LDAPv3 and AD LDAP at expert protocol and application-engineering depth.
Assume trees, Unicode, TCP/TLS and authorization. Explain DIT/naming contexts,
RDN/DN syntax, schema/matching rules, BER LDAPMessage/messageID, bind state,
simple versus SASL, StartTLS versus LDAPS, search base/scope/derefAliases/filter,
attribute selection, entries/references/done, controls, limits and paged results.
Separate RFC4515 filter escaping from RFC4514 DN escaping. Explain LDAP signing,
SASL sealing, TLS validation, channel binding and object/attribute ACLs, including
AD Global Catalog and referrals. Give worked literal-name filters, failure-code
diagnosis, exact read-only Windows observations and version/default caveats.
Supply a complete Python 3.12 stdlib offline search/escaping lab with tests,
clearly not an LDAP server, schema engine or access-check implementation. Use
RFC4511/4513/4514/4515, RFC2696 and Microsoft primary sources. No real directory,
credentials, production targets, offensive procedures or fabricated execution.
Teach here, do not edit files or study status; end with worked hard questions.
```

## Cheatsheet

### Directory and Wire Model

`CN=Iris,OU=People,DC=example,DC=invalid` is a distinguished name composed of RDNs from object toward root. RDNs can be multivalued (`+`); commas/backslashes and leading/trailing spaces require context-specific escaping. Never parse DNs by splitting on commas in a real client. A DN is a locator that can change on rename/move, not an immutable object identity; AD objectGUID is a different concept.

LDAP uses ASN.1 BER, not a textual line protocol. `LDAPMessage` wraps a messageID, a protocol operation and optional controls. Requests can be outstanding concurrently; responses correlate by messageID, and messageID 0 is reserved for unsolicited notifications. Bind changes connection authentication state; connection pools must not accidentally reuse a differently authenticated connection. Empty-name anonymous bind and nonempty-name/empty-password unauthenticated bind are distinct protocol cases and must not be interpreted by an application as successful user authentication.

| Search field | Example | Meaning |
|---|---|---|
| baseObject | `OU=People,DC=example,DC=invalid` | Starting object/naming context; not a filter clause. |
| scope | baseObject / singleLevel / wholeSubtree | Base only / immediate children / base plus descendants. |
| derefAliases | never / searching / finding base / always | Alias treatment; AD referrals are not simply LDAP aliases. |
| filter | `(&(objectClass=user)(cn=Iris))` | Boolean expression plus schema-defined matching; AD `objectClass=user` also includes computer objects, so user-account queries often also constrain category. |
| attributes | `cn`, `displayName`; `1.1` requests no attributes | Projection is not authorization. `*` requests user attributes, not all operational attributes. |
| sizeLimit/timeLimit | Bounded requested limits | Server limits may be stricter. Partial entries followed by an error are not a complete successful result. |
| typesOnly | true/false | Attribute names without values versus normal values. |

SearchResultEntry messages may be interleaved with SearchResultReference messages and terminate with SearchResultDone. Evaluate the final result code, not just whether entries arrived. Referrals cross a server/trust boundary; do not automatically send credentials to arbitrary referred destinations. AD Global Catalog commonly uses 3268 or TLS 3269 and exposes a partial attribute set across the forest; ordinary LDAP uses 389, LDAPS 636. A missing GC attribute may reflect replication/schema scope rather than denial.

Simple paged results control OID `1.2.840.113556.1.4.319` carries page size and an opaque cookie. Repeat the same query/control contract with the server cookie until it is empty; it is not an offset to invent or a stable snapshot guarantee. Critical unsupported controls produce `unavailableCriticalExtension` (12). Server-side sort, ranged multivalue retrieval and paging solve different problems; page count is not total result count.

### Filters, Binds and Protection

RFC4515 escapes filter assertion-value bytes: `*` -> `\2a`, `(` -> `\28`, `)` -> `\29`, backslash -> `\5c`, NUL -> `\00`. Literal `Iris*(Lab)` becomes `(cn=Iris\2a\28Lab\29)`. DN escaping has different rules; filter escaping is not safe for assembling a DN or choosing an attribute name/operator. Allowlist attribute names and use a mature LDAP library's structured builders in real applications. String equality in the fixture does not implement schema case-folding or matching rules.

Simple bind sends a password field without LDAP-layer cryptographic protection; use validated TLS if it is required at all. SASL negotiates a mechanism such as Kerberos and can provide integrity (signing) or confidentiality plus integrity (sealing). StartTLS is an extended operation on 389, OID `1.3.6.1.4.1.1466.20037`: require a successful upgrade and certificate validation before any sensitive bind; never silently continue unprotected. LDAPS starts TLS immediately on 636.

LDAP signing covers non-TLS SASL traffic; TLS already provides integrity. Server "Require signing" rejects unsigned non-TLS SASL and simple binds on unprotected connections, but does not mean simple bind over validated TLS is rejected. Channel binding ties supported SASL authentication to the TLS channel; it is not a generic extra signature on every LDAP operation and does not apply to a simple bind in the same way. Directory DACLs still control object/attribute reads, writes and extended rights after bind.

### Read-only Administration and Errors

On an owned disposable DC only, these local PowerShell queries inspect policy/logs without binding to a directory. No DC is needed for the offline lab; unavailable keys/logs on a workstation are expected. Runtime unverified.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' | Select-Object LDAPServerIntegrity,LdapEnforceChannelBinding
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' | Select-Object LDAPClientIntegrity
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=2886,2887,2888,2889,3039} -MaxEvents 20
```

New Server 2025 AD deployments require signing by default; its enforcement policy can override the signing-level policy. Existing upgrade policies may be preserved. Windows 11 24H2/Server 2025 LDAP clients have newer encryption defaults, but application API options and third-party libraries matter. Do not infer negotiated protection from OS version or missing registry values.

| LDAP result | Interpretation |
|---|---|
| 0 success | Operation succeeded; an empty search is still possible. |
| 3 timeLimitExceeded / 4 sizeLimitExceeded | Results may be partial; never silently call them complete. |
| 8 strongAuthRequired / 13 confidentialityRequired | Authentication/protection requirement, not merely wrong credentials. |
| 10 referral | Another naming context/server; explicit trust decision. |
| 32 noSuchObject | Base DN/object absent or not visible in this context. |
| 34 invalidDNSyntax | DN grammar failure, distinct from filter syntax. |
| 49 invalidCredentials | Bind failure; AD diagnostic subcodes require context and should not be exposed to end users. |
| 50 insufficientAccessRights | Identity authenticated but lacks required directory authority. |

## Gotchas

TLS does not authorize modifications. A search result omitting an attribute can reflect projection, schema/GC availability or authorization. An empty password must be rejected by application logic rather than treated as a successful identity proof after any permissive bind response.

## Labs

### Environment and Complete Files

Create an empty `ldap-tech-offline` directory with this single file. Python 3.12 standard library, embedded seed data, no packages, network, directory, credentials or admin rights. DNs are already-structured tuples of synthetic RDNs; this is deliberately not a DN parser. Matching is exact Python equality, not LDAP schema matching. The filter encoder is exercised on literals; no filter is sent anywhere. Runtime unverified.

### File: test_example.py

```python
import unittest


ROOT = ("dc=example", "dc=invalid")
PEOPLE = ("ou=people",) + ROOT
ENTRIES = (
	{"dn": PEOPLE, "cn": "People", "kind": "container"},
	{"dn": ("cn=iris",) + PEOPLE, "cn": "Iris*(Lab)", "kind": "user"},
	{"dn": ("cn=oak", "ou=team") + PEOPLE, "cn": "Oak", "kind": "user"},
	{"dn": ("cn=outside", "ou=other") + ROOT, "cn": "Outside", "kind": "user"},
)


def filter_value(value):
	return "".join(f"\\{octet:02x}" if octet in (0, 40, 41, 42, 92)
				   or octet >= 128 else chr(octet)
				   for octet in value.encode("utf-8"))


def search(base, scope, name=None, attributes=("cn",), limit=10):
	if scope not in {"base", "one", "sub"}:
		raise ValueError("unsupported scope")
	if not set(attributes).issubset({"cn", "kind"}):
		raise ValueError("projection outside fixture schema")
	if not any(entry["dn"] == base for entry in ENTRIES):
		raise LookupError("noSuchObject")
	matches = []
	for entry in ENTRIES:
		distinguished_name = entry["dn"]
		descendant = distinguished_name[-len(base):] == base
		distance = len(distinguished_name) - len(base)
		selected = ((scope == "base" and distinguished_name == base)
					or (scope == "one" and descendant and distance == 1)
					or (scope == "sub" and descendant and distance >= 0))
		if selected and (name is None or entry["cn"] == name):
			matches.append({attribute: entry[attribute] for attribute in attributes})
	return matches[:limit], "sizeLimitExceeded" if len(matches) > limit else "success"


class ExampleTests(unittest.TestCase):
	def test_literal_filter_encoding(self):
		self.assertEqual(filter_value("Iris*(Lab)"), r"Iris\2a\28Lab\29")
		self.assertEqual(filter_value("\\\x00"), r"\5c\00")
		self.assertEqual(filter_value("\u00e9"), r"\c3\a9")

	def test_scopes(self):
		self.assertEqual(len(search(PEOPLE, "base")[0]), 1)
		self.assertEqual(len(search(PEOPLE, "one")[0]), 1)
		self.assertEqual(len(search(PEOPLE, "sub")[0]), 3)

	def test_literal_match_and_projection(self):
		rows, status = search(PEOPLE, "sub", "Iris*(Lab)", ("cn",))
		self.assertEqual((rows, status), ([{"cn": "Iris*(Lab)"}], "success"))
		self.assertEqual(search(PEOPLE, "sub", "*")[0], [])

	def test_limits_are_not_success(self):
		rows, status = search(PEOPLE, "sub", limit=1)
		self.assertEqual(len(rows), 1)
		self.assertEqual(status, "sizeLimitExceeded")

	def test_base_and_attribute_errors(self):
		with self.assertRaisesRegex(LookupError, "noSuchObject"):
			search(("ou=missing",) + ROOT, "sub")
		with self.assertRaises(ValueError):
			search(PEOPLE, "sub", attributes=("notInSchema",))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Confirm `python --version` is 3.12; run `python -m unittest -v test_example` in the fixture directory. `py -3.12` can replace `python` on Windows.
2. Predict base/one/sub counts and explain why `Outside` is never returned. Identify why one returned row with `sizeLimitExceeded` is not a complete result.
3. Temporarily remove `42` from the encoder's special-octet tuple. The literal-filter test must fail. Restore and rerun.

### Hints

Tuple suffixes are safe only because the fixture already separates RDNs. A star in an assertion value is a literal only after escaping; attribute names and filter operators must be controlled separately.

### Solution and Expected Results

Five tests should pass. Scope counts are 1, 1, 3. Literal `Iris*(Lab)` encodes as `Iris\2a\28Lab\29`; UTF-8 bytes for the Unicode test are escaped independently. The query function never parses the rendered filter, so its successful literal match is not proof of an LDAP library's escaping behavior. Size-limit status must accompany the partial result. The temporary encoder edit is detected by the first test.

### Verification, Troubleshooting, and Cleanup

Acceptance: five passing tests after restoring the encoder and correct scope/partial-result explanations. Import failures usually mean wrong directory or filename. No directory bind or log event is expected. Delete the directory and `__pycache__`; no host policy changed.

### Retained Study Checklist

- [ ] Local LDAP exercise: Query a disposable directory for synthetic users with a narrow search base and limited account. Test filter escaping and a denied attribute modification.
- [ ] Boundary check: Submit a harmless filter-metacharacter name through a safe query builder and verify literal matching; confirm unauthorized modifications fail.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X4 Enterprise|X4 Enterprise]]
- [[LDAP Security]]

## References

- [RFC4511 LDAP protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC4513 authentication and TLS](https://www.rfc-editor.org/rfc/rfc4513)
- [RFC4514 distinguished names](https://www.rfc-editor.org/rfc/rfc4514)
- [RFC4515 search filter strings](https://www.rfc-editor.org/rfc/rfc4515)
- [RFC2696 paged results](https://www.rfc-editor.org/rfc/rfc2696)
- [Microsoft LDAP signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
