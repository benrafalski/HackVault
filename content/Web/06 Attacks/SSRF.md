---
title: "SSRF"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# SSRF

> [!abstract] TL;DR
> SSRF lets untrusted input influence a server-originated request, borrowing the server's network position or service identity.

> [!info] Agent scope
> URL-fetch trust boundaries; parser differences; redirects; DNS resolution; lab-only internal services; egress policy.

## Learn

```text
Teach SSRF as a server-side network authority boundary, assuming URLs, DNS,
HTTP clients, redirects, TLS, proxies, and service identities. Trace input through
URL parsing, resolution, destination policy, connection, redirects, and response
consumption. Explain parser differences and DNS check/connect races conceptually
without alternate-address tricks or bypass payloads. Compare fixed resource IDs,
allowlisted services, egress gateways, redirect denial/revalidation, credential
stripping, TLS hostname verification, and response/time limits. Distinguish
in-band data from blind I/O evidence without probing any service. Review an
offline fetch plan with synthetic DNS evidence; state what a mock cannot prove.
Cite primary Python/IETF documentation and give difficult review questions.
No requests to internal services, metadata, or real targets; no theft, scanning,
RCE, bypasses, chains, file authoring, or fabricated test results.
```

## Cheatsheet

> [!important] Defensive scope
> No sockets, DNS lookups, internal services, or metadata endpoints are used. The exercise builds an offline fetch plan for a reserved example origin and documentation-only IP addresses.

### Authority and Prerequisites

SSRF requires a path from untrusted input to a server-originated request whose destination, method, headers, or body exceeds intended authority. The server may have network reach or ambient credentials unavailable to the user. Returning fetched data is only one possible effect; blind cases have no returned response and require independent I/O evidence. A URL field alone does not establish arbitrary reachability.

| Stage | Required invariant | Limitation |
|---|---|---|
| Selection | Caller chooses reviewed resource IDs where possible | A catalog still needs change review |
| Parsing | One documented parser and narrow scheme/authority/path contract | `urlsplit` parses; it is not a complete security validator |
| DNS | Every candidate address satisfies destination policy | A separate later resolution can change the destination |
| Connection | Validated destination is bound to the actual connection | Preserve correct TLS SNI and certificate hostname checks |
| Redirect | Deny, or apply the full policy at every hop | Initial URL approval does not approve later destinations |
| Credentials | No inherited cookies, auth headers, or privileged client identity | A shared client/session can silently add state |
| Response | Bound bytes, decompression, duration, and content use | A timeout alone does not bound memory |

Prefer a dedicated egress service with a deployment-owned destination catalog, restricted method set, no ambient proxy credentials, and network policy enforcing the same boundaries. Do not forward arbitrary caller headers. Explicitly decide whether environment proxy settings are trusted; Python clients and frameworks differ. Redirect policies vary by library/version, so disable automatic following until reviewed.

### DNS, Parsing, and Evidence

Classify IPv4 and IPv6 with a maintained address library and policy, not textual prefixes. Private, loopback, link-local, multicast, unspecified, and reserved ranges have different semantics. Python `ipaddress` classification has changed across releases; pin the runtime and regression-test the ranges your policy depends on. A positive public classification is not sufficient business authorization.

The lab deliberately uses `192.0.2.10`, an RFC 5737 documentation address, as an offline approved fixture. It is not an Internet destination recommendation. Production code must use approved real service addresses and a connector that enforces destination binding; the plan below is not such a connector.

Record requested resource ID, normalized origin, resolved address classification, actual connected peer, redirect decision, method, and bounded byte count. Redact URL queries and headers. A resolution denial proves the policy decision, not that every transport path is covered. Egress logs and application logs must agree before making a reachability claim.

## Defense

Minimize outbound capabilities, use fixed resources, isolate fetch workers from sensitive networks, and enforce egress independently of application parsing. Keep TLS verification enabled. Treat fetched content as untrusted at its next parser. Review URL, redirect, DNS, proxy, and credential behavior as one path; securing one stage alone does not establish containment.

## Labs

### Environment and Objectives

Python 3.12 stdlib only. No packages, network, services, or real DNS. Review a proposal to accept arbitrary fetch URLs. Replace that contract with one named resource and an offline plan. Synthetic resolution results represent approved versus unapproved destinations without connecting to either.

### File: test_example.py

```python
from ipaddress import ip_address
from urllib.parse import urlsplit
import unittest
from unittest.mock import Mock


RESOURCES = {"manual": "https://docs.example/manual.txt"}
APPROVED_FIXTURE_ADDRESSES = {ip_address("192.0.2.10")}


def build_plan(resource_id, resolve):
	if resource_id not in RESOURCES:
		raise PermissionError("unknown resource")
	url = RESOURCES[resource_id]
	parsed = urlsplit(url)
	if (parsed.scheme != "https" or parsed.hostname != "docs.example"
			or parsed.port not in (None, 443) or parsed.username is not None
			or parsed.password is not None or parsed.query or parsed.fragment):
		raise PermissionError("catalog configuration")
	addresses = tuple(ip_address(value) for value in resolve(parsed.hostname))
	if not addresses or any(value not in APPROVED_FIXTURE_ADDRESSES for value in addresses):
		raise PermissionError("destination policy")
	return {"url": url, "addresses": addresses, "tls_name": parsed.hostname,
			"method": "GET", "headers": {}, "follow_redirects": False,
			"max_bytes": 4096, "timeout_seconds": 2}


def accept_status(status):
	if status != 200:
		raise PermissionError("non-success response; redirects are not followed")


class FetchPlanTests(unittest.TestCase):
	def test_reviewed_destination(self):
		resolver = Mock(return_value=["192.0.2.10"])
		plan = build_plan("manual", resolver)
		resolver.assert_called_once_with("docs.example")
		self.assertEqual(plan["tls_name"], "docs.example")
		self.assertFalse(plan["follow_redirects"])
		self.assertEqual(plan["headers"], {})
		accept_status(200)

	def test_all_answers_must_be_approved(self):
		for answers in [[], ["192.0.2.11"], ["192.0.2.10", "192.0.2.11"]]:
			with self.subTest(answers=answers), self.assertRaises(PermissionError):
				build_plan("manual", Mock(return_value=answers))

	def test_unknown_id_never_resolves(self):
		resolver = Mock()
		with self.assertRaises(PermissionError):
			build_plan("unlisted", resolver)
		resolver.assert_not_called()

	def test_redirect_denial(self):
		with self.assertRaises(PermissionError):
			accept_status(302)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other systems. Hint: approving one address out of several is not the same as approving every selectable peer. What component must consume the plan without resolving again?

Solution: fixed resource selection, all-answer validation, no caller headers, and redirect denial reduce the intended authority. Expected: four tests pass; unknown IDs never invoke the fake resolver, mixed results fail, and a redirect is rejected. No HTTP client consumes the plan. DNS rebinding resistance, TLS enforcement, actual egress, and internal-service isolation are not demonstrated by this offline fixture.

### Verification, Troubleshooting, and Cleanup

Tests were not executed during authoring. Run beside the file and do not replace the mock with network resolution. No server, proxy, or cloud account is required. Remove the disposable exercise directory afterward. The approved documentation address is deliberately nonproduction, not a connectivity problem to troubleshoot with live requests.

- [ ] Local SSRF exercise: Review the outbound authority and offline fetch plan.
- [ ] Boundary check: Run the no-network destination and redirect regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Python URL parsing security](https://docs.python.org/3.12/library/urllib.parse.html#url-parsing-security)
- [Python ipaddress](https://docs.python.org/3.12/library/ipaddress.html)
- [RFC 5737: documentation address blocks](https://www.rfc-editor.org/rfc/rfc5737)
