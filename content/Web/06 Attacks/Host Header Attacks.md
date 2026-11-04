---
title: "Host Header Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Host Header Attacks

> [!abstract] TL;DR
> Host-header attacks arise when client-selected authority or forwarded-host data is trusted for routing, absolute URLs, or security decisions without a configured canonical origin.

> [!info] Agent scope
> Host trust; absolute URL generation; routing; password-reset links; proxy headers; explicit origin configuration.

## Learn

```text
Teach Host-header trust failures at expert depth. Assume virtual hosting, HTTP
authority, TLS termination, proxies, routing, and absolute URLs. Trace HTTP/1.1
Host, HTTP/2 :authority, absolute-form targets, and forwarded host/proto metadata
through each hop. Separate request routing from canonical external URL generation
and tenant selection. Explain reset-link integrity, cache authority, explicit
origin configuration, trusted proxy boundaries, and duplicate-field rejection
conceptually without ambiguity payloads. Review a secure fake-mail generator
and host allowlist with synthetic inputs. Include framework/version caveats,
primary sources, and questions/answers. No real mail, reset credentials, theft,
bypasses, scanning, or chains. Teach, do not edit files or invent test results.
```

## Cheatsheet

> [!important] Defensive scope
> The lab creates a fake message in memory using a noncredential training reference. It sends no email or HTTP requests and includes no authority-confusion payloads.

### Authority Is Not Automatically Trust

Clients select an HTTP authority to route a request. TLS authenticates the server to the client; it does not make every application-visible Host value trustworthy. A flaw requires that untrusted authority influence a meaningful decision, such as a trusted absolute link, tenant routing, cache namespace, or downstream request. Diagnostic reflection alone does not demonstrate those effects.

| Input/source | Appropriate use | Required boundary |
|---|---|---|
| Host / `:authority` | Route among configured public authorities | Strict framework/server validation |
| Forwarded host/proto | Reconstruct external request context | Only from known trusted proxy hops, with client values replaced |
| Deployment origin | Generate sensitive absolute URLs | Validated configuration, independent of request headers |
| Tenant domain mapping | Select a verified tenant domain | Verified ownership and server-side mapping |
| Relative application path | Construct within configured origin | Fixed route or trusted routing API, not arbitrary URL joining |

Validate authority at the edge and application. Reject duplicate/inconsistent authority information using a maintained server parser; do not normalize it differently at different layers. HTTP/2 `:authority`, HTTP/1.1 Host, and absolute-form request targets must be reconciled according to the protocol and server configuration. Avoid permissive default virtual hosts that silently route unknown authorities to a privileged app.

### Canonical URL Generation

For password-reset or invitation messages, use a configured HTTPS origin and a fixed route. Generate, store, expire, and consume real tokens through a reviewed identity library; this lab deliberately uses no token. URL-encode query values, but do not assume URL encoding validates a host or authorizes a redirect.

Secure design fragment:

```python
from urllib.parse import urlencode
PUBLIC_ORIGIN = "https://accounts.example"
message_url = PUBLIC_ORIGIN + "/review?" + urlencode({"reference": "training-only"})
```

For multiple verified custom domains, choose an origin from an authenticated tenant's server-owned mapping, not directly from the incoming host. Relative URL generation can avoid unnecessary origin reconstruction, but emails require an absolute origin and still need explicit configuration.

### Proxy, Version, and Evidence Notes

Django's `ALLOWED_HOSTS` applies through its host-validation APIs; reading raw headers directly can skip that abstraction. `USE_X_FORWARDED_HOST` is a separate trust decision. Express `trust proxy` must match actual network topology and header replacement behavior. A fixed number of trusted hops can be unsafe when routes have different lengths. Review exact framework versions and deployment middleware order.

Log rejected authority categories, selected virtual host, proxy identity, and generated-link origin without tokens or recipient data. Inspect the final link in a fake-mail sink, not just an intermediate variable. A correct Host allowlist does not establish that forwarded headers or URL helpers use the same policy.

## Defense

Configure explicit public origins, allowlist authorities, reject unknown default routes, and strip/replace forwarding metadata at trusted ingress. Keep link generation independent of request authority. Align routing, cache keys, and tenant selection, and test alternate entry paths through the same trust boundary.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, in-memory outbox, no mail server/network/packages. Review a proposal that derives account-message links from request headers. The secure replacement validates the routed host and always generates links from deployment configuration. The route is a nonfunctional training review page, not a reset endpoint.

### File: test_example.py

```python
from urllib.parse import urlencode, urlsplit, parse_qs
import unittest


PUBLIC_ORIGIN = "https://accounts.example"
ALLOWED_AUTHORITIES = {"accounts.example"}


def queue_training_message(host, forwarded_host, reference, outbox):
	if host not in ALLOWED_AUTHORITIES:
		raise PermissionError("unknown authority")
	if type(reference) is not str or not 1 <= len(reference) <= 80:
		raise ValueError("reference")
	link = PUBLIC_ORIGIN + "/review?" + urlencode({"reference": reference})
	message = {"to": "student@example.invalid", "link": link,
			   "subject": "Synthetic account workflow review"}
	outbox.append(message)
	return link


class AuthorityTests(unittest.TestCase):
	def test_canonical_message(self):
		outbox = []
		link = queue_training_message("accounts.example", None, "training only", outbox)
		parsed = urlsplit(link)
		self.assertEqual((parsed.scheme, parsed.netloc), ("https", "accounts.example"))
		self.assertEqual(parse_qs(parsed.query), {"reference": ["training only"]})
		self.assertEqual(outbox[0]["link"], link)

	def test_forwarding_metadata_does_not_select_origin(self):
		links = [queue_training_message("accounts.example", forwarded, "training", [])
				 for forwarded in [None, "other.example", "internal.example"]]
		self.assertEqual(len(set(links)), 1)

	def test_reject_before_message_creation(self):
		outbox = []
		with self.assertRaises(PermissionError):
			queue_training_message("other.example", "accounts.example", "training", outbox)
		self.assertEqual(outbox, [])


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: `forwarded_host` is deliberately not consulted for link construction. Would validating it instead of using a configured origin reduce complexity for this product?

Solution: routing and URL generation use separate trusted contracts. Expected: three tests pass, approved requests produce the same configured origin regardless of synthetic forwarding metadata, and unknown authority produces no message. The fixture assumes already parsed single-string authority input; duplicate headers, proxy topology, and framework host parsing require separate integration review.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the named file; no mail credentials or DNS are needed. The `.invalid` recipient is intentionally non-deliverable. Remove the disposable exercise directory afterward. Real reset-token lifecycle and email delivery are out of scope, not omitted setup requirements.

- [ ] Local Host Header Attacks exercise: Review authority and canonical-origin boundaries.
- [ ] Boundary check: Run fake-message origin and no-output-on-denial tests.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [RFC 9110: Host and authority](https://www.rfc-editor.org/rfc/rfc9110#section-7.2)
- [RFC 7239: Forwarded](https://www.rfc-editor.org/rfc/rfc7239)
- [Django ALLOWED_HOSTS](https://docs.djangoproject.com/en/5.2/ref/settings/#allowed-hosts)
- [Express behind proxies](https://expressjs.com/en/guide/behind-proxies.html)
