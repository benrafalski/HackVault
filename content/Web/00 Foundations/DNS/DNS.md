---
title: "DNS"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: tech
status: draft
pair: "[[DNS Security]]"
updated: 2026-11-03
---
# DNS

> [!abstract] TL;DR
> DNS returns typed RRsets, not a single permanent address. Separate authoritative data, recursive validation/cache behavior, OS lookup policy, and application caches when explaining an answer.

## Prerequisites

Understand UDP/TCP and binary integers; Python 3.12 is sufficient for the offline lab. [[Web Lab Setup]] describes isolation. `dig` examples require BIND utilities and are optional observations against an approved resolver.

## Learn

```text
Teach me DNS from wire format to application lookup, assuming TCP/IP basics.
Explain stub versus recursive versus authoritative roles, iterative referrals,
zone cuts, glue and bailiwick, RRsets, CNAME chains, A/AAAA/NS/SOA/MX/TXT/SRV/CAA
and HTTPS records. Work through TTL, negative caching, NXDOMAIN versus NODATA,
SERVFAIL, EDNS, truncation and TCP retry, and DNS name compression.
Distinguish DNSSEC validation states and chain of trust from DoT/DoH transport
privacy, including local stub trust and split DNS. Provide an offline wire
parser exercise and deterministic cache tests, explicitly not a full resolver.
Include exact dig diagnostics, edge cases, version limitations and primary
RFC references. Teach in this conversation, not through file edits; give
worked answers and do not invent network measurements or test execution.
```

## Cheatsheet

### Resolution and Ownership

`application -> OS/stub -> recursive cache -> root referral -> TLD referral -> authoritative zone` is a possible miss path, not a mandatory sequence for every lookup. Hosts files, search suffixes, enterprise split DNS, browser DoH, and caches can short-circuit or change it. Thirteen named root server identities are distributed across many anycast instances. An authoritative server answers for zones it hosts; a recursive resolver follows delegations on a client's behalf. `AA` means authoritative answer, not cryptographic authentication. `RD` requests recursion; `RA` advertises availability; `AD` asserts validation by a resolver, whose channel you must trust.

At a zone cut, parent NS records refer to child authorities. Glue supplies address records needed to reach in-bailiwick nameservers without circular resolution. Resolvers must not treat every additional-section record as trusted cache data. A zone is an administrative boundary, not necessarily every name below a domain: child zones can be delegated separately.

| Record | Semantics and edge cases |
|---|---|
| A / AAAA | IPv4 / IPv6 addresses; multiple records form an RRset, not ordered failover |
| CNAME | Alias to another name; generally cannot coexist with other data at owner, apart from DNSSEC metadata; not an HTTP redirect |
| NS / SOA | Delegation/authority; SOA serial and refresh/retry/expire coordinate secondary maintenance |
| MX | Mail destination plus preference; lower preference first; target should not be an alias |
| TXT | One or more length-prefixed strings; application interprets them, DNS does not |
| SRV | Priority, weight, port, target for a named service; not universally used by browsers |
| CAA | CA issuance policy, not a runtime browser certificate allowlist |
| HTTPS / SVCB | Endpoint/service parameters such as ALPN; client support and fallback matter |

Names are case-insensitive ASCII labels on the DNS wire; internationalized hostnames commonly use IDNA A-labels. A label is at most 63 octets and an uncompressed full name at most 255 octets including length bytes/root. Presentation's final dot denotes the root. Search suffixes can change the lookup of a relative name.

### Transport, Caching, and Validation

The 12-byte header holds ID, flags, and four section counts. Questions contain name/type/class; resource records contain name/type/class/TTL/RDLENGTH/RDATA. Compression pointers use the high two bits `11` and a 14-bit offset; parsers need bounds and loop detection. TCP adds a two-byte message length prefix outside the DNS message. UDP has no such prefix. EDNS extends capabilities through an OPT pseudo-record; a larger advertised UDP size does not guarantee fragmentation will work. `TC=1` normally triggers TCP retry; TCP/53 is not only for transfers.

| Result | Cache interpretation | Diagnosis |
|---|---|---|
| NOERROR + requested RRset | Cache RRset until remaining TTL expires | Check owner/type and CNAME chain |
| NXDOMAIN | Name does not exist, with appropriate negative proof | Check spelling, suffix, delegation |
| NOERROR + no requested RRset | NODATA: name may exist with another type | Inspect SOA/authority; distinguish referral |
| SERVFAIL | Resolver could not complete resolution/validation | Inspect upstream availability, DNSSEC, clock; not absence |
| REFUSED | Server declines operation/policy | Check recursion ACL or query role |

TTL is a maximum cache lifetime, not a push notification. Decrease it before a planned migration by at least the old TTL. Negative TTL derives from the lesser of the SOA TTL and SOA MINIMUM under RFC 2308. Resolver serve-stale policies can return expired cached data during outages; label this separately from ordinary TTL behavior. Applications may retain addresses or connections beyond a resolver refresh.

DNSSEC uses DNSKEY, DS, and RRSIG plus authenticated denial (NSEC/NSEC3). Trust proceeds from a configured trust anchor through DS/DNSKEY links. `secure` is validated signed data; `insecure` is a legitimately unsigned branch; `bogus` means validation failed; `indeterminate` means insufficient basis. DNSSEC does not hide queries or authenticate the HTTP server. DoT (usually TCP/853) and DoH (HTTPS, usually 443) protect the client-resolver hop and authenticate the resolver endpoint, not all authoritative data. Resolver choice still affects privacy and split-horizon availability.

### Worked Diagnostics

Read-only examples, requiring network permission and an approved resolver:

```sh
dig example.com. A +noall +answer +comments
dig example.com. AAAA +tcp
dig example.com. A +dnssec
dig example.com. SOA
```

`+dnssec` requests DNSSEC-related data; it does not turn `dig` into a validating resolver. Record resolver address, timestamp, flags, RCODE and TTL; comparing answers without these is ambiguous. Windows: `Resolve-DnsName example.com -Type A -DnsOnly`; OS tool output is not necessarily the browser's lookup path.

## Gotchas

A cached NXDOMAIN can outlive a newly created record. TLS uses the original hostname even after a CNAME resolution. DNS TTL expiry does not close an existing TCP connection. Do not equate resolver `AD` over an untrusted plain channel with locally verified signatures.

## Labs

### Environment and Complete Files

Python 3.12+, no packages or network. The fixture is a real DNS wire response with one compressed owner name; the parser deliberately supports only this exact single-question/single-A layout. The cache is a deterministic teaching model, not an installed recursive resolver.

### File: test_example.py

```python
import ipaddress
import struct
import unittest


QUESTION = b"\x03www\x07example\x04test\x00" + struct.pack("!HH", 1, 1)
PACKET = (struct.pack("!6H", 7, 0x8180, 1, 1, 0, 0) + QUESTION
		  + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
		  + ipaddress.IPv4Address("192.0.2.7").packed)


def parse_fixture(packet):
	if len(packet) < 12 + len(QUESTION) + 16:
		raise ValueError("short response")
	identifier, flags, questions, answers, authority, extra = struct.unpack("!6H", packet[:12])
	if (identifier, flags, questions, answers, authority, extra) != (7, 0x8180, 1, 1, 0, 0):
		raise ValueError("unsupported header")
	if packet[12:12 + len(QUESTION)] != QUESTION:
		raise ValueError("unexpected question")
	offset = 12 + len(QUESTION)
	pointer, kind, klass, ttl, length = struct.unpack("!HHHIH", packet[offset:offset + 12])
	if (pointer, kind, klass, length) != (0xc00c, 1, 1, 4) or len(packet) != offset + 16:
		raise ValueError("unsupported answer")
	return str(ipaddress.IPv4Address(packet[-4:])), ttl


class Cache:
	def __init__(self):
		self.records = {}

	def put(self, name, kind, value, ttl, now):
		if ttl < 0:
			raise ValueError("negative TTL")
		self.records[(name.lower(), kind)] = (value, now + ttl)

	def get(self, name, kind, now):
		value, expires = self.records.get((name.lower(), kind), (None, now))
		return value if now < expires else None


class DNSTests(unittest.TestCase):
	def test_wire(self):
		self.assertEqual(parse_fixture(PACKET), ("192.0.2.7", 30))
		with self.assertRaises(ValueError):
			parse_fixture(PACKET[:-1])

	def test_expiry_and_type(self):
		cache = Cache()
		address, ttl = parse_fixture(PACKET)
		cache.put("www.example.test.", "A", address, ttl, 100)
		self.assertEqual(cache.get("WWW.example.test.", "A", 129), address)
		self.assertIsNone(cache.get("www.example.test.", "A", 130))
		self.assertIsNone(cache.get("www.example.test.", "AAAA", 101))

	def test_negative_cache_model(self):
		cache = Cache()
		cache.put("missing.example.test.", "A", "NODATA", min(120, 45), 0)
		self.assertEqual(cache.get("missing.example.test.", "A", 44), "NODATA")
		self.assertIsNone(cache.get("missing.example.test.", "A", 45))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`; map the packet header, question, pointer, TTL and address to byte offsets.
2. Explain why the pointer `c00c` resolves to the question name at byte 12 and why it does not encode the address.
3. Change the cache expiry comparison to `<=`; rerun to observe the boundary regression, then restore `<`.
4. Trace a planned authority change at model time 110: the cached address still survives to 129; at 130 the caller must refresh. No real DNS service is contacted.

### Hints

`!` means network byte order. The TTL is seconds, not milliseconds. NODATA is type-specific in this simple model; full NXDOMAIN caching rules are broader and intentionally not implemented.

### Solution and Expected Results

Header is 12 bytes; question is 22 bytes; answer begins at 34 and is 16 bytes. The pointer occupies two bytes, the fixed RR fields ten, the IPv4 data four. Expected address is `192.0.2.7`, TTL 30. Positive entry expires exactly at 130; negative entry at 45. Three tests should pass. The mutation incorrectly preserves an expired entry and fails two tests.

### Verification, Troubleshooting, and Cleanup

Unexecuted by the author. Optional runner: `python -m pytest -q test_example.py` with pytest already installed. No DNS server, host-file changes, or timing sleeps are needed. A parser `ValueError` means the fixture differs from its deliberately narrow supported format, not a general DNS failure. Delete the lab directory and bytecode caches.

- [ ] Decode the synthetic response and explain cache expiry.
- [ ] Distinguish NXDOMAIN, NODATA, SERVFAIL, and authenticated denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[DNS Security]]

## References

- [DNS concepts, RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)
- [DNS wire format, RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
- [Negative caching, RFC 2308](https://www.rfc-editor.org/rfc/rfc2308)
- [DNSSEC validation, RFC 4035](https://www.rfc-editor.org/rfc/rfc4035)
- [DoH, RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)
