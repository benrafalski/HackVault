---
title: "TCP/IP Security"
aliases: []
tags: [web, w0, security]
domain: web
phase: "W0"
type: security
status: draft
pair: "[[TCP and IP]]"
updated: 2026-11-03
---
# TCP/IP Security

> [!abstract] TL;DR
> Reachability is a prerequisite, not authorization. Inventory bind addresses, routes, address families, protocol, and owning process independently. Keep local-only services on explicit loopback addresses and apply application authentication even behind a firewall.

## Attack Surface

A listening socket, a route to it, and an allowing filter create a reachable service. NAT, container publishing, VPN routes, IPv6, and reverse proxies can change that path without changing application code. A TCP handshake establishes transport state, not the identity or trustworthiness of a user. UDP has no handshake at all.

## Learn

```text
Teach me TCP/IP defensive engineering, assuming socket programming and basic
IPv4/IPv6 addressing. Explain longest-prefix routing, wildcard versus explicit
binds, dual-stack listeners, TCP state and half-close, UDP datagrams, ephemeral
ports, NAT/conntrack, and application authentication. Trace SYN through accept
and application read; distinguish backlog pressure, refusal, silent filtering,
DNS failure, TLS failure, and application timeout. Show narrow listener and
firewall configurations, packet-capture interpretation and privacy constraints.
Use only synthetic policy fixtures or bounded benign loopback exchanges.
Give negative policy tests and prove allowed traffic remains allowed; do not
scan, exploit, flood, or target another system. Distinguish Linux and Windows
diagnostics and OS-dependent defaults. Cite RFC 9293 and platform documentation.
Teach here, not by editing notes. End with worked diagnostic questions; never
claim that an offline model proves an installed firewall works.
```

## Cheatsheet

### Address, Route, and Listener Decisions

| Observation | Meaning | Required decision |
|---|---|---|
| `127.0.0.1:8080` | IPv4 loopback listener | Only local namespace clients; a local proxy can still publish it |
| `[::1]:8080` | IPv6 loopback listener | Separate family; IPv4 success says nothing about this socket |
| `0.0.0.0:8080` | All local IPv4 interfaces | Includes interfaces added later; avoid for local-only labs |
| `[::]:8080` | IPv6 wildcard | IPv4-mapped acceptance depends on `IPV6_V6ONLY` and platform |
| RFC 1918 or ULA address | Private address space | Not a security boundary; VPNs and routes may reach it |
| `ESTABLISHED` | Transport considers connection open | Not evidence of authenticated application activity |
| `TIME_WAIT` | Recently closed connection retained | Usually normal; do not disable protections to hide it |

IP routing chooses the most specific matching prefix, then route attributes such as metrics. A default route does not override a more specific VPN route. An address inside a container's loopback is not the host loopback. A published host port creates another boundary. TCP and UDP port 53 are different sockets; a policy for one does not authorize the other.

TCP sequence numbers describe a byte stream. One `recv()` is not one request; enforce framing, maximum message size, and read deadlines. `recv()` returning empty bytes means orderly end-of-stream, not an empty application message. A peer can half-close its sending side while still receiving. UDP preserves message boundaries but may lose, reorder, or duplicate datagrams; an undersized receive buffer can truncate a datagram. Authenticate messages independently of source addresses where identity matters.

### Read-Only Local Diagnostics

Linux with iproute2 and tcpdump, on an authorized lab host:

```sh
ss -lntup
ip -brief address
ip route show
ip -6 route show
tcpdump -i lo -nn -s 96 -c 20 'tcp port 8080'
```

Windows PowerShell, without changing filters or routes:

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix
```

Capture requires suitable privileges and a supported loopback capture interface. A snap length of 96 reduces, but does not eliminate, payload collection. Capture only synthetic traffic; PCAPs can contain cookies and plaintext. Do not collect corporate-interface traffic. NIC offload can make local captures show apparent checksum errors or unusually large segments; compare capture location before diagnosing corruption.

### Diagnostic Evidence

| Symptom | Evidence to collect | Not justified by symptom alone |
|---|---|---|
| Immediate refusal | Local listener inventory, destination, RST | That a firewall definitely rejected it |
| Connect timeout | SYN retries and route/filter counters | That the destination is offline |
| Connect succeeds, read times out | Accepted socket, bytes sent, app log | That TLS or HTTP finished |
| ICMP unreachable | Type/code and sender at authorized capture point | That every protocol to host is blocked |
| UDP receive timeout | Sender/receiver local logs and capture | Whether packet or reply was lost |
| TLS certificate failure | Handshake log after TCP establishment | A routing failure |

TCP keepalive detects some dead peers, on OS-configurable timescales; it is not an application deadline. Enforce a total request budget in addition to per-read timeouts so repeated short reads cannot keep a request alive indefinitely. Rate limits, connection limits, and bounded queues protect different resources; never demonstrate exhaustion to validate them.

## Detection and Defense

Bind explicitly, deny unused paths, review both IP families, and map listeners to expected processes. Stateful filters usually permit replies to established flows; UDP conntrack is a timeout-based approximation, not a handshake. Record denied protocol/destination/port, rule ID, and timestamp without payload. Correlate with application request IDs after a connection reaches the app. A trusted proxy's source IP identifies that proxy, not the end user; accept forwarded identity only from configured proxies and still authorize requests.

## Labs

### Environment and Complete Files

Python 3.12+, standard library only. This offline lab audits a synthetic listener manifest and an explicit subnet policy. It neither creates sockets nor changes a firewall. All addresses use loopback or documentation ranges. Save the following file in a new disposable directory.

### File: test_example.py

```python
import ipaddress
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Listener:
	address: str
	port: int
	protocol: str


def local_only(listener):
	address = ipaddress.ip_address(listener.address)
	if address.version == 6 and address.ipv4_mapped is not None:
		address = address.ipv4_mapped
	return (address.is_loopback and listener.protocol in {"tcp", "udp"}
			and 1 <= listener.port <= 65535)


def permit(source, destination_port, protocol):
	address = ipaddress.ip_address(source)
	subnet = ipaddress.ip_network("192.0.2.0/28")
	return (address.version == subnet.version and address in subnet
			and destination_port == 8443 and protocol == "tcp")


class PolicyTests(unittest.TestCase):
	def test_listener_baseline_and_fix(self):
		baseline = Listener("0.0.0.0", 8080, "tcp")
		fixed = Listener("127.0.0.1", 8080, "tcp")
		self.assertFalse(local_only(baseline))
		self.assertTrue(local_only(fixed))

	def test_families_and_protocols(self):
		self.assertTrue(local_only(Listener("::1", 5353, "udp")))
		self.assertTrue(local_only(Listener("::ffff:127.0.0.1", 8080, "tcp")))
		self.assertFalse(local_only(Listener("::", 8080, "tcp")))
		self.assertFalse(local_only(Listener("127.0.0.1", 0, "tcp")))

	def test_narrow_ingress(self):
		self.assertTrue(permit("192.0.2.3", 8443, "tcp"))
		self.assertFalse(permit("192.0.2.16", 8443, "tcp"))
		self.assertFalse(permit("192.0.2.3", 8443, "udp"))
		self.assertFalse(permit("192.0.2.3", 8080, "tcp"))
		self.assertFalse(permit("2001:db8::3", 8443, "tcp"))


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`. Predict which manifest entry fails before reading the solution.
2. Change only the fixed listener to `::`; rerun and observe the assertion failure, then restore `127.0.0.1`.
3. Add a test for `192.0.2.15` versus `192.0.2.16`; explain the `/28` boundary. The policy is membership-based and does not model subnet broadcast behavior.
4. On a disposable host, optionally run the read-only inventory commands and compare expected listeners with actual bind addresses. Do not start a wildcard listener or probe another host.

### Hints

`is_private` is not a substitute for `is_loopback`. Check protocol and port as well as subnet. IPv4-mapped IPv6 requires an explicit interpretation.

### Solution and Fixed Retest

The baseline wildcard fails and both explicit loopbacks pass. `192.0.2.3:8443/tcp` passes; changing family, port, protocol, or leaving the first 16-address block fails. The wildcard mutation causes `test_listener_baseline_and_fix` to fail; reverting it restores the expected three passing tests. This demonstrates manifest validation, not packet enforcement. Deployment acceptance also needs listener inventory, firewall review, and authorized observation at the actual boundary.

### Verification, Troubleshooting, and Cleanup

Expected, not author-executed: three unittest tests pass; `python -m pytest -q test_example.py` is an alternative if pytest is already installed. No network or admin privileges are required. Invalid address strings raise `ValueError` rather than silently permitting access. Remove the disposable directory and `__pycache__`; no services, routes, or filters were changed.

- [ ] Record local listener and route evidence without unrelated traffic.
- [ ] Explain wildcard, dual-stack, and proxy boundary differences.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W0 Foundations|W0 Foundations]]
- [[TCP and IP]]
- [[TLS and PKI Security]]

## References

- [TCP specification, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)
- [UDP, RFC 768](https://www.rfc-editor.org/rfc/rfc768)
- [Python socket documentation](https://docs.python.org/3.12/library/socket.html)
- [Linux IP socket interface](https://man7.org/linux/man-pages/man7/ip.7.html)
