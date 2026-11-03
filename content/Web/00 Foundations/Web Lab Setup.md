---
title: "Web Lab Setup"
aliases: []
tags: [web, w0]
domain: web
phase: "W0"
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# Web Lab Setup

> [!abstract] TL;DR
> A reproducible lab has explicit ownership, bind addresses, dependencies, synthetic seeds, trust scope, reset and teardown. A container is packaging, not permission to expose a vulnerable application or execute arbitrary untrusted code.

## Prerequisites

Primary lab: Python 3.12+, standard library and an unused IPv4 loopback port. Optional workflows: current Docker Engine/Desktop, a disposable browser profile, and Burp Suite's built-in browser. Optional HTTPS fixture: OpenSSL 3.x CLI. No production accounts, corporate targets or credentials. Leave corporate VPN and required proxy settings unchanged.

## Learn

```text
Teach me reproducible web-lab administration assuming basic HTTP and sockets.
Cover local process versus container versus VM isolation, IPv4/IPv6 loopback
binding, container port publishing, host routes/firewalls, image digest pinning,
synthetic seeds, resource budgets, browser/proxy profiles and TLS interception
trust. Give complete benign loopback fixture files, reset tests, exact optional
container commands and a staged capture/cleanup workflow. Explain where proxy
CA trust belongs, how to verify every listener and how snapshots differ from
backups. Do not alter corporate VPN/global proxy/trust settings, scan other
hosts, exploit the app or use real secrets. Distinguish Docker/version-specific
networking and unexecuted commands from evidence. Cite official docs; teach here
without editing files. End with a worked preflight and retirement checklist.
```

## Cheatsheet

### Isolation and Ownership

| Environment | Suitable use | Important limit |
|---|---|---|
| Local loopback process | Benign fixtures and protocol learning | Shares host user/files/network privileges |
| Container with loopback publish | Disposable supported training app | Shares kernel; mounts and daemon access can expose host |
| Disposable VM | Broader OS isolation or untrusted components | Shared folders, clipboard, bridged NICs and snapshots still matter |
| Browser profile / proxy project | Separate cookies, CA trust and request history | A profile is not a general OS sandbox |

Use only 127.0.0.1 or ::1 unless a separately approved isolated network is required. `0.0.0.0` and `::` are wildcard binds, not synonyms for local-only. A service bound to a container's loopback may be unreachable through port publishing; the container app can listen on its internal interface while the host publish remains loopback-only. Host firewall, Docker NAT, VM networking, proxy listener and application bind are separate controls.

Docker `-p 3000:3000` usually publishes on all host addresses; use `-p 127.0.0.1:3000:3000`. Docker documents a localhost-publish reachability caveat for Engine versions before 28.0.0 on the same L2 network. Use a current patched engine and verify the actual implementation, including Docker Desktop/WSL networking. Do not change VPN or host-wide UDP/firewall policy to make a lab work.

These commands assume ordinary bridge NAT, not routed gateway mode, Swarm publishing, host networking, or a daemon configured for direct container routing. Those modes can change exposure independently of the displayed host binding; review the existing configuration and use an approved disposable environment rather than changing the shared daemon.

### Preflight Manifest

Record target name/version or immutable digest, owner, start/stop commands, bind family/address/port, browser profile, proxy port, trust-store changes, synthetic data source, storage paths, resource budget and expected reset state. Pin dependency versions for repeated comparisons; mutable image tags are not immutable provenance. Keep ports distinct from existing work. Inspect locally instead of scanning another host:

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
```

```bash
ss -lntp
```

Record only lab-owned listeners. Permission-limited process details do not imply absence. Avoid mounting home directories, source credentials, SSH agents, Docker sockets or production datasets into training containers. Read-only mounts still disclose their content. Apply CPU/memory/PID budgets and drop unnecessary capabilities; a writable app data directory may still be required.

### Browser, Proxy, and TLS Trust

Use a new disposable browser profile or Burp's built-in browser, a temporary proxy project, and a proxy listener explicitly on 127.0.0.1. For the primary fixture, choose proxy port 8790 and app port 8780; use another unused proxy port if necessary. Set only that profile's proxy or use the built-in browser; do not modify OS-wide proxy settings. Restrict capture scope to the local fixture and keep interception off for initial benign observations.

HTTPS interception creates two TLS channels: browser-to-proxy and proxy-to-origin. The browser trusts a lab interception CA; that does not prove the proxy validates the origin certificate. Record both decisions separately. Prefer the built-in browser's isolated trust configuration. If manually installing a CA, use only a disposable profile's certificate store where supported; some browsers use OS stores, so do not import there on the work host. Never install a training CA into the ordinary corporate/system trust store. Retire the CA/profile/project after use and protect proxy history as potentially sensitive.

### Reset and Retirement

A process restart resets only state held in memory. Container recreation resets the writable container layer but not bind mounts, named volumes, browser storage or external services. VM snapshots capture a point in time and can restore vulnerable state and stale credentials; use synthetic accounts and no shared production secrets. A snapshot is not an independent backup. Document which volumes must be discarded and verify seeds after rebuilding.

Teardown order: stop owned app/proxy, verify listener removal, remove only named lab containers/data, clear lab browser storage/profile, remove profile-scoped CA trust, delete synthetic captures/keys as appropriate, and verify ordinary browser/proxy settings are unchanged. Never use broad `docker system prune`, kill-all commands or recursive deletion of a guessed directory as routine cleanup.

## Gotchas

Browser profiles can retain service workers, cookies and HSTS after app reset. Proxy bypass rules often exclude localhost; use the built-in proxy browser and verify history rather than assuming capture. Container images may contact update/telemetry services; control egress in an approved disposable environment if isolation requires it. Lack of an externally reachable port is not a general malware sandbox guarantee.

## Labs

### Environment and Complete Files

Python 3.12+, no packages. The primary fixture serves only a synthetic JSON status record and keeps its seed in memory. Tests start an ephemeral loopback listener, perform bounded benign GETs, stop it and start a fresh instance. Optional manual mode uses port 8780. It is not a vulnerable application or a production server.

### File: test_example.py

```python
import argparse
import http.client
import ipaddress
import json
import ssl
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def manifest_allowed(manifest):
	return (ipaddress.ip_address(manifest["bind"]).is_loopback
			and manifest["data"] == "synthetic" and not manifest["host_mounts"])


class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path != "/status":
			self.send_error(404)
			return
		body = json.dumps(self.server.seed, sort_keys=True).encode("utf-8")
		self.send_response(200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, format, *args):
		pass


@contextmanager
def serve(port=0, cert=None, key=None):
	server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
	server.seed = {"account": "synthetic-reader", "revision": 0}
	if cert:
		try:
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.minimum_version = ssl.TLSVersion.TLSv1_2
			context.load_cert_chain(cert, key)
			server.socket = context.wrap_socket(server.socket, server_side=True)
		except Exception:
			server.server_close()
			raise
	worker = threading.Thread(target=server.serve_forever, daemon=True)
	worker.start()
	try:
		yield server
	finally:
		server.shutdown()
		server.server_close()
		worker.join(timeout=3)


def get_status(port):
	connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
	try:
		connection.request("GET", "/status")
		response = connection.getresponse()
		if response.status != 200:
			raise AssertionError(response.status)
		return json.loads(response.read())
	finally:
		connection.close()


class SetupTests(unittest.TestCase):
	def test_manifest_baseline_and_fix(self):
		baseline = {"bind": "0.0.0.0", "data": "synthetic", "host_mounts": []}
		self.assertFalse(manifest_allowed(baseline))
		self.assertTrue(manifest_allowed({**baseline, "bind": "127.0.0.1"}))
		self.assertFalse(manifest_allowed({**baseline, "bind": "127.0.0.1",
										  "host_mounts": ["home-directory"]}))

	def test_start_stop_reset(self):
		with serve() as first:
			self.assertEqual(first.server_address[0], "127.0.0.1")
			self.assertEqual(get_status(first.server_port)["revision"], 0)
			first.seed["revision"] = 7
			self.assertEqual(get_status(first.server_port)["revision"], 7)
		self.assertEqual(first.socket.fileno(), -1)
		with serve() as second:
			self.assertEqual(get_status(second.server_port),
							 {"account": "synthetic-reader", "revision": 0})


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--serve", action="store_true")
	parser.add_argument("--port", type=int, default=8780)
	parser.add_argument("--cert")
	parser.add_argument("--key")
	arguments, remaining = parser.parse_known_args()
	if arguments.serve:
		if bool(arguments.cert) != bool(arguments.key):
			parser.error("--cert and --key must be supplied together")
		with serve(arguments.port, arguments.cert, arguments.key):
			scheme = "https" if arguments.cert else "http"
			print(f"Open {scheme}://localhost:{arguments.port}/status; Ctrl+C stops.")
			try:
				threading.Event().wait()
			except KeyboardInterrupt:
				pass
	else:
		unittest.main(argv=[__file__, *remaining])
```

### Objectives and Steps

1. Run `python -m unittest -v test_example`; record manifest rejection and reset results.
2. Run `python test_example.py --serve`; visit `http://127.0.0.1:8780/status` in a disposable browser profile. Confirm the seed and loopback listener using the read-only platform command above.
3. Optional proxy observation: in a temporary Burp project create/select a listener on 127.0.0.1:8790, scope only `http://127.0.0.1:8780`, turn interception off, open Burp's built-in browser and request `/status`. Record the single benign request/response from HTTP history. Do not browse real accounts in that browser.
4. Stop with Ctrl+C, verify the owned listener disappears, restart with the same command and confirm revision 0. No external files are needed to reconstruct the seed.

### Optional HTTPS Trust Observation

OpenSSL CLI 3.x is an additional dependency. From this same disposable directory, generate a one-day local certificate/key; do not add it to any global trust store:

```sh
openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout lab-key.pem -out lab-cert.pem
python test_example.py --serve --cert lab-cert.pem --key lab-key.pem
```

These are separate commands, with the HTTP instance stopped first. The server still binds only IPv4 loopback. A direct browser should warn because the certificate is not normally trusted; do not use a permanent browser exception as a production pattern. A curl build with normal TLS support can validate this exact local certificate explicitly without global installation:

```sh
curl --cacert lab-cert.pem https://127.0.0.1:8780/status
```

For optional proxy observation, use only the disposable built-in browser and inspect the issuer it sees versus the origin certificate. Record the proxy's upstream verification configuration separately; seeing its generated certificate proves browser-to-proxy trust, not upstream validation. This optional trust observation is not part of the Python unit tests.

### Optional Packaged Training App

Use a maintained Docker installation and official Juice Shop instructions. The following PowerShell sequence pulls a deliberately selected historical training version, resolves its local immutable image ID, and publishes only IPv4 loopback under ordinary bridge NAT. The official v17.1.1 release exists; registry tag availability and runtime compatibility are unverified here. If unavailable, choose an officially documented tag and record its digest before proceeding, not an unknown replacement image.

```powershell
docker version
docker pull bkimminich/juice-shop:v17.1.1
$Image = docker image inspect bkimminich/juice-shop:v17.1.1 --format '{{.Id}}'
docker image inspect bkimminich/juice-shop:v17.1.1 --format '{{json .RepoDigests}}'
docker run --detach --rm --name hv-w0-shop --publish 127.0.0.1:3000:3000 --cap-drop ALL --security-opt no-new-privileges:true --memory 1g --cpus 1 --pids-limit 256 $Image
docker port hv-w0-shop
docker inspect hv-w0-shop --format '{{json .HostConfig.PortBindings}}'
```

Only continue after pull/inspect succeed and `$Image` is a nonempty expected SHA-256 image ID. No host mounts or real credentials are supplied. Visit only `http://127.0.0.1:3000/`, record the benign landing response, and optionally capture that request in the dedicated proxy browser. Do not perform exploit exercises. Expected port evidence is host IP `127.0.0.1` for container `3000/tcp`, not `0.0.0.0` or `::`.

Reset by `docker stop hv-w0-shop`, then repeat the exact run command with the recorded image ID; `--rm` removes the stopped container layer. No volume is created by these commands. Clear that app's browser storage separately. If the image declares persistence or startup fails, inspect official documentation and `docker logs hv-w0-shop` using only synthetic data; do not loosen host binding or privileges automatically.

### Hints

Bind address, published host address and advertised URL are not interchangeable. The reset test directly mutates synthetic server memory to make state loss observable without exposing a mutation endpoint. Proxy trust and origin trust are separate channels.

### Solution and Expected Results

Expected unit result: two tests pass. Wildcard and host-mount manifests fail; loopback/no-mount manifest passes. The first server exposes revisions 0 then 7, closes its socket, and the next server starts at 0. Manual HTTP/curl returns `{"account": "synthetic-reader", "revision": 0}`. An explicit local CA file permits matching local HTTPS identity without installing trust. Container inspection should show only the intended host binding. These outcomes are expectations, not author observations.

### Verification, Troubleshooting, and Cleanup

No commands, servers, container downloads or browser steps were executed during authoring. Optional unit runner: `python -m pytest -q test_example.py`. Occupied app port: use `--port` with an unused value and update only the lab URLs/scope. Localhost IPv6 resolution can differ from this IPv4 bind; use 127.0.0.1. Keep corporate proxy/VPN settings intact if downloads fail; resolve installation/network prerequisites outside the lab rather than disabling controls.

Stop only the owned fixture and proxy listener. Stop `hv-w0-shop` if created; verify it no longer appears in `docker ps` and no lab listener remains. Remove only the disposable test directory, generated lab PEM files and captures; retire the temporary browser/proxy profile and its trust. Do not remove shared images or other users' containers. Parent validation must separately run vault checks and printed examples; authoring did not certify them.

- [ ] Record isolation manifest, exact versions and loopback listener evidence.
- [ ] Rebuild from the documented seed and retire all lab-owned state/trust.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W0 Foundations|W0 Foundations]]

## References

- [Official Juice Shop setup](https://help.owasp-juice.shop/part1/running.html)
- [Juice Shop v17.1.1 release](https://github.com/juice-shop/juice-shop/releases/tag/v17.1.1)
- [Docker port publishing and localhost caveats](https://docs.docker.com/engine/network/port-publishing/)
- [Burp built-in browser](https://portswigger.net/burp/documentation/desktop/tools/proxy/browser)
- [Python HTTP server limitations](https://docs.python.org/3.12/library/http.server.html)
