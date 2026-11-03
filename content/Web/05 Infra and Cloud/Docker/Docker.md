---
title: "Docker"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Docker Security]]"
updated: 2026-11-03
---
# Docker

> [!abstract] TL;DR
> Avoid privileged mode and Docker-socket mounts; pin image digests for reproducibility; keep build contexts small and secrets out of layers.

> [!info] Agent scope
> Images and layers; containers; namespaces; capabilities; volumes; networks; secrets; rootless operation; build provenance.

## Prerequisites

- Processes, Linux permissions, TCP and HTTP; [[Web Lab Setup]].
- Real local lab: installed Docker Engine 28+ or Docker Desktop with Linux containers and an Engine 28+ backend, running locally; permission to use that daemon. Python 3.12 on the host for tests. The initial official Python image pull needs registry access unless already cached. No cloud account or credentials are required.

## Learn

```text
Teach me Docker at expert engineering depth, assuming Linux processes,
permissions and TCP. Trace image manifest/layers/digests through copy-on-write
container storage, namespaces, cgroups, capabilities, seccomp and user identity.
Compare bind mounts, named volumes, tmpfs, bridge networking, published ports,
rootless daemon and user namespace remapping. Explain build context, cache,
multi-stage builds, BuildKit secret mounts, provenance and digest pinning.
Provide a complete nonroot read-only loopback web lab with inspection/tests,
explicit dependency/daemon versions, failure cases and cleanup. Distinguish
container root from host authority and Docker Desktop's VM from native Linux.
Use Docker primary sources; no privileged mode, socket mounts, public ports,
real secrets or production defaults. Teach here without editing files/status.
```

## Cheatsheet

### Image, Process, and Host Boundaries

An image is a content-addressed filesystem/configuration artifact; a container is a process tree plus runtime configuration and a writable layer. Layers record filesystem differences. Removing a file in a later layer hides it from the merged view but does not erase earlier bytes. Keep secrets out of the build context and all layers, not just the final directory listing.

A registry tag is mutable. A digest identifies a manifest or multi-platform index; platform selection still matters. For a real release, resolve the expected platform, record the digest, verify publisher/provenance and scan the resulting artifact. Do not treat a digest as a trust signature or invent a hash. The lab uses a real version-family tag for accessibility and explicitly does not claim reproducible dependency pinning.

| Primitive | What it controls | What it does not prove |
|---|---|---|
| Namespaces | Process, mount, network and other views | Separate kernel or freedom from kernel bugs |
| cgroups | CPU/memory/PID accounting and limits | Application correctness or all disk/network limits |
| UID/GID | Filesystem/process identity | Rootless daemon; nonroot container can still have dangerous mounts |
| Capabilities | Selected privileged kernel operations | Full isolation if host devices/socket are exposed |
| Seccomp | System-call filtering | Object-level application authorization |
| Read-only root | Writes to image filesystem denied | Read-only volumes, tmpfs, or secret-safe application logs |
| Rootless | Daemon and containers run in a user namespace without host root | No host data exposure; user-owned mounts still matter |

Rootless mode and `userns-remap` differ: the former changes daemon privilege as well; the latter remaps container users while the daemon can remain rootful. Docker Desktop Linux containers run inside a VM; mounts and network forwarding cross that VM boundary. Do not extrapolate Linux host PID/network observations directly to Windows containers.

### Storage and Networks

Bind mounts expose exact host paths and inherit host-data risk. Named volumes are daemon-managed persistent storage; deleting a container need not delete them. Tmpfs is ephemeral memory-backed writable space, useful for bounded scratch data, not durable state. A read-only root usually needs explicitly writable paths for application temp files, runtime PID files or caches.

`EXPOSE` documents a container port; it does not publish it. `-p 127.0.0.1:18080:8080` binds the host side to IPv4 loopback; the app listens on its container interface. Omitting the host IP commonly publishes broadly. Engine releases before 28 had a documented localhost-publication caveat affecting hosts on the same L2 network, so this lab requires Engine 28+. Port publication is distinct from container egress: a bridge-connected app may still reach outbound destinations.

User-defined bridges provide scoped service-name resolution; default bridge behavior differs. `--network none` disables ordinary networking but cannot serve the HTTP lab. Network names are not security authorization. Avoid host networking and daemon socket mounts for application containers.

### Build and Runtime Commands

These are inspection commands for an already created lab container/image, not production actions:

```text
docker version
docker context show
docker image inspect w5-docker:lab
docker inspect w5-docker
docker port w5-docker
docker logs w5-docker
docker history --no-trunc w5-docker:lab
```

`docker inspect` reports intended runtime settings; inspect in-container effective identity and mount behavior too. Avoid logging environment variables indiscriminately. BuildKit secret mounts use `RUN --mount=type=secret,id=...` with `docker build --secret ...`; they avoid automatically adding the secret mount to a layer, but a build command can still copy/log secret bytes. Multi-stage builds reduce final contents, not necessarily every cache artifact.

For deployment, lock dependencies, minimize base/runtime packages, produce SBOM/provenance, verify them against an approved builder/source policy and update through reviewed rebuilds. Keep builder privileges separate from registry push and production deploy identities.

## Gotchas

- Docker CLI access to a rootful daemon is powerful host administration. Do not expose the daemon API or mount its socket into this lab.
- `--read-only` does not prevent writing to explicitly writable mounts. Test both rejected and permitted writes.
- Python's standard-library HTTP server below is a synthetic local lab service, not a production server.

## Labs

### Environment and Complete Files

Use a new empty directory containing exactly the four files below. Ensure `docker context show` selects the local disposable daemon and `docker version` shows Engine 28+. Do not point these commands at a remote or production daemon. Host Python 3.12 runs tests; the container uses official `python:3.12-slim`, a mutable lab tag with no fabricated digest. Record its resolved digest for your run.

### File: app.py

```python
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path != "/health":
			self.send_error(404)
			return
		body = b"W5 healthy\n"
		self.send_response(200)
		self.send_header("Content-Type", "text/plain; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body)


if __name__ == "__main__":
	ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

### File: Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "-B", "/app/app.py"]
```

### File: .dockerignore

```text
*
!Dockerfile
!app.py
!.dockerignore
```

### File: test_example.py

```python
import json
import subprocess
import unittest
from urllib.request import ProxyHandler, build_opener


def container_python(source):
	return subprocess.run(["docker", "exec", "w5-docker", "python", "-c", source],
						  check=True, capture_output=True, text=True).stdout.strip()


class ContainerTests(unittest.TestCase):
	def test_http(self):
		opener = build_opener(ProxyHandler({}))
		with opener.open("http://127.0.0.1:18080/health", timeout=5) as response:
			self.assertEqual(response.status, 200)
			self.assertEqual(response.read(), b"W5 healthy\n")

	def test_effective_identity(self):
		self.assertEqual(container_python("import os; print(os.getuid())"), "65532")

	def test_writes_are_scoped(self):
		source = """
from pathlib import Path
Path('/tmp/marker').write_text('synthetic')
assert Path('/tmp/marker').read_text() == 'synthetic'
try:
	Path('/app/marker').write_text('synthetic')
except OSError:
	print('protected')
else:
	raise AssertionError('unexpected root-filesystem write')
Path('/tmp/marker').unlink()
assert not Path('/host-marker').exists()
"""
		self.assertEqual(container_python(source), "protected")

	def test_runtime_contract(self):
		result = subprocess.run(["docker", "inspect", "w5-docker"], check=True,
								capture_output=True, text=True)
		config = json.loads(result.stdout)[0]
		self.assertTrue(config["HostConfig"]["ReadonlyRootfs"])
		self.assertFalse(config["HostConfig"]["Privileged"])
		bindings = config["HostConfig"]["PortBindings"]["8080/tcp"]
		self.assertEqual(bindings, [{"HostIp": "127.0.0.1", "HostPort": "18080"}])


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Startup

The host port must be free. Build and launch only this lab image:

```text
docker build --pull -t w5-docker:lab .
docker run --rm --detach --name w5-docker --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m,mode=1777 --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=64 --memory=128m --cpus=1 --publish 127.0.0.1:18080:8080 w5-docker:lab
docker logs w5-docker
python -m unittest -v test_example
docker port w5-docker
```

1. Predict which writes succeed, which UID serves the request and which host address is published.
2. Inspect image layers and runtime settings; distinguish build-time `USER` from enforced runtime capabilities/mounts.
3. Explain why `/host-marker` absence demonstrates only that this path is not mounted, not a proof of all host isolation.
4. Stop/recreate the container and verify scratch data does not persist; no named volume is created.

### Hints

The service binds all interfaces **inside** its network namespace; the host publication is loopback-only. A nonroot UID alone can reject `/app` writes, so combine the behavior check with `ReadonlyRootfs` inspection rather than attributing the result solely to one mechanism.

### Solution and Expected Results

Four tests should pass: HTTP returns the synthetic health line, UID is 65532, `/tmp` permits scratch data, `/app` does not, and Docker reports only `127.0.0.1:18080`. Image filesystem changes are separate from tmpfs writes. The image tag remains a lab convenience; a release would record/approve its real digest and provenance.

### Verification, Troubleshooting, and Cleanup

If the service is not ready, inspect `docker logs` and rerun after startup; no fixed sleep is required. Port conflict: stop only your previous lab container or choose another loopback port and update the test. Image pull requires approved registry access or a cached image; do not disable corporate network controls. Rootless cgroup limitations may reject resource flags: use a properly configured disposable runtime rather than silently dropping controls.

Cleanup: `docker stop w5-docker`, then `docker image rm w5-docker:lab`; remove the lab directory and `__pycache__`. Do not run broad prune commands. Shared base-image layers may remain cached. Static author review only: build, container, server and tests were not run during this revision.

### User-Owned Milestones

- [ ] Local Docker exercise: Run a harmless web image bound to loopback with a read-only filesystem and minimal writable volume. Inspect its identity, mounts, capabilities, and network exposure, then remove it.
- [ ] Boundary check: Attempt to write outside the designated volume and access an unmounted host marker from the lab container. Both should fail; inspect the actual published host address.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Docker Security]]

## References

- [Docker security](https://docs.docker.com/engine/security/)
- [Rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Port publishing](https://docs.docker.com/engine/network/port-publishing/)
- [Build secrets](https://docs.docker.com/build/building/secrets/)
- [Build attestations](https://docs.docker.com/build/metadata/attestations/)
