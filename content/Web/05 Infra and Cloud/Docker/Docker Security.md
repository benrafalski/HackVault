---
title: "Docker Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Docker]]"
updated: 2026-11-03
---
# Docker Security

> [!abstract] TL;DR
> Privileged containers, sensitive host mounts, exposed daemons, and leaked build secrets can turn container access into host or credential exposure.

> [!info] Agent scope
> Security of: Images and layers; containers; namespaces; capabilities; volumes; networks; secrets; rootless operation; build provenance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Daemon administration, build context and cache, image provenance, host mounts/devices, effective UID/capabilities, published listeners, container egress and secret delivery.
- Host kernel/runtime patching remains required. Container confinement, application authorization and release provenance are independent controls.

## Learn

```text
Teach me defensive Docker hardening at expert depth. Cover daemon authority,
rootless versus userns-remap, UID/capabilities/seccomp/no-new-privileges,
read-only filesystems, mounts, networks, cgroups, build secrets and layer
retention. Explain image digest versus publisher trust, provenance verification,
SBOM limits and patch/rebuild policy. Give concrete safe runtime configuration
and offline inspection fixtures with baseline findings, fixes and preserved
legitimate behavior. Distinguish linted intent from kernel/runtime enforcement;
cover Docker Desktop, Linux and Engine-version caveats. Use primary Docker
sources. No privileged lab launches, exploit steps, socket mounts, real secrets
or public listeners. Teach in this conversation without file/status edits.
```

## Cheatsheet

### Hardening Decisions

| Control | Concrete setting / review | Remaining limit |
|---|---|---|
| Nonroot | Numeric `USER 65532:65532` or reviewed runtime UID | Named users depend on image passwd data; host mounts still need permissions |
| Capabilities | `--cap-drop=ALL`, add none unless required | Kernel/runtime defects and mounted resources remain relevant |
| Privilege gain | `--security-opt=no-new-privileges:true` | Does not remove privileges already granted |
| Root filesystem | `--read-only`, bounded scratch tmpfs | Mounted data may still be writable |
| Syscall/LSM | Keep default seccomp and host AppArmor/SELinux where available | Profiles and support differ by OS/runtime |
| Resource use | Explicit memory, CPU and PID limits | Some rootless cgroup environments need host configuration |
| Network | Loopback publication for labs; scoped networks/egress for deployments | Loopback is not user authentication |
| Host integration | No daemon socket, host PID/network, host devices or broad bind mounts | Application still shares host kernel on native Linux |

Use rootless where compatible, but do not mistake it for a guarantee about user-owned host data. A read-only mount limits writes, not confidentiality. A Docker socket mount exposes daemon control even if the mount itself is read-only; do not put it in workload containers.

### Concrete Safe Runtime Fragment

For a separately reviewed image named `approved-lab-image`, a Linux runtime command shape is:

```text
docker run --rm --user 65532:65532 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m,mode=1777 --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=64 --memory=128m --cpus=1 --network none approved-lab-image
```

This is a reference fragment, not the lab startup: it needs an existing compatible image and starts no listener. A networked application needs an explicit network/exposure design rather than removing `--network none` casually. Engine 28+ is required for the companion page's loopback-publishing exercise because older releases had a documented same-L2 localhost caveat.

### Build and Supply-Chain Review

Keep the build context allowlisted with `.dockerignore`; `COPY . .` can unintentionally include credential/configuration files. Do not use `ARG`/`ENV` to transmit build secrets. BuildKit secret mounts are ephemeral inputs, but build scripts can still copy or log their contents. Multi-stage builds can omit build tools from the final image while leaving build cache or logs sensitive.

Verify a real image digest against approved provenance: expected repository, source revision, builder identity and build process. Digest pinning prevents tag movement from silently changing bytes; it does not authenticate the publisher by itself. Scan image contents and dependencies, evaluate reachable vulnerabilities and rebuild for fixes. An SBOM describes components; "has SBOM" is not a security pass.

Application secrets should be delivered through supported runtime secret mechanisms or tightly scoped read-only files, with rotation and access policy. Plain environment variables can appear in inspect/debug tooling. Compose secrets implemented as local file mounts are not automatically an encrypted secret store. Never print real inspect environments in evidence.

## Detection and Defense

Audit daemon access, new mounts, privileged/host-namespace settings, unexpected image digests, process/resource anomalies and publication changes. Correlate deployment approval with observed container configuration and image ID. A numeric nonroot UID is insufficient evidence without mount/capability review. Inspect running configuration and perform harmless write/network checks in disposable environments; do not infer enforcement from a Dockerfile alone.

## Labs

### Environment and Complete Files

Required lab is offline: Python 3.12 standard library in an empty directory, no Docker installation, image pull, daemon, network or credentials. Start/check: `python -m unittest -v test_example`. The dataset resembles a selected `docker inspect` structure but is synthetic. It checks an organizational runtime contract, **not kernel isolation**. Unsafe baseline settings are never launched.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"Config": {"User": "0"},
	"HostConfig": {"Privileged": False, "ReadonlyRootfs": False,
				   "CapDrop": [], "CapAdd": [], "SecurityOpt": [],
				   "NetworkMode": "bridge", "PidMode": "",
				   "Binds": [], "Devices": [], "Memory": 134217728,
				   "PidsLimit": 64,
				   "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}},
	"Mounts": [],
}


def review(config):
	issues = set()
	host = config["HostConfig"]
	if config["Config"].get("User") != "65532:65532":
		issues.add("identity")
	if host.get("Privileged") is not False:
		issues.add("privileged")
	if host.get("ReadonlyRootfs") is not True:
		issues.add("rootfs")
	if {value.upper() for value in host.get("CapDrop", [])} != {"ALL"} or host.get("CapAdd"):
		issues.add("capabilities")
	if "no-new-privileges:true" not in host.get("SecurityOpt", []):
		issues.add("privilege-gain")
	if host.get("Binds") or host.get("Devices") or config.get("Mounts"):
		issues.add("unreviewed-mount-or-device")
	if host.get("NetworkMode") != "bridge" or host.get("PidMode") != "":
		issues.add("namespace")
	if host.get("Memory") != 134217728 or host.get("PidsLimit") != 64:
		issues.add("resource-limits")
	expected = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}
	if host.get("PortBindings") != expected:
		issues.add("publication")
	return issues


def fixed():
	config = copy.deepcopy(BASELINE)
	config["Config"]["User"] = "65532:65532"
	config["HostConfig"].update(ReadonlyRootfs=True, CapDrop=["ALL"],
							   SecurityOpt=["no-new-privileges:true"])
	return config


class ContainerContractTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(review(BASELINE), {"identity", "rootfs", "capabilities", "privilege-gain"})
		self.assertEqual(review(fixed()), set())

	def test_keep_loopback_service_intent(self):
		self.assertEqual(fixed()["HostConfig"]["PortBindings"],
						 BASELINE["HostConfig"]["PortBindings"])

	def test_missing_limit(self):
		config = fixed()
		del config["HostConfig"]["PidsLimit"]
		self.assertEqual(review(config), {"resource-limits"})

	def test_unreviewed_mount(self):
		config = fixed()
		config["Mounts"] = [{"Type": "bind", "Source": "/synthetic", "Destination": "/data"}]
		self.assertEqual(review(config), {"unreviewed-mount-or-device"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Identify four baseline findings before running tests. Explain why a loopback listener does not fix filesystem/identity settings.
2. Apply `fixed()` and repeat exactly the same review. Keep the approved port mapping unchanged.
3. Remove a limit and add an unreviewed synthetic mount; require rejection without launching any container.
4. List separate runtime evidence needed: effective UID/capabilities, rejected root writes, permitted scratch writes, actual publication and host policy support.

### Hints

This exact contract intentionally has no volumes and one permitted loopback port. A legitimate application requiring storage needs a reviewed allowlist extension, not blanket acceptance of every mount. `Mounts` and `HostConfig.Binds` can expose different representations of runtime intent.

### Solution and Fixed Retest

The supplied fix selects the nonroot identity, read-only root, all-capability drop and no-new-privileges, preserving the approved service mapping. Four tests should pass. Baseline finds four issues; the mount and missing-limit variants each find one. No running container, daemon protection, supply-chain signature or network confinement is certified by these tests.

### Verification, Troubleshooting, and Cleanup

Use this page's file in its own directory. Different inspect serialization may use empty/null fields; adapt only after documenting real schema/version differences, not to silence findings. Delete file and `__pycache__` for cleanup; there are no containers or volumes to remove. Static author review only, no test execution. [[Docker]] contains a separate complete optional runtime lab, not a prerequisite for this fixture exercise.

### User-Owned Milestones

Retained runtime goals need actual disposable-container evidence.

- [ ] Local Docker exercise: Run a harmless web image bound to loopback with a read-only filesystem and minimal writable volume. Inspect its identity, mounts, capabilities, and network exposure, then remove it.
- [ ] Boundary check: Attempt to write outside the designated volume and access an unmounted host marker from the lab container. Both should fail; inspect the actual published host address.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Docker]]

## References

- [Docker security](https://docs.docker.com/engine/security/)
- [Seccomp profiles](https://docs.docker.com/engine/security/seccomp/)
- [Rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Build secrets](https://docs.docker.com/build/building/secrets/)
- [Image attestations](https://docs.docker.com/build/metadata/attestations/)
