---
title: "Kubernetes Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Kubernetes]]"
updated: 2026-11-03
---
# Kubernetes Security

> [!abstract] TL;DR
> Overprivileged service accounts, privileged pods, exposed control planes, and unrestricted east-west access can expand a workload compromise across the cluster.

> [!info] Agent scope
> Security of: Pods; deployments; services; ingress; RBAC; service accounts; secrets; admission; network policy; workloads. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Overprivileged service accounts, privileged pods, exposed control planes, and unrestricted east-west access can expand a workload compromise across the cluster.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Kubernetes security at expert depth. Assume container and
RBAC fundamentals. Use Linux Kubernetes 1.34 as a stated schema baseline.
Separate API authorization, admission, workload identity, runtime confinement,
Secrets handling and CNI enforcement. Explain additive RBAC/NetworkPolicy,
resourceNames limitations, workload creation authority, token audience/expiry,
restricted Pod Security, image provenance and rollout compatibility. Provide
real least-privilege YAML and a complete offline contract lab with baseline
findings, concrete remediation, allowed behavior and negative regressions.
Distinguish policy lint from actual cluster enforcement and provider IAM.
Include audit evidence, false positives and revocation limits using primary
sources. No exploitation, privilege bypass, secrets, live cluster changes,
public listeners or host policy changes. Teach here without editing files.
```

## Cheatsheet

### Authority Is Not One Setting

| Boundary | Least-privilege control | Evidence and remaining limit |
|---|---|---|
| API caller to object | Namespaced Role, specific verbs/resources, dedicated binding | API audit and caller-scoped authorization review; other bindings add grants |
| Caller to workload identity | Restrict workload creation and service-account selection | Merely denying Secret `get` does not prevent authorized workloads mounting data |
| Image to running process | Approved digest, verified builder/source provenance, restricted context | Digest identifies bytes, not a trusted publisher; admission must actually enforce |
| Process to node | Nonroot, drop capabilities, seccomp, no host mounts/namespaces | Shared kernel and node administrators remain in trust boundary |
| Pod to Pod | Default deny plus narrow ingress/egress allows | CNI must support enforcement; readiness is not network authorization |
| Identity to secret | No auto token unless needed; narrow Secret access; encryption/rotation | Environment values are snapshots; already read bytes cannot be recalled |

RBAC contains allows, not explicit denies. `get`, `list`, `watch` Secrets can expose values; avoid blanket reader roles. `resourceNames` can restrict named reads but does not generally constrain creation, and list/watch require matching name field selectors for name-constrained authorization. Binding updates, role creation and special `bind`, `escalate` or `impersonate` privileges need independent review. Avoid wildcard resources/verbs because future APIs can expand their meaning.

### Concrete Admission and Network Configuration

Reference only, no apply step in this lab. Kubernetes 1.34 Linux policy semantics, not an installation recommendation: 1.34 reached EOL on 2026-10-27. Pinning the Pod Security version makes policy upgrades explicit, not permanent.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: w5
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.34
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.34
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.34
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-default, namespace: w5}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: frontend-to-api, namespace: w5}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: frontend}
      ports:
        - {protocol: TCP, port: 8080}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: frontend-egress, namespace: w5}
spec:
  podSelector:
    matchLabels: {app: frontend}
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels: {app: api}
      ports:
        - {protocol: TCP, port: 8080}
```

The pair permits same-namespace frontend-to-API TCP/8080 in both directions of policy evaluation. Reply traffic is implicitly allowed for allowed connections. It intentionally does not allow DNS or API-to-database egress; real applications need separate explicit policies. Empty peer lists and empty selector objects mean different things. Adding another policy can broaden the union of allowed traffic; NetworkPolicy cannot subtract an existing broad allow. IP handling around NAT and host-network Pods is implementation-dependent.

Restricted Pod Security is not a complete organizational policy: it does not require image digest verification, read-only root filesystems, workload resource limits or business-specific service accounts. Add those checks in a separately managed admission mechanism, protect its configuration and assess failure behavior. `audit`/`warn` do not block admission. Admission affects new/updated requests, not retroactive termination of every already-running nonconforming Pod.

### Runtime and Secret Patterns

Container security-context fragment:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: {drop: [ALL]}
  seccompProfile: {type: RuntimeDefault}
```

Set `automountServiceAccountToken: false` at Pod or service-account level when unused. A Pod setting overrides the account default. For API access, use bound projected tokens with the intended audience; kubelet rotation requires clients to reread the file. Do not copy tokens to logs or create long-lived token Secrets as a shortcut. Namespace isolation does not protect against privileged node administrators. Secret encryption at rest protects storage, not authorized API responses or unprotected backups; external secret providers introduce their own identity, availability and rotation boundaries.

## Detection and Defense

Audit role/binding changes, service-account selection, admission configuration, new image digests, workload mounts and token/Secret reads. Choose audit levels carefully: logging Secret request/response bodies can create a second secret store. Reconcile desired configuration with observed Pods; a valid deployment manifest is not proof every old replica has been replaced. For CNI evidence, record permitted and denied source/destination/port tuples and effective policies, without collecting payloads. Treat rollout/tool activity as possible false positives and correlate identity, change approval and controller ownership.

## Labs

### Environment and Complete Files

This page's core lab is entirely offline and self-contained: Python 3.12 standard library, one new directory, no cluster, YAML parser, network or credentials. No companion page is needed to finish it. The program inspects embedded synthetic Pod spec fragments using an organizational contract. It is not Pod Security Admission, full Kubernetes validation, RBAC evaluation, provider IAM or proof of packet enforcement. Unsafe baseline objects are never submitted anywhere. The preserved runtime milestones below are separate stretch goals, not this lab's acceptance criteria.

### File: test_example.py

```python
import copy
import unittest

BASELINE = {
	"serviceAccountName": "default", "automountServiceAccountToken": True,
	"hostNetwork": False, "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "16Mi"}}],
	"containers": [{"name": "api", "image": "synthetic-reviewed-image",
					"securityContext": {"runAsNonRoot": True},
					"resources": {"limits": {"cpu": "250m", "memory": "64Mi"}}}],
}
CONTEXT = {"runAsNonRoot": True, "runAsUser": 65532,
		   "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
		   "capabilities": {"drop": ["ALL"]},
		   "seccompProfile": {"type": "RuntimeDefault"}}


def review(spec):
	findings = set()
	if spec.get("serviceAccountName") != "worker":
		findings.add("identity")
	if spec.get("automountServiceAccountToken") is not False:
		findings.add("token")
	if any(spec.get(field, False) for field in ("hostNetwork", "hostPID", "hostIPC")):
		findings.add("host-namespace")
	if any("hostPath" in volume for volume in spec.get("volumes", [])):
		findings.add("host-mount")
	for container in spec["containers"]:
		if container.get("securityContext") != CONTEXT:
			findings.add("runtime-context")
		if container.get("resources", {}).get("limits") != {"cpu": "250m", "memory": "64Mi"}:
			findings.add("limits")
	return findings


def fixed():
	spec = copy.deepcopy(BASELINE)
	spec.update(serviceAccountName="worker", automountServiceAccountToken=False)
	spec["containers"][0]["securityContext"] = copy.deepcopy(CONTEXT)
	return spec


class HardeningTests(unittest.TestCase):
	def test_baseline_and_fix(self):
		self.assertEqual(review(BASELINE), {"identity", "token", "runtime-context"})
		self.assertEqual(review(fixed()), set())

	def test_workload_and_scratch_preserved(self):
		self.assertEqual(fixed()["volumes"], BASELINE["volumes"])
		self.assertEqual(fixed()["containers"][0]["image"], "synthetic-reviewed-image")

	def test_host_mount_rejected(self):
		spec = fixed()
		spec["volumes"].append({"name": "unexpected", "hostPath": {"path": "/synthetic"}})
		self.assertEqual(review(spec), {"host-mount"})

	def test_each_runtime_control_required(self):
		for field in CONTEXT:
			with self.subTest(field=field):
				spec = fixed()
				del spec["containers"][0]["securityContext"][field]
				self.assertEqual(review(spec), {"runtime-context"})


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

Run `python -m unittest -v test_example`. Predict the three baseline findings, then compare `fixed()` through the same review. Require the intended image and scratch volume to remain unchanged. Remove each runtime control and introduce a synthetic host mount; require rejection without launching any workload.

### Hints

This exact contract intentionally does not implement API defaulting, context inheritance, init/ephemeral containers, admission exemptions or RBAC. Those omissions are reasons not to use it as a production validator. The image label is synthetic, not a resolvable image or a verified supply-chain claim.

### Solution and Fixed Retest

Four tests should pass. The fix replaces the default account, disables automatic token mounting and supplies every required container control. A host mount is independently rejected; removing any context field fails the same runtime check. Scratch intent and approved synthetic image remain accepted. Real migration must also inspect other container types, effective RBAC, image provenance, admission enforcement and the selected CNI.

### Verification, Troubleshooting, and Cleanup

No package install or cluster setup is needed. A failing equality often indicates an edited fixture, not a Kubernetes denial; compare to the printed data before interpreting it. Restore fixtures for reset and delete the directory/`__pycache__` for cleanup. Tests and real-cluster checks were not run in this revision. The original runtime milestones remain separate, not implied by passing the offline tests.

### User-Owned Milestones

- [ ] Local Kubernetes exercise: Use a disposable local cluster to deploy a nonroot app with resource limits and a dedicated service account. Test allowed API actions and a network policy between two toy workloads.
- [ ] Boundary check: From a test service account, attempt a forbidden secret read and require denial. Verify a blocked pod-to-pod connection fails with the chosen CNI.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Kubernetes]]

## References

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
