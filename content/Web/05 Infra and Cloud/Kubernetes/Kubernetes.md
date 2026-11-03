---
title: "Kubernetes"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Kubernetes Security]]"
updated: 2026-11-03
---
# Kubernetes

> [!abstract] TL;DR
> Minimize service-account tokens and RBAC; enforce restricted workload settings; set requests/limits; verify network policies actually work.

> [!info] Agent scope
> Pods; deployments; services; ingress; RBAC; service accounts; secrets; admission; network policy; workloads.

## Prerequisites

- Linux containers, HTTP, identity and declarative configuration; [[Web Lab Setup]].
- Offline preparation: Python 3.12 standard library only. Reference API examples use Linux Kubernetes 1.34 semantics, not a supported runtime recommendation: 1.34 reached EOL on 2026-10-27. The separate real exercise below specifies Kubernetes 1.35 and requires explicit disposable-VM approval.

## Learn

```text
Teach me Kubernetes at expert operational depth, assuming Linux containers,
HTTP and basic identity. Use Kubernetes 1.34 Linux API semantics as an explicit
baseline and distinguish newer or distribution-specific features. Trace an
API write through authentication, authorization, admission, persistence,
controllers, scheduling, kubelet and readiness to Service endpoints. Compare
Pods, Deployments, StatefulSets, Jobs, Services and Ingress; explain ownership,
selectors, rollout failure, requests/limits and probe design. Cover namespaced
RBAC, projected service-account token audience/lifetime, Secrets, restricted
admission and additive NetworkPolicy semantics, including CNI dependencies.
Supply exact manifests, read-only inspection commands, a complete offline
selection/reconciliation exercise and its tests. Explain what only a real
cluster can prove. Use primary sources; no public listeners, real credentials,
host policy changes or privileged workloads. Teach here; do not edit files.
```

## Cheatsheet

### Reconciliation and Workload Lifetime

API authentication establishes an identity; authorization decides an operation on a resource; admission can default, validate or mutate the accepted object. Persistence of desired state is not readiness. Controllers retry reconciliation against observed state; `metadata.generation` tracks spec changes while a controller's `status.observedGeneration` can lag. `resourceVersion` supports concurrency/watch semantics and must not be treated as a wall-clock timestamp. A failed optimistic update needs a fresh read and a deliberate merge, not a blind overwrite.

| Object | Ownership and lifetime | Important failure boundary |
|---|---|---|
| Pod | Scheduled unit; containers share network and declared volumes | Replacement gets a new UID and usually IP; restarting a container is not replacing a Pod |
| Deployment | Owns ReplicaSets, which own replicated Pods | Rolling update needs spare capacity; progress deadline reports stalled progress, not automatic rollback |
| StatefulSet | Stable ordinal/name and storage association | Stable identity is not database replication or automatic data recovery |
| Job / CronJob | Completion-oriented work / scheduling | Retries and overlapping schedules require application idempotency |
| Service | Stable virtual address and selector-based EndpointSlices | Selectors can accidentally include an unrelated workload; readiness controls ordinary endpoint eligibility |
| Ingress | HTTP routing declaration | Requires a controller; TLS, annotations and upstream behavior are controller-specific |

Deployment selectors are immutable and must match template labels. Avoid sharing selectors between controllers. Service `port` is the client-facing port; `targetPort` names or numbers the Pod endpoint. A ClusterIP does not publish an Internet listener, but it does not authorize clients either. Ingress resources alone do not install a proxy. The Ingress API is frozen; Gateway API is a separate, extensible API with its own installed implementations, not a drop-in API version.

### Resource and Health Decisions

Requests drive scheduling; limits bound supported runtime resources. CPU limits cause throttling; memory exhaustion can terminate a container. Requests do not reserve unlimited storage or network capacity. Readiness removes a Pod from ordinary Service traffic; liveness restarts the container; startup probes defer the other probes until startup succeeds. Do not make liveness depend on a shared database: a database outage should not restart every frontend. Graceful termination must coordinate readiness, endpoint propagation, in-flight work and termination grace, not assume a `preStop` hook instantly stops traffic.

### Concrete API Documents

Reference manifests, not required lab input and not executed here. The image tag is intentionally a mutable **lab** family; releases require a reviewed real digest and verified provenance. No Service, Ingress or host port is created. The sleeping process needs no API token. These settings target Linux and assume the runtime supports seccomp.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker
  namespace: w5
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: w5
spec:
  replicas: 2
  selector:
    matchLabels: {app: worker}
  template:
    metadata:
      labels: {app: worker}
    spec:
      serviceAccountName: worker
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: worker
          image: python:3.12-slim
          command: [python, -B, -c, "import time; time.sleep(3600)"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {cpu: 250m, memory: 64Mi}
          volumeMounts:
            - {name: scratch, mountPath: /tmp}
      volumes:
        - name: scratch
          emptyDir: {medium: Memory, sizeLimit: 16Mi}
```

`w5` must already be a disposable namespace before any optional use. `emptyDir` survives container restarts within the Pod but not Pod removal; memory-backed contents count toward memory usage. Nonroot identity, read-only root and no privilege escalation address different controls. A `ServiceAccount` selects API identity; it does not grant permission without a binding.

An exact namespaced grant for one synthetic ConfigMap:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: read-settings, namespace: w5}
rules:
  - apiGroups: [""]
    resources: [configmaps]
    resourceNames: [settings]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: read-settings, namespace: w5}
subjects:
  - {kind: ServiceAccount, name: worker, namespace: w5}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: read-settings}
```

This does not grant `list`, `watch`, Secrets or other namespaces. RBAC grants are additive; there is no deny rule to subtract another binding's permission. Projected bound service-account tokens have audience, expiry and object binding; clients must reread the rotated file rather than cache its first bytes forever. `automountServiceAccountToken: false` is appropriate when no API call is needed, even if a role exists. Secrets are base64-encoded API data, not encryption; use scoped readers, encryption at rest and protected backups. Volume-delivered Secret updates are eventually propagated; environment values and `subPath` mounts do not provide the same refresh semantics.

### Admission, Network, and Evidence

Pod Security Admission's `enforce`, `audit` and `warn` namespace labels are separate modes. Pin a policy version during rollout and review changes before advancing it. NetworkPolicy selects Pods and adds allowed traffic: once isolated in a direction, only the union of matching allows applies. Both source egress and destination ingress must permit a connection. Within a peer, `namespaceSelector` and `podSelector` combine; separate peers are alternatives. DNS, node traffic, SNAT and existing connections require implementation-specific review. A CNI that does not implement NetworkPolicy can accept the object without enforcing it.

Read-only inspection in an already authorized disposable context:

```text
kubectl config current-context
kubectl version --client
kubectl -n w5 get deploy,rs,pods,svc,endpointslices
kubectl -n w5 describe deployment worker
kubectl -n w5 get events --sort-by=.metadata.creationTimestamp
kubectl -n w5 auth can-i get configmap/settings
kubectl -n w5 auth can-i get secrets
```

These commands use the current caller, not automatically `worker`. Impersonation requires separate authority and is not needed for this offline exercise. A successful authorization check does not prove connectivity, admission approval or existence of the requested object.

## Gotchas

Namespaces are organizational/API scopes, not separate kernels. Secret-read restriction alone is insufficient if an identity can create workloads that mount those Secrets. Readiness success says the configured probe passed, not that every user operation succeeds.

## Labs

### Environment and Complete Files

Offline preparation: Python 3.12, standard library, no cluster, network, packages or credentials. Create an empty local directory and the one file below. All data is embedded. The executable teaches label/namespace matching, ready endpoints and replica deltas; it is deliberately not a scheduler, kube-proxy or Kubernetes policy emulator. It cannot satisfy the real runtime milestones.

### File: test_example.py

```python
import copy
import unittest

SERVICE = {"namespace": "w5", "selector": {"app": "api", "tier": "web"}}
PODS = [
		{"name": "api-1", "namespace": "w5", "labels": {"app": "api", "tier": "web"},
		 "ready": True, "deleting": False, "owner": "rs-a"},
		{"name": "api-2", "namespace": "w5", "labels": {"app": "api", "tier": "web"},
		 "ready": False, "deleting": False, "owner": "rs-a"},
		{"name": "other", "namespace": "other", "labels": {"app": "api", "tier": "web"},
		 "ready": True, "deleting": False, "owner": "rs-b"},
]


def endpoints(service, pods):
		return sorted(pod["name"] for pod in pods
									if pod["namespace"] == service["namespace"]
									and all(pod["labels"].get(key) == value
													for key, value in service["selector"].items())
									and pod["ready"] and not pod["deleting"])


def replica_delta(desired, owner, pods):
		active = sum(pod["owner"] == owner and not pod["deleting"] for pod in pods)
		return desired - active


class ReconciliationTests(unittest.TestCase):
		def test_namespace_and_readiness(self):
				self.assertEqual(endpoints(SERVICE, PODS), ["api-1"])

		def test_readiness_does_not_create_new_replica(self):
				self.assertEqual(replica_delta(2, "rs-a", PODS), 0)
				changed = copy.deepcopy(PODS)
				changed[1]["ready"] = True
				self.assertEqual(endpoints(SERVICE, changed), ["api-1", "api-2"])

		def test_replacement_is_distinct_from_readiness(self):
				changed = copy.deepcopy(PODS)
				changed[0]["deleting"] = True
				self.assertEqual(replica_delta(2, "rs-a", changed), 1)
				self.assertEqual(endpoints(SERVICE, changed), [])

		def test_accidental_label_match(self):
				changed = copy.deepcopy(PODS)
				changed.append(dict(changed[0], name="unrelated", owner="rs-other"))
				self.assertEqual(endpoints(SERVICE, changed), ["api-1", "unrelated"])


if __name__ == "__main__":
		unittest.main()
```

### Objectives and Steps

Run `python -m unittest -v test_example`. Predict endpoint membership before each test. Explain why an unready Pod still satisfies a replica count and why Service selection ignores controller ownership. Mark one Pod deleting, then compare the replica delta with the endpoint set. No cluster objects are created.

### Hints

Replica count, ownership, readiness and label selection are different dimensions. A Service is not a request to route only to a particular Deployment. Real terminating endpoints and `publishNotReadyAddresses` have additional semantics intentionally omitted here.

### Solution and Expected Results

Four tests should pass. Initial eligible endpoint: `api-1`; making `api-2` ready yields two endpoints without a replica change. Deleting `api-1` requires one replacement but leaves no ready endpoint. A same-namespace unrelated Pod with matching labels is selected despite its other owner. Correct remediation for accidental membership is unique reviewed selectors and corresponding labels, not changing ownership references.

### Verification, Troubleshooting, and Cleanup

Run in this page's own directory to avoid another note's test module. Restore the embedded fixtures to reset; delete the directory and `__pycache__` to clean up. No runtime, API server, admission, CNI or RBAC enforcement was exercised. The original runtime goals below remain separate and uncompleted. Author checks were limited to static inspection; tests were not run.

### Real Exercise: Approved Disposable VM Only

> [!warning] Approval boundary
> These are instructions for a later, separately approved run, not authorization to execute now. Use a disposable Ubuntu VM with no production kubeconfigs, real secrets, shared host directories or cloud credentials. Never run this cluster on the workstation, disconnect its VPN, change its firewall/protections, or elevate there. kind nodes and Calico are privileged infrastructure inside the disposable VM; the toy workloads are not privileged. Docker socket access is effectively VM-root authority and must already be approved. If VM networking or security policy prevents setup, stop and use the offline preparation; do not disable protections.

Objective: observe restricted workloads and scoped API authorization, then demonstrate policy enforcement using the same healthy endpoints before/after a control. Scope is one named cluster, namespace `w5-runtime`, and two HTTP servers with empty temporary directories. No external targets, Ingress, NodePort, LoadBalancer, host mounts or port-forwards are used. The API is published only on VM loopback; the servers listen on their Pod interfaces, not on VM/workstation interfaces.

Prerequisites must be provisioned in the approved VM before starting. Package installation is not part of this exercise. All locally authored inputs are printed below; vendor binaries, images and the two tagged Calico operator manifests are external dependencies.

| Component | Exact exercise baseline / prerequisite | Public verification and limits |
|---|---|---|
| Guest | Ubuntu 24.04 LTS amd64, maintained kernel 6.8 or newer; 4 vCPU, 8 GiB RAM, 30 GiB free disk | [Docker Ubuntu support](https://docs.docker.com/engine/install/ubuntu/); [Calico requirements](https://docs.tigera.io/calico/3.31/getting-started/kubernetes/requirements) require kernel 5.10+. Sizing here is a lab budget, not a vendor minimum. Record the actual patched guest/kernel build. |
| Docker CLI and Engine | 29.9.2, rootful local Unix socket, default iptables backend, cgroup v2 | [Engine 29 release](https://docs.docker.com/engine/release-notes/29/#2992). No remote daemon or rootless/Windows-container variant in this recipe. |
| kind | v0.33.0, linux-amd64 | [Release and node images](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0) publish the 1.35.8 digest used below; do not use kind's newer default image. |
| Kubernetes / kubectl | Server v1.35.8; client v1.35.8 | [Version skew](https://kubernetes.io/releases/version-skew-policy/) permits matching minors; [lifecycle](https://kubernetes.io/releases/patch-releases/#1-35) keeps 1.35 supported on 2026-11-03. This published kind image is a reproducibility baseline, not a claim to be the newest/security-complete patch. Reassess advisories before approving a run. |
| Calico | v3.31.7 operator installation | [3.31 requirements](https://docs.tigera.io/calico/3.31/getting-started/kubernetes/requirements) list Kubernetes 1.35 as tested; [kind recipe](https://docs.tigera.io/calico/3.31/getting-started/kubernetes/kind) supplies the tagged operator URLs and disables kindnet. |
| Workload Python | `python:3.12.16-slim-bookworm` | Listed by the [official image](https://hub.docker.com/_/python); patch tag can be rebuilt. Record Pod `imageID` digests; no invented image digest. No pip dependencies or image build. |
| Guest tools | Bash 5.2, Python 3.12 standard library, GNU coreutils (`timeout`, `sha256sum`), curl with trusted HTTPS CAs, iproute2 | Ubuntu-provided utilities; retain their security updates and record actual versions. No Helm, jq, calicoctl, YAML parser or companion-note files required. |

This is documentation-backed compatibility review, **not an executed integration certification**. Stop if versions differ; review the new combination rather than silently substituting versions. Approved egress must permit vendor downloads and image pulls (GitHub, Kubernetes downloads, Docker Hub and Calico registries). Use approved proxy/CA provisioning without disabling TLS verification. The Pod range `192.168.0.0/16`, Service range `10.96.0.0/12`, and Docker bridge ranges must not overlap guest, routed or VPN-connected networks. Check guest routes and Docker networks before creation; if they overlap, stop for a reviewed address plan. Do not repair this by changing the workstation's routes/VPN.

### Runtime Files

Use a new empty directory outside the vault **inside the approved VM**, separate from the offline exercise. In that directory create the eight files named in the following headings with exactly the printed contents. Outputs later created here are `kubeconfig`, `cache/`, and downloaded vendor manifests. No hidden helper, Dockerfile, application source or seed file is needed.

#### File: kind.yaml

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "127.0.0.1"
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
  serviceSubnet: "10.96.0.0/12"
  kubeProxyMode: iptables
nodes:
  - role: control-plane
  - role: worker
  - role: worker
```

#### File: calico-installation.yaml

Only networking is needed; no Calico API server, flow UI or published UI port. This is the operator's `Installation` resource, not a core Kubernetes kind. The CIDR must match kind. Cross-subnet VXLAN follows the vendor custom-resource example; same-subnet kind nodes can route directly.

```yaml
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    ipPools:
      - name: default-ipv4-ippool
        blockSize: 26
        cidr: 192.168.0.0/16
        encapsulation: VXLANCrossSubnet
        natOutgoing: Enabled
        nodeSelector: all()
```

#### File: namespace.yaml

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: w5-runtime
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.35
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.35
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.35
```

#### File: workloads.yaml

Both servers have dedicated service accounts, no mounted API token, restricted contexts and explicit resources. Placing them on separate workers exercises inter-node traffic. The synthetic Secret is never mounted or printed. Authorization checks use the worker identity via approved administrator impersonation, not an administrative result mislabeled as a workload result.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: worker, namespace: w5-runtime}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: api, namespace: w5-runtime}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ConfigMap
metadata: {name: settings, namespace: w5-runtime}
data:
  mode: toy
---
apiVersion: v1
kind: Secret
metadata: {name: synthetic-secret, namespace: w5-runtime}
type: Opaque
stringData:
  marker: not-a-real-credential
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: read-settings, namespace: w5-runtime}
rules:
  - apiGroups: [""]
    resources: [configmaps]
    resourceNames: [settings]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: read-settings, namespace: w5-runtime}
subjects:
  - kind: ServiceAccount
    name: worker
    namespace: w5-runtime
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: read-settings
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: w5-runtime}
spec:
  replicas: 1
  selector:
    matchLabels: {app: frontend}
  template:
    metadata:
      labels: {app: frontend}
    spec:
      nodeSelector:
        kubernetes.io/hostname: hv-k8s-runtime-worker
      serviceAccountName: worker
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: http
          image: python:3.12.16-slim-bookworm
          imagePullPolicy: Always
          command: [python, -B, -m, http.server, "8080", --bind, "0.0.0.0", --directory, /tmp]
          ports:
            - {name: http, containerPort: 8080}
          readinessProbe:
            httpGet: {path: /, port: http}
            periodSeconds: 2
            timeoutSeconds: 2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {cpu: 250m, memory: 64Mi}
          volumeMounts:
            - {name: scratch, mountPath: /tmp}
      volumes:
        - name: scratch
          emptyDir: {medium: Memory, sizeLimit: 16Mi}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: w5-runtime}
spec:
  replicas: 1
  selector:
    matchLabels: {app: api}
  template:
    metadata:
      labels: {app: api}
    spec:
      nodeSelector:
        kubernetes.io/hostname: hv-k8s-runtime-worker2
      serviceAccountName: api
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: http
          image: python:3.12.16-slim-bookworm
          imagePullPolicy: Always
          command: [python, -B, -m, http.server, "8080", --bind, "0.0.0.0", --directory, /tmp]
          ports:
            - {name: http, containerPort: 8080}
          readinessProbe:
            httpGet: {path: /, port: http}
            periodSeconds: 2
            timeoutSeconds: 2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {cpu: 250m, memory: 64Mi}
          volumeMounts:
            - {name: scratch, mountPath: /tmp}
      volumes:
        - name: scratch
          emptyDir: {medium: Memory, sizeLimit: 16Mi}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: w5-runtime}
spec:
  type: ClusterIP
  selector: {app: api}
  ports:
    - {name: http, port: 8080, targetPort: http, protocol: TCP}
```

#### File: deny.yaml

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-default, namespace: w5-runtime}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
```

#### File: allow.yaml

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: frontend-to-api, namespace: w5-runtime}
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
metadata: {name: frontend-egress, namespace: w5-runtime}
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

#### File: guard.sh

Source this only from the runtime directory in a fresh Bash session. It checks the dedicated config before every `labk` command; it does not switch the user's normal context. Context names are accident guards, not authentication. TLS still uses kind's generated CA/client credentials. Do not add context/server overrides to `labk` invocations.

```bash
set -euo pipefail
export LAB_DIR="$PWD"
export KUBECTL_KUBERC=false
export KIND_EXPERIMENTAL_PROVIDER=docker
export DOCKER_HOST=unix:///var/run/docker.sock
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export NO_PROXY="${NO_PROXY:-},127.0.0.1,localhost"
export no_proxy="${no_proxy:-},127.0.0.1,localhost"

guard() {
  local context server
  test -f "$LAB_DIR/kubeconfig" || return 1
  context=$(kubectl --kubeconfig "$LAB_DIR/kubeconfig" config current-context) || return 1
  server=$(kubectl --kubeconfig "$LAB_DIR/kubeconfig" --context kind-hv-k8s-runtime \
    config view --minify -o jsonpath='{.clusters[0].cluster.server}') || return 1
  test "$context" = kind-hv-k8s-runtime || return 1
  [[ "$server" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || return 1
}

labk() {
  guard || { printf '%s\n' 'STOP: unexpected kubeconfig/context/server' >&2; return 1; }
  kubectl --kubeconfig "$LAB_DIR/kubeconfig" --context kind-hv-k8s-runtime \
    --cache-dir "$LAB_DIR/cache" --request-timeout=30s "$@"
}
```

#### File: verify_network.py

The host-side harness executes the probe **inside each Pod**, never on the guest network. It obtains fresh IPs, rejects unhealthy/extra replicas, checks loopback health in both Pods, and makes new TCP/HTTP connections without DNS or proxy use. Only an explicit socket timeout matches `TIMEOUT`; refused connections, missing exec permission, bad HTTP status and API errors fail. Five bounded attempts accommodate asynchronous policy programming; a pass needs two consecutive matching matrices, not one transient observation.

```python
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

phase = sys.argv[1] if len(sys.argv) == 2 else ""
if phase not in {"baseline", "deny", "allow"}:
    raise SystemExit("usage: python3 verify_network.py baseline|deny|allow")
directory = Path(os.environ["LAB_DIR"])
base = ["kubectl", "--kubeconfig", str(directory / "kubeconfig"),
        "--context", "kind-hv-k8s-runtime", "--cache-dir", str(directory / "cache"),
        "--request-timeout=10s"]


def command(*args):
    result = subprocess.run(base + list(args), capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


config = json.loads(command("config", "view", "--minify", "-o", "json"))
endpoint = urlsplit(config["clusters"][0]["cluster"]["server"])
if (config["current-context"] != "kind-hv-k8s-runtime"
        or endpoint.scheme != "https" or endpoint.hostname != "127.0.0.1"
        or endpoint.port is None):
    raise SystemExit("STOP: unexpected runtime context/server")

probe = """
import http.client
import sys
connection = http.client.HTTPConnection(sys.argv[1], 8080, timeout=3)
try:
    connection.request('GET', '/')
    response = connection.getresponse()
    if response.status != 200:
        raise RuntimeError('unexpected HTTP status: ' + str(response.status))
    print('HTTP200')
except TimeoutError:
    print('TIMEOUT')
finally:
    connection.close()
"""


def snapshot():
    pods = {}
    for app in ("frontend", "api"):
        items = json.loads(command("-n", "w5-runtime", "get", "pods",
                                   "-l", "app=" + app, "-o", "json"))["items"]
        if len(items) != 1:
            raise RuntimeError("expected exactly one Pod for " + app)
        pod = items[0]
        ready = any(condition["type"] == "Ready" and condition["status"] == "True"
                    for condition in pod["status"].get("conditions", []))
        if not ready or pod["metadata"].get("deletionTimestamp"):
            raise RuntimeError("unhealthy/deleting Pod: " + app)
        pods[app] = (pod["metadata"]["name"], pod["status"]["podIP"])
    service = json.loads(command("-n", "w5-runtime", "get", "service", "api", "-o", "json"))
    return pods, service["spec"]["clusterIP"]


forward = "TIMEOUT" if phase == "deny" else "HTTP200"
reverse = "HTTP200" if phase == "baseline" else "TIMEOUT"
consecutive = 0
for attempt in range(1, 6):
    pods, service_ip = snapshot()
    cases = [("frontend", "127.0.0.1", "HTTP200", "frontend self"),
             ("api", "127.0.0.1", "HTTP200", "api self"),
             ("frontend", pods["api"][1], forward, "frontend -> api Pod"),
             ("frontend", service_ip, forward, "frontend -> api Service"),
             ("api", pods["frontend"][1], reverse, "api -> frontend Pod")]
    matched = True
    for source, address, expected, label in cases:
        actual = command("-n", "w5-runtime", "exec", pods[source][0], "-c", "http", "--",
                         "python", "-B", "-c", probe, address)
        print(phase, attempt, label, actual, "expected=" + expected, flush=True)
        matched = matched and actual == expected
    consecutive = consecutive + 1 if matched else 0
    if consecutive == 2:
        print("PASS", phase)
        break
    time.sleep(2)
else:
    raise SystemExit("FAIL: matrix did not stabilize; inspect health/CNI/policies")
```

### Runtime Setup and Identity Checks

Use a fresh Bash session in the directory containing the eight files. Stop on any unexpected result. This gate is a human approval reminder, not proof the machine is disposable. Confirm its identity against the approved VM inventory first. The local Docker socket override prevents accidental use of a remote Docker context.

```bash
read -r -p 'Approved disposable VM only; type APPROVED-VM: ' approval
test "$approval" = APPROVED-VM || exit 1
source ./guard.sh
umask 077
test ! -e "$LAB_DIR/kubeconfig"
kind version
docker version --format '{{.Client.Version}} {{.Server.Version}}'
docker info --format '{{.OSType}} {{.Architecture}} cgroup={{.CgroupVersion}}'
kubectl version --client -o json
python3 --version
bash --version
curl --version
timeout --version
uname -r
ip -4 route
docker network ls
kind get clusters
```

Require the table's versions, Linux/amd64, cgroup v2, and **no existing kind cluster** in this fresh VM. Inspect any listed Docker network with `docker network inspect NAME` and compare subnets with the guest routes. Do not proceed when the network plan conflicts. In the following setup, `timeout` bounds downloads/creation; do not use `kind --wait` before installing the CNI because nodes initially have no Pod network.

```bash
timeout 600s kind create cluster --name hv-k8s-runtime \
  --kubeconfig "$LAB_DIR/kubeconfig" --config kind.yaml \
  --image kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0
guard
labk get nodes -o wide
docker port hv-k8s-runtime-control-plane 6443/tcp
curl --fail --location --max-time 120 \
  https://raw.githubusercontent.com/projectcalico/calico/v3.31.7/manifests/operator-crds.yaml \
  --output operator-crds.yaml
curl --fail --location --max-time 120 \
  https://raw.githubusercontent.com/projectcalico/calico/v3.31.7/manifests/tigera-operator.yaml \
  --output tigera-operator.yaml
sha256sum operator-crds.yaml tigera-operator.yaml
```

The published API binding must be `127.0.0.1:<port>` only. Nodes initially `NotReady` are expected before CNI installation. Review the two downloaded vendor manifests and their image references before continuing; hashes record retrieved bytes, not publisher authentication. Their privileged infrastructure permissions are confined to this cluster/VM and do not justify weakening the toy namespace.

```bash
labk create -f operator-crds.yaml
labk wait --for=condition=Established crd/installations.operator.tigera.io --timeout=120s
labk create -f tigera-operator.yaml
labk -n tigera-operator rollout status deployment/tigera-operator --timeout=180s
labk apply --dry-run=server --validate=strict -f calico-installation.yaml
labk apply -f calico-installation.yaml
labk wait --for=condition=Ready nodes --all --timeout=300s
labk -n calico-system rollout status daemonset/calico-node --timeout=300s
labk -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
labk -n kube-system rollout status deployment/coredns --timeout=180s
labk get tigerastatus
labk version -o json
labk apply --dry-run=server --validate=strict -f namespace.yaml
labk apply -f namespace.yaml
labk apply --dry-run=server --validate=strict -f workloads.yaml
labk apply -f workloads.yaml
labk -n w5-runtime rollout status deployment/frontend --timeout=180s
labk -n w5-runtime rollout status deployment/api --timeout=180s
labk -n w5-runtime get pods -o wide
labk -n w5-runtime get endpointslices -l kubernetes.io/service-name=api
labk -n w5-runtime get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.serviceAccountName}{" "}{.status.containerStatuses[0].imageID}{"\n"}{end}'
```

Require three Ready nodes, healthy Calico (`AVAILABLE=True`, `DEGRADED=False`), both deployments available, separate worker placement and one ready API endpoint. Server dry-run checks schema/admission requests, not packet enforcement; a Deployment dry-run alone does not prove its Pods pass enforce mode. Real Pod readiness plus inspection is the additional evidence.

The administrator config may impersonate identities **only in this disposable cluster**. Supply the service account's actual groups, including `system:authenticated`, so group-based grants participate in the authorization review. Do not grant impersonation to the toy account, create tokens or weaken RBAC to make a negative check succeed.

```bash
worker_identity=(--as=system:serviceaccount:w5-runtime:worker \
  --as-group=system:serviceaccounts --as-group=system:serviceaccounts:w5-runtime \
  --as-group=system:authenticated)
api_identity=(--as=system:serviceaccount:w5-runtime:api \
  --as-group=system:serviceaccounts --as-group=system:serviceaccounts:w5-runtime \
  --as-group=system:authenticated)

expect_can() {
  local expected="$1" answer status=0
  shift
  answer=$(labk "$@") || status=$?
  printf 'answer=%s exit=%s expected=%s\n' "$answer" "$status" "$expected"
  if [[ "$expected" = yes ]]; then
    [[ "$answer" = yes && "$status" = 0 ]]
  else
    [[ "$answer" = no && "$status" = 1 ]]
  fi
}

expect_can yes "${worker_identity[@]}" -n w5-runtime auth can-i get configmap/settings
expect_can no "${worker_identity[@]}" -n w5-runtime auth can-i list configmaps
expect_can no "${worker_identity[@]}" -n w5-runtime auth can-i get secret/synthetic-secret
expect_can no "${worker_identity[@]}" -n w5-runtime auth can-i create pods
expect_can no "${worker_identity[@]}" -n default auth can-i get configmap/settings
expect_can no "${api_identity[@]}" -n w5-runtime auth can-i get configmap/settings
labk "${worker_identity[@]}" -n w5-runtime get configmap settings -o jsonpath='{.data.mode}{"\n"}'
labk -n w5-runtime get secret synthetic-secret -o name
if denial=$(labk "${worker_identity[@]}" -n w5-runtime get secret synthetic-secret -o name 2>&1); then
  printf '%s\n' 'FAIL: forbidden Secret read succeeded'
  exit 1
else
  printf '%s\n' "$denial"
  [[ "$denial" == *Forbidden* && "$denial" == *system:serviceaccount:w5-runtime:worker* \
     && "$denial" == *'cannot get resource "secrets"'* ]] || exit 1
fi
```

Expected: exactly one `yes`, five `no`, ConfigMap value `toy`, admin existence check `secret/synthetic-secret`, and a `Forbidden` denial for the worker's actual GET. `NotFound`, TLS failure, timeout or inability to impersonate is **not** a passed denial. These are server-side identity authorization checks through impersonation, not tests of token authentication or API reachability from the Pod. No token is mounted, and network policies later deny workload API egress.

### Runtime Connection Matrix and Retest

Predict the table before running. Every target is inside this cluster and uses TCP/8080. Direct Pod/ClusterIP addresses deliberately eliminate DNS as a false-denial explanation. DNS is not allowed after isolation; do not substitute a hostname and interpret its resolution failure as packet enforcement.

| Request source -> destination | Baseline: no policies | Default deny | Narrow allow added | Remove allows / restore allows |
|---|---|---|---|---|
| Frontend -> its loopback | HTTP200 | HTTP200 | HTTP200 | HTTP200 / HTTP200 |
| API -> its loopback | HTTP200 | HTTP200 | HTTP200 | HTTP200 / HTTP200 |
| Frontend -> API Pod IP | HTTP200 | TIMEOUT | HTTP200 | TIMEOUT / HTTP200 |
| Frontend -> API ClusterIP | HTTP200 | TIMEOUT | HTTP200 | TIMEOUT / HTTP200 |
| API -> frontend Pod IP | HTTP200 | TIMEOUT | TIMEOUT | TIMEOUT / TIMEOUT |

```bash
guard
labk -n w5-runtime get networkpolicies
timeout 240s python3 -B verify_network.py baseline
labk apply --dry-run=server --validate=strict -f deny.yaml
labk apply -f deny.yaml
timeout 240s python3 -B verify_network.py deny
labk apply --dry-run=server --validate=strict -f allow.yaml
labk apply -f allow.yaml
timeout 240s python3 -B verify_network.py allow
labk -n w5-runtime describe networkpolicies
labk delete -f allow.yaml
timeout 240s python3 -B verify_network.py deny
labk apply -f allow.yaml
timeout 240s python3 -B verify_network.py allow
```

Require no policies initially, then `PASS baseline`, `PASS deny`, `PASS allow`, `PASS deny`, `PASS allow`. No extra broad allow may exist. The two policy directions jointly authorize the frontend's connection; return packets are implicitly permitted, not permission for API-initiated connections. The matrix proves these observed tuples under this CNI, not isolation of every protocol or independent attribution to each direction. Fresh sockets avoid relying on implementation-defined behavior for established connections.

Record actual versions/image IDs, approved VM identity, manifest hashes, Pod/node/IP mapping, authorization outputs, matrix output and timestamp for each phase. Record failures as failures. Expected observations are not measured results; nothing here marks the user milestones complete.

### Runtime Troubleshooting and Teardown

| Symptom | Discriminating check / bounded action |
|---|---|
| Nodes stay NotReady or Calico degraded | `labk get pods -A`, `labk get tigerastatus`, `labk -n calico-system logs daemonset/calico-node --tail=80`; check matching CIDRs, kernel/prerequisites and vendor pull errors. Stop after the stated timeout; do not turn off firewalls/VPN/security software. |
| Pending / ImagePullBackOff / admission failure | `labk -n w5-runtime get events --sort-by=.metadata.creationTimestamp`; inspect `labk -n w5-runtime describe pods`. Check exact worker names, capacity, approved registry/proxy access and restricted settings. Do not remove admission labels. |
| Baseline or loopback fails | Fix workload readiness first; `labk -n w5-runtime logs deployment/api --tail=40`. A broken server or connection refusal does not establish a denial. |
| Pod IP succeeds, Service fails | Inspect Service selector/port, ready EndpointSlice and kube-proxy health. Do not credit this as NetworkPolicy proof. |
| Denied row succeeds | Inspect effective labels and all policies, Calico health and whether kindnet was actually disabled. Policy objects alone are not enforcement evidence. |
| RBAC result unexpected | Check `labk -n w5-runtime get role,rolebinding -o yaml`, exact impersonated groups and other cluster grants. Do not use the admin result as a substitute. |

For reset, delete only this cluster and recreate from the printed files; do not delete broad sets of Docker resources. Teardown runs in the same approved VM/session. It also works after a failed creation; if no kubeconfig was produced, verify the exact named cluster through `kind get clusters` before deleting it. Never use a stale directory from another run.

```bash
test "$DOCKER_HOST" = unix:///var/run/docker.sock
if test -f "$LAB_DIR/kubeconfig"; then guard; fi
timeout 180s kind delete cluster --name hv-k8s-runtime --kubeconfig "$LAB_DIR/kubeconfig"
kind get clusters
docker ps -a --filter label=io.x-k8s.kind.cluster=hv-k8s-runtime
rm -f -- "$LAB_DIR/kubeconfig"
```

Require the named cluster and its node containers absent. Keep nonsecret observations separately if needed, then discard the disposable VM through its approved lifecycle; this removes downloaded images, cache, manifests and generated cluster credentials without host-wide pruning. No workstation files or protections need cleanup. If cluster deletion fails, stop and dispose of the approved VM; do not escalate on the workstation. Author validation was limited to source/schema review and editor diagnostics: YAML parsing, server dry-runs, Python checks, all cluster commands and matrix results remain unexecuted.

### User-Owned Milestones

- [ ] Local Kubernetes exercise: Use a disposable local cluster to deploy a nonroot app with resource limits and a dedicated service account. Test allowed API actions and a network policy between two toy workloads.
- [ ] Boundary check: From a test service account, attempt a forbidden secret read and require denial. Verify a blocked pod-to-pod connection fails with the chosen CNI.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Kubernetes Security]]

## References

- [Deployments and rollout semantics](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Services](https://kubernetes.io/docs/concepts/services-networking/service/)
- [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Service accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
