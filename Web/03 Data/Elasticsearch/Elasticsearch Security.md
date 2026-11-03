---
title: "Elasticsearch Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[Elasticsearch]]"
updated: 2026-11-03
---
# Elasticsearch Security

> [!abstract] TL;DR
> Unauthenticated clusters, overbroad roles, arbitrary DSL submission, and expensive queries can disclose data or exhaust resources.

> [!info] Agent scope
> Security of: Documents; mappings; search DSL; indexes; cluster interfaces; authentication; index privileges; resource limits. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unauthenticated clusters, overbroad roles, arbitrary DSL submission, and expensive queries can disclose data or exhaust resources.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Elasticsearch 8.x security assuming JSON/HTTP and search basics.
Trace application query building, authentication, cluster/index privileges,
aliases, document/field-level controls and shard execution. Explain why filtered
aliases and caller-selected DSL are insufficient tenant boundaries. Cover exact
role scopes, API-key ownership, TLS, body/page/bucket/time budgets, script and
wildcard costs, audit availability and incomplete responses. Build a tiny local
policy lab with separate admin/app identities, broad-role baseline, narrow fix
and bounded aggregation rejection. No data theft, resource attacks or escalation.
Use official sources and version caveats; teach without edits or invented runs.
```

## Cheatsheet

### Enforce Index and Query Boundaries

Cluster privileges and index privileges are separate. A search-only service rarely needs cluster management, index creation, document writes or security APIs. Scope roles to exact index names or a carefully controlled naming scheme; a broad wildcard can silently include a new sensitive index. An alias filter is a routing convenience, not a universal authorization rule across all APIs.

Build public searches from a small typed contract, for example `{term: string, page_size: integer}`. Set the index, field names, tenant filter and `_source` projection in trusted code. Do not forward arbitrary DSL, scripts, aggregation definitions, index names or `_msearch` bodies from callers. Even valid JSON may express costly or overbroad work. Field hiding in the response is not a substitute for authorized access.

```json
{
	"cluster": [],
	"indices": [{"names": ["catalog-public"], "privileges": ["read"]}]
}
```

This role body allows reads only on one index; application tenant authorization remains necessary if that index mixes tenants. Document/field-level security capabilities depend on license and deployment. Role combinations can broaden effective access; test the final identity rather than reviewing one role in isolation. API keys are bearer secrets with privileges constrained by their owner/descriptor; rotation and expiration are separate lifecycle tasks.

### Resource Budgets

| Layer | Concrete control / limitation |
|---|---|
| HTTP/application | Bound body bytes, string lengths, page size, concurrency and result fields. Reject before issuing a cluster request. |
| Search request | `timeout`, bounded `size`, fixed sorts; inspect `timed_out` and shard failures, because HTTP 200 can be incomplete. |
| Aggregations | `search.max_buckets` limits bucket counts, not every query's CPU or memory. |
| Cluster | Circuit breakers, result-window limits and supported expensive-query settings; not a per-user quota system. |
| Pagination | PIT plus `search_after` for stable deep walks; close PITs and bound lifetime/concurrency. |

Avoid arbitrary regex/wildcard and runtime-script endpoints. Turning off all expensive queries can break legitimate application features; use policy tests and measured query plans. A client timeout may disconnect without instantly cancelling every shard task. Handle partial results explicitly rather than silently treating them as authoritative.

Enable verified HTTP/transport TLS in real deployments, protect snapshots and never expose cluster-management interfaces directly to a public frontend. Custom Elasticsearch 8 configuration can bypass auto-security setup. The lab deliberately uses authenticated plaintext only on host loopback; it does not certify production transport security.

## Detection and Defense

Monitor 401 versus 403, rejected searches, circuit-breaker trips, slow logs, shard failures and security-role changes. Audit logging availability varies by license/configuration; do not assume every denied action is retained. Query logs can contain personal data, so use redaction and bounded retention. A bucket-limit test should use a few synthetic documents and a tiny configured threshold, never a large resource-exhaustion workload.

## Labs

### Environment and Complete Files

Python 3.12+ stdlib, PowerShell, Docker Linux containers and sufficient memory. Published image `8.19.0` is an explicit API baseline, not a current security-patch recommendation; record digest/version and vet patched deployment versions separately. **Not executed here.** Port 19201 must be free. No host kernel settings are changed; unmet bootstrap checks require an approved compatible environment. Authentication is enabled; TLS is disabled only for this loopback fixture.

### File: admin.py
```python
import base64
import json
import sys
import urllib.request

TOKEN = base64.b64encode(b"elastic:Admin-lab-only-819!").decode()
def send(method, path, body):
	request = urllib.request.Request("http://127.0.0.1:19201" + path, json.dumps(body).encode(),
		{"Authorization": "Basic " + TOKEN, "Content-Type": "application/json"}, method=method)
	with urllib.request.urlopen(request, timeout=30) as response:
		return json.load(response)

fixed = "--fix" in sys.argv
if not fixed:
	send("PUT", "/w3-public", {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
		"mappings": {"dynamic": "strict", "properties": {"category": {"type": "keyword"}}}})
	send("PUT", "/w3-operator", {"settings": {"number_of_replicas": 0}})
	for identifier, category in enumerate(["alpha", "beta", "gamma", "delta"]):
		send("PUT", f"/w3-public/_doc/{identifier}?refresh=wait_for", {"category": category})
	send("PUT", "/_cluster/settings", {"persistent": {"search.max_buckets": 3}})
send("PUT", "/_security/role/app_reader", {"cluster": [], "indices": [
	{"names": ["w3-public"] if fixed else ["w3-*"], "privileges": ["read"]}]})
if not fixed:
	send("POST", "/_security/user/searchapp", {"password": "App-lab-only-819!", "roles": ["app_reader"]})
print("fixed role" if fixed else "baseline seeded")
```

### File: test_example.py
```python
import base64
import json
import unittest
import urllib.error
import urllib.request

TOKEN = base64.b64encode(b"searchapp:App-lab-only-819!").decode()
def request(index, body):
	message = urllib.request.Request("http://127.0.0.1:19201/" + index + "/_search",
		json.dumps(body).encode(), {"Authorization": "Basic " + TOKEN,
		"Content-Type": "application/json"}, method="POST")
	with urllib.request.urlopen(message, timeout=5) as response:
		result = json.load(response)
	if result["timed_out"] or result["_shards"]["failed"]:
		raise RuntimeError("incomplete response")
	return result

def public_search(payload):
	if not isinstance(payload, dict) or set(payload) != {"term", "page_size"}:
		raise ValueError("unsupported fields")
	if not isinstance(payload["term"], str) or not 1 <= len(payload["term"]) <= 40:
		raise ValueError("term length")
	if type(payload["page_size"]) is not int or not 1 <= payload["page_size"] <= 20:
		raise ValueError("page size")
	return request("w3-public", {"query": {"term": {"category": payload["term"]}},
		"size": payload["page_size"], "_source": ["category"], "timeout": "1s"})

class SearchPolicy(unittest.TestCase):
	def test_index_boundary(self):
		with self.assertRaises(urllib.error.HTTPError) as denied:
			request("w3-operator", {"size": 0})
		self.assertEqual(denied.exception.code, 403)

	def test_allowed_and_input_bounds(self):
		result = public_search({"term": "alpha", "page_size": 10})
		self.assertEqual(len(result["hits"]["hits"]), 1)
		with self.assertRaises(ValueError):
			public_search({"term": "alpha", "page_size": 21})
		with self.assertRaises(ValueError):
			public_search({"term": "alpha", "page_size": 10, "aggs": {}})

	def test_tiny_bucket_budget(self):
		with self.assertRaises(urllib.error.HTTPError) as limited:
			request("w3-public", {"size": 0, "aggs": {"categories": {"terms": {"field": "category", "size": 4}}}})
		details = limited.exception.read().decode()
		self.assertIn("too_many_buckets_exception", details)

if __name__ == "__main__":
	unittest.main()
```

### Baseline, Hints, and Solution

```powershell
docker run --name w3-es-sec -d -p 127.0.0.1:19201:9200 -m 2g -e discovery.type=single-node -e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=false -e ELASTIC_PASSWORD=Admin-lab-only-819! -e 'ES_JAVA_OPTS=-Xms512m -Xmx512m' docker.elastic.co/elasticsearch/elasticsearch:8.19.0
curl.exe --fail -u elastic:Admin-lab-only-819! http://127.0.0.1:19201/
python admin.py
python test_example.py -v
python admin.py --fix
python test_example.py -v
```

Retry readiness manually. Baseline fails exactly the index-boundary test because `w3-*` includes an empty operator index. Fixed run passes all three tests. The four-document aggregation exceeds the deliberately tiny three-bucket limit, while approved scalar search succeeds. Hint: empty results from an unauthorized index are still a permission failure, not isolation.

### Troubleshooting and Cleanup

The bucket assertion checks the response error type, not any generic failure. Missing credentials, connection errors and startup failures cannot satisfy it. Roles are changed by the admin script only; the test uses app credentials. The cluster setting is fixture-wide and must not be applied to a shared cluster. Cleanup removes only this disposable instance:

```powershell
docker rm -f -v w3-es-sec
```

- [ ] Local Elasticsearch exercise: Index synthetic records with explicit mappings and query them using a restricted role. Compare text and keyword behavior and enforce a bounded page size.
- [ ] Boundary check: Use the app identity to query an unrelated index and submit an over-limit aggregation in a disposable cluster; require denial or controlled rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Elasticsearch]]

## References

- [Security privileges](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/security-privileges.html)
- [Bucket aggregation limits](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/search-aggregations-bucket.html)
- [Security limitations](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/security-limitations.html)
