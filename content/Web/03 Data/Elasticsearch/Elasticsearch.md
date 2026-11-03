---
title: "Elasticsearch"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[Elasticsearch Security]]"
updated: 2026-11-03
---
# Elasticsearch

> [!abstract] TL;DR
> Define mappings, constrain query shapes, limit result sizes, and use narrow index privileges. Do not expose the cluster directly as an unfiltered public search API.

> [!info] Agent scope
> Documents; mappings; search DSL; indexes; cluster interfaces; authentication; index privileges; resource limits.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Elasticsearch 8.x application search assuming JSON/HTTP and indexes.
Explain documents, Lucene segments, shards/replicas, refresh versus durability,
text analyzers, keyword fields, explicit mappings, nested objects and doc values.
Trace match/term/bool filters, scoring, aggregation costs, stable pagination,
optimistic concurrency and reindex/alias migrations. Cover authentication,
index privileges and bounded search APIs. Build a complete local mapped-index
fixture with separate admin/app identities and text-versus-keyword assertions.
Use official sources and version caveats; do not imply a dev single node is HA.
Teach here with worked answers, not file edits or fabricated execution results.
```

## Cheatsheet

### Storage and Visibility

An index consists of primary shards and optional replicas; each shard is a Lucene index with immutable segments and merges. A document write can be acknowledged before it is visible to search. Refresh opens searchable segments; flush/translog durability is a different mechanism. Use `refresh=wait_for` when a workflow needs the next search to observe a write, not `refresh=true` on every high-volume update. A single node with zero replicas demonstrates APIs, not availability.

Updates internally replace document versions; large frequently rewritten documents cost work. Use `_seq_no` and `_primary_term` with conditional writes to detect stale updates. Bulk API requests can return HTTP 200 while individual items fail; inspect every item and retry only eligible operations with stable IDs.

### Mapping and Query Semantics

| Mapping/query | Behavior |
|---|---|
| `text` + `match` | Analyzer tokenizes query and documents; relevance scoring is meaningful. |
| `keyword` + `term` | Exact term comparison; suitable for tenant IDs, states and facets. |
| Numeric/date fields | Typed range queries; date parsing format/timezone must be explicit. |
| `object` arrays | Field values can flatten across object boundaries; correlated predicates may need `nested`. |
| `dynamic: strict` | Rejects unmapped fields; avoids accidental mapping growth, but requires coordinated schema evolution. |
| `doc_values` | Column-oriented access for supported fields, useful for aggregations/sorts; enabling fielddata on text can consume large heap. |

```json
{
	"size": 20,
	"_source": ["title", "state"],
	"query": {"bool": {
		"must": [{"match": {"title": "distributed systems"}}],
		"filter": [{"term": {"tenant": "t7"}}, {"term": {"state": "open"}}]
	}},
	"sort": [{"created_at": "desc"}, {"document_id": "asc"}]
}
```

This fragment assumes corresponding date/keyword mappings. Filters constrain membership without contributing relevance scores. A `term` against analyzed text compares indexed terms, not original phrases. Set `track_total_hits` deliberately: exact totals have cost and default result metadata may be a lower bound.

### Cost, Pagination, and Evolution

`from`+`size` deep paging requires collecting/discarding earlier hits; use `search_after` with a stable sort and point-in-time search for consistent walks. PITs hold resources and must be closed. Result-window limits, bucket limits and circuit breakers cover different costs. A request timeout is not a guarantee of immediate cancellation; check `timed_out` and shard failures. `_source` filtering reduces response data, not necessarily every storage read.

Mapping type changes generally require a new index and reindexing. Use a reviewed alias swap for cutover, reconcile concurrent writes and retain a rollback plan. Aliases route queries but filtered aliases are not a complete authorization boundary. Manage shard count deliberately: too many small shards waste heap and coordination overhead.

Separate index provisioning from runtime search. Grant app `read` on named indexes, not cluster `all` or broad wildcards. API keys have privileges constrained by their owner and descriptor intersection; they are bearer credentials. Elasticsearch 8 security auto-configuration is deployment-dependent; explicit custom Docker settings can skip defaults. Remote production HTTP and transport channels require appropriate TLS verification.

## Gotchas

An alias or application-side filter does not automatically provide robust tenant isolation. Search results may lag writes according to refresh behavior.

## Labs

### Environment and Complete Files

Python 3.12+ stdlib, PowerShell and Docker Linux containers with enough memory for Elasticsearch. The published `8.19.0` image is a named API baseline, not a claim of latest patch or production suitability; review supported patched releases before deployment and record digest/version. **Not executed here.** If the host fails bootstrap checks, use an approved development environment; do not change host kernel limits as part of this exercise. Port 19200 must be free.

This loopback-only fixture explicitly disables HTTP TLS but retains authentication. Do not expose it remotely or use real secrets. Production TLS behavior is not validated by it.

### File: setup.py
```python
import base64
import json
import urllib.request

BASE = "http://127.0.0.1:19200"
TOKEN = base64.b64encode(b"elastic:Admin-lab-only-819!").decode()

def send(method, path, body):
	request = urllib.request.Request(BASE + path, json.dumps(body).encode(),
		{"Authorization": "Basic " + TOKEN, "Content-Type": "application/json"}, method=method)
	with urllib.request.urlopen(request, timeout=30) as response:
		return json.load(response)

mapping = {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
	"mappings": {"dynamic": "strict", "properties": {
		"title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
		"tenant": {"type": "keyword"}, "price": {"type": "integer"}
	}}}
send("PUT", "/w3-books", mapping)
send("PUT", "/w3-operator", {"settings": {"number_of_replicas": 0}})
send("PUT", "/w3-books/_doc/1?refresh=wait_for", {"title": "Distributed Systems", "tenant": "t7", "price": 25})
send("PUT", "/w3-books/_doc/2?refresh=wait_for", {"title": "Local Storage", "tenant": "t7", "price": 10})
send("PUT", "/_security/role/book_reader", {"cluster": [], "indices": [{"names": ["w3-books"], "privileges": ["read"]}]})
send("POST", "/_security/user/searchapp", {"password": "App-lab-only-819!", "roles": ["book_reader"]})
print("Seeded two documents and search-only identity")
```

### File: test_example.py
```python
import base64
import json
import unittest
import urllib.error
import urllib.request

TOKEN = base64.b64encode(b"searchapp:App-lab-only-819!").decode()

def search(index, query, size=10):
	if type(size) is not int or not 1 <= size <= 20:
		raise ValueError("page size 1..20 required")
	request = urllib.request.Request("http://127.0.0.1:19200/" + index + "/_search",
		json.dumps({"query": query, "size": size, "track_total_hits": True, "timeout": "1s"}).encode(),
		{"Authorization": "Basic " + TOKEN, "Content-Type": "application/json"}, method="POST")
	with urllib.request.urlopen(request, timeout=5) as response:
		result = json.load(response)
	if result["timed_out"] or result["_shards"]["failed"]:
		raise RuntimeError("incomplete search")
	return result["hits"]["hits"]

class SearchMechanisms(unittest.TestCase):
	def test_analysis(self):
		self.assertEqual(len(search("w3-books", {"match": {"title": "distributed"}})), 1)
		self.assertEqual(search("w3-books", {"term": {"title.raw": "distributed"}}), [])
		self.assertEqual(len(search("w3-books", {"term": {"title.raw": "Distributed Systems"}})), 1)
		self.assertEqual(len(search("w3-books", {"range": {"price": {"lte": 10}}})), 1)

	def test_boundaries(self):
		with self.assertRaises(ValueError):
			search("w3-books", {"match_all": {}}, 21)
		with self.assertRaises(urllib.error.HTTPError) as denied:
			search("w3-operator", {"match_all": {}})
		self.assertEqual(denied.exception.code, 403)

if __name__ == "__main__":
	unittest.main()
```

```powershell
docker run --name w3-es-tech -d -p 127.0.0.1:19200:9200 -m 2g -e discovery.type=single-node -e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=false -e ELASTIC_PASSWORD=Admin-lab-only-819! -e 'ES_JAVA_OPTS=-Xms512m -Xmx512m' docker.elastic.co/elasticsearch/elasticsearch:8.19.0
curl.exe --fail -u elastic:Admin-lab-only-819! http://127.0.0.1:19200/
python setup.py
python test_example.py -v
```

### Objectives, Hints, and Solution

Retry the curl readiness command manually until it returns server metadata. Predict analyzed versus exact matches and why refresh waiting matters. Expected: two tests pass; lowercase analyzed search matches, lowercase exact keyword does not, full exact keyword does, and the limited role receives 403 on the operator index. Hint: a projection/filter cannot replace the role's index boundary.

### Troubleshooting and Cleanup

401 means authentication failed, not index denial. A connection refusal means startup/port trouble; inspect container logs. Setup is for a fresh fixture, not an idempotent migration. The lab helper accepts internal query objects for tests; it must not be exposed as arbitrary public DSL. Remove only the container/data volume:

```powershell
docker rm -f -v w3-es-tech
```

- [ ] Local Elasticsearch exercise: Index synthetic records with explicit mappings and query them using a restricted role. Compare text and keyword behavior and enforce a bounded page size.
- [ ] Boundary check: Use the app identity to query an unrelated index and submit an over-limit aggregation in a disposable cluster; require denial or controlled rejection.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Elasticsearch Security]]

## References

- [Elasticsearch 8.19 Docker guidance](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/docker.html)
- [Mapping](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/mapping.html)
- [Near-real-time search](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/near-real-time.html)
- [Security privileges](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/security-privileges.html)
