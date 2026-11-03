---
title: "BloodHound"
aliases: []
tags: [tools, workflow]
domain: tools
phase: ""
type: method
status: draft
pair: ""
updated: 2026-11-03
---
# BloodHound

> [!abstract] TL;DR
> Treat graph relationships as versioned evidence, not proof of effective authority. Use the offline synthetic OpenGraph fixture to review a document-edit grant and verify its removal while approved reading remains.

> [!info] Agent scope
> Graph model; collection provenance and permissions; query interpretation; evidence validation; sensitive data handling; remediation. This note's executable scope is offline synthetic graph review only: no directory collection, real AD access, or operational privilege-escalation paths.

## Prerequisites

- Required offline lab: Python 3.12 standard library, a plain text editor, and an empty temporary working directory. No AD domain, collector, account credentials, network connection, database, or service is required for its six checks.
- Optional native UI verification: an **already provisioned, isolated** BloodHound Community Edition **8.0.0+ with PostgreSQL graph storage** and an empty synthetic-only dataset, using a local UI account authorized to upload/delete this fixture. Full OpenGraph support has these requirements per current official documentation. Record exact application build/backend/schema; do not infer support from the legacy BloodHound desktop application or a Neo4j tutorial.
- Enterprise findings/metrics and structured-extension pathfinding are distinct features. This lab uses a generic OpenGraph payload for search and review, not attack-path calculations or Enterprise remediation metrics. No installation or service startup is needed for the offline track.

## Learn

```text
Teach me BloodHound at expert graph-evidence and defensive-review depth, using
only offline synthetic data. Assume graph basics, access-control concepts, and
JSON; do not assume an AD lab or a collector. Establish exact CE/Enterprise
version, backend, schema, OpenGraph support, and read/query/upload permissions.
Explain stable node identity versus display names, labels, directed relationship
semantics, membership versus grants versus observed sessions, raw versus derived
edges, provenance, source coverage, collection failure, timestamps and staleness.
Discuss collection permissions and completeness only conceptually: no commands
to contact or collect from a directory. Show actual BloodHound Explore/Cypher
workflows, typed bounded patterns, nulls, duplicates, DISTINCT, result limits,
and why unsupported Neo4j syntax/procedures are not portable to CE. Explain
generic OpenGraph versus structured extensions and why graph search is not
proof of effective rights or a successful operation.
Build complete synthetic before/after JSON payloads for a document-edit access
review, with unique snapshot IDs and a registered source_kind. Supply Python
3.12 stdlib checks and exact Cypher queries with expected rows. Remove one
unapproved document-edit grant and preserve approved reading. Explain stale
evidence, source merge/deletion semantics, import validation, and why deleting a
database edge is not a real-world remediation. Include independent setup,
hints, worked solution, evidence, cleanup and unverified UI/version limits.
No operational escalation paths, real AD collection, credential handling,
external uploads, or real corporate data. Use SpecterOps primary documentation.
Teach here, not by editing notes or study status.
```

## Cheatsheet

### Model and Evidence Boundaries

| Element | Meaning | Review requirement |
|---|---|---|
| Node ID | Stable identity; not the human-readable name | Built-in directory schemas use appropriate immutable identifiers. Synthetic OpenGraph IDs here are snapshot-qualified strings, never real SIDs. |
| Node kind/label | Type available to Cypher matching | Use `HV_` names to avoid built-in/reserved namespaces. A label is not an OS account or authority claim. |
| Directed edge | A precisely defined relationship from source to destination | Do not reverse membership or treat a session observation as an enduring ACL. Read the edge's documented semantics. |
| Derived edge | Computed during post-processing from supporting relationships | It can disappear/reappear when supporting data changes; do not directly inject built-in derived edges as an import shortcut. |
| Missing edge | Absent from this graph at this time | Could mean no right, uncollected data, denied collection, parser failure, expiry, or a filter. |
| Path | Composition of the specified relations under the graph model | A graph match is not a permitted or completed operation. Conditions and current evidence need independent validation. |

Collection is a separate authorization boundary: directory queries, endpoint observations, and cloud APIs require different permissions and coverage. A successful import does not certify complete collection; a collector failure must remain in the provenance record. This exercise runs no collector and makes no live access claim.

For real defensive reviews, retain schema/collector versions, methods, permitted scope, observation time, failures, source identifier, ingestion time, and policy evidence. An ingest-generated `lastseen` reflects ingestion, not necessarily when a right was observed. Here the explicit `observed_at` field is synthetic fixture provenance and remains distinct from BloodHound's own metadata.

### Actual BloodHound Workflow

1. Inspect About/version and the backend recorded by the lab administrator. Old desktop/Neo4j screenshots and CE query interfaces are not interchangeable. Do not query or alter a backing database directly.
2. Upload only the generated OpenGraph JSON through the UI's data-upload action (commonly Administration -> File Ingest). Require successful ingest status; queued/failed/partially processed data is not ready evidence.
3. Explore -> Cypher: use a narrow kind and snapshot filter; disable automatic running of selected saved queries when reviewing unfamiliar queries. Run the exact read-only patterns below.
4. Click a node/edge and inspect its Entity Panel properties and direction. Compare the returned graph with the offline fixture's IDs and approval record.
5. Save a private lab query with a descriptive title and snapshot scope. Query export JSON is **not graph data JSON**. Do not upload one as the other or share queries/datasets publicly by default.

CE implements a documented Cypher subset; do not assume arbitrary Neo4j procedures, APOC, database writes, or query-plan commands work. `LIMIT` bounds returned rows, not necessarily search cost. Unbounded variable-length traversals and Cartesian matches can still be expensive. Typed, directed, bounded patterns with explicit start/snapshot filters are preferable. `DISTINCT` deduplicates results but does not prove complete coverage. Null/missing properties are not the same as false; make missing approval evidence an explicit review category.

### Review Queries for This Fixture

These are real read-only Cypher queries for the supplied **custom OpenGraph kinds**, not built-in AD privilege queries. `HV_MemberOf` means membership in a fictional documentation team; `HV_CanEdit`/`HV_CanRead` describe an intended document policy, not an actual Windows permission.

**Q1: inventory one snapshot** (expect five nodes):

```cypher
MATCH (entity:HV_Entity)
WHERE entity.snapshot = 'before'
RETURN entity
LIMIT 20
```

**Q2: unapproved direct document-edit grant** (before: one relationship; after: none):

```cypher
MATCH review=(team:HV_Team)-[grant:HV_CanEdit]->(document:HV_Document)
WHERE team.snapshot = 'before' AND grant.approved = false
RETURN review
LIMIT 20
```

Run the same query with `'after'` replacing `'before'`. Require the Q1 inventory with `'after'` still to return five nodes, so an empty result cannot be explained by importing nothing.

**Q3: approved membership-mediated reading** (one path per snapshot):

```cypher
MATCH review=(person:HV_Person)-[:HV_MemberOf]->(team:HV_Team)-[grant:HV_CanRead]->(document:HV_Document)
WHERE person.snapshot = 'after' AND grant.approved = true
RETURN review
LIMIT 20
```

**Q4: stale recorded relationship** (before: one; repeat for after: one):

```cypher
MATCH review=(source:HV_Entity)-[relationship]->(target:HV_Entity)
WHERE source.snapshot = 'before' AND relationship.observed_at < '2026-11-02T00:00:00Z'
RETURN review
LIMIT 20
```

The string comparison works because every fixture timestamp has the same UTC ISO format/precision. It is not a generic timestamp parser. Missing timestamps need a separate `IS NULL` query; they must not silently count as fresh. Inspect result properties if your build's graph-only rendering does not expose tabular projections.

### Import, Trust, and Remediation

OpenGraph requires `graph.nodes` and `graph.edges`; nodes have `id`, `kinds`, and primitive-valued properties; edges have `start`, `end`, `kind`, and optional properties. IDs map internally to `objectid`; do not also put `objectid` into properties. Use `match_by: id`, not deprecated name matching. Current docs discourage colons in IDs and reserve tag-related kinds. Names can be uppercased during ingest; use stable IDs or the exact snapshot field for comparisons.

Top-level `metadata.source_kind` registers/applies the fixture's source label. Do not add arbitrary metadata fields there. This lab uses two explicit snapshots with different IDs because uploading a file that omits an edge need not remove a previously imported edge. Snapshot separation is an evidence technique, not a recommended replacement for production reconciliation.

A remediation claim needs an owner-approved policy change, evidence the excessive grant is removed, unchanged legitimate access, and a fresh observation with comparable coverage. Deleting a visual edge, hiding a relationship, or removing data from BloodHound changes the model, not the underlying system. Here the change is solely to a self-authored document-policy fixture; no real directory remediation is claimed.

## Gotchas

- Upload success and graph rendering are distinct checks. A stale query filter can make newly ingested data look absent.
- Generic OpenGraph search does not automatically supply structured-extension traversal semantics or Enterprise findings. Do not invent a numeric risk score from this dataset.
- A graph database or exported JSON can reveal relationships even without passwords. Use only these synthetic identities, never a personal copy of corporate directory data.

## Labs

### Environment and Complete File

Save this file in an empty temporary directory. It constructs actual generic OpenGraph payloads, validates the deliberately narrow fixture contract, and checks the same review predicates as Q1..Q4. It is an offline oracle, **not a Cypher interpreter or BloodHound substitute**. No socket/client/collector is used.

### File: test_example.py

```python
import argparse
import copy
import json
from pathlib import Path
import unittest


SOURCE = "HV_LabReview_20261103"
FRESH = "2026-11-03T00:00:00Z"
STALE = "2026-10-01T00:00:00Z"
CUTOFF = "2026-11-02T00:00:00Z"


def build(snapshot):
	if snapshot not in {"before", "after"}:
		raise ValueError("Unknown snapshot")
	kinds = {"alice": "HV_Person", "ben": "HV_Person", "editors": "HV_Team",
			 "readers": "HV_Team", "handbook": "HV_Document"}
	nodes = [{"id": f"HV-20261103-{snapshot}-{name}",
			  "kinds": [kind, "HV_Entity"],
			  "properties": {"name": name.upper(), "snapshot": snapshot}}
			 for name, kind in kinds.items()]

	def edge(start, end, kind, approved=True, observed_at=FRESH):
		return {"start": {"match_by": "id", "value": f"HV-20261103-{snapshot}-{start}"},
				"end": {"match_by": "id", "value": f"HV-20261103-{snapshot}-{end}"},
				"kind": kind,
				"properties": {"approved": approved, "observed_at": observed_at,
							   "evidence": "self-authored-document-policy"}}

	edges = [edge("alice", "editors", "HV_MemberOf"),
			 edge("ben", "readers", "HV_MemberOf"),
			 edge("readers", "handbook", "HV_CanRead"),
			 edge("alice", "handbook", "HV_CanRead", observed_at=STALE)]
	if snapshot == "before":
		edges.append(edge("editors", "handbook", "HV_CanEdit", approved=False))
	return {"metadata": {"source_kind": SOURCE},
			"graph": {"nodes": nodes, "edges": edges}}


def validate(payload):
	if payload["metadata"] != {"source_kind": SOURCE}:
		raise ValueError("Unexpected source")
	nodes = payload["graph"]["nodes"]
	identifiers = [node["id"] for node in nodes]
	if len(set(identifiers)) != len(identifiers):
		raise ValueError("Duplicate node ID")
	for node in nodes:
		if ":" in node["id"] or not 1 <= len(node["kinds"]) <= 3:
			raise ValueError("Invalid fixture node")
		if "objectid" in node.get("properties", {}):
			raise ValueError("Reserved property")
	for edge in payload["graph"]["edges"]:
		if edge["kind"] not in {"HV_MemberOf", "HV_CanRead", "HV_CanEdit"}:
			raise ValueError("Unexpected relation")
		for endpoint in ("start", "end"):
			if edge[endpoint]["match_by"] != "id" or edge[endpoint]["value"] not in identifiers:
				raise ValueError("Dangling endpoint")
		properties = edge["properties"]
		if type(properties.get("approved")) is not bool:
			raise ValueError("Missing approval evidence")
		if properties.get("observed_at") not in {FRESH, STALE}:
			raise ValueError("Unexpected fixture observation time")


def unapproved_edits(payload):
	return [edge for edge in payload["graph"]["edges"]
			if edge["kind"] == "HV_CanEdit" and edge["properties"]["approved"] is False]


def approved_readers(payload):
	edges = payload["graph"]["edges"]
	return sorted({membership["start"]["value"]
				   for membership in edges if membership["kind"] == "HV_MemberOf"
				   for grant in edges if grant["kind"] == "HV_CanRead"
				   and grant["start"]["value"] == membership["end"]["value"]
				   and grant["properties"]["approved"] is True})


class ExampleTests(unittest.TestCase):
	def test_inventory(self):
		for snapshot, edge_count in (("before", 5), ("after", 4)):
			payload = build(snapshot)
			validate(payload)
			self.assertEqual(len(payload["graph"]["nodes"]), 5)
			self.assertEqual(len(payload["graph"]["edges"]), edge_count)

	def test_grant_removed(self):
		self.assertEqual(len(unapproved_edits(build("before"))), 1)
		self.assertEqual(unapproved_edits(build("after")), [])

	def test_approved_read_preserved(self):
		for snapshot in ("before", "after"):
			self.assertEqual(approved_readers(build(snapshot)),
							 [f"HV-20261103-{snapshot}-ben"])

	def test_stale_not_fresh(self):
		for snapshot in ("before", "after"):
			stale = [edge for edge in build(snapshot)["graph"]["edges"]
					 if edge["properties"]["observed_at"] < CUTOFF]
			self.assertEqual(len(stale), 1)
			self.assertEqual(stale[0]["kind"], "HV_CanRead")

	def test_dangling_endpoint_rejected(self):
		payload = copy.deepcopy(build("before"))
		payload["graph"]["edges"][0]["end"]["value"] = "HV-missing"
		with self.assertRaisesRegex(ValueError, "Dangling"):
			validate(payload)

	def test_roundtrip_and_disjoint_snapshots(self):
		before, after = build("before"), build("after")
		self.assertEqual(json.loads(json.dumps(before)), before)
		self.assertTrue({node["id"] for node in before["graph"]["nodes"]}.isdisjoint(
						{node["id"] for node in after["graph"]["nodes"]}))


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--write", action="store_true")
	options = parser.parse_args()
	if options.write:
		output = Path("generated")
		output.mkdir(exist_ok=False)
		for snapshot in ("before", "after"):
			payload = build(snapshot)
			validate(payload)
			(output / f"{snapshot}.json").write_text(
				json.dumps(payload, indent=2) + "\n", encoding="utf-8")
			print(snapshot, "nodes=", len(payload["graph"]["nodes"]),
				  "edges=", len(payload["graph"]["edges"]),
				  "unapproved_edits=", len(unapproved_edits(payload)),
				  "readers=", approved_readers(payload))
	else:
		unittest.main(argv=[__file__], verbosity=2)
```

### Objectives and Steps

Commands for the learner (offline, no dependency install):

```powershell
py -3.12 --version
py -3.12 test_example.py
py -3.12 test_example.py --write
py -3.12 -m json.tool generated/before.json
py -3.12 -m json.tool generated/after.json
Get-FileHash generated/before.json, generated/after.json -Algorithm SHA256
```

1. Require six passing tests. Inspect both generated files. For each, count nodes/edges and resolve the two endpoints of every edge; no external seed file is needed.
2. Treat the fixture's `approved` values as the supplied owner decision record. Identify the unapproved edit grant in before, the one-edge removal in after, the preserved approved reader, and the stale direct-read observation. Write a review conclusion using IDs, not inferred real accounts.
3. Manually evaluate Q1..Q4 from the JSON, then compare with the Python assertions. Do not claim this executes Cypher.
4. Optional UI track, only in the already provisioned synthetic instance: verify the source label is unused, upload both files using the data-upload UI, and wait for successful ingest. Run Q1..Q4 in Explore -> Cypher and compare expected results below. No collector, directory credentials, or real domain is involved.
5. Record whether the UI track was performed. A fixture test success does not establish backend support, ingest success, or query execution.

### Hints

- The stale direct read by Alice is intentionally retained in both snapshots; removal of an unapproved edit grant must not silently turn old observations into fresh evidence.
- The readers team and Ben's membership remain. Their permitted documentation reading is the positive regression check.
- If Q2 after returns an edge, inspect the node's snapshot and IDs first; do not delete broad database contents to make the query pass.

### Solution and Expected Results

| Check | Before | After |
|---|---|---|
| Nodes | 5 | 5 |
| Edges | 5 | 4 |
| Q2 unapproved edit | Editors -> Handbook, one edge | None |
| Q3 approved team-mediated reader | Ben -> Readers -> Handbook | Same logical relationship, after-qualified IDs |
| Q4 stale observation | Alice -> Handbook direct read, 2026-10-01 | Same stale observation |

The combined import has **10 distinct nodes and 9 edges** for these fixture kinds. The conclusion is: the proposed document-policy snapshot removes one unapproved edit grant while preserving approved reading; the old direct-read observation still needs refresh. It does **not** prove a real AD right, operation, session, or remediation.

### Verification, Troubleshooting, and Cleanup

Expected **6 unittest tests**, JSON parse checks for **2 payloads**, and optional **4 query families** against the documented result table. The validator enforces this fixture's contract, not the entire official OpenGraph JSON Schema. UI schema rejection is an independent failure to investigate.

`generated` already exists: inspect it, then use a new temporary directory rather than overwrite evidence. Import rejection: check CE/backend requirements, encoding, reserved fields, endpoint IDs, and ingest errors. Generic graphs may show default icons; that is not data loss. For cleanup, delete only this lab's generated directory/files. In the optional dedicated instance use Administration -> Database Management and select only the registered source `HV_LabReview_20261103`; do not choose all data or Sourceless data. Confirm the fixture-kind query returns no nodes afterward. If the build lacks source-scoped deletion, revert the **dedicated disposable instance's** clean snapshot, not a shared database.

Author validation: official schema reviewed; **no Python tests, graph upload, Cypher execution, installation, or service startup performed**. Version-specific UI ingestion/query rendering remains unverified.

- [ ] Local BloodHound exercise: Generate and review both synthetic OpenGraph snapshots; record offline checks separately from optional UI verification.
- [ ] Boundary check: Verify the unapproved document-edit grant is absent after remediation while the approved reading relationship remains.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Tools Index]]

## References

- [BloodHound documentation](https://bloodhound.specterops.io/)
- [Search with Cypher](https://bloodhound.specterops.io/analyze-data/cypher-search)
- [Supported Cypher syntax](https://bloodhound.specterops.io/analyze-data/explore/cypher-supported)
- [OpenGraph data and version/backend requirements](https://bloodhound.specterops.io/opengraph/developer/graph-data)
- [OpenGraph nodes](https://bloodhound.specterops.io/opengraph/developer/nodes)
- [OpenGraph edges](https://bloodhound.specterops.io/opengraph/developer/edges)
- [OpenGraph metadata and source-scoped management](https://bloodhound.specterops.io/opengraph/developer/metadata)
