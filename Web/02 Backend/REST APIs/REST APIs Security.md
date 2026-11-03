---
title: "REST APIs Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[REST APIs]]"
updated: 2026-11-03
---
# REST APIs Security

> [!abstract] TL;DR
> Broken object authorization, overposting, excessive data exposure, and unbounded operations are independent of how predictable an identifier is.

> [!info] Agent scope
> Security of: Resources; methods; status codes; pagination; versioning; validation; authentication; object and function authorization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Broken object authorization, overposting, excessive data exposure, and unbounded operations are independent of how predictable an identifier is.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach defensive REST API security to a developer familiar with HTTP, JSON, SQL
and authentication. Separate identity validation, function permission, tenant
membership, object ownership, writable-field validation, response projection and
state transitions. Trace these across list/read/create/update/delete and jobs.
Explain why UUIDs, UI visibility, CORS and ETags are not authorization. Use a real
framework test client with two synthetic principals, positive/negative tests and
a harmless baseline defect followed by repair. Cover issuer/audience/expiry,
cookie CSRF versus bearer APIs, cache isolation, pagination, quotas, idempotency,
atomic writes and safe audit records. Cite standards and framework documentation.
No exploitation payloads, real accounts, or bypass procedures.
```

## Cheatsheet

### Policy Matrix

| Boundary | Invariant | Evidence |
|---|---|---|
| Identity | Verify cryptography, issuer, audience, expiry and allowed algorithms | Invalid identity: `401` with challenge |
| Function | Actor may perform this action | Reader cannot update their own object: `403` |
| Object | Load inside tenant/resource policy | Foreign read/update/delete: concealed `404` |
| Input | Only declared writable properties reach domain code | Owner and role properties rejected |
| Output | Project approved fields | Internal marker absent from successful JSON |
| State | Policy/precondition and effect are atomic | Denied/stale operations leave storage unchanged |
| Collection | Filter before paging/counting | No foreign records, totals or cursors |
| Cache/job | Preserve context across boundaries | No cross-principal reuse; job rechecks current permission |

Loading by ID and checking only `is_authenticated` is defective even with random IDs. Prefer parameterized tenant-scoped queries and operation-specific rules. Validate both ends of relationships. A bulk route needs policy on each item and an explicit all-or-nothing or partial-success contract. A route prefix such as `/admin` grants nothing by itself.

### Implementation Decisions

Use DTO allowlists, not `model.__dict__.update(body)`. Reject unknown properties when ignoring them hides mistakes; distinguish omitted values from null. Derive ownership from verified context. Project outputs instead of returning whole ORM objects. The lab rejects `owner` and keeps the fixture-only `internal` value out of JSON.

Bearer tokens need TLS and must not enter query strings/logs. Cookie-authenticated unsafe methods need CSRF protection as well as cookie controls. CORS controls browser response access, not authorization. Forwarded identity is trusted only on authenticated, restricted gateway-to-origin connections.

Strong `If-Match` protects against lost updates but is checked after authorization. Commit idempotency records with the effect and scope them to actor/operation; reject different bodies under one key. Bound bytes, row counts, batches, response size, execution time and concurrency separately. `429` is a quota result, not a substitute for terminating expensive work.

### Failure and Evidence

Keep `401`, function-level `403`, and concealed object-level `404` consistent. `405` must retain `Allow`; error wrappers must not strip protocol headers. A denial must not write, queue a job or emit a success event. Log principal surrogate, route template, action, policy version, outcome and correlation ID, not bearer tokens or entire bodies. Successful foreign reads are often more important than a burst of denials. Compare permitted controls alongside denied cases so a globally broken endpoint cannot appear secure.

## Detection and Defense

Centralize resource policies, validate DTOs, constrain response fields, enforce quotas, and test an authorization matrix. Log denied object/action combinations and unusual enumeration patterns.

## Labs

### Independent Authorization Regression

**Requirements:** Python 3.12, Flask 3.1.0, pytest 8.3.5. Empty temporary directory; only the file below. Test client, no sockets. Synthetic bearer fixtures stand in for an already-verified principal; token verification itself is not demonstrated. Execution is **unverified**.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install Flask==3.1.0 pytest==8.3.5
.venv\Scripts\python -m pytest -q test_rest_policy.py
```

**Objective:** verify read/write/delete policy and response projection independently. **Hint:** inspect policy before mutation, not just response status. Baseline failure is an over-restrictive function policy that rejects permitted writes; no vulnerable endpoint is exposed.

### File: test_rest_policy.py

```python
from copy import deepcopy
from flask import Flask, abort, g, jsonify, request


def build_app(allow_writes):
	app = Flask(__name__)
	app.config.update(TESTING=True, MAX_CONTENT_LENGTH=1024)
	records = {
		1: dict(owner="alice", text="alpha", internal="private-a"),
		2: dict(owner="bob", text="beta", internal="private-b"),
	}
	actors = {"Bearer fixture-a": ("alice", "writer"),
			  "Bearer fixture-b": ("bob", "writer"),
			  "Bearer fixture-reader": ("alice", "reader")}

	@app.before_request
	def identity():
		principal = actors.get(request.headers.get("Authorization"))
		if principal is None:
			return jsonify(error="identity required"), 401, {"WWW-Authenticate": "Bearer"}
		g.actor, g.role = principal

	@app.after_request
	def cache(response):
		response.headers["Cache-Control"] = "no-store"
		return response

	@app.route("/notes/<int:note_id>", methods=["GET", "PATCH", "DELETE"])
	def note(note_id):
		if request.method not in ("GET", "HEAD"):
			if not allow_writes or g.role != "writer":
				abort(403)
		record = records.get(note_id)
		if record is None or record["owner"] != g.actor:
			abort(404)
		if request.method == "DELETE":
			del records[note_id]
			return "", 204
		if request.method == "PATCH":
			body = request.get_json()
			if not isinstance(body, dict) or set(body) != {"text"}:
				abort(422)
			if not isinstance(body["text"], str) or not 1 <= len(body["text"]) <= 40:
				abort(422)
			record["text"] = body["text"]
		return jsonify(id=note_id, text=record["text"])

	return app.test_client(), records


def test_baseline_and_repair():
	alice = {"Authorization": "Bearer fixture-a"}
	baseline, _ = build_app(False)
	assert baseline.patch("/notes/1", headers=alice, json={"text": "new"}).status_code == 403
	client, records = build_app(True)
	assert client.get("/notes/1").status_code == 401
	assert client.get("/notes/1", headers=alice).json == {"id": 1, "text": "alpha"}
	before = deepcopy(records)
	for method in ("GET", "PATCH", "DELETE"):
		response = client.open("/notes/2", method=method, headers=alice,
							   json={"text": "changed"})
		assert response.status_code == 404
		assert records == before
	assert client.patch("/notes/1", headers=alice,
						json={"text": "x", "owner": "bob"}).status_code == 422
	reader = {"Authorization": "Bearer fixture-reader"}
	assert client.patch("/notes/1", headers=reader, json={"text": "x"}).status_code == 403
	assert records == before
	assert client.patch("/notes/1", headers=alice, json={"text": "new"}).json == {
		"id": 1, "text": "new"}
	assert records[1]["owner"] == "alice"
	assert client.delete("/notes/1", headers=alice).status_code == 204
	bob = {"Authorization": "Bearer fixture-b"}
	assert client.get("/notes/2", headers=bob).json == {"id": 2, "text": "beta"}
```

### Solution and Acceptance

Enable writes only for the writer role, then retain ownership checks on every operation. Expected: one passing test, the baseline returns `403`, repaired own update/delete work, foreign operations return `404`, extra fields return `422`, and denied operations preserve the full dictionary. The loop performs bounded synthetic checks, not discovery against an external service. This single-threaded fixture does not establish database isolation or token cryptographic correctness.

Troubleshooting: `415` means a non-JSON request; an HTML error body is Flask's default, not protected record data. A production JSON error handler should retain headers. Every factory call resets state. Cleanup: remove the temporary environment/files; there is no listener or database to stop.

- [ ] Local REST APIs exercise: Implement a synthetic notes API with two users, pagination, and a versioned update. Test ownership, invalid input, stale updates, and repeated creation requests.
- [ ] Boundary check: Swap one synthetic user's object ID for another's across read, update, and delete. Every unauthorized operation must fail consistently without leaking protected fields.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Broken Access Control and IDOR]]
- [[Business Logic Attacks]]
- [[REST APIs]]

## References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [HTTP authentication and status semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [Flask testing](https://flask.palletsprojects.com/en/stable/testing/)
