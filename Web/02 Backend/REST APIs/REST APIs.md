---
title: "REST APIs"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[REST APIs Security]]"
updated: 2026-11-03
---
# REST APIs

> [!abstract] TL;DR
> Document request/response schemas and errors. Check actor, object, action, and tenant on every operation; use bounded page sizes and explicit writable fields.

> [!info] Agent scope
> Resources; methods; status codes; pagination; versioning; validation; authentication; object and function authorization.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach REST-oriented HTTP API design at expert implementation depth. Assume HTTP,
JSON, Python and SQL knowledge. Distinguish REST constraints, including hypermedia,
from JSON CRUD. Trace routing, authentication, validation, object/function policy,
atomic state changes, representations, caching and errors. Work through method
semantics, strong ETags, If-Match, retries and idempotency records. Compare keyset
and offset pagination under concurrent inserts, API versus record versioning,
request DTOs and response projections. Use real framework examples with two-user
synthetic data and complete positive/negative tests. Explain which invariants need
database transactions rather than process locks. Ask me to predict responses.
Cite RFC 9110/9111 and framework docs; label version-sensitive behavior. No exploit
payloads, production targets or real credentials.
```

## Cheatsheet

### Contract and Pipeline

A resource is not a database row; a representation is not the storage model. Stateless requests carry enough context to interpret each request, but the service may still store records. REST additionally constrains the interface, caching, layering and hypermedia; a JSON CRUD service is not automatically fully RESTful.

| Decision | Contract | Edge case |
|---|---|---|
| GET / HEAD | Read; HEAD sends no body | Logs are compatible with safe methods, business-state changes are not |
| POST collection | Create: `201` and `Location` | Repeating a POST may create another object |
| PUT resource | Replace writable representation; idempotent intent | Do not send an ETag on successful PUT if representation bytes were transformed |
| PATCH resource | Apply a documented partial-update format | Not inherently idempotent; omitted and null differ |
| DELETE resource | `204` without content when applied | Repeated `404` is compatible with idempotent effect |
| Async work | `202` plus status-resource link | Accepted is not completed |
| Invalid request | `400` syntax, `415` media type, `422` domain validation | `405` must include `Allow` |
| Identity / policy | `401` with challenge; `403` denial | A deliberate `404` may conceal existence |

Authenticate, authorize the function, load within actor/tenant policy, validate writable fields, then apply state preconditions atomically with the effect. Project responses explicitly. RFC 9457 problem details provide a stable error format, not permission to expose stack traces.

### Concurrency and Retries

```http
PATCH /v1/notes/7 HTTP/1.1
Content-Type: application/json
If-Match: "7-r3"

{"text":"reviewed"}
```

`If-Match` uses strong comparison: `W/"7-r3"` cannot match. A list succeeds if any strong tag matches; `*` means existence, not a particular revision. Missing mandatory precondition can return `428`; false precondition returns `412`. `If-None-Match` on GET uses weak comparison and can produce bodyless `304`. ETags prevent lost updates/cache staleness, not impersonation.

Parameterized production CAS fragment:

```sql
UPDATE notes SET text = :text, revision = revision + 1
WHERE id = :id AND owner_id = :actor AND revision = :expected;
```

Check affected-row count and keep policy/state changes transactionally consistent. Reading then writing unconditionally has a race. For retryable creation, atomically persist `(actor, operation, idempotency_key, request_hash, response)` with the effect. Reject reuse with a different body and define retention. A separate cache written after committing leaves a crash window.

### Pagination, Versions and Capacity

Offset pages shift under inserts/deletes. Keyset uses stable order with a unique tie-breaker, e.g. `(created_at, id) > (:time, :id) ORDER BY created_at, id LIMIT :limit`. Filter by tenant before paging/counting. Bind opaque cursors to filters; they are not access tokens. Consistent exports need a snapshot or explicit high-water policy.

`/v1` is an API version; an ETag is a representation revision. Removing fields, narrowing accepted values and changing nullability can break clients. Strict writable-field allowlists prevent overposting; response projections prevent accidental disclosure. Bound bytes, rows, elapsed work and concurrent work independently. `429` describes caller throttling, `503` service capacity; `Retry-After` does not make an unsafe action retryable.

For identity-specific lab responses use `Cache-Control: no-store`. Production private caching needs a deliberate key/policy; `Vary` alone is not authorization. Flask 3.1 `get_json()` rejects non-JSON types with `415`; the lab checks the exact media type explicitly.

## Gotchas

UUIDs reduce guessability but do not authorize access. A 404 can conceal existence, but policy still must be enforced before returning data.

## Labs

### Conditional Notes API

**Requirements:** Python 3.12, Flask 3.1.0, pytest 8.3.5; an empty disposable directory outside the vault. Only the following file is needed; seeds are inline. Flask's test client opens no listener. Bearer strings are synthetic fixtures, not a production identity provider. All execution is **unverified**.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install Flask==3.1.0 pytest==8.3.5
.venv\Scripts\python -m pytest -q test_rest_contract.py
```

**Objective:** explain filtered paging, stale writes and repeated creation. **Hint:** inspect ownership before ETag checks; distinguish retry from a new POST.

### File: test_rest_contract.py

```python
from threading import RLock
from flask import Flask, abort, g, jsonify, request


def make_app():
	app = Flask(__name__)
	app.config.update(TESTING=True, MAX_CONTENT_LENGTH=2048)
	notes = {
		1: dict(id=1, owner="alice", text="alpha", revision=1),
		2: dict(id=2, owner="bob", text="beta", revision=1),
		3: dict(id=3, owner="alice", text="gamma", revision=1),
	}
	lock = RLock()

	@app.before_request
	def authenticate():
		g.actor = {"Bearer fixture-a": "alice", "Bearer fixture-b": "bob"}.get(
			request.headers.get("Authorization"))
		if g.actor is None:
			return jsonify(error="identity required"), 401, {"WWW-Authenticate": "Bearer"}

	@app.after_request
	def cache_policy(response):
		response.headers["Cache-Control"] = "no-store"
		return response

	def text_input():
		if request.mimetype != "application/json":
			abort(415)
		body = request.get_json()
		if not isinstance(body, dict) or set(body) != {"text"}:
			abort(422)
		if not isinstance(body["text"], str) or not 1 <= len(body["text"]) <= 80:
			abort(422)
		return body["text"]

	def visible(note):
		return {key: note[key] for key in ("id", "text")}

	def representation(note):
		response = jsonify(visible(note))
		response.set_etag(f'{note["id"]}-r{note["revision"]}')
		return response

	@app.route("/v1/notes", methods=["GET", "POST"])
	def collection():
		with lock:
			if request.method == "POST":
				text = text_input()
				note_id = max(notes, default=0) + 1
				note = dict(id=note_id, owner=g.actor, text=text, revision=1)
				notes[note_id] = note
				response = representation(note)
				response.status_code = 201
				response.headers["Location"] = f"/v1/notes/{note_id}"
				return response
			try:
				after = int(request.args.get("after", "0"))
				limit = int(request.args.get("limit", "2"))
			except ValueError:
				abort(400)
			if after < 0 or not 1 <= limit <= 2:
				abort(400)
			rows = [notes[key] for key in sorted(notes)
					if key > after and notes[key]["owner"] == g.actor]
			page = rows[:limit]
			return jsonify(items=[visible(note) for note in page],
						   next_after=page[-1]["id"] if len(rows) > limit else None)

	@app.route("/v1/notes/<int:note_id>", methods=["GET", "PATCH", "DELETE"])
	def resource(note_id):
		with lock:
			note = notes.get(note_id)
			if note is None or note["owner"] != g.actor:
				abort(404)
			if request.method in ("GET", "HEAD"):
				return representation(note)
			if "If-Match" not in request.headers:
				abort(428)
			if not request.if_match.contains(f'{note_id}-r{note["revision"]}'):
				abort(412)
			if request.method == "DELETE":
				del notes[note_id]
				return "", 204
			note["text"] = text_input()
			note["revision"] += 1
			return representation(note)

	return app


def test_contract():
	client = make_app().test_client()
	alice = {"Authorization": "Bearer fixture-a"}
	assert client.get("/v1/notes").status_code == 401
	assert client.get("/v1/notes?limit=1", headers=alice).json == {
		"items": [{"id": 1, "text": "alpha"}], "next_after": 1}
	assert client.get("/v1/notes?after=1", headers=alice).json["items"] == [
		{"id": 3, "text": "gamma"}]
	assert client.get("/v1/notes?limit=3", headers=alice).status_code == 400
	assert client.get("/v1/notes/2", headers=alice).status_code == 404
	response = client.get("/v1/notes/1", headers=alice)
	stale = {**alice, "If-Match": response.headers["ETag"]}
	assert client.patch("/v1/notes/1", headers=alice, json={"text": "new"}).status_code == 428
	assert client.patch("/v1/notes/1", headers=stale, json={"text": "new"}).status_code == 200
	assert client.patch("/v1/notes/1", headers=stale, json={"text": "lost"}).status_code == 412
	assert client.get("/v1/notes/1", headers=alice).json["text"] == "new"
	assert client.post("/v1/notes", headers=alice, json={"text": "x", "owner": "bob"}).status_code == 422
	first = client.post("/v1/notes", headers=alice, json={"text": "repeat"})
	second = client.post("/v1/notes", headers=alice, json={"text": "repeat"})
	assert first.status_code == second.status_code == 201
	assert first.headers["Location"] != second.headers["Location"]
	current = client.get(first.headers["Location"], headers=alice)
	removed = client.delete(first.headers["Location"], headers={
		**alice, "If-Match": current.headers["ETag"]})
	assert removed.status_code == 204 and removed.data == b""
```

### Solution and Acceptance

The solution is the ownership predicate plus the locked precondition/write block. Expected: one passing test, Alice sees IDs 1 and 3, a stale write cannot replace `new`, and repeated POST creates distinct resources. This deliberately does not implement idempotency keys, persistent storage, full conditional GET or production authentication. A process lock cannot coordinate multiple workers. Function-level roles have an independent lab in the security note.

For a harmless fix/retest exercise, lower the page ceiling to 1 without changing its default: the default request should now fail. Restore 2 and repeat. On unexpected errors check interpreter/package versions and JSON versus form submission. State resets on `make_app()`. Cleanup: delete only this disposable directory after closing its interpreter; no service is left running.

- [ ] Local REST APIs exercise: Implement a synthetic notes API with two users, pagination, and a versioned update. Test ownership, invalid input, stale updates, and repeated creation requests.
- [ ] Boundary check: Swap one synthetic user's object ID for another's across read, update, and delete. Every unauthorized operation must fail consistently without leaking protected fields.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Broken Access Control and IDOR]]
- [[Business Logic Attacks]]
- [[REST APIs Security]]

## References

- [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
- [HTTP caching, RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html)
- [Flask testing](https://flask.palletsprojects.com/en/stable/testing/)
- [Problem details, RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html)
