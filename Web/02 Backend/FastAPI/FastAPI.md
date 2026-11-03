---
title: "FastAPI"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[FastAPI Security]]"
updated: 2026-11-03
---
# FastAPI

> [!abstract] TL;DR
> Use explicit request/response models and documented HTTP errors. Treat OpenAPI as a visible contract, not evidence that authorization is implemented.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

Copy this prompt into an agent conversation. The reference and lab below do not require an agent.

```text
Teach me FastAPI at an expert engineering and security level, not as an overview.
Assume I know Python and HTTP. State the Python, FastAPI, Starlette, Pydantic,
and ASGI-server versions you use; distinguish Pydantic v2 from older examples.

Trace a request through ASGI scope/receive/send, middleware, routing, dependency
resolution, validation, handler execution, response serialization, and cleanup.
Explain dependency caching, yield-dependency lifetimes, lifespan resources,
sync thread-pool work versus async event-loop work, cancellation, and blocking I/O.

Build a runnable multi-tenant API, showing every file, installation command,
request/response example, and test. Explain path/query/body binding, Annotated,
Pydantic coercion/strictness, partial updates, response models, HTTP errors,
transactions, uniqueness races, pagination, and OpenAPI generation.

Separate identity verification from tenant, object, and action authorization.
Show an intentionally flawed local-only example, a concrete request proving
the failure, a corrected implementation, and regression tests for each boundary.
Cover mass assignment, response leakage, JWT validation, CORS versus CSRF,
proxy trust, blocking dependencies, request limits, and deployment timeouts.

Explain why alternatives fail and when each design is appropriate. Include
debugging evidence and version-specific caveats, not just best-practice lists.
Use public primary sources. Do not claim examples were executed unless you ran
them. Use synthetic identities and loopback-only targets. Finish with difficult
design questions and worked answers. Do not change my files or study status.
```

## Cheatsheet

### Request Pipeline and Ownership

`ASGI server -> middleware -> router -> dependencies + validation -> handler -> response validation/serialization -> send -> request-scope cleanup`.

| Layer | What it owns | What it does not prove |
|---|---|---|
| Uvicorn | Connections, HTTP parsing, ASGI invocation, concurrency settings | Business authorization or a universal request-body limit |
| Starlette | Routing/middleware primitives, responses, thread-pool integration | Safe application policy |
| FastAPI | Dependency graph, parameter binding, validation orchestration, OpenAPI | That every sensitive route attached an authorization check |
| Pydantic v2 | Parsing, constraints, serialization | That an ID belongs to this user or a requested action is permitted |
| Application/database | Identity mapping, permissions, transactions, invariants | Protection from deployment mistakes elsewhere |

Middleware runs inward on the request and outward on the response. A directly returned `Response` bypasses normal response-model serialization. Streaming can send headers before later application work fails: after that, changing the HTTP status is too late.

### Parameter Binding and Validation

| Declaration | Meaning | Important edge |
|---|---|---|
| `note_id: int` matching `{note_id}` | Required path value | Invalid integer normally produces 422 |
| `limit: Annotated[int, Query(ge=1, le=50)] = 20` | Bounded query value | Query values arrive as text and are parsed |
| `payload: NoteCreate` | JSON request body | Parsing is not authorization |
| `Field(strict=True)` | Reject supported coercions for that field | Strict JSON behavior can differ from Python-input behavior |
| `ConfigDict(extra="forbid")` | Reject undeclared fields | Default extra-field ignoring can hide client mistakes |
| `model_dump(exclude_unset=True)` | Only fields explicitly supplied | An explicit `null` is still supplied |
| `response_model=NoteOut` | Validate/filter ordinary returned data | Does not redact logs or a manually built `JSONResponse` |

In Pydantic v2, `field: str | None` without a default is required but nullable. `field: str | None = None` is omittable and nullable. Decide whether PATCH `null` means clear, reject, or no change; do not let an accidental default decide.

Pydantic's `model_copy(update=...)` does not validate the update dictionary. Pass validated/allowlisted values, or construct and validate a new model when changing invariants. `model_construct()` also bypasses validation.

### Dependencies and Lifetimes

```python
from collections.abc import Iterator
from typing import Annotated
import sqlite3

from fastapi import Depends


def get_connection() -> Iterator[sqlite3.Connection]:
	connection = sqlite3.connect("notes.db", check_same_thread=False)
	try:
		yield connection
	finally:
		connection.close()


Connection = Annotated[
	sqlite3.Connection, Depends(get_connection, scope="function")
]
```

This is a lifecycle fragment, not the lab's storage implementation. Do not share that connection between requests. Disabling SQLite's thread check does not add synchronization; synchronous dependencies and handlers need not execute on the same thread.

- FastAPI normally reuses a dependency result within a request; it is not a global cache. `use_cache=False` requests another evaluation where appropriate.
- Current `yield` dependencies default to request scope: cleanup runs after the response. `scope="function"` ends after the handler, before sending the response. Do not close a resource early if a streaming body still needs it.
- Commit before returning success. A commit in request-scope cleanup can fail after a success response has already gone out. Catch specific database conflicts, roll back, and map intended conflicts to 409.
- Use lifespan for shared clients/pools and request dependencies for sessions/units of work. Background work must own its resources; do not hand it a request session that is about to close.
- A dependency is executed by FastAPI when attached to a route/dependency graph. Calling a function directly does not make `Depends(...)` resolve itself.

### Concurrency and Capacity

| Work | Handler/design | Failure to avoid |
|---|---|---|
| Awaitable database/HTTP I/O | `async def`, await the asynchronous driver | Blocking the event loop with a synchronous client |
| Synchronous database/client | Plain `def`, or deliberate thread offload | Assuming a normal helper called inside `async def` is automatically offloaded |
| CPU-heavy work | Bounded process workers/task system as appropriate | Treating `async def` or an unbounded thread pool as CPU parallelism |
| Durable jobs | Queue with retries, idempotency, job state | Treating in-process `BackgroundTasks` as durable delivery |
| Streaming | Bounded chunks, cancellation, explicit resource lifetime | Holding a scarce database connection for a slow client indefinitely |

Thread capacity, database-pool capacity, and server concurrency are separate bottlenecks. More workers multiply per-process pools and memory. A keep-alive timeout is not a deadline for all request processing. Test overload, disconnects, and shutdown using a real server; TestClient cannot certify those properties.

### Database Authorization and Races

Bind values; scope the operation itself to the authenticated tenant and owner:

```sql
SELECT id, title, body
FROM notes
WHERE id = :note_id
  AND tenant_id = :tenant_id
  AND owner_id = :subject;

UPDATE notes
SET title = :title, version = version + 1
WHERE id = :note_id
  AND tenant_id = :tenant_id
  AND owner_id = :subject
  AND version = :expected_version;
```

The named parameters are bound through your database driver, not string-formatted. A zero-row update can mean missing, forbidden, or stale data; choose a documented non-disclosing error policy. Use database uniqueness constraints for uniqueness, not just a separate "does it exist?" query. For concurrent edits, an expected version/ETag prevents silent lost updates; an idempotency key handles retried creation as a different problem.

### HTTP Contract

| Situation | Status | Notes |
|---|---|---|
| Successful creation | 201 | Include `Location` when identifying the new resource |
| Successful read/update with body | 200 | Match the response schema |
| Successful deletion without body | 204 | Do not serialize a JSON body |
| Missing/invalid bearer credential | 401 | Include `WWW-Authenticate: Bearer` |
| Known identity, disallowed action | 403 | Or a consistent 404 policy to conceal object existence |
| Object missing or not visible | 404 | Do not reveal forbidden ownership in the error message |
| Schema/input constraint failure | 422 | Keep sensitive rejected values out of logs/error customizations |
| State conflict | 409 | Define the conflict and retry behavior |
| Invalid server response | 500 | Application defect, not the client's validation error |

OpenAPI documents schemas and declared security requirements; it cannot infer a missing owner check. Put fixed routes such as `/notes/search` before a competing `/notes/{note_id}` route where ordering matters. Keep documentation access policy separate from endpoint access policy.

## Gotchas

- Type hints in arbitrary Python functions are not runtime validation. Validation occurs at the framework/model boundary.
- Authentication helpers parse credentials and document schemes; they are not an identity provider or an authorization engine.
- CORS constrains browser JavaScript access, not `curl`, server-to-server traffic, or object ownership.
- Response filtering is a last boundary, not a reason to fetch unnecessary secrets from storage.
- Multiple workers do not share a Python dictionary. The application below deliberately uses one process and disposable memory, not production persistence.

## Labs

### Lab Contract

Build an owner-private notes API and prove that its HTTP contract enforces the declared boundaries. All required source is below. No database, cloud account, agent, or external CTF platform is required.

Use Python 3.12 and PowerShell 7 in a disposable local directory. The pinned top-level packages below establish the example baseline; they are not a production dependency lock or a claim that the versions are vulnerability-free. Capture `pip freeze` when reproducing. Internet access is needed for installation, not for running the tests.

Synthetic bearer strings stand in for an identity provider. `alice-local`, `bob-local`, and `carol-local` are public lab fixtures, not secure API keys. Only bind to loopback. The server initializes new in-memory state when restarted.

### File: requirements.txt

```text
fastapi==0.162.0
starlette==1.10.0
pydantic==2.14.2
uvicorn==0.54.0
httpx2==2.16.0
pytest==9.2.0
```

### File: app.py

```python
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field


class Principal(BaseModel):
	subject: str
	tenant: str


class NoteCreate(BaseModel):
	model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
	title: str = Field(min_length=1, max_length=80)
	body: str = Field(max_length=1000)


class NotePatch(BaseModel):
	model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
	title: str = Field(min_length=1, max_length=80)


class NoteOut(BaseModel):
	id: str
	title: str
	body: str


bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
IDENTITIES = {
	"alice-local": Principal(subject="alice", tenant="red"),
	"bob-local": Principal(subject="bob", tenant="red"),
	"carol-local": Principal(subject="carol", tenant="blue"),
}


async def authenticate(credentials: Credentials) -> Principal:
	principal = IDENTITIES.get(credentials.credentials) if credentials else None
	if principal is None:
		raise HTTPException(
			401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"}
		)
	return principal


CurrentUser = Annotated[Principal, Depends(authenticate)]


def create_app() -> FastAPI:
	@asynccontextmanager
	async def lifespan(application: FastAPI):
		application.state.notes = {
			"1": {
				"id": "1", "title": "Alice note", "body": "red marker",
				"tenant": "red", "owner": "alice", "internal": "never serialize",
			},
			"2": {
				"id": "2", "title": "Bob note", "body": "same-tenant private",
				"tenant": "red", "owner": "bob", "internal": "never serialize",
			},
			"3": {
				"id": "3", "title": "Carol note", "body": "other-tenant private",
				"tenant": "blue", "owner": "carol", "internal": "never serialize",
			},
		}
		yield
		application.state.notes.clear()

	application = FastAPI(title="Notes boundary lab", lifespan=lifespan)

	def owned_note(request: Request, note_id: str, user: Principal) -> dict:
		note = request.app.state.notes.get(note_id)
		if note is None or note["tenant"] != user.tenant or note["owner"] != user.subject:
			raise HTTPException(404, "Not found")
		return note

	@application.get("/notes", response_model=list[NoteOut])
	async def list_notes(
		request: Request,
		user: CurrentUser,
		limit: Annotated[int, Query(ge=1, le=50)] = 20,
	):
		visible = [
			note for note in request.app.state.notes.values()
			if note["tenant"] == user.tenant and note["owner"] == user.subject
		]
		return sorted(visible, key=lambda note: note["id"])[:limit]

	@application.post("/notes", response_model=NoteOut, status_code=201)
	async def create_note(
		payload: NoteCreate, request: Request, response: Response, user: CurrentUser
	):
		note_id = str(uuid4())
		note = {
			"id": note_id, **payload.model_dump(),
			"tenant": user.tenant, "owner": user.subject, "internal": "server-only",
		}
		request.app.state.notes[note_id] = note
		response.headers["Location"] = f"/notes/{note_id}"
		return note

	@application.get("/notes/{note_id}", response_model=NoteOut)
	async def read_note(note_id: str, request: Request, user: CurrentUser):
		return owned_note(request, note_id, user)

	@application.patch("/notes/{note_id}", response_model=NoteOut)
	async def rename_note(
		note_id: str, payload: NotePatch, request: Request, user: CurrentUser
	):
		note = owned_note(request, note_id, user)
		note["title"] = payload.title
		return note

	return application


app = create_app()
```

The nested helper does no blocking I/O. It runs on the event loop because it is called directly. Each handler's dictionary mutation has no intervening `await`; this is deliberately not a cross-worker transaction design. PATCH here is specifically a rename operation requiring `title`, not a generic sparse update.

### File: test_app.py

```python
import pytest
from fastapi.testclient import TestClient

from app import create_app


@pytest.fixture
def client():
	with TestClient(create_app()) as session:
		yield session


ALICE = {"Authorization": "Bearer alice-local"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid"}])
def test_authentication(client, headers):
	response = client.get("/notes", headers=headers)
	assert response.status_code == 401
	assert response.headers["www-authenticate"] == "Bearer"


def test_filtered_read_and_list(client):
	response = client.get("/notes/1", headers=ALICE)
	assert response.status_code == 200
	assert response.json() == {"id": "1", "title": "Alice note", "body": "red marker"}
	assert client.get("/notes", headers=ALICE).json() == [response.json()]


@pytest.mark.parametrize("note_id", ["2", "3", "missing"])
def test_invisible_objects(client, note_id):
	response = client.get(f"/notes/{note_id}", headers=ALICE)
	assert response.status_code == 404
	assert response.json() == {"detail": "Not found"}
	renamed = client.patch(f"/notes/{note_id}", headers=ALICE, json={"title": "changed"})
	assert renamed.status_code == 404


def test_create_and_rename(client):
	created = client.post("/notes", headers=ALICE, json={"title": " New ", "body": "test"})
	assert created.status_code == 201
	assert created.json()["title"] == "New"
	assert set(created.json()) == {"id", "title", "body"}
	location = created.headers["location"]
	assert client.get(location, headers=ALICE).json() == created.json()
	renamed = client.patch(location, headers=ALICE, json={"title": "Renamed"})
	assert renamed.status_code == 200
	assert renamed.json()["title"] == "Renamed"


@pytest.mark.parametrize("payload", [
	{"title": " ", "body": "test"},
	{"title": "ok", "body": "test", "owner": "bob"},
	{"title": "ok", "body": "test", "tenant": "blue"},
	{"title": "ok", "body": "test", "is_admin": True},
	{"title": "ok", "body": "x" * 1001},
])
def test_invalid_create(client, payload):
	assert client.post("/notes", headers=ALICE, json=payload).status_code == 422


@pytest.mark.parametrize("payload", [{}, {"title": None}, {"title": "ok", "owner": "bob"}])
def test_invalid_patch(client, payload):
	assert client.patch("/notes/1", headers=ALICE, json=payload).status_code == 422


@pytest.mark.parametrize("limit", ["0", "51", "invalid"])
def test_bounded_query(client, limit):
	assert client.get(f"/notes?limit={limit}", headers=ALICE).status_code == 422


def test_openapi_contract(client):
	schema = client.get("/openapi.json").json()
	operation = schema["paths"]["/notes"]["post"]
	assert "201" in operation["responses"]
	assert operation["security"] == [{"HTTPBearer": []}]
	assert set(schema["components"]["schemas"]["NoteOut"]["properties"]) == {"id", "title", "body"}
```

### Run and Inspect

Use the three file blocks above in the same local directory. These commands do not require shell activation or an execution-policy change:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Use another PowerShell terminal while Uvicorn runs:

```powershell
$headers = @{ Authorization = 'Bearer alice-local' }
Invoke-RestMethod http://127.0.0.1:8000/notes/1 -Headers $headers
$created = Invoke-WebRequest http://127.0.0.1:8000/notes -Method Post `
	-Headers $headers -ContentType 'application/json' `
	-Body '{"title":"Local note","body":"synthetic marker"}'
$created.StatusCode
$created.Headers.Location
curl.exe -i http://127.0.0.1:8000/notes/2 -H 'Authorization: Bearer alice-local'
curl.exe -i http://127.0.0.1:8000/notes
```

Expected: Alice's read exposes only `id/title/body`; creation returns 201 and a relative `Location`; Bob's record returns 404; the unauthenticated list returns 401 with a bearer challenge. `/docs` shows separate create/patch/output schemas. These are acceptance criteria, not fabricated observations from your run.

### Completion and Reset

- [ ] Run all included tests; inspect the same-tenant and cross-tenant denials separately.
- [ ] Reproduce the documented requests and compare status, headers, and body.
- [ ] Explain why validation, authentication, and ownership checks are different boundaries using the actual code.
- [ ] Stop Uvicorn with Ctrl+C and restart it; verify only the three seeded notes remain. Remove the disposable lab directory when finished.

Troubleshooting: connection refused means the server is not running on that port; 401 means the lab bearer is missing/incorrect; 422 means inspect the field-specific validation error. If port 8000 is occupied, choose a free port and change every request URL consistently. The TestClient context manager is required to run lifespan initialization.

This lab does not validate real JWT/OIDC login, persistent storage, TLS, a reverse proxy, or concurrent multi-worker behavior. Those are explicit deployment boundaries, not capabilities silently implied by passing unit tests.

Author verification: the application and test files printed above were extracted from this note and passed 19 tests on Python 3.12 with the pinned framework/test packages. This validates the supplied examples, not your completion of the lab.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[FastAPI Security]]

## References

- [Parameter and request-body declarations](https://fastapi.tiangolo.com/tutorial/body/)
- [Dependency lifetimes and scope](https://fastapi.tiangolo.com/tutorial/dependencies/dependencies-with-yield/)
- [Concurrency and directly called helpers](https://fastapi.tiangolo.com/async/)
- [Response filtering and direct Response caveats](https://fastapi.tiangolo.com/tutorial/response-model/)
- [Pydantic model behavior](https://docs.pydantic.dev/latest/concepts/models/)
- [Testing lifespan](https://fastapi.tiangolo.com/advanced/testing-events/)
