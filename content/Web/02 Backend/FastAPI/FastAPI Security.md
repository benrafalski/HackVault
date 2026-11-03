---
title: "FastAPI Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[FastAPI]]"
updated: 2026-11-03
---
# FastAPI Security

> [!abstract] TL;DR
> Overbroad serialization, missing dependency enforcement, permissive CORS, and blocking work in async routes can disclose data or exhaust service capacity.

## Attack Surface

| Boundary | Attacker-controlled input | Security decision |
|---|---|---|
| Authentication | Bearer token, cookie, identity headers | Which verified principal is calling? |
| Object/action access | Path ID, tenant selector, requested operation | May this principal perform this action on this object? |
| Model binding | JSON properties, query values, nested input | Which fields may the caller set, and within which limits? |
| Serialization | Returned object and chosen response class | Which fields may this caller receive? |
| Browser integration | Origin, cookies, cross-site requests | What can a browser send or read with ambient authority? |
| Deployment | Forwarded headers, Host, slow/large requests | Which proxy is trusted, and how is work bounded? |

## Learn

Copy this prompt into an agent conversation. Use Cheatsheet and Labs directly when you do not need a tutor.

```text
Teach me FastAPI security as an expert application-security engineer.
Assume Python and HTTP knowledge. Pin the framework/library versions and explain
where FastAPI, Starlette, Pydantic, the ASGI server, and the application each
enforce a boundary. Do not substitute generic OWASP advice for framework details.

For object/tenant authorization, dependency enforcement, mass assignment,
response-model leakage, JWT verification, CORS/CSRF, proxy trust, unsafe error
handling, and resource exhaustion: explain the root cause and prerequisites;
show minimal vulnerable code, an exact synthetic HTTP request, the observable
result, the fixed code, a negative regression test, and detection evidence.

Build a complete loopback-only CTF using synthetic users and records. Include
all files, dependency setup, seed data, objectives, hints, a separated solution,
and automated checks. A reader must not need to ask you to invent missing steps.
Separate teaching shortcuts from production-capable security controls.

Explain authentication versus authorization, dependency caching/lifetimes,
validation versus policy, schema coercion, response filtering, transaction races,
and why hiding OpenAPI or setting CORS does not secure an API. Include the limits
of TestClient and the deployment checks it cannot prove. Reference primary docs.
Do not claim tests passed without executing them. Do not touch real services,
collect real credentials, alter my vault, or mark labs complete.
```

## Cheatsheet

### Authentication Is Not Object Authorization

This verifies a caller but still exposes every accessible database row by ID:

```python
@app.get("/notes/{note_id}")
async def read_note(note_id: int, user: CurrentUser):
	return await repository.get_by_id(note_id)
```

The snippet is a defect pattern, not a complete program. `CurrentUser` must verify identity; it cannot infer an object policy from the URL. Correct the data access itself:

```sql
SELECT id, title, body
FROM notes
WHERE id = :note_id
  AND tenant_id = :verified_tenant
  AND owner_id = :verified_subject;
```

- Bind values through the driver. Derive tenant and subject from verified server-side identity/membership, not arbitrary request fields or `X-User` headers.
- Test another user in the **same tenant**, then a user in a **different tenant**. A tenant-only predicate can still expose private records within that tenant.
- Apply the policy to list, export, update, delete, bulk operations, attachments, and background jobs, not just GET-by-ID.
- UUIDs can reduce casual guessing; they are not access control. A response schema can conceal fields, not repair an unauthorized read of allowed fields.
- Use a consistent 404 policy if object existence is intentionally concealed. Do not fetch a forbidden record and reveal its owner in a detailed error.

### Property Authorization and Mass Assignment

`user.update(payload)` or `Model(**request_json)` can let a caller set `is_admin`, `tenant_id`, `owner_id`, approval status, or billing state. A value being a valid boolean or UUID does not make the caller authorized to set it.

```python
from pydantic import BaseModel, ConfigDict, Field


class ProfilePatch(BaseModel):
	model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
	display_name: str = Field(min_length=1, max_length=40)


def apply_profile_patch(stored_user: dict, payload: ProfilePatch) -> None:
	stored_user["display_name"] = payload.display_name
```

Use separate input, internal, and output models. Explicit assignment makes the writable set visible; a future internal-model field should not silently become client-writable. For sparse PATCH, validate both provided fields and the resulting invariants. `model_copy(update=...)` is not a second validation pass.

### Serialization and Error Boundaries

| Pattern | Result | Appropriate control |
|---|---|---|
| Return an ORM object/dict with a narrow `response_model` | Ordinary return data is validated and filtered | Keep output schemas explicit and test exact response keys |
| Return `JSONResponse(content=internal_record)` directly | Normal model filtering is bypassed | Construct the public projection yourself or return ordinary data |
| Reuse password-bearing request schema as output | Sensitive fields can be serialized | Separate input/output models |
| Use an output model but log full records | HTTP may be safe while logs leak | Redact at the logging boundary too |
| Return invalid output data | Server response validation fails | Treat as a server bug; do not blame client input |
| Return exception text/SQL/token details | Error path becomes a disclosure surface | Stable public errors, correlated private diagnostics |

`response_model_exclude` is not a substitute for an accurate public schema: OpenAPI can still describe the larger model. Serialization behavior also differs for manually built responses and streaming; test the actual response path.

### JWT Verification Checklist

The runnable decoder in Labs demonstrates these checks with a public **test-only** HMAC key. Production must use trusted key configuration and a vetted issuer, not that fixture.

1. Select the acceptable algorithm in server configuration. Never trust the token's `alg` as the algorithm allowlist; do not mix symmetric and asymmetric keys indiscriminately.
2. Verify the signature and require/validate issuer, audience, expiry, and subject. A claim's presence and its valid value are separate requirements.
3. Check `nbf` and time behavior; permit only a deliberate small clock tolerance. Decide maximum token age and revocation/session requirements separately.
4. With JWKS, use a configured trusted issuer/JWKS location, bounded fetches/cache/rotation, and key selection within that trust. Do not fetch arbitrary token-supplied `jku`/`x5u` URLs.
5. Resolve the verified subject into current account/membership state. A valid token does not guarantee a current role, active account, or permission to access a selected tenant.

Decoding without signature verification is useful for inspection, not authorization. An ID token intended for a client application is not automatically an API access token. Helpers such as `OAuth2PasswordBearer` do not implement these checks for you.

### CORS, CSRF, and Cookies

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
	CORSMiddleware,
	allow_origins=["https://ui.example"],
	allow_credentials=True,
	allow_methods=["GET", "POST", "PATCH"],
	allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)
```

This is a configuration fragment for a cookie-capable application, not authentication. Use actual trusted origins, including the correct scheme and port. Do not combine wildcard trust with credentialed access or reflect arbitrary origins.

- CORS does not stop non-browser clients. Some cross-origin requests can be sent even when the response is unreadable to the attacker's JavaScript.
- Cookie authentication uses ambient credentials: state-changing endpoints need an appropriate CSRF defense, such as a session-bound token plus Origin validation. `SameSite` is defense in depth, not a universal substitute.
- `HttpOnly` prevents JavaScript reading a cookie, not an XSS script sending authenticated requests. `Secure` restricts cookie transport to HTTPS.
- Header bearer authentication has a different CSRF exposure when browsers do not automatically attach the header; XSS and token storage remain relevant risks.
- WebSocket Origin/authentication checks need their own policy; HTTP CORS middleware is not a WebSocket authorization policy.

### Availability and Deployment Traps

| Risk | Why the apparent safeguard fails | Test/control |
|---|---|---|
| `requests.get()` inside `async def` | Direct synchronous call blocks the event loop | Await an async client or deliberately offload bounded work; set downstream timeouts |
| Huge JSON or uploads | Pydantic constraints can run after buffering/parsing | Enforce actual byte limits at the edge/application boundary; bound decoded work |
| Trust `Content-Length` alone | Missing, chunked, or transformed bodies need accounting | Count accepted bytes or use an enforcing proxy, including chunked requests |
| Deep nesting or expensive regex/parser | Small input can still be computationally expensive | Constrain depth/shape, safe patterns, time and concurrency budgets |
| Unlimited file processing | Spooling prevents some RAM growth, not disk/CPU exhaustion | Quotas, file-count/size limits, isolated processing, controlled storage names |
| Trust all proxy headers | Clients can forge apparent scheme/address | Trust only the actual proxy and block direct backend bypass |
| Shared-cache private responses | Correct origin authorization can be bypassed by wrong cache keys | Prevent shared caching or key it by the real authorization boundary |
| Hiding `/docs` | Routes are still callable | Authenticate/authorize operations; treat docs exposure separately |

Do not treat Uvicorn's keep-alive timeout as a universal request execution deadline. Bound server concurrency, database pools, outbound requests, and expensive operations separately. Test timeouts and cancellation with a real server; a fast TestClient run cannot demonstrate resistance to overload.

### Assessment Matrix

| Test | Baseline | Mutate only | Secure result |
|---|---|---|---|
| Authentication | Alice bearer | Remove/replace credential | 401 and bearer challenge |
| Same-tenant object access | Alice reads her note | ID to Bob's note | Consistent denial |
| Cross-tenant object access | Alice reads her note | ID to Carol's note | Consistent denial |
| Property authorization | Change display name | Add `is_admin`/tenant/owner | Reject or explicitly ignore under documented policy; no privilege change |
| Response filtering | Read permitted object | Inspect full response keys | No internal secret fields |
| Action authorization | Normal authenticated user | Call admin-only route directly | 403, not merely a hidden UI button |
| JWT validation | Valid local fixture | Wrong audience/issuer, expiry, key, required claim | Reject each independently |

Preserve the exact request, identity, status, relevant response fields, server decision, and fixed retest. Never infer a vulnerability solely from a response-length change.

## Detection and Defense

Record route templates, request/correlation ID, verified subject/tenant, operation, status, latency, and an internal policy reason. Do not record bearer headers, cookies, passwords, entire bodies, or full JWTs. If a public 404 conceals a forbidden object, internal telemetry can still distinguish policy denial from absence.

Useful signals: many distinct object IDs denied to one principal; attempts to submit privileged properties; repeated invalid JWT claim classes; unexpected 500/response-validation errors; elevated event-loop lag or pool waits. Correlate signals with normal application behavior and account for legitimate client bugs. A generic 422 count alone is not proof of an attack.

Regression coverage should include allowed operations as well as denied ones. A service that rejects every request is not a correct authorization fix. Clear dependency overrides after tests; otherwise tests may accidentally bypass authentication and falsely certify the application.

## Labs

### CTF - Three Broken Boundaries

**Target:** the service below on `127.0.0.1:8001`. **Starting identity:** Alice using `Bearer alice-local`. **Objectives:** obtain the internal serialization flag, read a different owner's note, and reach the admin flag by changing a property the caller should not control.

This is a white-box educational CTF: source and fixture flags are visible, but an objective counts only when the corresponding HTTP response proves the broken boundary. Use synthetic data only. Do not expose the vulnerable app through `0.0.0.0`, a container-published public port, or a tunnel.

Everything needed is on this page. Use Python 3.12 and PowerShell 7 in a fresh local directory. Installation needs package-registry access; running the CTF and tests does not. No agent, database, external CTF account, or other note's code is required.

### File: requirements.txt

```text
fastapi==0.162.0
starlette==1.10.0
pydantic==2.14.2
uvicorn==0.54.0
httpx2==2.16.0
pytest==9.2.0
PyJWT==2.15.1
```

### File: ctf.py

```python
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field


class NoteOut(BaseModel):
	id: int
	title: str
	body: str


class ProfileOut(BaseModel):
	username: str
	display_name: str


class ProfilePatch(BaseModel):
	model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
	display_name: str = Field(min_length=1, max_length=40)


bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


async def current_user(request: Request, credentials: Credentials) -> dict:
	username = {
		"alice-local": "alice", "bob-local": "bob", "carol-local": "carol"
	}.get(credentials.credentials) if credentials else None
	if username is None:
		raise HTTPException(
			401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"}
		)
	return request.app.state.users[username]


CurrentUser = Annotated[dict, Depends(current_user)]


def create_app(secure: bool = False) -> FastAPI:
	@asynccontextmanager
	async def lifespan(application: FastAPI):
		application.state.users = {
			"alice": {"username": "alice", "display_name": "Alice", "tenant": "red", "is_admin": False},
			"bob": {"username": "bob", "display_name": "Bob", "tenant": "red", "is_admin": False},
			"carol": {"username": "carol", "display_name": "Carol", "tenant": "blue", "is_admin": False},
		}
		application.state.notes = {
			1: {"id": 1, "title": "Alice", "body": "your note", "owner": "alice", "tenant": "red", "internal_flag": "FLAG{output_allowlist}"},
			2: {"id": 2, "title": "Bob", "body": "FLAG{owner_scope}", "owner": "bob", "tenant": "red", "internal_flag": "private"},
			3: {"id": 3, "title": "Carol", "body": "FLAG{tenant_scope}", "owner": "carol", "tenant": "blue", "internal_flag": "private"},
		}
		yield
		application.state.users.clear()
		application.state.notes.clear()

	application = FastAPI(title="Local boundary CTF", lifespan=lifespan)

	@application.get("/notes/{note_id}", response_model=NoteOut if secure else None)
	async def read_note(note_id: int, request: Request, user: CurrentUser):
		note = request.app.state.notes.get(note_id)
		if note is None:
			raise HTTPException(404, "Not found")
		if secure and (note["owner"] != user["username"] or note["tenant"] != user["tenant"]):
			raise HTTPException(404, "Not found")
		return note

	@application.get("/me", response_model=ProfileOut)
	async def read_profile(user: CurrentUser):
		return user

	if secure:
		@application.patch("/me", response_model=ProfileOut)
		async def patch_profile(payload: ProfilePatch, user: CurrentUser):
			user["display_name"] = payload.display_name
			return user
	else:
		@application.patch("/me", response_model=ProfileOut)
		async def patch_profile(payload: dict, user: CurrentUser):
			user.update(payload)
			return user

	@application.get("/admin")
	async def admin_flag(user: CurrentUser):
		if user["is_admin"] is not True:
			raise HTTPException(403, "Forbidden")
		return {"flag": "FLAG{property_authorization}"}

	return application


app = create_app()
fixed = create_app(secure=True)
```

`app` is intentionally vulnerable. `fixed` contains the reference repairs. Both have separate disposable state. Public bearer strings are fixture identities, not JWTs, and this single-process in-memory service is not a deployable identity system.

### File: jwt_checks.py

```python
from datetime import datetime, timedelta, timezone

import jwt


LAB_KEY = "public-lab-key-not-for-production-1234567890"
ISSUER = "https://issuer.example"
AUDIENCE = "vault-api"


def valid_claims() -> dict:
	now = datetime.now(timezone.utc)
	return {
		"sub": "alice", "iss": ISSUER, "aud": AUDIENCE,
		"iat": now, "nbf": now, "exp": now + timedelta(minutes=5),
	}


def verify(token: str) -> dict:
	claims = jwt.decode(
		token,
		LAB_KEY,
		algorithms=["HS256"],
		issuer=ISSUER,
		audience=AUDIENCE,
		leeway=5,
		options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp"]},
	)
	if not isinstance(claims["sub"], str) or not claims["sub"]:
		raise jwt.InvalidTokenError("Subject must be nonempty")
	return claims
```

This decoder is a separate micro-lab. It does not silently replace the CTF's fixture bearer scheme. The key is intentionally public, so anyone can sign its test tokens; the exercise proves claim validation, not secret management or real identity-provider trust.

### File: test_ctf.py

```python
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ctf import NoteOut, create_app
from jwt_checks import LAB_KEY, valid_claims, verify


ALICE = {"Authorization": "Bearer alice-local"}


def test_vulnerable_flags_are_reachable():
	with TestClient(create_app()) as client:
		own = client.get("/notes/1", headers=ALICE)
		assert own.json()["internal_flag"] == "FLAG{output_allowlist}"
		assert client.get("/notes/2", headers=ALICE).json()["body"] == "FLAG{owner_scope}"
		assert client.get("/notes/3", headers=ALICE).json()["body"] == "FLAG{tenant_scope}"
		assert client.get("/admin", headers=ALICE).status_code == 403
		assert client.patch("/me", headers=ALICE, json={"is_admin": True}).status_code == 200
		assert client.get("/admin", headers=ALICE).json()["flag"] == "FLAG{property_authorization}"


def test_fixed_filtering_and_allowed_update():
	with TestClient(create_app(secure=True)) as client:
		response = client.get("/notes/1", headers=ALICE)
		assert response.status_code == 200
		assert response.json() == {"id": 1, "title": "Alice", "body": "your note"}
		renamed = client.patch("/me", headers=ALICE, json={"display_name": " Alice 2 "})
		assert renamed.status_code == 200
		assert renamed.json() == {"username": "alice", "display_name": "Alice 2"}


@pytest.mark.parametrize("note_id", [2, 3, 999])
def test_fixed_object_policy(note_id):
	with TestClient(create_app(secure=True)) as client:
		response = client.get(f"/notes/{note_id}", headers=ALICE)
		assert response.status_code == 404
		assert response.json() == {"detail": "Not found"}


@pytest.mark.parametrize("field,value", [
	("is_admin", True), ("tenant", "blue"), ("username", "carol")
])
def test_fixed_property_policy(field, value):
	with TestClient(create_app(secure=True)) as client:
		payload = {"display_name": "Alice", field: value}
		assert client.patch("/me", headers=ALICE, json=payload).status_code == 422
		assert client.get("/admin", headers=ALICE).status_code == 403
		assert client.get("/notes/3", headers=ALICE).status_code == 404


@pytest.mark.parametrize("secure", [False, True])
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid"}])
def test_authentication_remains_required(secure, headers):
	with TestClient(create_app(secure=secure)) as client:
		response = client.get("/notes/1", headers=headers)
		assert response.status_code == 401
		assert response.headers["www-authenticate"] == "Bearer"


def test_direct_response_bypasses_model_filtering():
	demonstration = FastAPI()

	@demonstration.get("/demo", response_model=NoteOut)
	async def direct_response():
		return JSONResponse({"id": 1, "title": "demo", "body": "public", "internal": "leaked"})

	with TestClient(demonstration) as client:
		assert client.get("/demo").json()["internal"] == "leaked"


def test_valid_jwt():
	token = jwt.encode(valid_claims(), LAB_KEY, algorithm="HS256")
	assert verify(token)["sub"] == "alice"


@pytest.mark.parametrize("field,value", [
	("iss", "https://other.example"), ("aud", "another-api"), ("sub", "")
])
def test_invalid_identity_claims(field, value):
	claims = valid_claims()
	claims[field] = value
	with pytest.raises(jwt.InvalidTokenError):
		verify(jwt.encode(claims, LAB_KEY, algorithm="HS256"))


@pytest.mark.parametrize("case", ["expired", "future", "missing_exp", "bad_key", "bad_alg"])
def test_invalid_token_conditions(case):
	claims = valid_claims()
	key, algorithm = LAB_KEY, "HS256"
	if case == "expired":
		claims["exp"] = datetime.now(timezone.utc) - timedelta(minutes=1)
	elif case == "future":
		claims["nbf"] = datetime.now(timezone.utc) + timedelta(minutes=1)
	elif case == "missing_exp":
		del claims["exp"]
	elif case == "bad_key":
		key = "another-public-lab-key-not-production-1234567890"
	elif case == "bad_alg":
		algorithm = "HS384"
		key = LAB_KEY * 2
	with pytest.raises(jwt.InvalidTokenError):
		verify(jwt.encode(claims, key, algorithm=algorithm))
```

The direct-response test intentionally proves a dangerous exception to filtering; it is not an endorsement of that route. The vulnerable-service test expects flags to be exposed. Only the fixed-mode tests assert the repairs.

### Start the Target

Use the four file blocks above in the same disposable directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn ctf:app --host 127.0.0.1 --port 8001
```

The package versions are the example baseline, not a production lock/audit. In a second terminal, establish a baseline:

```powershell
$headers = @{ Authorization = 'Bearer alice-local' }
Invoke-RestMethod http://127.0.0.1:8001/me -Headers $headers
curl.exe -i http://127.0.0.1:8001/admin -H 'Authorization: Bearer alice-local'
```

Expected: Alice's profile and an initial 403 from `/admin`. If the admin call succeeds before the exercise, restart the service to reset state. If the port is occupied, choose a free port and consistently change the URLs.

### Objectives and Hints

1. Read a permitted note and find a property outside its public contract. Hint: compare all JSON keys with what a normal notes UI needs.
2. Obtain another owner's body without changing your bearer. Hint: `/notes/1` is Alice, `/notes/2` is Bob in the same tenant, `/notes/3` is Carol in another tenant.
3. Reach `/admin` as Alice. Hint: the profile endpoint accepts a JSON dictionary, not a write-specific model; the output model does not constrain stored mutations.
4. Start the fixed implementation and repeat the **same** requests. Legitimate operations must still work while the three unwanted capabilities disappear.

### Solution and Fixed Retest

```powershell
$headers = @{ Authorization = 'Bearer alice-local' }
Invoke-RestMethod http://127.0.0.1:8001/notes/1 -Headers $headers
Invoke-RestMethod http://127.0.0.1:8001/notes/2 -Headers $headers
Invoke-RestMethod http://127.0.0.1:8001/notes/3 -Headers $headers
Invoke-RestMethod http://127.0.0.1:8001/me -Method Patch -Headers $headers `
	-ContentType 'application/json' -Body '{"display_name":"Alice","is_admin":true}'
Invoke-RestMethod http://127.0.0.1:8001/admin -Headers $headers
```

Expected vulnerable observations: the first response includes `FLAG{output_allowlist}`; the second contains `FLAG{owner_scope}`; the third contains `FLAG{tenant_scope}`; the profile update succeeds and `/admin` returns `FLAG{property_authorization}`.

Stop Uvicorn with Ctrl+C, then start the reference fix on the same address:

```powershell
.\.venv\Scripts\python.exe -m uvicorn ctf:fixed --host 127.0.0.1 --port 8001
```

| Repeated operation | Fixed acceptance criterion | Repair in code |
|---|---|---|
| Read own note | 200; exactly `id`, `title`, `body` | `response_model=NoteOut` |
| Read Bob/Carol note | 404 for both | Owner **and** tenant check |
| PATCH including `is_admin` | 422; no stored privilege change | Write-specific model, extra fields forbidden, explicit assignment |
| GET `/admin` | 403 | Action check still enforced |
| PATCH only `display_name` | 200; name changes | Legitimate update remains available |

PowerShell's `Invoke-RestMethod` throws for expected non-success statuses. Use `curl.exe -i` to inspect them, or PowerShell 7's `Invoke-WebRequest -SkipHttpErrorCheck` when scripting assertions. Do not interpret that expected exception as a crashed server.

### Automated Acceptance and Cleanup

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip freeze
```

Tests run both implementations in-process and reset state per application. They also check JWT failure cases and demonstrate direct-response filtering bypass. They do **not** prove TLS, real issuer trust, proxy correctness, browser CORS enforcement, or overload resilience.

- [ ] Obtain each flag through the intended HTTP boundary, not by reading its source value.
- [ ] Run the fixed retest and show both denied attacks and the still-permitted profile update.
- [ ] Run all included tests; distinguish tests proving a vulnerability from tests proving a fix.
- [ ] Stop the server, verify requests no longer connect, and remove the disposable lab directory. No persistent database or remote resource was created.

The original draft's open-ended lab prompts are replaced by this reproducible exercise; study completion is still yours to record.

Author verification: the printed CTF, decoder, and tests were extracted directly from this note and passed 22 tests on Python 3.12 with the pinned packages. The live-server commands and browser/proxy/overload boundaries are separate from those in-process tests.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[FastAPI]]

## References

- [FastAPI security dependencies](https://fastapi.tiangolo.com/tutorial/security/)
- [FastAPI response-model behavior](https://fastapi.tiangolo.com/tutorial/response-model/)
- [PyJWT validation API](https://pyjwt.readthedocs.io/en/stable/api.html)
- [FastAPI CORS configuration](https://fastapi.tiangolo.com/tutorial/cors/)
- [FastAPI behind a proxy](https://fastapi.tiangolo.com/advanced/behind-a-proxy/)
- [OWASP API security risks](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP CSRF prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
