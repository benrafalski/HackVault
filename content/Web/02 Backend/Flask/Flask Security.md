---
title: "Flask Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Flask]]"
updated: 2026-11-03
---
# Flask Security

> [!abstract] TL;DR
> Exposed debugging, weak signing keys, untrusted template source, and absent CSRF or resource checks can compromise the application.

> [!info] Agent scope
> Security of: Application factory; request context; routing; sessions; Jinja integration; WSGI deployment; debug configuration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Exposed debugging, weak signing keys, untrusted template source, and absent CSRF or resource checks can compromise the application.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Flask 3.1 security given Python, WSGI, cookies and HTML.
Explain request/application context isolation, signed-cookie integrity versus
confidentiality, key rotation, CSRF, fixed-source Jinja rendering, per-resource
authorization, trusted hosts, proxy counts and debug deployment. Show review-only
unsafe patterns and complete hardened test-client examples with synthetic users,
CSRF enabled, permitted writes, denied writes and literal template text. Cover
database atomicity, response headers, session lifetime and logging limitations.
No exploitation, debugger access, credential theft or bypass demonstrations.
Use public Pallets sources, identify version changes, and label unexecuted
results. Teach in the conversation without file editing instructions.
```

## Cheatsheet

### Trust Boundaries

| Boundary | Root cause | Fix and remaining limit |
|---|---|---|
| Jinja source/data | Rendering user data as template source | Use a fixed `.html` template and keyword values. Avoid `safe`/`Markup` on input. Autoescape does not authorize content or constrain URL schemes. |
| Session cookie | Treating a signature as encryption | Store only minimal nonsecret identity/session claims, or use a maintained server-side store. A client can read signed cookie data. |
| CSRF | Browser automatically sends ambient session cookies | Enable `CSRFProtect` before routes; include tokens in forms or X-CSRFToken for supported AJAX flows. SameSite is defense in depth, not the entire control. |
| Private object | Looking up by ID alone | Constrain read/update by verified principal and object ID. Avoid separate mutable owner checks followed by unrestricted writes. |
| Proxy/Host | Trusting all forwarding hops or arbitrary hosts | Flask 3.1 `TRUSTED_HOSTS`; narrowly configured `ProxyFix` behind controlled ingress. Host validation is distinct from user authentication. |
| Debug/exception | Production debugger or raw traceback response | Debug false, production WSGI server, stable error responses, server-side redacted logs. |

Unsafe review fragment: `render_template_string(request.form['message'])` changes source code based on input. Fixed fragment: `render_template('message.html', message=validated_message)`. The regression should assert literal `{{ label }}` remains literal data and `<b>` is HTML-escaped; no active payload is necessary.

Flask sessions are normally client-side; deleting a browser cookie does not revoke a copied valid cookie. Use short lifetimes and a server-side revocation/version mechanism when needed. Flask 3.1 supports signing-key fallbacks for rotation; old keys extend acceptance and must be removed after the planned overlap. Rotate login session state and never accept role/owner fields from forms as authority.

Factory configuration should fail closed for absent signing keys. `TESTING=True` changes exception behavior; keep CSRF on in the regression suite. For production enable Secure/HttpOnly/SameSite cookies, size limits and appropriate CSP/frame/nosniff headers. HTTPS and correct forwarded scheme are prerequisites for trustworthy Secure-cookie deployment.

## Detection and Defense

Log bounded CSRF failures, authentication outcomes, policy denials and request IDs without cookies/tokens/form bodies. A missing CSRF token may be an expired tab rather than malicious activity. Check deployment flags and proxy topology as configuration evidence; a passing test client cannot prove ingress TLS or header rewriting. Commit database writes inside explicit transactions; teardown closes resources but must not commit an operation that failed authorization.

## Labs

- [ ] Local Flask exercise: Build a factory-based app with a form, signed session, and parameterized template. Use the test client for missing input, unauthorized access, and a literal HTML marker.
- [ ] Boundary check: Submit a template-expression marker as ordinary form data and confirm literal output. Verify a state-changing form fails without its CSRF token in the chosen protection library.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. CPython 3.12-3.14, Flask 3.1.x, Flask-WTF 1.2.x, WTForms 3.2.x and Waitress 3.0.x, with latest patched releases in those lines. New disposable directory. Synthetic sessions are injected only through Flask's trusted test API; there is no public fixture-login route.

### File: requirements.txt

```text
Flask>=3.1,<3.2
Flask-WTF>=1.2,<1.3
WTForms>=3.2,<3.3
waitress>=3.0,<3.1
```

### File: example.py

```python
import os
from flask import Flask, abort, render_template, request, session
from flask_wtf.csrf import CSRFProtect


def create_app(config=None):
	app = Flask(__name__)
	app.config.from_mapping(SECRET_KEY=os.environ.get("LAB_SECRET"), DEBUG=False,
		MAX_CONTENT_LENGTH=4096, SESSION_COOKIE_HTTPONLY=True,
		SESSION_COOKIE_SAMESITE="Lax", TRUSTED_HOSTS=["localhost", "127.0.0.1"])
	app.config.update(config or {})
	if not app.config["SECRET_KEY"]:
		raise RuntimeError("Set LAB_SECRET")
	CSRFProtect(app)
	notes = {1: {"owner": "alice", "text": "synthetic"}}
	app.extensions["lab_notes"] = notes

	@app.get("/")
	def form():
		return render_template("edit.html", message="{{ label }} <b>literal</b>")

	@app.post("/notes/<int:note_id>")
	def edit(note_id):
		user = session.get("user")
		if user not in {"alice", "bob"}:
			abort(401)
		note = notes.get(note_id)
		if not note or note["owner"] != user:
			abort(404)
		if set(request.form) != {"text", "csrf_token"}:
			abort(400)
		text = request.form["text"].strip()
		if not text or len(text) > 80:
			abort(400)
		note["text"] = text
		return {"text": text}

	@app.after_request
	def headers(response):
		response.headers["Cache-Control"] = "private, no-store"
		response.headers["X-Content-Type-Options"] = "nosniff"
		return response

	return app
```

### File: templates/edit.html

```html
<!doctype html>
<html lang="en"><title>Edit</title><body><p>{{ message }}</p>
<form method="post" action="/notes/1">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="text" value="reviewed"><button type="submit">Save</button>
</form></body></html>
```

### File: test_example.py

```python
import unittest
from html.parser import HTMLParser
from example import create_app


class TokenParser(HTMLParser):
	token = None
	def handle_starttag(self, tag, attrs):
		fields = dict(attrs)
		if tag == "input" and fields.get("name") == "csrf_token":
			self.token = fields["value"]


class PolicyTests(unittest.TestCase):
	def setUp(self):
		self.app = create_app({"TESTING": True, "SECRET_KEY": "synthetic-test-only"})
		self.client = self.app.test_client()

	def token(self, user=None):
		with self.client.session_transaction() as stored:
			stored.clear()
			if user:
				stored["user"] = user
		page = self.client.get("/").get_data(as_text=True)
		self.assertIn("{{ label }} &lt;b&gt;literal&lt;/b&gt;", page)
		parser = TokenParser()
		parser.feed(page)
		self.assertIsNotNone(parser.token)
		return parser.token

	def test_negative_and_permitted_writes(self):
		for user, expected in [(None, 401), ("bob", 404), ("alice", 200)]:
			token = self.token(user)
			response = self.client.post("/notes/1", data={"text": "reviewed", "csrf_token": token})
			self.assertEqual(response.status_code, expected)
			if expected != 200:
				self.assertEqual(self.app.extensions["lab_notes"][1]["text"], "synthetic")
		self.assertEqual(response.json, {"text": "reviewed"})
		self.assertEqual(response.headers["Cache-Control"], "private, no-store")

	def test_csrf_and_field_allowlist(self):
		token = self.token("alice")
		self.assertEqual(self.client.post("/notes/1", data={"text": "reviewed"}).status_code, 400)
		response = self.client.post("/notes/1", data={"text": "reviewed", "owner": "bob", "csrf_token": token})
		self.assertEqual(response.status_code, 400)
		self.assertEqual(self.app.extensions["lab_notes"][1]["text"], "synthetic")


if __name__ == "__main__":
	unittest.main()
```

### Objectives, Baseline and Hints

Run `py -3.12 -m venv .venv`, `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`, `.\.venv\Scripts\python.exe -m unittest -v`. Baseline is the single Alice-owned seed. Confirm all denied requests preserve it and the permitted Alice request still succeeds. Hint: get a fresh CSRF token after replacing the fixture session, otherwise CSRF rejection masks the authorization outcome.

### Solution and Fixed Retest

The supplied solution separates CSRF, authenticated principal, owner lookup, field allowlist and output encoding. Predicted suite: two passing methods; authorization cases 401/404/200, absent token and unknown field 400. The literal marker is displayed, never evaluated as template source. No vulnerable server is supplied.

For a local HTTP smoke check, set `$env:LAB_SECRET = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")` and run `.\.venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8001 --call example:create_app`. GET `/` is public; submitting its valid-token form returns 401 because there is deliberately no login endpoint. The test harness owns fixture identity injection.

### Troubleshooting and Reset

If Bob returns 400 instead of 404, obtain the token after changing session identity. Production cookie Secure is omitted only for local HTTP; require it under HTTPS. In-memory mutation is not cross-worker transactional persistence; use an owner-constrained database update in a real app. Stop Ctrl+C, clear cookies, unset `LAB_SECRET`; restarting reseeds data. Remove the disposable directory to remove dependencies.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Flask]]

## References

- [Flask web security](https://flask.palletsprojects.com/en/stable/web-security/)
- [Configuration](https://flask.palletsprojects.com/en/stable/config/)
- [Flask-WTF CSRF](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/)
- [ProxyFix](https://werkzeug.palletsprojects.com/en/stable/middleware/proxy_fix/)
