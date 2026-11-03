---
title: "Flask"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Flask Security]]"
updated: 2026-11-03
---
# Flask

> [!abstract] TL;DR
> Use render_template with fixed templates and data parameters. Keep debug disabled in deployment and avoid storing secrets in client-readable session contents.

> [!info] Agent scope
> Application factory; request context; routing; sessions; Jinja integration; WSGI deployment; debug configuration.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Flask 3.1 given Python context managers, HTTP and HTML. Trace WSGI into
application/request contexts, URL matching, before_request, view, error handler,
after_request, session saving and teardown. Explain LocalProxy/contextvars, g,
factories, blueprints, extension init_app, signed cookies, Jinja autoescape and
async-view limits under WSGI. Cover database unit-of-work ownership, forms/CSRF,
authorization, ProxyFix, trusted hosts, debug settings and Waitress/Gunicorn
deployment. Give complete examples and unittest test-client checks with expected
results, using official Pallets sources and explicit version assumptions. Teach
here without editing files; do not claim unexecuted examples were tested.
```

## Cheatsheet

### Lifecycle and Context

`create_app` constructs a distinct Flask instance, loads configuration, calls extensions' `init_app`, registers blueprints and returns the WSGI callable. Do this before serving; setup after the first request can diverge across workers. An extension object can be module-global if its application-specific state is attached during initialization rather than retained globally.

For a request Flask pushes an application context and request context, opens the session, matches URL/method, invokes preprocessing/view logic, converts the result to a response, runs response processing, saves the session, and tears contexts down. Error handlers can convert exceptions to responses; teardown runs even when dispatch fails. Teardown must release resources, not assume a successful response or silently commit failed work.

`request`, `session`, `current_app` and `g` are context-local proxies, not ordinary globals. `g` normally lives for the application context associated with one request; it is not cross-request storage. Access outside a context raises RuntimeError. A background job must receive explicit immutable inputs and establish its own application context where needed; passing `request` or a live database connection into it is unsafe.

### Routing, Rendering and State

| API | Semantics and edge case |
|---|---|
| `@app.get('/items/<int:item_id>')` | Converter rejects non-integers during routing, typically 404; it does not check existence/ownership. Wrong method is 405. |
| `request.get_json()` | Parses JSON; unsupported media types produce 415 in recent Flask. `silent=True` can hide malformed input as None. Validate the resulting structure. |
| `render_template('page.html', value=data)` | Fixed source, data substitution. HTML templates autoescape; `Markup`/`safe` opt out and require already-safe content. HTML escaping alone does not validate URL schemes. |
| `session['name'] = value` | Default session is signed client-side data: integrity, not confidentiality. Nested mutations may require `session.modified=True`. Cookie size is limited. |
| `redirect(url_for(...), code=303)` | Post/Redirect/Get avoids form resubmission; redirects do not undo a database commit. |
| `errorhandler` | Register specific HTTP/domain exceptions and preserve status. A blanket Exception handler can accidentally turn 404/405 into 500. |

Use a transaction around the service operation, not a commit in teardown. Authenticate through a maintained session/login component, then constrain database lookups by the server-derived user. Flask supplies neither object authorization nor built-in complete CSRF protection. A cookie session signature does not eliminate CSRF.

### Versions and Deployment

Flask 3 uses modern contextvars-based context handling; old context-stack recipes and deprecated hooks are not portable. Flask 3.1 adds `TRUSTED_HOSTS` and additional request/form resource controls. `MAX_CONTENT_LENGTH` bounds request bodies; also review multipart part count and field limits. Async views require Flask's async extra and still occupy a WSGI worker; background tasks created inside an async view may be cancelled when its loop ends.

Waitress works on Windows and POSIX; Gunicorn is commonly used on Unix. The built-in development server is not a production server. Set debug false, use a persistent deployment secret, terminate HTTPS at controlled ingress and configure `ProxyFix` only for exact trusted forwarded-header counts. Multiple workers do not share module dictionaries or in-memory sessions.

## Gotchas

A signed session is tamper-evident, not confidential. Flask does not add every security control automatically.

## Labs

- [ ] Local Flask exercise: Build a factory-based app with a form, signed session, and parameterized template. Use the test client for missing input, unauthorized access, and a literal HTML marker.
- [ ] Boundary check: Submit a template-expression marker as ordinary form data and confirm literal output. Verify a state-changing form fails without its CSRF token in the chosen protection library.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. CPython 3.12-3.14; supported Flask 3.1.x, Flask-WTF 1.2.x, WTForms 3.2.x, Waitress 3.0.x. Resolve patched releases in these lines and record `python -m pip freeze` after installation; ranges are not a reproducible lock. Create a disposable directory and the files below, including the templates subdirectory.

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
from flask import Flask, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def create_app(config=None):
	app = Flask(__name__)
	app.config.from_mapping(SECRET_KEY=os.environ.get("LAB_SECRET"), DEBUG=False,
		MAX_CONTENT_LENGTH=4096, SESSION_COOKIE_HTTPONLY=True,
		SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False,
		TRUSTED_HOSTS=["localhost", "127.0.0.1"])
	app.config.update(config or {})
	if not app.config["SECRET_KEY"]:
		raise RuntimeError("Set LAB_SECRET")
	csrf.init_app(app)

	@app.before_request
	def request_state():
		g.label = "request-local"

	@app.get("/")
	def home():
		return render_template("page.html", name=session.get("name", "guest"), label=g.label)

	@app.post("/name")
	def save_name():
		name = request.form.get("name", "").strip()
		if not name or len(name) > 40:
			return {"error": "invalid_name"}, 400
		session["name"] = name
		return redirect(url_for("home"), code=303)

	return app
```

### File: templates/page.html

```html
<!doctype html>
<html lang="en"><title>Name</title><body>
<p id="name">{{ name }}</p><p>{{ label }}</p>
<form method="post" action="{{ url_for('save_name') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="name" maxlength="40" required>
  <button type="submit">Save</button>
</form></body></html>
```

### File: test_example.py

```python
import unittest
from html.parser import HTMLParser
from flask import g
from example import create_app


class TokenParser(HTMLParser):
	token = None
	def handle_starttag(self, tag, attrs):
		fields = dict(attrs)
		if tag == "input" and fields.get("name") == "csrf_token":
			self.token = fields["value"]


class FlaskTests(unittest.TestCase):
	def setUp(self):
		self.app = create_app({"TESTING": True, "SECRET_KEY": "synthetic-test-only"})
		self.client = self.app.test_client()

	def token(self):
		parser = TokenParser()
		parser.feed(self.client.get("/").get_data(as_text=True))
		self.assertIsNotNone(parser.token)
		return parser.token

	def test_session_and_escape(self):
		response = self.client.post("/name", data={"name": "<b>literal</b>", "csrf_token": self.token()})
		self.assertEqual(response.status_code, 303)
		page = self.client.get("/").get_data(as_text=True)
		self.assertIn("&lt;b&gt;literal&lt;/b&gt;", page)
		with self.client.session_transaction() as stored:
			self.assertEqual(stored["name"], "<b>literal</b>")

	def test_invalid_and_context(self):
		self.assertEqual(self.client.post("/name", data={"name": "ok"}).status_code, 400)
		self.assertEqual(self.client.post("/name", data={"name": "", "csrf_token": self.token()}).status_code, 400)
		with self.assertRaises(RuntimeError):
			_ = g.label


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Commands

PowerShell: `py -3.12 -m venv .venv`; `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`; `.\.venv\Scripts\python.exe -m unittest -v`. Set a disposable signing key with `$env:LAB_SECRET = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")`, then `.\.venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 --call example:create_app`. Open `http://127.0.0.1:8000/` and submit a name. POSIX uses `.venv/bin/python`, `.venv/bin/waitress-serve` and exported `LAB_SECRET`.

### Hints and Separate Solution

The hidden token binds the form submission to a session; name persistence is a separate signed-cookie feature. Expected: two passing unittest methods, valid POST 303, page contains escaped text, missing token/empty name 400, and accessing `g` outside a context raises RuntimeError. A new app instance with a different secret invalidates existing cookies. The supplied factory is the solution; no route requires an unwritten companion service.

### Troubleshooting and Reset

An absent secret fails at startup. A 400 after restarting with a new secret means reload the form to obtain a new session/token. `Secure=False` is deliberately limited to loopback HTTP; production HTTPS should use Secure. Stop Ctrl+C, clear site cookies and unset `LAB_SECRET` to reset. This lab uses a guest preference, not authentication; authorization is exercised in [[Flask Security]].

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Flask Security]]

## References

- [Flask lifecycle](https://flask.palletsprojects.com/en/stable/lifecycle/)
- [Application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/)
- [Request context](https://flask.palletsprojects.com/en/stable/reqcontext/)
- [Flask-WTF CSRF](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/)
