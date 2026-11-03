---
title: "Django Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Django]]"
updated: 2026-11-03
---
# Django Security

> [!abstract] TL;DR
> Misconfigured deployment, unsafe template filters/raw queries, and missing object-level authorization can bypass otherwise strong framework defaults.

> [!info] Agent scope
> Security of: Request middleware; views; models; forms; authentication; admin; templates; deployment defaults. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Misconfigured deployment, unsafe template filters/raw queries, and missing object-level authorization can bypass otherwise strong framework defaults.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me Django 5.2 LTS defensive security given Python, SQL and browser sessions.
Explain Security/Session/CSRF/Authentication middleware order, session rotation,
model versus object permissions, admin policy, ModelForm allowlists, ORM/raw SQL
boundaries, template context escaping and deployment defaults. Show atomic owner-
constrained updates and negative regressions with Client(enforce_csrf_checks=True)
using synthetic Alice/Bob accounts. Cover permitted operations, unchanged state
after denial, audit evidence, proxy trust, static/media separation and DEBUG.
No exploitation, escalation, credential theft or bypass demonstrations. Use
official public docs and label version assumptions/unexecuted examples. Teach
in the conversation without editing files or requiring a companion lesson.
```

## Cheatsheet

### Defaults and Application Responsibilities

Django ORM ordinary filters bind values, templates escape ordinary HTML output, and CSRF middleware protects unsafe browser methods. These defaults do not authorize rows, sanitize arbitrary HTML, make raw SQL safe, or turn a privileged flag supplied in a form into trustworthy identity.

| Review concern | Fixed design | Regression evidence |
|---|---|---|
| `Document.objects.get(pk=id)` on private data | Filter by ID and authenticated owner/tenant before serialization | Bob sees 404 and no document content; Alice still reads/writes. |
| `ModelForm(fields='__all__')` | Enumerate editable fields and assign owner server-side | Submitted privileged fields are rejected or excluded and persisted owner stays fixed. |
| Raw SQL/dynamic order clause | Parameterize values; map ordering choices to static identifiers | Allowed sort values work, unrecognized choices fail validation. |
| Unsafe template trust assertion | Keep autoescape; use `json_script` for JSON data | Literal markup is escaped and data is not reinterpreted as template source. |
| Staff/admin shortcut | Restrict ModelAdmin queryset and object permission hooks consistently | Staff without specific access cannot view/edit unrelated records. |
| CSRF disabled in tests | Explicit `enforce_csrf_checks=True` and real token round trip | Missing token 403; valid token still proceeds to object policy. |

Unsafe review fragment: `Document.objects.filter(pk=id).update(**request.POST)` combines unrestricted fields with unrestricted row selection. Fixed shape: validate one editable field, then `filter(pk=id, owner=request.user).update(title=clean_title)`. It avoids a read/check/write authorization race. Use `transaction.atomic` for multi-statement invariants; combine constraints and transaction tests on the production database engine.

### Session, Origin and Deployment Boundaries

CSRF is not authentication and CORS is not CSRF protection. `CSRF_TRUSTED_ORIGINS` accepts scheme-qualified trusted origins; do not add wildcards to silence a deployment problem. Configure `SECURE_PROXY_SSL_HEADER` only behind a proxy that strips/replaces the header. Require explicit `ALLOWED_HOSTS`; it protects Host processing, not per-user access.

`login` rotates session keys; logout flushes server-side session state. Secret-key rotation must account for signatures and allowed fallback lifetime. Deploy with DEBUG false, Secure/HttpOnly session cookies, secure CSRF cookies under HTTPS, HSTS only after HTTPS is ready, and media served from a non-executable origin/path. Django 5.2 is LTS; retain patched updates. Run `check --deploy` against real settings and treat warnings as actionable, not a substitute for policy tests.

## Detection and Defense

Monitor `django.security.*` events, CSRF/DisallowedHost rates, admin changes and denied object operations without request bodies or session tokens. Expired forms and misconfigured proxies can create benign CSRF spikes. Admin's log does not audit every API/service write; record application audit events at the committed service boundary, using `on_commit` or an outbox where appropriate.

## Labs

- [ ] Local Django exercise: Build a small model-backed form and per-user detail view. Test validation, CSRF rejection, duplicate constraints, and direct access to another user's object.
- [ ] Boundary check: Use Django's test client with CSRF enforcement enabled and two synthetic accounts. Require denial for missing tokens and cross-user object access.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. CPython 3.12/3.13 and patched Django 5.2.x. This independent single-file WSGI project has an in-memory schema and no public login route. Test code uses `force_login` for synthetic identities; manual HTTP remains anonymous. SQLite and the single-thread server are deliberate local teaching constraints.

### File: requirements.txt

```text
Django>=5.2,<5.3
```

### File: example.py

```python
from django.conf import settings
settings.configure(SECRET_KEY="synthetic-test-only", DEBUG=False, ROOT_URLCONF=__name__,
	ALLOWED_HOSTS=["localhost", "127.0.0.1", "testserver"],
	INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions"],
	DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
	MIDDLEWARE=["django.middleware.security.SecurityMiddleware",
		"django.contrib.sessions.middleware.SessionMiddleware",
		"django.middleware.csrf.CsrfViewMiddleware",
		"django.contrib.auth.middleware.AuthenticationMiddleware"],
	DEFAULT_AUTO_FIELD="django.db.models.AutoField")
import django
django.setup()
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.wsgi import get_wsgi_application
from django.db import connection, models, transaction
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.urls import path
from django.utils.html import format_html
from django.views.decorators.http import require_http_methods


class Document(models.Model):
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	title = models.CharField(max_length=80)
	class Meta:
		app_label = "lab"


@require_http_methods(["GET"])
def form(request):
	return HttpResponse(format_html(
		'<form method="post" action="/documents/1"><input name="csrfmiddlewaretoken" '
		'type="hidden" value="{}"><input name="title" value="reviewed"><button>Save</button></form>',
		get_token(request)))


@require_http_methods(["POST"])
def update(request, document_id):
	if not request.user.is_authenticated:
		return JsonResponse({"error": "authentication_required"}, status=401)
	if set(request.POST) - {"title", "csrfmiddlewaretoken"}:
		return JsonResponse({"error": "unknown_field"}, status=400)
	title = request.POST.get("title", "").strip()
	if not title or len(title) > 80:
		return JsonResponse({"error": "invalid_title"}, status=400)
	with transaction.atomic():
		changed = Document.objects.filter(pk=document_id, owner=request.user).update(title=title)
	if changed != 1:
		return JsonResponse({"error": "not_found"}, status=404)
	response = JsonResponse({"title": title})
	response["Cache-Control"] = "private, no-store"
	return response


urlpatterns = [path("", form), path("documents/<int:document_id>", update)]


def initialize():
	call_command("migrate", verbosity=0)
	with connection.schema_editor() as editor:
		editor.create_model(Document)
	for name in ("alice", "bob"):
		get_user_model().objects.create_user(username=name)
	Document.objects.create(owner=get_user_model().objects.get(username="alice"), title="synthetic")


if __name__ == "__main__":
	from wsgiref.simple_server import make_server
	initialize()
	with make_server("127.0.0.1", 8001, get_wsgi_application()) as server:
		server.serve_forever()
```

### File: test_example.py

```python
import unittest
from example import Document, get_user_model, initialize
from django.test import Client


class PolicyTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		initialize()

	def setUp(self):
		Document.objects.update(title="synthetic")
		self.client = Client(enforce_csrf_checks=True)

	def select(self, user):
		self.client.logout()
		if user:
			self.client.force_login(get_user_model().objects.get(username=user))
		self.client.get("/")
		return self.client.cookies["csrftoken"].value

	def test_owner_policy(self):
		for user, status in [(None, 401), ("bob", 404), ("alice", 200)]:
			token = self.select(user)
			response = self.client.post("/documents/1", {"title": "reviewed"}, HTTP_X_CSRFTOKEN=token)
			self.assertEqual(response.status_code, status)
			self.assertEqual(Document.objects.get(pk=1).title, "reviewed" if status == 200 else "synthetic")
		self.assertEqual(response.json(), {"title": "reviewed"})

	def test_csrf_and_overposting(self):
		token = self.select("alice")
		self.assertEqual(self.client.post("/documents/1", {"title": "no token"}).status_code, 403)
		response = self.client.post("/documents/1", {"title": "reviewed", "owner": "bob"}, HTTP_X_CSRFTOKEN=token)
		self.assertEqual(response.status_code, 400)
		document = Document.objects.get(pk=1)
		self.assertEqual(document.title, "synthetic")
		self.assertEqual(document.owner.username, "alice")


if __name__ == "__main__":
	unittest.main()
```

### Objectives, Baseline and Hints

Run `py -3.12 -m venv .venv`, `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`, then `.\.venv\Scripts\python.exe -m unittest -v`. Optional startup: `.\.venv\Scripts\python.exe example.py`; GET `http://127.0.0.1:8001/` supplies a valid form but submission is anonymous and returns 401. Baseline: one Alice document. Hint: refresh the CSRF token after changing the session; otherwise a 403 can hide the intended ownership assertion.

### Solution and Fixed Retest

The solution is an owner-constrained atomic update plus an explicit field allowlist, with CSRF middleware intact. Expected: two passing methods; 401 anonymous, 404 Bob, 200 Alice, 403 missing token, 400 extra owner field. Denied requests retain the seed and owner. Repeat the same tests after changing middleware or repository code. No vulnerable endpoint or exploitation procedure is supplied.

### Troubleshooting and Reset

Tests must run in a fresh interpreter, without importing another self-configuring Django lab. Do not use a threaded server with this in-memory connection. Restarting clears the database; clear browser cookies as well. Stop Ctrl+C and remove the disposable venv/project. Production migrations, admin integration, real identity provisioning and database-engine concurrency require separate deployment validation; their security responsibilities are described above.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Django]]

## References

- [Django security](https://docs.djangoproject.com/en/5.2/topics/security/)
- [CSRF](https://docs.djangoproject.com/en/5.2/ref/csrf/)
- [Authentication permissions](https://docs.djangoproject.com/en/5.2/topics/auth/default/)
- [Admin permissions](https://docs.djangoproject.com/en/5.2/ref/contrib/admin/)
