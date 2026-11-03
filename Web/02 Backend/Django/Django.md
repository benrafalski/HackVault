---
title: "Django"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Django Security]]"
updated: 2026-11-03
---
# Django

> [!abstract] TL;DR
> Run `manage.py check --deploy` against deployment settings. Keep DEBUG false, ALLOWED_HOSTS explicit, and uploaded media separate from executable application code.

> [!info] Agent scope
> Request middleware; views; models; forms; authentication; admin; templates; deployment defaults.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Django 5.2 LTS given Python, SQL, HTTP and templates. Trace middleware
onion order, URL resolution, views, forms, template rendering and response
unwinding. Explain QuerySet laziness, model validation versus database constraints,
transactions/savepoints/on_commit, N+1 queries and async ORM boundaries. Cover
session authentication, model versus object permissions, admin customization,
CSRF test-client defaults, static/media handling and deployment settings.
Provide complete runnable implementations and unittest examples with synthetic
users; include duplicate constraints, rollback, invalid forms and denied object
access. Compare relevant older/newer APIs, cite official sources and label
unexecuted outcomes. Teach here without editing files or assuming vault access.
```

## Cheatsheet

### Request, Model and Form Lifecycle

Middleware wraps the next layer: request work runs top-down, response work bottom-up; short circuits skip inner layers. Place SecurityMiddleware early, SessionMiddleware before AuthenticationMiddleware, and retain CsrfViewMiddleware for cookie-authenticated writes. URL resolution chooses a view; path converters validate syntax, not ownership. A function view returns an HttpResponse; TemplateResponse rendering can be deferred and intercepted.

QuerySets are lazy. Iteration, `list`, `len` and truth testing can execute them; `exists()` is useful only when the later code does not need the rows anyway. Use `select_related` for single-valued joins and `prefetch_related` for collections; constrain columns/relations to avoid accidental disclosure and N+1 work. `get` raises DoesNotExist/MultipleObjectsReturned. `get_object_or_404` converts absence, not failed authorization automatically.

`Form.is_valid()` runs field cleaning then cross-field `clean`; ModelForm adds model-oriented validation. `Model.save()` does not automatically call `full_clean`. Database unique/check constraints remain necessary because two valid forms can race. Restrict ModelForm fields explicitly, exclude ownership and privileged flags, and set them from trusted server context.

### Transactions and Authentication

```python
with transaction.atomic():
	changed = Item.objects.filter(pk=item_id, owner=request.user).update(name=clean_name)
	if changed != 1:
		raise Http404
	transaction.on_commit(lambda: enqueue_notification(item_id))
```

This is a fragment. `atomic` nests savepoints; catch IntegrityError outside the atomic block that failed, not while the connection remains in a broken transaction. `on_commit` avoids sending notifications for rolled-back changes, but a transactional outbox is needed for durable delivery. `ATOMIC_REQUESTS` wraps view execution, not middleware or body generation performed later by streaming responses. SQLite does not model PostgreSQL row-lock behavior; `select_for_update` needs a supporting database and active transaction.

Session authentication loads the user after sessions middleware. `login_required` redirects browser clients by default; API endpoints often need deliberate 401/403 semantics. Django's default backend provides model permissions, not general per-object permissions. `is_staff` permits admin entry, not access to every model/object. Admin ModelAdmin methods such as `get_queryset` and permission hooks must align with application ownership policy.

### Templates and Deployment

Templates autoescape HTML by default. `safe`/`mark_safe` are trust assertions; use `json_script` for structured data embedded in HTML instead of constructing JavaScript literals. Serve collected static assets separately; uploaded media must not execute as application code. `DEBUG=False`, explicit `ALLOWED_HOSTS`, a protected SECRET_KEY, HTTPS-aware cookie settings and a correctly constrained proxy configuration are deployment inputs, not tutorial afterthoughts.

Django 5.2 is an LTS line. It has async view/ORM capabilities, but transaction-heavy ORM work should remain a cohesive synchronous function adapted with the documented sync/async bridge; do not assume `atomic` becomes async-safe by adding `await`. Authentication async APIs and composite-key features differ across versions. Run deployment checks against actual deployment settings, not the lab's intentionally HTTP-only configuration.

## Gotchas

Being authenticated or staff does not automatically imply permission to every object. Development test clients can bypass CSRF unless configured to enforce it.

## Labs

- [ ] Local Django exercise: Build a small model-backed form and per-user detail view. Test validation, CSRF rejection, duplicate constraints, and direct access to another user's object.
- [ ] Boundary check: Use Django's test client with CSRF enforcement enabled and two synthetic accounts. Require denial for missing tokens and cross-user object access.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. CPython 3.12 or 3.13, latest patched Django 5.2.x. This intentionally compact single-file WSGI lab uses an in-memory SQLite database and explicit schema setup, not a production migration scheme. The single-thread standard-library server preserves that connection; do not switch it to a threaded/reloading server. All required files follow.

### File: requirements.txt

```text
Django>=5.2,<5.3
```

### File: example.py

```python
from django.conf import settings
settings.configure(SECRET_KEY="synthetic-local-only", DEBUG=False,
	ALLOWED_HOSTS=["localhost", "127.0.0.1", "testserver"], ROOT_URLCONF=__name__,
	INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions"],
	DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
	MIDDLEWARE=["django.middleware.security.SecurityMiddleware",
		"django.contrib.sessions.middleware.SessionMiddleware",
		"django.middleware.csrf.CsrfViewMiddleware",
		"django.contrib.auth.middleware.AuthenticationMiddleware"],
	TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "OPTIONS": {
		"loaders": [("django.template.loaders.locmem.Loader", {
			"form.html": '<form method="post">{% csrf_token %}{{ form.as_p }}<button>Save</button></form>',
			"login.html": '<form method="post">{% csrf_token %}{{ form.as_p }}<button>Login</button></form>'})]}}],
	LOGIN_REDIRECT_URL="/items", DEFAULT_AUTO_FIELD="django.db.models.AutoField")
import django
django.setup()
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.core.management import call_command
from django.core.wsgi import get_wsgi_application
from django.db import IntegrityError, connection, models, transaction
from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.urls import path
from django.views.decorators.http import require_http_methods


class Item(models.Model):
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	name = models.CharField(max_length=40)
	class Meta:
		app_label = "lab"
		constraints = [models.UniqueConstraint(fields=["owner", "name"], name="unique_owner_name")]


class ItemForm(forms.ModelForm):
	class Meta:
		model = Item
		fields = ["name"]


@require_http_methods(["GET", "POST"])
def items(request):
	if not request.user.is_authenticated:
		return JsonResponse({"error": "authentication_required"}, status=401)
	form = ItemForm(request.POST if request.method == "POST" else None)
	if request.method == "GET":
		return render(request, "form.html", {"form": form})
	if not form.is_valid():
		return JsonResponse({"error": "invalid_name"}, status=400)
	try:
		with transaction.atomic():
			item = form.save(commit=False)
			item.owner = request.user
			item.save()
	except IntegrityError:
		return JsonResponse({"error": "duplicate"}, status=409)
	response = JsonResponse({"id": item.pk, "name": item.name}, status=201)
	response["Location"] = f"/items/{item.pk}"
	return response


@require_http_methods(["GET"])
def detail(request, item_id):
	if not request.user.is_authenticated:
		return JsonResponse({"error": "authentication_required"}, status=401)
	item = Item.objects.filter(pk=item_id, owner=request.user).first()
	if item is None:
		raise Http404
	return JsonResponse({"id": item.pk, "name": item.name})


urlpatterns = [path("login/", LoginView.as_view(template_name="login.html")),
	path("items", items), path("items/<int:item_id>", detail)]


def initialize():
	call_command("migrate", verbosity=0)
	with connection.schema_editor() as editor:
		editor.create_model(Item)
	for name in ("alice", "bob"):
		get_user_model().objects.create_user(username=name, password="synthetic-local-password")


if __name__ == "__main__":
	from wsgiref.simple_server import make_server
	initialize()
	with make_server("127.0.0.1", 8000, get_wsgi_application()) as server:
		server.serve_forever()
```

### File: test_example.py

```python
import unittest
from example import Item, get_user_model, initialize
from django.test import Client


class ModelTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		initialize()

	def setUp(self):
		Item.objects.all().delete()
		self.client = Client(enforce_csrf_checks=True)
		self.alice = get_user_model().objects.get(username="alice")
		self.bob = get_user_model().objects.get(username="bob")
		self.client.force_login(self.alice)
		self.client.get("/items")
		self.token = self.client.cookies["csrftoken"].value

	def post(self, name):
		return self.client.post("/items", {"name": name}, HTTP_X_CSRFTOKEN=self.token)

	def test_form_constraint_and_ownership(self):
		self.assertEqual(self.post("").status_code, 400)
		created = self.post("synthetic")
		self.assertEqual(created.status_code, 201)
		self.assertEqual(self.post("synthetic").status_code, 409)
		self.assertEqual(Item.objects.count(), 1)
		self.assertEqual(self.client.get(created["Location"]).status_code, 200)
		self.client.force_login(self.bob)
		self.assertEqual(self.client.get(created["Location"]).status_code, 404)

	def test_csrf(self):
		self.assertEqual(self.client.post("/items", {"name": "blocked"}).status_code, 403)
		self.assertEqual(Item.objects.count(), 0)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Commands

Create a venv: `py -3.12 -m venv .venv`; install with `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`; run `.\.venv\Scripts\python.exe -m unittest -v`; start `.\.venv\Scripts\python.exe example.py`. POSIX uses `.venv/bin/python`. Open `http://127.0.0.1:8000/login/`, sign in as synthetic Alice with `synthetic-local-password`, and submit the item form twice with the same name. The synthetic password is local fixture data, not a deployment credential.

### Hints and Separate Solution

ModelForm does not accept owner; the view sets it. The unique constraint is enforced at save time and IntegrityError is caught after rollback. Predicted: two passing test methods, valid create 201 with Location, duplicate 409, empty name 400, Bob detail 404 and absent CSRF 403. The supplied files are the complete solution. Ordinary ModelForm validation alone cannot prevent a concurrent duplicate insert.

### Troubleshooting and Reset

Use a fresh Python process per suite; `initialize` intentionally creates the schema once. An unexpected 403 often means the client did not fetch a token after login. The file is not an installable Django project: production apps should use registered apps and reviewed migrations rather than runtime schema creation. Stop Ctrl+C; all users/items/sessions disappear with the in-memory database. Clear browser cookies before restarting. No admin credentials or production deployment are provisioned.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Django Security]]

## References

- [Middleware](https://docs.djangoproject.com/en/5.2/topics/http/middleware/)
- [Transactions](https://docs.djangoproject.com/en/5.2/topics/db/transactions/)
- [Model forms](https://docs.djangoproject.com/en/5.2/topics/forms/modelforms/)
- [Deployment checklist](https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/)
