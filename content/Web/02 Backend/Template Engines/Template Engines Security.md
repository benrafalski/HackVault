---
title: "Template Engines Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Template Engines]]"
updated: 2026-11-03
---
# Template Engines Security

> [!abstract] TL;DR
> Keep template programs and loaders deployment-owned. Validate view identifiers and data, encode at the final output context, and treat helpers and raw-output types as explicit capabilities.

> [!info] Agent scope
> Security of: Jinja2; Twig; Razor; parsing and evaluation; escaping contexts; sandbox assumptions; untrusted templates versus template data. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Template source, theme uploads, dynamic includes, helper functions, rich objects, compiled caches, and response caches are distinct boundaries. Stored data from a database is still untrusted display data. This note covers defensive review and local rendering tests only; it does not compile hostile templates or demonstrate escapes.

## Learn

```text
Teach me defensive security for Jinja 3.1, Twig 3.x, and ASP.NET Core Razor.
Assume template syntax, HTML contexts, and application authorization basics.
Trace each trust boundary: source, loader name, context object, helper call,
compiled cache, rendered output, and shared response cache. Distinguish source
evaluation from HTML interpretation; explain exactly what autoescape does not
guarantee. Compare Jinja StrictUndefined and Sandbox, Twig strict_variables and
version-specific sandbox policy, and Razor's trusted C# compilation model.
Show safe fixed-source code, view-name allowlists, primitive-only view models,
output-context decisions, and application-owned include paths. Review raw/safe,
IHtmlContent and rich objects without giving any exploit or escape payloads.
Provide an offline real-engine lab using benign text/markup, a reproducible
incorrect-encoding baseline, the fixed implementation, and identical tests
showing both rejection and legitimate rendering. Cover budgets, process
isolation, cache tenant keys, error redaction, audit evidence and false positives.
Use official primary docs and name version assumptions. Do not claim tests ran,
edit files, change study status, or provide bypass/credential-theft walkthroughs.
```

## Cheatsheet

### Root Causes and Controls

| Boundary | Failure | Concrete control / remaining limit |
|---|---|---|
| Source | Request or stored text becomes program input | Use `get_template('card.html').render(...)`; never concatenate data into compilation input |
| Selection | A valid loader name selects an inappropriate template | Map public choices to a small fixed set; filesystem confinement alone is not authorization |
| Context | A property/getter or helper exposes more than display data | Copy approved scalar fields; omit request/configuration/service/ORM objects |
| Output | Raw types suppress encoding | Ordinary strings by default; narrow reviewed HTML sanitizer boundary if rich text is required |
| Resource use | Valid templates iterate unbounded data or call expensive helpers | Bound inputs before render; isolate untrusted authoring with CPU/memory/time/output caps |
| Cache | Compiled source is writable or response keys mix identities | Deployment-owned compilation cache; authorized, identity-aware response caching |

Jinja standalone `Environment()` does not enable autoescape by default. `select_autoescape` bases the decision on extensions and string defaults, not analysis of every HTML sink. `StrictUndefined` catches missing data, not dangerous source. A Jinja sandbox restricts selected operations; it is not an OS boundary and does not neutralize trusted helpers that themselves perform I/O.

Twig uses its own escaping strategies and sandbox policy. Configure `autoescape => 'html'` and `strict_variables => true` explicitly. `raw` is a trust assertion; it is not a sanitizer. Twig 3.x is a moving series: use the documentation matching the installed version, particularly sandbox changes and callable behavior. Do not transplant a policy example from another minor version without regression checks.

Razor `.cshtml` compiles trusted C#. String expressions are encoded; `IHtmlContent` is written directly. The safe view fragment is `<p>@Model.DisplayName</p>` where `DisplayName` is a string. `Html.Raw(Model.DisplayName)` changes that contract. A runtime compilation plugin does not turn Razor into a safe user-template interpreter.

### Reviewable Fixed Patterns

Jinja integration fragment, with an application-created `env`:

```python
VIEWS = {"compact": "card.html", "expanded": "details.html"}


def display(env, choice, record):
	if choice not in VIEWS:
		raise ValueError("view")
	view_model = {"name": str(record["display_name"])}
	return env.get_template(VIEWS[choice]).render(person=view_model)
```

Do not blindly stringify arbitrary objects at a public boundary; the fragment assumes `record` is an already validated internal record. The lab enforces exact primitive types. Authorize the record before this function; hiding a field in a template is not access control.

Twig integration fragment, fixed selection and no raw filter:

```php
$views = ['compact' => 'card.html.twig'];
if (!isset($views[$choice])) {
	throw new \InvalidArgumentException('view');
}
echo $twig->render($views[$choice], ['name' => $validatedName]);
```

For links, validate schemes/hosts independently from HTML escaping. Prefer fixed application routes plus encoded path parameters. For JavaScript, prefer a JSON endpoint; an HTML entity encoder is not a JavaScript serializer. For email use separate text and HTML templates, not a global safe flag.

## Detection and Defense

Review compilation entry points (`from_string`, Twig string loading, runtime Razor compilation), dynamic includes, raw-output helpers, environment globals, and cache writers. A string-compilation call is not automatically a defect when the string is a fixed application literal; identify its provenance. Log a template ID, deployment version, duration, output byte count, and redacted error class. Do not log full render contexts. Alert on unexpected template selection, render-time spikes, or cross-tenant response cache hits. Keep error pages generic and full stack traces in restricted logs.

## Labs

### Environment and Complete Files

CPython 3.12; Jinja2 3.1.6; MarkupSafe 3.0.3; pytest 8.3.5. Fresh local directory, no HTTP server and no companion files. The baseline uses harmless `<em>` formatting to demonstrate a text contract violation, not executable browser content. Everything stays in memory. Author execution: **not performed**.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install Jinja2==3.1.6 MarkupSafe==3.0.3 pytest==8.3.5
.venv\Scripts\python -m pytest -q
```

### File: test_example.py

```python
import pytest
from jinja2 import DictLoader, Environment, StrictUndefined

SOURCE = {"card.html": '<p title="{{ name }}">{{ name }}</p>'}


def environment(escape):
	return Environment(loader=DictLoader(SOURCE), autoescape=escape,
					   undefined=StrictUndefined)


def render(name, choice="card", hardened=True):
	if type(name) is not str or len(name) > 80:
		raise ValueError("name")
	if choice != "card":
		raise ValueError("view")
	return environment(hardened).get_template("card.html").render(name=name)


def text_contract(output):
	return "&lt;em&gt;draft&lt;/em&gt;" in output and "<em>" not in output


def test_same_contract_before_and_after():
	sample = "<em>draft</em>"
	assert not text_contract(render(sample, hardened=False))
	assert text_contract(render(sample))


def test_permitted_text_survives():
	assert render("Ada & Co") == (
		'<p title="Ada &amp; Co">Ada &amp; Co</p>'
	)


def test_quotes_encoded():
	assert render('A "note"') == (
		'<p title="A &#34;note&#34;">A &#34;note&#34;</p>'
	)


@pytest.mark.parametrize("choice", ["details", "unknown", ""])
def test_unapproved_views(choice):
	with pytest.raises(ValueError, match="view"):
		render("Ada", choice=choice)


@pytest.mark.parametrize("name", [None, {"name": "Ada"}, "x" * 81])
def test_data_limits(name):
	with pytest.raises(ValueError, match="name"):
		render(name)
```

### Objectives, Baseline, and Hints

Run the one test file. Explain why the exact same `text_contract` rejects the explicit baseline but accepts the hardened output. Determine whether changing `StrictUndefined` alone would fix the baseline (it would not). Identify what else must change before this renderer can accept rich HTML (a separate sanitization and trust policy, not disabling autoescape).

Hint: `<em>` is meaningful markup but contains no scripting. The quote check verifies quoted attributes; it says nothing about URL scheme safety.

### Solution and Fixed Retest

`hardened=True` selects the fixed environment. Both environments render the same application-owned template and the same data. The expected result is nine collected cases passing, including permitted text and all three unknown choices; this is a specification, not a measured pass. A failure only in the quote representation can indicate a dependency/version change: inspect rendered bytes before weakening assertions.

### Verification, Troubleshooting, and Cleanup

Use `.venv\Scripts\python -m pip show Jinja2 MarkupSafe` to record versions. No browser is needed. Do not replace the real engine with Python string formatting. If imports fail, check the venv interpreter. Delete the disposable directory after inspection; no services or system configuration need resetting. Twig and Razor controls above are reference fragments and were not runtime-validated here.

- [ ] Local Template Engines exercise: compare an explicit incorrect-encoding baseline with the fixed real-engine renderer.
- [ ] Boundary check: verify allowed views and text still work while unknown views and invalid data fail.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[SSTI]]
- [[XSS]]
- [[Template Engines]]

## References

- [Jinja environment and escaping](https://jinja.palletsprojects.com/en/stable/api/)
- [Jinja sandbox security considerations](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Twig sandbox documentation](https://twig.symfony.com/doc/3.x/sandbox.html)
- [Razor expression encoding](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor?view=aspnetcore-10.0)
