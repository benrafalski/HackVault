---
title: "Template Engines"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Template Engines Security]]"
updated: 2026-11-03
---
# Template Engines

> [!abstract] TL;DR
> A template is a program; a render context is data. Load application-owned source, compile it once, pass a small view model per render, and encode for the actual output context.

> [!info] Agent scope
> Jinja2; Twig; Razor; parsing and evaluation; escaping contexts; sandbox assumptions; untrusted templates versus template data.

## Prerequisites

- Python mappings, HTML text/attribute contexts, PHP arrays, and basic C#.
- [[Web Lab Setup]]

## Learn

```text
Teach me server-side template engines at expert implementation depth, assuming
Python/PHP/C# basics and HTML. Compare Jinja 3.1, Twig 3.x, and ASP.NET Core
Razor .cshtml, distinguishing them from browser templates and Blazor components.
Trace source loading, lexing, AST construction, compilation, cache lookup,
context resolution, evaluation, output encoding, and response delivery.
Work through inheritance, blocks, includes, macros/partials, missing values,
attribute-versus-item lookup, and per-render data versus shared globals.
Show complete real-engine examples with fixed source and synthetic data; explain
HTML text, quoted attributes, URL validation, JSON-in-HTML, and JS/CSS boundaries.
Explain Markup/raw/IHtmlContent, why escaping is not sandboxing, why Razor is
trusted C# code, and why template sandboxes still need external resource limits.
Compare compiled-template caches with rendered-response caches and tenant keys.
Give expected outputs and tests for missing fields, ordinary markup as text,
empty collections, and disallowed view identifiers. Cite official versioned
documentation, identify untested assumptions, and end with worked review
questions. Teach here; do not author vault files or alter study status. No
exploit payloads, engine escapes, confidential data, or external targets.
```

## Cheatsheet

### Execution Pipeline

1. A logical name selects source through a loader. Search order is significant: an override directory before the bundled directory changes which program runs.
2. The engine parses and compiles source. Jinja emits Python code; Twig generates PHP; the Razor SDK compiles generated C# with the application.
3. Rendering resolves names against the context, executes conditions/loops/helpers, and encodes values at output sites.
4. The resulting bytes still pass through HTTP, browser parsing, and possibly a response cache. Correct HTML encoding does not validate links or authorize the response recipient.

| Concern | Jinja 3.1 | Twig 3.x | Razor on ASP.NET Core 10 |
|---|---|---|---|
| Print / branch | `{{ name }}`, `{% if ready %}` | Same delimiters, different semantics | `@Model.Name`, `@if (...)` |
| Composition | `extends`, blocks, `include`, macros | `extends`, blocks, `include`, macros | Layout, sections, partials, view components |
| Missing data | Default Undefined can print empty; choose `StrictUndefined` | `strict_variables => true` | Strongly typed models catch members at compile time; null remains a runtime concern |
| HTML encoding | Explicit environment configuration required | Set `autoescape => 'html'` explicitly | Strings encoded; `IHtmlContent` writes directly |
| Raw output | `safe`, MarkupSafe `Markup` | `raw`, `Twig\Markup` | `Html.Raw`, `HtmlString` |
| Untrusted source | Sandbox is a restricted runtime, not process isolation | Version-specific sandbox policy | Not a security sandbox; source is trusted C# |

Jinja `item.name` tries an attribute before an item; `item['name']` reverses that preference. A mapping key named `items` can collide with a method. Use bracket access for view-model mappings. Twig dot access can invoke getters/methods; passing a service object is not equivalent to passing a plain array. Razor properties can execute getters too. Materialize a bounded plain-data projection before rendering.

### Output Contexts

| Destination | Required decision |
|---|---|
| HTML text | Autoescape ordinary strings; do not pre-escape and then encode again |
| Quoted attribute | Always quote; HTML encoding protects delimiters, not the attribute's meaning |
| `href` / `src` | Construct routes server-side or validate permitted schemes and destinations, then HTML-encode |
| JavaScript | Prefer a JSON endpoint or a data attribute read by fixed JS; HTML encoding alone is wrong |
| JSON script data | Jinja `tojson` handles HTML-sensitive characters; not safe directly inside a double-quoted HTML attribute |
| CSS / event handler | Do not interpolate free-form user text; map identifiers to fixed application-owned values |

Jinja fragment for trusted source: `<script type="application/json" id="model">{{ model|tojson }}</script>`. This produces inert data, but HTML-safe JSON is still needed because the HTML parser processes the element before any JSON consumer. In Twig use a reviewed JSON embedding strategy, not merely `json_encode|raw`. In Razor the standard JSON helper is preferable to hand-built JSON or an unsafe relaxed encoder.

### Twig Worked Program

Optional independent CLI exercise: PHP 8.3+, Composer 2, current patched Twig 3.x. In an empty directory run `composer require 'twig/twig:^3.0'`, retain the generated lockfile, then `php example.php`. No web server is required. This resolves a version rather than claiming a reproducible latest patch; record `composer show twig/twig`.

### File: example.php

```php
<?php
require __DIR__ . '/vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([
	'base.html.twig' => '<main>{% block body %}{% endblock %}</main>',
	'card.html.twig' => '{% extends "base.html.twig" %}{% block body %}<p>{{ name }}</p>{% endblock %}',
]);
$twig = new \Twig\Environment($loader, [
	'autoescape' => 'html', 'strict_variables' => true, 'cache' => false,
]);
$result = $twig->render('card.html.twig', ['name' => 'Ada & Co']);
if ($result !== '<main><p>Ada &amp; Co</p></main>') {
	throw new \RuntimeException('Unexpected rendering');
}
echo $result, PHP_EOL;
```

### Razor Worked View

Complete optional local project, .NET SDK 10.0, no extra packages. The Web SDK supplies Razor compilation; no runtime compilation package is needed. Create the following three files in an empty directory with a `Pages` subdirectory. Run `dotnet run --urls http://127.0.0.1:5182`; in another terminal `curl.exe http://127.0.0.1:5182/`. Expect `<p>Ada &amp; Co</p>` in the response. This is a Razor Pages rendering exercise, not an API implementation.

### File: RenderLab.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
	<TargetFramework>net10.0</TargetFramework>
	<ImplicitUsings>enable</ImplicitUsings>
	<Nullable>enable</Nullable>
	<EmitCompilerGeneratedFiles>true</EmitCompilerGeneratedFiles>
  </PropertyGroup>
</Project>
```

### File: Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
var app = builder.Build();
app.MapRazorPages();
app.Run();
```

### File: Pages/Index.cshtml

```cshtml
@page
@{
	Layout = null;
	var name = "Ada & Co";
}
<!doctype html>
<html lang="en"><head><title>Render lab</title></head>
<body><p>@name</p></body></html>
```

### Caching and Version Decisions

- Jinja's in-process template cache defaults to 400 entries. A bytecode cache avoids repeat compilation across processes, not rendering. Never let upload writers modify cache storage.
- Pass identity-specific data to `render`, not `Environment.globals` or cached template globals. Those objects outlive a request.
- Twig compilation cache is PHP code, not an HTML cache. `auto_reload` defaults according to debug mode; deploy versioned immutable source or invalidate caches deliberately.
- Twig 3.18 introduced streaming APIs. Yield-ready extensions matter when moving toward Twig 4; do not assume all 3.x extensions support streaming unchanged.
- Razor build/publish compilation and runtime recompilation are different features. Match case in view names across OSes; Linux physical lookup differs from typical Windows filesystems.
- Streaming lowers buffered output memory but errors can occur after headers have been sent. Validate and authorize before producing the first chunk.

## Gotchas

An HTML-safe value is not universally safe. A sandbox does not limit output length, wall time, database calls, or what a helper intentionally exposes. Autoescape depends on the environment and sometimes the filename: a `.txt` email and an `.html` page are different contracts. Do not silently use `default` to hide required view-model fields.

## Labs

### Environment and Complete Files

Primary lab: CPython 3.12, Jinja2 3.1.6, MarkupSafe 3.0.3, pytest 8.3.5. Use a fresh directory, not the vault. No service, network calls, database, or companion note is required after installation. Versions are exercise pins, not a claim that they are the latest security releases. All three engine exercises are **unexecuted author examples**.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install Jinja2==3.1.6 MarkupSafe==3.0.3 pytest==8.3.5
.venv\Scripts\python -m pytest -q
```

### File: test_example.py

```python
import pytest
from jinja2 import DictLoader, Environment, StrictUndefined, UndefinedError

SOURCES = {
	"base.html": "<main>{% block body %}{% endblock %}</main>",
	"card.html": '{% extends "base.html" %}{% block body %}'
				 '<h1>{{ person["name"] }}</h1><ul>'
				 '{% for label in labels %}<li>{{ label }}</li>'
				 '{% else %}<li>None</li>{% endfor %}</ul>{% endblock %}',
}
ENV = Environment(loader=DictLoader(SOURCES), autoescape=True,
				  undefined=StrictUndefined)


def render_card(name, labels):
	if type(name) is not str or len(name) > 80:
		raise ValueError("name")
	if type(labels) is not list or len(labels) > 10:
		raise ValueError("labels")
	if any(type(label) is not str or len(label) > 40 for label in labels):
		raise ValueError("label")
	return ENV.get_template("card.html").render(person={"name": name}, labels=labels)


def test_inheritance_and_encoding():
	assert render_card("Ada & Co", ["<draft>"]) == (
		"<main><h1>Ada &amp; Co</h1><ul><li>&lt;draft&gt;</li></ul></main>"
	)


def test_empty_collection():
	assert "<li>None</li>" in render_card("Ada", [])


def test_missing_required_field():
	with pytest.raises(UndefinedError):
		ENV.get_template("card.html").render(person={}, labels=[])


def test_data_is_not_source():
	assert "{{ label }}" in render_card("{{ label }}", [])


def test_budget():
	with pytest.raises(ValueError):
		render_card("Ada", ["x"] * 11)
```

### Objectives and Steps

1. Predict the five tests' outcomes before running the printed command.
2. Trace the base block override and the loop's empty branch. Explain which stage transforms `&` and which stage resolves `person`.
3. Run the optional Twig and Razor examples independently; inspect generated Razor output under `obj` and compare it with HTML response encoding.

### Hints

The compiled template is reusable; the render context changes. `StrictUndefined` fails when a missing value is used, not when a mapping is created. Do not alter source to insert the name.

### Solution and Expected Results

The complete solution is the test file: fixed DictLoader sources, strict undefined values, explicit autoescape, bounded data. Expected: five tests pass; the markup-like label remains text and the expression-shaped name is never evaluated. Twig's CLI program should emit its one expected line. Razor should return a page with the encoded name. These are acceptance criteria, **not recorded results**.

### Verification, Troubleshooting, and Cleanup

An import failure means the command is using the wrong interpreter. Empty output for missing values indicates the wrong Undefined class. For Twig check PHP/Composer versions and the generated lockfile; for Razor a 404 usually means the file is outside `Pages` or lacks `@page`. Stop Razor with Ctrl+C. Remove only each disposable exercise directory, including `.venv`, `vendor`, `bin`, and `obj`; no system settings were changed.

- [ ] Local Template Engines exercise: render fixed source with bounded data in the real engine; compare output contexts.
- [ ] Boundary check: confirm template-shaped data stays literal, required fields fail loudly, and limits hold.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[SSTI]]
- [[XSS]]
- [[Template Engines Security]]

## References

- [Jinja API and loaders](https://jinja.palletsprojects.com/en/stable/api/)
- [Jinja sandbox limits](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Twig environment and compilation](https://twig.symfony.com/doc/3.x/api.html)
- [Razor syntax and encoding](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor?view=aspnetcore-10.0)
