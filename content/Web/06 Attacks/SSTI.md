---
title: "SSTI"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# SSTI

> [!abstract] TL;DR
> SSTI occurs when user-controlled data becomes server-side template source and is evaluated as template logic.

> [!info] Agent scope
> Template source versus data; engine fingerprinting in labs; evaluation contexts; sandbox limits; safe templating design.

## Learn

```text
Teach server-side template injection as confusion between trusted template source
and untrusted template data. Assume parsing, server rendering, HTML escaping,
and basic Jinja/Twig/Razor syntax. Trace loader selection, compilation, context,
helpers, evaluation, and output. Explain engine identification from manifests,
configuration, and redacted errors rather than expression probes. Contrast text
and expression contexts, HTML autoescaping versus evaluation safety, sandbox
capabilities, globals, object methods, resource limits, and cache/loader trust.
Work through fixed Jinja templates with plain bounded data and regression tests;
compare Twig sandbox policy and Razor's trusted compilation model. Cite vendor
docs, specify versions, and give questions/answers. No evaluation payloads,
bypasses, RCE, shells, theft, scanning, or chains. No file authoring or invented
test results. Explain exactly what the secure fixture does not establish.
```

## Cheatsheet

> [!important] Defensive scope
> This lab renders only a fixed trusted template. No untrusted source is compiled, and no engine probes or executable template payloads are supplied.

### Source, Context, and Output Are Different Boundaries

SSTI requires untrusted influence over template source or another expression-evaluating interface. Normal rendering of a fixed template with data is not inherently SSTI. Available globals, helpers, loaders, and object methods determine the evaluator's authority. Output manipulation is not evidence that every host capability is reachable.

| Boundary | Safe design | Limitation |
|---|---|---|
| Source | Version-controlled fixed templates | A writable template directory is still a trust problem |
| Template selection | Closed map from product choice to template name | A loader name is not an authorization check |
| Context | Plain validated scalars/records | Rich objects may expose methods or sensitive attributes |
| Output | Context-aware autoescaping | HTML escaping does not prevent server evaluation |
| Helpers/globals | Small reviewed capability surface | A helper may do privileged work outside sandbox checks |
| Untrusted authoring | Separate restricted service with quotas and policy | Sandboxing is not universal containment |

Avoid constructing source by concatenating a user label into a template before compilation. Do not render a first result as a second template. A trusted `{{ name }}` expression in the file below reads a data value; it does not recursively compile that value. HTML formatting in a name is escaped because this template is HTML, not because the engine universally knows every output context.

### Engine and Version Details

The fixture pins Jinja2 3.1.6 and MarkupSafe 3.0.3 for Python 3.12. These are reproducibility pins, not a claim that they remain the newest secure versions. `Environment` is not sandboxed. `StrictUndefined` surfaces missing variables but is not a security sandbox. `select_autoescape` depends on template naming and defaults; explicitly configure the formats you serve. `Markup`/safe filters are trust assertions and should not receive unreviewed content.

Jinja's `SandboxedEnvironment` restricts selected operations; callers must still limit exposed objects, helper effects, memory, and CPU. Twig has a distinct sandbox policy and implementation; settings are not interchangeable. Razor compiles application templates and should be treated as trusted application code, not a safe language for arbitrary user templates. Identify engines through dependency manifests and configuration; ambiguous output or error text is weak fingerprint evidence.

For review, record template identity/hash, loader origin, environment configuration, names/types of context values, and whether any path compiles dynamic source. Do not log full rendered personal content. Successful escaping proves a particular output transformation, not that every source path is trusted.

## Defense

Keep template source deployment-owned, allowlist template selection, supply minimal plain data, and maintain autoescaping for each output type. Remove unnecessary globals and filters, patch the engine, and treat user-authored templates as a separate constrained product feature. Enforce resource budgets outside the evaluator when untrusted authoring is required.

## Labs

### Environment and Objectives

Python 3.12 plus the pinned packages below. No server, network use during tests, or companion template file: the trusted template is embedded in the code. Review a proposed personalized-template feature that would compile each submitted label. Explain why the replacement renders data through a single precompiled template.

### File: requirements.txt

```text
Jinja2==3.1.6
MarkupSafe==3.0.3
```

### File: test_example.py

```python
import unittest
from jinja2 import DictLoader, Environment, StrictUndefined, select_autoescape


ENVIRONMENT = Environment(
	loader=DictLoader({"greeting.html": "<p>Hello {{ name }}</p>"}),
	autoescape=select_autoescape(["html"], default_for_string=True),
	undefined=StrictUndefined,
)
TEMPLATE = ENVIRONMENT.get_template("greeting.html")


def greeting(name):
	if type(name) is not str or not 1 <= len(name) <= 80:
		raise ValueError("plain bounded name required")
	return TEMPLATE.render(name=name)


class TemplateTests(unittest.TestCase):
	def test_normal_render(self):
		self.assertEqual(greeting("Ada"), "<p>Hello Ada</p>")

	def test_data_is_html_escaped(self):
		self.assertEqual(greeting("A & B"), "<p>Hello A &amp; B</p>")
		self.assertEqual(greeting("<b>Draft</b>"),
						 "<p>Hello &lt;b&gt;Draft&lt;/b&gt;</p>")

	def test_plain_data_only(self):
		for value in [{"name": "Ada"}, None, "A" * 81]:
			with self.subTest(value=value), self.assertRaises(ValueError):
				greeting(value)

	def test_template_identity_stays_fixed(self):
		before = id(TEMPLATE)
		greeting("First")
		greeting("Second")
		self.assertEqual(id(TEMPLATE), before)
		self.assertEqual(ENVIRONMENT.list_templates(), ["greeting.html"])


if __name__ == "__main__":
	unittest.main()
```

### Setup and Test Commands

Run only when deliberately performing this lab; these commands were not run during authoring:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest -v test_example
```

On POSIX use `python3.12 -m venv .venv` and `.venv/bin/python` for the remaining commands. Installation requires access to an approved package source; tests themselves are offline.

### Hints and Separate Solution

Hint: count template compilation sites and inspect which strings can reach them. Why does restricting context to a plain string also reduce exposed capabilities?

Solution: the loader contains one deployment-owned source, selected before request data exists. The function only renders a bounded string value. Expected: four tests pass; ordinary names render, HTML is escaped, and non-scalar data is rejected. Template identity is a useful regression but code review is still needed to exclude other compilation paths. This lab does not certify sandbox behavior, Twig/Razor configuration, JavaScript output contexts, or untrusted-template safety.

### Troubleshooting and Cleanup

No tests or installations occurred during authoring. `ModuleNotFoundError` means the pinned packages are absent from the interpreter used for testing; use the venv interpreter. Do not name files `jinja2.py` or `markupsafe.py`. Remove the disposable directory, including its venv, after the exercise. No service is started and no application files outside it are changed.

- [ ] Local SSTI exercise: Review the trusted-source versus data boundary in Jinja.
- [ ] Boundary check: Run the fixed-template and safe-output regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Jinja API and autoescaping](https://jinja.palletsprojects.com/en/stable/api/)
- [Jinja sandbox limitations](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Twig sandbox](https://twig.symfony.com/doc/3.x/sandbox.html)
- [ASP.NET Core Razor syntax](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor)
