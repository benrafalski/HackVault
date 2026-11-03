---
title: "XSS"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# XSS

> [!abstract] TL;DR
> XSS occurs when attacker-controlled data reaches a browser execution context without the required separation, encoding, or sanitization.

> [!info] Agent scope
> Reflected, stored, and DOM XSS; source-to-sink flow; HTML/attribute/JavaScript contexts; encoding; sanitization; CSP limits.

## Learn

```text
Teach XSS at expert defensive depth, assuming HTML parsing, JavaScript, HTTP,
and the same-origin policy. Separate reflected/stored delivery from server/DOM
execution paths. Trace sources through decoding and transformations into HTML,
quoted attributes, URL attributes, JavaScript, and CSS contexts. Explain why
one encoder cannot secure all contexts, and why parsing and execution differ.
Work through textContent, element construction, fixed templates, URL allowlists,
and maintained rich-text sanitization without any exploit strings. Compare CSP
nonces/hashes, strict-dynamic, and Trusted Types, including support limitations,
report-only versus enforcement, policy creation, and dangerous trust escapes.
Discuss stored content, hydration, framework escape hatches, and second renders.
Provide synthetic rendering regressions, evidence interpretation, and difficult
review questions with answers. Cite primary browser/framework specifications.
No payloads, bypasses, data theft, live exploitation, RCE, scanning, or chains.
Teach the topic, not file authoring; do not claim unexecuted tests passed.
```

## Cheatsheet

> [!important] Defensive scope
> Only source/sink review and safe rendering regressions are supplied. No executable injection strings or vulnerable browser demonstrations are included.

### Mechanisms and Contexts

An untrusted value must reach a browser interpretation boundary with insufficient separation to create XSS. Mere reflection is not execution. Reflected data arrives with a request; stored data survives into later views; DOM-based data reaches client-side sinks. A stored value can also be DOM-based. Templates, preview panes, admin consoles, and hydration paths can have different sinks for the same field.

| Destination | Preferred operation | Exact limitation |
|---|---|---|
| Text node | `element.textContent = value` | Does not validate business content |
| HTML text in a server template | Autoescaping; `html.escape` for this Python fixture | Must not reuse HTML encoding for script/style |
| Ordinary quoted attribute | Fixed attribute name, quote-aware encoding | Event attributes and arbitrary names are not data-only sinks |
| URL attribute | Fixed scheme/origin policy then attribute handling | Encoding alone does not make a URL destination trustworthy |
| JavaScript/CSS | Keep untrusted data out of source; use typed APIs | JSON serialization alone is not safe inline-script embedding |
| Supported rich HTML | Maintained sanitizer configured for a narrow format | Post-sanitization DOM/string changes can invalidate assumptions |

Secure DOM fragment, not a complete page:

```javascript
const label = document.createElement("span");
label.textContent = displayName;
container.replaceChildren(label);
```

`textContent` on an ordinary display element preserves text; it is not permission to write untrusted source into a `script` element. React's ordinary text interpolation is escaped, but explicit HTML APIs are a separate trust decision. Template trust annotations and framework sanitization overrides need review. Avoid repeated encode/decode cycles; encode for the final sink.

### CSP, Evidence, and Limits

An HTTP CSP with `script-src` nonces or hashes limits which scripts may run; nonces must be unpredictable, response-specific, and inserted only on trusted scripts. `strict-dynamic` delegates loading trust from authorized scripts in supporting browsers, so those scripts must be reviewed. Report-only records violations but does not block. CSP does not repair unsafe DOM construction or authorize actions. `HttpOnly` limits JavaScript cookie access, not all actions available to an origin.

Trusted Types enforcement (`require-trusted-types-for 'script'`) restricts selected DOM injection sinks where supported; it is not universal browser support or automatic sanitization. Review the policy implementation and any default policy. Record the exact browser build and production response headers during integration validation. A CSP report is evidence of a policy violation, not proof of a successful attack or of complete prevention.

## Defense

Inventory sources and final contexts, preserve trusted template source, use safe DOM construction, and isolate rich-text handling. Patch sanitizers and retest after renderer upgrades. Bound input length and avoid logging full private content. Keep authentication, authorization, CSRF protection, and origin isolation independent. Primary prevention is context-correct output handling, with CSP as an additional layer.

## Labs

### Environment and Objectives

Python 3.12 standard library; one file, no services, browser, or packages. Review a proposal that inserts profile labels into HTML using string concatenation. Replace that contract with text-only rendering. Synthetic labels include ordinary quotation marks and inert formatting text. The exercise tests resulting parse structure without executing anything.

### File: test_example.py

```python
from html import escape
from html.parser import HTMLParser
import unittest


def render_label(value):
	if type(value) is not str or len(value) > 200:
		raise ValueError("invalid label")
	return '<span class="label">' + escape(value, quote=True) + '</span>'


class ParsedLabel(HTMLParser):
	def __init__(self):
		super().__init__(convert_charrefs=True)
		self.tags = []
		self.text = []

	def handle_starttag(self, tag, attrs):
		self.tags.append((tag, attrs))

	def handle_data(self, data):
		self.text.append(data)


class RenderingTests(unittest.TestCase):
	def test_text_round_trip(self):
		for value in ["Ada", "A & B", 'A "quoted" label', "<b>Draft</b>"]:
			with self.subTest(value=value):
				parsed = ParsedLabel()
				parsed.feed(render_label(value))
				parsed.close()
				self.assertEqual(parsed.tags, [("span", [("class", "label")])])
				self.assertEqual("".join(parsed.text), value)

	def test_encoding_is_for_html_text(self):
		self.assertIn("&lt;b&gt;", render_label("<b>Draft</b>"))
		self.assertIn("&amp;", render_label("A & B"))

	def test_contract(self):
		for value in [None, ["Ada"], "A" * 201]:
			with self.subTest(value=value), self.assertRaises(ValueError):
				render_label(value)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on systems without the Windows launcher. Hint: compare parsed element count with reconstructed text. Seeing angle brackets on screen is permitted; creating new DOM elements is not this renderer's contract.

Solution: keep the wrapper trusted and encode only the text value once. Expected: three tests pass; the only element is `span`, its class stays fixed, and each original label round-trips as text. No script is present or executed. `HTMLParser` is not a full browser HTML5 parser and does not establish CSP enforcement, sanitizer safety, JavaScript-context safety, or framework hydration behavior.

### Verification, Troubleshooting, and Cleanup

The named file is the entire lab, with all data inline. Run in its directory; an import error usually means the filename or working directory differs. Do not name the file `html.py`. Remove the disposable directory and optional `__pycache__` afterward. Authoring was static only; tests and browser compatibility remain unverified.

- [ ] Local XSS exercise: Review source-to-sink contexts and the text-only implementation.
- [ ] Boundary check: Verify literal text and unchanged element structure in the regression suite.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [DOM Standard: textContent](https://dom.spec.whatwg.org/#dom-node-textcontent)
- [CSP Level 3](https://www.w3.org/TR/CSP3/)
- [Trusted Types specification](https://www.w3.org/TR/trusted-types/)
- [Python 3.12 HTML escaping](https://docs.python.org/3.12/library/html.html)
- [React common components and dangerous HTML](https://react.dev/reference/react-dom/components/common)
