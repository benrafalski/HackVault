---
title: "HTML"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[HTML Security]]"
updated: 2026-11-03
---
# HTML

> [!abstract] TL;DR
> Prefer textContent for text, explicit input types, and semantic controls. Inspect the live DOM as well as View Source.

> [!info] Agent scope
> Document parsing; forms; semantic elements; resource loading; attributes; escaping contexts; accessibility basics.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me HTML at expert browser-engineering depth. I know HTTP and basic
JavaScript. Cover tokenizer states, tree construction and error recovery,
source versus live DOM, semantic landmarks, accessible names, form ownership,
successful controls, constraint validation, URL resolution, attributes versus
properties, resource discovery, classic/defer/async/module script scheduling,
and context-specific escaping. Trace a form from user input to encoded request.
Use complete local browser examples, keyboard checks, DOM assertions, and
Network-panel observations. Explain boolean attributes, duplicate form names,
disabled versus readonly, implicit submission, parser-inserted elements, and
why browser validation is not server authorization. Distinguish HTML Living
Standard behavior from browser support. Use WHATWG/W3C primary references.
Provide difficult debugging questions and worked answers. Teach here without
editing files; do not claim examples were executed or mark study completion.
```

## Cheatsheet

### Parsing and Document State

Bytes are decoded using the document encoding, tokenized, and processed by the tree builder. Use `<!doctype html>` for standards mode and put `<meta charset="utf-8">` early in the head. Error recovery is specified behavior, not a validation service: omitted end tags, invalid nesting, and table insertion modes can produce a DOM unlike the source. Inspect both source and Elements; script mutation creates another difference.

The parser can pause at a parser-inserted classic script while the preload scanner discovers later resources. DOM readiness and resource completion are different milestones:

| Resource | Scheduling / consequence |
|---|---|
| Classic external script without attributes | Usually blocks parsing at its position |
| Classic `defer` script | Fetches in parallel, executes in document order after parsing, before `DOMContentLoaded` |
| Classic `async` script | Executes when available; no document-order guarantee |
| `type="module"` | Deferred by default; dependency graph and module CORS rules apply; `async` changes scheduling |
| Stylesheet | Usually render-blocking when applicable; can delay scripts that need preceding styles |
| Image | Does not block DOM construction; intrinsic size discovery can cause layout shift |

`DOMContentLoaded` does not mean images are loaded. `load` is later; lazy resources are special. A module served with the wrong MIME type fails even if the body contains JavaScript. File URLs are not a substitute for an HTTP origin when testing modules or fetch.

Complete resource syntax fragments, not a standalone document:

```html
<link rel="stylesheet" href="/assets/site.css">
<script type="module" src="/assets/main.js"></script>
<img src="/assets/chart.png" width="640" height="320"
		 alt="Completed jobs increased from 4 to 7">
```

Explicit image dimensions reserve space; `alt` expresses the image's purpose, not its filename. Do not lazy-load a primary above-the-fold image merely by habit. Preload only measured critical resources; incorrect `as`, CORS mode, or URL can create duplicate downloads.

### Attributes, Properties, and URLs

| Case | Precise behavior |
|---|---|
| `disabled="false"` | Still disabled: boolean attributes use presence, not the string's truthiness |
| `input.getAttribute("value")` | Initial/default markup value; not necessarily the current edited value |
| `input.value` | Current value; assigning it does not dispatch an input event |
| `input.defaultValue` | Default value used by form reset; reflects the value attribute |
| `link.href` | Resolved absolute URL; the content attribute can remain relative |
| `textContent` | Creates text, without interpreting it as markup |
| `innerHTML` | Parses a fragment in the element's context; not a text API |

Relative URLs resolve against the document base URL, which `<base href>` can change. Setting an attribute through the DOM avoids HTML quotation parsing but does not validate URL schemes or business policy. Never use a single generic escaping function for HTML, CSS, URLs, and JavaScript strings.

### Forms and Semantics

A control needs a `name` to contribute to form data; `id` associates labels and scripting references. Disabled controls are omitted, readonly textual controls are included, unchecked checkboxes are omitted, and repeated names produce repeated entries. `Object.fromEntries(new FormData(form))` loses repeated values: use `getAll()` where multiplicity matters. The clicked submit button's name/value requires a submitter-aware `FormData(form, submitter)` in supporting browsers.

`GET` encodes form fields in the URL, suitable for retrieval but unsuitable for secrets. Default POST encoding is `application/x-www-form-urlencoded`; file uploads need `multipart/form-data`. When sending a `FormData` body with fetch, let the browser supply the multipart boundary. Form validation, field limits, and authorization must also exist at the receiving service.

`requestSubmit()` follows submission and validation behavior. `submit()` skips constraint validation and the submit event; a control named `submit` can also mask that method. Native buttons give keyboard activation and focus behavior that a clickable `div` does not. Use one descriptive `h1`, coherent headings, `main`, explicit labels, and `fieldset`/`legend` for related controls. Placeholder text is not a label. Announce results with `output` or an appropriate live region; do not move focus unexpectedly.

## Gotchas

HTML character references are decoded by the HTML parser, not by arbitrary string consumers. Hidden inputs are ordinary request data, not protected state. Native constraint validation varies in presentation across browsers and is not sufficient accessibility evidence. Custom validation messages must be cleared with `setCustomValidity("")` once the condition is resolved.

## Labs

### Environment and Complete Files

Use a current desktop Chromium or Firefox browser with developer tools. No packages, server, images, or external resources are required. Record browser/version and OS. This complete classic-script document deliberately works when opened directly. Execution has not been performed by the author in this revision.

Create an empty `html-form-lab` directory and the following single file. Synthetic data is embedded; no real addresses are collected.

### File: index.html

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Form serialization lab</title></head>
<body>
<main>
	<h1>Workshop registration</h1>
	<form id="registration" method="get" action="index.html">
		<p><label for="person">Name</label>
		<input id="person" name="person" required maxlength="40" value="Ada"></p>
		<p><label for="email">Email</label>
		<input id="email" name="email" type="email" required value="ada@example.test"></p>
		<fieldset><legend>Sessions</legend>
			<label><input type="checkbox" name="session" value="html" checked>HTML</label>
			<label><input type="checkbox" name="session" value="css" checked>CSS</label>
		</fieldset>
		<input name="reference" value="DEMO-7" readonly aria-label="Reference">
		<input name="internal" value="ignored" disabled aria-label="Disabled example">
		<button type="submit" name="action" value="preview">Preview</button>
		<button type="reset">Reset</button>
	</form>
	<h2>Encoded query</h2><output id="result" aria-live="polite"></output>
	<pre id="checks"></pre>
</main>
<script>
const form = document.querySelector('#registration');
const result = document.querySelector('#result');
form.addEventListener('submit', event => {
	event.preventDefault();
	const data = new FormData(form, event.submitter);
	const query = new URLSearchParams(data).toString();
	result.textContent = query;
});
form.addEventListener('reset', () => { result.textContent = ''; });
function verify() {
	const data = new FormData(form);
	const tests = [
		['standards mode', document.compatMode === 'CSS1Compat'],
		['both sessions retained', data.getAll('session').join(',') === 'html,css'],
		['disabled omitted', !data.has('internal')],
		['readonly included', data.get('reference') === 'DEMO-7'],
		['label associated', document.querySelector('#person').labels.length === 1]
	];
	document.querySelector('#checks').textContent = tests.map(([name, ok]) =>
		`${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n');
}
verify();
</script>
</body></html>
```

### Objectives and Steps

Open `index.html` from the directory in the browser (`Start-Process .\index.html` is an optional PowerShell launch command). Tab through every enabled control; activate Preview with the keyboard. Inspect the live `value` property and `value` attribute after changing Ada to Lin. Submit once with both sessions, then with CSS unchecked. Finally clear the required name and attempt submission. The submit handler previews serialization; it does not claim a request was sent.

To observe an actual GET navigation, temporarily comment out `event.preventDefault()` and submit the synthetic data. The browser navigates to the same file with a query string; a file navigation is not an HTTP server receipt. Restore the line afterward. An HTTP receiver would need its own validation and cannot be inferred from this exercise.

### Hints

Inspect `new FormData(form).getAll('session')`; compare it with `Object.fromEntries`. A required field prevents the submit event on interactive submission. The disabled field is intentionally absent from keyboard traversal and serialization.

### Solution and Expected Results

With defaults, Preview should display `person=Ada&email=ada%40example.test&session=html&session=css&reference=DEMO-7&action=preview`. Unchecking CSS removes only its entry. Empty name keeps the previous preview and displays browser validation UI. All five initial checks should say PASS. A changed `.value` reads Lin while the original `value` attribute remains Ada; Reset restores Ada and clears the preview.

### Verification, Troubleshooting, and Cleanup

Repeat using keyboard only and at 200% zoom. Verify accessible labels in the browser accessibility tree, not only visually. If the submitter field is absent, check support for the two-argument FormData constructor and confirm a submit button was used. If validation never runs, check for `novalidate`, `formnovalidate`, or use of `submit()`. These are expected results, not a report of execution. Close the tab and remove only the disposable lab directory. Keep original user study checkboxes below unchanged.

- [ ] Local HTML exercise: Build a local labeled form with required fields and inspect the resulting request. Disable client validation and submit again; document why the server must validate independently.
- [ ] Boundary check: Render the harmless marker `<b>LAB</b>` once as text and once as HTML in a toy page. The safe text path must display the brackets literally.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Clickjacking]]
- [[HTML Security]]

## References

- [Official documentation or primary training reference](https://html.spec.whatwg.org/multipage/)
