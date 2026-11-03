---
title: "HTML Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[HTML]]"
updated: 2026-11-03
---
# HTML Security

> [!abstract] TL;DR
> Untrusted markup inserted into an executable HTML context can become XSS; trusting form constraints lets crafted requests bypass validation.

> [!info] Agent scope
> Security of: Document parsing; forms; semantic elements; resource loading; attributes; escaping contexts; accessibility basics. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Untrusted markup inserted into an executable HTML context can become XSS; trusting form constraints lets crafted requests bypass validation.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me HTML security as defensive browser engineering. Prerequisites: HTML
forms, HTTP, DOM APIs, and JavaScript. Explain tokenizer contexts, text versus
markup sinks, attribute/URL policy, resource loading, form trust boundaries,
accessible trusted UI, iframe sandboxing, CSP and Trusted Types limitations.
Show concrete safe rendering and URL construction, and distinguish escaping,
sanitization, validation, and server authorization. Cover parser recovery,
base URLs, duplicate names, disabled/hidden fields, and document-versus-response
policy. Use only harmless synthetic fixtures for local validation/hardening
labs, with all files, expected DOM observations and negative regression tests.
No exploit payloads, credential access, bypass or offensive procedures.
Use WHATWG and W3C primary sources and version-qualified browser support.
Teach here, not by editing notes; never fabricate executed results.
```

## Cheatsheet

### Trust Boundaries and Contexts

The critical boundary is data becoming grammar. HTML text, quoted attributes, URL attributes, CSS, and JavaScript are different grammars. Escaping `<` and `&` for text does not establish a safe URL policy or make a string safe inside executable script. Parser repair also means reviewing a string is not equivalent to reviewing its resulting tree.

| Intended value | Construction | Remaining validation |
|---|---|---|
| Plain label | `node.textContent = label` | Length, display direction, business rules |
| Fixed attribute | `node.setAttribute('title', label)` | Use a known attribute name; never arbitrary names |
| Link destination | `new URL(value, trustedBase)` then explicit origin/protocol policy | Redirects and destination authorization are separate |
| Rich document | Maintained sanitizer configured for required elements/attributes only | Keep library updated; do not mutate sanitized output through unsafe transformations |
| JSON data | Fetch JSON, validate shape, render as text | JSON serialization alone is not safe embedding in an HTML script element |

An HTML parser API is not a sanitizer. The synthetic string `<b>LAB</b>` is harmless but illustrates the difference: parsing yields an element; text insertion yields literal angle brackets. The lab restricts its parsed baseline to that fixed fixture. Do not turn it into a user-controlled renderer.

### Forms and Resource Policy

Client `required`, `pattern`, `max`, hidden values, and disabled UI improve interaction but do not protect server state. The server must parse media types correctly, bound request size, validate multiplicity, validate fields, authorize the requested operation against the authenticated principal, and handle CSRF where ambient credentials are used. Prefer explicit scalar/list schemas; do not silently choose first or last duplicate values without a contract.

A fixed action URL is safer than accepting arbitrary submission destinations. Browser constraint validation is not evidence that a request is authorized. `autocomplete` attributes improve correct filling; they are not storage or credential-security controls. GET query strings can appear in history and logs, so use only synthetic, nonsensitive lab data.

Illustrative production response headers, requiring an HTTP deployment and separately hosted script/style files:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

This CSP would block the inline script in the standalone lab; it is a separate deployment example, not a header to paste into that file. `frame-ancestors` must be a response policy, not a meta policy; it restricts who can frame the page, while `frame-src` restricts what this page frames. A nonce must be unpredictable and fresh per response; a fixed nonce in a static example is not a production solution. CSP report-only supports rollout and does not enforce blocking. Reports can include sensitive URLs; minimize and redact telemetry.

Sandboxing reduces iframe capabilities only when permissions are chosen deliberately. Combining same-origin content with both `allow-scripts` and `allow-same-origin` can undermine the intended isolation. Use a separate origin for genuinely untrusted active content; do not treat an iframe wrapper as automatic containment. Trusted Types, where implemented, can constrain dangerous DOM sinks but a permissive policy merely relocates the bug. It does not replace URL validation or server authorization.

## Detection and Defense

Review every path into `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and document writing, including library wrappers. Prefer removal of unnecessary parsing over writing a homegrown sanitizer. Inspect rendered DOM, resolved URLs, browser console policy violations, and Network initiators. An absence of CSP reports is not proof of safe rendering: browser support, policy mode, sampling, and reporting failures matter. Test permitted content alongside rejected data so hardening does not silently break legitimate behavior.

## Labs

### Environment and Complete Files

Current Chromium or Firefox; no server or dependencies. Open the following complete document directly. It performs only in-memory rendering with fixed synthetic strings and never fetches a destination. Record browser/version. All expected results below remain unexecuted in this revision.

### File: index.html

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>HTML rendering boundary</title></head><body>
<main><h1>Rendering policy</h1>
<h2>Fixed baseline</h2><div id="baseline"></div>
<h2>Text-only result</h2><div id="safe"></div>
<h2>Approved link</h2><div id="links"></div>
<pre id="results" role="status"></pre></main>
<script>
const fixture = '<b>LAB</b>';
const baseline = document.querySelector('#baseline');
baseline.innerHTML = fixture;
const safe = document.querySelector('#safe');
safe.textContent = fixture;
const base = new URL('https://docs.example.test/');
function approvedURL(value) {
	if (typeof value !== 'string' || value.length > 200) return null;
	try {
		const url = new URL(value, base);
		if (url.protocol !== 'https:' || url.origin !== base.origin ||
				url.username || url.password) return null;
		return url;
	} catch { return null; }
}
function renderLink(label, destination) {
	const url = approvedURL(destination);
	if (!url) throw new TypeError('Destination rejected');
	const link = document.createElement('a');
	link.textContent = label;
	link.href = url.href;
	return link;
}
const link = renderLink('Local documentation fixture', '/guide?q=html');
document.querySelector('#links').append(link);
const checks = [
	['baseline parses fixed fixture', baseline.querySelectorAll('b').length === 1],
	['safe path creates no child elements', safe.children.length === 0],
	['safe path preserves all text', safe.textContent === fixture],
	['relative allowed', approvedURL('/guide')?.pathname === '/guide'],
	['different origin rejected', approvedURL('https://other.example.test/') === null],
	['insecure scheme rejected', approvedURL('http://docs.example.test/') === null],
	['non-string rejected', approvedURL({path: '/guide'}) === null],
	['label preserved', link.textContent === 'Local documentation fixture']
];
document.querySelector('#results').textContent = checks.map(([name, ok]) =>
	`${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n');
if (checks.some(([, ok]) => !ok)) throw new Error('Rendering regression');
</script></body></html>
```

### Objectives and Baseline

Create a disposable `html-policy-lab` directory, add the file, and open it (`Start-Process .\index.html` optionally). Inspect both result containers in Elements. The baseline intentionally parses only the hardcoded inert fixture. Do not add arbitrary input. Predict which destinations the policy accepts before reading the output. Do not follow the example.test link; it is a reserved synthetic destination.

### Hints

Compare child element count with `textContent`; visual boldness alone is a weak assertion. Compare parsed URL origins, not string prefixes. A safe DOM setter and an allowed destination solve different problems.

### Solution and Fixed Retest

The fixed path uses `textContent` and should display the literal `<b>LAB</b>`. Baseline has one `b` child; safe has none. Eight PASS lines are expected. To apply the same hardening to the baseline, replace `baseline.innerHTML = fixture` with `baseline.textContent = fixture`, and change its assertion to `baseline.children.length === 0 && baseline.textContent === fixture`. Rerun the same fixture and URL checks. Both containers now preserve text and the legitimate link remains present. This is a rendering-policy regression, not evidence of executing script or bypassing a control.

### Verification, Troubleshooting, and Cleanup

Network should show no fixture-initiated external request. The URL constructor only parses; it does not fetch. A failed origin check is a policy mismatch, not a CORS error. If the page is blank, check the console for a syntax error or extension interference. CSP/header enforcement is intentionally outside this file-only lab and requires an authorized HTTP harness; it has not been validated here. Close the page and delete only the lab directory. Original study checkboxes remain below.

- [ ] Local HTML exercise: Build a local labeled form with required fields and inspect the resulting request. Disable client validation and submit again; document why the server must validate independently.
- [ ] Boundary check: Render the harmless marker `<b>LAB</b>` once as text and once as HTML in a toy page. The safe text path must display the brackets literally.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[Clickjacking]]
- [[HTML]]

## References

- [Official documentation or primary training reference](https://html.spec.whatwg.org/multipage/)
- [W3C Content Security Policy](https://www.w3.org/TR/CSP3/)
- [W3C Trusted Types](https://www.w3.org/TR/trusted-types/)
