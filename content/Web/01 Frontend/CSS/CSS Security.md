---
title: "CSS Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[CSS]]"
updated: 2026-11-03
---
# CSS Security

> [!abstract] TL;DR
> Untrusted style rules can hide controls, alter trusted UI, and sometimes cause data-dependent requests; CSS injection is not equivalent to harmless formatting.

> [!info] Agent scope
> Security of: Cascade and specificity; layout; selectors; responsive design; loading; style injection boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Untrusted style rules can hide controls, alter trusted UI, and sometimes cause data-dependent requests; CSS injection is not equivalent to harmless formatting.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive CSS security. I know the cascade, selectors, Grid/Flexbox,
and DOM mutation. Explain why stylesheet authority includes visibility, layout,
interaction and resource loading; trace custom properties to their consumers.
Compare arbitrary CSS, property allowlists and bounded application tokens.
Cover URL-valued properties, selectors, third-party styles, isolation, CSP
style-src/resource directives, accessibility and client-versus-server trust.
Use complete local labs with inert synthetic fixtures, computed-style and
network observations, positive tests and rejection tests. Explain browser
support and CSP deployment distinctions. No data extraction, exploit payloads,
bypass or offensive walkthroughs. Use W3C primary references. Teach here without
editing files or claiming that unexecuted tests passed.
```

## Cheatsheet

### Styling Is a Capability

Author styles can reorder or obscure controls, create overlays, alter pointer behavior, remove focus indicators, change readable contrast, and load resources. A stylesheet does not need JavaScript execution to violate UI integrity. Do not equate browser CSS parsing with application policy validation: the browser accepts many valid declarations that your product should not let users choose.

| Boundary | Weak design | Bounded replacement |
|---|---|---|
| Theme setting | Store arbitrary stylesheet text | Store an enum such as `forest` or `ocean` |
| Numeric spacing | Concatenate a supplied string into a declaration | Parse a finite number, range-check, and append a fixed unit |
| Custom property | Assume `--anything` is harmless | Review every consuming property; use trusted tokens |
| Class selection | Accept arbitrary whitespace-separated classes | Map one validated identifier to one owned class |
| Rich user document | Apply its styles to the host page | Separate origin and deliberately restricted embedding policy |
| Authorization | Hide restricted actions with CSS | Enforce permissions at the service; UI visibility is only presentation |

A declaration accepted by `CSS.supports()` is syntactically supported, not approved by your business rules. It cannot certify absence of resource loading or misleading layout. `CSS.escape()` escapes a selector component; it is not a stylesheet sanitizer and is not appropriate for arbitrary declaration values.

### Concrete Policy Fragments

This fragment is safe for a numeric layout preference because the output grammar and range are fixed:

```js
function gapPixels(value) {
	if (typeof value !== 'number' || !Number.isFinite(value) ||
			value < 0 || value > 32) throw new TypeError('Invalid gap');
	return `${Math.round(value)}px`;
}
// ownedContainer.style.gap = gapPixels(parsedPreference);
```

Do not pass through arbitrary objects into a style object and assume a framework will authorize the resulting properties. A safe text template does not make style bindings semantically safe. An enum-to-class map lets a reviewed stylesheet own all values, preserves responsive states, and works with a stricter external-style CSP.

Illustrative response policy for a page with external same-origin scripts and CSS:

```http
Content-Security-Policy: default-src 'self'; style-src 'self'; style-src-attr 'none'; script-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'
```

Deploy only after checking required inline/framework-generated styles and actual browser enforcement. `style-src` controls stylesheet sources; resource directives also govern images/fonts referenced by styles. A policy allowing trusted CSS is not evidence that arbitrary CSS is safe. Nonces/hashes approve a style block's origin/content, not the safety of a string subsequently incorporated into it. Report-only observes without blocking. Legacy browser support differs for granular directives such as `style-src-attr`.

## Detection and Defense

Inventory style sinks: inline declarations, stylesheet text, CSSOM insertion, framework style bindings, CSS-in-JS interpolation, user-selected classes, and imported theme packages. Inspect computed styles, loaded stylesheet origin, Network initiators, focus visibility and click targets. Log rejected token identifiers with bounded length rather than entire user documents. Treat new dependencies and remote stylesheets as code review events. CSP and resource telemetry are supporting evidence, not comprehensive detection.

## Labs

### Environment and Complete Files

Current desktop browser, no packages or server. Create `css-policy-lab/index.html` below. The bad baseline uses only the inert fixture `transparent`; it demonstrates readability loss without loading anything. Rejected URL-shaped text is checked as data and never assigned to CSS.

### File: index.html

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Theme policy</title>
<style>
body { font: 1rem/1.5 sans-serif; margin: 2rem; }
.preview { padding: 1rem; border: 1px solid #777; background: white; }
.forest { color: #14532d; background: #f0fdf4; }
.ocean { color: #164e63; background: #ecfeff; }
button:focus-visible { outline: 3px solid #b45309; }
pre { white-space: pre-wrap; }
</style></head><body><main>
<h1>Bounded themes</h1><p id="baseline" class="preview">Synthetic baseline label</p>
<p id="safe" class="preview">Approved theme label</p>
<button id="forest">Forest</button><button id="ocean">Ocean</button>
<pre id="results" role="status"></pre>
</main><script>
const baseline = document.querySelector('#baseline');
baseline.style.color = 'transparent';
const safe = document.querySelector('#safe');
const themes = new Map([['forest', 'forest'], ['ocean', 'ocean']]);
function applyTheme(value) {
	if (typeof value !== 'string' || !themes.has(value)) return false;
	safe.className = `preview ${themes.get(value)}`;
	return true;
}
for (const name of themes.keys()) {
	document.querySelector(`#${name}`).addEventListener('click', () => applyTheme(name));
}
const checks = [];
function check(name, ok) { checks.push([name, ok]); }
check('baseline loses visible text', getComputedStyle(baseline).color === 'rgba(0, 0, 0, 0)');
check('forest accepted', applyTheme('forest'));
const before = safe.className;
check('unknown rejected', !applyTheme('transparent'));
check('URL-shaped value rejected', !applyTheme('url(/fixture-image.png)'));
check('object rejected', !applyTheme({theme: 'forest'}));
check('rejection preserves prior state', safe.className === before);
check('no inline style written', !safe.hasAttribute('style'));
check('ocean accepted', applyTheme('ocean'));
check('approved class active', safe.classList.contains('ocean'));
document.querySelector('#results').textContent = checks.map(([name, ok]) =>
	`${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n');
if (checks.some(([, ok]) => !ok)) throw new Error('Theme regression');
</script></body></html>
```

### Objectives and Baseline

Open the file directly (`Start-Process .\index.html` optionally). Inspect the baseline's text node and computed color: data still exists although the label is not visible. Inspect the Network panel after reload; the rejected URL-shaped fixture must not initiate an image request. Both approved theme buttons must work by keyboard.

### Hints

Reject before any DOM write. A policy failure should leave the last approved state intact. Check semantic state (`className`, absence of inline styles), not only screenshots; browser serialization can vary.

### Solution and Fixed Retest

The solution is `Map` membership followed by assignment of an owned class. Nine PASS lines are expected. To repair the baseline too, remove its inline color assignment and give it `class="preview forest"`; replace the first check with `!baseline.hasAttribute('style') && baseline.classList.contains('forest')`. Rerun all other checks unchanged. The label becomes visible, both approved themes still work, and all unsupported values remain rejected. The existing study boundary checkbox refers to the same rejected URL-shaped fixture, not to an external request experiment.

### Verification, Troubleshooting, and Cleanup

No external resource is required. If the transparent-color assertion differs in a browser's serialization, inspect computed color/alpha and adjust only that observation, not policy acceptance. Inline CSS/script are intentional for this file-only lab, so the production header fragment is not applied here. Real CSP enforcement needs a separate authorized HTTP harness and has not been run. Verify focus visibility and 200% zoom manually. Close the tab and remove the disposable directory; no shared browser settings need changing.

- [ ] Local CSS exercise: Build the same small toolbar with Flexbox and Grid. Inspect computed styles and overflow at narrow and wide widths; expected result: no overlapping text or shifting controls.
- [ ] Boundary check: Allow only a small color-token set in a toy editor and submit a url() value. Confirm rejection and absence of an outbound resource request.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Clickjacking]]
- [[CSS]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/CSS)
- [CSS Syntax](https://www.w3.org/TR/css-syntax-3/)
- [CSS Custom Properties](https://www.w3.org/TR/css-variables-1/)
- [W3C Content Security Policy](https://www.w3.org/TR/CSP3/)
