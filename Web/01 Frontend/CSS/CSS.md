---
title: "CSS"
aliases: []
tags: [web, w1]
domain: web
phase: "W1"
type: tech
status: draft
pair: "[[CSS Security]]"
updated: 2026-11-03
---
# CSS

> [!abstract] TL;DR
> Inspect matched and computed rules separately. Prefer minmax(), gap, and explicit overflow handling over position-based layout patches.

> [!info] Agent scope
> Cascade and specificity; layout; selectors; responsive design; loading; style injection boundaries.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me CSS at expert implementation depth. I know semantic HTML and basic
DOM APIs. Cover selector matching, cascade origins/importance/layers,
specificity, inheritance, computed/used values, custom properties, box sizing,
formatting contexts, Flexbox and Grid intrinsic sizing, responsive and container
queries, loading, fonts, layout/paint/compositing, and style injection boundaries.
Work through conflicting rules and long-content overflow with actual styles,
browser computed-style evidence and geometry assertions. Explain :is/:where,
min-width:auto, minmax(0,1fr), logical properties, focus states, reduced motion,
and progressive enhancement. Distinguish specification semantics from browser
support; use W3C CSS specifications and browser documentation. Give complete
local labs with keyboard/zoom/viewport checks and worked solutions. Teach in
this conversation without editing files or claiming unperformed tests.
```

## Cheatsheet

### Cascade Before Specificity

For declarations relevant to the element and media conditions, origin/importance and cascade layer precedence come before selector specificity. Normal author declarations override normal user/UA declarations; important user rules override important author rules. Animations outrank normal declarations; transitions have exceptionally high cascade priority while active. Within comparable declarations, specificity wins, then scoping proximity when applicable, then order.

For normal author declarations, unlayered rules outrank layered rules, and later declared layers outrank earlier layers. Important layer priority reverses. Adding a very specific selector in a low-priority layer cannot defeat a normal unlayered rule. Use layers to manage ownership, not `!important` as a default repair.

```css
/* Fragment: layer order is declared before imports and rules. */
@layer reset, components, overrides;
@layer components {
	:where(.toolbar) button { color: #155e75; }
}
@layer overrides {
	.toolbar button { color: #166534; }
}
```

`:where()` contributes zero specificity; `:is()`, `:not()`, and `:has()` use the specificity of their most specific argument. IDs dominate any count of classes within the specificity comparison, not because they have a numeric weight of 100. Inherited values are used only when the property has no applicable specified value or is explicitly inherited; a directly targeted low-specificity rule beats an inherited high-specificity color.

Custom properties usually inherit and are substituted at computed-value time. `var(--space, 1rem)` provides a fallback for an absent/invalid custom property, not for every invalid value after substitution. A defined `--space: blue` can make `padding: var(--space, 1rem)` invalid at computed-value time. Registered properties using `@property` can impose syntax and inheritance behavior, but require support checks.

### Layout and Rendering

| Problem | Mechanism and decision |
|---|---|
| Width exceeds container | Default content-box adds padding/border; prefer `box-sizing: border-box` |
| Flex child refuses to shrink | Automatic minimum size can track min-content; apply `min-inline-size: 0` to the appropriate child |
| Grid expands for a long token | A bare `1fr` track has an automatic minimum; use `minmax(0, 1fr)` and a text wrapping policy |
| Float/margin behavior surprises | Establishing a formatting context with `display: flow-root` can contain floats and stop certain margin collapsing |
| Positioned child escapes | Absolute positioning uses its containing block, not necessarily its DOM parent; transforms can establish containing blocks |
| High z-index still behind | Stacking contexts isolate local stacking order; inspect ancestors, opacity, transforms and isolation |
| Hidden control still focusable | Offscreen positioning and opacity do not remove interactivity; use appropriate DOM/hidden/inert state |

Flexbox distributes along one main axis, then aligns on the cross axis. Grid allocates tracks and places items in two dimensions. `gap` belongs to the layout container. Prefer logical dimensions (`inline-size`, `margin-block`) where writing direction matters. `overflow-wrap: anywhere` changes opportunities relevant to min-content sizing; `word-break: break-all` can damage readability.

Style recalculation determines computed values; layout resolves geometry; paint creates drawing work; compositing combines layers. A transform may avoid layout but is not guaranteed free. Reading geometry after a write may synchronously flush pending layout. Batch reads and writes; profile before adding `will-change`, which consumes resources and creates stacking contexts.

### Responsive Design and Loading

Use content failure points for breakpoints, not device brands. `@media` depends on the environment; container queries depend on a named/eligible container. Container size containment affects intrinsic sizing, so apply it to a wrapper with a meaningful width. `@supports` checks parsing support, not all behavior or absence of browser bugs.

```css
/* Fragment: progressive enhancement with an explicit container. */
.region { container-type: inline-size; }
.summary { display: block; }
@container (min-width: 32rem) {
	.summary { display: grid; grid-template-columns: 2fr 1fr; }
}
@media (prefers-reduced-motion: reduce) {
	.animated { animation: none; transition: none; }
}
```

External CSS normally blocks first rendering when applicable. Late `@import` discovery can lengthen the critical chain. Fonts can change text metrics and layout; choose fallback metrics and `font-display` deliberately. CSS URLs create resource requests, and custom properties can flow into URL-valued properties. A stylesheet is code-like presentation authority, not inert text.

## Gotchas

Inspect matched rules, computed values, box geometry, and accessibility separately. `display: none` removes the box and usually its accessibility-tree representation; it does not prevent server requests or authorize access. Zoom, scrollbar widths, long translated labels, and focus outlines reveal failures that a single screenshot misses.

## Labs

### Environment and Complete Files

Current Chromium/Firefox supporting cascade layers and Grid. No dependency or server is needed; open `index.html` directly in a disposable `css-layout-lab` folder. This is a complete example, not a component fragment. Author execution is deferred.

### File: index.html

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>CSS sizing lab</title>
<style>
@layer base, layout, theme;
@layer base {
	* { box-sizing: border-box; }
	body { margin: 1rem; font: 1rem/1.5 sans-serif; color: #172323; }
	button, input { font: inherit; max-inline-size: 100%; }
	button:focus-visible, input:focus-visible { outline: 3px solid #b45309; }
}
@layer layout {
	.toolbar { display: flex; flex-wrap: wrap; gap: .75rem; align-items: end; }
	.field { flex: 1 1 14rem; min-inline-size: 0; }
	label, input { display: block; inline-size: 100%; }
	.grid { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .75rem; }
	.record { min-inline-size: 0; overflow-wrap: anywhere; }
	@media (max-width: 30rem) { .grid { grid-template-columns: minmax(0, 1fr); } }
}
@layer theme {
	.toolbar { border-block: 1px solid #667; padding-block: 1rem; }
	button { color: #fff; background: #166534; border: 0; padding: .5rem 1rem; }
	pre { white-space: pre-wrap; overflow-wrap: anywhere; }
}
</style></head><body><main>
<h1>Record lookup</h1>
<form class="toolbar" id="search">
	<div class="field"><label for="query">Record identifier</label>
	<input id="query" value="DEMO-000000000000000000000000000000000000000007"></div>
	<button type="submit">Search records</button>
</form>
<section class="grid" aria-label="Result">
	<p class="record" id="record"></p><p>Ready</p>
</section>
<button id="check" type="button">Check layout</button><pre id="results"></pre>
</main><script>
const query = document.querySelector('#query');
const record = document.querySelector('#record');
record.textContent = query.value;
document.querySelector('#search').addEventListener('submit', event => {
	event.preventDefault(); record.textContent = query.value;
});
document.querySelector('#check').addEventListener('click', () => {
	const checks = [
		['no document overflow', document.documentElement.scrollWidth <= innerWidth + 1],
		['record has width', record.getBoundingClientRect().width > 0],
		['border box active', getComputedStyle(query).boxSizing === 'border-box'],
		['grid active', getComputedStyle(document.querySelector('.grid')).display === 'grid']
	];
	document.querySelector('#results').textContent = checks.map(([name, ok]) =>
		`${ok ? 'PASS' : 'FAIL'} ${name}`).join('\n');
});
</script></body></html>
```

### Objectives and Steps

Open the file (`Start-Process .\index.html` optionally). Test 320px and 1280px viewport widths, then 200% zoom. Press Check layout after each change. Replace the identifier with 200 consecutive `A` characters and Search; controls must remain reachable and the record must wrap. In DevTools change `.toolbar` to Grid with `grid-template-columns: minmax(0, 1fr) auto`; compare the one-row wide layout with the Flexbox wrapping behavior. Restore before finishing.

### Hints

Use the Grid/Flex overlays and inspect a child's minimum size. A fixed viewport test does not catch all content failures. To intentionally observe the defect, remove `overflow-wrap` and change the record track to `1fr` in DevTools; no file changes are required.

### Solution and Expected Results

Four PASS lines are expected at both widths with the original file. Flexbox wraps the action below the field when its bases and gap no longer fit; the result grid switches to one track below 30rem. The long identifier wraps because both the track minimum and wrapping policy permit it. Repair the intentional defect with `minmax(0, 1fr)`, `min-inline-size: 0`, and `overflow-wrap: anywhere`; do not conceal it using page-wide `overflow-x: hidden`.

### Verification, Troubleshooting, and Cleanup

Check keyboard focus is visible and text remains legible at zoom. Geometry assertions do not prove contrast or accessible reading order; inspect those manually. If every rule disappears, check layer support and syntax. If overflow remains, inspect ancestor minimum sizes and padding rather than only the overflowing node. Close the tab and remove only the lab directory. No test execution is claimed.

- [ ] Local CSS exercise: Build the same small toolbar with Flexbox and Grid. Inspect computed styles and overflow at narrow and wide widths; expected result: no overlapping text or shifting controls.
- [ ] Boundary check: Allow only a small color-token set in a toy editor and submit a url() value. Confirm rejection and absence of an outbound resource request.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[Clickjacking]]
- [[CSS Security]]

## References

- [Official documentation or primary training reference](https://developer.mozilla.org/en-US/docs/Web/CSS)
- [CSS Cascade Level 5](https://www.w3.org/TR/css-cascade-5/)
- [CSS Grid Layout](https://www.w3.org/TR/css-grid-2/)
- [CSS Flexible Box Layout](https://www.w3.org/TR/css-flexbox-1/)
