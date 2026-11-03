---
title: "postMessage Security"
aliases: []
tags: [web, w1, security]
domain: web
phase: "W1"
type: security
status: draft
pair: "[[postMessage]]"
updated: 2026-11-03
---
# postMessage Security

> [!abstract] TL;DR
> A message is a request from another principal, not trusted UI state. Bind the protocol to an exact origin and expected window, validate a small data schema, and authorize each operation before changing state.

> [!info] Agent scope
> Security of: Window messaging; targetOrigin; sender validation; structured clone; iframe and popup trust boundaries. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

Window references cross iframe/popup boundaries. Delivery may outlive navigation, pending requests or authorization changes. Embedding permission, transport delivery and operation permission are separate controls. This page uses synthetic labels only; no secrets, active markup, privileged actions or operational exploitation.

## Learn

```text
Teach defensive postMessage protocol design at expert depth. Assume JavaScript,
iframes and same-origin policy. Explain destination restriction versus sender
authentication, origin/source intersection, WindowProxy navigation, opaque
origins, structured clone limits, MessagePort capabilities and popup lifetimes.
Compare weak and strict policies using only synthetic status labels. Supply a
complete local three-origin browser lab that tests an expected frame, same-origin
sibling, third-origin frame, invalid schema and forbidden action. Show evidence,
fixed retests, rate/pending bounds, timeout/replay handling and safe text rendering.
Discuss CSP/COOP/sandbox as complementary controls, not message authentication.
Use primary sources; no bypass, exploitation, credential access, or file edits.
Do not fabricate test results. End with difficult questions and worked answers.
```

## Cheatsheet

### Trust Checks in Order

| Check | Concrete rule | Failure avoided |
|---|---|---|
| Destination | `peer.postMessage(data, expectedOrigin)` | Delivering sensitive replies after destination navigation |
| Sender origin | `event.origin === expectedOrigin` | Accepting an unrelated principal |
| Sender window | `event.source === expectedFrame.contentWindow` | Trusting every window hosted by the same origin |
| Shape/version | Plain data object; exact permitted keys/types/ranges | Confusing versions and coerced values |
| Operation | Allowlist and current application authorization | Treating a valid sender as universally privileged |
| Lifecycle | Match an outstanding request and reject duplicate/late IDs | Accepting stale results as current decisions |
| Output | `element.textContent = validatedText` | Treating data as markup or executable code |

`event.origin` is supplied by the browser for the sender at send time. A payload's `origin` field is merely a claim. Use `new URL(configuredURL).origin` when deriving an origin from trusted configuration; do not accept a message-supplied URL as the trust anchor. Origin is scheme/host/port, not path or domain substring. Two applications sharing an origin are not separated by path checks in `postMessage`.

### Weak and Fixed Patterns

Weak policy fragment for a harmless status display:

```javascript
function weakPolicy(event) {
	return typeof event.data?.label === 'string';
}
```

This establishes only that some string exists. The lab implements the fixed policy: exact origin, exact frame, version, action, field set and label length. Do not repair a trust check merely by sanitizing its string; authorization is independent from rendering safety.

Structured clone does not permit functions/DOM nodes, but supports more than JSON, including Maps and buffers. Define what your protocol accepts rather than accepting every cloneable value. Bound string/buffer sizes and per-peer request rates. A message may already have incurred cloning cost before validation; avoid exposing listeners to unnecessary peers, and terminate channels after repeated policy failures.

### Frame, Popup, and Port Boundaries

The expected WindowProxy can survive frame navigation, so source equality alone is insufficient. Event origin reflects the sender at send time, not necessarily its current document. Reply using the configured expected origin, not `*`. A sandboxed opaque-origin frame may report `"null"`; do not allowlist `"null"` as if it uniquely identified that frame's principal.

Popups may be blocked or lose opener relationships under `noopener`/COOP. Check those conditions explicitly; do not weaken security to restore a severed relationship. A transferred MessagePort is a capability: authenticate the initial transfer, keep the permitted operations narrow, and close it on logout/navigation. A correlation ID is not a bearer credential. Real business authorization remains server-side where authoritative data lives.

## Detection and Defense

Log bounded rejection counters by reason (origin/source/schema/action/expired), protocol version and non-sensitive operation type. Avoid payload dumps, user data and tokens. Multiple widgets can legitimately share one origin, making source-only versus origin-only mistakes observable in integration tests. CSP `frame-ancestors` limits who embeds a page; it does not validate messages. `frame-src` limits embedding destinations; sandbox flags change document capabilities, not your action allowlist.

## Labs

### Environment and Complete Files

Use current Chromium/Firefox and Python 3.11+ in an empty disposable directory. Three loopback ports 8821/8822/8823, no dependencies, accounts or permissions. Do not use any existing site. All frames display only synthetic marker strings.

### File: receiver.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Message policy matrix</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
iframe { display: block; width: min(100%, 36rem); height: 14rem; box-sizing: border-box; }
</style>
<h1>Receiver</h1>
<label><input id="strict" type="checkbox" checked>Strict validation</label>
<button id="reset">Reset evidence</button>
<p>Last accepted label: <output id="state">none</output></p>
<pre id="log" aria-live="polite"></pre>
<iframe id="expected" title="Expected sender" src="http://127.0.0.1:8822/sender.html?label=EXPECTED"></iframe>
<iframe id="sibling" title="Same-origin sibling" src="http://127.0.0.1:8822/sender.html?label=SIBLING"></iframe>
<iframe id="third" title="Third-origin sender" src="http://127.0.0.1:8823/sender.html?label=THIRD"></iframe>
<script>
const expectedOrigin = 'http://127.0.0.1:8822';
const expectedFrame = document.querySelector('#expected');
const state = document.querySelector('#state');
const log = document.querySelector('#log');
function reason(event) {
	if (event.origin !== expectedOrigin) return 'origin';
	if (event.source !== expectedFrame.contentWindow) return 'source';
	const data = event.data;
	if (!data || typeof data !== 'object' || Array.isArray(data)) return 'schema';
	if (Object.keys(data).sort().join(',') !== 'label,type,v') return 'fields';
	if (data.v !== 1 || typeof data.label !== 'string' ||
			!/^[A-Z]{1,16}$/.test(data.label)) return 'schema';
	if (data.type !== 'set-label') return 'action';
	return null;
}
addEventListener('message', event => {
	const denial = document.querySelector('#strict').checked
		? reason(event)
		: (typeof event.data?.label === 'string' ? null : 'schema');
	if (denial) {
		log.textContent += 'REJECT ' + denial + '\n';
		return;
	}
	state.textContent = event.data.label;
	log.textContent += 'ACCEPT label\n';
});
document.querySelector('#reset').onclick = () => {
	state.textContent = 'none';
	log.textContent = '';
};
</script>
```

### File: sender.html

```html
<!doctype html>
<meta charset="utf-8">
<title>Synthetic sender</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<h2 id="name"></h2>
<button id="valid">Valid label</button>
<button id="schema">Wrong version</button>
<button id="action">Unapproved action</button>
<script>
const label = new URLSearchParams(location.search).get('label') || 'EXPECTED';
document.querySelector('#name').textContent = label;
const send = data => parent.postMessage(data, 'http://127.0.0.1:8821');
document.querySelector('#valid').onclick = () => send({v: 1, type: 'set-label', label});
document.querySelector('#schema').onclick = () => send({v: 2, type: 'set-label', label});
document.querySelector('#action').onclick = () => send({v: 1, type: 'unknown', label});
</script>
```

### Objectives and Baseline

Start each server in a separate terminal in the lab directory:

```powershell
python -m http.server 8821 --bind 127.0.0.1
```

```powershell
python -m http.server 8822 --bind 127.0.0.1
```

```powershell
python -m http.server 8823 --bind 127.0.0.1
```

Open `http://127.0.0.1:8821/receiver.html`. Uncheck Strict validation to observe the deliberately weak status-only policy. Click Valid label in each frame, then Wrong version and Unapproved action in EXPECTED. Record that every string changes the harmless display. This is a local trust-policy demonstration, not an instruction to probe other applications.

### Hints

SIBLING and EXPECTED share an origin but are different windows. THIRD has a different origin. Schema and action checks must be tested from EXPECTED so identity checks do not mask their result.

### Solution and Fixed Retest

Check Strict validation, reset evidence and repeat these exact operations:

| Operation | Expected evidence | Display afterwards |
|---|---|---|
| EXPECTED valid | `ACCEPT label` | `EXPECTED` |
| SIBLING valid | `REJECT source` | `EXPECTED` |
| THIRD valid | `REJECT origin` | `EXPECTED` |
| EXPECTED wrong version | `REJECT schema` | `EXPECTED` |
| EXPECTED unapproved action | `REJECT action` | `EXPECTED` |
| EXPECTED valid again | `ACCEPT label` | `EXPECTED` |

The fix is the `reason` function, not a change to sender data. In an actual application remove the weak mode entirely. Additional manual check: change EXPECTED's iframe URL in Elements to the THIRD URL; its valid message must be denied by origin even though the expected frame element is unchanged. Reload to restore the permitted behavior.

### Verification, Troubleshooting, and Cleanup

Unexecuted during authoring. Parent must run the full matrix in a browser and confirm rejected messages do not mutate state. Empty frames indicate wrong ports or unavailable servers; `file:` URLs give different/opaque origin behavior. Keep the exact host `127.0.0.1`. Stop only these three servers, close tabs and delete the lab directory. No persistent registrations, network policy or real-site changes are required.

- [ ] Local postMessage exercise: Create a parent and iframe on different loopback origins. Exchange a versioned message with an explicit targetOrigin and verify origin/source checks before updating text.
- [ ] Boundary check: Send a valid-looking message from an unexpected third lab origin. The receiver must ignore it and leave state unchanged; capture a diagnostic rejection without including sensitive data.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W1 Frontend|W1 Frontend]]
- [[XSS]]
- [[postMessage]]

## References

- [HTML messaging security guidance](https://html.spec.whatwg.org/multipage/web-messaging.html#security-9)
- [Window.postMessage security concerns](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns)
- [HTML structured data](https://html.spec.whatwg.org/multipage/structured-data.html)
- [MessageChannel](https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel)
