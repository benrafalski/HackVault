---
title: "CSRF"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# CSRF

> [!abstract] TL;DR
> CSRF abuses automatically attached credentials to cause an unwanted state-changing request without proving the user's intent.

> [!info] Agent scope
> Ambient credentials; state-changing requests; token validation; SameSite; origin checks; login CSRF.

## Learn

```text
Teach CSRF as a failure to distinguish ambient authentication from request intent.
Assume HTTP, cookies, origins/sites, forms, and sessions. Explain what browsers
can send without reading a response; contrast CORS, SOP, authorization, and CSRF.
Cover state-changing methods, login CSRF, synchronizer tokens, signed and
session-bound double-submit designs, token lifetime, SameSite modes, schemeful
sites, exact Origin validation, Referer fallback, and Fetch Metadata tradeoffs.
Trace middleware order from session lookup through rejection before mutation.
Use a secure synthetic profile update and positive/negative regression matrix.
Explain XSS limitations, nonbrowser APIs, missing/null origins, and compatibility
exceptions. Include primary sources and questions with separate answers.
Only defensive review/hardening; no forged-request pages, payloads, bypasses,
credential theft, scanning, or chains. No file authoring or invented results.
```

## Cheatsheet

> [!important] Defensive scope
> The lab calls a protected update function with synthetic sessions. It does not construct cross-origin attack pages or exercise real accounts.

### Trust Boundaries

CSRF requires usable ambient authority and a state-changing operation accepted without adequate intent validation. Cookies, cached HTTP authentication, and client certificates can be ambient. A manually attached bearer token changes the analysis, but only if it is not also automatically supplied through another path. Authentication identifies a session; authorization permits the operation; a CSRF control binds this request to an intended interaction.

| Control | Required property | Limitation |
|---|---|---|
| Synchronizer token | Unpredictable secret bound to session, checked on every unsafe action | Same-origin script compromise can access or use it |
| Double-submit | Signed construction bound to session-specific state | Naive equality of two attacker-influenced values is insufficient |
| Origin | Exact configured origin, not request Host-derived trust | Missing headers need an explicit policy; nonbrowser clients can forge them |
| SameSite | Explicit cookie attribute; consider site versus origin | Same-site does not imply same-origin; browser behavior varies |
| Fetch Metadata | Reject inappropriate cross-site unsafe requests | Not supplied by all clients; requires compatibility policy |
| GET/HEAD safety | No business mutation through safe methods | Caching and navigation can invoke them without intent |

Cookie fragment for an HTTPS application:

```http
Set-Cookie: __Host-session=<opaque-session-id>; Path=/; Secure; HttpOnly; SameSite=Lax
```

The angle-bracket value documents a server-generated identifier, not a runnable credential. `__Host-` requires Secure, Path=/, and no Domain. `SameSite=None` requires Secure in modern browsers and is needed for some cross-site integrations; that makes independent intent checks especially important. `Lax` allows some top-level navigation contexts, so keep GET side-effect-free. Explicit settings avoid reliance on version-specific default behavior.

### Login and Evidence

Login changes identity state even before authentication. Bind a login attempt to a pre-authentication session, protect the form, and rotate the session on success. Do not treat lack of an authenticated cookie as proof that login needs no CSRF analysis. For logout, enrollment, and account linking, review the actual mutation as well.

Evidence should include method, normalized route, reason for rejection, and whether state changed, without tokens in logs. A CORS console error does not establish that the server rejected the write. A missing Origin is not equivalent to a trusted Origin. For browser-only endpoints a deny policy is straightforward; mixed API clients may need separate authentication and routes rather than broad exceptions.

## Defense

Prefer maintained framework middleware. Validate after session establishment and before mutation, including alternate content types and methods. Use constant-time token comparison for fixed-form ASCII tokens. Set no-store on token-bearing responses; never place tokens in URLs. Rotate with session changes and plan multi-tab behavior. CSRF protection is not a replacement for authorization or deliberate confirmation of sensitive operations.

## Labs

### Environment and Complete Files

Python 3.12 stdlib only. No web server or actual cookies. Create the file below in a disposable directory. Objective: review a proposed profile handler that checks only session existence, then explain the supplied pre-mutation guard. Fixed token strings are synthetic test fixtures; production tokens require `secrets.token_urlsafe(32)` or framework generation.

### File: test_example.py

```python
import hmac
import unittest


ORIGIN = "https://profile.example"


def update_profile(session, method, origin, token, display_name):
	if method != "POST" or origin != ORIGIN:
		raise PermissionError("request context")
	expected = session.get("csrf")
	if not isinstance(expected, str) or not expected:
		raise PermissionError("missing session token")
	if not isinstance(token, str) or not token.isascii():
		raise PermissionError("invalid token type")
	if not hmac.compare_digest(token, expected):
		raise PermissionError("token mismatch")
	if type(display_name) is not str or not 1 <= len(display_name) <= 80:
		raise ValueError("display name")
	session["display_name"] = display_name


class IntentTests(unittest.TestCase):
	def setUp(self):
		self.session = {"csrf": "session-a-synthetic-token", "display_name": "Ada"}

	def test_intended_update(self):
		update_profile(self.session, "POST", ORIGIN,
					   self.session["csrf"], "Grace")
		self.assertEqual(self.session["display_name"], "Grace")

	def test_rejections_do_not_mutate(self):
		cases = [
			("GET", ORIGIN, self.session["csrf"]),
			("POST", "https://other.example", self.session["csrf"]),
			("POST", None, self.session["csrf"]),
			("POST", "null", self.session["csrf"]),
			("POST", ORIGIN, None),
			("POST", ORIGIN, "session-b-synthetic-token"),
		]
		for method, origin, token in cases:
			with self.subTest(method=method, origin=origin, token=token):
				before = dict(self.session)
				with self.assertRaises(PermissionError):
					update_profile(self.session, method, origin, token, "Grace")
				self.assertEqual(self.session, before)

	def test_invalid_business_data(self):
		with self.assertRaises(ValueError):
			update_profile(self.session, "POST", ORIGIN,
						   self.session["csrf"], "")
		self.assertEqual(self.session["display_name"], "Ada")


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` where appropriate. Hint: locate the first mutation and enumerate every condition that must precede it. A correct token from another session is still wrong for this session.

Separate solution: the guard checks method, exact origin, session-bound token, and field shape before changing the profile. Expected: three tests pass; six request-context cases leave the complete session unchanged; the intended update changes only the display name. There is no authorization implementation here: the caller supplies the already authenticated user's session. Browser cookie attachment and middleware integration require separate testing.

### Verification, Troubleshooting, and Cleanup

Tests were not executed during authoring. No dependencies or data files beyond the listed file are required. Run in the file's directory; do not name it `hmac.py`. An Origin mismatch in an integration may reflect a proxy configuration error, not a reason to trust arbitrary hosts. Remove the disposable directory after review; no persistent state or services exist.

- [ ] Local CSRF exercise: Explain the authenticated-session versus request-intent boundary.
- [ ] Boundary check: Run the secure positive and no-mutation negative regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Fetch Standard: origins and credentials](https://fetch.spec.whatwg.org/)
- [Django CSRF middleware design](https://docs.djangoproject.com/en/5.2/ref/csrf/)
- [Fetch Metadata specification](https://www.w3.org/TR/fetch-metadata/)
