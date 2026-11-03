---
title: "Serverless Security"
aliases: []
tags: [web, w5, security]
domain: web
phase: "W5"
type: security
status: draft
pair: "[[Serverless]]"
updated: 2026-11-03
---
# Serverless Security

> [!abstract] TL;DR
> Overprivileged identities, unvalidated events, dependency compromise, and cross-invocation state assumptions can expose data or repeat harmful side effects.

> [!info] Agent scope
> Security of: Functions; triggers; execution identity; event validation; deployment packaging; secrets; isolation and lifecycle limits. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Trigger identity, tenant/object authorization, function execution identity, bindings/extensions, package provenance, secret access, retries, logs and warm-instance state.
- Treat event payload as data even when a trusted service delivered it. A trusted queue can contain records produced by several applications with different authority.

## Learn

```text
Teach me defensive serverless security at expert depth. Cover trigger versus
execution permissions, verified adapter identity versus body fields, tenant and
object authorization, strict event schemas, retry-safe effects, warm-state
segregation, package provenance, secrets and logging. Show a harmless local
baseline that lacks a required authorization decision, then a concrete fix and
the same positive/negative regression matrix. Explain which checks need actual
provider IAM/gateway/event-source verification and cannot be proved locally.
Compare Lambda and Azure Functions identity/runtime boundaries using primary
sources. Include timeout, batch retry, cost and dependency tradeoffs. No exploit,
credential collection, evasion or public deployment. Teach here without edits.
```

## Cheatsheet

### Trust Transitions

| Boundary | Required decision | Common incomplete control |
|---|---|---|
| Caller -> trigger | Authenticate caller/service; restrict source resource/account where supported | Assuming a function URL or obscure endpoint is private |
| Trigger -> adapter | Verify platform identity context and expected event envelope | Reading caller identity from the JSON body |
| Adapter -> handler | Authorize tenant/object/action and validate bounded schema | Schema validation without authorization |
| Handler -> cloud API | Narrow execution role/managed identity | Broad storage administration for one object operation |
| Handler -> retry | Stable scoped operation key and atomic effect | In-memory global "seen" set |
| Package -> runtime | Approved artifact digest, builder and source; locked dependencies | Signature or SBOM treated as unconditional approval |

For AWS service invocation policies, constrain supported `AWS:SourceArn` and `AWS:SourceAccount` context where the integration supplies them. Function invocation policy and execution role remain separate. For Azure Functions, trigger authentication, function keys and Entra-based application authorization have different purposes; a function key is a shared endpoint credential, not tenant/object authorization. Never put keys in URLs or logs.

Real adapters must verify issuer, audience, signature, expiry and relevant claims using a maintained identity library/platform. The lab receives a preverified synthetic principal as a Python argument; it **does not authenticate tokens**. Never bind that argument from an unverified request field.

### Concrete Permission and Event Design

An AWS role fragment for a function reading only input records:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
	"Effect": "Allow",
	"Action": "s3:GetObject",
	"Resource": "arn:aws:s3:::example-w5-events/incoming/*"
  }]
}
```

This is not a complete role: role trust, logging permissions, optional KMS and invocation/event-source policies require separate decisions. Add no write/list/IAM permissions merely to resolve an unexplained denial. A separate publisher can write output using a different identity. On Azure, scope the analogous data role to the specific container rather than subscription Contributor.

Event contract example: `{"operation":"read-report","tenant":"alpha","report":"daily","request_id":"r-1"}`. Permit only known fields, exact types and bounded lengths. Choose resource destinations from server-owned configuration; do not accept arbitrary storage locations, URLs or role names in events. Log decision code, correlation ID and duration, not full events or secrets.

Warm caches may hold public configuration and reusable clients. Avoid globals containing the last user, authorization result or mutable response. If caching secret values, include rotation/expiry handling and access segregation; a long-lived warm instance can outlast a rotation. Clear temporary files on success and failure, while acknowledging hard timeouts may interrupt cleanup.

### Packaging and Operational Limits

Build for the target runtime/architecture; inspect deployment archives for environment files, private keys, test fixtures and unnecessary binaries. Verify a cryptographic digest against a separately approved release record. Digest equality alone says nothing about who built the file; combine it with verifiable provenance and an approved builder/source policy. Pin real reviewed dependency versions and action commits; do not insert invented hashes.

Set bounded event size, timeout, concurrency and downstream deadlines. Retries need limits and a dead-letter/destination workflow with restricted access and safe replay. Replaying a dead letter is a new operational authorization decision and must preserve idempotency. Provider isolation does not guarantee application-level tenant isolation.

## Detection and Defense

Track allowed/denied decisions by reason, duplicate/conflicting operations, timeout and throttle counts, oldest queue age, dead-letter growth and unexpected execution-identity changes. Correlate deployment digest and runtime version with behavioral changes. A retry spike may reflect a downstream outage rather than hostile input; preserve both failure and recovery signals. Keep audit readers separate from deployers and minimize sensitive log content.

## Labs

### Environment and Complete Files

Python 3.12 standard library only, an empty directory, no provider account or dependency. Start/test with `python -m unittest -v test_example`. This is a local authorization regression using synthetic principals and reports, not a token validator or IAM emulator. No network request or real data access occurs.

### File: test_example.py

```python
import unittest

REPORTS = {("alpha", "daily"): "ALPHA-SYNTHETIC",
		   ("beta", "daily"): "BETA-SYNTHETIC"}


def baseline_requires_tenant_check(principal, event):
	return True


def authorize(principal, event):
	return (principal.get("tenant") == event["tenant"]
			and "reports:read" in principal.get("scopes", ()))


def handle(principal, event, audit):
	required = {"operation", "tenant", "report", "request_id"}
	if not isinstance(event, dict) or set(event) != required:
		raise ValueError("event shape")
	if any(not isinstance(value, str) or not 1 <= len(value) <= 64
		   for value in event.values()):
		raise ValueError("event field")
	if event["operation"] != "read-report":
		raise ValueError("operation")
	if not authorize(principal, event):
		audit.append({"request_id": event["request_id"], "decision": "deny"})
		raise PermissionError("not authorized")
	body = REPORTS[(event["tenant"], event["report"])]
	audit.append({"request_id": event["request_id"], "decision": "allow"})
	return body


class EventBoundaryTests(unittest.TestCase):
	def setUp(self):
		self.principal = {"tenant": "alpha", "scopes": ["reports:read"]}
		self.event = {"operation": "read-report", "tenant": "alpha",
					  "report": "daily", "request_id": "r-1"}
		self.audit = []

	def test_baseline_missing_decision_and_fixed_denial(self):
		other = dict(self.event, tenant="beta")
		self.assertTrue(baseline_requires_tenant_check(self.principal, other))
		self.assertFalse(authorize(self.principal, other))
		with self.assertRaises(PermissionError):
			handle(self.principal, other, self.audit)
		self.assertEqual(self.audit, [{"request_id": "r-1", "decision": "deny"}])

	def test_legitimate_read_and_repeat(self):
		for attempt in range(2):
			self.assertEqual(handle(self.principal, self.event, self.audit),
							 "ALPHA-SYNTHETIC")
		self.assertNotIn("ALPHA-SYNTHETIC", str(self.audit))

	def test_scope_and_shape(self):
		with self.assertRaises(PermissionError):
			handle({"tenant": "alpha", "scopes": []}, self.event, self.audit)
		with self.assertRaises(ValueError):
			handle(self.principal, dict(self.event, secret="DUMMY"), self.audit)

	def test_no_cross_invocation_identity(self):
		handle(self.principal, self.event, self.audit)
		beta = {"tenant": "beta", "scopes": ["reports:read"]}
		self.assertEqual(handle(beta, dict(self.event, tenant="beta"), self.audit),
						 "BETA-SYNTHETIC")
		self.assertEqual(handle(self.principal, self.event, self.audit),
						 "ALPHA-SYNTHETIC")


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Baseline

1. Run the four tests. The baseline demonstrates only a missing decision, not a data-access technique: it returns a boolean and never reads a report.
2. Explain why the fixed check requires both tenant equality and operation scope.
3. Verify legitimate repeat reads remain valid and consecutive tenants do not share request identity.
4. Identify what the real platform adapter must verify before constructing `principal`; identify which execution-role permissions remain untested.

### Hints

Authorization belongs before report lookup. A trusted trigger does not make the body-supplied tenant authoritative. Repeated reads are naturally side-effect-free; mutating functions additionally need transactional idempotency as in [[Serverless]].

### Solution and Fixed Retest

`authorize()` replaces unconditional admission with tenant and scope checks. Four tests should pass; a different tenant or absent read scope is denied, valid reads return only the correct synthetic report, unknown fields are rejected, and logs contain decisions rather than report contents. The same candidate authorization decision is compared before and after the fix without exposing real data.

### Verification, Troubleshooting, and Cleanup

Use a fresh directory, run the exact module name, and restore printed fixtures after experiments. Tests hold only in-memory data. Delete the file and `__pycache__` to clean up. No runtime, package-signature, cloud-role or gateway verification was performed; author review is static only.

### User-Owned Milestones

Retained live deployment/identity goals need separate authorized evidence.

- [ ] Local Serverless exercise: Deploy a small function in a dedicated sandbox with a narrow role and a synthetic event. Test invalid input, retry behavior, and cleanup of temporary state.
- [ ] Boundary check: Replay the same synthetic event and verify one business effect. Attempt access to an unrelated resource with the function identity and require denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Serverless]]

## References

- [Lambda best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Lambda permissions](https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html)
- [Lambda code signing](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html)
- [Azure Functions security](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
