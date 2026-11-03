---
title: "Serverless"
aliases: []
tags: [web, w5]
domain: web
phase: "W5"
type: tech
status: draft
pair: "[[Serverless Security]]"
updated: 2026-11-03
---
# Serverless

> [!abstract] TL;DR
> Validate events, bound work, make retried operations idempotent, and minimize the execution role. Keep secrets out of packages and logs.

> [!info] Agent scope
> Functions; triggers; execution identity; event validation; deployment packaging; secrets; isolation and lifecycle limits.

## Prerequisites

- HTTP, queues, transactions and identity; [[Web Lab Setup]].
- Required lab: Python 3.12 with standard-library `sqlite3` and `unittest`, one empty local directory. No cloud account, SDK, credentials, package installation or server.

## Learn

```text
Teach me serverless functions at expert engineering depth. Assume HTTP, queues,
transactions and workload identities. Trace HTTP, queue, object-storage and
scheduled triggers through authentication, event decoding, execution and ack.
Explain cold/warm lifecycle, concurrency, timeout/cancellation, /tmp lifetime,
connection reuse, retries, ordering, partial batch failures and dead letters.
Build an atomic local idempotent ledger; explain why a local SQLite result is
not distributed exactly-once processing. Cover execution-role scope, packaging,
native dependencies, secrets and deployment version/alias rollback. Compare
AWS Lambda and Azure Functions hosting/runtime caveats with public sources.
Use synthetic events, zero-cost offline work and complete tests. No real
credentials, public listeners or file-edit requests. Teach here and finish with
worked failure scenarios, including a crash between effect and acknowledgment.
```

## Cheatsheet

### Trigger Contracts

| Trigger | Admission / completion | Failure behavior to design for |
|---|---|---|
| HTTP | Gateway authentication plus application authorization; HTTP response | Caller/proxy retry may repeat a timed-out successful mutation |
| Queue | Event-source identity and message validation; ack/delete after success | Visibility timeout, redelivery, poison messages, batch-wide versus partial retry |
| Object storage | Service event source plus bucket/account checks; event handler result | Duplicates, ordering differences, URL-encoded keys and object version ambiguity |
| Schedule | Scheduler invocation permission; bounded task | Overlapping runs, late events and missed schedule recovery |

The function's execution role authorizes outbound API calls; invocation permissions authorize triggering it. They are different policies. AWS Lambda event-source mappings poll supported sources; an SQS mapping's batch semantics differ from Lambda asynchronous invocation retry behavior. Azure Functions retry behavior depends on trigger extension and hosting model; never apply one generic retry count to every binding.

For AWS SQS partial failures, the response shape is `{"batchItemFailures":[{"itemIdentifier":"message-id"}]}` and the event-source mapping must enable `ReportBatchItemFailures`. FIFO processing needs ordering-aware failure handling. A response body alone does not activate the feature. Set queue visibility timeout based on documented function/batch timing guidance; do not make it equal to a normal fast-path duration.

Lambda event-source-mapping configuration fragment, not a complete deployment or part of the local lab:

```json
{
	"BatchSize": 10,
	"FunctionResponseTypes": ["ReportBatchItemFailures"],
	"ScalingConfig": {"MaximumConcurrency": 2}
}
```

The fragment assumes an SQS integration with supported settings, a separately selected queue/function and reviewed poller/runtime permissions. For FIFO, stop after the first failed record and return failed plus unprocessed identifiers to preserve ordering. Exceptions escaping the handler can fail the entire batch. Source mapping concurrency, function reserved concurrency and downstream capacity must agree. Lambda's documented SQS guidance includes visibility timeout at least six times function timeout, plus any batch window; this is service-specific guidance, not an Azure or generic queue rule. Redrive count, retention and DLQ access need separate queue configuration.

### Idempotency Is a Business Invariant

Choose a tenant-scoped business-operation key, not merely a delivery attempt ID. Atomically claim the key and commit its effect, or use a transactional outbox with an idempotent downstream consumer. Store a fingerprint of relevant normalized input: reusing the same key with changed amount should be rejected, not silently treated as a successful retry.

| Failure window | Correct design |
|---|---|
| Crash before transaction commit | Neither claim nor effect persists; retry may proceed |
| Crash after commit before ack | Retry detects completed operation and returns previous result |
| Claim committed before remote effect | Needs state machine/recovery; "already seen" alone can lose work |
| Effect committed before claim | Retry can repeat effect; use same transaction or downstream idempotency |
| Retention expires too early | Late duplicate can execute again; retention must cover redelivery/business window |

Do not use a module-global set as durable deduplication: warm instances are reused opportunistically, multiple instances run concurrently, and instances disappear. The local lab uses one transactional database to demonstrate atomicity, not a local filesystem as a cloud persistence recommendation.

### Lifecycle and Resource Limits

Reuse thread-safe clients/connections across invocations where supported, but not request-specific identity or mutable tenant data. Temporary files can survive warm reuse and disappear on recycling; remove per-invocation files in `finally`. A timeout may stop the handler without stopping an already accepted downstream write. Give downstream calls shorter deadlines and leave time for cleanup/response.

Bound concurrency against downstream capacity: connection count, rate limits and queue backlog. Reserved concurrency can protect workloads and cap concurrent Lambda execution, but does not universally cap total event-processing cost. Provisioned concurrency reduces startup latency at additional cost. Azure Functions timeouts, scaling, network features and execution guarantees depend on plan and runtime model; use the relevant plan's current limits, not one universal table.

### Packaging, Identity, and Secrets

Package only runtime files and locked dependencies built for the correct OS/architecture/runtime ABI; a Python wheel built for a laptop may not load in Linux hosting. Version the artifact immutably, retain a digest/SBOM/provenance record, verify the expected builder and source, then promote the same bytes. Signing alone does not prove dependencies are safe.

Keep execution role/managed identity minimal per function. Retrieve secrets using supported identity and secret service; bound cache lifetimes to rotation needs and never log values. Environment variables may be protected at rest by the platform but are visible to code and tooling with appropriate privileges. Layers/extensions/bindings are additional code and privilege surfaces, not inherently trusted because they are platform-integrated.

Use published versions/aliases or deployment slots as supported; rollback code does not roll back external side effects or schema migrations. Treat event schema changes as compatibility changes across queued old messages and new handlers.

## Gotchas

- At-least-once delivery does not imply exactly-once effects. FIFO does not eliminate application idempotency requirements.
- A local handler test cannot prove gateway authentication, event-source permissions, runtime isolation or provider timeout behavior.
- Quotas and service limits vary by runtime, region and plan; no numeric provider limits are assumed in this lab.

## Labs

### Environment and Complete Files

In an empty directory create these two files. All events are synthetic credit records, not payments. Start/test: `python -m unittest -v test_example`. The tests create and remove a temporary SQLite database automatically. No provider SDK or listener is used.

### File: ledger.py

```python
from contextlib import closing
import json
import sqlite3


def initialize(path):
	with closing(sqlite3.connect(path)) as database, database:
		database.execute("""CREATE TABLE IF NOT EXISTS credits (
			tenant TEXT NOT NULL, operation TEXT NOT NULL,
			payload TEXT NOT NULL, cents INTEGER NOT NULL,
			PRIMARY KEY (tenant, operation))""")


def handle(path, event):
	if not isinstance(event, dict) or set(event) != {"tenant", "operation", "cents"}:
		raise ValueError("unexpected event shape")
	for field in ("tenant", "operation"):
		if not isinstance(event[field], str) or not 1 <= len(event[field]) <= 64:
			raise ValueError("invalid identifier")
	if type(event["cents"]) is not int or not 1 <= event["cents"] <= 10000:
		raise ValueError("invalid cents")
	payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
	with closing(sqlite3.connect(path, timeout=5)) as database, database:
		database.execute("BEGIN IMMEDIATE")
		prior = database.execute(
			"SELECT payload FROM credits WHERE tenant=? AND operation=?",
			(event["tenant"], event["operation"])).fetchone()
		if prior:
			if prior[0] != payload:
				raise ValueError("idempotency key reused with different input")
			return "duplicate"
		database.execute("INSERT INTO credits VALUES (?, ?, ?, ?)",
						 (event["tenant"], event["operation"], payload, event["cents"]))
		return "applied"


def total(path, tenant):
	with closing(sqlite3.connect(path)) as database, database:
		return database.execute("SELECT COALESCE(SUM(cents), 0) FROM credits WHERE tenant=?",
								(tenant,)).fetchone()[0]
```

### File: test_example.py

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from ledger import handle, initialize, total


class RetryTests(unittest.TestCase):
	def setUp(self):
		self.directory = TemporaryDirectory()
		self.addCleanup(self.directory.cleanup)
		self.path = Path(self.directory.name) / "ledger.sqlite"
		initialize(self.path)
		self.event = {"tenant": "alpha", "operation": "credit-1", "cents": 250}

	def test_retry_after_commit(self):
		self.assertEqual(handle(self.path, self.event), "applied")
		self.assertEqual(handle(self.path, self.event), "duplicate")
		self.assertEqual(total(self.path, "alpha"), 250)

	def test_conflicting_retry(self):
		handle(self.path, self.event)
		with self.assertRaises(ValueError):
			handle(self.path, dict(self.event, cents=300))
		self.assertEqual(total(self.path, "alpha"), 250)

	def test_tenant_scoped_key(self):
		handle(self.path, self.event)
		handle(self.path, dict(self.event, tenant="beta"))
		self.assertEqual(total(self.path, "alpha"), 250)
		self.assertEqual(total(self.path, "beta"), 250)

	def test_validation_precedes_effect(self):
		for value in (True, 0, -1, 10001, "250"):
			with self.subTest(value=value), self.assertRaises(ValueError):
				handle(self.path, dict(self.event, cents=value))
		self.assertEqual(total(self.path, "alpha"), 0)


if __name__ == "__main__":
	unittest.main()
```

### Objectives and Steps

1. Run the four tests and trace the transaction boundaries.
2. Explain why a successful retry leaves total at 250 rather than 500 and why a changed amount is rejected.
3. Identify the tenant authorization missing from this technology example. The tenant comes from the event, so a real adapter must authorize it; [[Serverless Security]] supplies an independent defensive exercise.
4. Describe an outbox design for an external notification that cannot participate in this SQLite transaction.

### Hints

The ledger row is both the deduplication record and the local business effect. SQLite serializes writers here; this is intentionally a small local mechanism, not a scalable cloud database prescription.

### Solution and Expected Results

Four tests should pass. `BEGIN IMMEDIATE` acquires the write transaction before read/check/insert; the primary key enforces tenant-operation uniqueness. The inner connection context commits successful work or rolls it back on exceptions; the outer `closing` context then closes the handle, including on early return. A SQLite connection context alone does not close the connection. For an external notification, commit an outbox record with the credit, then have a separate retried publisher send a stable operation ID to a deduplicating recipient. Merely sending before commit is not atomic.

### Verification, Troubleshooting, and Cleanup

If `sqlite3` is absent, use a Python distribution including it. Run from the directory containing both files. A locked database can indicate another process holding a write transaction; use a fresh lab directory, not shorter correctness checks. Tests remove temporary data; delete the two files and `__pycache__` for full cleanup. Author validation was static only; no tests or cloud execution were performed.

### User-Owned Milestones

These retained deployment goals are separate optional cloud verification, not satisfied by local tests.

- [ ] Local Serverless exercise: Deploy a small function in a dedicated sandbox with a narrow role and a synthetic event. Test invalid input, retry behavior, and cleanup of temporary state.
- [ ] Boundary check: Replay the same synthetic event and verify one business effect. Attempt access to an unrelated resource with the function identity and require denial.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W5 Infra and Cloud|W5 Infra and Cloud]]
- [[Serverless Security]]

## References

- [Lambda best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Lambda SQS error handling](https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-errorhandling.html)
- [Lambda SQS queue configuration](https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-configure.html)
- [Python 3.12 SQLite connection context managers](https://docs.python.org/3.12/library/sqlite3.html#how-to-use-the-connection-context-manager)
- [Azure Functions error handling and retries](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-error-pages)
- [Azure Functions hosting options](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scale)
