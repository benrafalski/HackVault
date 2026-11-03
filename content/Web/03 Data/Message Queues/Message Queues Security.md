---
title: "Message Queues Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[Message Queues]]"
updated: 2026-11-03
---
# Message Queues Security

> [!abstract] TL;DR
> Unvalidated messages, overly broad broker roles, poison-message loops, and duplicate processing can alter state or exhaust capacity.

> [!info] Agent scope
> Security of: Producers and consumers; broker permissions; acknowledgement; retries; dead letters; ordering; idempotency; message validation. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unvalidated messages, overly broad broker roles, poison-message loops, and duplicate processing can alter state or exhaust capacity.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive queue security using RabbitMQ 4.1, Python and SQL. Explain
vhost configure/write/read permissions, routing, producer versus payload identity,
schema validation, bounded bodies, idempotent commits, ACK timing and retry budgets.
Distinguish permanent malformed input from transient processing failure; show
confirmed retry publish before original ACK and its duplicate window. Build a
local synthetic least-privilege baseline/fix lab with an empty unrelated queue,
safe messages, two bounded retries and quarantine. Cover ordering, DLQ access,
resource limits, TLS, observability and version caveats. No theft, escalation or
resource attacks. Use primary sources; teach without edits or fabricated runs.
```

## Cheatsheet

### Broker Permissions Are Not Payload Authority

RabbitMQ permissions are per virtual host and expressed as configure/write/read resource-name regexes. Configure allows topology changes; write permits relevant exchange/queue operations; read permits consumption. Bindings have additional permission requirements. Anchor patterns: `^orders\.input$` is narrower than `orders`. Topic permissions can further constrain routing keys, but a queue name alone does not authenticate a tenant claim inside JSON.

```text
rabbitmqctl set_permissions -p lab producer '^$' '^orders\.input$' '^$'
rabbitmqctl set_permissions -p lab worker '^$' '^orders\.retry$' '^orders\.jobs$'
```

Operator-side example only. Predeclare topology using a separate identity. Do not repair a client queue-declare failure by granting broad configure rights. Keep management/API credentials and the Erlang cookie out of application processes. Use AMQPS with verified certificates for remote deployments and network-isolate management interfaces.

### Validate Before Work

Require an explicit schema version, message type, bounded identifier, allowed fields and bounded payload bytes. JSON is data, but types, depth and values still need validation; do not deserialize native executable object formats. Authenticate business authority from the producer channel/trusted envelope, not a client-provided role or tenant. Do not log full malformed bodies containing potential secrets.

Store deduplication IDs and business changes atomically. Duplicate IDs with conflicting payloads need a defined rejection policy, often a stored payload digest; silently accepting mismatched duplicate content is unsafe. Retain deduplication state for the real replay horizon, including DLQ reprocessing. Apply tenant and authorization checks again when consuming delayed work because the original user may have lost permission.

### Bounded Failure Handling

| Failure | Treatment |
|---|---|
| Malformed/permanently unauthorized | Reject without requeue; quarantine with safe reason, usually zero retries. |
| Transient dependency outage | Finite attempts, backoff/jitter and bounded in-flight concurrency. |
| Retry publication fails | Do not ACK the original; reconnect/recover and expect duplicates. |
| Retry confirmed, original ACK lost | Both copies may appear; use the same event ID and idempotency store. |
| Quarantine full/unavailable | Alert and follow retention/reliability policy; do not assume every dead-letter route is lossless. |

A producer-supplied retry counter is not trusted proof of attempts. Own retry metadata at a trusted worker/gateway and apply hard limits even to malformed counters. Queue length limits, message TTLs, broker max-message settings and consumer prefetch address different budgets. Producer-side body checks do not protect the broker from every authorized publisher; configure supported broker-side limits too. RabbitMQ 4.x quorum delivery limits differ from classic queues and prior defaults.

Classic dead-letter forwarding can lose messages when the target is unavailable; quorum at-least-once dead-lettering requires explicit configuration. A dead-letter queue is storage requiring access control, monitoring and retention, not automatic incident resolution. Multiple consumers, retries and priorities disrupt completion order; include entity sequence/version checks where ordering is security relevant.

## Detection and Defense

Monitor ready/unacked depth, publish returns/NACKs, oldest-message age, retry distributions, quarantine counts and permission failures. Distinguish slow consumers from connection starvation or poison loops. Record stable event IDs and validation categories, not full credentials/bodies. Audit permission/topology changes under operator identities. A 403 AMQP channel close is a permission result; a TCP refusal is not.

## Labs

### Environment and Complete Files

Python 3.12+, PowerShell, Docker Linux containers, RabbitMQ `4.1`, Pika `>=1.3,<2`. Record installed versions/image digest. **Not executed here.** Port 15674 must be free. No external targets, host mounts or real credentials. The unrelated audit queue is empty; the permission test never consumes other users' data.

### File: requirements.txt
```text
pika>=1.3,<2
```

### File: setup.py
```python
import pika

connection = pika.BlockingConnection(pika.ConnectionParameters("127.0.0.1", 15674, "lab",
	pika.PlainCredentials("operator", "Admin-lab-only-41!")))
channel = connection.channel()
for exchange in ["w3.in", "w3.retry", "w3.dead"]:
	channel.exchange_declare(exchange, "direct", durable=True)
channel.queue_declare("w3.jobs", durable=True, arguments={"x-queue-type": "classic",
	"x-dead-letter-exchange": "w3.dead", "x-dead-letter-routing-key": "dead",
	"x-max-length": 20, "x-overflow": "reject-publish"})
channel.queue_declare("w3.quarantine", durable=True, arguments={"x-queue-type": "classic", "x-max-length": 20})
channel.queue_declare("w3.audit", durable=True, arguments={"x-queue-type": "classic"})
channel.queue_bind("w3.jobs", "w3.in", "job")
channel.queue_bind("w3.jobs", "w3.retry", "job")
channel.queue_bind("w3.quarantine", "w3.dead", "dead")
connection.close()
```

### File: test_example.py
```python
import json
import sqlite3
import unittest
import pika

def connect(user):
	password = "Producer-lab-only!" if user == "producer" else "Worker-lab-only!"
	return pika.BlockingConnection(pika.ConnectionParameters("127.0.0.1", 15674, "lab",
		pika.PlainCredentials(user, password), blocked_connection_timeout=5))

def publish(body):
	if len(body) > 1024:
		raise ValueError("body budget")
	connection = connect("producer")
	try:
		channel = connection.channel()
		channel.confirm_delivery()
		channel.basic_publish("w3.in", "job", body, mandatory=True,
			properties=pika.BasicProperties(content_type="application/json", delivery_mode=2))
	finally:
		connection.close()

class QueuePolicy(unittest.TestCase):
	def test_producer_cannot_consume(self):
		connection = connect("producer")
		try:
			with self.assertRaises(pika.exceptions.ChannelClosedByBroker) as denied:
				connection.channel().basic_get("w3.audit", auto_ack=False)
			self.assertEqual(denied.exception.reply_code, 403)
		finally:
			connection.close()

	def test_validation_retry_and_deduplication(self):
		with self.assertRaises(ValueError):
			publish(b"x" * 1025)
		approved = json.dumps({"id": "event-1", "version": 1, "kind": "credit", "amount": 3}).encode()
		transient = json.dumps({"id": "event-2", "version": 1, "kind": "transient-fixture", "amount": 1}).encode()
		for body in [b'{"invalid":true}', approved, approved, transient]:
			publish(body)
		database = sqlite3.connect(":memory:")
		database.executescript("CREATE TABLE inbox(id TEXT PRIMARY KEY, body BLOB NOT NULL);"
			"CREATE TABLE balance(total INTEGER NOT NULL); INSERT INTO balance VALUES(0);")
		connection = connect("worker")
		rejected = 0
		retried = 0
		try:
			channel = connection.channel()
			channel.confirm_delivery()
			for delivery in range(6):
				method, properties, body = channel.basic_get("w3.jobs", auto_ack=False)
				self.assertIsNotNone(method, "expected ready delivery; inspect broker state")
				try:
					if len(body) > 1024 or properties.content_type != "application/json":
						raise ValueError("envelope")
					event = json.loads(body)
					if not isinstance(event, dict) or set(event) != {"id", "version", "kind", "amount"}:
						raise ValueError("fields")
					if not isinstance(event["id"], str) or not 1 <= len(event["id"]) <= 64:
						raise ValueError("id")
					if type(event["version"]) is not int or event["version"] != 1:
						raise ValueError("version")
					if event["kind"] not in ("credit", "transient-fixture"):
						raise ValueError("kind")
					if type(event["amount"]) is not int or not 1 <= event["amount"] <= 10:
						raise ValueError("amount")
					attempt = (properties.headers or {}).get("attempt", 0)
					if type(attempt) is not int or not 0 <= attempt <= 2:
						raise ValueError("attempt")
				except (ValueError, UnicodeDecodeError):
					channel.basic_nack(method.delivery_tag, requeue=False)
					rejected += 1
					continue
				if event["kind"] == "transient-fixture":
					if attempt < 2:
						channel.basic_publish("w3.retry", "job", body, mandatory=True,
							properties=pika.BasicProperties(content_type="application/json", delivery_mode=2,
								headers={"attempt": attempt + 1}))
						channel.basic_ack(method.delivery_tag)
						retried += 1
					else:
						channel.basic_nack(method.delivery_tag, requeue=False)
						rejected += 1
					continue
				with database:
					existing = database.execute("SELECT body FROM inbox WHERE id=?", (event["id"],)).fetchone()
					if existing:
						self.assertEqual(existing[0], body, "conflicting duplicate")
					else:
						database.execute("INSERT INTO inbox VALUES(?,?)", (event["id"], body))
						database.execute("UPDATE balance SET total=total+?", (event["amount"],))
				channel.basic_ack(method.delivery_tag)
			self.assertEqual((rejected, retried), (2, 2))
			self.assertEqual(database.execute("SELECT total FROM balance").fetchone()[0], 3)
		finally:
			database.close()
			connection.close()

if __name__ == "__main__":
	unittest.main()
```

### Baseline and Setup

```powershell
docker run --name w3-queue-sec -d -p 127.0.0.1:15674:5672 -e RABBITMQ_DEFAULT_USER=operator -e RABBITMQ_DEFAULT_PASS=Admin-lab-only-41! rabbitmq:4.1
docker exec w3-queue-sec rabbitmq-diagnostics -q ping
docker exec w3-queue-sec rabbitmqctl add_vhost lab
docker exec w3-queue-sec rabbitmqctl set_permissions -p lab operator '.*' '.*' '.*'
docker exec w3-queue-sec rabbitmqctl add_user producer Producer-lab-only!
docker exec w3-queue-sec rabbitmqctl add_user worker Worker-lab-only!
docker exec w3-queue-sec rabbitmqctl set_permissions -p lab producer '^$' '^w3\.in$' '^w3\.audit$'
docker exec w3-queue-sec rabbitmqctl set_permissions -p lab worker '^$' '^w3\.retry$' '^w3\.jobs$'
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python setup.py
.\.venv\Scripts\python test_example.py QueuePolicy.test_producer_cannot_consume -v
```

Retry readiness manually. Baseline fails because producer can poll the empty audit queue. Objective: remove consumption rights while preserving publish; then verify malformed rejection, two retries and idempotent processing. Hint: publishing and consuming use different permissions even in the same vhost.

### Solution and Fixed Retest

```powershell
docker exec w3-queue-sec rabbitmqctl set_permissions -p lab producer '^$' '^w3\.in$' '^$'
.\.venv\Scripts\python test_example.py -v
docker exec w3-queue-sec rabbitmqctl list_queues -p lab name messages_ready messages_unacknowledged
```

Expected: two tests pass. Producer consumption closes its channel with 403; publishing works. Six deliveries comprise one malformed message, two identical credits, and three attempts of one synthetic transient failure. The worker performs two retry publications, quarantines two messages, and total stays `3`. Final jobs ready/unacked counts are zero and quarantine ready count is two. The retry fixture is intentionally immediate and tiny; production backoff and durable retry metadata need additional design. It does not expose a caller-controlled failure trigger in a public API.

### Verification, Troubleshooting, and Cleanup

A fresh connection is used after role changes; cached permissions and channel closure otherwise complicate retests. If a partial test leaves messages, reset this fixture rather than consuming unrelated state. The in-memory inbox demonstrates transaction semantics but is not persistent across test runs; production deduplication must be durable. Retry counters are bounded here but are not claimed to authenticate arbitrary publishers. Classic-queue DLX loss under broker failures and remote TLS remain untested. Remove only this container:

```powershell
docker rm -f -v w3-queue-sec
```

- [ ] Local Message Queues exercise: Run a local broker with a producer and idempotent consumer. Force a consumer restart after processing but before acknowledgement and show the duplicate does not repeat the business effect.
- [ ] Boundary check: Publish a malformed synthetic message and verify bounded retries followed by quarantine. Confirm a producer identity cannot consume an unrelated queue.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Message Queues]]

## References

- [RabbitMQ access control](https://www.rabbitmq.com/docs/access-control)
- [Consumer acknowledgments](https://www.rabbitmq.com/docs/confirms)
- [Dead-letter reliability](https://www.rabbitmq.com/docs/dlx)
- [Quorum queues and delivery limits](https://www.rabbitmq.com/docs/quorum-queues)
