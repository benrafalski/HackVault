---
title: "Message Queues"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[Message Queues Security]]"
updated: 2026-11-03
---
# Message Queues

> [!abstract] TL;DR
> Define delivery semantics, idempotency key, retry budget, dead-letter handling, and schema version. Separate producer, consumer, and administrator permissions.

> [!info] Agent scope
> Producers and consumers; broker permissions; acknowledgement; retries; dead letters; ordering; idempotency; message validation.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me message-queue engineering with RabbitMQ 4.1 and Python, assuming SQL
transactions and HTTP. Explain exchanges/routing, queues, durable/persistent
messages, publisher confirms, mandatory returns, manual consumer acknowledgments,
prefetch and redelivery. Trace crash windows, database inbox/outbox patterns,
bounded retries, dead letters, ordering and idempotency. Build a complete local
broker plus SQLite consumer fixture that crashes after commit before ack and
proves one business effect after redelivery. Separate admin/producer/worker roles,
validate messages, and explain classic versus quorum queue durability limits.
Use official sources/version caveats; teach without edits or invented evidence.
```

## Cheatsheet

### Delivery Boundaries

Producer serialization -> network -> exchange routing -> queue storage -> delivery -> consumer database commit -> acknowledgment. Each transition can fail independently. A publisher confirm is broker acceptance according to queue semantics, not proof of consumer completion. A consumer ACK removes the broker's responsibility for that delivery, not proof that external systems committed correctly.

| Failure window | Correct response |
|---|---|
| Publish succeeded but confirm lost | Retry with stable event ID; duplicates are possible. |
| Confirmed message unroutable | Confirms alone are insufficient; use mandatory publish and handle returns. |
| Consumer ACK before commit | Crash can lose the business effect; commit first. |
| Commit before ACK, then crash | Redelivery can repeat work; atomic inbox deduplication is required. |
| Database update then publish | Use a transactional outbox to avoid a lost follow-up event. |

An inbox table with a unique event ID and business changes in the same database transaction gives once-only effects within that database. It cannot atomically commit an email, payment API and queue ACK; external actions need their own idempotency protocol or outbox/workflow. Exactly-once is always scoped. Store a payload digest too if conflicting reuse of the same ID must be detected.

### Topology, Durability, and Flow

Direct exchanges route exact keys; topic exchanges match patterns; fanout exchanges broadcast to bound queues. A queue is competing-consumer work sharing, not one copy per consumer. Durable queues survive broker restart; delivery_mode=2 requests persistent messages; publisher confirms complete the reliability picture. A single classic queue is not replicated HA. Quorum queues replicate and have different limits/defaults; review RabbitMQ 4.x delivery limits explicitly.

Manual acknowledgments are channel-scoped and delivery tags cannot be ACKed on another channel. `basic_qos(prefetch_count=10)` bounds outstanding deliveries for normal consuming; it does not turn polling `basic_get` into the same flow-control model. Bound application concurrency and payload sizes too. Closing a connection with an unacked delivery normally requeues it, potentially with a redelivery indication.

FIFO enqueue order is not guaranteed completion order with multiple consumers, requeueing, priorities or retries. Partition by entity, use single active consumers or apply sequence/version checks when order is required. A redelivered flag is a hint, not a unique identifier or trustworthy retry counter.

### Retries and Message Contracts

Reject permanently malformed messages without requeue. Retry transient failures with bounded attempts and backoff, then quarantine with original ID, safe diagnostic category and schema version. Immediate `nack(requeue=True)` loops can monopolize capacity. Dead-lettering needs a configured exchange/binding and monitoring; classic-queue dead-letter forwarding is not universally lossless during target failures. Quorum at-least-once dead-lettering has explicit prerequisites.

Use JSON or another constrained schema, not executable object deserialization. Require event ID, schema version, type, trusted tenant/producer context and bounded fields. Broker identity authorizes queue/exchange operations, not claims inside the payload. Separate configure/write/read permissions and keep topology management with an operator. For real remote traffic use AMQPS with certificate validation; the loopback lab below does not exercise TLS.

## Gotchas

Exactly-once claims are usually scoped to a broker or transaction boundary, not every external side effect.

## Labs

### Environment and Complete Files

Python 3.12+, PowerShell, Docker Linux containers, RabbitMQ `4.1` and Pika `>=1.3,<2`. These are release/API ranges, not immutable pins; record broker/image/client versions. **Not executed here.** Port 15673 maps only to local AMQP. All data is synthetic; the only crash is the lab Python process exiting deliberately.

### File: requirements.txt
```text
pika>=1.3,<2
```

### File: setup.py
```python
import pika

connection = pika.BlockingConnection(pika.ConnectionParameters("127.0.0.1", 15673, "lab",
	pika.PlainCredentials("operator", "Admin-lab-only-41!")))
channel = connection.channel()
channel.exchange_declare("w3.events", "direct", durable=True)
channel.exchange_declare("w3.dead", "direct", durable=True)
channel.queue_declare("w3.jobs", durable=True, arguments={
	"x-queue-type": "classic", "x-dead-letter-exchange": "w3.dead",
	"x-dead-letter-routing-key": "dead", "x-max-length": 100,
	"x-overflow": "reject-publish"})
channel.queue_declare("w3.quarantine", durable=True, arguments={"x-queue-type": "classic", "x-max-length": 100})
channel.queue_bind("w3.jobs", "w3.events", "job")
channel.queue_bind("w3.quarantine", "w3.dead", "dead")
connection.close()
```

### File: app.py
```python
import json
import os
import sqlite3
import sys
import pika

mode = sys.argv[1]
if mode not in {"publish", "publish-invalid", "crash", "finish"}:
	raise SystemExit("mode: publish | publish-invalid | crash | finish")
publishing = mode.startswith("publish")
username = "producer" if publishing else "worker"
password = "Producer-lab-only!" if publishing else "Worker-lab-only!"
connection = pika.BlockingConnection(pika.ConnectionParameters("127.0.0.1", 15673, "lab",
	pika.PlainCredentials(username, password), blocked_connection_timeout=5))
channel = connection.channel()
if publishing:
	channel.confirm_delivery()
	body = json.dumps({"id": "event-1", "version": 1, "delta": 3}).encode() if mode == "publish" else b'{"version":1}'
	channel.basic_publish("w3.events", "job", body, mandatory=True,
		properties=pika.BasicProperties(content_type="application/json", delivery_mode=2))
	connection.close()
	print("confirmed publish")
else:
	method, properties, body = channel.basic_get("w3.jobs", auto_ack=False)
	if method is None:
		connection.close()
		raise SystemExit("No ready delivery; inspect queue and retry manually")
	try:
		if len(body) > 1024 or properties.content_type != "application/json":
			raise ValueError("envelope")
		event = json.loads(body)
		if not isinstance(event, dict) or set(event) != {"id", "version", "delta"}:
			raise ValueError("fields")
		if not isinstance(event["id"], str) or not 1 <= len(event["id"]) <= 64:
			raise ValueError("id")
		if type(event["version"]) is not int or event["version"] != 1:
			raise ValueError("version")
		if type(event["delta"]) is not int or not 1 <= event["delta"] <= 10:
			raise ValueError("delta")
	except (ValueError, UnicodeDecodeError):
		channel.basic_nack(method.delivery_tag, requeue=False)
		connection.close()
		print("quarantined invalid fixture; zero retries")
		raise SystemExit(0)
	database = sqlite3.connect("lab.sqlite")
	database.executescript("CREATE TABLE IF NOT EXISTS inbox(id TEXT PRIMARY KEY);"
		"CREATE TABLE IF NOT EXISTS balance(id INTEGER PRIMARY KEY,total INTEGER NOT NULL);"
		"INSERT OR IGNORE INTO balance VALUES(1,0);")
	with database:
		inserted = database.execute("INSERT INTO inbox VALUES(?) ON CONFLICT(id) DO NOTHING", (event["id"],)).rowcount
		if inserted:
			database.execute("UPDATE balance SET total=total+? WHERE id=1", (event["delta"],))
	total = database.execute("SELECT total FROM balance WHERE id=1").fetchone()[0]
	database.close()
	if mode == "crash":
		os._exit(23)
	channel.basic_ack(method.delivery_tag)
	connection.close()
	assert total == 3, total
	print("total=3", "duplicate suppressed" if not inserted else "first effect")
```

### Start and Bootstrap

```powershell
docker run --name w3-queue-tech -d -p 127.0.0.1:15673:5672 -e RABBITMQ_DEFAULT_USER=operator -e RABBITMQ_DEFAULT_PASS=Admin-lab-only-41! rabbitmq:4.1
docker exec w3-queue-tech rabbitmq-diagnostics -q ping
docker exec w3-queue-tech rabbitmqctl add_vhost lab
docker exec w3-queue-tech rabbitmqctl set_permissions -p lab operator '.*' '.*' '.*'
docker exec w3-queue-tech rabbitmqctl add_user producer Producer-lab-only!
docker exec w3-queue-tech rabbitmqctl add_user worker Worker-lab-only!
docker exec w3-queue-tech rabbitmqctl set_permissions -p lab producer '^$' '^w3\.events$' '^$'
docker exec w3-queue-tech rabbitmqctl set_permissions -p lab worker '^$' '^$' '^w3\.jobs$'
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python setup.py
.\.venv\Scripts\python app.py publish
.\.venv\Scripts\python app.py crash
$LASTEXITCODE
docker exec w3-queue-tech rabbitmqctl list_queues -p lab name messages_ready messages_unacknowledged
.\.venv\Scripts\python app.py finish
.\.venv\Scripts\python app.py publish-invalid
.\.venv\Scripts\python app.py finish
docker exec w3-queue-tech rabbitmqctl list_queues -p lab name messages_ready messages_unacknowledged
```

### Objectives, Hints, and Solution

Retry readiness manually before bootstrap. Predict the commit/ACK crash window. The crash invocation exits `23` after SQLite commits. Wait until the queue listing shows one ready, zero unacknowledged, then finish. Expected: redelivery prints `total=3 duplicate suppressed`; the business effect is not repeated. The malformed message gets zero retries and appears in quarantine. Final jobs count is zero, quarantine ready count one. Hint: the unique inbox key and balance update must share one transaction.

### Verification, Troubleshooting, and Cleanup

A permission failure on queue declaration indicates the app wrongly tried to configure topology; only setup.py uses operator credentials. `basic_get` empty just after a crash can be a requeue timing issue, not lost data; inspect ready/unacked counts. This deterministic exercise uses polling one message at a time, not production consumer flow control. Reset both broker and inbox together:

```powershell
docker rm -f -v w3-queue-tech
Remove-Item -LiteralPath ./lab.sqlite
```

No distributed transaction, replicated failover or external side-effect exactly-once guarantee is claimed.

- [ ] Local Message Queues exercise: Run a local broker with a producer and idempotent consumer. Force a consumer restart after processing but before acknowledgement and show the duplicate does not repeat the business effect.
- [ ] Boundary check: Publish a malformed synthetic message and verify bounded retries followed by quarantine. Confirm a producer identity cannot consume an unrelated queue.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Message Queues Security]]

## References

- [RabbitMQ reliability](https://www.rabbitmq.com/docs/reliability)
- [Publisher confirms and consumer ACKs](https://www.rabbitmq.com/docs/confirms)
- [Dead-letter exchanges](https://www.rabbitmq.com/docs/dlx)
- [Pika BlockingConnection](https://pika.readthedocs.io/en/stable/modules/adapters/blocking.html)
