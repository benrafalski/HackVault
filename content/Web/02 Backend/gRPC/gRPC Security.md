---
title: "gRPC Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[gRPC]]"
updated: 2026-11-03
---
# gRPC Security

> [!abstract] TL;DR
> Overtrusted metadata, missing per-message/resource checks, and unbounded streams can expose data or retain work after clients disappear.

> [!info] Agent scope
> Security of: Protocol Buffers; service definitions; HTTP/2 transport; streaming; metadata; deadlines; authentication and authorization. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Overtrusted metadata, missing per-message/resource checks, and unbounded streams can expose data or retain work after clients disappear.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach defensive gRPC security to an engineer who knows protobuf, HTTP/2, Python
and TLS. Separate transport peer authentication, application identity, method
permission and per-resource/per-message policy. Trace metadata through interceptors
and handlers, including duplicates, trusted proxy boundaries and token validation.
Explain mTLS identity mapping, deadline propagation, cooperative cancellation,
bounded queues/messages/streams and retry ambiguity after side effects. Provide
complete generated-protobuf local regression tests with synthetic identities and
a harmless baseline failure/fix. Include positive controls, status interpretation,
error redaction, reflection exposure and safe telemetry. Cite grpc.io and protobuf
docs; label runtime-specific behavior. No exploit payloads or real credentials.
```

## Cheatsheet

### Identity and Policy

| Check | Mechanism | Failure |
|---|---|---|
| Transport | TLS hostname/trust validation; optional client cert verification | Untrusted connection never reaches ordinary business handling |
| Application identity | Verify token issuer, audience, signature, expiry, allowed algorithm | `UNAUTHENTICATED` |
| Method | Principal may invoke the service method | `PERMISSION_DENIED` |
| Object/message | Referenced resource is permitted now | `PERMISSION_DENIED` or deliberately concealed `NOT_FOUND` |
| Domain | Required values, lengths, enum semantics, state transitions | `INVALID_ARGUMENT` or `FAILED_PRECONDITION` |
| Capacity | Message bytes, concurrent RPCs, stream aggregate work | `RESOURCE_EXHAUSTED` |

Metadata is a sequence and may contain duplicate keys. Avoid silently choosing an arbitrary identity header: reject ambiguous authorization metadata. Do not equate `context.peer()` or an unverified forwarded principal with an application user. Map validated certificate identities through explicit policy; an authenticated service account is not entitled to every tenant.

Interceptors are useful for shared identity/method checks but must preserve all four RPC cardinalities. Wrapping only unary-unary leaves streams uncovered. Resource authorization belongs near data access and must cover every requested object in client/bidirectional streams. For long-lived streams, define revocation/revalidation behavior and a finite lifetime; authorization at stream-open time may become stale.

### Availability and State

Configure `grpc.max_receive_message_length` and `grpc.max_send_message_length` deliberately on clients and servers; these bound individual messages, not the stream total. Enforce counts, aggregate bytes, lifetime, backend timeout and queue sizes too. HTTP/2 flow control and executor thread counts do not constitute a complete admission policy. Set `maximum_concurrent_rpcs` where appropriate and manage fairness by authenticated caller.

Client deadlines normally stop waiting; handlers must observe cancellation and stop spawned work. Pass remaining time downstream, bounded by local policy. `DEADLINE_EXCEEDED` does not prove a mutation failed to commit. Persist deduplication keys with side effects before allowing retries. `UNAVAILABLE` can likewise describe an uncertain outcome.

Protobuf parsing only establishes wire validity. Validate empty IDs, default enum values and lengths. Reserve retired field tags/names and keep compiler/runtime versions compatible. Reflection reveals service schemas; disable or restrict it when unnecessary, but never treat its absence as authorization. Redact status details and trailers; log method, principal surrogate, status, message counts, deadlines and cleanup duration without raw tokens or content.

## Detection and Defense

Validate identity at the transport/application boundary, enforce resource policies, bound streams/messages, and use structured status handling. Monitor active streams, deadlines, cancellations, and authorization failures.

## Labs

### Bounded Resource Service

**Requirements:** Python 3.12, grpcio/grpcio-tools 1.71.0, protobuf 5.29.4, pytest 8.3.5. Empty temporary directory, two source files. Generated files come from the command below. Real loopback server, synthetic metadata and data only; plaintext transport is not a production recommendation. **All execution unverified.**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install grpcio==1.71.0 grpcio-tools==1.71.0 protobuf==5.29.4 pytest==8.3.5
.venv\Scripts\python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. policy.proto
.venv\Scripts\python -m pytest -q test_grpc_policy.py
```

### File: policy.proto

```protobuf
syntax = "proto3";
package policylab;
service Notes {
  rpc Read (Key) returns (Note);
  rpc Watch (Key) returns (stream Note);
}
message Key { string id = 1; }
message Note { string text = 1; }
```

**Objective:** separate missing identity, denied method, denied resource, message size and cancellation. Baseline is a disabled read permission that prevents legitimate use. **Hint:** authentication occurs before looking up fixture data; watch has a separate permission.

### File: test_grpc_policy.py

```python
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import grpc
import pytest
import policy_pb2 as messages
import policy_pb2_grpc as services


class Notes(services.NotesServicer):
	def __init__(self):
		self.read_enabled = False
		self.finished = Event()

	def authorize(self, request, context, method):
		tokens = [value for key, value in context.invocation_metadata()
				  if key == "authorization"]
		identities = {"Bearer fixture-a": ("alice", {"Read", "Watch"}),
					  "Bearer fixture-b": ("bob", {"Read"})}
		if len(tokens) != 1 or tokens[0] not in identities:
			context.abort(grpc.StatusCode.UNAUTHENTICATED, "identity required")
		actor, methods = identities[tokens[0]]
		if method not in methods or (method == "Read" and not self.read_enabled):
			context.abort(grpc.StatusCode.PERMISSION_DENIED, "method denied")
		if not request.id or len(request.id) > 16:
			context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid id")
		records = {"1": ("alice", "alpha"), "2": ("bob", "beta")}
		record = records.get(request.id)
		if record is None or record[0] != actor:
			context.abort(grpc.StatusCode.PERMISSION_DENIED, "resource denied")
		return record[1]

	def Read(self, request, context):
		return messages.Note(text=self.authorize(request, context, "Read"))

	def Watch(self, request, context):
		text = self.authorize(request, context, "Watch")
		stopped = Event()
		context.add_callback(stopped.set)
		try:
			for sequence in range(2):
				if not context.is_active():
					return
				yield messages.Note(text=f"{text}:{sequence}")
				if stopped.wait(0.1):
					return
		finally:
			self.finished.set()


def test_policy_and_cleanup():
	executor = ThreadPoolExecutor(max_workers=2)
	server = grpc.server(executor, maximum_concurrent_rpcs=4,
						 options=[("grpc.max_receive_message_length", 1024),
								  ("grpc.max_send_message_length", 1024)])
	implementation = Notes()
	services.add_NotesServicer_to_server(implementation, server)
	port = server.add_insecure_port("127.0.0.1:0")
	assert port
	server.start()
	channel = grpc.insecure_channel(f"127.0.0.1:{port}")
	alice = (("authorization", "Bearer fixture-a"),)
	bob = (("authorization", "Bearer fixture-b"),)
	try:
		grpc.channel_ready_future(channel).result(timeout=3)
		stub = services.NotesStub(channel)

		def denied(call, code):
			with pytest.raises(grpc.RpcError) as failure:
				call()
			assert failure.value.code() == code

		denied(lambda: stub.Read(messages.Key(id="1"), metadata=alice, timeout=2),
			   grpc.StatusCode.PERMISSION_DENIED)
		implementation.read_enabled = True
		assert stub.Read(messages.Key(id="1"), metadata=alice, timeout=2).text == "alpha"
		denied(lambda: stub.Read(messages.Key(id="1"), timeout=2),
			   grpc.StatusCode.UNAUTHENTICATED)
		denied(lambda: stub.Read(messages.Key(id="1"), metadata=alice + bob, timeout=2),
			   grpc.StatusCode.UNAUTHENTICATED)
		denied(lambda: stub.Read(messages.Key(id="2"), metadata=alice, timeout=2),
			   grpc.StatusCode.PERMISSION_DENIED)
		denied(lambda: list(stub.Watch(messages.Key(id="2"), metadata=bob, timeout=2)),
			   grpc.StatusCode.PERMISSION_DENIED)
		assert stub.Read(messages.Key(id="2"), metadata=bob, timeout=2).text == "beta"
		denied(lambda: stub.Read(messages.Key(id="x" * 2048), metadata=alice, timeout=2),
			   grpc.StatusCode.RESOURCE_EXHAUSTED)
		stream = stub.Watch(messages.Key(id="1"), metadata=alice, timeout=2)
		assert next(stream).text == "alpha:0"
		stream.cancel()
		assert implementation.finished.wait(2)
		assert [item.text for item in stub.Watch(messages.Key(id="1"),
				metadata=alice, timeout=2)] == ["alpha:0", "alpha:1"]
	finally:
		channel.close()
		server.stop(0).wait(3)
		executor.shutdown(wait=True)
```

### Solution and Acceptance

Enable only the intended read function and retain the independent method/resource checks. Expected: one passing test; missing/duplicate identity is unauthenticated, foreign resource and Bob's watch are denied, legitimate reads work, the oversized frame is rejected, and cancelled stream cleanup completes. These fixture strings test policy plumbing, not token cryptography or mTLS. No mutable customer state exists.

Troubleshooting: missing modules require protoc generation; version errors require regenerating with pinned packages. A stream error appears when iterating, not necessarily when creating the call. Cleanup is guaranteed by `finally` for ordinary assertion failures. Reset by rerunning the test; remove only the temporary directory after process exit. TLS, revocation, proxy behavior and durable-write retries remain integration checks.

- [ ] Local gRPC exercise: Build a unary echo method and a short server stream using generated stubs. Test a deadline, cancellation, invalid identity, and an oversized message.
- [ ] Boundary check: Cancel a synthetic streaming call and confirm server work ends. Request another user's resource with a valid but insufficient identity and require a permission error.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[gRPC]]

## References

- [gRPC authentication](https://grpc.io/docs/guides/auth/)
- [Cancellation](https://grpc.io/docs/guides/cancellation/)
- [Status codes](https://grpc.io/docs/guides/status-codes/)
- [Python API](https://grpc.github.io/grpc/python/grpc.html)
