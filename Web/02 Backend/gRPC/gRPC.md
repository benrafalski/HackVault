---
title: "gRPC"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[gRPC Security]]"
updated: 2026-11-03
---
# gRPC

> [!abstract] TL;DR
> Set deadlines explicitly, preserve cancellation, use TLS/mTLS where appropriate, and authorize the method plus referenced resource. Never reuse retired protobuf field numbers.

> [!info] Agent scope
> Protocol Buffers; service definitions; HTTP/2 transport; streaming; metadata; deadlines; authentication and authorization.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach gRPC and Protocol Buffers at expert implementation depth. Assume HTTP,
Python, concurrency and basic TLS knowledge. Trace a generated stub through
serialization, HTTP/2 headers/message framing, server dispatch and final status.
Explain field tags, wire types, proto3 presence/defaults, oneof, unknown fields,
reserved tags/names and binary versus JSON compatibility. Compare unary, client
streaming, server streaming and bidirectional streaming, including ordering,
flow control, half-close and cancellation. Build a complete Python grpcio example
with generated stubs, bounded messages, deadlines and cooperative cleanup. Show
metadata identity versus resource authorization, TLS/mTLS, interceptors and retry
uncertainty. Ask me to predict client/server outcomes and cite grpc.io/protobuf
primary docs. Use synthetic local data; label external execution unverified.
```

## Cheatsheet

### Wire and Schema

An RPC method has a fully qualified path such as `/lab.Echo/Once`. Generated stubs serialize messages and select cardinality; they do not enforce business constraints. gRPC commonly uses HTTP/2 with `application/grpc`, length-prefixed messages (compression flag plus four-byte big-endian length), and final `grpc-status` in trailers or a trailers-only response. HTTP success alone does not mean RPC success.

| Schema decision | Rule | Consequence |
|---|---|---|
| Field number | Stable wire identity; reserve removed numbers and names | Renaming a field is different from changing its tag |
| Proto3 scalar | Implicit presence normally conflates unset/default | Use `optional` where absence differs from zero/empty |
| `oneof` | At most one active member | Case selection is still untrusted domain input |
| Repeated/map | Variable cardinality | Generated types do not set your application count limits |
| Unknown fields | Binary readers can preserve them | JSON conversions/rebuilding messages can lose them |
| Enum | Zero/default value needs explicit semantics | Unknown numeric values must not silently grant a role |

Do not reuse retired tags, change wire types casually or assume binary-compatible evolution is JSON-compatible. ProtoJSON represents 64-bit integers as strings and uses named fields; schema changes require checking both encodings and generated-language APIs. Generator/runtime version compatibility is separate from network compatibility; pin and regenerate together.

### Lifecycle and Capacity

| Cardinality | Lifecycle | Required control |
|---|---|---|
| Unary | One request, one response | Deadline and idempotent retry decision |
| Server stream | One request, many responses | Finite count/lifetime; stop on cancellation |
| Client stream | Many requests, one response | Aggregate bytes/count and per-message validation |
| Bidirectional | Independent send/receive streams | Concurrent read/write, bounded queues, explicit half-close |

Messages retain order within one RPC, not across calls. HTTP/2 flow control manages transport buffering; it does not cap rows fetched or application queues. A blocked write is not evidence that downstream processing completed. Bound receive/send sizes on both sides, active RPCs, stream lifetime and backend work. Python synchronous handlers occupy executor threads; long streams consume capacity even while waiting.

### Deadline, Status and Identity

Python supplies relative `timeout=...`; gRPC otherwise permits calls without a deadline. Use `context.time_remaining()` for downstream budgets, subtract local overhead and propagate cancellation. `context.is_active()` and callbacks help cooperative work stop; cancellation does not roll back an already committed write.

`INVALID_ARGUMENT`: domain validation; `UNAUTHENTICATED`: no accepted identity; `PERMISSION_DENIED`: accepted identity lacks access; `RESOURCE_EXHAUSTED`: capacity/message bound; `DEADLINE_EXCEEDED`: caller budget elapsed; `UNAVAILABLE`: transient connectivity/service issue, not automatic permission to repeat a mutation. Client and server may observe different final outcomes after a deadline. Deduplicate side-effecting retries transactionally.

Metadata keys are lower-case; binary values use `-bin`. Metadata is not trustworthy merely because it arrived over gRPC. TLS validates the server; mTLS validates a client certificate identity, which still needs method/resource policy. Shared interceptors can validate identity; handlers/repositories authorize specific objects. HTTP/1-only proxies and missing trailer support can break native gRPC; gRPC-Web is a distinct transport adaptation.

## Gotchas

mTLS authenticates a certificate identity, not every requested operation. A generated client does not prevent a custom client from sending unexpected values.

## Labs

### Generated Unary and Streaming RPCs

**Requirements:** Python 3.12, grpcio/grpcio-tools 1.71.0, protobuf 5.29.4, pytest 8.3.5. Empty temporary directory with the two files below. The test starts a real loopback HTTP/2 gRPC server on an ephemeral port and stops it. Plaintext is intentional for local synthetic data only. **Unverified runtime/network behavior.**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install grpcio==1.71.0 grpcio-tools==1.71.0 protobuf==5.29.4 pytest==8.3.5
.venv\Scripts\python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. echo.proto
.venv\Scripts\python -m pytest -q test_grpc_contract.py
```

### File: echo.proto

```protobuf
syntax = "proto3";
package lab;
service Echo {
  rpc Once (Message) returns (Message);
  rpc Watch (Message) returns (stream Message);
}
message Message {
  string text = 1;
  uint32 delay_ms = 2;
}
```

**Objective:** observe generated serialization, deadlines, streaming cancellation and receive limits. **Hint:** an RPC failure is a `grpc.RpcError`, while server cleanup needs its own observation.

### File: test_grpc_contract.py

```python
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import grpc
import pytest
import echo_pb2 as messages
import echo_pb2_grpc as services


class Echo(services.EchoServicer):
	def __init__(self):
		self.stream_finished = Event()

	def Once(self, request, context):
		if request.delay_ms > 200:
			context.abort(grpc.StatusCode.INVALID_ARGUMENT, "delay exceeds fixture limit")
		cancelled = Event()
		context.add_callback(cancelled.set)
		if cancelled.wait(request.delay_ms / 1000):
			context.abort(grpc.StatusCode.CANCELLED, "caller stopped")
		return messages.Message(text=request.text)

	def Watch(self, request, context):
		cancelled = Event()
		context.add_callback(cancelled.set)
		try:
			for sequence in range(3):
				if not context.is_active():
					return
				yield messages.Message(text=f"{request.text}:{sequence}")
				if cancelled.wait(0.1):
					return
		finally:
			self.stream_finished.set()


def test_real_transport():
	executor = ThreadPoolExecutor(max_workers=2)
	server = grpc.server(executor, options=[("grpc.max_receive_message_length", 1024)])
	implementation = Echo()
	services.add_EchoServicer_to_server(implementation, server)
	port = server.add_insecure_port("127.0.0.1:0")
	assert port != 0
	server.start()
	channel = grpc.insecure_channel(f"127.0.0.1:{port}")
	try:
		grpc.channel_ready_future(channel).result(timeout=3)
		stub = services.EchoStub(channel)
		assert stub.Once(messages.Message(text="marker"), timeout=2).text == "marker"
		with pytest.raises(grpc.RpcError) as failure:
			stub.Once(messages.Message(text="slow", delay_ms=200), timeout=0.02)
		assert failure.value.code() == grpc.StatusCode.DEADLINE_EXCEEDED
		with pytest.raises(grpc.RpcError) as failure:
			stub.Once(messages.Message(text="x" * 2048), timeout=2)
		assert failure.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
		stream = stub.Watch(messages.Message(text="tick"), timeout=2)
		assert next(stream).text == "tick:0"
		stream.cancel()
		assert implementation.stream_finished.wait(2)
		complete = list(stub.Watch(messages.Message(text="all"), timeout=2))
		assert [item.text for item in complete] == ["all:0", "all:1", "all:2"]
	finally:
		channel.close()
		server.stop(0).wait(3)
		executor.shutdown(wait=True)
```

### Solution and Acceptance

Expected: one passing test, echo text preserved, client deadline status, oversized-message status, cancellation cleanup observed and a complete three-message stream. The callback wakes fixture work; `finally` records handler termination. Authentication/resource policy have an independent complete lab in the security note. This lab does not claim TLS, proxy or cross-language compatibility.

Troubleshooting: missing `echo_pb2` means generation was skipped or cwd differs. Runtime-version errors require the pinned tool/runtime pair and regeneration. `UNAVAILABLE` suggests loopback restriction or server startup failure. Very overloaded hosts may need a larger ordinary-call timeout, but keep the delayed call's timeout below its fixture delay. Cleanup is in `finally`; after the process exits, remove the temporary directory including generated modules and environment.

- [ ] Local gRPC exercise: Build a unary echo method and a short server stream using generated stubs. Test a deadline, cancellation, invalid identity, and an oversized message.
- [ ] Boundary check: Cancel a synthetic streaming call and confirm server work ends. Request another user's resource with a valid but insufficient identity and require a permission error.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[gRPC Security]]

## References

- [gRPC core concepts](https://grpc.io/docs/what-is-grpc/core-concepts/)
- [Deadlines and server cleanup](https://grpc.io/docs/guides/deadlines/)
- [Python generated code](https://grpc.io/docs/languages/python/generated-code/)
- [Protocol Buffers proto3 guide](https://protobuf.dev/programming-guides/proto3/)
