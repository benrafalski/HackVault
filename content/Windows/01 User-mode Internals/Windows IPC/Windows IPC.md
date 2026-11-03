---
title: "Windows IPC (Named Pipes, ALPC, RPC)"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[Windows IPC Security]]"
updated: 2026-11-03
---
# Windows IPC (Named Pipes, ALPC, RPC)

> [!abstract] TL;DR
> Validate endpoint identity, caller token, impersonation level, message schema, and requested action. Treat transferred handles as capabilities.

> [!info] Agent scope
> Named pipes; ALPC; RPC interfaces and endpoints; authentication; impersonation; message validation; ACLs.

## Prerequisites

- Windows 10/11, an already-installed .NET 8 SDK, C# async/streams, tokens and DACLs. Standard user; no service or network endpoint deployment.
- [[Windows Lab Setup]]

## Learn

```text
Teach Windows named pipes, local RPC/ALPC and RPC at implementation depth.
Assume Win32 handles, tokens, DACLs, C# streams and async cancellation. Explain
pipe instances, byte/message modes, partial I/O, ERROR_MORE_DATA, connection
races, overlapped lifetime, disconnects, deadlines, server identity and ACLs.
Trace an IDL interface through NDR marshaling, binding, endpoint selection,
transport, authentication, callback checks and per-operation authorization.
Compare ncalrpc, ncacn_np and ncacn_ip_tcp; distinguish RPC interface UUID/version
from an endpoint address. Explain ALPC messages/ports and handle capabilities
without treating undocumented native interfaces as a stable public SDK.
Provide a complete same-user bounded pipe exchange and malformed/disconnect
tests. Explain impersonation levels and guaranteed reversion conceptually;
never demonstrate privileged impersonation or escalation. Describe cancellation
and ownership hazards, confused-deputy prevention, version limits and meaningful
telemetry. Use primary Microsoft sources, worked traces, and answered questions.
No persistence, bypass/evasion, external targets, file edits or fabricated runs.
```

## Cheatsheet

### Transport, Naming, and Lifetime

| Mechanism | Contract | Boundary |
|---|---|---|
| Named pipe `\\.\pipe\Name` | Server owns one or more instances; clients open instances; byte or message framing | Pipe DACL controls opens, not application operations. Names alone do not authenticate the server. |
| RPC `ncalrpc` | Local RPC using Windows local transport | Locality is not authorization. Interface security and call checks still apply. |
| RPC `ncacn_np` | Connection-oriented RPC over named pipes | SMB/pipe access and RPC authentication are distinct layers. |
| RPC `ncacn_ip_tcp` | RPC over TCP, fixed or mapped endpoints | Endpoint mapper discovery is not interface permission. Firewalls must account for the actual endpoint. |
| ALPC | Kernel-mediated local ports, messages, optional shared views/attributes | Native details are version-sensitive. Prefer documented RPC/COM contracts for application development. |

Pipe creation: `CreateNamedPipeW` supplies direction, byte/message mode, instance count, buffers, and security descriptor. `ConnectNamedPipe` can report `ERROR_PIPE_CONNECTED` when a client arrives before the connect call; this is a successful connection race, not a fatal error. `CreateFileW` can fail with `ERROR_PIPE_BUSY`; `WaitNamedPipeW` only waits for availability, it does not reserve an instance.

Byte pipes preserve bytes, not write boundaries: read an exact fixed header, validate size before allocating, then read the exact payload. Message pipes preserve writes, but a small read buffer can return `ERROR_MORE_DATA`; accumulate boundedly. A zero-byte/EOF or `ERROR_BROKEN_PIPE` means peer closure, not an empty valid command. `FlushFileBuffers` on a pipe can block until the peer drains data; it is not an application acknowledgment.

Overlapped operations own their buffer and `OVERLAPPED` until completion. Cancellation requests do not immediately free them. Cancel, observe completion, then release handles/buffers. Bound connection time, message size, concurrent clients and total request time. One timeout per read can be defeated by an indefinitely slow request; use a request-wide deadline.

### RPC and Authority

An IDL `[uuid(...), version(1.0)] interface` defines method signatures and NDR layout; generated stubs marshal counts, arrays, strings and contexts. Bounds in IDL supplement, not replace, semantic validation. An RPC binding combines protocol sequence, network address, endpoint and options. `RpcBindingSetAuthInfoExW` configures client authentication/QoS; server authentication registration and `RpcServerRegisterIfEx` callback policy govern acceptance. `RpcBindingInqAuthClientExW` can inspect authenticated call context. An interface UUID is not a secret or an authorization credential.

Impersonation determines which token a thread uses for resource access. Identification permits identity inspection, not acting as the caller; impersonation and delegation have progressively different scope. Check every impersonation result, authorize the requested operation, and guarantee `RevertToSelf`/`RpcRevertToSelf` on every path. Never fall back to server identity after failed impersonation. Handle transfer conveys already-granted authority: validate type, rights, provenance, lifetime and intended use; a numeric handle value from another process is not directly usable.

### Security and Version Notes

Default pipe security is not a private-channel guarantee. Specify a DACL appropriate to the caller/logon SID; a user SID can cover multiple sessions. `FILE_GENERIC_WRITE` includes `FILE_CREATE_PIPE_INSTANCE` because it shares a bit with append data; use specific rights for clients. `FILE_FLAG_FIRST_PIPE_INSTANCE` helps detect preexisting names, but is not mutual authentication. `PIPE_REJECT_REMOTE_CLIENTS` is a Windows 7+ server flag; the managed lab below selects a local client and same-user policy but does not claim that flag is set.

## Gotchas

- Never deserialize arbitrary objects merely because a peer passed the pipe DACL. Use a fixed schema and explicit operation authorization.
- A server PID is useful evidence, not durable identity; PID reuse and image replacement require stronger trust checks.
- App-container pipes have additional namespace/platform restrictions. Do not extrapolate desktop examples to packaged applications.

## Labs

### Environment and Complete Files

Create these two files in a new scratch directory. .NET 8 SDK is required in advance. No packages, credentials, admin rights, registration or persistent listener. Both endpoints run in one self-authored process but communicate through a real Windows named pipe.

### File: PipeLab.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>
	<ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>
</Project>
```

### File: Program.cs

```csharp
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows lab");
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
var token = deadline.Token;
string name = "HV-" + Guid.NewGuid().ToString("N");
using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
	PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

async Task Serve()
{
	await server.WaitForConnectionAsync(token);
	byte[] request = await Receive(server, token);
	if (!request.AsSpan().SequenceEqual("PING"u8)) throw new InvalidDataException("operation");
	await Send(server, "PONG"u8.ToArray(), token);
}

Task serving = Serve();
using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut,
	PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
await client.ConnectAsync(token);
await Send(client, "PING"u8.ToArray(), token);
string reply = Encoding.ASCII.GetString(await Receive(client, token));
await serving;
if (reply != "PONG") throw new Exception("wrong reply");
Console.WriteLine("PASS: PING -> PONG over a same-user byte pipe");

static async Task Send(Stream stream, byte[] payload, CancellationToken token)
{
	if (payload.Length is < 1 or > 64) throw new InvalidDataException("length");
	byte[] header = new byte[4];
	BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
	await stream.WriteAsync(header, token);
	await stream.WriteAsync(payload, token);
}

static async Task<byte[]> Receive(Stream stream, CancellationToken token)
{
	byte[] header = new byte[4];
	await stream.ReadExactlyAsync(header, token);
	int length = BinaryPrimitives.ReadInt32LittleEndian(header);
	if (length is < 1 or > 64) throw new InvalidDataException("length");
	byte[] payload = new byte[length];
	await stream.ReadExactlyAsync(payload, token);
	return payload;
}
```

### Objectives, Steps, and Hints

Run `dotnet build PipeLab.csproj -c Release`, then `dotnet run --project PipeLab.csproj -c Release --no-build`. The SDK may restore framework assets; no third-party packages are specified. Predict header bytes `04 00 00 00` and payload ASCII `PING`. Explain why one `ReadAsync` is not sufficient and why the buffer limit is checked before allocation. Hint: request lifetime is bounded by the shared ten-second token.

### Solution and Expected Results

Expected one PASS line and exit 0. `Receive` reconstructs a frame independent of pipe chunking; the server accepts one fixed operation and returns one fixed response. `CurrentUserOnly` uses Windows user identity checks; this is not a cross-user denial test or per-method authorization framework. Both endpoints are disposed at process exit, releasing the transient named instance.

### Verification, Troubleshooting, and Cleanup

Check output and absence of an indefinitely running process. An unsupported SDK requires the stated prerequisite; do not install during this lab. A timeout is a failed run, not successful delivery. Enterprise endpoint policy may prevent pipe creation; record it without weakening policy. Delete the two scratch files plus their `bin`/`obj` directories only after exit. Source reviewed, not built/run; parent must validate Windows pipe behavior and .NET 8 compilation. Malformed input and unauthorized-operation regression cases are supplied independently in the paired security note.

- [ ] Local Windows IPC exercise: Observe a bounded framed exchange over a real same-user named pipe.
- [ ] Boundary check: Explain connection identity, framing limits, operation policy, and handle lifetime separately.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows IPC Security]]

## References

- [Named pipe operations](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-operations)
- [Named pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [RPC security](https://learn.microsoft.com/en-us/windows/win32/rpc/security)
- [Protocol sequence constants](https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants)
