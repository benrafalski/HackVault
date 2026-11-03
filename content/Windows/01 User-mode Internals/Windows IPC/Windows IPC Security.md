---
title: "Windows IPC (Named Pipes, ALPC, RPC) Security"
aliases: []
tags: [windows, x1, security]
domain: windows
phase: "X1"
type: security
status: draft
pair: "[[Windows IPC]]"
updated: 2026-11-03
---
# Windows IPC (Named Pipes, ALPC, RPC) Security

> [!abstract] TL;DR
> Permissive pipe/RPC ACLs, unsafe impersonation, spoofable endpoint names, and malformed messages can cross privilege boundaries.

> [!info] Agent scope
> Security of: Named pipes; ALPC; RPC interfaces and endpoints; authentication; impersonation; message validation; ACLs. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Endpoint ownership, transport identity, connection ACL, per-operation permission, message bounds, impersonation lifetime, and transferred handles are separate checks.
- This lab uses a real pipe between two endpoints in a standard-user process. The deliberately overbroad operation only returns a synthetic string; it changes no resources or privileges.

## Learn

```text
Teach Windows IPC defense with named-pipe, RPC and ALPC trust boundaries.
Assume Windows tokens, handles, DACLs and bounded binary parsing. Explain why
endpoint reachability, authenticated identity and operation authorization are
three different predicates. Cover default pipe ACLs, instance-creation rights,
server authentication, local-only limits, RPC authn/QoS, interface callbacks,
impersonation-level constraints and unconditional reversion after failures.
Use a complete same-user pipe program whose defective policy returns a harmless
ADMIN marker to a read-only client, then rejects that operation while retaining
PING. Include oversized frames, truncated frames, deadlines and disconnects.
Explain handle-capability validation and why client-supplied PID/SID strings
are not identity. Discuss auditing, false positives and what a same-user test
cannot prove about cross-user ACLs or privileged servers. Use primary sources.
No exploitation, escalation, credential access, impersonation demonstrations,
persistence, bypass/evasion or external targets. Teach here, do not edit files;
finish with exact expected outcomes and answered design-review questions.
```

## Cheatsheet

### Boundary Checklist

| Boundary | Defective assumption | Required design |
|---|---|---|
| Pipe DACL | Default security means creator-only | Explicit subject/logon-SID policy; minimum individual rights; review remote access separately. |
| Endpoint identity | Recognizable pipe name proves trusted server | Protect server-instance creation and verify trusted endpoint identity; fail on unexpected preexisting instance. |
| RPC transport | `ncalrpc` means all clients are trusted | Configure authentication and authorize each operation using authenticated context. |
| Request identity | Payload `user=admin` or claimed PID is authoritative | Obtain OS-authenticated caller context; treat payload claims as data. |
| Method authority | A permitted connection may call every method | Map principal to allowed operations/resources; default deny unknown operations. |
| Impersonation | Failure can fall back to server identity | Check success and level; revert on all paths; fail closed if reversion cannot be guaranteed. |
| Parsing | One write equals one read | Exact bounded framing, overflow-safe lengths, version/type checks, request-wide deadline. |
| Handle transfer | Received handle grants intended resource only | Verify object type and access scope; duplicate only necessary rights; own and close transferred handles. |

`FILE_GENERIC_WRITE` on a pipe includes the bit used for `FILE_CREATE_PIPE_INSTANCE`. Granting read/write data does not require granting that bit. `PIPE_REJECT_REMOTE_CLIENTS` rejects remote pipe clients on supported Windows; it does not exclude other local users. A logon SID scopes more narrowly than a user SID reused across sessions. A same-user process can still be lower-trust application code.

RPC authentication levels range from none/connect through packet integrity/privacy; transport availability and defaults vary. `RpcBindingSetAuthInfoExW` configures client authentication/QoS; server callback policy and method-level authorization remain necessary. `RpcImpersonateClient`/`ImpersonateNamedPipeClient` failures must abort privileged work. `RevertToSelf`/`RpcRevertToSelf` must execute even when parsing, allocation or I/O fails. This note does not exercise impersonation.

ALPC ports are local, but messages, shared views and transferred capabilities cross trust boundaries. Native port implementation details change across Windows versions; application code should favor documented RPC contracts. NDR stubs provide wire-layout checks, not permission to act on a named file or object.

## Detection and Defense

Record endpoint/interface version, authenticated principal identifier, operation, authorized resource identifier, decision and correlation ID, excluding secrets and raw unbounded payloads. Repeated malformed/denied requests are useful signals but can be compatibility defects. A connection event alone cannot establish misuse. Sysmon pipe events, when configured, record creation/connection rather than semantic authorization; application decision logs fill that gap. Track timeouts, parse rejection and collection loss separately.

## Labs

### Environment and Complete Files

Windows 10/11, preinstalled .NET 8 SDK, standard user. New scratch directory; no packages, service, network host or privileged operation. Each case creates a new GUID pipe and disposes it. Both endpoints share the same user; cross-user DACL testing is explicitly not claimed.

### File: PipeReview.csproj

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
await Check(false, 5, "ADMIN", "WOULD_ALLOW_ADMIN");
await Check(true, 5, "ADMIN", "DENY");
await Check(true, 4, "PING", "PONG");
await Check(true, 65, "", "BAD_LENGTH");
await Check(true, 4, "PI", "TRUNCATED");
Console.WriteLine("PASS: 5 real-pipe policy/framing cases");

static async Task Check(bool fixedPolicy, int advertised, string body, string expected)
{
	using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
	var token = deadline.Token;
	string name = "HVReview-" + Guid.NewGuid().ToString("N");
	using var server = new NamedPipeServerStream(name, PipeDirection.In, 1,
		PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
	async Task<string> Receive()
	{
		await server.WaitForConnectionAsync(token);
		try
		{
			byte[] header = new byte[4];
			await server.ReadExactlyAsync(header, token);
			int length = BinaryPrimitives.ReadInt32LittleEndian(header);
			if (length is < 1 or > 64) return "BAD_LENGTH";
			byte[] payload = new byte[length];
			await server.ReadExactlyAsync(payload, token);
			string operation = Encoding.ASCII.GetString(payload);
			if (operation == "PING") return "PONG";
			if (operation == "ADMIN" && !fixedPolicy) return "WOULD_ALLOW_ADMIN";
			return "DENY";
		}
		catch (EndOfStreamException) { return "TRUNCATED"; }
	}
	Task<string> received = Receive();
	using (var client = new NamedPipeClientStream(".", name, PipeDirection.Out,
		PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
	{
		await client.ConnectAsync(token);
		byte[] header = new byte[4];
		BinaryPrimitives.WriteInt32LittleEndian(header, advertised);
		await client.WriteAsync(header, token);
		if (body.Length > 0) await client.WriteAsync(Encoding.ASCII.GetBytes(body), token);
		if (advertised == body.Length || advertised > 64) await received;
	}
	string actual = await received;
	if (actual != expected) throw new Exception($"Expected {expected}; got {actual}");
	Console.WriteLine(actual);
}
```

### Objectives and Baseline

Run `dotnet build PipeReview.csproj -c Release` then `dotnet run --project PipeReview.csproj -c Release --no-build`. The first case deliberately accepts an operation outside the lab's read-only policy, returning only `WOULD_ALLOW_ADMIN`. There are no admin resources, roles or actions behind that marker. Predict the remaining results before running.

### Hints and Fixed Solution

The fix is removing the `ADMIN` allow branch when `fixedPolicy` is true; unknown operations deny by default. A valid connection remains allowed, but its method set is restricted. Header 65 is rejected before payload allocation. The final client advertises four bytes but sends two and closes; EOF is classified as truncation. Expected lines: `WOULD_ALLOW_ADMIN`, `DENY`, `PONG`, `BAD_LENGTH`, `TRUNCATED`, then PASS.

### Verification, Troubleshooting, and Cleanup

All five cases must pass and exit 0 within bounded time. A timeout or `IOException` is a failed transport run, not an authorization denial; record OS/runtime details. The lab tests framing and operation policy, not peer-process authentication, RPC callbacks, remote rejection or privileged impersonation. Delete only the scratch project/source and `bin`/`obj` after process exit. Source reviewed; compilation and Windows runtime cases remain unexecuted for parent validation.

- [ ] Local Windows IPC exercise: Run the five same-user real-pipe regression cases.
- [ ] Boundary check: Deny the synthetic forbidden operation while retaining PING and rejecting malformed/truncated frames.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[Windows IPC]]

## References

- [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [RPC security](https://learn.microsoft.com/en-us/windows/win32/rpc/security)
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [CreateNamedPipeW flags](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew)
