---
title: "ETW and Event Log"
aliases: []
tags: [windows, x1]
domain: windows
phase: "X1"
type: tech
status: draft
pair: "[[ETW and Event Log Security]]"
updated: 2026-11-03
---
# ETW and Event Log

> [!abstract] TL;DR
> Record provider/version/channel and collection configuration, not just event ID. Distinguish no event observed from proof that no action occurred.

> [!info] Agent scope
> Providers; sessions; consumers; event channels; manifests; permissions; collection; loss and retention; distinction from ETW-TI.

## Prerequisites

- Windows 10/11, preinstalled VS 2022 MSVC/Windows SDK, x64 Native Tools prompt. The native ETW lab needs existing authorization to control an ordinary trace session (commonly Performance Log Users membership or an approved elevated lab session); it does not change memberships or policies.
- [[Windows Lab Setup]]

## Learn

```text
Teach ETW and Windows Event Log as distinct but related Windows telemetry systems.
Assume native APIs, GUIDs, buffers, timestamps and access control. Trace provider
registration, controller StartTrace/EnableTraceEx2, event filtering/buffering,
ETL or real-time delivery, consumer decoding and session teardown. Compare
manifest-based, TraceLogging, WPP and classic metadata/version contracts.
Explain level/keyword filters, activity IDs, QPC versus wall-clock time, buffer
loss, consumer backpressure and collection statistics. Contrast Event Log
channels/EVTX with ETW sessions/ETL, including EvtQuery/EvtNext/EvtRender,
bookmarks, XPath limits, forwarding, channel ACLs and retention modes.
Provide a complete self-authored TraceLogging provider/controller that records
one harmless marker to an own scratch ETL and stops only its own session; give
exact native build and built-in decoding commands. Include read-only Event Log
queries without creating sources or changing channels. Separate emission from
confirmed collection and decoding. Explain ETW-TI protected access as a distinct
topic, not something ordinary provider rights grant. Use primary sources,
expected evidence and answered questions. No logging disablement, bypass,
evasion, persistence, confidential data, note edits or fabricated execution.
```

## Cheatsheet

### ETW Pipeline and Ownership

| Component | APIs and responsibility |
|---|---|
| Provider | `EventRegister`/`EventWrite` or TraceLogging macros; owns event schema, levels/keywords and activity data. Registration is process lifetime, not service installation. |
| Controller | `StartTraceW`, `EnableTraceEx2`, `ControlTraceW`; owns session name/GUID, buffers, filters, destination, stop/flush and statistics. |
| Consumer | `OpenTraceW`, `ProcessTrace`, callbacks, `CloseTrace`; consumes ETL or real-time records and decodes with metadata/TDH. |
| Windows Event Log | Persists selected publisher events to configured channels/EVTX and exposes `Evt*` APIs; not every ETW event goes into an Event Log channel. |

Provider GUID identifies the source schema, not an authenticated user. Manifest event identity includes event ID **and version**, plus task/opcode/keywords as relevant. TraceLogging carries self-describing metadata; WPP decoding often needs matching TMF/PDB material. A missing message DLL can prevent localized rendering while raw event fields remain available. Never parse localized message text as the primary schema.

Level filtering ordinarily includes events whose level is at or below the session's configured verbosity (special zero semantics exist); keyword MatchAny/MatchAll masks further select provider-defined categories. Provider-side enable checks are an optimization; emission success or enablement is not proof that a consumer durably retained an event. Keep events small and avoid secrets. Event size/buffer limits, disk throughput and slow consumers can drop data.

Session `EventsLost`, `LogBuffersLost` and `RealTimeBuffersLost` describe different loss paths. Increasing buffers can trade memory for burst tolerance but cannot guarantee delivery under sustained overload. QPC timestamps and system time require correct trace metadata conversion; cross-host clocks and concurrent CPUs do not imply a globally ordered causal sequence. Use activity/related-activity IDs and application sequence numbers where the producer contract defines them.

### Event Log Queries and Retention

`EvtQuery` creates a query handle; `EvtNext` yields event handles; `EvtRender` renders XML/values; close all with `EvtClose`. A bookmark represents a source position for resumption, not a durable copy or global event ID. Rollover, clearing and source recreation can invalidate continuity assumptions. `EvtSubscribe` callbacks must handle errors/lag, not just records.

Read-only observation on an authorized local host:

```powershell
wevtutil.exe gl Application
Get-WinEvent -LogName Application -MaxEvents 3 |
	Select-Object ProviderName,Id,Version,TimeCreated,RecordId
Get-WinEvent -LogName System -FilterXPath '*[System[Level=2]]' -MaxEvents 3 |
	ForEach-Object { $_.ToXml() }
```

An empty result, inaccessible log, and query failure are different outcomes. Event Log XPath supports a restricted subset, not arbitrary XPath functions/namespaces. For multiple channels or complex expressions use a `QueryList` with `Select`/`Suppress`; suppressors can remove selected events. Preserve the configured query as evidence.

| Retention choice | Consequence |
|---|---|
| Overwrite oldest | Bounded disk, older evidence can roll out before collection. |
| Retain without overwrite | Preserves old records but can stop accepting new events when full. |
| Auto-backup where supported/configured | Requires disk planning and operational monitoring; backup files are not automatically centrally collected. |

Forwarding adds subscriptions, transport, queueing, destination permissions and latency. It does not automatically make collection complete or immutable. Channel read/write/clear permissions and trace-controller/provider permissions are distinct. Security channel access and specialized protected providers have additional constraints. [[ETW-TI]] covers the specialized Threat Intelligence provider; ordinary trace permissions do not grant its protected access.

## Gotchas

- Event record ID is channel-local, not an application sequence or a cross-machine primary key.
- A provider can be active without an Event Log manifest/channel. An ETL is not an EVTX and the two require appropriate readers.
- Do not stop a session merely because its name resembles your lab. Retain the successful creation handle/name and stop only that session.

## Labs

### Environment and Complete Files

One native file in a new scratch directory on Windows 10/11. Preinstalled MSVC/SDK and existing trace authorization are required. No package install, provider manifest registration, service, Event Log source creation, channel modification or protected provider access. The program refuses to overwrite an existing `marker.etl`, starts a uniquely named ordinary session, enables only its own provider and stops that session.

### File: marker.cpp

```cpp
#include <windows.h>
#include <evntrace.h>
#include <TraceLoggingProvider.h>
#include <objbase.h>
#include <cstdio>
#include <cstddef>
#include <cwchar>

TRACELOGGING_DEFINE_PROVIDER(g_provider, "HackVault.Marker",
	(0x8c321f42, 0x984f, 0x4eed, 0x91, 0x2a, 0x1d, 0x2b, 0xc3, 0x44, 0x55, 0x66));
static const GUID providerId =
	{0x8c321f42, 0x984f, 0x4eed, {0x91,0x2a,0x1d,0x2b,0xc3,0x44,0x55,0x66}};
struct Properties {
	EVENT_TRACE_PROPERTIES values;
	wchar_t name[128];
	wchar_t path[MAX_PATH];
};

int wmain() {
	Properties properties{};
	DWORD length = GetFullPathNameW(L"marker.etl", MAX_PATH, properties.path, nullptr);
	if (!length || length >= MAX_PATH) return 1;
	if (GetFileAttributesW(properties.path) != INVALID_FILE_ATTRIBUTES) {
		std::puts("Refusing existing marker.etl"); return 2;
	}
	if (FAILED(CoCreateGuid(&properties.values.Wnode.Guid))) return 3;
	wchar_t guidText[40]{};
	if (!StringFromGUID2(properties.values.Wnode.Guid, guidText, 40)) return 3;
	swprintf_s(properties.name, L"HVMarker-%ls", guidText);
	properties.values.Wnode.BufferSize = sizeof(properties);
	properties.values.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	properties.values.Wnode.ClientContext = 1;
	properties.values.BufferSize = 64;
	properties.values.MinimumBuffers = 2;
	properties.values.MaximumBuffers = 4;
	properties.values.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
	properties.values.MaximumFileSize = 1;
	properties.values.LoggerNameOffset = offsetof(Properties, name);
	properties.values.LogFileNameOffset = offsetof(Properties, path);
	ULONG registered = TraceLoggingRegister(g_provider);
	if (registered != ERROR_SUCCESS) { std::printf("register=%lu\n", registered); return 4; }
	TRACEHANDLE session = 0;
	ULONG started = StartTraceW(&session, properties.name, &properties.values);
	if (started != ERROR_SUCCESS) {
		TraceLoggingUnregister(g_provider);
		std::printf("start=%lu\n", started); return 5;
	}
	std::wprintf(L"Own session: %ls\nETL: %ls\n", properties.name, properties.path);
	ULONG enabled = EnableTraceEx2(session, &providerId, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_INFORMATION, 1, 0, 1000, nullptr);
	if (enabled == ERROR_SUCCESS) {
		TraceLoggingWrite(g_provider, "Marker",
			TraceLoggingLevel(TRACE_LEVEL_INFORMATION), TraceLoggingKeyword(1),
			TraceLoggingString("BENIGN-MARKER", "Message"), TraceLoggingUInt32(7, "Sequence"));
	}
	ULONG stopped = ControlTraceW(session, nullptr, &properties.values, EVENT_TRACE_CONTROL_STOP);
	TraceLoggingUnregister(g_provider);
	std::wprintf(L"enable=%lu stop=%lu events_lost=%lu log_buffers_lost=%lu\n",
		enabled, stopped, properties.values.EventsLost, properties.values.LogBuffersLost);
	return enabled == ERROR_SUCCESS && stopped == ERROR_SUCCESS &&
		properties.values.EventsLost == 0 && properties.values.LogBuffersLost == 0 ? 0 : 6;
}
```

### Objectives and Steps

In the scratch directory, x64 Native Tools command prompt:

```bat
cl /nologo /W4 /EHsc /std:c++17 marker.cpp /link Advapi32.lib Ole32.lib
marker.exe
tracerpt marker.etl -o decoded.xml -of XML
```

Then in PowerShell in that same directory:

```powershell
Select-String -LiteralPath .\decoded.xml -Pattern 'HackVault.Marker|BENIGN-MARKER|Sequence'
```

Do not grant extra privileges if `StartTraceW` returns access denied; record the unmet trace-authorization prerequisite. The provider/controller does not require COM initialization merely to generate a GUID. There is no persistent provider installation to remove.

### Hints and Solution

Expected enable/stop status 0, loss counters 0, and decoded evidence containing provider `HackVault.Marker`, message `BENIGN-MARKER` and sequence 7. Exact XML layout and additional trace metadata depend on Windows/decoder version. A successful provider write is not the acceptance test: the marker must be present in decoded ETL. TraceLogging metadata means no external manifest is required for this event.

### Verification, Troubleshooting, and Cleanup

Require the marker payload and zero reported loss; a decoder without appropriate TraceLogging support is an unverified-decoder failure, not proof no event was emitted. If execution is interrupted or stop fails, use the exact printed own-session name with `logman.exe query "<printed-own-session-name>" -ets`; only if it exists, `logman.exe stop "<printed-own-session-name>" -ets`. Substitute that exact name, never a system session. Normally the program stops it itself. Delete only scratch source/build artifacts, `marker.etl`, `decoded.xml`, and any report files produced by this invocation of `tracerpt` after inspection. No Event Log/channel cleanup is needed.

Source reviewed, not built/run. Parent must validate MSVC/SDK, trace authorization, actual ETL delivery/decoding and teardown; read-only Event Log queries are separately optional. No throughput/retention guarantees are established by a one-event trace.

- [ ] Local ETW and Event Log exercise: Collect/decode a self-authored benign event and distinguish ETL from channel evidence.
- [ ] Boundary check: Verify own-session teardown and explain loss/retention limits without disabling any collection control.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Windows Roadmap#X1 User-mode Internals|X1 User-mode Internals]]
- [[ETW-TI]]
- [[Detection Engineering]]
- [[ETW and Event Log Security]]

## References

- [About event tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [TraceLogging native quick start](https://learn.microsoft.com/en-us/windows/win32/tracelogging/tracelogging-native-quick-start)
- [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
- [Consuming Windows Event Log events](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)
- [Event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema)
