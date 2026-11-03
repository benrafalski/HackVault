---
title: "Redis Security"
aliases: []
tags: [web, w3, security]
domain: web
phase: "W3"
type: security
status: draft
pair: "[[Redis]]"
updated: 2026-11-03
---
# Redis Security

> [!abstract] TL;DR
> Exposed Redis, broad command rights, shared key namespaces, and unsafe session caching can disclose data or alter application state.

> [!info] Agent scope
> Security of: Data types; expiration; persistence; pub/sub; ACLs; network exposure; cache and session use. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Exposed Redis, broad command rights, shared key namespaces, and unsafe session caching can disclose data or alter application state.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me Redis 7.4 defensive security assuming cache/session design. Separate
network reachability, ACL command/key/channel permissions and application tenant
authorization. Explain safe session TTLs, invalidation, eviction, persistence-file
protection, pub/sub confidentiality limits and bounded resource use. Build a
local synthetic policy fixture that narrows an overbroad key pattern and removes
unnecessary CONFIG-read permission, with identical denied/allowed retests.
Avoid destructive commands, host operations, theft and escalation. Explain ACL
additive updates, persistence of ACL changes, version caveats and monitoring.
Use primary sources; teach here without edits or invented test evidence.
```

## Cheatsheet

### ACL Design

Start with `-@all` and grant exact commands, key patterns and channel patterns. Categories can broaden as new commands are added across versions. Redis 6 introduced ACLs; Redis 7 added selectors and other finer-grained controls. Inspect the deployed version rather than assuming every syntax exists.

```text
ACL SETUSER reporter reset on >DisposableExamplePassword ~app:7:* resetchannels -@all +get +ttl +ping
ACL DRYRUN reporter GET app:7:session
ACL DRYRUN reporter GET app:8:missing
```

This administrator-only fragment illustrates intent, not a production password policy. ACL SETUSER updates are additive unless reset tokens remove old rules. Adding `~app:7:*` does not remove a prior `~app:*`; use `resetkeys`. Channel `&...` rules do not follow key `~...` rules. ACL DRYRUN evaluates permission without executing the command; runtime tests still need the actual app credentials.

A shared role with access to every tenant prefix cannot enforce which tenant an HTTP request belongs to. Construct prefixes from authenticated context and separate identities where stronger isolation is needed. Logical Redis database numbers are not a robust tenant authorization model, and Redis Cluster supports only database 0.

### Sessions, Memory, and Files

Use a bounded opaque session identifier, a small validated value and atomic `SET key value EX seconds`. Repeated SET without EX can remove the TTL. Cap sliding renewal with an absolute expiry stored in validated session data. On cache miss, require reauthentication or authoritative verification; do not grant default access. Logout/revocation needs a defined invalidation model rather than waiting for incidental eviction.

`maxmemory` and an eviction policy are operational controls, not per-tenant quotas. A permitted SET can still exhaust memory if application key/value counts are unbounded. Limit payloads, TTL range, concurrency and key creation at the service layer. `noeviction` fails writes instead of silently evicting; applications must handle that failure. Some administrative/replication buffers are outside ordinary eviction accounting.

Do not grant CONFIG, ACL management, module loading, replication reconfiguration or broad key enumeration to runtime users. Protect RDB/AOF/backups at the OS layer. ACL files contain credentials or hashes and need operator-only handling. Runtime ACL changes require `ACL SAVE` when an aclfile is configured; otherwise restart can restore old policy.

Use private listeners/firewalls and verified TLS for remote connections. Protected mode is not a complete deployment design. AUTH over plaintext is not confidential. Pub/sub has separate channel ACLs and no durable replay or business acknowledgment; choose a different mechanism when audit/recovery is required.

## Detection and Defense

Review `ACL LOG` for denied commands/keys/channels, and monitor evictions, rejected connections, memory and latency. ACL LOG is bounded operational evidence, not an immutable audit log. Avoid MONITOR in routine production diagnostics because it exposes command data and adds cost. Alert on unexpected ACL/config changes, but distinguish operator maintenance from runtime activity.

## Labs

### Environment and Complete Files

PowerShell, Docker Linux containers and `redis:7.4`; no ports or host mounts. Record actual image/version. **Not executed here.** Only a missing foreign-prefix key is queried; no other tenant data is read. The only administrative command tested is harmless CONFIG GET.

### File: redis.conf
```text
bind 127.0.0.1
protected-mode yes
aclfile /data/users.acl
dir /data
maxmemory 64mb
maxmemory-policy noeviction
```

### File: users.acl
```text
user default off
user operator on >Admin-lab-only-74! ~* &* +@all
user app on >App-lab-only-74! ~app:* resetchannels -@all +get +set +ttl +ping +config|get
```

### File: test.ps1
```powershell
$ErrorActionPreference = 'Stop'
function Invoke-App([string[]]$Command) {
	$reply = & docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-sec redis-cli --raw --user app -e @Command 2>&1
	[pscustomobject]@{ Code = $LASTEXITCODE; Text = ($reply -join "`n") }
}
$allowed = Invoke-App @('SET','app:7:session','synthetic','EX','60')
if ($allowed.Code -ne 0 -or $allowed.Text.Trim() -ne 'OK') { throw 'Allowed SET failed' }
$read = Invoke-App @('GET','app:7:session')
if ($read.Code -ne 0 -or $read.Text.Trim() -ne 'synthetic') { throw 'Allowed GET failed' }
$ttl = Invoke-App @('TTL','app:7:session')
if ($ttl.Code -ne 0 -or [int]$ttl.Text -lt 1 -or [int]$ttl.Text -gt 60) { throw 'TTL contract failed' }
$foreign = Invoke-App @('GET','app:8:missing')
$config = Invoke-App @('CONFIG','GET','maxmemory')
if ($foreign.Text -notmatch 'NOPERM' -or $config.Text -notmatch 'NOPERM') {
	throw "Read-only boundary checks failed: key=$($foreign.Text); config=$($config.Text)"
}
'PASS: own session allowed; foreign key and CONFIG denied'
```

### Baseline and Objectives

```powershell
docker create --name w3-redis-sec redis:7.4 redis-server /tmp/redis.conf
docker cp redis.conf w3-redis-sec:/tmp/redis.conf
docker cp users.acl w3-redis-sec:/data/users.acl
docker start w3-redis-sec
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-sec redis-cli --user app -e PING
pwsh -NoProfile -File ./test.ps1
```

Retry PING manually. Baseline fails the boundary assertion: the broad key rule permits the missing-key read and CONFIG GET succeeds. Objective: remove these capabilities while preserving session writes/reads and TTL. Hint: adding a narrower pattern alone leaves the broad pattern active.

### Solution and Fixed Retest

```powershell
docker exec -e REDISCLI_AUTH=Admin-lab-only-74! w3-redis-sec redis-cli --user operator -e ACL SETUSER app resetkeys '~app:7:*' '-config'
pwsh -NoProfile -File ./test.ps1
docker exec -e REDISCLI_AUTH=Admin-lab-only-74! w3-redis-sec redis-cli --user operator -e ACL LOG 10
docker exec -e REDISCLI_AUTH=Admin-lab-only-74! w3-redis-sec redis-cli --user operator -e ACL SAVE
docker restart w3-redis-sec
pwsh -NoProfile -File ./test.ps1
```

Expected fixed/restart runs pass; both denials contain NOPERM, own session remains usable and TTL is within 1..60 seconds. ACL LOG records denied categories. Retry readiness if restart has not finished. A connection error, NOAUTH or wrong password is not a passing denial.

### Troubleshooting and Cleanup

If ACL SAVE fails, inspect the container ACL-file permissions rather than changing host permissions. Do not copy the baseline ACL file back after the fix. Passwords in docker exec are visible to local operators and are acceptable only for these disposable fixtures. Remove just this container:

```powershell
docker rm -f -v w3-redis-sec
```

- [ ] Local Redis exercise: Store a synthetic session with an expiry, observe TTL changes, and test a restricted ACL user against allowed and denied key prefixes.
- [ ] Boundary check: Attempt to read a different synthetic tenant's prefix and run a denied administrative command with the app ACL user; both should fail.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Redis]]

## References

- [Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
- [ACL guide](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/)
- [ACL DRYRUN](https://redis.io/docs/latest/commands/acl-dryrun/)
