---
title: "Redis"
aliases: []
tags: [web, w3]
domain: web
phase: "W3"
type: tech
status: draft
pair: "[[Redis Security]]"
updated: 2026-11-03
---
# Redis

> [!abstract] TL;DR
> Bound TTL and value sizes; use atomic operations or appropriate transactions/scripts for invariants. Keep administrative commands out of runtime roles.

> [!info] Agent scope
> Data types; expiration; persistence; pub/sub; ACLs; network exposure; cache and session use.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Redis 7.4 application engineering assuming web sessions and basic data
structures. Explain strings, hashes, lists, sets, sorted sets, streams, expiration,
eviction, memory overhead, atomic commands, MULTI/EXEC, WATCH and scripts. Contrast
RDB/AOF durability, replication, cache-aside consistency and pub/sub loss. Cover
session TTL, invalidation, key namespaces, ACL commands/keys/channels and transport
security. Build a complete local restricted-user lab with TTL, transactions,
persistence and pub/sub observations. Explain failure cases and version-sensitive
features using Redis primary sources. Teach here without editing or invented runs.
```

## Cheatsheet

### Data Structures and Boundaries

| Type | Typical operation | Design constraint |
|---|---|---|
| String | `SET app:7:session value EX 60 NX` | Atomic value+expiry; cap value size. NX is conditional creation, not durable lock ownership by itself. |
| Hash | `HSET app:7:profile name Ada` | Partial field updates; key TTL semantics differ from newer per-field expiry features. |
| List | `LPUSH` / `BRPOP` | Blocking work distribution alone lacks durable acknowledgment semantics. |
| Set | `SADD` / `SISMEMBER` | Unordered uniqueness; huge membership scans still cost work. |
| Sorted set | `ZADD` / `ZRANGE` | Score-ordered leaderboards/time indexes; use explicit bounded ranges. |
| Stream | `XADD` / `XREADGROUP` / `XACK` | Retained messages and pending entries; reclaim/retry and idempotency remain application work. |

Most ordinary commands execute atomically in the server's command execution path, but client read/modify/write sequences do not. `INCR` is atomic; GET then SET is not. Multi-key operations in Redis Cluster need compatible hash slots, often via `{tag}` key hash tags. A naming prefix is organization, not access control without ACL key patterns.

### Transactions and Expiry

```text
MULTI
INCR app:7:counter
EXPIRE app:7:counter 120
EXEC
```

MULTI queues commands; EXEC executes them without interleaving from other clients. Redis transactions do not roll back earlier successful commands if a later command fails at execution time. WATCH provides optimistic conflict detection; a null EXEC result means retry the bounded whole operation. Scripts can combine conditional logic atomically, but long scripts block work and need strict bounds.

`TTL`: positive seconds remaining, `-1` no expiry, `-2` missing. SET normally replaces an existing TTL unless an expiry or KEEPTTL is specified; field updates such as HSET do not automatically refresh the key TTL. Use atomic `SET ... EX` instead of SET then EXPIRE where a crash could leave an immortal session. Sliding sessions also need an absolute maximum lifetime enforced by the application.

Expiry removes keys according to time; eviction removes keys under memory pressure according to `maxmemory-policy`. Neither is a reliable authorization-revocation mechanism. Cache misses must not become authorization bypasses. Cache-aside writes can race with refill; use versioned values or an invalidation design that tolerates stale entries.

### Durability and Messaging

RDB is point-in-time snapshots; AOF records writes, with fsync policy determining the durability/performance tradeoff. `appendfsync everysec` commonly leaves a recent-loss window; persistence is not an acknowledgment of a business transaction in another database. Replication is asynchronous, and WAIT does not turn Redis into a strongly consistent database. Test recovery, backup integrity and eviction behavior for the actual deployment.

Pub/sub is at-most-once delivery with no replay for disconnected subscribers. Publish return values count matching subscribers, not completed business work. Streams or a dedicated durable broker fit acknowledged jobs better. ACL channel patterns (`&prefix:*`) are distinct from key patterns (`~prefix:*`).

Keep Redis on a private network with verified TLS for remote clients. Protected mode is a safety mechanism, not a substitute for ACLs/firewalls. Withhold configuration, module, replication and broad key enumeration commands from runtime accounts. Persistence files contain application data and need separate filesystem/backup protection.

## Gotchas

Cache expiry is not authorization. Redis pub/sub messages are not replayed to disconnected subscribers.

## Labs

### Environment and Complete Files

PowerShell, Docker Linux containers and official `redis:7.4`; record image digest and server INFO as administrator. **Not executed here.** No port publication or host mounts. Bootstrap admin is distinct from app; passwords below are disposable fixtures.

### File: redis.conf
```text
bind 127.0.0.1
protected-mode yes
port 6379
dir /data
aclfile /data/users.acl
appendonly yes
appendfsync everysec
maxmemory 64mb
maxmemory-policy noeviction
```

### File: users.acl
```text
user default off
user operator on >Admin-lab-only-74! ~* &* +@all
user app on >App-lab-only-74! ~app:7:* &app:7:* -@all +ping +get +set +ttl +hset +hgetall +incr +multi +exec +expire +publish +subscribe
```

### File: transaction.txt
```text
MULTI
INCR app:7:counter
INCR app:7:counter
EXEC
```

```powershell
docker create --name w3-redis-tech redis:7.4 redis-server /tmp/redis.conf
docker cp redis.conf w3-redis-tech:/tmp/redis.conf
docker cp users.acl w3-redis-tech:/data/users.acl
docker start w3-redis-tech
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e PING
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e SET app:7:session synthetic EX 60
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e TTL app:7:session
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e HSET app:7:profile name Ada
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e HGETALL app:7:profile
Get-Content -Raw transaction.txt | docker exec -i -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e
docker restart w3-redis-tech
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e GET app:7:counter
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e GET app:8:missing
```

Retry PING manually until ready. In a separate terminal, subscribe:

```powershell
docker exec -it -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app SUBSCRIBE app:7:events
```

In the original terminal publish, stop the subscriber with Ctrl+C, and publish again:

```powershell
docker exec -e REDISCLI_AUTH=App-lab-only-74! w3-redis-tech redis-cli --user app -e PUBLISH app:7:events synthetic
```

### Objectives, Hints, and Solution

Observe TTL decline by repeating TTL manually; after expiry it becomes `-2`. The counter transaction returns `1,2`; graceful restart retains `2` through AOF. This proves normal restart recovery, not crash/fsync guarantees. GET on another prefix must return NOPERM. With one active subscriber, publish returns `1`; after disconnect it returns `0`, and reconnecting does not replay the missed message. Hint: the nonexpiring counter is deliberate persistence data, not a session example.

### Verification, Troubleshooting, and Cleanup

Use `-e` to request failing redis-cli exits on command errors and inspect replies as well as `$LASTEXITCODE`. AOF setup errors often mean an unwritable container data directory. Repeated transactions increment again; reset for a repeatable initial state. Stop the subscriber, then remove only this fixture:

```powershell
docker rm -f -v w3-redis-tech
```

- [ ] Local Redis exercise: Store a synthetic session with an expiry, observe TTL changes, and test a restricted ACL user against allowed and denied key prefixes.
- [ ] Boundary check: Attempt to read a different synthetic tenant's prefix and run a denied administrative command with the app ACL user; both should fail.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W3 Data|W3 Data]]
- [[Redis Security]]

## References

- [Transactions](https://redis.io/docs/latest/develop/interact/transactions/)
- [Persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
- [Pub/sub](https://redis.io/docs/latest/develop/pubsub/)
- [ACLs](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/)
