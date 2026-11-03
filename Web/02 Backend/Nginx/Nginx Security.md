---
title: "Nginx Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Nginx]]"
updated: 2026-11-03
---
# Nginx Security

> [!abstract] TL;DR
> Path-mapping mistakes, exposed internal locations, untrusted forwarded headers, and edge/origin parsing differences can bypass intended routing controls.

> [!info] Agent scope
> Security of: Server and location matching; reverse proxying; static files; TLS termination; buffering; upstreams; configuration inheritance. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Path-mapping mistakes, exposed internal locations, untrusted forwarded headers, and edge/origin parsing differences can bypass intended routing controls.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach defensive Nginx configuration review at expert depth. Assume HTTP/TLS and
basic Nginx knowledge. Trace authority, normalized path, location selection,
internal redirect, filesystem mapping and upstream request construction. Explain
unknown-host defaults, root/alias boundaries, internal locations, trusted forwarded
headers, direct-origin exposure, TLS termination and inherited security headers.
Distinguish body limits from buffers, idle timeouts from total deadlines, and
rate limits from application quotas. Supply a complete local config and benign
request matrix with baseline failure, repair and positive controls. Show useful
edge/origin telemetry and safe configuration rollout. Cite nginx.org, label version
requirements, and exclude payload catalogs, bypass procedures and real targets.
```

## Cheatsheet

### Review Matrix

| Boundary | Root cause | Defensive decision |
|---|---|---|
| Authority | First/default site serves unexpected names | Separate rejecting default on each exposed listener |
| Mapping | Treating alias as root; unintended internal rematch | Simple mappings, dedicated data tree, path/result matrix |
| Private file | URL secrecy treated as access control | Keep outside served tree or use explicit internal delivery policy |
| Origin identity | Client-supplied forwarding headers trusted | Replace at a single edge; trust only configured proxy peers |
| Upload/content | Data directory inherits execution route | Static-only mapping, no interpreter handoff, read-only service access |
| Headers | Child header set shadows parent set | Check success and error paths on the deployed version |
| Capacity | Buffers/timeouts mistaken for total limits | Body size, time, disk, concurrency and application budgets |

`internal` rejects direct external requests to a location but permits internal redirects; it is not user authorization. If an application selects an internal download, authorize the record and map it to a server-owned file name first. No user-chosen filesystem paths belong in that decision. Filesystem ACLs and mount layout remain important even when URLs are restricted.

At a single trusted edge use `proxy_set_header X-Forwarded-For $remote_addr`, not an unvalidated client chain. Multi-proxy deployments need an explicit trusted-hop model; configure real-IP rewriting only for known peers, otherwise client-supplied addresses can contaminate access logs and IP quotas. Clear alternate identity headers the origin might interpret. The origin should be unreachable except through the intended boundary, with authenticated transport when the hop is not local.

### Capacity, TLS and Version Notes

`client_max_body_size` limits request body size; `client_body_buffer_size` only controls memory buffering. Response buffering can consume temporary disk. `proxy_read_timeout` and `client_body_timeout` measure idle intervals, not a whole-request deadline. Application cancellation and deadlines remain necessary. Streaming needs bounded application queues and finite lifetime even with proxy buffering off.

`limit_req_zone $binary_remote_addr zone=perip:1m rate=5r/s;` belongs in `http`; `limit_req zone=perip burst=5 nodelay;` belongs in a serving context. Set `limit_req_status 429` deliberately if desired. The default rejection status is 503, and shared NAT addresses make per-IP policy imprecise. Never use a caller-controlled header as an identity key.

Patch Nginx and TLS libraries; validate certificate names/chains and origin trust. Banner suppression is not patching. On 1.28, a child `add_header` set prevents inheritance of the parent set. `always` affects status coverage, not inheritance. Check effective headers after internal redirects too. Newer inheritance directives must not be assumed available on older builds.

## Detection and Defense

Keep routing simple, test root/alias/proxy_pass mappings, reject unknown hosts, and set headers at trusted boundaries. Correlate edge and origin logs and patch protocol implementations.

## Labs

### Independent Static Boundary Lab

**Requirements:** Docker Desktop Linux containers, PowerShell 7 and `curl.exe`; fixed teaching image `nginx:1.28.0`. New temporary directory with all files below. Local synthetic data only. **Runtime and VM behavior unverified.** This exercises actual Nginx mapping and proxying, not a configuration parser substitute.

### File: nginx.conf

```nginx
events { worker_connections 128; }
http {
	default_type text/plain;
	access_log /dev/stdout;
	error_log /dev/stderr notice;
	server {
		listen 8080 default_server;
		server_name _;
		return 404;
	}
	server {
		listen 8080;
		server_name lab.test;
		client_max_body_size 1k;
		add_header X-Content-Type-Options nosniff always;
		location /public/ {
			root /srv;
			deny all;
			limit_except GET { deny all; }
		}
		location /private/ { internal; root /srv; }
		location = /proxy {
			proxy_set_header Host origin.test;
			proxy_set_header X-Forwarded-For $remote_addr;
			proxy_set_header X-Forwarded-Proto $scheme;
			proxy_set_header Forwarded "";
			proxy_set_header X-User "";
			proxy_pass http://127.0.0.1:8081/;
		}
		location / { return 404; }
	}
	server {
		listen 127.0.0.1:8081;
		server_name origin.test;
		location / {
			add_header X-Lab-Forwarded-For $http_x_forwarded_for always;
			add_header X-Lab-Proto $http_x_forwarded_proto always;
			return 200 "ORIGIN-MARKER\n";
		}
	}
}
```

### File: public/marker.txt

```text
PUBLIC-MARKER
```

### File: private/marker.txt

```text
PRIVATE-MARKER
```

**Setup and baseline:**

```powershell
$lab = (Get-Location).Path
docker run --rm --mount "type=bind,source=$lab/nginx.conf,target=/etc/nginx/nginx.conf,readonly" nginx:1.28.0 nginx -t
docker run --detach --name w2-nginx-security -p 127.0.0.1:18081:8080 --mount "type=bind,source=$lab/nginx.conf,target=/etc/nginx/nginx.conf,readonly" --mount "type=bind,source=$lab/public,target=/srv/public,readonly" --mount "type=bind,source=$lab/private,target=/srv/private,readonly" nginx:1.28.0
curl.exe --noproxy "*" -i -H "Host: lab.test" http://127.0.0.1:18081/public/marker.txt
```

**Objective:** repair the unintended denial of public static data without broadening private access or allowed methods. Baseline expected: `403` for the public marker. **Hint:** only the unconditional `deny all` is defective; the `limit_except` denial is intentional. GET permission also permits HEAD under Nginx access-method handling.

### Solution and Acceptance

Remove the standalone `deny all;` inside `/public/`, retaining `limit_except GET { deny all; }`. Validate and reload, then run this bounded matrix:

```powershell
docker exec w2-nginx-security nginx -t
docker exec w2-nginx-security nginx -s reload
$base = 'http://127.0.0.1:18081'
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/public/marker.txt"
curl.exe --noproxy "*" -I -H "Host: lab.test" "$base/public/marker.txt"
curl.exe --noproxy "*" -i -X POST -H "Host: lab.test" "$base/public/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/private/marker.txt"
curl.exe --noproxy "*" -i -H "Host: unknown.test" "$base/public/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/proxy"
docker logs w2-nginx-security
```

Expected after repair: GET `200` with public marker; HEAD `200` without body; POST `403`; direct private and unknown-host requests `404`; proxy `200` with origin marker, one edge-observed address and `X-Lab-Proto: http`. The address can be a Docker gateway address, so do not assert literal `127.0.0.1`. Known-site responses include `nosniff`, including denials. Verify private marker text never appears in returned bodies. These checks do not prove all parsing/path variants or TLS behavior.

Troubleshooting: syntax success does not prove the live mount/reload changed. Recreate this named container if file replacement leaves a stale bind mount. `502` identifies upstream reachability, not policy denial. Restore the baseline line to reproduce `403`, then reapply the fix. Cleanup: `docker rm -f w2-nginx-security`; remove the temporary files after log review. No external targets, uploads or interpreter payloads are used.

- [ ] Local Nginx exercise: Configure a loopback static location and a reverse-proxied toy API. Run `nginx -t`, request known and missing paths, and compare edge/origin logs for trailing-slash variants.
- [ ] Boundary check: Try harmless dot-segment and trailing-slash variants against the isolated static/proxy setup. Verify all resolved paths remain inside the intended resource boundary.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Nginx]]

## References

- [Official documentation or primary training reference](https://nginx.org/en/docs/http/ngx_http_core_module.html)
