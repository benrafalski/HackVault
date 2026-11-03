---
title: "Nginx"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Nginx Security]]"
updated: 2026-11-03
---
# Nginx

> [!abstract] TL;DR
> `nginx -t` checks configuration; inspect the effective configuration before reload. Set explicit trusted authorities, request limits, and upstream timeouts.

> [!info] Agent scope
> Server and location matching; reverse proxying; static files; TLS termination; buffering; upstreams; configuration inheritance.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach Nginx request processing at expert configuration/debugging depth. Assume
HTTP, TLS, filesystems and containers. Trace listen/default server, TLS SNI and
Host selection, normalized URI, exact/prefix/regex locations, internal redirects,
root versus alias, and proxy_pass with/without URI. Explain worker/event behavior,
upstream keepalive, buffering, temp files, request/response size limits and timeout
semantics. Show inheritance pitfalls for headers and proxy settings, trusted
forwarded headers and TLS termination. Use complete loopback configurations and
request matrices with expected edge/origin paths. Distinguish nginx -t from routing
tests, and nginx -T from a full effective-policy proof. Cite nginx.org and label
version differences, especially HTTP/2 and header inheritance. No exploit payloads.
```

## Cheatsheet

### Selection and Mapping

| Stage | Rule | Diagnostic |
|---|---|---|
| Listener | Address/port select candidates; default belongs to listener | `default_server` is not a special server name |
| TLS | SNI influences certificate/context before HTTP headers | Host cannot repair a wrong certificate selection |
| Host | Match configured names; otherwise listener default | Explicit rejection default avoids accidental first-site service |
| Location | Exact `=` wins; longest prefix remembered; eligible regexes tested in order | `^~` on selected prefix suppresses regex search at that level; nested cases need care |
| Internal redirect | Index, rewrite or `try_files` fallback may restart selection | Final handler may differ from initial location |
| File/proxy | Map using selected directives | Query string is not part of location matching |

Flat mapping examples (fragments, not complete servers):

```nginx
location /static/ { root /srv; }
location /media/ { alias /srv/assets/; }
location /api/ { proxy_pass http://backend/; }
location /raw/ { proxy_pass http://backend; }
```

`/static/a.txt` maps to `/srv/static/a.txt`; `/media/a.txt` to `/srv/assets/a.txt`. `/api/items?q=1` becomes `/items?q=1` upstream, while `/raw/items?q=1` keeps `/raw/items?q=1`. URI-bearing `proxy_pass` replaces the matched normalized prefix; regex/named locations and variable-based targets have different restrictions. Avoid assuming a trailing slash is cosmetic. `$request_uri` preserves original URI plus arguments; `$uri` is normalized/current and can change on internal redirect.

### Proxy Work and Inheritance

`proxy_request_buffering on` receives the body before forwarding; `proxy_buffering on` decouples upstream response reads from slow clients and may spill to disk. Streaming/SSE may need response buffering off and app flushing, but then upstream resources remain tied to slow clients. Body buffers are not size limits: use `client_max_body_size`. Bound temp storage as well.

`proxy_connect_timeout` bounds connection establishment; `proxy_read_timeout` is between successive upstream reads, not a total request deadline. Add application deadlines. Upstream keepalive is a reusable idle-connection cache per worker, not a global concurrency cap. Configure HTTP/1.1 and clear `Connection` when reusing upstream connections. Retry only when method/effect semantics permit it; retries after an uncertain side effect can duplicate work.

Directives merge differently. On the 1.28 lab baseline, child `add_header` directives replace inherited `add_header` sets; use `always` for error statuses where required. `proxy_set_header` inheritance is likewise all-or-none at a level. Newer `add_header_inherit` behavior is version-specific (1.29.3+); do not paste it into 1.28. `nginx -T` prints loaded configuration, not a per-request merged result, and may expose sensitive configuration.

### TLS and Operations

Deployment fragment for Nginx 1.25.1+ with the HTTP/2 module and operator-provisioned certificate/key:

```nginx
listen 443 ssl;
http2 on;
ssl_certificate /etc/nginx/tls/site-chain.pem;
ssl_certificate_key /etc/nginx/tls/site-key.pem;
ssl_protocols TLSv1.2 TLSv1.3;
```

Certificate chain, names, private-key permissions and library support must be checked separately. TLS termination leaves a second origin hop: restrict or authenticate it. HSTS applies only after deliberate HTTPS rollout; do not copy it into a plaintext lab. Record `nginx -V`, validate with `nginx -t`, inspect loaded files with `nginx -T`, then reload and check logs/requests. A successful reload command does not prove new workers adopted the intended routing.

## Gotchas

Configuration syntax validity does not prove routing correctness. An alias location cannot be reasoned about as if it were a root location.

## Labs

### Static and Proxy Path Matrix

**Requirements:** Docker Desktop Linux containers, PowerShell 7, `curl.exe`; image `nginx:1.28.0`. This is a fixed teaching baseline, not a current security-patch recommendation. Create an empty temporary directory containing the files below. The origin is a second real Nginx listener in the same container; it returns its observed URI. Only the edge is published to host loopback. **Container/TLS behavior unverified; this lab does not configure TLS.**

### File: nginx.conf

```nginx
events { worker_connections 128; }
http {
	default_type text/plain;
	log_format trace '$server_port $host "$request" $status "$uri"';
	access_log /dev/stdout trace;
	error_log /dev/stderr notice;
	upstream origin { server 127.0.0.1:8081; keepalive 4; }
	server {
		listen 8080 default_server;
		server_name _;
		return 404;
	}
	server {
		listen 8080;
		server_name lab.test;
		client_max_body_size 1k;
		location = /health { return 200 "edge-ready\n"; }
		location /static/ { root /srv; }
		location /media/ { alias /srv/static/; }
		location = /api { return 308 /api/; }
		location /api/ {
			proxy_http_version 1.1;
			proxy_set_header Connection "";
			proxy_set_header Host origin.test;
			proxy_set_header X-Forwarded-For $remote_addr;
			proxy_set_header X-Forwarded-Proto $scheme;
			proxy_connect_timeout 2s;
			proxy_read_timeout 3s;
			proxy_pass http://origin/;
		}
		location / { return 404; }
	}
	server {
		listen 127.0.0.1:8081;
		server_name origin.test;
		location / { return 200 "origin:$request_uri\n"; }
	}
}
```

### File: static/marker.txt

```text
STATIC-MARKER
```

**Launch/check commands** from that directory (do not reuse a container name already in use):

```powershell
$lab = (Get-Location).Path
docker run --rm --mount "type=bind,source=$lab/nginx.conf,target=/etc/nginx/nginx.conf,readonly" nginx:1.28.0 nginx -t
docker run --detach --name w2-nginx-tech -p 127.0.0.1:18080:8080 --mount "type=bind,source=$lab/nginx.conf,target=/etc/nginx/nginx.conf,readonly" --mount "type=bind,source=$lab/static,target=/srv/static,readonly" nginx:1.28.0
docker exec w2-nginx-tech nginx -V
curl.exe --noproxy "*" -i -H "Host: lab.test" http://127.0.0.1:18080/health
```

**Objective:** predict each mapping and correlate the two access-log entries for a proxy request. **Hint:** `/media/` replaces a prefix; `/static/` appends the whole URI.

```powershell
$base = 'http://127.0.0.1:18080'
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/static/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/media/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/api"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/api/items?q=1"
curl.exe --noproxy "*" -i -H "Host: unknown.test" "$base/health"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/static/missing.txt"
docker logs w2-nginx-tech
```

### Solution and Acceptance

Expected: static and alias requests give `200` with `STATIC-MARKER`; `/api` gives `308`; `/api/items?q=1` gives `200` with `origin:/items?q=1`; unknown host and missing file give `404`. The origin log uses port 8081 and path `/items`; the edge uses 8080 and `/api/items`. No origin port is published. Confirm all rows, not just syntax success.

Change only `proxy_pass http://origin/;` to `proxy_pass http://origin;`, validate and reload using the commands below, then repeat the exact query: expected body becomes `origin:/api/items?q=1`. Restore the slash, validate/reload and confirm the original result. This is a controlled mapping change, not a traversal exercise.

```powershell
docker exec w2-nginx-tech nginx -t
docker exec w2-nginx-tech nginx -s reload
docker logs w2-nginx-tech
```

Troubleshooting: connection refused means container/startup/port trouble; `502` means the origin hop failed; `404` on every request often means the Host header is missing. Bind-mount edits should be visible inside the container; if a host editor replaces a file inode, recreate the container to refresh the mount. Cleanup: `docker rm -f w2-nginx-tech`, then remove only the temporary files. Images may be retained for later labs.

- [ ] Local Nginx exercise: Configure a loopback static location and a reverse-proxied toy API. Run `nginx -t`, request known and missing paths, and compare edge/origin logs for trailing-slash variants.
- [ ] Boundary check: Try harmless dot-segment and trailing-slash variants against the isolated static/proxy setup. Verify all resolved paths remain inside the intended resource boundary.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Nginx Security]]

## References

- [Request processing and selection](https://nginx.org/en/docs/http/request_processing.html)
- [Proxy module and URI mapping](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [Header inheritance](https://nginx.org/en/docs/http/ngx_http_headers_module.html)

- [Official documentation or primary training reference](https://nginx.org/en/docs/http/ngx_http_core_module.html)
