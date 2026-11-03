---
title: "Apache"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Apache Security]]"
updated: 2026-11-03
---
# Apache

> [!abstract] TL;DR
> Use `apachectl configtest` or the platform equivalent; inspect loaded modules and effective virtual hosts. Disable unneeded overrides and directory listings.

> [!info] Agent scope
> Virtual hosts; modules; directory configuration; rewrites; proxying; authentication; file mapping.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach Apache HTTP Server 2.4 at expert configuration/debugging depth. Assume HTTP,
TLS, filesystem permissions and containers. Trace IP/port and name-based virtual
host selection, URL-to-file translation, authorization, handler selection and logs.
Explain MPM/module roles, Directory/Files/Location merge order, .htaccess delegation,
Options, AllowOverride, rewrites in server versus directory context, aliases and
reverse proxies. Compare authentication providers with authorization and OS ACLs.
Build a complete loopback configuration and request matrix with static, aliased,
rewritten, denied and proxied content. Explain configtest/-S/-M limits, TLS SNI and
safe reloads. Cite official 2.4 documentation and version caveats. Use synthetic
fixtures, no execution payloads, confidential data or production targets.
```

## Cheatsheet

### Selection, Modules and Namespaces

Apache first chooses the best address/port virtual-host set, then matches `ServerName`/`ServerAlias`; the first virtual host in that set is the default for unmatched names. TLS certificate selection occurs before the HTTP request using SNI. `ServerName` does not itself enforce an authority allowlist. Inspect `httpd -S` and exercise unexpected names.

The MPM controls process/thread/connection scheduling. Event MPM reduces idle keepalive thread occupation; it does not make blocking application handlers free. Modules implement authentication, authorization, rewriting, MIME mapping, proxying and execution. Load only required modules; a missing required security module should fail configuration, not disappear behind `<IfModule>`.

| Container/directive | Namespace | Important behavior |
|---|---|---|
| `<Directory>` | Filesystem tree | Use for actual disk resource protection; shortest-to-longest merge |
| `<Files>` / `<FilesMatch>` | Filename | Combine with Directory when directory-specific |
| `<Location>` | URL space | Suitable for proxy/module endpoints; not a replacement for filesystem protection |
| `Alias` | URL to another directory | Grant intended destination policy explicitly |
| `AllowOverride None` | Directory delegation | Prevent `.htaccess` policy/handler changes |
| `Options None` | Directory features | Disables indexes/CGI/includes and symlink following unless separately enabled |

Broad merge sequence: non-regex Directory plus permitted `.htaccess`, regex Directory, Files, Location, then If. Modules define how their directives merge. A later broad Location authorization rule can replace filesystem restrictions. Includes behave as if inserted at their inclusion point; only the selected virtual host participates. Use 2.4 `Require`, not mixed legacy `Order`/`Allow`/`Deny` semantics from `mod_access_compat`.

### Rewrites, Proxying and Authentication

In server context rewrite patterns see a URL path with a leading slash; per-directory patterns see the directory prefix removed. `[L]` ends that rule pass; `[END]` (2.4) also stops later per-directory rewriting. Internal redirects may invoke further processing. Prefer a simple `Alias` or `Redirect` when a regex rewrite is unnecessary.

Reverse-proxy fragment, requiring `mod_proxy` and `mod_proxy_http`:

```apache
ProxyRequests Off
ProxyPass "/api/" "http://127.0.0.1:8081/" connectiontimeout=2 timeout=5
ProxyPassReverse "/api/" "http://127.0.0.1:8081/"
```

Pair trailing slashes. More specific mappings/exclusions precede general mappings. `ProxyPassReverse` rewrites selected response headers such as Location, not arbitrary HTML links or all cookie attributes. `ProxyPreserveHost` changes the upstream authority contract; choose deliberately. Forward proxies and reverse proxies are different roles: leave `ProxyRequests Off` unless explicitly building a controlled forward proxy.

Authentication proves identity; `Require valid-user`, `Require user`, or provider-specific rules authorize. Basic authentication encodes credentials, it does not encrypt them; use TLS outside loopback synthetic labs. OS permissions are a separate gate: `Require all granted` cannot make an unreadable file readable. Application object ownership is still an application responsibility.

### Operations and Version Caveats

`httpd -t` checks syntax; `httpd -M` lists modules; `httpd -S` shows virtual hosts. None proves the request-to-file policy. Distribution wrappers (`apachectl`, `apache2ctl`) set environment paths; don't mix packaged and upstream binary assumptions. `httpd -k graceful` reloads while existing requests finish; verify startup/error logs and the new request matrix. Rewrite escaping/security behavior has changed across 2.4 patches; review release/security notes rather than adding permissive compatibility flags blindly.

## Gotchas

Filesystem permissions and HTTP authorization are separate checks. A Location rule and a Directory rule do not necessarily describe the same resources.

## Labs

### Filesystem and URL Mapping

**Requirements:** Docker Desktop Linux containers, PowerShell 7, `curl.exe`; fixed baseline `httpd:2.4.63` (not a current patch recommendation). Create a temporary directory with all files below. The proxy origin is another listener in the same actual Apache process. **Container behavior unverified; TLS/authentication providers are not exercised here.**

### File: httpd.conf

```apache
ServerRoot "/usr/local/apache2"
ServerName localhost
Listen 8080
Listen 127.0.0.1:8081
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule dir_module modules/mod_dir.so
LoadModule mime_module modules/mod_mime.so
LoadModule alias_module modules/mod_alias.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule log_config_module modules/mod_log_config.so
User daemon
Group daemon
TypesConfig conf/mime.types
ErrorLog /proc/self/fd/2
LogFormat "%v %p %r %>s" trace
CustomLog /proc/self/fd/1 trace
ProxyRequests Off
<Directory />
	AllowOverride None
	Require all denied
</Directory>
<VirtualHost *:8080>
	ServerName reject.test
	<Location />
		Require all denied
	</Location>
</VirtualHost>
<VirtualHost *:8080>
	ServerName lab.test
	DocumentRoot /srv/public
	<Directory /srv/public>
		Options None
		AllowOverride None
		Require all granted
	</Directory>
	<Directory /srv/public/private>
		Require all denied
	</Directory>
	Alias /media/ /srv/media/
	<Directory /srv/media>
		Options None
		AllowOverride None
		Require all granted
	</Directory>
	RewriteEngine On
	RewriteRule ^/?legacy$ /marker.txt [PT,L]
	RewriteRule ^/?private-marker$ /private/marker.txt [PT,L]
	ProxyPass /api/ http://127.0.0.1:8081/ connectiontimeout=2 timeout=5
	ProxyPassReverse /api/ http://127.0.0.1:8081/
</VirtualHost>
<VirtualHost 127.0.0.1:8081>
	ServerName origin.test
	DocumentRoot /srv/origin
	<Directory /srv/origin>
		Options None
		AllowOverride None
		Require all granted
	</Directory>
</VirtualHost>
```

### File: public/marker.txt

```text
PUBLIC-MARKER
```

### File: public/private/marker.txt

```text
PRIVATE-MARKER
```

### File: media/marker.txt

```text
MEDIA-MARKER
```

### File: origin/marker.txt

```text
ORIGIN-MARKER
```

```powershell
$lab = (Get-Location).Path
docker run --rm --mount "type=bind,source=$lab/httpd.conf,target=/usr/local/apache2/conf/httpd.conf,readonly" httpd:2.4.63 httpd -t
docker run --detach --name w2-apache-tech -p 127.0.0.1:18082:8080 --mount "type=bind,source=$lab/httpd.conf,target=/usr/local/apache2/conf/httpd.conf,readonly" --mount "type=bind,source=$lab,target=/srv,readonly" httpd:2.4.63
docker exec w2-apache-tech httpd -M
docker exec w2-apache-tech httpd -S
$base = 'http://127.0.0.1:18082'
foreach ($path in @('/marker.txt','/legacy','/media/marker.txt','/api/marker.txt','/private/marker.txt','/private-marker','/missing.txt')) {
	curl.exe --noproxy "*" -i -H "Host: lab.test" "$base$path"
}
curl.exe --noproxy "*" -i -H "Host: unknown.test" "$base/marker.txt"
docker logs w2-apache-tech
```

**Objective:** map each response to the selected virtual host, physical file or upstream. **Hint:** both private URLs converge on a filesystem policy; the alias needs its own Directory grant.

### Solution and Acceptance

Expected rows in order: `200 PUBLIC`, `200 PUBLIC`, `200 MEDIA`, `200 ORIGIN`, `403`, `403`, `404`; unknown Host gives `403`. Marker labels above abbreviate the complete fixture text. The proxy request appears at both ports in logs. No private marker may appear in any body.

To study mapping repair, change `/legacy`'s target to `/missing.txt`: expected `404`. Restore `/marker.txt`, then validate/reload and repeat for `200`:

```powershell
docker exec w2-apache-tech httpd -t
docker exec w2-apache-tech httpd -k graceful
```

Troubleshooting: missing directive means a module/load problem; file `403` can also mean permissions; proxy `503` commonly means origin connection failure. Check logs before changing access policy. Recreate this container if host file replacement leaves a stale mount. Reset uses the printed configuration. Cleanup: `docker rm -f w2-apache-tech`, then remove only the temporary directory.

- [ ] Local Apache exercise: Create a local virtual host with a static directory and denied private subdirectory. Validate configuration and test direct, rewritten, and missing paths.
- [ ] Boundary check: Upload a harmless text file to a nonexecuting lab media directory and verify it remains data regardless of its extension. Confirm private paths stay denied after rewriting.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Apache Security]]

## References

- [Configuration sections and merging](https://httpd.apache.org/docs/2.4/sections.html)
- [Virtual-host matching](https://httpd.apache.org/docs/2.4/vhosts/details.html)
- [mod_proxy](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html)
- [mod_rewrite](https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html)
