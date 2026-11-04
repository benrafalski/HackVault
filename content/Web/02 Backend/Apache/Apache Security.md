---
title: "Apache Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Apache]]"
updated: 2026-11-03
---
# Apache Security

> [!abstract] TL;DR
> Overbroad overrides, unsafe handler mappings, rewrite mistakes, and permissive proxy configuration can expose files or execute uploaded content.

> [!info] Agent scope
> Security of: Virtual hosts; modules; directory configuration; rewrites; proxying; authentication; file mapping. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Overbroad overrides, unsafe handler mappings, rewrite mistakes, and permissive proxy configuration can expose files or execute uploaded content.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach defensive Apache HTTP Server 2.4 review at expert depth. Assume HTTP,
filesystem permissions, containers and ordinary Apache configuration knowledge.
Trace virtual hosts, aliases/rewrites, Directory/Files/Location merging,
authentication providers, Require policy and handler selection. Explain why
AllowOverride delegation, broad Location grants, inherited handlers and proxy
settings can contradict the intended policy. Build a complete benign loopback
lab with synthetic authentication, private-file denial and static media handling,
an over-restrictive baseline and concrete repair. Include positive controls,
configtest/-M/-S, logging and reset. Cite primary docs, distinguish 2.4 from legacy
2.2 semantics, and exclude executable payloads, bypasses and production targets.
```

## Cheatsheet

### Configuration Controls

| Surface | Root cause | Review/fix |
|---|---|---|
| Virtual host | Unmatched names reach first site | Rejecting default per address/port; test Host and TLS SNI separately |
| Directory policy | URL and filesystem rules confused | Protect real files in Directory/Files; review aliases and symlinks |
| Delegation | Writable content changes policy via `.htaccess` | `AllowOverride None`; narrowly delegate only necessary directives |
| Handler | Uploaded data inherits execution mapping | Separate static tree/service, no interpreters, explicit static handler |
| Rewrites | Remapping changes the policy/handler context | Check direct and rewritten resource paths after every change |
| Proxy | Reverse-proxy setup accidentally enables forward proxy | `ProxyRequests Off`, fixed upstreams, restricted origin |
| Diagnostics | Status/config detail exposed publicly | Restrict diagnostics and logs; never expose configuration backups |

`Options -ExecCGI` alone is not a universal nonexecution policy: module handlers such as PHP/FastCGI can have separate dispatch rules. Remove unnecessary modules and execution mappings, then force static handling only for a dedicated data tree. `ForceType text/plain` controls content type, not execution by itself. `SetHandler default-handler` selects core static handling in the lab; absence of interpreter modules provides a second independent constraint.

### Authorization and Merge Behavior

Use `Require` from 2.4 authorization modules. Multiple requirements may be combined with `<RequireAll>`/`<RequireAny>`; a negated requirement cannot independently grant access. `AuthMerging` affects how authorization sections combine; do not assume all inherited requirements accumulate. Broad later Location rules can supersede earlier Directory authorization. Keep file permissions in filesystem sections, with no global Location grant that undoes them.

Basic authentication proves possession of a password but exposes a reversible encoding unless TLS protects transport. Password hashes belong outside document roots with restricted filesystem rights. Application ownership remains separate from `Require valid-user`. Shared server identities can read any site data their OS permissions allow; configure worker identities/ACLs deliberately.

Do not hide required security directives behind optional `<IfModule>` blocks: losing a module should fail closed at startup. Review loaded modules, MPM choice, upload/service accounts, writable directories and include-file ownership. `ServerTokens Prod` and `ServerSignature Off` reduce details, not vulnerability exposure. Patch according to Apache advisories; rewrite/escaping behavior is patch-sensitive.

## Detection and Defense

Minimize modules, separate executable and upload directories, restrict AllowOverride, and define explicit access policies. Monitor handler changes, unexpected listings, and denied path variants.

## Labs

### Independent Static and Authentication Boundary

**Requirements:** Docker Desktop Linux containers, PowerShell 7, `curl.exe`; `httpd:2.4.63` teaching baseline. Temporary directory with files below. The only password is public synthetic fixture `fixture-only`. Never reuse it or expose this plaintext lab beyond loopback. **Runtime behavior unverified.**

### File: httpd.conf

```apache
ServerRoot /usr/local/apache2
ServerName localhost
Listen 8080
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule alias_module modules/mod_alias.so
LoadModule log_config_module modules/mod_log_config.so
User daemon
Group daemon
ErrorLog /proc/self/fd/2
LogFormat "%v %r %>s %u" audit
CustomLog /proc/self/fd/1 audit
ServerTokens Prod
ServerSignature Off
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
		SetHandler default-handler
		ForceType text/plain
		Require all denied
	</Directory>
	<Directory /srv/public/private>
		Require all denied
	</Directory>
	<Directory /srv/public/member>
		AuthType Basic
		AuthName "Synthetic lab"
		AuthBasicProvider file
		AuthUserFile /srv/auth/users
		Require user student
	</Directory>
	Alias /media/ /srv/media/
	<Directory /srv/media>
		Options None
		AllowOverride None
		SetHandler default-handler
		ForceType text/plain
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

### File: public/member/marker.txt

```text
MEMBER-MARKER
```

### File: media/marker.cgi

```text
DATA-ONLY-MARKER
```

Generate the required password-hash fixture and launch from this directory. The generation command contains only the explicitly public lab password, never a real secret.

```powershell
New-Item -ItemType Directory -Force auth | Out-Null
docker run --rm httpd:2.4.63 htpasswd -nbB student fixture-only | Set-Content -Encoding ascii auth/users
$lab = (Get-Location).Path
docker run --rm --mount "type=bind,source=$lab/httpd.conf,target=/usr/local/apache2/conf/httpd.conf,readonly" httpd:2.4.63 httpd -t
docker run --detach --name w2-apache-security -p 127.0.0.1:18083:8080 --mount "type=bind,source=$lab/httpd.conf,target=/usr/local/apache2/conf/httpd.conf,readonly" --mount "type=bind,source=$lab,target=/srv,readonly" httpd:2.4.63
curl.exe --noproxy "*" -i -H "Host: lab.test" http://127.0.0.1:18083/marker.txt
```

**Objective:** repair only public access and preserve private denial, authentication and static media behavior. Baseline expected: public marker is incorrectly `403`. **Hint:** edit the exact `/srv/public` section, not the root, private or member sections.

### Solution and Acceptance

Change only `/srv/public`'s `Require all denied` to `Require all granted`. Validate/reload and run:

```powershell
docker exec w2-apache-security httpd -t
docker exec w2-apache-security httpd -k graceful
docker exec w2-apache-security httpd -M
$base = 'http://127.0.0.1:18083'
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/private/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/member/marker.txt"
curl.exe --noproxy "*" -i -u student:fixture-only -H "Host: lab.test" "$base/member/marker.txt"
curl.exe --noproxy "*" -i -H "Host: lab.test" "$base/media/marker.cgi"
curl.exe --noproxy "*" -i -H "Host: unknown.test" "$base/marker.txt"
docker logs w2-apache-security
```

Expected: public `200`; private `403`; unauthenticated member `401` with Basic challenge; fixture-authenticated member `200`; media `200`, `Content-Type: text/plain`, and unchanged `DATA-ONLY-MARKER`; unknown host `403`. Module listing must contain no CGI, PHP or FastCGI execution module. The marker has no executable syntax: its extension does not determine execution. This lab stages a media file directly and does not implement an upload endpoint.

Troubleshooting: member `500` can indicate unreadable/missing password file; inspect error logs. `401` with fixture credentials suggests hash generation/encoding or account mismatch. Don't repair failures with a global grant. Restore printed configuration for baseline reset. Cleanup: `docker rm -f w2-apache-security`, then remove the temporary directory/hash file. TLS, external identity providers and application ownership remain separate integration checks.

- [ ] Local Apache exercise: Create a local virtual host with a static directory and denied private subdirectory. Validate configuration and test direct, rewritten, and missing paths.
- [ ] Boundary check: Upload a harmless text file to a nonexecuting lab media directory and verify it remains data regardless of its extension. Confirm private paths stay denied after rewriting.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Apache]]

## References

- [Official documentation or primary training reference](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
