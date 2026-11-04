---
title: "PHP and Laravel"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[PHP and Laravel Security]]"
updated: 2026-11-03
---
# PHP and Laravel

> [!abstract] TL;DR
> Use escaped Blade output, policies/gates, validated request data, and bound queries. Keep APP_DEBUG false and .env outside public serving paths.

> [!info] Agent scope
> PHP runtime and request lifecycle; Composer; Laravel routing and middleware; Blade; Eloquent; sessions; deployment.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me PHP 8.3/8.4 and Laravel 12 given HTTP, SQL and object-oriented code.
Trace PHP-FPM request execution, OPcache, Composer PSR-4 autoloading, Laravel
bootstrap/container/providers, routing and middleware, Blade, validation,
Eloquent and response termination. Compare ordinary workers with long-lived
Octane/queue workers. Explain sessions/CSRF, gates/policies, mass assignment,
database transactions, configuration caching and public-directory deployment.
Provide complete runnable files and acceptance checks, including validation,
rollback, escaped output and owner authorization. Use official PHP/Laravel
sources and version-specific APIs; label unexecuted expectations. Teach here,
not through note-writing or external-scaffold instructions.
```

## Cheatsheet

### Runtime and Request Lifecycle

PHP-FPM maintains worker processes but ordinary request variables are recreated per request. OPcache reuses compiled bytecode, not arbitrary request-local objects. Persistent database connections and extensions can retain resources; PHP memory limits do not bound database work or all native allocations. Long-lived Laravel Octane/queue workers retain application state, so request/user objects must not leak into singletons and deployments need worker restarts.

Composer resolves packages and writes `composer.lock`; `composer install` reproduces the lock, while `update` changes resolution. PSR-4 maps namespace prefixes to source directories; `vendor/autoload.php` installs the autoloader. Package scripts/plugins execute code during installation, so review provenance and allowed plugins. `strict_types=1` controls scalar coercion for relevant PHP calls, not HTTP input validation. Superglobals and JSON still require explicit shape/type checks.

Laravel's front controller loads autoloading and the application, bootstrap loads configuration/providers, the HTTP kernel builds a middleware pipeline, the router matches a route, binding resolves parameters/models, and the response unwinds middleware. In Laravel 11/12 the streamlined application builder configures middleware/routes in bootstrap rather than requiring older tutorial Kernel files. Providers register bindings before booting cross-service behavior. Avoid database work in provider registration.

### Routing, Eloquent and Transactions

| Mechanism | Correct use | Edge case |
|---|---|---|
| `web` middleware | Sessions, cookie handling and CSRF for browser forms | `api` routes do not automatically share the same session semantics. Authentication choice must be explicit. |
| Route-model binding | Resolve model existence from a path identifier | It does not generally authorize the current user. Scoped nested bindings are not a replacement for policies. |
| FormRequest/Validator | Use validated fields and deliberate error responses | Browser failures commonly redirect with flashed errors; JSON clients usually receive 422. Unknown fields may be excluded rather than rejected. |
| Eloquent `$fillable` | Allowlist attributes passed to `fill/create/update` on a model | Direct property assignment and query-builder updates have different behavior. Fillable is not an authorization policy. |
| Blade `{{ $value }}` | Escaped HTML output | `{!! $value !!}` opts out. Templates are trusted source code, not user-provided strings. |
| Query binding | Values bound through query builder/ORM | Raw expressions and dynamic SQL identifiers need separate allowlists. |

```php
DB::transaction(function () use ($profileId, $userId, $name) {
	$changed = Profile::whereKey($profileId)->where('owner_id', $userId)
		->update(['display_name' => $name]);
	abort_unless($changed === 1, 404);
});
```

This fragment couples owner selection and mutation. Use database constraints for uniqueness and `lockForUpdate` inside a transaction when a read-modify-write invariant needs locking on a supporting engine. A queued notification should dispatch after commit; durable exactly-once effects need idempotency/outbox design. Do not send external requests while holding row locks.

### Configuration and Deployment

Serve only `public`, never the repository root. Keep `.env`, vendor, storage internals and application source outside the document root. Configure app URL/key, DEBUG false, HTTPS session cookies, trusted proxies/hosts, body/time limits and least-privilege storage permissions. `config:cache` means runtime code should read `config(...)`, not call `env(...)` throughout the application. Changing environment values requires rebuilding caches/restarting long-lived workers. Do not commit generated configuration containing secrets. Use PHP-FPM with a controlled web server in production, not `php -S`.

## Gotchas

Client-hidden fields are still submit-able. A web server should expose only the application's intended public directory.

## Labs

- [ ] Local PHP and Laravel exercise: Build a form-backed resource with a Laravel policy, request validation, and a bounded fillable field list. Verify invalid data and unauthorized updates fail.
- [ ] Boundary check: Submit an extra synthetic role field to a profile update and verify it is ignored or rejected. Confirm a markup marker renders as text and .env is not served.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. PHP 8.3 or 8.4 with mbstring, OpenSSL, PDO_SQLite, tokenizer, XML/DOM, ctype and fileinfo; Composer 2; supported patched Laravel 12.x. This is a deliberately small, explicit Laravel bootstrap, not a generated application. Install resolves a Composer lockfile; retain it. All data/keys are synthetic and local. Create the directories implied by file headings.

### File: composer.json

```json
{"require":{"php":"^8.3","laravel/framework":"^12.0"},"config":{"allow-plugins":false}}
```

### File: bootstrap/providers.php

```php
<?php
return [];
```

### File: lab.php

```php
<?php
declare(strict_types=1);
require __DIR__.'/vendor/autoload.php';

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

foreach (['bootstrap/cache', 'storage/framework/views', 'storage/framework/sessions',
	'storage/logs'] as $directory) {
	if (!is_dir(__DIR__.'/'.$directory)) mkdir(__DIR__.'/'.$directory, 0700, true);
}
if (!file_exists(__DIR__.'/storage/lab.sqlite')) touch(__DIR__.'/storage/lab.sqlite');

class Profile extends Model {
	public $timestamps = false;
	protected $fillable = ['display_name'];
	protected $casts = ['owner_id' => 'integer'];
}

$app = Application::configure(basePath: __DIR__)->withRouting(using: function () {
	Route::middleware('web')->group(function () {
		Route::get('/', function () {
			return view('profile', ['profile' => Profile::findOrFail(1)]);
		});
		Route::post('/profile', function (Request $request) {
			$user = new GenericUser(['id' => getenv('LAB_USER') === 'bob' ? 2 : 1]);
			$profile = Profile::findOrFail(1);
			Gate::forUser($user)->authorize('edit-profile', $profile);
			$data = $request->validate(['display_name' => 'required|string|max:40', 'role' => 'prohibited']);
			DB::transaction(function () use ($profile, $user, $data) {
				$changed = Profile::whereKey($profile->id)->where('owner_id', $user->id)
					->update(['display_name' => $data['display_name']]);
				abort_unless($changed === 1, 404);
			});
			return redirect('/', 303);
		});
	});
})->create();
$app->make(Kernel::class)->bootstrap();
$app['config']->set([
	'app.env' => 'local', 'app.debug' => false,
	'app.key' => 'base64:'.base64_encode(str_repeat('L', 32)), 'app.cipher' => 'AES-256-CBC',
	'database.default' => 'sqlite', 'database.connections.sqlite' => [
		'driver' => 'sqlite', 'database' => __DIR__.'/storage/lab.sqlite', 'prefix' => '', 'foreign_key_constraints' => true],
	'view.paths' => [__DIR__.'/resources/views'], 'view.compiled' => __DIR__.'/storage/framework/views',
	'session.driver' => 'file', 'session.files' => __DIR__.'/storage/framework/sessions',
	'session.cookie' => 'lab_session', 'session.lifetime' => 30, 'session.path' => '/',
	'session.http_only' => true, 'session.same_site' => 'lax', 'session.secure' => false,
	'cache.default' => 'array', 'cache.stores.array' => ['driver' => 'array'],
	'logging.default' => 'single', 'logging.channels.single' => [
		'driver' => 'single', 'path' => __DIR__.'/storage/logs/laravel.log', 'level' => 'warning'],
]);
Gate::define('edit-profile', fn (GenericUser $user, Profile $profile) => $user->id === $profile->owner_id);
if (!Schema::hasTable('profiles')) {
	Schema::create('profiles', function (Blueprint $table) {
		$table->id(); $table->integer('owner_id'); $table->string('display_name');
	});
	DB::table('profiles')->insert(['id' => 1, 'owner_id' => 1, 'display_name' => 'synthetic']);
}
return $app;
```

### File: public/index.php

```php
<?php
$app = require dirname(__DIR__).'/lab.php';
$app->handleRequest(Illuminate\Http\Request::capture());
```

### File: resources/views/profile.blade.php

```html
<!doctype html>
<html lang="en"><title>Profile</title><body>
<p>{{ $profile->display_name }}</p>
<form method="post" action="/profile">@csrf
<input name="display_name" maxlength="40" required>
<button type="submit">Save</button></form></body></html>
```

### Objectives and Commands

Run `composer install`, then `php -S 127.0.0.1:8000 -t public public/index.php`. The bootstrap creates only the documented local storage/cache directories and SQLite file. Open `http://127.0.0.1:8000/`; submit `<b>literal</b>`. Inspect the POST (303) and displayed escaped text. This form edits a public synthetic profile; `LAB_USER` is a server-side fixture selector, not authentication. Stop and set PowerShell `$env:LAB_USER='bob'` (POSIX `export LAB_USER=bob`), restart, reload the form and confirm its POST returns 403.

### Hints and Separate Solution

Blade renders the token and escapes the display name. The gate checks owner before mutation; the UPDATE repeats the predicate to bind the write to policy. For validation, send `Accept: application/json` with a valid browser form submission and an empty name: expected 422. A missing CSRF token is rejected earlier with 419. A harmless extra `role=reader` is prohibited, independent of the model fillable list. The supplied files are the solution; no artisan scaffold is required.

### Verification, Troubleshooting and Reset

Manual smoke commands: `curl.exe -i http://127.0.0.1:8000/` expects 200; `curl.exe -i -X POST http://127.0.0.1:8000/profile -H "Accept: application/json" --data "display_name=reviewed"` expects 419; `curl.exe -i http://127.0.0.1:8000/.env` expects 404 and no configuration contents. These are unexecuted predictions. SQLite driver errors mean PDO_SQLite is missing. Session/token errors require cookies and a freshly loaded form. This local app does not cache configuration; schema creation on request is a teaching convenience and must become migrations in production. Stop Ctrl+C; remove only storage/lab.sqlite and this project's session/view files to reseed. Unset LAB_USER and clear browser cookies. Keep public-directory isolation under a production web server too.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[PHP and Laravel Security]]

## References

- [Laravel 12 lifecycle](https://laravel.com/docs/12.x/lifecycle)
- [Eloquent](https://laravel.com/docs/12.x/eloquent)
- [Database transactions](https://laravel.com/docs/12.x/database#database-transactions)
- [Deployment](https://laravel.com/docs/12.x/deployment)
- [PHP-FPM](https://www.php.net/manual/en/install.fpm.php)
