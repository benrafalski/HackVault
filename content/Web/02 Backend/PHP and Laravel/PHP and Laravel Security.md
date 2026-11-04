---
title: "PHP and Laravel Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[PHP and Laravel]]"
updated: 2026-11-03
---
# PHP and Laravel Security

> [!abstract] TL;DR
> Unsafe unserialize, raw template output, arbitrary mass assignment, and exposed configuration can turn request data into execution or privilege changes.

> [!info] Agent scope
> Security of: PHP runtime and request lifecycle; Composer; Laravel routing and middleware; Blade; Eloquent; sessions; deployment. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unsafe unserialize, raw template output, arbitrary mass assignment, and exposed configuration can turn request data into execution or privilege changes.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive PHP 8.3/8.4 and Laravel 12 security. Explain request parsing,
Composer/autoload trust, unserialize versus JSON, Blade source/data separation,
fillable versus DTO validation, policy/gate authorization, route binding, CSRF,
session rotation and transactional ownership checks. Cover public document root,
configuration caching, debug output, queue workers and least-privilege deployment.
Give complete synthetic-user regression tests that retain permitted updates and
reject unauthorized/extra fields without state changes. No exploitation, privilege
escalation, credential theft or bypass demonstrations. Use public primary sources,
explicit version assumptions and expected rather than fabricated outputs. Teach
here, without asking me to generate missing application files.
```

## Cheatsheet

### Separate the Four Controls

Authentication proves who is calling; a gate/policy decides whether that caller may act on a resource; validation constrains values; assignment/output allowlists constrain which attributes may cross the boundary. None replaces the others. Unsafe review fragment: `$profile->update($request->all())`. Fixed pattern: authorize the profile, validate a named input DTO, then update only `display_name` with an owner predicate in the database statement.

| Surface | Defense and limitation |
|---|---|
| Eloquent mass assignment | `$fillable=['display_name']` protects model fill operations, not direct property writes or raw query updates. `validated()` excludes unruled fields; add `prohibited` rules when rejection matters. |
| Route binding | Resolving a model is not checking its owner. Apply policy after binding or constrain the route's query and still authorize the operation. |
| Serialization | Use `json_decode(..., flags: JSON_THROW_ON_ERROR)` with bounded bytes/depth and a schema. Do not accept native serialized objects from untrusted sources; `allowed_classes` is not a general sandbox. |
| Blade | Use escaped `{{ }}` with fixed source. Raw output requires separately trusted/sanitized HTML. Do not compile user strings as Blade/PHP. |
| Sessions | Regenerate session IDs after authentication, invalidate on logout, Secure/HttpOnly/SameSite cookies, maintained server-side store | 
| CSRF | Keep web middleware and tokens on ambient-cookie writes; Laravel test mode ordinarily skips CSRF verification, so explicitly exercise the real check. |
| Configuration | `APP_DEBUG=false`, strong APP_KEY, public-only document root, no `.env` exposure; config cache artifacts may contain secrets. |

PHP loose comparison/coercion is distinct from authorization: use strict comparisons for identifiers with normalized types. PDO binding handles values, not table/column names. Map sort identifiers to a fixed allowlist. Avoid shell execution and native deserialization for request data. Queue workers and Octane are long-lived; never capture the first request's identity in a singleton.

### Transactions and Version Boundaries

Laravel 12 requires modern PHP (8.2 minimum); this lab selects PHP 8.3/8.4. The Laravel 11/12 bootstrap differs from older Kernel-based skeletons. Authorization policy discovery conventions depend on namespace/model layout; explicitly register policies when the convention is not used. Use transactions and owner-scoped writes, check affected rows, and defer side effects until commit. SQLite tests do not establish row-lock behavior on MySQL/PostgreSQL.

## Detection and Defense

Log policy denials, validation categories, CSRF failures and configuration-access requests without cookies or payloads. Validate production web-root configuration independently of application tests. Trace unexpected worker state retention by request/user correlation IDs, not by dumping sessions. Review Composer lock changes, scripts/plugins and advisories; a passing application suite does not certify third-party package integrity.

## Labs

- [ ] Local PHP and Laravel exercise: Build a form-backed resource with a Laravel policy, request validation, and a bounded fillable field list. Verify invalid data and unauthorized updates fail.
- [ ] Boundary check: Submit an extra synthetic role field to a profile update and verify it is ignored or rejected. Confirm a markup marker renders as text and .env is not served.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. PHP 8.3/8.4 with PDO_SQLite, mbstring, OpenSSL, DOM/XML and standard Laravel extensions; Composer 2. Laravel 12.x, Orchestra Testbench 10.x and PHPUnit 11.5.x are supported dependency lines; retain composer.lock after resolution. Testbench supplies its documented framework test application as a dependency, not an assumed external project. Every authored file follows. The startup command is the in-process PHPUnit harness; no network server is needed.

### File: composer.json

```json
{"require":{"php":"^8.3","laravel/framework":"^12.0"},"require-dev":{"orchestra/testbench":"^10.0","phpunit/phpunit":"^11.5"},"config":{"allow-plugins":false}}
```

### File: phpunit.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="vendor/autoload.php" colors="true">
  <testsuites><testsuite name="policy"><directory>tests</directory></testsuite></testsuites>
</phpunit>
```

### File: tests/ProfileTest.php

```php
<?php
declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;

class Profile extends Model {
	public $timestamps = false;
	protected $fillable = ['display_name'];
	protected $casts = ['owner_id' => 'integer'];
}

class EnforcedCsrf extends VerifyCsrfToken {
	protected function runningUnitTests() { return false; }
}

class ProfilePolicy {
	public function update(GenericUser $user, Profile $profile): bool {
		return $user->id === $profile->owner_id;
	}
}

final class ProfileTest extends TestCase {
	protected function defineEnvironment($app) {
		$app['config']->set('database.default', 'testing');
		$app['config']->set('database.connections.testing', [
			'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
		$app['config']->set('session.driver', 'array');
		$app['config']->set('app.debug', false);
	}

	protected function defineRoutes($router) {
		Route::middleware(['web', EnforcedCsrf::class])->post('/profile/{id}', function (Request $request, int $id) {
			if (!$request->user()) return response()->json(['error' => 'authentication_required'], 401);
			$profile = Profile::findOrFail($id);
			Gate::authorize('update', $profile);
			$data = $request->validate(['display_name' => 'required|string|max:40', 'role' => 'prohibited']);
			DB::transaction(function () use ($profile, $request, $data) {
				$changed = Profile::whereKey($profile->id)->where('owner_id', $request->user()->id)
					->update(['display_name' => $data['display_name']]);
				abort_unless($changed === 1, 404);
			});
			return response()->json(['display_name' => $data['display_name']]);
		});
	}

	protected function setUp(): void {
		parent::setUp();
		Schema::create('profiles', function (Blueprint $table) {
			$table->id(); $table->integer('owner_id'); $table->string('display_name');
		});
		DB::table('profiles')->insert(['id' => 1, 'owner_id' => 1, 'display_name' => 'synthetic']);
		Gate::policy(Profile::class, ProfilePolicy::class);
	}

	private function fixture(int $id): void {
		$this->actingAs(new GenericUser(['id' => $id]));
		$this->withSession(['_token' => 'synthetic-csrf-token']);
	}

	public function test_owner_and_allowed_write(): void {
		$this->fixture(2);
		$this->postJson('/profile/1', ['display_name' => 'reviewed'],
			['X-CSRF-TOKEN' => 'synthetic-csrf-token'])->assertForbidden();
		$this->assertSame('synthetic', Profile::findOrFail(1)->display_name);
		$this->fixture(1);
		$this->postJson('/profile/1', ['display_name' => 'reviewed'],
			['X-CSRF-TOKEN' => 'synthetic-csrf-token'])->assertOk()->assertExactJson(['display_name' => 'reviewed']);
	}

	public function test_csrf_and_privileged_field_rejection(): void {
		$this->fixture(1);
		$this->postJson('/profile/1', ['display_name' => 'reviewed'])->assertStatus(419);
		$this->postJson('/profile/1', ['display_name' => 'reviewed', 'role' => 'reader'],
			['X-CSRF-TOKEN' => 'synthetic-csrf-token'])->assertUnprocessable();
		$this->assertSame('synthetic', Profile::findOrFail(1)->display_name);
		$this->assertSame(1, Profile::findOrFail(1)->owner_id);
	}

	public function test_blade_escapes_data(): void {
		$this->assertSame('&lt;b&gt;literal&lt;/b&gt;',
			Blade::render('{{ $name }}', ['name' => '<b>literal</b>']));
	}
}
```

### Objectives, Baseline and Hints

Run `composer install`, then `php vendor/phpunit/phpunit/phpunit --testdox`. Baseline is one synthetic Alice-owned profile. Verify Bob's denied update leaves its name intact, Alice's permitted update returns only display_name, and missing CSRF/extra role are rejected. Hint: the test-specific CSRF subclass disables only the framework's test-environment shortcut, not token validation. The synthetic identities come from `actingAs`, never public HTTP headers.

### Solution and Fixed Retest

Expected: three passing PHPUnit tests, with 403, 200, 419 and 422 outcomes and escaped markup. The solution layers explicit policy registration, owner-constrained write, validation and DTO serialization. Repeat the same suite after refactoring assignment or routing. The Blade template source in this test is a fixed literal; only its data changes. No vulnerable variant or privilege-change demonstration is included.

### Troubleshooting and Reset

If tests unexpectedly accept a missing token, confirm the route includes EnforcedCsrf rather than relying on Laravel's default unit-test behavior. Missing PDO driver requires enabling PDO_SQLite; do not replace the test with a production database. Framework/Testbench major versions must match (Laravel 12/Testbench 10). Each test application uses a new in-memory database; rerun to reset. Remove the disposable project/vendor directory for cleanup. This suite does not start a web server, so public-root/.env isolation remains an explicit deployment check, not a claimed test result.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[PHP and Laravel]]

## References

- [Laravel authorization](https://laravel.com/docs/12.x/authorization)
- [CSRF](https://laravel.com/docs/12.x/csrf)
- [Validation](https://laravel.com/docs/12.x/validation)
- [Testbench](https://packages.tools/testbench)
- [PHP unserialize warning](https://www.php.net/manual/en/function.unserialize.php)
