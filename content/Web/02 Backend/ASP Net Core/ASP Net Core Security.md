---
title: "ASP.NET Core Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[ASP Net Core]]"
updated: 2026-11-03
---
# ASP.NET Core Security

> [!abstract] TL;DR
> Missing endpoint authorization, overposting, unsafe deserialization, and misconfigured proxy or key trust can expose data despite framework protections.

> [!info] Agent scope
> Security of: Hosting; middleware order; routing; minimal APIs and controllers; binding; authorization; dependency injection; configuration. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Missing endpoint authorization, overposting, unsafe deserialization, and misconfigured proxy or key trust can expose data despite framework protections.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive ASP.NET Core 10 security given C#, HTTP and claims identity.
Explain authentication schemes, challenges versus forbids, fallback/endpoint/
resource policies, middleware order, binding/validation and DTO serialization.
Cover Data Protection key-ring trust, cookies/CSRF versus bearer APIs, proxy trust,
configuration precedence, dependency lifetimes, transactions and Problem Details.
Provide complete local synthetic-principal tests for anonymous, wrong-role,
wrong-owner, malformed/extra-field and permitted requests, with no identity
selected by public request data. No exploitation, escalation, credential theft,
evasion or bypass demonstrations. Use public Microsoft sources and explicit
version assumptions; label unexecuted outcomes. Teach here without file editing.
```

## Cheatsheet

### Identity, Policy and Resource Boundaries

Authentication handlers produce a ClaimsPrincipal from a verified mechanism. Authorization evaluates requirements against that principal and optionally a resource. Challenge means authentication is required (normally 401 for an API); forbid means an authenticated identity lacks permission (normally 403). Cookie schemes historically redirected; .NET 10 changes behavior for recognized API endpoints toward 401/403. Test the actual scheme/endpoint metadata instead of assuming all clients see JSON.

An endpoint's role policy cannot establish ownership of an object loaded later. Use `IAuthorizationService.AuthorizeAsync(user, resource, policy)` or owner-constrained repository operations. Missing/non-owned resources may consistently return 404 to avoid disclosing existence. Keep authorization and mutation atomic through a write predicate/version check or transaction; checking a mutable owner and later writing without that predicate creates a race.

| Boundary | Defense | Limit |
|---|---|---|
| DTO binding | Immutable input DTO, explicit validation and unmapped-field handling | Ignored fields are not necessarily an error; decide contract intentionally. Never bind EF entities directly. |
| Serialization | Explicit output DTO; no polymorphic type resolution from untrusted names | JSON output is not HTML sanitization and does not authorize data. |
| Middleware | Routing before policy evaluation; authentication before authorization | UI redirects or custom early middleware are not a substitute for endpoint metadata and resource checks. |
| Cookies | HTTPS Secure/HttpOnly/SameSite, antiforgery on ambient-cookie writes | HttpOnly does not stop CSRF. CORS is not authentication. |
| Bearer | Validate signature, issuer, audience, lifetime and permitted algorithms | Parsing a JWT is not validating it; accepting a user-supplied role is not verification. |
| Forwarded headers | Known proxies/networks, controlled stripping/replacement | Recent servicing releases tightened unknown-proxy behavior; do not restore broad trust merely to fix redirects. |
| Data Protection | Protect key ring at rest, restrict readers, persist/share intentionally across replicas, set application isolation | Anyone with appropriate keys can act within that protection domain. Key deletion can invalidate sessions/data. |

Unsafe review fragment: `db.Update(requestBoundEntity)` persists whatever was bound and ignores object policy. Fixed shape: authorize a resource, validate a named input DTO, update only an allowed field with an owner/version predicate, return a minimal response DTO. Use scoped DbContext/services; never retain HttpContext or scoped dependencies in a singleton.

### Errors and Operational Configuration

Register Problem Details, production exception middleware and status-code pages; never return raw exception messages or configuration values. Use explicit known domain mappings. .NET 10 handled-exception diagnostic suppression differs from earlier releases, so verify audit/telemetry intentionally. OpenAPI may expose route/schema information; restrict its deployment separately from API authentication. Use startup option validation and least-privilege hosting identity. Development user secrets and debug pages are not production secret/error controls.

## Detection and Defense

Record scheme, policy name, bounded correlation ID and outcome; keep tokens/cookies/body data out of logs. Track challenge/forbid/not-found rates without assuming every missing resource is hostile. Test proxy/header behavior through deployed ingress and test key sharing/rotation across replicas. A loopback fixture suite does not establish either operational property.

## Labs

- [ ] Local ASP Net Core exercise: Build a small typed API with GET and POST, validation, an ownership policy, and Problem Details. Test 400, 401/403, 404, and successful creation including its Location header.
- [ ] Boundary check: Invoke a protected endpoint directly with the wrong synthetic user and an extra privileged field. Verify denial and that response DTOs exclude dummy internal data.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. .NET 10 SDK and PowerShell 7. Packages are pinned to 10.0.0 as an API baseline; select current 10.0 servicing packages for deployment and retest. The fixture authentication handler selects only a startup environment identity. It must never be deployed or converted into a trusted public identity header. No real credentials or external services are used.

### File: Lab.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings><GenerateDocumentationFile>true</GenerateDocumentationFile></PropertyGroup>
  <ItemGroup>
	<PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="10.0.0" />
	<PackageReference Include="Microsoft.Extensions.Validation" Version="10.0.0" />
  </ItemGroup>
</Project>
```

### File: Program.cs

```csharp
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddValidation();
builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(options =>
{
	options.SerializerOptions.PropertyNameCaseInsensitive = false;
	options.SerializerOptions.NumberHandling = JsonNumberHandling.Strict;
	options.SerializerOptions.AllowDuplicateProperties = false;
	options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
	options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.Services.AddAuthentication("Fixture")
	.AddScheme<AuthenticationSchemeOptions, FixtureHandler>("Fixture", _ => { });
builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("writer", policy => policy.RequireAuthenticatedUser().RequireRole("writer"));
	options.AddPolicy("owner", policy => policy.RequireAssertion(context =>
		context.Resource is StoredNote note && context.User.Identity?.Name == note.Owner));
});
builder.Services.AddScoped<INoteService, NoteService>();
var app = builder.Build();
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
if (app.Environment.IsDevelopment()) app.MapOpenApi();
app.MapNotes();
app.Run();

internal sealed class FixtureHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
	protected override Task<AuthenticateResult> HandleAuthenticateAsync()
	{
		var user = Environment.GetEnvironmentVariable("LAB_USER");
		if (user is not ("alice" or "bob" or "viewer")) return Task.FromResult(AuthenticateResult.NoResult());
		var claims = new[] { new Claim(ClaimTypes.Name, user),
			new Claim(ClaimTypes.Role, user == "viewer" ? "reader" : "writer") };
		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
		return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
	}
}

/// <summary>Permitted text for an edit preview.</summary>
public sealed record PreviewNoteRequest
{
	[Required, StringLength(80, MinimumLength = 1)]
	public required string Text { get; init; }
}
/// <summary>Public preview result without owner or internal fields.</summary>
public sealed record NoteResponse(int Id, string Text);
internal sealed record StoredNote(int Id, string Owner, string Internal);

internal interface INoteService
{
	Task<NoteResponse?> PreviewAsync(int id, PreviewNoteRequest request,
		ClaimsPrincipal principal, CancellationToken cancellationToken);
}
internal sealed class NoteService(IAuthorizationService authorization) : INoteService
{
	public async Task<NoteResponse?> PreviewAsync(int id, PreviewNoteRequest request,
		ClaimsPrincipal principal, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (id != 1) return null;
		var note = new StoredNote(1, "alice", "DUMMY_INTERNAL_ONLY");
		var result = await authorization.AuthorizeAsync(principal, note, "owner");
		cancellationToken.ThrowIfCancellationRequested();
		return result.Succeeded ? new NoteResponse(id, request.Text.Trim()) : null;
	}
}
internal static class NoteEndpoints
{
	public static void MapNotes(this WebApplication app)
	{
		app.MapPost("/notes/{id:int}/preview", async Task<Results<Ok<NoteResponse>, ProblemHttpResult>> (
			int id, PreviewNoteRequest request, ClaimsPrincipal principal,
			INoteService service, CancellationToken cancellationToken) =>
		{
			var result = await service.PreviewAsync(id, request, principal, cancellationToken);
			return result is null ? TypedResults.Problem(statusCode: 404, title: "Not Found") : TypedResults.Ok(result);
		}).RequireAuthorization("writer").WithName("PreviewNote")
			.WithSummary("Validate a synthetic owner's edit")
			.WithDescription("Checks role and ownership; returns a DTO without persisting changes.")
			.ProducesValidationProblem().ProducesProblem(401).ProducesProblem(403).ProducesProblem(404);
	}
}
```

### File: requests.http

```http
@baseUrl = http://127.0.0.1:5081

### Permitted or denied according to startup fixture
POST {{baseUrl}}/notes/1/preview
Content-Type: application/json

{"text":"reviewed"}

### Unknown input field
POST {{baseUrl}}/notes/1/preview
Content-Type: application/json

{"text":"reviewed","owner":"alice"}

### Missing resource
POST {{baseUrl}}/notes/999/preview
Content-Type: application/json

{"text":"reviewed"}
```

### File: check.ps1

```powershell
param([ValidateSet('anonymous','alice','bob','viewer')][string]$User = 'anonymous')
$ErrorActionPreference = 'Stop'
$expected = @{ anonymous = 401; alice = 200; bob = 404; viewer = 403 }[$User]
$base = 'http://127.0.0.1:5081'
$response = Invoke-WebRequest "$base/notes/1/preview" -Method Post -ContentType 'application/json' -Body '{"text":"reviewed"}' -SkipHttpErrorCheck
if ($response.StatusCode -ne $expected) { throw "Expected $expected, got $($response.StatusCode)" }
if ($response.Content.Contains('DUMMY_INTERNAL_ONLY') -or $response.Content.Contains('"owner"')) { throw 'Unexpected internal field' }
if ($User -eq 'alice') {
	$dto = $response.Content | ConvertFrom-Json
	if ($dto.id -ne 1 -or $dto.text -ne 'reviewed') { throw 'Wrong DTO' }
	foreach ($body in @('{"text":""}', '{"text":"reviewed","owner":"alice"}')) {
		$invalid = Invoke-WebRequest "$base/notes/1/preview" -Method Post -ContentType 'application/json' -Body $body -SkipHttpErrorCheck
		if ($invalid.StatusCode -ne 400) { throw 'Expected validation/binding 400' }
	}
	$missing = Invoke-WebRequest "$base/notes/999/preview" -Method Post -ContentType 'application/json' -Body '{"text":"reviewed"}' -SkipHttpErrorCheck
	if ($missing.StatusCode -ne 404) { throw 'Expected missing resource' }
} else {
	if (($response.Content | ConvertFrom-Json).status -ne $expected) { throw 'Expected Problem Details status' }
}
"$User checks passed"
```

### Objectives and Commands

Run `dotnet restore`, `dotnet build`. Set `$env:ASPNETCORE_ENVIRONMENT='Development'`, `$env:LAB_USER='alice'`, then `dotnet run --no-launch-profile --urls http://127.0.0.1:5081`. In another terminal run `pwsh -NoProfile -File ./check.ps1 -User alice`. Stop/restart the server for each fixture: LAB_USER bob, viewer, then unset with `Remove-Item Env:LAB_USER -ErrorAction SilentlyContinue`; run the script with the matching User value (anonymous when unset). No request header selects a principal.

### Hints and Separate Solution

Role policy runs before the handler, owner policy after resource construction. `AuthorizeAsync` has no CancellationToken overload; cancellation is checked around it and forwarded to downstream APIs that support it. Expected cases: Alice 200; Bob (writer, wrong owner) 404; viewer 403; anonymous 401; Alice invalid/unknown fields 400. Public output contains only id/text. The supplied solution is a nonpersistent edit preview, not a privilege-changing application.

### Verification, Troubleshooting and Reset

Inspect `/openapi/v1.json` in Development for the documented POST/statuses. If all identities behave alike, restart after changing LAB_USER and confirm the script label matches server configuration. Missing Problem Details can indicate status-code pages were omitted or a handler wrote a body first. These checks are unexecuted and exercise fixture policy, not production credential validation. Stop Ctrl+C, unset both environment variables, remove bin/obj if needed. No persistent data exists. TLS, key-ring sharing, real authentication and database race behavior require separate integration checks.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[ASP Net Core]]

## References

- [Resource authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased?view=aspnetcore-10.0)
- [Authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-10.0)
- [Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction?view=aspnetcore-10.0)
- [Proxy configuration](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0)
