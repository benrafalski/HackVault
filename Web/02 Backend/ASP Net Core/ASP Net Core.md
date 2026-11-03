---
title: "ASP.NET Core"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[ASP Net Core Security]]"
updated: 2026-11-03
---
# ASP.NET Core

> [!abstract] TL;DR
> Authenticate the caller, authorize the resource, validate the model, then perform the operation. Never trust arbitrary forwarded headers or expose development exception pages in production.

> [!info] Agent scope
> Hosting; middleware order; routing; minimal APIs and controllers; binding; authorization; dependency injection; configuration.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me ASP.NET Core 10 given C#, tasks, HTTP and SQL. Trace host/Kestrel startup,
configuration providers, DI scopes, ordered middleware, routing, authentication,
authorization, minimal API binding/validation, endpoint execution and response
serialization. Compare controllers/[ApiController] with minimal APIs and .NET 8/9/10
validation/OpenAPI behavior. Cover cancellation, Problem Details, resource policies,
transactions, Data Protection, proxy trust, graceful shutdown and singleton safety.
Provide complete projects, HTTP requests and deterministic acceptance scripts;
explain failure paths and expected statuses using primary Microsoft sources.
Teach here without editing instructions or claiming unexecuted checks passed.
```

## Cheatsheet

### Hosting and Middleware

`WebApplication.CreateBuilder` builds configuration, logging and DI; `Build` creates the host/application pipeline; `Run` starts Kestrel and waits for shutdown. Appsettings, environment-specific settings, development user secrets, environment variables and command-line arguments can override earlier sources. Configuration values are not automatically validated: bind options and validate on startup for required URLs, limits and secrets. Development user secrets are not a production secret store.

Middleware wraps the next delegate; response work unwinds in reverse order. A representative explicit order is trusted forwarded headers, exception handling/HSTS as appropriate, HTTPS redirection, routing, CORS if used, authentication, authorization, then endpoints. Forwarded headers must be processed before consumers of scheme/address but trusted only from configured proxies. Minimal hosting can insert routing/auth middleware automatically; explicit placement is preferable when other middleware depends on them.

Kestrel owns connection/protocol handling; a reverse proxy may add its own limits. Cancellation binds to `RequestAborted`, but downstream work stops only if it observes the token. Do not block on `.Result`/`.Wait()` or wrap asynchronous I/O in `Task.Run`. Background jobs need independent DI scopes and durable scheduling when required; do not capture HttpContext after the response.

### DI, Binding and Contracts

| Concern | Mechanism and trap |
|---|---|
| Singleton | One instance per container; shared mutable state needs synchronization. Never capture scoped DbContext in it. |
| Scoped | Usually one instance per HTTP request; good for units of work. It is not automatically a database transaction. |
| Transient | New resolution each time; container still owns disposal of instances it creates. Avoid resolving disposables from the root repeatedly. |
| Minimal API | Parameters bind from route/query/body/services by convention and explicit attributes. JSON parsing precedes handler execution; validation is a separate step. |
| Controller | `[ApiController]` provides automatic model-state 400 responses and binding conventions. Controller filters are not minimal endpoint filters. |
| Validation | .NET 10 minimal APIs opt into `AddValidation`; .NET 8/9 need explicit validation/filter/library. Attributes alone are insufficient there. |
| Response | `TypedResults` plus explicit `Results<T1,T2>` preserve response metadata; POST creation includes Location, not just 200. |

Use separate immutable request/response DTOs. JSON Web defaults differ from strict parsing: decide property casing, unmapped properties, numeric strings and duplicates as a contract. This new .NET 10 lab chooses strict behavior; do not silently retrofit it into a compatible existing API. For enums use string conversion intentionally. Use DateTimeOffset for externally visible timestamps.

### Transactions, Errors and Version Boundaries

Services own data access and DTO mapping. A single EF Core SaveChanges normally uses a transaction for its changes; multiple saves/SQL statements may require an explicit transaction, correct retry strategy and optimistic concurrency handling. Do not serialize tracked entities or hold a transaction over external network calls. Authorization and mutation must share an owner/version predicate or locking boundary.

`AddProblemDetails` registers a writer; exception middleware and status-code pages produce consistent generic errors. Map known domain errors deliberately and log internal exceptions without returning stacks/messages. .NET 10 changes diagnostics behavior for handled exceptions; explicitly record required audit/diagnostic events instead of relying on old defaults.

ASP.NET Core 9+ offers built-in OpenAPI generation through the Microsoft.AspNetCore.OpenApi package and `AddOpenApi`/`MapOpenApi`; a documentation UI is separate. This lab maps the document only in Development. .NET 10 validation uses Microsoft.Extensions.Validation. ASP.NET Core 8 deployments use different validation/OpenAPI setup; do not mix package major versions.

## Gotchas

Authentication establishes identity; authorization establishes permission. Anti-forgery requirements differ between cookie-authenticated browser flows and bearer-token APIs.

## Labs

- [ ] Local ASP Net Core exercise: Build a small typed API with GET and POST, validation, an ownership policy, and Problem Details. Test 400, 401/403, 404, and successful creation including its Location header.
- [ ] Boundary check: Invoke a protected endpoint directly with the wrong synthetic user and an extra privileged field. Verify denial and that response DTOs exclude dummy internal data.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. .NET 10 SDK with a current servicing patch, PowerShell 7 for the check script. Package versions 10.0.0 are explicit API-baseline teaching pins, not a current security-patch claim; update within 10.0 servicing before deployment and rerun checks. No database or authentication provider is needed for this public job-creation exercise. Object policy has an independent complete lab in [[ASP Net Core Security]].

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
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddValidation();
builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(options =>
{
	options.SerializerOptions.PropertyNameCaseInsensitive = false;
	options.SerializerOptions.NumberHandling = JsonNumberHandling.Strict;
	options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
	options.SerializerOptions.AllowDuplicateProperties = false;
	options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.Services.AddSingleton<IJobService, JobService>();
var app = builder.Build();
app.UseExceptionHandler();
app.UseStatusCodePages();
if (app.Environment.IsDevelopment()) app.MapOpenApi();
app.MapJobs();
app.Run();

/// <summary>Input for a local job.</summary>
public sealed record CreateJobRequest
{
	[Required, StringLength(40, MinimumLength = 1)]
	public required string Name { get; init; }
}

/// <summary>Public job representation.</summary>
public sealed record JobResponse(Guid Id, string Name, DateTimeOffset CreatedAt);

internal interface IJobService
{
	Task<JobResponse> CreateAsync(CreateJobRequest request, CancellationToken cancellationToken);
	Task<JobResponse?> GetAsync(Guid id, CancellationToken cancellationToken);
}

internal sealed class JobService : IJobService
{
	private readonly ConcurrentDictionary<Guid, JobResponse> jobs = new();
	public Task<JobResponse> CreateAsync(CreateJobRequest request, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var job = new JobResponse(Guid.NewGuid(), request.Name.Trim(), DateTimeOffset.UtcNow);
		jobs[job.Id] = job;
		return Task.FromResult(job);
	}
	public Task<JobResponse?> GetAsync(Guid id, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return Task.FromResult(jobs.GetValueOrDefault(id));
	}
}

internal static class JobEndpoints
{
	public static void MapJobs(this WebApplication app)
	{
		app.MapPost("/jobs", async Task<Created<JobResponse>> (
			CreateJobRequest request, IJobService service, CancellationToken cancellationToken) =>
		{
			var job = await service.CreateAsync(request, cancellationToken);
			return TypedResults.Created($"/jobs/{job.Id}", job);
		}).WithName("CreateJob").WithSummary("Create a local job")
			.WithDescription("Validates a name and returns the created job location.")
			.ProducesValidationProblem();
		app.MapGet("/jobs/{id:guid}", async Task<Results<Ok<JobResponse>, ProblemHttpResult>> (
			Guid id, IJobService service, CancellationToken cancellationToken) =>
		{
			var job = await service.GetAsync(id, cancellationToken);
			return job is null ? TypedResults.Problem(statusCode: 404, title: "Not Found") : TypedResults.Ok(job);
		}).WithName("GetJob").WithSummary("Read a local job")
			.WithDescription("Returns the public DTO or a 404 Problem Details response.")
			.ProducesProblem(404);
	}
}
```

### File: requests.http

```http
@baseUrl = http://127.0.0.1:5080

### Create
POST {{baseUrl}}/jobs
Content-Type: application/json

{"name":"synthetic"}

### Missing resource
GET {{baseUrl}}/jobs/00000000-0000-0000-0000-000000000001

### Invalid input
POST {{baseUrl}}/jobs
Content-Type: application/json

{"name":""}

### Development document
GET {{baseUrl}}/openapi/v1.json
```

### File: check.ps1

```powershell
$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:5080'
$created = Invoke-WebRequest "$base/jobs" -Method Post -ContentType 'application/json' -Body '{"name":"synthetic"}' -SkipHttpErrorCheck
if ($created.StatusCode -ne 201) { throw 'Expected 201' }
$location = [string]$created.Headers.Location[0]
if (-not $location.StartsWith('/jobs/')) { throw 'Missing Location' }
$read = Invoke-WebRequest "$base$location" -SkipHttpErrorCheck
if ($read.StatusCode -ne 200 -or ($read.Content | ConvertFrom-Json).name -ne 'synthetic') { throw 'Read mismatch' }
foreach ($body in @('{"name":""}', '{"name":"ok","owner":"alice"}', '{"name":"a","name":"b"}')) {
	$result = Invoke-WebRequest "$base/jobs" -Method Post -ContentType 'application/json' -Body $body -SkipHttpErrorCheck
	if ($result.StatusCode -ne 400) { throw "Expected 400: $body" }
}
$missing = Invoke-WebRequest "$base/jobs/00000000-0000-0000-0000-000000000001" -SkipHttpErrorCheck
if ($missing.StatusCode -ne 404 -or ($missing.Content | ConvertFrom-Json).status -ne 404) { throw 'Expected 404 problem' }
$document = Invoke-RestMethod "$base/openapi/v1.json"
if (-not $document.paths.'/jobs') { throw 'Missing OpenAPI path' }
'All job checks passed'
```

### Objectives and Commands

Run `dotnet restore`, `dotnet build`; set PowerShell `$env:ASPNETCORE_ENVIRONMENT='Development'`, then `dotnet run --no-launch-profile --urls http://127.0.0.1:5080`. In another PowerShell 7 terminal run `pwsh -NoProfile -File ./check.ps1`. POSIX environment syntax is `ASPNETCORE_ENVIRONMENT=Development dotnet run --no-launch-profile --urls http://127.0.0.1:5080`. The HTTP file is optional editor-client documentation; the script needs no REST extension.

### Hints and Separate Solution

`AddValidation` supplies the validation filter; a parser error may occur before it. DTO JSON names are camelCase and case-sensitive here. The service is singleton only because its process-local store is thread-safe. Expected checks: 201/Location, 200 read, three 400 rejections, 404 Problem Details, and an OpenAPI paths entry; final script line `All job checks passed`. This is predicted, not executed. The complete files implement the solution.

### Troubleshooting and Reset

SDK mismatch produces a target-framework error; use .NET 10, not just a runtime. Package/API major mismatch can hide AddValidation or duplicate-property options. OpenAPI is absent outside Development by design. Occupied port: choose a different loopback port and update both the HTTP file and script. Stop Ctrl+C; all jobs disappear. Remove bin/obj for a clean build. HTTP/no-auth and the in-memory service are local exercise limits, not deployment guidance.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[ASP Net Core Security]]

## References

- [Middleware](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-10.0)
- [Minimal APIs](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/minimal-apis/?view=aspnetcore-10.0)
- [OpenAPI](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/openapi/overview?view=aspnetcore-10.0)
- [Error handling](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling?view=aspnetcore-10.0)
