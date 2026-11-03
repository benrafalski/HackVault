---
title: "Java and Spring"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Java and Spring Security]]"
updated: 2026-11-03
---
# Java and Spring

> [!abstract] TL;DR
> Use DTOs rather than binding directly to privileged persistence entities. Expose only required Actuator endpoints and keep detailed errors out of public responses.

> [!info] Agent scope
> JVM web applications; Spring Boot; dependency injection; MVC; binding; Spring Security; build and deployment.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Java 21 and Spring Boot 3.5 MVC given Java, SQL and HTTP. Trace JVM
class loading/JIT/GC, embedded servlet container, security filters, DispatcherServlet,
handler mapping, argument resolution, validation, service call and JSON conversion.
Explain constructor DI, bean scopes, proxy-based transactions/method security,
DTO binding, exception advice, configuration precedence, Actuator and deployment.
Contrast MVC/WebFlux, platform/virtual threads and Boot 2 javax versus Boot 3
jakarta APIs; identify Boot 4 migration assumptions rather than mixing examples.
Provide complete Maven projects, MockMvc checks and expected HTTP semantics,
including owner checks and transactional failure behavior. Use public primary
sources and label unexecuted examples. Teach here without editing instructions.
```

## Cheatsheet

### Runtime and Dispatch

The JVM loads/verifies classes, interprets and JIT-compiles hot paths, and garbage-collects heap objects. Warm-up, allocation rate and GC pauses affect latency; a larger heap does not fix leaked references. Java 21 virtual threads can improve blocking-I/O concurrency, but do not increase CPU capacity or database connection counts. Thread-local request/security state and library behavior must be checked when changing execution models.

Spring Boot performs classpath/configuration-driven auto-configuration; user beans often cause defaults to back off. Constructor injection makes required dependencies explicit. Singleton is the default bean scope: controllers/services must not keep mutable per-request identity in fields. Request-scoped proxies resolve against the active request. Avoid manually constructing a service that is supposed to receive transactional/security proxies.

Servlet filters wrap DispatcherServlet. Spring Security's FilterChainProxy selects the first matching SecurityFilterChain, then DispatcherServlet resolves the handler, binds inputs, validates, invokes the controller and writes through message converters. An MVC interceptor is not a substitute for the security filter chain. MVC with blocking JDBC and WebFlux with reactive drivers have different execution contracts; a reactive return type alone does not make blocking persistence safe on event-loop threads.

### Binding, Errors and Transactions

| Mechanism | Required decision |
|---|---|
| `@RequestBody` | Jackson parses JSON into a DTO. Choose unknown-field behavior explicitly; never bind privileged persistence entities directly. |
| `@Valid` | Bean Validation runs when its integration is installed. `@NotBlank`, `@Size`, `@Min` express constraints, not authorization. Boot 3 uses `jakarta.validation`. |
| `@PathVariable` | Syntax conversion errors normally become 400; valid IDs still need existence and ownership checks. |
| `@RestControllerAdvice` | Map domain exceptions to deliberate statuses/ProblemDetail without exposing database errors. Preserve framework validation/method errors. |
| `@Transactional` | Normally proxy-based around externally invoked methods. Self-invocation bypasses the proxy; unchecked exceptions roll back by default, checked exceptions require explicit rules when desired. |
| Lazy entities | Access after a transaction can fail or trigger hidden queries through Open Session in View. Prefer service-owned queries and DTO mapping; avoid serializing ORM graphs. |

Service-level invariant example: begin transaction, lock/reserve inventory, insert reservation with unique idempotency key, commit; publish through an outbox. Catching an exception and returning success can accidentally commit or leave rollback-only state. `readOnly=true` is a hint, not an authorization control. Connections and entity managers are not shared across arbitrary asynchronous tasks.

### Security and Deployment

Authentication loads a principal; URL rules choose allowed endpoint categories; service/resource checks enforce ownership. CSRF is enabled by default for browser-oriented flows and also matters when browsers automatically send Basic credentials. Stateless bearer APIs have different CSRF assumptions; do not disable it merely because output is JSON. Method security requires `@EnableMethodSecurity` and proxy-invoked methods.

Boot 3 requires Java 17+ and Jakarta namespaces; this lab uses Java 21 and Boot 3.5. Boot 4 dependency/API changes require a separate migration, not a parent-version-only edit. Package an executable JAR, configure bounded request/thread/connection pools, keep management exposure minimal, and set error-message/stacktrace inclusion to never. External configuration overrides must be reviewed; environment/property sources can override packaged defaults. Do not expose Actuator environment/configuration endpoints publicly.

## Gotchas

A security annotation can be ineffective when calls bypass the expected proxy mechanism. Confirm behavior with endpoint-level tests rather than annotation presence alone.

## Labs

- [ ] Local Java and Spring exercise: Create a small REST controller with validated DTOs, a service, and object ownership checks. Test unauthenticated, wrong-owner, invalid, and valid requests.
- [ ] Boundary check: Send an unexpected administrative field to a DTO and confirm rejection or exclusion. Verify management endpoints and alternate route patterns require the intended identity.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. JDK 21, Maven 3.9.x. Boot 3.5.7 is a concrete teaching pin with matching Spring dependencies managed by its parent; it is not asserted to be the latest patched release. Before deployment choose a currently supported patched 3.5 release and rerun the suite. No database or external identity provider. Synthetic Basic credentials are loopback-only fixtures. Create these paths exactly.

### File: pom.xml

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
 <modelVersion>4.0.0</modelVersion>
 <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.5.7</version><relativePath/></parent>
 <groupId>lab</groupId><artifactId>reservations</artifactId><version>1.0.0</version>
 <properties><java.version>21</java.version></properties>
 <dependencies>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  <dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-test</artifactId><scope>test</scope></dependency>
 </dependencies>
 <build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>
</project>
```

### File: src/main/resources/application.properties

```properties
server.address=127.0.0.1
server.port=8080
server.error.include-message=never
server.error.include-stacktrace=never
spring.jackson.deserialization.fail-on-unknown-properties=true
```

### File: src/main/java/lab/Application.java

```java
package lab;

import java.net.URI;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
public class Application {
	public static void main(String[] args) { SpringApplication.run(Application.class, args); }
	@Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(rules -> rules.anyRequest().authenticated())
			.httpBasic(Customizer.withDefaults()).build();
	}
	@Bean UserDetailsService users() {
		return new InMemoryUserDetailsManager(
			User.withUsername("alice").password("{noop}synthetic-local-password").roles("USER").build(),
			User.withUsername("bob").password("{noop}synthetic-local-password").roles("USER").build());
	}
}

record CreateReservation(@Min(1) @Max(5) int seats) {}
record ReservationResponse(long id, int seats) {}
record StoredReservation(String owner, int seats) {}

@Service
class ReservationService {
	private final Map<Long, StoredReservation> reservations = new HashMap<>();
	private long sequence;
	synchronized ReservationResponse create(String owner, int seats) {
		long id = ++sequence;
		reservations.put(id, new StoredReservation(owner, seats));
		return new ReservationResponse(id, seats);
	}
	synchronized ReservationResponse read(String owner, long id) {
		StoredReservation stored = reservations.get(id);
		if (stored == null || !stored.owner().equals(owner)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		}
		return new ReservationResponse(id, stored.seats());
	}
}

@RestController
@RequestMapping("/reservations")
class ReservationController {
	private final ReservationService service;
	ReservationController(ReservationService service) { this.service = service; }
	@PostMapping ResponseEntity<ReservationResponse> create(
			@Valid @RequestBody CreateReservation input, Principal principal) {
		ReservationResponse result = service.create(principal.getName(), input.seats());
		return ResponseEntity.created(URI.create("/reservations/" + result.id())).body(result);
	}
	@GetMapping("/{id}") ReservationResponse read(@PathVariable long id, Principal principal) {
		return service.read(principal.getName(), id);
	}
}
```

### File: src/test/java/lab/ApplicationTest.java

```java
package lab;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ApplicationTest {
	@Autowired MockMvc mvc;
	@Test void lifecycle() throws Exception {
		mvc.perform(get("/reservations/999")).andExpect(status().isUnauthorized());
		mvc.perform(post("/reservations").with(user("alice")).with(csrf())
			.contentType("application/json").content("{\"seats\":0}"))
			.andExpect(status().isBadRequest());
		String location = mvc.perform(post("/reservations").with(user("alice")).with(csrf())
			.contentType("application/json").content("{\"seats\":2}"))
			.andExpect(status().isCreated()).andExpect(jsonPath("$.seats").value(2))
			.andReturn().getResponse().getHeader("Location");
		mvc.perform(get(location).with(user("alice"))).andExpect(status().isOk());
		mvc.perform(get(location).with(user("bob"))).andExpect(status().isNotFound());
		mvc.perform(post("/reservations").with(user("alice"))
			.contentType("application/json").content("{\"seats\":2}"))
			.andExpect(status().isForbidden());
	}
}
```

### Objectives and Commands

Run `mvn test`, then `mvn spring-boot:run`. In another terminal run `curl.exe -i -u alice:synthetic-local-password http://127.0.0.1:8080/reservations/999` (expected 404), then without `-u` (expected 401). The suite performs token-aware POSTs through MockMvc; manual browser-cookie/token acquisition is not required for the supplied acceptance check. Build the distributable with `mvn package` and run `java -jar target/reservations-1.0.0.jar` after stopping the dev process.

### Hints and Separate Solution

Binding/validation precedes service execution. The response omits owner; the service enforces it. The synchronized map makes individual local operations coherent, but is neither a database transaction nor distributed persistence. Expected: one passing JUnit test covering 401, 400, 201 with Location, 200, 404 and 403. The supplied code is the solution; CSRF remains enabled.

### Troubleshooting and Reset

Use JDK 21 in both `java` and Maven's configured JAVA_HOME. A POST without `.with(csrf())` returns 403 before body validation. A JSON naming mismatch returns 400 with strict unknown fields. Stop Ctrl+C; reservations vanish on restart. `mvn clean` removes only generated build output. `{noop}` is intentionally synthetic local-only test credential handling, not a password-storage recommendation. No JPA/transaction integration is claimed by this in-memory lab.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Java and Spring Security]]

## References

- [Spring MVC](https://docs.spring.io/spring-framework/reference/web/webmvc.html)
- [Declarative transactions](https://docs.spring.io/spring-framework/reference/data-access/transaction/declarative.html)
- [Boot reference](https://docs.spring.io/spring-boot/3.5/reference/)
- [Security architecture](https://docs.spring.io/spring-security/reference/servlet/architecture.html)
