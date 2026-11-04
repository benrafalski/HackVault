---
title: "Java and Spring Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Java and Spring]]"
updated: 2026-11-03
---
# Java and Spring Security

> [!abstract] TL;DR
> Overbinding, unsafe deserialization, expression evaluation, exposed management endpoints, and incomplete filter-chain coverage can bypass intended controls.

> [!info] Agent scope
> Security of: JVM web applications; Spring Boot; dependency injection; MVC; binding; Spring Security; build and deployment. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Overbinding, unsafe deserialization, expression evaluation, exposed management endpoints, and incomplete filter-chain coverage can bypass intended controls.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Spring Boot 3.5 / Spring Security 6 with Java 21. Explain
first-matching filter chains, authentication, URL authorization, method proxies,
resource ownership, CSRF, DTO binding and Bean Validation. Cover native Java
serialization, Jackson polymorphism, SpEL trust, Actuator, error disclosure,
configuration overrides and transactional authorization. Give complete MockMvc
negative regressions using synthetic principals and retained permitted cases.
Explain proxy self-invocation and management-chain pitfalls without exploitation
or bypass demonstrations. No escalation, credential theft or evasion. Use public
primary sources, explicit versions and unexecuted expectations. Teach here.
```

## Cheatsheet

### Filter, Binding and Service Boundaries

FilterChainProxy chooses the first matching SecurityFilterChain. `securityMatcher` selects the chain; `requestMatchers` describes authorization inside that chain. A custom chain with a narrow matcher can leave other routes outside it unless a fallback chain covers them. Use a final deny rule, and test the actual endpoint patterns/methods, not merely annotation presence.

`@EnableMethodSecurity` enables supported method authorization. Proxy-based checks require calls through the Spring-managed proxy: self-invocation and manually constructed objects are common coverage mistakes. Method policy and database owner predicates should agree. Role-only checks cannot distinguish two users with the same role. For mutations constrain owner/version in the write or lock/read/update in one transaction.

| Root cause | Defensive choice |
|---|---|
| Binding persistence entities | Immutable request DTO with only editable fields; `@Valid`; explicit Jackson unknown-field policy. Separate response DTO excludes internal flags. |
| Unsafe object construction | Avoid native ObjectInputStream for untrusted input; avoid broad Jackson default typing. Use explicit known DTOs/subtypes and size limits. |
| Untrusted expression/template source | Keep SpEL/templates server-owned; pass user values as data, never expression source. |
| Management exposure | Minimize Actuator endpoints and bind/isolate management ingress. A management port is not inherently private. Test management authorization separately. |
| Session/CSRF confusion | Retain CSRF on ambient browser credentials; stateless bearer-only designs need documented authentication assumptions, not blanket disabling. |
| Configuration leakage | No environment/config dump in HTTP errors; restrict configuration overrides and secret sources. Log redacted server-side details. |

Unsafe review fragment: controller accepts a `UserEntity` and saves it wholesale. Fixed fragment: `record UpdateProfile(@NotBlank @Size(max=40) String displayName) {}`; authorize the owner, assign only displayName, return a separate DTO. Validation controls values; a request JSON field named `admin` must never be treated as an authorization decision.

Boot 3 uses Jakarta APIs and Spring Security's bean-based SecurityFilterChain configuration; old WebSecurityConfigurerAdapter tutorials are not drop-in recipes. Boot 4 introduces further ecosystem changes; this note deliberately fixes the Boot 3.5/Security 6 generation. Servlet MVC exceptions and reactive WebFlux errors take different paths.

## Detection and Defense

Monitor bounded authentication failures, denied route/method categories, admin/config changes and unusual deserialization errors. Failed authorization should not log request credentials or full DTOs. Distinguish invalid client versions from sustained anomalies. Recheck dependency advisories and management exposure after changing the Boot parent; unit policy tests do not certify infrastructure or every filter-chain configuration.

## Labs

- [ ] Local Java and Spring exercise: Create a small REST controller with validated DTOs, a service, and object ownership checks. Test unauthenticated, wrong-owner, invalid, and valid requests.
- [ ] Boundary check: Send an unexpected administrative field to a DTO and confirm rejection or exclusion. Verify management endpoints and alternate route patterns require the intended identity.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted independent project. JDK 21, Maven 3.9.x, Spring Boot 3.5.7 teaching pin. Use a maintained patched release in the supported 3.5 line before deployment and rerun all checks; this pin is not a security freshness claim. No credentials in tests: Spring Security test support injects synthetic principals. The standalone server uses a local synthetic Basic fixture only.

### File: pom.xml

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
 <modelVersion>4.0.0</modelVersion>
 <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.5.7</version><relativePath/></parent>
 <groupId>lab</groupId><artifactId>policy</artifactId><version>1.0.0</version>
 <properties><java.version>21</java.version></properties>
 <dependencies>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-actuator</artifactId></dependency>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  <dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-test</artifactId><scope>test</scope></dependency>
 </dependencies>
 <build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>
</project>
```

### File: src/main/resources/application.properties

```properties
server.address=127.0.0.1
server.port=8081
server.error.include-message=never
server.error.include-stacktrace=never
spring.jackson.deserialization.fail-on-unknown-properties=true
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never
```

### File: src/main/java/lab/Application.java

```java
package lab;

import java.security.Principal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
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
		return http.authorizeHttpRequests(rules -> rules
			.requestMatchers("/actuator/health").permitAll()
			.requestMatchers("/profiles/**").authenticated()
			.anyRequest().denyAll()).httpBasic(Customizer.withDefaults()).build();
	}
	@Bean UserDetailsService users() {
		return new InMemoryUserDetailsManager(User.withUsername("alice")
			.password("{noop}synthetic-local-password").roles("USER").build());
	}
}

record UpdateProfile(@NotBlank @Size(max=40) String displayName) {}
record ProfileResponse(String displayName) {}

@Service
class ProfileService {
	synchronized ProfileResponse preview(String principal, long id, String displayName) {
		if (id != 1 || !"alice".equals(principal)) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		return new ProfileResponse(displayName);
	}
}

@RestController
class ProfileController {
	private final ProfileService service;
	ProfileController(ProfileService service) { this.service = service; }
	@PostMapping("/profiles/{id}/preview") ProfileResponse preview(@PathVariable long id,
			@Valid @RequestBody UpdateProfile input, Principal principal) {
		return service.preview(principal.getName(), id, input.displayName());
	}
}
```

### File: src/test/java/lab/PolicyTest.java

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
class PolicyTest {
	@Autowired MockMvc mvc;
	@Test void identity_fields_and_csrf() throws Exception {
		mvc.perform(post("/profiles/1/preview").with(csrf()).contentType("application/json")
			.content("{\"displayName\":\"reviewed\"}")).andExpect(status().isUnauthorized());
		mvc.perform(post("/profiles/1/preview").with(user("bob")).with(csrf()).contentType("application/json")
			.content("{\"displayName\":\"reviewed\"}")).andExpect(status().isNotFound());
		mvc.perform(post("/profiles/1/preview").with(user("alice")).with(csrf()).contentType("application/json")
			.content("{\"displayName\":\"reviewed\",\"admin\":false}")).andExpect(status().isBadRequest());
		mvc.perform(post("/profiles/1/preview").with(user("alice")).contentType("application/json")
			.content("{\"displayName\":\"reviewed\"}")).andExpect(status().isForbidden());
		mvc.perform(post("/profiles/1/preview").with(user("alice")).with(csrf()).contentType("application/json")
			.content("{\"displayName\":\"reviewed\"}")).andExpect(status().isOk())
			.andExpect(content().json("{\"displayName\":\"reviewed\"}"));
	}
	@Test void management_and_fallback() throws Exception {
		mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.components").doesNotExist());
		mvc.perform(get("/actuator/env").with(user("alice"))).andExpect(status().isForbidden());
		mvc.perform(get("/other").with(user("alice"))).andExpect(status().isForbidden());
	}
}
```

### Objectives, Baseline and Hints

Run `mvn test`; start `mvn spring-boot:run` and call `curl.exe -i http://127.0.0.1:8081/actuator/health`. Baseline exposes only health status. The profile endpoint is a nonpersistent authorization preview, so negative tests never alter a real identity or role. Hint: supply CSRF for tests intended to reach authorization/binding; omit it only for the explicit CSRF test. An extra `admin:false` is a harmless unknown-field regression, not a privilege-change attempt.

### Solution and Fixed Retest

The solution is a complete fallback filter rule, strict DTO binding, owner policy in the service, and minimal output. Expected: two passing JUnit methods, preview 401/404/400/403/200 as specified; health 200 without components; management/fallback 403 for authenticated Alice. Repeat the same suite after any matcher/configuration change. No vulnerable configuration or bypass demonstration is supplied.

### Troubleshooting and Reset

Unexpected 403 before binding often means missing CSRF. An unexpected 404 on a fallback path can indicate the security chain did not cover it; do not merely change the test expectation. Verify the pinned dependency tree and Java version before adapting APIs. Stop Ctrl+C; the preview stores nothing. `mvn clean` resets build artifacts. Real database atomicity, production credential storage and deployed management isolation remain unexecuted integration responsibilities.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Java and Spring]]

## References

- [Servlet authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [Method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [CSRF testing](https://docs.spring.io/spring-security/reference/servlet/test/mockmvc/csrf.html)
- [Actuator endpoints](https://docs.spring.io/spring-boot/3.5/reference/actuator/endpoints.html)
