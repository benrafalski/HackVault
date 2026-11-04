---
title: "Go Security"
aliases: []
tags: [web, w2, security]
domain: web
phase: "W2"
type: security
status: draft
pair: "[[Go]]"
updated: 2026-11-03
---
# Go Security

> [!abstract] TL;DR
> Unbounded reads, goroutine leaks, unsafe template choice, and missing resource authorization expose availability and data boundaries.

> [!info] Agent scope
> Security of: Go runtime; net/http; routing; contexts; goroutines; templates; error handling; server timeouts. Cover attack surface, root causes, authorized-lab checks, detection, and defense; link shared techniques.

## Attack Surface

- Unbounded reads, goroutine leaks, unsafe template choice, and missing resource authorization expose availability and data boundaries.
- Treat each externally supplied identifier, message, file, or configuration value as a separate trust decision.

## Learn

```text
Teach me defensive Go net/http security using a supported Go 1.26/1.27 toolchain.
Assume contexts, goroutines and HTTP. Explain body/time/concurrency limits,
JSON decoder ambiguity, template source and trusted types, response commit,
context cancellation, goroutine ownership and race-free resource authorization.
Show complete standard-library tests with synthetic identities, owner-constrained
updates, denied requests that leave state unchanged, and permitted requests.
Cover database/sql atomicity, proxy/header trust, client timeouts, secret-free
logging and shutdown. No exploitation, privilege escalation, credential theft,
evasion or bypass demonstrations. Use public primary sources and explicitly
unexecuted outcomes. Teach here without missing-file or agent dependencies.
```

## Cheatsheet

### Resource and Data Boundaries

| Root cause | Control | Limit |
|---|---|---|
| Unbounded body/work | MaxBytesReader, bounded collections, explicit server timeouts and concurrency budgets | Content-Length alone is not a trustworthy read limit; decompression and downstream work need separate budgets. |
| One goroutine per unbounded job | Bounded worker pool/semaphore, cancellation-aware sends and receives | A context does not kill a goroutine that ignores Done. Bound queue length as well as active workers. |
| Owner check outside mutation | Hold one mutex for local check/write, or use one owner/version-constrained SQL update | A mutex does not protect another process or database client. |
| Identity from request fields | Validated auth middleware sets a private typed context key/principal | Context values are transport, not cryptographic identity verification. Do not trust X-User/X-Forwarded-For as login. |
| Loose JSON contract | Bound bytes, reject unknowns, enforce one value, validate exact domain types | encoding/json v1 accepts duplicate keys and case-insensitive names. Never let identity/role/owner come from this DTO. |
| Template trust | html/template with fixed source and plain data | template.HTML/JS/URL deliberately bypass contextual protections and require trusted values. |
| Error response | Generic public error, redacted structured server log | Once response bytes are sent, later errors cannot replace status; avoid logging raw bodies/tokens. |

Unsafe review fragment: read a map entry, release its lock, check owner, then reacquire a lock and update a potentially changed entry. Fixed design checks ownership and mutates under the same lock. For SQL, use `UPDATE ... WHERE id = ? AND owner_id = ? AND version = ?`, check affected rows and bind values; the transaction must use one transaction handle throughout.

### Runtime and Deployment

Go's convenience `ListenAndServe` does not choose all appropriate application timeouts for you. Use an explicit Server with header/body/write/idle limits, and tailor streaming endpoints separately. Reuse an outbound Client/Transport with request contexts, bounded response reads and body closure. Limit open connections and per-principal quotas independently of goroutine count.

Panic recovery in net/http protects the serving process from some handler panics but may terminate/reset the connection; it is not an intentional JSON error contract. A panic in an unrelated goroutine can crash the process. Use checked errors and lifecycle-owned workers. Use `errors.Is/As`, not string inspection, to distinguish cancellation/deadline/size conditions.

Go 1.22 mux method/path syntax is assumed; legacy mux compatibility settings change behavior. This lab uses stable encoding/json v1, not experimental v2 behavior. Keep the Go toolchain patched because net/http/TLS parsers ship with it. Run the race detector on supported build environments and review dependency advisories; memory safety does not provide application authorization.

## Detection and Defense

Observe active requests/workers, goroutine trend, heap growth, dependency latency, timeouts, body-limit rejections and policy outcomes. A short-lived goroutine spike can be normal; a rising post-load baseline suggests retained work. Keep diagnostic endpoints private. Log route templates and bounded request IDs, not user-controlled high-cardinality paths or sensitive bodies. Validate limits at both proxy and application layers.

## Labs

- [ ] Local Go exercise: Build a local JSON endpoint with a body limit, decoder checks, validation, and a request deadline. Test malformed input, trailing data, and client cancellation.
- [ ] Boundary check: Submit an oversized body and confirm bounded rejection. Cancel a request to a toy slow dependency and verify its work stops rather than continuing indefinitely.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. Current patched Go 1.26.x/1.27.x, standard library only. Separate disposable module. The server is fixed to synthetic Alice; tests inject Alice/Bob/anonymous outside HTTP. This is a policy fixture, not a production authentication system.

### File: go.mod

```go
module example.local/policy

go 1.26.0
```

### File: main.go

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

type store struct {
	mutex sync.Mutex
	owner string
	text string
}
type editInput struct { Text string `json:"text"` }
type editOutput struct { Text string `json:"text"` }

func (storage *store) update(principal, text string) bool {
	storage.mutex.Lock()
	defer storage.mutex.Unlock()
	if storage.owner != principal { return false }
	storage.text = text
	return true
}

func cancellableWork(ctx context.Context) error {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done(): return ctx.Err()
	case <-timer.C: return nil
	}
}

func handler(principal string, storage *store, work func(context.Context) error) http.Handler {
	slots := make(chan struct{}, 2)
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /note", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "private, no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if principal != "alice" && principal != "bob" { http.Error(response, "authentication required", 401); return }
		select {
		case slots <- struct{}{}: defer func() { <-slots }()
		default: http.Error(response, "busy", 503); return
		}
		media, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || media != "application/json" { http.Error(response, "JSON required", 415); return }
		request.Body = http.MaxBytesReader(response, request.Body, 256)
		defer request.Body.Close()
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input editInput
		err = decoder.Decode(&input)
		if err == nil {
			var extra any
			trailing := decoder.Decode(&extra)
			if trailing != io.EOF {
				if trailing == nil { err = errors.New("extra JSON") } else { err = trailing }
			}
		}
		if err != nil {
			var limit *http.MaxBytesError
			if errors.As(err, &limit) { http.Error(response, "too large", 413) } else { http.Error(response, "invalid JSON", 400) }
			return
		}
		text := strings.TrimSpace(input.Text)
		if text == "" || len(text) > 80 { http.Error(response, "invalid text", 400); return }
		ctx, cancel := context.WithTimeout(request.Context(), 100*time.Millisecond)
		defer cancel()
		if err := work(ctx); err != nil { http.Error(response, "work stopped", 408); return }
		if !storage.update(principal, text) { http.Error(response, "not found", 404); return }
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(editOutput{text}); err != nil { log.Print("response write failed") }
	})
	return mux
}

func main() {
	storage := &store{owner: "alice", text: "synthetic"}
	server := &http.Server{Addr: "127.0.0.1:8081", Handler: handler("alice", storage, cancellableWork),
		ReadHeaderTimeout: 5*time.Second, ReadTimeout: 10*time.Second,
		WriteTimeout: 15*time.Second, IdleTimeout: 60*time.Second}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) { log.Fatal(err) }
}
```

### File: main_test.go

```go
package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyAndInput(t *testing.T) {
	cases := []struct { user, body string; status int }{
		{"", `{"text":"reviewed"}`, 401}, {"bob", `{"text":"reviewed"}`, 404},
		{"alice", `{"text":"reviewed","owner":"alice"}`, 400},
		{"alice", `{"text":"reviewed"} {}`, 400},
		{"alice", `{"text":"` + strings.Repeat("x", 300) + `"}`, 413},
		{"alice", `{"text":"reviewed"}`, 200},
	}
	for _, item := range cases {
		storage := &store{owner: "alice", text: "synthetic"}
		request := httptest.NewRequest("PATCH", "/note", strings.NewReader(item.body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler(item.user, storage, cancellableWork).ServeHTTP(recorder, request)
		if recorder.Code != item.status { t.Fatalf("got %d want %d", recorder.Code, item.status) }
		expectedText := "synthetic"
		if item.status == 200 { expectedText = "reviewed" }
		if storage.text != expectedText || storage.owner != "alice" { t.Fatal("unexpected state") }
		if item.status == 200 && recorder.Body.String() != "{\"text\":\"reviewed\"}\n" { t.Fatal("unexpected DTO") }
	}
}

func TestCancellationPreventsWrite(t *testing.T) {
	storage := &store{owner: "alice", text: "synthetic"}
	observed := false
	work := func(ctx context.Context) error { <-ctx.Done(); observed = true; return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest("PATCH", "/note", strings.NewReader(`{"text":"reviewed"}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler("alice", storage, work).ServeHTTP(recorder, request)
	if !observed || recorder.Code != 408 || storage.text != "synthetic" { t.Fatal("cancellation boundary failed") }
}
```

### Objectives, Baseline and Hints

Run `go test -v ./...`, then `go run .`. Save `{"text":"reviewed"}` in body.json and call `curl.exe -i -X PATCH http://127.0.0.1:8081/note -H "Content-Type: application/json" --data-binary "@body.json"`. Baseline has Alice's synthetic note; tests prove denied requests leave it unchanged. Hint: the store lock covers the owner check and mutation together; the input DTO never contains owner. Cancellation tests wait on Done directly and do not depend on timing sleeps.

### Solution and Fixed Retest

The solution layers fixed synthetic identity, bounded input/concurrency, strict allowed fields, cooperative cancellation and atomic local policy/mutation. Expected: two passing tests; cases return 401/404/400/400/413/200, cancellation returns 408 to the in-process recorder, and no denied write changes state. The live allowed request returns only `{"text":"reviewed"}`. Repeat after changing parsers, middleware or persistence. No vulnerable endpoint or exploitation procedure is included.

### Troubleshooting and Reset

A 415 means Content-Type is missing/invalid; a 413 means the body exceeded 256 bytes. Length here is UTF-8 bytes, not displayed characters. The two-slot limit is per handler instance/process, not a global distributed quota. The sample maps all dependency failures to a generic stopped-work response for this fixed dependency; a production adapter should distinguish deadline, cancellation and upstream failure. Race testing requires supported tooling and additional concurrent workloads; these sequential tests do not prove all races absent. Stop Ctrl+C; restart restores the seed. Remove the disposable module to clean up.

## Related Techniques

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Go]]

## References

- [net/http](https://pkg.go.dev/net/http)
- [Go database transactions](https://go.dev/doc/database/execute-transactions)
- [Canceling database work](https://go.dev/doc/database/cancel-operations)
- [html/template security model](https://pkg.go.dev/html/template#hdr-Security_Model)
- [Go security](https://go.dev/security/)
