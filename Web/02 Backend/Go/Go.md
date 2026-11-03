---
title: "Go"
aliases: []
tags: [web, w2]
domain: web
phase: "W2"
type: tech
status: draft
pair: "[[Go Security]]"
updated: 2026-11-03
---
# Go

> [!abstract] TL;DR
> Use r.Context(), explicit http.Server timeouts, and parameterized database calls. Check every returned error and close owned resources.

> [!info] Agent scope
> Go runtime; net/http; routing; contexts; goroutines; templates; error handling; server timeouts.

## Prerequisites

- Use an isolated, disposable environment; record OS, runtime, and tool versions.
- [[Web Lab Setup]]

## Learn

```text
Teach me Go backend engineering with a supported Go 1.26/1.27 toolchain given
HTTP, typed programming and basic SQL. Explain goroutine scheduling, memory
ownership, net/http handler concurrency, ServeMux method/path patterns, response
commit, contexts/cancellation and graceful shutdown. Work through bounded JSON,
unknown/trailing input, html/template, error wrapping, database/sql transactions,
connection reuse, timeouts and race-free state. Contrast pre-1.22 routing and
encoding/json v1 behavior with experimental/new alternatives rather than mixing
APIs. Supply complete programs, go test/httptest checks and expected results.
Use official public sources and label unexecuted examples; teach here, not by
editing files or delegating required exercise steps to an agent.
```

## Cheatsheet

### Runtime and HTTP Lifecycle

Goroutines are multiplexed onto OS threads by the runtime. They are cheap, not free: stacks, captured objects, blocked channels and downstream connections consume resources. The scheduler does not make unsynchronized map access safe. Use mutexes/channels/atomic operations to establish ordering, and run the race detector when its platform prerequisites are available.

The server invokes handlers concurrently. Do not retain ResponseWriter or request-scoped data for use after ServeHTTP returns. A first `Write` implicitly commits status 200; later `WriteHeader` cannot replace it. Set headers/status before writing. Buffer small templates/JSON when an encoding error must be reported before commit; use deliberate streaming protocols for large results.

Go 1.22 added method-aware ServeMux patterns such as `POST /quotes` and path wildcards `GET /items/{id}`, read with `request.PathValue("id")`. GET patterns also match HEAD. Pattern conflict detection and path unescaping differ from older mux behavior; `GODEBUG=httpmuxgo121=1` restores legacy routing and is incompatible with assuming new patterns work. Route conversion/existence/authorization remain application responsibilities.

### Boundaries and Error Handling

| API | Use and limitation |
|---|---|
| `http.MaxBytesReader` | Bound the body consumed by a handler; return a deliberate 413 for MaxBytesError. It is not a request-timeout or decompression-work limit. |
| `json.Decoder.DisallowUnknownFields` | Reject extra object names; perform a second Decode expecting EOF to reject multiple JSON values. encoding/json v1 still accepts duplicate names and matches fields case-insensitively. |
| `html/template` | Contextual HTML/attribute/JS escaping for trusted template source and untrusted data. `text/template` does not provide HTML safety; template.HTML and related types assert trust. |
| `errors.Is/As` | Inspect wrapped sentinel/typed errors; wrap with `%w`. Do not match error text or expose internal errors as HTTP bodies. |
| `request.Context()` | Cancel downstream operations on disconnect/deadline. Passing a context does nothing unless the callee observes it. Never store it globally. |
| `defer Close/Rollback` | Release owned resources on return; do not defer inside an unbounded loop and accumulate resources until function exit. |

Use `database/sql` parameter placeholders appropriate to the driver, `BeginTx(ctx, ...)`, deferred rollback, all statements through the transaction and explicit commit/error handling. A separate pool call is outside that transaction. Authentication supplies a principal through trusted middleware; constrain resource operations by that principal, not a JSON owner field. A mutex is process-local, not a database transaction across replicas.

### Timeouts and Shutdown

`ReadHeaderTimeout` bounds header reading; `ReadTimeout` covers reading the request including body; `WriteTimeout` constrains writes with protocol-specific timing; `IdleTimeout` bounds idle keep-alive. A handler context deadline bounds cooperative application work separately. Streaming endpoints need tailored deadlines rather than a blanket short write timeout. `http.TimeoutHandler` is buffered and does not magically terminate ignored work.

For outbound requests reuse an `http.Client`/Transport, set appropriate timeouts and attach context. Close response bodies; read/drain bounded bodies when connection reuse is appropriate. `Server.Shutdown` stops accepting and waits for active work within its context; it does not forcibly finish every hijacked connection or cancel all application goroutines. Keep background workers under an explicit lifecycle.

## Gotchas

A data race is not fixed by using goroutines. The default convenience server lacks many production timeout choices you should set explicitly.

## Labs

- [ ] Local Go exercise: Build a local JSON endpoint with a body limit, decoder checks, validation, and a request deadline. Test malformed input, trailing data, and client cancellation.
- [ ] Boundary check: Submit an oversized body and confirm bounded rejection. Cancel a request to a toy slow dependency and verify its work stops rather than continuing indefinitely.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

### Environment and Complete Files

Unexecuted. Current patched Go 1.26.x or 1.27.x, standard library only. Go 1.22+ routing is required; this module selects 1.26. No external dependencies or go.sum are needed. Create a new disposable directory.

### File: go.mod

```go
module example.local/quotes

go 1.26.0
```

### File: main.go

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

type quoteInput struct { Quantity int `json:"quantity"` }
type quoteOutput struct { TotalCents int `json:"total_cents"` }

func waitForPrice(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done(): return ctx.Err()
	case <-timer.C: return nil
	}
}

func newHandler(work func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	page := template.Must(template.New("quote").Parse(`<p>{{.}}</p>`))
	mux.HandleFunc("GET /{$}", func(response http.ResponseWriter, request *http.Request) {
		var buffer bytes.Buffer
		if err := page.Execute(&buffer, "<b>literal</b>"); err != nil {
			http.Error(response, "render failed", 500); return
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := response.Write(buffer.Bytes()); err != nil { log.Print("response write failed") }
	})
	mux.HandleFunc("POST /quotes", func(response http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(response, request.Body, 1024)
		defer request.Body.Close()
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input quoteInput
		err := decoder.Decode(&input)
		if err == nil {
			var extra any
			if trailing := decoder.Decode(&extra); trailing != io.EOF {
				if trailing == nil { err = errors.New("extra value") } else { err = trailing }
			}
		}
		if err != nil {
			var limit *http.MaxBytesError
			if errors.As(err, &limit) { http.Error(response, "too large", 413) } else { http.Error(response, "invalid JSON", 400) }
			return
		}
		if input.Quantity < 1 || input.Quantity > 10 { http.Error(response, "invalid quantity", 400); return }
		ctx, cancel := context.WithTimeout(request.Context(), 200*time.Millisecond)
		defer cancel()
		if err := work(ctx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) { http.Error(response, "dependency timeout", 504) } else if errors.Is(err, context.Canceled) {
				http.Error(response, "request cancelled", 408)
			} else { http.Error(response, "dependency failed", 502) }
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(quoteOutput{input.Quantity * 125}); err != nil { log.Print("response write failed") }
	})
	return mux
}

func main() {
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: newHandler(waitForPrice),
		ReadHeaderTimeout: 5*time.Second, ReadTimeout: 10*time.Second,
		WriteTimeout: 15*time.Second, IdleTimeout: 60*time.Second}
	stop, release := signal.NotifyContext(context.Background(), os.Interrupt)
	defer release()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Print(err)
			if closeErr := server.Close(); closeErr != nil { log.Print(closeErr) }
		}
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) { log.Fatal(err) }
	<-drained
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

func TestDecodeAndTemplate(t *testing.T) {
	handler := newHandler(waitForPrice)
	cases := []struct { body string; status int }{
		{`{"quantity":2}`, 200}, {`{`, 400}, {`{"quantity":0}`, 400},
		{`{"quantity":2,"extra":1}`, 400}, {`{"quantity":2} {}`, 400},
		{`{"quantity":2}` + strings.Repeat(" ", 1100), 413},
	}
	for _, item := range cases {
		request := httptest.NewRequest("POST", "/quotes", strings.NewReader(item.body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != item.status { t.Fatalf("got %d want %d", recorder.Code, item.status) }
		if item.status == 200 && recorder.Body.String() != "{\"total_cents\":250}\n" { t.Fatal(recorder.Body.String()) }
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(recorder.Body.String(), "&lt;b&gt;literal&lt;/b&gt;") { t.Fatal(recorder.Body.String()) }
}

func TestCancellation(t *testing.T) {
	stopped := false
	handler := newHandler(func(ctx context.Context) error { <-ctx.Done(); stopped = true; return ctx.Err() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest("POST", "/quotes", strings.NewReader(`{"quantity":1}`)).WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 408 || !stopped { t.Fatal("work did not observe cancellation") }
}
```

### Objectives and Commands

Run `go test -v ./...`, then `go run .`. Save `{"quantity":2}` in body.json; call `curl.exe -i http://127.0.0.1:8080/quotes -H "Content-Type: application/json" --data-binary "@body.json"`. Open `/` for the template. The test decoder intentionally validates JSON bytes independent of media type; production endpoints should also enforce a documented Content-Type policy.

### Hints and Separate Solution

The second Decode must reach EOF; trailing whitespace is allowed until it exceeds the byte limit. `DisallowUnknownFields` is not duplicate-key rejection. Expected: two passing Go tests; HTTP 200 with total_cents 250, invalid/extra JSON 400, large input 413, cancelled in-process request 408, and escaped template output. A real disconnected client cannot necessarily receive the generated 408; the meaningful assertion is that work stopped. Complete files above are the solution.

### Troubleshooting and Reset

Method routes failing unexpectedly can indicate a pre-1.22 toolchain or legacy mux GODEBUG setting. Race checks (`go test -race ./...`) require a supported platform and C toolchain; they are optional additional validation, not claimed executed. Stop Ctrl+C; main waits for draining and force-closes connections if the shutdown deadline expires. Unix service deployments should additionally register SIGTERM in a platform-appropriate signal setup. No persistent state exists; remove the disposable directory to reset.

## Related

- [[Web Roadmap#W2 Backend|W2 Backend]]
- [[Go Security]]

## References

- [net/http](https://pkg.go.dev/net/http)
- [context](https://pkg.go.dev/context)
- [encoding/json](https://pkg.go.dev/encoding/json)
- [html/template](https://pkg.go.dev/html/template)
- [Go race detector](https://go.dev/doc/articles/race_detector)
