package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAuth struct {
	err         error
	token       atomic.Value
	invalidated atomic.Int32
}

func (a *fakeAuth) Authorize(_ context.Context, r *http.Request) error {
	if a.err != nil {
		return a.err
	}
	r.Header.Set("Authorization", "Bearer "+a.token.Load().(string))
	return nil
}
func (a *fakeAuth) Invalidate() { a.invalidated.Add(1); a.token.Store("fresh") }

func run(t *testing.T, hosted http.Handler, auth *fakeAuth, input string) []map[string]any {
	t.Helper()
	server := httptest.NewServer(hosted)
	defer server.Close()
	r := &Relay{Resource: server.URL + "/mcp", Auth: auth, HTTP: NewHTTPClient()}
	var out strings.Builder
	if err := r.Serve(context.Background(), strings.NewReader(input), &syncWriter{w: &out}); err != nil {
		t.Fatal(err)
	}
	var msgs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout carried a non-JSON line: %q", line)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Messages pass through unchanged with the bearer token; the negotiated
// protocol version rides on later requests; a notification gets no answer;
// and a refused token is renewed once and the message retried.
func TestRelayForwardsRenewsAndNegotiates(t *testing.T) {
	var versions []string
	var mu sync.Mutex
	hosted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer stale" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var env struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &env)
		mu.Lock()
		versions = append(versions, env.Method+"="+r.Header.Get("MCP-Protocol-Version"))
		mu.Unlock()
		if len(env.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result := `{"ok":true}`
		if env.Method == "initialize" {
			result = `{"protocolVersion":"2025-06-18"}`
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(env.ID) + `,"result":` + result + `}`))
	})
	auth := &fakeAuth{}
	auth.token.Store("stale")
	msgs := run(t, hosted, auth, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
`)
	if len(msgs) != 1 || msgs[0]["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %v", msgs)
	}
	if auth.invalidated.Load() != 1 {
		t.Fatalf("a refused token was renewed %d times", auth.invalidated.Load())
	}

	server := httptest.NewServer(hosted)
	defer server.Close()
	r := &Relay{Resource: server.URL + "/mcp", Auth: auth, HTTP: NewHTTPClient()}
	var out strings.Builder
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	if err := r.Serve(context.Background(), strings.NewReader(input), &syncWriter{w: &out}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	input = `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":"a","method":"tools/list"}` + "\n"
	if err := r.Serve(context.Background(), strings.NewReader(input), &syncWriter{w: &out}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"id":"a"`) {
		t.Fatalf("expected only the tools/list answer, got %q", out.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(versions, "tools/list=2025-06-18") {
		t.Fatalf("negotiated version not sent: %v", versions)
	}
}

// Login problems and hosted refusals become JSON-RPC errors a person can act
// on, never the hosted body, and only requests (not notifications) get one.
func TestRelayErrorsAreActionable(t *testing.T) {
	notSignedIn := &fakeAuth{err: ErrNotSignedIn}
	msgs := run(t, http.NotFoundHandler(), notSignedIn, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}
{"jsonrpc":"2.0","method":"notifications/initialized"}
`)
	if len(msgs) != 1 || !strings.Contains(msgs[0]["error"].(map[string]any)["message"].(string), "webdecoy login") {
		t.Fatalf("not signed in: %v", msgs)
	}

	storeDown := &fakeAuth{err: fmt.Errorf("%w (secret-tool failed)", ErrCredentialStore)}
	msgs = run(t, http.NotFoundHandler(), storeDown, `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`+"\n")
	if m := msgs[0]["error"].(map[string]any)["message"].(string); !strings.Contains(m, "credential store") || strings.Contains(m, "network") {
		t.Fatalf("credential store failure reported as %q", m)
	}

	auth := &fakeAuth{}
	auth.token.Store("ok")
	for status, want := range map[int]string{429: "Wait a few seconds", 503: "busy", 500: "HTTP 500"} {
		status := status
		hosted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"secret upstream detail"}`))
		})
		msgs := run(t, hosted, auth, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
		msg := msgs[0]["error"].(map[string]any)["message"].(string)
		if !strings.Contains(msg, want) || strings.Contains(msg, "secret") {
			t.Fatalf("%d: %q", status, msg)
		}
	}
}

// A client's cancellation stops the hosted request and nothing is answered.
func TestRelayCancellationStopsTheHostedCall(t *testing.T) {
	cancelled := make(chan struct{})
	hosted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server notices a client hang-up only once the body is read.
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "notifications/cancelled") {
			w.WriteHeader(http.StatusAccepted) // the cancellation notification itself
			return
		}
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	})
	server := httptest.NewServer(hosted)
	defer server.Close()
	auth := &fakeAuth{}
	auth.token.Store("ok")
	r := &Relay{Resource: server.URL + "/mcp", Auth: auth, HTTP: NewHTTPClient()}
	pr, pw := io.Pipe()
	var out strings.Builder
	done := make(chan struct{})
	go func() { _ = r.Serve(context.Background(), pr, &syncWriter{w: &out}); close(done) }()
	_, _ = pw.Write([]byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"search_detections"}}` + "\n"))
	time.Sleep(100 * time.Millisecond)
	_, _ = pw.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}` + "\n"))
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("the hosted call was not cancelled")
	}
	pw.Close()
	<-done
	if strings.Contains(out.String(), `"id":9`) {
		t.Fatalf("a cancelled request was answered: %q", out.String())
	}
}

// Oversized input is refused with a clear error rather than forwarded.
func TestRelayRefusesOversizedMessages(t *testing.T) {
	auth := &fakeAuth{}
	auth.token.Store("ok")
	var hits atomic.Int32
	hosted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	server := httptest.NewServer(hosted)
	defer server.Close()
	r := &Relay{Resource: server.URL + "/mcp", Auth: auth, HTTP: NewHTTPClient()}
	var out strings.Builder
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":"` + strings.Repeat("a", MaxMessageBytes) + `"}}` + "\n"
	_ = r.Serve(context.Background(), strings.NewReader(big), &syncWriter{w: &out})
	if hits.Load() != 0 || !strings.Contains(out.String(), "larger than") {
		t.Fatalf("oversized message: hits=%d out=%q", hits.Load(), out.String())
	}
}
