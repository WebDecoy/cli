package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/WebDecoy/cli/internal/authn"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type step struct {
	status  int
	body    any
	err     error
	headers http.Header
}
type fixture struct {
	client *Client
	now    time.Time
	waits  []time.Duration
	forms  []url.Values
	paths  []string
	steps  []step
}

func grant() map[string]any {
	return map[string]any{"device_code": "private-device-code", "user_code": "ABCD-EFGH", "verification_uri": "https://tenant.auth0.com/activate", "expires_in": 900}
}
func token() map[string]any {
	return map[string]any{"access_token": "private-access-token", "token_type": "Bearer", "expires_in": 300}
}
func failure(code string) step {
	return step{status: 400, body: map[string]any{"error": code, "error_description": "private-secret-in-provider-error", "error_uri": "https://evil.example/private-secret"}}
}

func setup(t *testing.T, steps ...step) *fixture {
	t.Helper()
	c, err := New(Config{Issuer: "https://tenant.auth0.com/", Resource: "https://mcp.webdecoy.com/mcp", ClientID: "device-client"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{client: c, now: time.Now(), steps: steps}
	c.now = func() time.Time { return f.now }
	c.wait = func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.waits = append(f.waits, d)
		f.now = f.now.Add(d)
		return nil
	}
	c.verify = func(context.Context, string) (*authn.Identity, error) {
		return &authn.Identity{Subject: "auth0|customer", ClientID: "device-client", ExpiresAt: f.now.Add(300 * time.Second), Scopes: []string{authn.ReadScope}}, nil
	}
	c.http = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != "tenant.auth0.com" || r.Header.Get("Authorization") != "" {
			t.Error("unsafe authorization request")
		}
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if form.Get("client_secret") != "" || form.Get("client_id") != "device-client" {
			t.Error("public client contract violated")
		}
		f.forms = append(f.forms, form)
		f.paths = append(f.paths, r.URL.Path)
		if len(f.steps) == 0 {
			t.Error("unbounded or unexpected request")
			return nil, errors.New("unexpected request")
		}
		next := f.steps[0]
		f.steps = f.steps[1:]
		if next.err != nil {
			return nil, next.err
		}
		encoded, err := json.Marshal(next.body)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: next.status, Header: next.headers, Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
	})}
	return f
}

func present(Prompt) error { return nil }

func TestLoginPollingAndBinding(t *testing.T) {
	f := setup(t, step{status: 200, body: grant()}, failure("authorization_pending"), failure("slow_down"), step{status: 200, body: token()})
	shown := false
	session, err := f.client.Login(context.Background(), func(p Prompt) error {
		shown = true
		if p.VerificationURI != "https://tenant.auth0.com/activate" || p.UserCode != "ABCD-EFGH" || p.ExpiresAt.IsZero() {
			t.Fatalf("bad human prompt: %+v", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !shown || !reflect.DeepEqual(f.waits, []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}) {
		t.Fatalf("poll waits: %v", f.waits)
	}
	for i, form := range f.forms {
		// Auth0 rejects the resource parameter on these endpoints outright.
		if form.Get("audience") != f.client.config.Resource || form.Has("resource") {
			t.Error("resource binding missing")
		}
		if i == 0 {
			if form.Get("scope") != authn.ReadScope {
				t.Error("session-only login requested extra scopes")
			}
		} else if form.Get("device_code") != "private-device-code" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Error("invalid poll form")
		}
	}
	request, _ := http.NewRequest("POST", f.client.config.Resource, nil)
	if err := session.Authorize(request); err != nil || request.Header.Get("Authorization") != "Bearer private-access-token" {
		t.Fatal("authorized session did not set bearer")
	}
	for _, target := range []string{"https://api.webdecoy.com/mcp", "http://mcp.webdecoy.com/mcp", "https://mcp.webdecoy.com/mcp?token=1", "https://mcp.webdecoy.com/other"} {
		request, _ := http.NewRequest("POST", target, nil)
		if err := session.Authorize(request); err == nil || request.Header.Get("Authorization") != "" {
			t.Error("credential could escape hosted resource")
		}
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(format, session), "private-") {
			t.Fatal("session formatting leaked credentials")
		}
	}
	serialized, _ := json.Marshal(session)
	if strings.Contains(string(serialized), "private-") {
		t.Fatal("JSON leaked credentials")
	}
	session.Close()
	if !errors.Is(session.Authorize(request), ErrClosed) {
		t.Fatal("closed session usable")
	}
}

func TestTerminalPollingOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response step
		want     error
	}{
		{"denied", failure("access_denied"), ErrDenied},
		{"expired", failure("expired_token"), ErrExpired},
		{"reused code", failure("invalid_grant"), ErrUnavailable},
		{"unknown error", failure("private-secret-error"), ErrUnavailable},
		{"rate limit", step{status: 429, body: map[string]any{"error": "too_many_requests"}}, ErrUnavailable},
		{"provider outage", step{status: 503, body: map[string]any{"error": "private-secret"}}, ErrUnavailable},
		{"redirect", step{status: 302, body: map[string]any{}}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, step{status: 200, body: grant()}, tc.response)
			session, err := f.client.Login(context.Background(), present)
			if session != nil || !errors.Is(err, tc.want) || len(f.forms) != 2 {
				t.Fatalf("unexpected outcome: %v / requests %d", err, len(f.forms))
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("provider error leaked")
			}
		})
	}
}

func TestPollingTimeoutsBackOffAndStop(t *testing.T) {
	timeout := step{err: &net.DNSError{IsTimeout: true, Err: "private-secret-timeout"}}
	f := setup(t, step{status: 200, body: grant()}, timeout, timeout, timeout, timeout)
	_, err := f.client.Login(context.Background(), present)
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(f.waits, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}) {
		t.Fatalf("timeout outcome: %v, waits %v", err, f.waits)
	}
}

func TestAuth0StatusCodesAndRetryAfter(t *testing.T) {
	for _, header := range []string{"17", "date", "1", "invalid", "900"} {
		t.Run(header, func(t *testing.T) {
			pending := failure("authorization_pending")
			pending.status = 403
			slow := failure("slow_down")
			slow.status = 429
			f := setup(t, step{status: 200, body: grant()}, pending, slow, step{status: 200, body: token()})
			started := f.now
			value := header
			if header == "date" {
				value = f.now.Add(27 * time.Second).UTC().Format(http.TimeFormat)
			}
			f.steps[2].headers = http.Header{"Retry-After": []string{value}}
			session, err := f.client.Login(context.Background(), present)
			switch header {
			case "invalid":
				if !errors.Is(err, ErrUnavailable) || len(f.forms) != 3 {
					t.Fatal("invalid retry delay ignored")
				}
				return
			case "900":
				if !errors.Is(err, ErrExpired) || len(f.forms) != 3 {
					t.Fatal("retry beyond expiry attempted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if len(f.waits) != 3 {
				t.Fatalf("polling waits: %v", f.waits)
			}
			want := 17 * time.Second
			if header == "date" {
				date, _ := http.ParseTime(value)
				want = date.Sub(started.Add(10 * time.Second))
			}
			if header == "1" {
				want = 10 * time.Second
			}
			if f.waits[2] != want || f.waits[2] < 10*time.Second {
				t.Fatalf("polling waits %v, last want %v", f.waits, want)
			}
		})
	}
	for _, code := range []string{"access_denied", "expired_token"} {
		response := failure(code)
		response.status = 403
		f := setup(t, step{status: 200, body: grant()}, response)
		_, err := f.client.Login(context.Background(), present)
		want := ErrDenied
		if code == "expired_token" {
			want = ErrExpired
		}
		if !errors.Is(err, want) || len(f.forms) != 2 {
			t.Fatalf("Auth0 %s: %v", code, err)
		}
	}
}

func TestGrantValidationAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing device code", func(g map[string]any) { delete(g, "device_code") }},
		{"oversized device code", func(g map[string]any) { g["device_code"] = strings.Repeat("x", MaxCredentialBytes+1) }},
		{"terminal injection", func(g map[string]any) { g["user_code"] = "CODE\x1b[2J" }},
		{"foreign verification URL", func(g map[string]any) { g["verification_uri"] = "https://evil.example/activate" }},
		{"verification URL query", func(g map[string]any) { g["verification_uri"] = "https://tenant.auth0.com/activate?code=secret" }},
		{"invalid interval", func(g map[string]any) { g["interval"] = 0 }},
		{"negative expiry", func(g map[string]any) { g["expires_in"] = -1 }},
		{"oversized document", func(g map[string]any) { g["padding"] = strings.Repeat("x", MaxResponseBytes) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := grant()
			tc.change(g)
			f := setup(t, step{status: 200, body: g})
			shown := false
			_, err := f.client.Login(context.Background(), func(Prompt) error { shown = true; return nil })
			if !errors.Is(err, ErrInvalidResponse) || shown || len(f.forms) != 1 {
				t.Fatalf("invalid grant accepted: %v", err)
			}
		})
	}
	g := grant()
	g["expires_in"] = 5
	f := setup(t, step{status: 200, body: g})
	_, err := f.client.Login(context.Background(), present)
	if !errors.Is(err, ErrExpired) || len(f.forms) != 1 {
		t.Fatal("expired grant polled")
	}
	f = setup(t, step{status: 200, body: grant()})
	_, err = f.client.Login(context.Background(), func(Prompt) error { f.now = f.now.Add(MaxLoginDuration); return nil })
	if !errors.Is(err, ErrExpired) || len(f.forms) != 1 {
		t.Fatal("presentation time not counted")
	}
}

func TestCancellationAndSingleLogin(t *testing.T) {
	f := setup(t, step{status: 200, body: grant()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := f.client.Login(ctx, func(Prompt) error {
		if _, err := f.client.Login(context.Background(), present); err == nil {
			t.Error("concurrent login accepted")
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(f.forms) != 1 {
		t.Fatal("cancelled login polled")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("poll wait ignored cancellation")
	}
	f = setup(t, step{status: 200, body: grant()})
	_, err = f.client.Login(context.Background(), func(Prompt) error { return errors.New("private-secret-presenter-error") })
	if err == nil || strings.Contains(err.Error(), "private-") || len(f.forms) != 1 {
		t.Fatal("presentation error leaked or polling continued")
	}
}

func TestRejectInvalidTokens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"bad token type", func(r map[string]any) { r["token_type"] = "MAC" }},
		{"missing token", func(r map[string]any) { delete(r, "access_token") }},
		{"long lifetime", func(r map[string]any) { r["expires_in"] = 3600 }},
		{"scope expansion", func(r map[string]any) { r["scope"] = "mcp:read mcp:write" }},
		{"missing read scope", func(r map[string]any) { r["scope"] = "offline_access" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := token()
			tc.change(r)
			f := setup(t, step{status: 200, body: grant()}, step{status: 200, body: r})
			if session, err := f.client.Login(context.Background(), present); session != nil || !errors.Is(err, ErrInvalidToken) {
				t.Fatal("invalid token accepted")
			}
		})
	}
	f := setup(t, step{status: 200, body: grant()}, step{status: 200, body: token()})
	f.client.verify = func(context.Context, string) (*authn.Identity, error) {
		return nil, errors.New("private-secret-verifier-error")
	}
	if _, err := f.client.Login(context.Background(), present); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("unverified token accepted")
	}
	f = setup(t, step{status: 200, body: grant()}, step{status: 200, body: token()})
	f.client.verify = func(context.Context, string) (*authn.Identity, error) {
		return &authn.Identity{Subject: "customer", ClientID: "device-client", ExpiresAt: f.now.Add(time.Minute), Scopes: []string{authn.ReadScope, "mcp:write"}}, nil
	}
	if _, err := f.client.Login(context.Background(), present); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("JWT scope expansion accepted")
	}
}
