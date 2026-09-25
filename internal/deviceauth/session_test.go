package deviceauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WebDecoy/cli/internal/authn"
)

func renewable(t *testing.T, extra ...step) (*fixture, *Session) {
	t.Helper()
	response := token()
	response["refresh_token"] = "private-refresh-original"
	steps := append([]step{{status: 200, body: grant()}, {status: 200, body: response}}, extra...)
	f := setup(t, steps...)
	f.client.config.OfflineAccess = true
	session, err := f.client.Login(context.Background(), present)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	if f.forms[0].Get("scope") != "mcp:read offline_access" {
		t.Fatal("offline consent not requested")
	}
	return f, session
}

func TestRefreshRotationAndRevocation(t *testing.T) {
	rotated := token()
	rotated["access_token"] = "private-access-rotated"
	rotated["refresh_token"] = "private-refresh-rotated"
	f, session := renewable(t, step{status: 200, body: rotated}, step{status: 200, body: map[string]any{}})
	if err := session.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.forms[2].Get("refresh_token") != "private-refresh-original" || f.forms[2].Get("grant_type") != "refresh_token" {
		t.Fatal("incorrect refresh credential")
	}
	request, _ := http.NewRequest("POST", f.client.config.Resource, nil)
	if err := session.Authorize(request); err != nil || request.Header.Get("Authorization") != "Bearer private-access-rotated" {
		t.Fatal("rotated access token not used")
	}
	if err := session.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.paths[3] != "/oauth/revoke" || f.forms[3].Get("token") != "private-refresh-rotated" {
		t.Fatal("rotated credential was not revoked")
	}
	if !errors.Is(session.Authorize(request), ErrClosed) || session.refresh != "" || session.access != "" {
		t.Fatal("revocation left session usable")
	}
	if err := session.Revoke(context.Background()); err != nil || len(f.forms) != 4 {
		t.Fatal("repeated revoke performed remote work")
	}
}

func TestRefreshWithoutRotationRetainsCredential(t *testing.T) {
	f, session := renewable(t, step{status: 200, body: token()}, step{status: 200, body: map[string]any{}})
	if err := session.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.forms[3].Get("token") != "private-refresh-original" {
		t.Fatal("provider's unchanged refresh token lost")
	}
}

func TestRefreshFailureIsTerminal(t *testing.T) {
	for _, response := range []step{failure("invalid_grant"), {status: 503, body: map[string]any{"error_description": "private-secret"}}} {
		f, session := renewable(t, response)
		if err := session.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private-") {
			t.Fatal("unsafe refresh failure")
		}
		if err := session.Refresh(context.Background()); !errors.Is(err, ErrClosed) || len(f.forms) != 3 {
			t.Fatal("failed refresh retried")
		}
		if session.access != "" || session.refresh != "" {
			t.Fatal("failed renewal retained credentials")
		}
	}
}

func TestRefreshCannotSwitchAccountOrExpandScope(t *testing.T) {
	f, session := renewable(t, step{status: 200, body: token()})
	f.client.verify = func(context.Context, string) (*authn.Identity, error) {
		return &authn.Identity{Subject: "auth0|other-user", ClientID: "device-client", ExpiresAt: f.now.Add(time.Minute), Scopes: []string{authn.ReadScope}}, nil
	}
	if err := session.Refresh(context.Background()); !errors.Is(err, ErrInvalidToken) || !session.closed {
		t.Fatal("account changed through refresh")
	}
	response := token()
	response["scope"] = "mcp:read mcp:write"
	_, session = renewable(t, step{status: 200, body: response})
	if err := session.Refresh(context.Background()); !errors.Is(err, ErrInvalidToken) || !session.closed {
		t.Fatal("refresh expanded permissions")
	}
}

func TestSessionOnlyAndRevocationFailure(t *testing.T) {
	response := token()
	response["refresh_token"] = "private-unrequested-refresh"
	f := setup(t, step{status: 200, body: grant()}, step{status: 200, body: response})
	session, err := f.client.Login(context.Background(), present)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.refresh != "" || !errors.Is(session.Refresh(context.Background()), ErrNoRefresh) {
		t.Fatal("session-only mode retained refresh credential")
	}
	f.now = f.now.Add(301 * time.Second)
	request, _ := http.NewRequest("POST", f.client.config.Resource, nil)
	if !errors.Is(session.Authorize(request), ErrExpired) {
		t.Fatal("expired session usable")
	}
	if err := session.Revoke(context.Background()); err != nil || len(f.forms) != 2 {
		t.Fatal("session-only revoke issued a network request")
	}
	f, session = renewable(t, step{status: 503, body: map[string]any{}})
	if err := session.Revoke(context.Background()); !errors.Is(err, ErrUnavailable) || !session.closed || session.access != "" || session.refresh != "" {
		t.Fatal("failed revocation retained credentials or claimed success")
	}
}

func TestRequestHostCannotOverrideResource(t *testing.T) {
	f := setup(t, step{status: 200, body: grant()}, step{status: 200, body: token()})
	session, err := f.client.Login(context.Background(), present)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	r, _ := http.NewRequest("POST", f.client.config.Resource, nil)
	r.Host = "evil.example"
	if session.Authorize(r) == nil || r.Header.Get("Authorization") != "" {
		t.Fatal("foreign Host received bearer")
	}
}

// A stored refresh credential resumes a session by one verified renewal; the
// session learns its user from that token, and Persist hands the rotated
// credential (never the access token) to the caller's store.
func TestResumeFromStoredCredential(t *testing.T) {
	rotated := token()
	rotated["refresh_token"] = "private-refresh-rotated"
	f := setup(t, step{status: 200, body: rotated})
	f.client.config.OfflineAccess = true
	session, err := f.client.Resume(context.Background(), "private-refresh-stored")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if f.forms[0].Get("refresh_token") != "private-refresh-stored" || f.forms[0].Get("grant_type") != "refresh_token" {
		t.Fatal("resume did not renew the stored credential")
	}
	if session.Subject() != "auth0|customer" {
		t.Fatalf("resumed session subject %q", session.Subject())
	}
	var saved string
	if err := session.Persist(func(refresh string) error { saved = refresh; return nil }); err != nil || saved != "private-refresh-rotated" {
		t.Fatalf("persisted %q, %v", saved, err)
	}
	request, _ := http.NewRequest("POST", f.client.config.Resource, nil)
	if err := session.Authorize(request); err != nil {
		t.Fatal(err)
	}
}

func TestResumeRefusesWithoutOfflineModeOrOnFailure(t *testing.T) {
	f := setup(t)
	if _, err := f.client.Resume(context.Background(), "private-refresh-stored"); !errors.Is(err, ErrNoRefresh) {
		t.Fatalf("resume without offline mode: %v", err)
	}
	f = setup(t, failure("invalid_grant"))
	f.client.config.OfflineAccess = true
	if s, err := f.client.Resume(context.Background(), "private-refresh-revoked"); err == nil || s != nil {
		t.Fatal("a refused credential resumed a session")
	}
}

// Setup is requested only when configured, and a token carrying mcp:setup is
// refused unless it was.
func TestSetupScopeIsOptIn(t *testing.T) {
	withSetup := token()
	withSetup["scope"] = "mcp:read mcp:setup"
	f := setup(t, step{status: 200, body: grant()}, step{status: 200, body: withSetup})
	if _, err := f.client.Login(context.Background(), present); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unrequested setup scope accepted: %v", err)
	}
	f = setup(t, step{status: 200, body: grant()}, step{status: 200, body: withSetup})
	f.client.config.Setup = true
	session, err := f.client.Login(context.Background(), present)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if f.forms[0].Get("scope") != "mcp:read mcp:setup" || !slices.Contains(session.Scopes(), "mcp:setup") {
		t.Fatalf("setup not requested or kept: %q %v", f.forms[0].Get("scope"), session.Scopes())
	}
}

// The token goes to the disconnect route only as a DELETE to that exact URL,
// and never there at all unless one is configured.
func TestDisconnectAuthorizationIsExact(t *testing.T) {
	_, session := renewable(t)
	del, _ := http.NewRequest(http.MethodDelete, "https://api.webdecoy.com/mcp/v1/connection", nil)
	if err := session.AuthorizeDisconnect(del); err == nil {
		t.Fatal("authorized with no disconnect URL configured")
	}
	session.client.config.DisconnectURL = "https://api.webdecoy.com/mcp/v1/connection"
	for _, bad := range []struct{ method, url string }{
		{http.MethodGet, "https://api.webdecoy.com/mcp/v1/connection"},
		{http.MethodDelete, "https://api.webdecoy.com/mcp/v1/connection?x=1"},
		{http.MethodDelete, "https://evil.example/mcp/v1/connection"},
		{http.MethodDelete, "https://api.webdecoy.com/mcp/v1/properties"},
	} {
		r, _ := http.NewRequest(bad.method, bad.url, nil)
		if err := session.AuthorizeDisconnect(r); err == nil || r.Header.Get("Authorization") != "" {
			t.Fatalf("%s %s was authorized", bad.method, bad.url)
		}
	}
	if err := session.AuthorizeDisconnect(del); err != nil || !strings.HasPrefix(del.Header.Get("Authorization"), "Bearer ") {
		t.Fatalf("the disconnect request was not authorized: %v", err)
	}
}
