package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKey(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"iss": "https://tenant.auth0.com/", "aud": "https://mcp.webdecoy.com/mcp",
		"sub": "auth0|customer", "azp": "approved-client", "scope": "mcp:read",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(4 * time.Minute).Unix()}
}

func sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testVerifier(t *testing.T, handler http.Handler) *Verifier {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	v, err := New(Config{Issuer: "https://tenant.auth0.com/", Audience: "https://mcp.webdecoy.com/mcp", ClientIDs: []string{"approved-client", "device-client"}})
	if err != nil {
		t.Fatal(err)
	}
	// Only package tests replace the public-network transport and fixed URL.
	v.keys.client = server.Client()
	v.keys.url = server.URL + "/.well-known/jwks.json"
	return v
}

func TestVerifyAccessTokens(t *testing.T) {
	key := signingKey(t)
	otherKey := signingKey(t)
	var calls atomic.Int32
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/.well-known/jwks.json" || r.Header.Get("Authorization") != "" {
			t.Error("unsafe metadata request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
	}))
	for _, tc := range []struct {
		name   string
		change func(jwt.MapClaims)
		want   error
	}{
		{"hosted user", func(jwt.MapClaims) {}, nil},
		{"device user", func(c jwt.MapClaims) { c["azp"] = "device-client" }, nil},
		{"RFC9068 client", func(c jwt.MapClaims) { delete(c, "azp"); c["client_id"] = "approved-client" }, nil},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example/" }, ErrInvalidToken},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "https://api.webdecoy.com" }, ErrInvalidToken},
		{"missing audience", func(c jwt.MapClaims) { delete(c, "aud") }, ErrInvalidToken},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, ErrInvalidToken},
		{"missing expiration", func(c jwt.MapClaims) { delete(c, "exp") }, ErrInvalidToken},
		{"missing issued-at", func(c jwt.MapClaims) { delete(c, "iat") }, ErrInvalidToken},
		{"future issued-at", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Minute).Unix() }, ErrInvalidToken},
		{"future not-before", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, ErrInvalidToken},
		{"long lifetime", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(time.Hour).Unix() }, ErrInvalidToken},
		{"expired before issued", func(c jwt.MapClaims) { c["exp"] = c["iat"] }, ErrInvalidToken},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }, ErrInvalidToken},
		{"service subject", func(c jwt.MapClaims) { c["sub"] = "approved-client@clients" }, ErrInvalidToken},
		{"service grant", func(c jwt.MapClaims) { c["gty"] = "client-credentials" }, ErrInvalidToken},
		{"missing client", func(c jwt.MapClaims) { delete(c, "azp") }, ErrInvalidToken},
		{"unknown client", func(c jwt.MapClaims) { c["azp"] = "unapproved-client" }, ErrInvalidToken},
		{"conflicting client", func(c jwt.MapClaims) { c["client_id"] = "device-client" }, ErrInvalidToken},
		{"missing scope", func(c jwt.MapClaims) { delete(c, "scope") }, ErrInsufficientScope},
		{"write scope only", func(c jwt.MapClaims) { c["scope"] = "mcp:write" }, ErrInsufficientScope},
		{"scope substring", func(c jwt.MapClaims) { c["scope"] = "mcp:read-all" }, ErrInsufficientScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			tc.change(claims)
			identity, err := v.Verify(context.Background(), sign(t, key, claims, "key-1"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (identity == nil || identity.Subject != "auth0|customer" || identity.ClientID == "" || identity.ExpiresAt.IsZero()) {
				t.Fatalf("identity = %+v", identity)
			}
			if tc.want != nil && identity != nil {
				t.Fatal("failed token established identity")
			}
		})
	}
	for _, raw := range []string{"", "not.a.jwt", strings.Repeat("x", MaxTokenBytes+1), sign(t, otherKey, validClaims(), "key-1")} {
		if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("invalid credential: %v", err)
		}
	}
	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	hmac.Header["kid"] = "key-1"
	raw, _ := hmac.SignedString([]byte("attacker-key"))
	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("algorithm confusion accepted")
	}
	for i := 0; i < 32; i++ {
		if _, err := v.Verify(context.Background(), sign(t, key, validClaims(), fmt.Sprintf("unknown-%d", i))); !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unknown IDs amplified key fetches: %d", calls.Load())
	}
	// Remote key references supplied by a token are ignored; only the pinned
	// issuer's cached key can verify its signature.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims())
	token.Header["kid"] = "key-1"
	token.Header["jku"] = "http://169.254.169.254/secret"
	token.Header["x5u"] = "https://evil.example/key"
	raw, _ = token.SignedString(key)
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("remote token key reference was fetched")
	}
}

func TestRejectBeforeRemoteWork(t *testing.T) {
	var calls atomic.Int32
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	key := signingKey(t)
	claims := validClaims()
	claims["aud"] = "https://api.webdecoy.com"
	_, _ = v.Verify(context.Background(), sign(t, key, claims, "key-1"))
	_, _ = v.Verify(context.Background(), "invalid")
	v.config.ClientIDs = nil
	_, _ = v.Verify(context.Background(), sign(t, key, validClaims(), "key-1"))
	if calls.Load() != 0 {
		t.Fatal("unrelated credentials triggered remote work")
	}
}

func TestKeyRotationAndFailureBackoff(t *testing.T) {
	key := signingKey(t)
	var fail atomic.Bool
	var calls atomic.Int32
	var rotation atomic.Bool
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "sensitive provider detail", 503)
			return
		}
		kid := "key-1"
		if rotation.Load() {
			kid = "key-2"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, kid)}})
	}))
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	v.keys.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	verify := func(kid string, want error) {
		t.Helper()
		_, err := v.Verify(context.Background(), sign(t, key, validClaims(), kid))
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", kid, err, want)
		}
	}
	verify("key-1", nil)
	rotation.Store(true)
	verify("key-2", ErrInvalidToken)
	clock.Add(int64(KeyCacheTTL / time.Second))
	verify("key-2", nil)
	verify("key-1", ErrInvalidToken)
	fail.Store(true)
	clock.Add(int64(KeyCacheTTL / time.Second))
	for i := 0; i < 8; i++ {
		verify("key-2", ErrKeysUnavailable)
	}
	if calls.Load() != 3 {
		t.Fatalf("failure amplified fetches: %d", calls.Load())
	}
	fail.Store(false)
	clock.Add(int64(KeyFailureBackoff / time.Second))
	verify("key-2", nil)
}

func TestSharedRefreshAndCancellation(t *testing.T) {
	key := signingKey(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := sign(t, key, validClaims(), "key-1")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = v.Verify(ctx, raw) }()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("fetch did not start")
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiters ignored cancellation")
	}
	if len(entered) != 0 {
		t.Fatal("more than one refresh started")
	}
}

func TestJWKSBounds(t *testing.T) {
	key := signingKey(t)
	for _, tc := range []struct {
		name     string
		document func() any
	}{
		{"empty", func() any { return map[string]any{"keys": []any{}} }},
		{"duplicate", func() any { return map[string]any{"keys": []any{publicKey(key, "same"), publicKey(key, "same")}} }},
		{"too many keys", func() any {
			keys := []any{}
			for i := 0; i <= MaxJWKSKeys; i++ {
				keys = append(keys, publicKey(key, fmt.Sprint(i)))
			}
			return map[string]any{"keys": keys}
		}},
		{"wrong key use", func() any { k := publicKey(key, "key-1"); k["use"] = "enc"; return map[string]any{"keys": []any{k}} }},
		{"weak key", func() any { k := publicKey(key, "key-1"); k["n"] = "AQAB"; return map[string]any{"keys": []any{k}} }},
		{"invalid exponent", func() any { k := publicKey(key, "key-1"); k["e"] = "AA"; return map[string]any{"keys": []any{k}} }},
		{"oversized body", func() any {
			return map[string]any{"padding": strings.Repeat("x", MaxJWKSBytes), "keys": []any{publicKey(key, "key-1")}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(tc.document()) }))
			_, err := v.Verify(context.Background(), sign(t, key, validClaims(), "key-1"))
			if !errors.Is(err, ErrKeysUnavailable) {
				t.Fatalf("unsafe JWKS accepted: %v", err)
			}
		})
	}
}

// With "*", any client the issuer registered may authenticate a user. Machine
// identities, oversized client IDs and missing scope are still refused: what
// the user shares is decided by their per-app connection, not by this list.
func TestAnyRegisteredClient(t *testing.T) {
	if _, err := New(Config{Issuer: "https://tenant.auth0.com/", Audience: "https://mcp.webdecoy.com/mcp", ClientIDs: []string{"*", "approved-client"}}); err == nil {
		t.Fatal("* mixed with explicit IDs was accepted")
	}
	key := signingKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
	}))
	t.Cleanup(server.Close)
	v, err := New(Config{Issuer: "https://tenant.auth0.com/", Audience: "https://mcp.webdecoy.com/mcp", ClientIDs: []string{AnyClient}})
	if err != nil {
		t.Fatal(err)
	}
	v.keys.client = server.Client()
	v.keys.url = server.URL + "/.well-known/jwks.json"
	for name, tc := range map[string]struct {
		change func(jwt.MapClaims)
		want   error
	}{
		"dynamically registered": {func(c jwt.MapClaims) { c["azp"] = "dcr-7f3a" }, nil},
		"metadata document URL":  {func(c jwt.MapClaims) { c["azp"] = "https://client.example/oauth/metadata.json" }, nil},
		"service grant":          {func(c jwt.MapClaims) { c["azp"] = "dcr-7f3a"; c["gty"] = "client-credentials" }, ErrInvalidToken},
		"service subject":        {func(c jwt.MapClaims) { c["sub"] = "dcr-7f3a@clients" }, ErrInvalidToken},
		"oversized client":       {func(c jwt.MapClaims) { c["azp"] = strings.Repeat("a", 513) }, ErrInvalidToken},
		"whitespace client":      {func(c jwt.MapClaims) { c["azp"] = "a b" }, ErrInvalidToken},
		"missing scope":          {func(c jwt.MapClaims) { c["azp"] = "dcr-7f3a"; delete(c, "scope") }, ErrInsufficientScope},
	} {
		claims := validClaims()
		tc.change(claims)
		_, err := v.Verify(context.Background(), sign(t, key, claims, "key-1"))
		if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

func TestRefusalsNameAReasonWithoutTheToken(t *testing.T) {
	key := signingKey(t)
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
	}))
	for want, change := range map[string]func(jwt.MapClaims){
		"audience": func(c jwt.MapClaims) { c["aud"] = "https://webdecoy.us.auth0.com/userinfo" },
		"expired": func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		},
		"client_not_allowed": func(c jwt.MapClaims) { c["azp"] = "someone-else" },
		"lifetime":           func(c jwt.MapClaims) { c["exp"] = time.Now().Add(time.Hour).Unix() },
	} {
		claims := validClaims()
		change(claims)
		raw := sign(t, key, claims, "key-1")
		_, err := v.Verify(context.Background(), raw)
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != want || !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: got %v", want, err)
		}
		if r != nil && strings.Contains(fmt.Sprintf("%+v %v", r, err), raw[:20]) {
			t.Errorf("%s: refusal carries the token", want)
		}
	}
	if _, err := v.Verify(context.Background(), "opaque-token-value"); err == nil || !strings.Contains(err.Error(), "not_a_jwt") {
		t.Errorf("opaque token: %v", err)
	}
}

// Ready is true once keys can be had, false while the provider fails, and
// asking repeatedly during the failure backoff makes no extra JWKS requests.
func TestReadyFollowsTheKeyCache(t *testing.T) {
	key := signingKey(t)
	var fail atomic.Bool
	var calls atomic.Int32
	v := testVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "down", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
	}))
	if err := v.Ready(context.Background()); err != nil {
		t.Fatalf("keys available: %v", err)
	}
	var clock atomic.Int64
	clock.Store(time.Now().Add(KeyCacheTTL + time.Second).Unix())
	v.keys.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	fail.Store(true)
	if err := v.Ready(context.Background()); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("provider down: %v", err)
	}
	before := calls.Load()
	for i := 0; i < 20; i++ {
		_ = v.Ready(context.Background())
	}
	if calls.Load() != before {
		t.Fatalf("readiness during backoff made %d JWKS requests", calls.Load()-before)
	}
}
