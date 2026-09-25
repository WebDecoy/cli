package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestInspectProviderDoesNotTrustMetadataURLs(t *testing.T) {
	key := signingKey(t)
	var wrong atomic.Bool
	var requests atomic.Int32
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Error("preflight used credentials or mutated state")
		}
		if r.URL.Path == "/.well-known/jwks.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{publicKey(key, "key-1")}})
			return
		}
		jwks := issuer + ".well-known/jwks.json"
		if wrong.Load() {
			jwks = "http://169.254.169.254/credentials"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "authorize", "token_endpoint": issuer + "oauth/token", "jwks_uri": jwks,
			"device_authorization_endpoint": issuer + "oauth/device/code", "registration_endpoint": issuer + "oidc/register",
			"grant_types_supported":            []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
			"code_challenge_methods_supported": []string{"S256"}, "unknown_private_field": "secret",
		})
	}))
	defer server.Close()
	issuer = server.URL + "/"
	v := &Verifier{config: Config{Issuer: issuer}, keys: newKeyCache(issuer)}
	v.keys.client = server.Client()
	report, err := inspectProvider(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if !report.AuthorizationCodeAdvertised || !report.PKCES256Advertised || !report.DeviceCodeAdvertised || !report.TokenExchangeAdvertised || !report.RegistrationAdvertised || report.UsableSigningKeys != 1 || report.ApplicationGrantsVerified {
		t.Fatalf("incorrect capability report: %+v", report)
	}
	wrong.Store(true)
	_, err = inspectProvider(context.Background(), v)
	if err == nil || requests.Load() != 3 {
		t.Fatal("untrusted metadata URL accepted or fetched")
	}
}
