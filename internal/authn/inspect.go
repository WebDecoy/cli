package authn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"
)

// ProviderReport contains only public, allowlisted observations. Advertised
// features do not establish client grants, plan entitlement or a working login.
type ProviderReport struct {
	ObservedAt                  time.Time `json:"observed_at"`
	Issuer                      string    `json:"issuer"`
	AuthorizationCodeAdvertised bool      `json:"authorization_code_advertised"`
	PKCES256Advertised          bool      `json:"pkce_s256_advertised"`
	DeviceCodeAdvertised        bool      `json:"device_code_advertised"`
	TokenExchangeAdvertised     bool      `json:"token_exchange_advertised"`
	RegistrationAdvertised      bool      `json:"registration_advertised"`
	UsableSigningKeys           int       `json:"usable_rs256_signing_keys"`
	ApplicationGrantsVerified   bool      `json:"application_grants_verified"`
}

func InspectProvider(ctx context.Context, issuer string) (*ProviderReport, error) {
	v, err := New(Config{Issuer: issuer, Audience: "public-metadata-preflight"})
	if err != nil {
		return nil, err
	}
	return inspectProvider(ctx, v)
}

func inspectProvider(ctx context.Context, v *Verifier) (*ProviderReport, error) {
	issuer := v.config.Issuer
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+".well-known/openid-configuration", nil)
	if err != nil {
		return nil, errors.New("invalid provider metadata configuration")
	}
	resp, err := v.keys.client.Do(req)
	if err != nil {
		return nil, errors.New("provider metadata unavailable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil || resp.StatusCode != 200 || len(body) > MaxJWKSBytes {
		return nil, errors.New("provider metadata unavailable")
	}
	var metadata struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		DeviceEndpoint        string   `json:"device_authorization_endpoint"`
		RegistrationEndpoint  string   `json:"registration_endpoint"`
		GrantTypes            []string `json:"grant_types_supported"`
		ChallengeMethods      []string `json:"code_challenge_methods_supported"`
	}
	if json.Unmarshal(body, &metadata) != nil || metadata.Issuer != issuer ||
		metadata.AuthorizationEndpoint != issuer+"authorize" || metadata.TokenEndpoint != issuer+"oauth/token" ||
		metadata.JWKSURI != issuer+".well-known/jwks.json" ||
		(metadata.DeviceEndpoint != "" && metadata.DeviceEndpoint != issuer+"oauth/device/code") ||
		(metadata.RegistrationEndpoint != "" && metadata.RegistrationEndpoint != issuer+"oidc/register") {
		return nil, errors.New("provider metadata does not match the configured Auth0 issuer")
	}
	keys, err := v.keys.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return &ProviderReport{
		ObservedAt: time.Now().UTC(), Issuer: issuer,
		AuthorizationCodeAdvertised: slices.Contains(metadata.GrantTypes, "authorization_code"),
		PKCES256Advertised:          slices.Contains(metadata.ChallengeMethods, "S256"),
		DeviceCodeAdvertised:        metadata.DeviceEndpoint != "" && slices.Contains(metadata.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code"),
		TokenExchangeAdvertised:     slices.Contains(metadata.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange"),
		RegistrationAdvertised:      metadata.RegistrationEndpoint != "",
		UsableSigningKeys:           len(keys),
	}, nil
}
