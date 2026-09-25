// Package authn verifies Auth0 access tokens for the MCP resource. A verified
// identity is not a connection grant or permission to read customer data.
package authn

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// AnyClient in the client list admits every client the issuer registered
	// (dynamic registration and client ID metadata documents). What a client
	// may read is then decided only by the user's per-app connection.
	AnyClient        = "*"
	maxClientID      = 512
	ReadScope        = "mcp:read"
	MaxTokenBytes    = 8 << 10
	MaxTokenLifetime = 15 * time.Minute
	ClockSkew        = 30 * time.Second
)

// Refusal carries why a token was refused, for operator logs only. It names a
// fixed reason and non-secret claim values (audience, client); never the token.
type Refusal struct {
	Reason   string
	Audience []string
	Client   string
}

func (r *Refusal) Error() string { return "invalid access token: " + r.Reason }
func (r *Refusal) Unwrap() error { return ErrInvalidToken }

var (
	ErrInvalidToken      = errors.New("invalid access token")
	ErrInsufficientScope = errors.New("insufficient scope")
	ErrKeysUnavailable   = errors.New("signing keys unavailable")
)

type Config struct {
	Issuer    string
	Audience  string
	ClientIDs []string
}

// Identity deliberately excludes the raw JWT and arbitrary provider claims.
// The backend must still intersect an original site grant with current access.
type Identity struct {
	Subject   string
	ClientID  string
	ExpiresAt time.Time
	Scopes    []string
}

type claims struct {
	jwt.RegisteredClaims
	Scope           string `json:"scope"`
	AuthorizedParty string `json:"azp"`
	ClientID        string `json:"client_id"`
	GrantType       string `json:"gty"`
}

type Verifier struct {
	config Config
	keys   *keyCache
}

func New(c Config) (*Verifier, error) {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "/" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.Issuer, "#") ||
		u.RawPath != "" || u.Port() != "" || u.Host != strings.ToLower(u.Host) ||
		strings.HasSuffix(u.Host, ".") || c.Audience == "" {
		return nil, errors.New("Auth0 issuer must be a canonical HTTPS origin and audience is required")
	}
	if len(c.ClientIDs) > 16 {
		return nil, errors.New("at most 16 MCP client IDs may be configured")
	}
	if slices.Contains(c.ClientIDs, AnyClient) && len(c.ClientIDs) != 1 {
		return nil, errors.New("MCP client IDs must be either * alone or explicit IDs")
	}
	for _, id := range c.ClientIDs {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, " \t\r\n,") {
			return nil, errors.New("invalid MCP client ID configuration")
		}
	}
	c.ClientIDs = slices.Clone(c.ClientIDs)
	return &Verifier{config: c, keys: newKeyCache(c.Issuer)}, nil
}

// Ready reports whether signing keys can be had right now: a fresh cache, or a
// fetch that succeeds within ctx. It shares the cache's single bounded
// refresh and failure backoff, so asking often cannot multiply JWKS traffic.
func (v *Verifier) Ready(ctx context.Context) error {
	if _, err := v.keys.key(ctx, ""); errors.Is(err, ErrKeysUnavailable) {
		return err
	}
	return nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (*Identity, error) {
	if ctx.Err() != nil || len(raw) == 0 || len(raw) > MaxTokenBytes {
		return nil, &Refusal{Reason: "empty_or_oversized"}
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithLeeway(ClockSkew),
	}
	// Reject malformed/unrelated tokens before they can trigger remote work.
	// Unverified claims never leave this function or establish identity, except
	// as the non-secret audience/client values in a Refusal for operator logs.
	c := &claims{}
	token, _, err := jwt.NewParser(opts...).ParseUnverified(raw, c)
	if err != nil {
		return nil, &Refusal{Reason: "not_a_jwt"}
	}
	client := c.AuthorizedParty
	if client == "" {
		client = c.ClientID
	}
	refuse := func(reason string) error {
		r := &Refusal{Reason: reason, Audience: c.Audience}
		if len(client) <= maxClientID {
			r.Client = client
		}
		return r
	}
	if token.Method.Alg() != "RS256" {
		return nil, refuse("algorithm")
	}
	if err := jwt.NewValidator(opts...).Validate(c); err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, refuse("audience")
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, refuse("issuer")
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, refuse("expired")
		default:
			return nil, refuse("claims")
		}
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || len(kid) == 0 || len(kid) > 128 || token.Header["crit"] != nil {
		return nil, refuse("key_id")
	}
	switch {
	case c.ClientID != "" && c.AuthorizedParty != "" && c.ClientID != c.AuthorizedParty:
		return nil, refuse("conflicting_client")
	case client == "" || len(client) > maxClientID || strings.ContainsAny(client, " \t\r\n"):
		return nil, refuse("client_format")
	case !(slices.Contains(v.config.ClientIDs, AnyClient) || slices.Contains(v.config.ClientIDs, client)):
		return nil, refuse("client_not_allowed")
	case c.Subject == "" || len(c.Subject) > 256 || strings.HasSuffix(c.Subject, "@clients") || c.GrantType == "client-credentials":
		return nil, refuse("service_identity")
	case c.IssuedAt == nil || c.ExpiresAt == nil || !c.ExpiresAt.After(c.IssuedAt.Time) ||
		c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxTokenLifetime:
		return nil, refuse("lifetime")
	}
	key, err := v.keys.key(ctx, kid)
	if err != nil {
		return nil, err
	}
	verified := &claims{}
	if _, err := jwt.ParseWithClaims(raw, verified, func(*jwt.Token) (any, error) { return key, nil }, opts...); err != nil {
		return nil, refuse("signature")
	}
	if !slices.Contains(strings.Split(verified.Scope, " "), ReadScope) {
		return nil, ErrInsufficientScope
	}
	return &Identity{Subject: verified.Subject, ClientID: client, ExpiresAt: verified.ExpiresAt.Time, Scopes: strings.Split(verified.Scope, " ")}, nil
}
