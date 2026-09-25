package deviceauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/WebDecoy/cli/internal/authn"
)

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	Scope        *string `json:"scope"`
}

// Session keeps credentials in process memory only. Formatting and JSON
// serialization never reveal them. There is deliberately no token getter.
type Session struct {
	mu      sync.Mutex
	client  *Client
	access  string
	refresh string
	subject string
	expires time.Time
	scope   string
	closed  bool
}

func (s *Session) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte("[device session: credentials redacted]"))
}
func (s *Session) MarshalJSON() ([]byte, error) { return []byte(`{"credentials":"redacted"}`), nil }

func (c *Client) session(ctx context.Context, response tokenResponse, scope, subject string) (*Session, error) {
	if !strings.EqualFold(response.TokenType, "Bearer") || !credential(response.AccessToken) ||
		response.ExpiresIn <= 0 || response.ExpiresIn > int64(authn.MaxTokenLifetime/time.Second) ||
		(response.RefreshToken != "" && !credential(response.RefreshToken)) {
		return nil, ErrInvalidToken
	}
	if response.Scope != nil {
		scope = *response.Scope
	}
	read := false
	for _, permission := range strings.Split(scope, " ") {
		switch permission {
		case authn.ReadScope:
			read = true
		case "offline_access":
			if !c.config.OfflineAccess {
				return nil, ErrInvalidToken
			}
		case SetupScope:
			if !c.config.Setup {
				return nil, ErrInvalidToken
			}
		default:
			return nil, ErrInvalidToken
		}
	}
	if !read {
		return nil, ErrInvalidToken
	}
	identity, err := c.verify(ctx, response.AccessToken)
	if err != nil || identity == nil || identity.ClientID != c.config.ClientID || (subject != "" && identity.Subject != subject) {
		return nil, ErrInvalidToken
	}
	if !identity.ExpiresAt.After(c.now()) {
		return nil, ErrInvalidToken
	}
	if !slices.Contains(identity.Scopes, authn.ReadScope) {
		return nil, ErrInvalidToken
	}
	for _, permission := range identity.Scopes {
		if !slices.Contains(strings.Split(scope, " "), permission) {
			return nil, ErrInvalidToken
		}
	}
	refresh := response.RefreshToken
	if !c.config.OfflineAccess {
		refresh = ""
	}
	expires := minTime(identity.ExpiresAt, c.now().Add(time.Duration(response.ExpiresIn)*time.Second))
	return &Session{client: c, access: response.AccessToken, refresh: refresh, subject: identity.Subject, expires: expires, scope: scope}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Session) ExpiresAt() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.expires }

// Subject is the verified user the session belongs to. It is an identifier,
// not a credential.
func (s *Session) Subject() string { s.mu.Lock(); defer s.mu.Unlock(); return s.subject }

// Scopes are the permissions the current access token carries.
func (s *Session) Scopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Fields(s.scope)
}

// Persist hands the refresh credential to save, the caller's secure store,
// and nothing else. It is the only way the credential leaves this package;
// there is still no getter. A session without one saves nothing.
func (s *Session) Persist(save func(refresh string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.refresh == "" {
		return ErrNoRefresh
	}
	return save(s.refresh)
}

// Resume builds a session from a stored refresh credential by renewing it
// once, which verifies the resulting token exactly as a login does. Failure
// leaves nothing usable: the caller asks the human to log in again.
func (c *Client) Resume(ctx context.Context, refresh string) (*Session, error) {
	if !c.config.OfflineAccess || !credential(refresh) {
		return nil, ErrNoRefresh
	}
	s := &Session{client: c, refresh: refresh, scope: c.requestedScope(), expires: c.now()}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Authorize adds a bearer token only to the exact configured hosted resource.
// It neither refreshes implicitly nor makes a network request. Callers must
// disable HTTP redirects when using the resulting request.
func (s *Session) Authorize(r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if !s.expires.After(s.client.now()) {
		return ErrExpired
	}
	if r == nil || r.URL == nil || r.URL.String() != s.client.config.Resource || (r.Host != "" && r.Host != r.URL.Host) {
		return ErrInvalidResponse
	}
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("Authorization", "Bearer "+s.access)
	return nil
}

// AuthorizeDisconnect adds the bearer token to the one request that ends
// this app's connection: a DELETE to the configured disconnect URL, exactly.
func (s *Session) AuthorizeDisconnect(r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if !s.expires.After(s.client.now()) {
		return ErrExpired
	}
	target := s.client.config.DisconnectURL
	if target == "" || r == nil || r.URL == nil || r.Method != http.MethodDelete || r.URL.String() != target || (r.Host != "" && r.Host != r.URL.Host) {
		return ErrInvalidResponse
	}
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("Authorization", "Bearer "+s.access)
	return nil
}

// Refresh makes exactly one renewal request. An ambiguous network failure can
// consume a rotating token, so any failure closes the local session; there is
// no automatic retry or refresh loop. Account changes require a fresh login.
func (s *Session) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.refresh == "" {
		return ErrNoRefresh
	}
	var response tokenResponse
	err := s.client.post(ctx, "oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {s.client.config.ClientID}, "refresh_token": {s.refresh}, "audience": {s.client.config.Resource}}, &response)
	if err != nil {
		s.clear()
		return ErrUnavailable
	}
	next, err := s.client.session(ctx, response, s.scope, s.subject)
	if err != nil {
		s.clear()
		return err
	}
	if next.refresh == "" {
		next.refresh = s.refresh
	}
	s.access, s.refresh, s.expires, s.scope = next.access, next.refresh, next.expires, next.scope
	if s.subject == "" {
		// A resumed session learns its user from the first verified token;
		// every later renewal must then match it.
		s.subject = next.subject
	}
	next.clear()
	return nil
}

// Revoke discards local credentials even if the provider is unavailable. This
// revokes only refresh credentials; backend connection revocation is separate
// and must be implemented before the CLI can claim to disconnect an MCP grant.
func (s *Session) Revoke(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	defer s.clear()
	if s.refresh == "" {
		return nil
	}
	if err := s.client.post(ctx, "oauth/revoke", url.Values{"client_id": {s.client.config.ClientID}, "token": {s.refresh}, "token_type_hint": {"refresh_token"}}, nil); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Close forgets the local credentials. It does not revoke remote access and
// does not promise cryptographic zeroization of Go-managed memory.
func (s *Session) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.clear() }
func (s *Session) clear() { s.access = ""; s.refresh = ""; s.subject = ""; s.closed = true }
