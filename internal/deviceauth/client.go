// Package deviceauth implements bounded Auth0 RFC 8628 login for the first-party
// local client. It authenticates a user; it never grants WebDecoy site access.
package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WebDecoy/cli/internal/authn"
)

const (
	MaxLoginDuration   = 15 * time.Minute
	MaxPolls           = 180
	MaxTimeoutRetries  = 3
	MaxResponseBytes   = 32 << 10
	MaxCredentialBytes = 8 << 10
)

var (
	ErrDenied          = errors.New("device authorization denied")
	ErrExpired         = errors.New("device authorization expired; start a new login")
	ErrUnavailable     = errors.New("device authorization unavailable; retry login later")
	ErrInvalidResponse = errors.New("invalid device authorization response")
	ErrInvalidToken    = errors.New("device access token failed validation")
	ErrNoRefresh       = errors.New("this session has no refresh credential")
	ErrClosed          = errors.New("device session is closed")
)

type Config struct {
	Issuer   string
	Resource string
	ClientID string
	// OfflineAccess must only be requested when a caller can keep the returned
	// credential secure. The diagnostic command uses session-only mode.
	OfflineAccess bool
	// Setup also requests mcp:setup, for the two setup tools. Auth0 grants it
	// only if the client is allowed it; the login still succeeds without.
	Setup bool
	// DisconnectURL is the one other place the token may go: the backend
	// route that ends this app's own connection, and only as a DELETE.
	DisconnectURL string
}

// Prompt is intended only for a human-owned terminal, never MCP stdio or tool
// results. It contains no device code, access token, or refresh credential.
type Prompt struct {
	VerificationURI string
	UserCode        string
	ExpiresAt       time.Time
}

type Client struct {
	config  Config
	http    *http.Client
	verify  func(context.Context, string) (*authn.Identity, error)
	now     func() time.Time
	wait    func(context.Context, time.Duration) error
	loginMu sync.Mutex
}

func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Resource)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/mcp" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.Resource, "#") ||
		u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") || c.ClientID == "" {
		return nil, errors.New("device login requires a canonical HTTPS MCP resource and a public client ID")
	}
	if c.DisconnectURL != "" {
		d, err := url.Parse(c.DisconnectURL)
		if err != nil || d.Scheme != "https" || d.User != nil || d.RawQuery != "" || d.Fragment != "" || d.Host != strings.ToLower(d.Host) {
			return nil, errors.New("the disconnect URL must be a canonical HTTPS URL")
		}
	}
	verifier, err := authn.New(authn.Config{Issuer: c.Issuer, Audience: c.Resource, ClientIDs: []string{c.ClientID}})
	if err != nil {
		return nil, err
	}
	return &Client{config: c, http: authn.NewPublicClient(), verify: verifier.Verify, now: time.Now, wait: wait}, nil
}

func (c *Client) requestedScope() string {
	scope := authn.ReadScope
	if c.config.Setup {
		scope += " " + SetupScope
	}
	if c.config.OfflineAccess {
		scope += " offline_access"
	}
	return scope
}

// SetupScope is the hosted service's permission for its two setup tools.
const SetupScope = "mcp:setup"

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Login makes one device-code request and bounded polling attempts. A caller
// must explicitly invoke Login again after denial/expiry/failure. Presentation
// errors stop login, and no verification URL is opened automatically.
func (c *Client) Login(ctx context.Context, present func(Prompt) error) (*Session, error) {
	if present == nil {
		return nil, errors.New("a human device-code presenter is required")
	}
	if !c.loginMu.TryLock() {
		return nil, errors.New("device login already in progress")
	}
	defer c.loginMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, MaxLoginDuration)
	defer cancel()
	started := c.now()
	scope := c.requestedScope()
	var grant struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int64  `json:"expires_in"`
		Interval        *int64 `json:"interval"`
	}
	// Auth0's device and token endpoints refuse the RFC 8707 resource
	// parameter ("does not yet support"), so the MCP resource travels as the
	// audience only. The returned token's audience is still verified.
	err := c.post(ctx, "oauth/device/code", url.Values{"client_id": {c.config.ClientID}, "audience": {c.config.Resource}, "scope": {scope}}, &grant)
	if err != nil {
		return nil, err
	}
	defer func() { grant.DeviceCode = "" }()
	if !credential(grant.DeviceCode) || !userCode(grant.UserCode) || grant.VerificationURI != c.config.Issuer+"activate" || grant.ExpiresIn <= 0 ||
		(grant.Interval != nil && (*grant.Interval <= 0 || *grant.Interval > 60)) {
		return nil, ErrInvalidResponse
	}
	lifetime := min(grant.ExpiresIn, int64(MaxLoginDuration/time.Second))
	expires := started.Add(time.Duration(lifetime) * time.Second)
	interval := 5 * time.Second
	if grant.Interval != nil {
		interval = max(interval, time.Duration(*grant.Interval)*time.Second)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !c.now().Before(expires) {
		return nil, ErrExpired
	}
	if err := present(Prompt{VerificationURI: grant.VerificationURI, UserCode: grant.UserCode, ExpiresAt: expires}); err != nil {
		return nil, errors.New("device login presentation cancelled")
	}
	timeouts := 0
	for attempt := 0; attempt < MaxPolls; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !c.now().Add(interval).Before(expires) {
			return nil, ErrExpired
		}
		if err := c.wait(ctx, interval); err != nil {
			return nil, err
		}
		if !c.now().Before(expires) {
			return nil, ErrExpired
		}
		var response tokenResponse
		// Waiting starts after the previous HTTP response, never from a ticker
		// that could accumulate ticks while the provider request is in flight.
		err := c.post(ctx, "oauth/token", url.Values{"client_id": {c.config.ClientID}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {grant.DeviceCode}, "audience": {c.config.Resource}}, &response)
		if err == nil {
			if !c.now().Before(expires) {
				return nil, ErrExpired
			}
			return c.session(ctx, response, scope, "")
		}
		var protocol *protocolError
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.As(err, &protocol):
			switch protocol.code {
			case "authorization_pending":
			case "slow_down":
				interval = max(interval+5*time.Second, protocol.retryAfter)
			case "access_denied":
				return nil, ErrDenied
			case "expired_token":
				return nil, ErrExpired
			default:
				return nil, ErrUnavailable
			}
		case errors.Is(err, errTimeout):
			timeouts++
			if timeouts > MaxTimeoutRetries {
				return nil, ErrUnavailable
			}
			interval *= 2
		default:
			return nil, err
		}
	}
	return nil, ErrExpired
}

func userCode(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && ch != '-' {
			return false
		}
	}
	return true
}

func credential(s string) bool {
	return len(s) > 0 && len(s) <= MaxCredentialBytes && !strings.ContainsAny(s, "\r\n\x00")
}

var errTimeout = errors.New("authorization request timed out")

type protocolError struct {
	code       string
	retryAfter time.Duration
}

func (e *protocolError) Error() string { return "authorization request rejected" }

func (c *Client) post(ctx context.Context, path string, form url.Values, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Issuer+path, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var network net.Error
		if errors.As(err, &network) && network.Timeout() {
			return errTimeout
		}
		return ErrUnavailable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var network net.Error
		if errors.As(err, &network) && network.Timeout() {
			return errTimeout
		}
		return ErrInvalidResponse
	}
	if len(body) > MaxResponseBytes {
		return ErrInvalidResponse
	}
	if resp.StatusCode == 200 {
		if result == nil {
			return nil
		}
		if json.Unmarshal(body, result) != nil {
			return ErrInvalidResponse
		}
		return nil
	}
	// Auth0 uses 403 for pending/denied/expired and 429 for slow_down.
	// Generic overload, 5xx, redirects and unknown errors remain terminal.
	// Provider text is never returned to the CLI, log or model.
	if resp.StatusCode != 400 && resp.StatusCode != 403 && resp.StatusCode != 429 {
		return ErrUnavailable
	}
	var failure struct {
		Code string `json:"error"`
	}
	if json.Unmarshal(body, &failure) != nil {
		return ErrInvalidResponse
	}
	if resp.StatusCode == 429 && failure.Code != "slow_down" {
		return ErrUnavailable
	}
	switch failure.Code {
	case "authorization_pending", "slow_down", "access_denied", "expired_token", "invalid_grant":
		delay := time.Duration(0)
		if failure.Code == "slow_down" {
			if value := resp.Header.Get("Retry-After"); value != "" {
				if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
					delay = time.Duration(min(seconds, int64(MaxLoginDuration/time.Second))) * time.Second
				} else if date, err := http.ParseTime(value); err == nil {
					delay = min(MaxLoginDuration, max(time.Duration(0), date.Sub(c.now())))
				} else {
					return ErrUnavailable
				}
			}
		}
		return &protocolError{code: failure.Code, retryAfter: delay}
	default:
		return ErrUnavailable
	}
}
