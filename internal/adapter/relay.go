// Package adapter is the WebDecoy CLI's local MCP server: it speaks
// MCP over stdio to an assistant and relays every message, unchanged, to the
// hosted service with the user's stored login. It has no tools or rules of its
// own, so the hosted service's tools, scopes, limits and errors apply exactly
// as they do to a hosted client. Nothing but protocol messages is written to
// stdout; diagnostics go to stderr and never carry a credential.
package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// MaxMessageBytes matches the hosted service's request limit.
	MaxMessageBytes  = 64 << 10
	maxResponseBytes = 1 << 20
	maxConcurrent    = 4
	requestTimeout   = 20 * time.Second
)

// Authorizer supplies the bearer token for the hosted resource.
type Authorizer interface {
	Authorize(ctx context.Context, r *http.Request) error
	Invalidate()
}

// Relay forwards stdio MCP messages to the hosted resource.
type Relay struct {
	Resource string
	Auth     Authorizer
	HTTP     *http.Client

	outMu    sync.Mutex
	out      io.Writer
	version  string
	verMu    sync.Mutex
	inFlight sync.Map // request id (raw JSON) -> context.CancelFunc
}

// NewHTTPClient is the relay's client: no redirects, bounded time. A bearer
// token must never follow a redirect to another host.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10},
	}
}

type envelope struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Serve reads newline-delimited messages from in until it ends or ctx is
// cancelled, and writes responses to out.
func (r *Relay) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	r.out = out
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), MaxMessageBytes)
	seats := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := append([]byte(nil), line...)
		var env envelope
		if err := json.Unmarshal(msg, &env); err != nil {
			r.writeError(nil, -32700, "Parse error")
			continue
		}
		if env.Method == "notifications/cancelled" {
			r.cancel(env.Params)
		}
		select {
		case seats <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-seats }()
			r.forward(ctx, msg, env)
		}()
	}
	if errors.Is(scanner.Err(), bufio.ErrTooLong) {
		r.writeError(nil, -32600, "Message larger than the WebDecoy MCP limit")
	}
	return scanner.Err()
}

func (r *Relay) cancel(params json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(params, &p) == nil && len(p.RequestID) > 0 {
		if cancel, ok := r.inFlight.Load(string(p.RequestID)); ok {
			cancel.(context.CancelFunc)()
		}
	}
}

func (r *Relay) forward(ctx context.Context, msg []byte, env envelope) {
	isRequest := len(env.ID) > 0 && env.Method != ""
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if isRequest {
		r.inFlight.Store(string(env.ID), cancel)
		defer r.inFlight.Delete(string(env.ID))
	}
	status, body, err := r.post(ctx, msg, true)
	switch {
	case errors.Is(err, ErrNotSignedIn):
		r.fail(isRequest, env.ID, "Not signed in to WebDecoy. Run `webdecoy login` in a terminal, then try again.")
	case errors.Is(err, ErrLoginInvalid):
		r.fail(isRequest, env.ID, "Your WebDecoy login expired or was revoked. Run `webdecoy login` in a terminal, then try again.")
	case errors.Is(err, ErrCredentialStore):
		r.fail(isRequest, env.ID, "Could not read the WebDecoy login from this system's credential store. On Linux, check that a Secret Service (for example gnome-keyring) is running.")
	case ctx.Err() != nil:
		// Cancelled by the client or shutting down: nothing to answer.
	case err != nil:
		r.fail(isRequest, env.ID, "Could not reach WebDecoy. Check the network and try again.")
	case status == http.StatusAccepted || (status == http.StatusOK && len(bytes.TrimSpace(body)) == 0):
		// A notification's acknowledgement carries no message.
	case status == http.StatusOK:
		for _, m := range messages(body) {
			if env.Method == "initialize" {
				r.learnVersion(m)
			}
			r.write(m)
		}
	default:
		r.fail(isRequest, env.ID, hostedRefusal(status, body))
	}
}

// post sends one message, renewing the login and retrying once if the hosted
// service refuses the token.
func (r *Relay) post(ctx context.Context, msg []byte, retry bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Resource, bytes.NewReader(msg))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	r.verMu.Lock()
	if r.version != "" {
		req.Header.Set("MCP-Protocol-Version", r.version)
	}
	r.verMu.Unlock()
	if err := r.Auth.Authorize(ctx, req); err != nil {
		return 0, nil, err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return 0, nil, errors.New("response too large")
	}
	if resp.StatusCode == http.StatusUnauthorized && retry {
		r.Auth.Invalidate()
		return r.post(ctx, msg, false)
	}
	return resp.StatusCode, body, nil
}

// messages returns the JSON-RPC messages in a response body: a JSON body as
// is, or the data lines of an event stream.
func messages(body []byte) [][]byte {
	body = bytes.TrimSpace(body)
	if len(body) > 0 && (body[0] == '{' || body[0] == '[') {
		return [][]byte{body}
	}
	var out [][]byte
	for _, line := range strings.Split(string(body), "\n") {
		if data, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "data:"); ok {
			if d := strings.TrimSpace(data); d != "" && json.Valid([]byte(d)) {
				out = append(out, []byte(d))
			}
		}
	}
	return out
}

func (r *Relay) learnVersion(msg []byte) {
	var resp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(msg, &resp) == nil && resp.Result.ProtocolVersion != "" && len(resp.Result.ProtocolVersion) <= 32 {
		r.verMu.Lock()
		r.version = resp.Result.ProtocolVersion
		r.verMu.Unlock()
	}
}

// hostedRefusal turns a hosted HTTP refusal into a sentence for the user. It
// never repeats the response body.
func hostedRefusal(status int, body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	switch {
	case status == http.StatusUnauthorized:
		return "WebDecoy refused this login. Run `webdecoy login` in a terminal, then try again."
	case status == http.StatusForbidden && e.Error == "insufficient_scope":
		return "This WebDecoy login lacks the permission for that. Run `webdecoy login --setup` in a terminal to request it."
	case status == http.StatusTooManyRequests:
		return "Too many WebDecoy requests in a short time. Wait a few seconds and try again."
	case status == http.StatusServiceUnavailable:
		return "WebDecoy is busy right now. Wait a few seconds and try again."
	}
	return fmt.Sprintf("WebDecoy could not answer (HTTP %d). Try again shortly.", status)
}

func (r *Relay) fail(isRequest bool, id json.RawMessage, message string) {
	if isRequest {
		r.writeError(id, -32000, message)
	}
}

func (r *Relay) writeError(id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
	r.write(msg)
}

func (r *Relay) write(msg []byte) {
	r.outMu.Lock()
	defer r.outMu.Unlock()
	_, _ = r.out.Write(append(bytes.TrimSpace(msg), '\n'))
}
