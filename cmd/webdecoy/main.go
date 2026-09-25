// webdecoy is the first-party WebDecoy CLI: device-code login with the
// credential in the OS credential store, and a local stdio MCP server that
// relays to the hosted service for assistants that run MCP servers locally.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/WebDecoy/cli/internal/adapter"
	"github.com/WebDecoy/cli/internal/credstore"
	"github.com/WebDecoy/cli/internal/deviceauth"
)

// Version is set at release build time.
var Version = "dev"

// Public identifiers of WebDecoy's production login. Never credentials. The
// environment may override them for development against another tenant.
const (
	defaultIssuer     = "https://auth.webdecoy.com/"
	defaultResource   = "https://mcp.webdecoy.com/mcp"
	defaultClientID   = "wuNBtlyJLEInlcYwpKrEgIOAURZQqWyF"
	defaultDisconnect = "https://api.webdecoy.com/mcp/v1/connection"
	appURL            = "https://app.webdecoy.com"
)

const usage = `Usage: webdecoy <command> [--profile name]

  login [--setup]        Sign in with a code in your browser. --setup also asks
                         for permission to create a site's script tag and check
                         installs.
  status                 Show who is signed in and which sites this app can read.
  logout [--disconnect]  Sign out here. --disconnect also removes this app's
                         site approval in WebDecoy (for every machine using it).
  mcp                    Run the local MCP server over stdio. Add it to your
                         assistant as the command: webdecoy mcp
  version                Print the version.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(os.Stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profile := fs.String("profile", "default", "credential profile")
	setup := fs.Bool("setup", false, "also request setup permission (login)")
	disconnect := fs.Bool("disconnect", false, "also remove this app's site approval (logout)")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if (*setup && cmd != "login") || (*disconnect && cmd != "logout") {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if cmd == "version" {
		fmt.Println("webdecoy " + Version)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch cmd {
	case "login":
		err = login(ctx, *profile, *setup)
	case "status":
		err = status(ctx, *profile, os.Stdout)
	case "logout":
		err = logout(ctx, *profile, *disconnect, os.Stdout)
	case "mcp":
		err = serve(ctx, *profile)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdecoy: "+explain(err))
		return 1
	}
	return 0
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func newClient(setup bool) (*deviceauth.Client, error) {
	return deviceauth.New(deviceauth.Config{
		Issuer:        env("AUTH0_ISSUER", defaultIssuer),
		Resource:      env("MCP_RESOURCE_URL", defaultResource),
		ClientID:      env("MCP_DEVICE_CLIENT_ID", defaultClientID),
		DisconnectURL: env("MCP_DISCONNECT_URL", defaultDisconnect),
		OfflineAccess: true,
		Setup:         setup,
	})
}

func lockPath(profile string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "webdecoy", profile+".lock"), nil
}

func openLogin(profile string) (*adapter.Login, error) {
	store, err := credstore.New(profile)
	if err != nil {
		return nil, err
	}
	client, err := newClient(false)
	if err != nil {
		return nil, err
	}
	lock, err := lockPath(profile)
	if err != nil {
		return nil, err
	}
	return adapter.NewLogin(client, store, lock), nil
}

// login runs the device flow in a human terminal. The code goes only to that
// terminal, never to stdout, which an assistant may be capturing.
func login(ctx context.Context, profile string, setup bool) error {
	terminal, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return errors.New("login requires a human terminal. Run `webdecoy login` directly in Terminal, not from an assistant")
	}
	defer terminal.Close()
	store, err := credstore.New(profile)
	if err != nil {
		return err
	}
	client, err := newClient(setup)
	if err != nil {
		return err
	}
	session, err := client.Login(ctx, func(p deviceauth.Prompt) error {
		_, err := fmt.Fprintf(terminal, "Open %s in your browser and enter the code %s\nIt expires at %s. Press Ctrl+C to cancel.\n",
			p.VerificationURI, p.UserCode, p.ExpiresAt.Local().Format("15:04"))
		return err
	})
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.Persist(store.Save); err != nil {
		return fmt.Errorf("signed in, but %w", err)
	}
	fmt.Fprintf(terminal, "Signed in as %s. The login is saved in your system's credential store.\n", session.Subject())
	if setup && !contains(session.Scopes(), deviceauth.SetupScope) {
		fmt.Fprintln(terminal, "Setup permission was not granted, so the two setup tools will be refused. Reading works.")
	}
	fmt.Fprintf(terminal, "Next: approve which sites this app may read at %s, then run `webdecoy status`.\n", approvalURL())
	return nil
}

func approvalURL() string {
	return appURL + "/connect/mcp?client_id=" + url.QueryEscape(env("MCP_DEVICE_CLIENT_ID", defaultClientID))
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// status signs in from the stored credential and lists the sites the hosted
// service lets this app read, through the same relay the MCP server uses.
func status(ctx context.Context, profile string, out io.Writer) error {
	l, err := openLogin(profile)
	if err != nil {
		return err
	}
	result, err := callTool(ctx, l, "list_properties")
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Signed in as %s (%s).\n", l.Subject(), strings.Join(l.Scopes(), " "))
	var body struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Structured struct {
			Properties []struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"properties"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &body); err != nil {
		return errors.New("WebDecoy returned an answer this version cannot read")
	}
	if body.IsError {
		// Report WebDecoy's own answer; it names the fix (for an app with no
		// approved sites, the approval link).
		for _, c := range body.Content {
			fmt.Fprintln(out, c.Text)
		}
		return nil
	}
	fmt.Fprintf(out, "Sites this app can read: %d\n", len(body.Structured.Properties))
	for _, p := range body.Structured.Properties {
		fmt.Fprintf(out, "  %s  %s\n", p.ID, p.Name)
	}
	return nil
}

// callTool sends one tools/call through the relay and returns its result.
func callTool(ctx context.Context, l *adapter.Login, name string) (json.RawMessage, error) {
	r := &adapter.Relay{Resource: env("MCP_RESOURCE_URL", defaultResource), Auth: l, HTTP: adapter.NewHTTPClient()}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}` + "\n")
	var out strings.Builder
	if err := r.Serve(ctx, in, &out); err != nil {
		return nil, err
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		return nil, errors.New("no answer from WebDecoy")
	}
	if resp.Error != nil {
		return nil, errors.New(resp.Error.Message)
	}
	return resp.Result, nil
}

// logout revokes the refresh credential at Auth0 and deletes the stored copy.
// With disconnect it first ends this app's WebDecoy connection.
func logout(ctx context.Context, profile string, disconnect bool, out io.Writer) error {
	store, err := credstore.New(profile)
	if err != nil {
		return err
	}
	if _, err := store.Load(); errors.Is(err, credstore.ErrNotFound) {
		fmt.Fprintln(out, "Not signed in.")
		return nil
	}
	l, err := openLogin(profile)
	if err != nil {
		return err
	}
	if disconnect {
		if err := disconnectApp(ctx, l); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed this app's site approval in WebDecoy.")
	}
	revokeErr := l.Revoke(ctx)
	if err := store.Delete(); err != nil {
		return err
	}
	if revokeErr != nil && !errors.Is(revokeErr, adapter.ErrLoginInvalid) {
		fmt.Fprintln(out, "Signed out here. Auth0 could not be reached to revoke the login; it expires unused.")
		return nil
	}
	fmt.Fprintln(out, "Signed out.")
	return nil
}

func disconnectApp(ctx context.Context, l *adapter.Login) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, env("MCP_DISCONNECT_URL", defaultDisconnect), nil)
	if err != nil {
		return err
	}
	if err := l.AuthorizeDisconnect(ctx, req); err != nil {
		return err
	}
	resp, err := adapter.NewHTTPClient().Do(req)
	if err != nil {
		return errors.New("could not reach WebDecoy to remove the site approval; nothing was signed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("WebDecoy refused to remove the site approval (HTTP %d); nothing was signed out", resp.StatusCode)
	}
	return nil
}

// serve is the local MCP server. stdout carries protocol messages only.
func serve(ctx context.Context, profile string) error {
	l, err := openLogin(profile)
	if err != nil {
		return err
	}
	r := &adapter.Relay{Resource: env("MCP_RESOURCE_URL", defaultResource), Auth: l, HTTP: adapter.NewHTTPClient()}
	return r.Serve(ctx, os.Stdin, os.Stdout)
}

func explain(err error) string {
	switch {
	case errors.Is(err, adapter.ErrNotSignedIn):
		return "not signed in. Run `webdecoy login`."
	case errors.Is(err, adapter.ErrLoginInvalid):
		return "the saved login expired or was revoked. Run `webdecoy login` again."
	case errors.Is(err, deviceauth.ErrDenied):
		return "the login was denied in the browser."
	case errors.Is(err, deviceauth.ErrExpired):
		return "the code expired before it was approved. Run `webdecoy login` again."
	case errors.Is(err, context.Canceled):
		return "cancelled."
	}
	return err.Error()
}
