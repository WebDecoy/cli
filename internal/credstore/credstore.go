// Package credstore keeps the WebDecoy CLI's refresh credential in the
// operating system's credential store: the macOS login Keychain, or
// the Secret Service on Linux through secret-tool. Nothing is ever written to
// a file, an environment variable or client configuration, and the secret
// reaches the helper program on stdin, never in its arguments, where any local
// user could read it from the process list.
//
// Anywhere else Store is unavailable and the CLI says so plainly; there is no
// fallback to a plain file.
package credstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	maxSecret = 8 << 10
	service   = "webdecoy-mcp"
	label     = "WebDecoy MCP login"
	timeout   = 10 * time.Second
)

var (
	// ErrNotFound means no login is stored for this profile.
	ErrNotFound = errors.New("no stored WebDecoy login")
	// ErrUnsupported means this system has no supported secure store.
	ErrUnsupported = errors.New("no supported secure credential store on this system: " +
		"WebDecoy CLI login needs the macOS Keychain, or secret-tool (libsecret) with a running Secret Service on Linux")

	profilePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// secretPattern admits OAuth token characters only, so a value can never
	// break out of the one line it is written on.
	secretPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

// runner executes one helper program with stdin, returning its stdout, whether
// it wrote anything to stderr, and its exit code. Tests replace it. stderr's
// content is never kept: a helper could echo its input there.
type runner func(ctx context.Context, name string, args []string, stdin string) (stdout string, complained bool, code int, err error)

// Store is one profile's credential slot.
type Store struct {
	profile string
	goos    string
	run     runner
	look    func(string) (string, error)
}

// New returns the store for a profile ("default" unless the user names one).
func New(profile string) (*Store, error) {
	return newStore(profile, runtime.GOOS, execRun, exec.LookPath)
}

func newStore(profile, goos string, run runner, look func(string) (string, error)) (*Store, error) {
	if !profilePattern.MatchString(profile) {
		return nil, fmt.Errorf("profile names are 1-32 lowercase letters, digits or dashes")
	}
	s := &Store{profile: profile, goos: goos, run: run, look: look}
	switch goos {
	case "darwin":
		return s, nil
	case "linux":
		if _, err := look("secret-tool"); err != nil {
			return nil, ErrUnsupported
		}
		return s, nil
	}
	return nil, ErrUnsupported
}

// Save stores the credential, replacing any earlier one, and reads it back to
// confirm the store kept it.
func (s *Store) Save(secret string) error {
	if !validSecret(secret) {
		return errors.New("refusing to store a malformed credential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	switch s.goos {
	case "darwin":
		// Interactive mode reads the command, secret included, from stdin.
		_, _, _, err = s.run(ctx, "/usr/bin/security", []string{"-i"},
			fmt.Sprintf("add-generic-password -U -s %s -a %s -l %q -w %s\n", service, s.profile, label, secret))
	default:
		var code int
		_, _, code, err = s.run(ctx, "secret-tool", []string{"store", "--label=" + label, "service", service, "account", s.profile}, secret)
		if err == nil && code != 0 {
			err = ErrUnsupported
		}
	}
	if err != nil {
		return fmt.Errorf("could not save the login to the credential store")
	}
	if got, err := s.Load(); err != nil || got != secret {
		return fmt.Errorf("the credential store did not keep the login")
	}
	return nil
}

// Load returns the stored credential, or ErrNotFound.
func (s *Store) Load() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var out string
	var complained bool
	var code int
	var err error
	switch s.goos {
	case "darwin":
		out, _, code, err = s.run(ctx, "/usr/bin/security", []string{"find-generic-password", "-s", service, "-a", s.profile, "-w"}, "")
		if err == nil && code == 44 {
			return "", ErrNotFound
		}
	default:
		out, complained, code, err = s.run(ctx, "secret-tool", []string{"lookup", "service", service, "account", s.profile}, "")
		// secret-tool exits 1 both for "no such item" and for "could not
		// reach the Secret Service"; only the second says anything. Reporting
		// an unreachable store as "not signed in" would send the user to log
		// in again for nothing.
		if err == nil && code == 1 && strings.TrimSpace(out) == "" && !complained {
			return "", ErrNotFound
		}
	}
	if err != nil || code != 0 {
		return "", fmt.Errorf("could not read the login from the credential store; on Linux, check that a Secret Service is running")
	}
	secret := strings.TrimRight(out, "\r\n")
	if !validSecret(secret) {
		return "", fmt.Errorf("the stored login is unreadable; run webdecoy logout, then webdecoy login")
	}
	return secret, nil
}

// Delete removes the stored credential. Nothing stored is not an error.
func (s *Store) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var code int
	var err error
	switch s.goos {
	case "darwin":
		_, _, code, err = s.run(ctx, "/usr/bin/security", []string{"delete-generic-password", "-s", service, "-a", s.profile}, "")
		if err == nil && code == 44 {
			return nil
		}
	default:
		_, _, code, err = s.run(ctx, "secret-tool", []string{"clear", "service", service, "account", s.profile}, "")
	}
	if err != nil || code != 0 {
		return fmt.Errorf("could not remove the login from the credential store")
	}
	if _, err := s.Load(); !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("the credential store still holds the login")
	}
	return nil
}

func validSecret(s string) bool { return len(s) <= maxSecret && secretPattern.MatchString(s) }

func execRun(ctx context.Context, name string, args []string, stdin string) (string, bool, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	complained := strings.TrimSpace(errOut.String()) != ""
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), complained, exit.ExitCode(), nil
	}
	if err != nil {
		return "", complained, -1, err
	}
	return out.String(), complained, 0, nil
}
