package credstore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// fakeHelper records every call and keeps one secret, like the OS store.
type fakeHelper struct {
	calls   []string
	stdins  []string
	stored  string
	noStore bool // the Secret Service is unreachable
}

func (f *fakeHelper) run(ctx context.Context, name string, args []string, stdin string) (string, bool, int, error) {
	if f.noStore {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		return "", true, 1, nil
	}
	out, code, err := f.answer(name, args, stdin)
	return out, false, code, err
}

func (f *fakeHelper) answer(name string, args []string, stdin string) (string, int, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.stdins = append(f.stdins, stdin)
	switch {
	case name == "/usr/bin/security" && args[0] == "-i":
		f.stored = strings.Fields(stdin)[len(strings.Fields(stdin))-1]
		return "", 0, nil
	case args[0] == "store":
		f.stored = stdin
		return "", 0, nil
	case args[0] == "find-generic-password", args[0] == "lookup":
		if f.stored == "" {
			if args[0] == "lookup" {
				return "", 1, nil
			}
			return "", 44, nil
		}
		return f.stored + "\n", 0, nil
	case args[0] == "delete-generic-password", args[0] == "clear":
		if f.stored == "" && args[0] == "delete-generic-password" {
			return "", 44, nil
		}
		f.stored = ""
		return "", 0, nil
	}
	return "", 2, nil
}

func found(string) (string, error)   { return "/usr/bin/secret-tool", nil }
func missing(string) (string, error) { return "", errors.New("not found") }

// The secret travels on stdin and never in a helper's arguments, where any
// local user could read it from the process list; save, load and delete
// round-trip on both platforms.
func TestSecretNeverInArgumentsAndRoundTrips(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		f := &fakeHelper{}
		s, err := newStore("default", goos, f.run, found)
		if err != nil {
			t.Fatal(err)
		}
		const secret = "v1.private-refresh_TOKEN"
		if _, err := s.Load(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: empty store: %v", goos, err)
		}
		if err := s.Save(secret); err != nil {
			t.Fatalf("%s: save: %v", goos, err)
		}
		if got, err := s.Load(); err != nil || got != secret {
			t.Fatalf("%s: load %q %v", goos, got, err)
		}
		if err := s.Delete(); err != nil {
			t.Fatalf("%s: delete: %v", goos, err)
		}
		if _, err := s.Load(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: after delete: %v", goos, err)
		}
		if err := s.Delete(); err != nil {
			t.Fatalf("%s: deleting nothing: %v", goos, err)
		}
		for _, call := range f.calls {
			if strings.Contains(call, "private-refresh") {
				t.Fatalf("%s: secret in arguments: %s", goos, call)
			}
		}
	}
}

// An unreachable Secret Service is reported as such, never as "not signed
// in", which would send the user to log in again for nothing.
func TestUnreachableStoreIsNotReportedAsSignedOut(t *testing.T) {
	f := &fakeHelper{noStore: true}
	s, _ := newStore("default", "linux", f.run, found)
	if _, err := s.Load(); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unreachable store read as %v", err)
	}
}

func TestUnsupportedSystemsFailClearly(t *testing.T) {
	if _, err := newStore("default", "windows", nil, found); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("windows: %v", err)
	}
	if _, err := newStore("default", "linux", nil, missing); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("linux without secret-tool: %v", err)
	}
	if _, err := newStore("Bad Profile", "darwin", nil, found); err == nil {
		t.Fatal("malformed profile accepted")
	}
}

// A value that could end the line it is written on, and so inject a second
// command into the helper, is refused before any helper runs.
func TestMalformedSecretsAreRefused(t *testing.T) {
	f := &fakeHelper{}
	s, _ := newStore("default", "darwin", f.run, found)
	for _, bad := range []string{"", "a b", "tok\ndelete-generic-password", `tok"`, strings.Repeat("a", 8193)} {
		if err := s.Save(bad); err == nil {
			t.Fatalf("stored %q", bad)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("helper ran for a refused value: %v", f.calls)
	}
}

// The real OS store round-trips under a throwaway profile: the Keychain on a
// Mac, and on Linux the Secret Service when WEBDECOY_TEST_SECRET_SERVICE=1
// says one is running (CI machines usually have none).
func TestRealKeychain(t *testing.T) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("/usr/bin/security"); err != nil {
			t.Skip("no security tool")
		}
	case "linux":
		if os.Getenv("WEBDECOY_TEST_SECRET_SERVICE") != "1" {
			t.Skip("set WEBDECOY_TEST_SECRET_SERVICE=1 with a running Secret Service")
		}
	default:
		t.Skip("no supported store")
	}
	s, err := New("selftest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Delete() })
	if err := s.Save("v1.selftest-value"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "v1.selftest-value" {
		t.Fatalf("load %q %v", got, err)
	}
	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
}
