package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/WebDecoy/cli/internal/credstore"
	"github.com/WebDecoy/cli/internal/deviceauth"
)

var (
	// ErrNotSignedIn means no login is stored for this profile.
	ErrNotSignedIn = errors.New("not signed in")
	// ErrLoginInvalid means the stored login was refused (revoked, expired or
	// replaced); only a new `webdecoy login` fixes it.
	ErrLoginInvalid = errors.New("stored login no longer valid")
	// ErrCredentialStore means the OS credential store could not be read. It
	// is neither "not signed in" nor a network problem, and says so.
	ErrCredentialStore = errors.New("could not read the login from this system's credential store")
)

// renewBefore renews an access token this long before it expires.
const renewBefore = 30 * time.Second

// Login holds the adapter's current access token and renews it from the
// credential store. Every renewal takes a lock shared by every webdecoy
// process on the machine and resumes from the credential in the store, not a
// copy held in memory, so two MCP clients running the adapter never race a
// rotating refresh token.
type Login struct {
	client   *deviceauth.Client
	store    *credstore.Store
	lockPath string

	mu      sync.Mutex
	session *deviceauth.Session
}

func NewLogin(client *deviceauth.Client, store *credstore.Store, lockPath string) *Login {
	return &Login{client: client, store: store, lockPath: lockPath}
}

// Authorize adds the bearer token to a request for the hosted resource,
// renewing first if the token is missing or about to expire.
func (l *Login) Authorize(ctx context.Context, r *http.Request) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil || time.Until(l.session.ExpiresAt()) < renewBefore {
		if err := l.renew(ctx); err != nil {
			return err
		}
	}
	return l.session.Authorize(r)
}

// AuthorizeDisconnect adds the bearer token to the request that ends this
// app's own connection, renewing first if needed.
func (l *Login) AuthorizeDisconnect(ctx context.Context, r *http.Request) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil || time.Until(l.session.ExpiresAt()) < renewBefore {
		if err := l.renew(ctx); err != nil {
			return err
		}
	}
	return l.session.AuthorizeDisconnect(r)
}

// Subject is the signed-in user, once a token has been obtained.
func (l *Login) Subject() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		return ""
	}
	return l.session.Subject()
}

// Scopes are the current token's permissions, once one has been obtained.
func (l *Login) Scopes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		return nil
	}
	return l.session.Scopes()
}

// Revoke revokes the stored refresh credential at Auth0 and forgets the local
// session. The caller deletes the stored copy.
func (l *Login) Revoke(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		if err := l.renew(ctx); err != nil {
			return err
		}
	}
	err := l.session.Revoke(ctx)
	l.session = nil
	return err
}

// Invalidate drops the current access token after the hosted service refused
// it, so the next Authorize renews.
func (l *Login) Invalidate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session != nil {
		l.session.Close()
		l.session = nil
	}
}

func (l *Login) renew(ctx context.Context) error {
	unlock, err := lockFile(l.lockPath)
	if err != nil {
		return fmt.Errorf("%w (lock file: %v)", ErrCredentialStore, err)
	}
	defer unlock()
	stored, err := l.store.Load()
	if errors.Is(err, credstore.ErrNotFound) {
		return ErrNotSignedIn
	}
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrCredentialStore, err)
	}
	next, err := l.client.Resume(ctx, stored)
	if err != nil {
		if errors.Is(err, deviceauth.ErrUnavailable) {
			return err
		}
		return ErrLoginInvalid
	}
	if err := next.Persist(l.store.Save); err != nil && !errors.Is(err, deviceauth.ErrNoRefresh) {
		next.Close()
		return err
	}
	if l.session != nil {
		l.session.Close()
	}
	l.session = next
	return nil
}

// lockFile takes an exclusive advisory lock, creating the file (0600, in a
// 0700 directory) if needed. It holds no secret.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
