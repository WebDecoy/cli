package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	KeyCacheTTL       = 5 * time.Minute
	KeyFailureBackoff = 30 * time.Second
	KeyFetchTimeout   = 3 * time.Second
	MaxJWKSBytes      = 64 << 10
	MaxJWKSKeys       = 8
)

type keyCache struct {
	url      string
	client   *http.Client
	now      func() time.Time
	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	expires  time.Time
	retryAt  time.Time
	fetching chan struct{}
}

func newKeyCache(issuer string) *keyCache {
	return &keyCache{url: issuer + ".well-known/jwks.json", client: publicClient(), now: time.Now}
}

func (c *keyCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	for {
		if ctx.Err() != nil {
			return nil, ErrKeysUnavailable
		}
		c.mu.Lock()
		now := c.now()
		if now.Before(c.expires) {
			key := c.keys[kid]
			c.mu.Unlock()
			// Unknown kid values never force a refresh of a fresh cache.
			if key == nil {
				return nil, ErrInvalidToken
			}
			return key, nil
		}
		if now.Before(c.retryAt) {
			c.mu.Unlock()
			return nil, ErrKeysUnavailable
		}
		if c.fetching == nil {
			c.fetching = make(chan struct{})
			go c.refresh()
		}
		done := c.fetching
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ErrKeysUnavailable
		case <-done:
		}
	}
}

func (c *keyCache) refresh() {
	// A canceled caller cannot cancel a refresh shared by other requests.
	// There is at most one bounded refresh goroutine per verifier, no retries.
	ctx, cancel := context.WithTimeout(context.Background(), KeyFetchTimeout)
	defer cancel()
	keys, err := c.fetch(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.keys = nil
		c.expires = time.Time{}
		c.retryAt = c.now().Add(KeyFailureBackoff)
	} else {
		c.keys = keys
		c.expires = c.now().Add(KeyCacheTTL)
		c.retryAt = time.Time{}
	}
	close(c.fetching)
	c.fetching = nil
}

func (c *keyCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, ErrKeysUnavailable
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ErrKeysUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrKeysUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil || len(body) > MaxJWKSBytes {
		return nil, ErrKeysUnavailable
	}
	var document struct {
		Keys []struct {
			KID    string   `json:"kid"`
			KTY    string   `json:"kty"`
			Use    string   `json:"use"`
			Alg    string   `json:"alg"`
			N      string   `json:"n"`
			E      string   `json:"e"`
			KeyOps []string `json:"key_ops"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &document) != nil || len(document.Keys) == 0 || len(document.Keys) > MaxJWKSKeys {
		return nil, ErrKeysUnavailable
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range document.Keys {
		if k.KTY != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if len(k.KeyOps) > 0 && (len(k.KeyOps) != 1 || k.KeyOps[0] != "verify") {
			continue
		}
		if k.KID == "" || len(k.KID) > 128 || keys[k.KID] != nil {
			return nil, ErrKeysUnavailable
		}
		n, nerr := base64.RawURLEncoding.DecodeString(k.N)
		e, eerr := base64.RawURLEncoding.DecodeString(k.E)
		if nerr != nil || eerr != nil || len(n) > 512 || len(e) == 0 || len(e) > 4 {
			return nil, ErrKeysUnavailable
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Int64()
		if modulus.BitLen() < 2048 || modulus.Bit(0) == 0 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return nil, ErrKeysUnavailable
		}
		keys[k.KID] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if len(keys) == 0 {
		return nil, ErrKeysUnavailable
	}
	return keys, nil
}
