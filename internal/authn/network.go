package authn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Metadata is fetched only from the configured issuer, never JWT jku/x5u/iss
// URLs. No proxy, redirects, private addresses, or second DNS lookup at dial.
func publicClient() *http.Client {
	return &http.Client{
		Timeout:       KeyFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:            dialPublic,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    time.Second,
			ResponseHeaderTimeout:  2 * time.Second,
			MaxResponseHeaderBytes: 8 << 10,
			MaxConnsPerHost:        1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: true,
		},
	}
}

// NewPublicClient returns the bounded HTTPS transport shared by first-party
// Auth0 clients. Callers must still fix their endpoints from trusted config.
func NewPublicClient() *http.Client { return publicClient() }

func dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, ErrKeysUnavailable
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrKeysUnavailable
	}
	for _, address := range addresses {
		if !publicIP(address) {
			return nil, ErrKeysUnavailable
		}
	}
	// One dial attempt within the shared fetch deadline. Prefer an IPv4
	// address when present, since deployment environments may lack IPv6 egress.
	chosen := addresses[0]
	for _, address := range addresses {
		if address.Is4() {
			chosen = address
			break
		}
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(chosen.String(), port))
	if err != nil {
		return nil, errors.New("public issuer connection failed")
	}
	return conn, nil
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	// Exclude translation/special IPv6 ranges outside ordinary global unicast.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range reserved {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
