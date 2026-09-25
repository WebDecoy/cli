package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestPublicIssuerAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.100.100.200",
		"0.0.0.0", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:db8::1",
	} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("non-public address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("public address refused: %s", raw)
		}
	}
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:443", "1.1.1.1:80"} {
		if conn, err := dialPublic(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Errorf("unsafe dial accepted: %s", address)
		}
	}
}

func TestIssuerClientDoesNotRedirect(t *testing.T) {
	var followed atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer source.Close()
	client := publicClient()
	// Permit only the local source transport for this test of redirect policy.
	client.Transport = source.Client().Transport
	resp, err := client.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || followed.Load() {
		t.Fatal("issuer redirect followed")
	}
}

func TestIssuerConfiguration(t *testing.T) {
	for _, issuer := range []string{"", "http://tenant.auth0.com/", "https://tenant.auth0.com/path", "https://user:secret@tenant.auth0.com/", "https://tenant.auth0.com/?x=1", "https://tenant.auth0.com/#", "https://tenant.auth0.com:443/"} {
		if _, err := New(Config{Issuer: issuer, Audience: "resource"}); err == nil {
			t.Errorf("unsafe issuer accepted: %s", issuer)
		}
	}
}
