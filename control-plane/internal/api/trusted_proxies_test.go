package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/config"
)

func clientIPOf(s *Server, peer string, xff ...string) string {
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.RemoteAddr = peer
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return s.clientIP(r)
}

// Without configured proxies X-Forwarded-For is ignored, also for clients in private ranges: an
// internal client must not be able to choose the address used for rate limits, CIDR-bound service
// accounts and the audit trail.
func TestForwardedForIgnoredWithoutTrustedProxies(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	for _, peer := range []string{"10.20.1.15:51000", "192.168.1.7:443", "[fd00::5]:8080", "203.0.113.9:1234"} {
		got := clientIPOf(s, peer, "198.51.100.77")
		want := netip.MustParseAddrPort(peer).Addr().String()
		if got != want {
			t.Errorf("peer %s with spoofed X-Forwarded-For: client %s, want %s", peer, got, want)
		}
	}
}

// Only the configured proxy hops are skipped: a client behind the proxy cannot push its own forged
// entry past the proxy, because its own (untrusted) address is the right-most untrusted hop.
func TestForwardedForTrustsOnlyConfiguredHops(t *testing.T) {
	s := &Server{cfg: &config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.96.4.0/24")}}}
	if got := clientIPOf(s, "10.96.4.12:5000", "203.0.113.50, 10.20.1.15"); got != "10.20.1.15" {
		t.Fatalf("client behind the proxy: %s, want 10.20.1.15 (its forged left-most entry must be ignored)", got)
	}
	if got := clientIPOf(s, "10.20.1.15:5000", "203.0.113.50"); got != "10.20.1.15" {
		t.Fatalf("direct client with forged header: %s", got)
	}
}

// AEGIS_TRUSTED_PROXY_HOSTS: the addresses of a DNS name (e.g. the headless Service of the console
// pods) are trusted; lookups run in the background and the last good answer survives errors.
func TestTrustedProxyHosts(t *testing.T) {
	answers := map[string][]netip.Addr{"console.aegis.svc.cluster.local": {netip.MustParseAddr("10.244.1.17"), netip.MustParseAddr("10.244.2.9")}}
	var fail bool
	p := &proxyHostSet{hosts: []string{"console.aegis.svc.cluster.local"}, refresh: time.Hour, addrs: map[netip.Addr]bool{},
		lookup: func(_ context.Context, h string) ([]netip.Addr, error) {
			if fail {
				return nil, errors.New("SERVFAIL")
			}
			return answers[h], nil
		}}
	p.resolve()
	s := &Server{cfg: &config.Config{}, proxyHosts: p}
	if got := clientIPOf(s, "10.244.2.9:40000", "10.20.1.15"); got != "10.20.1.15" {
		t.Fatalf("request through a console pod: %s, want the forwarded client", got)
	}
	if got := clientIPOf(s, "10.244.3.3:40000", "198.51.100.77"); got != "10.244.3.3" {
		t.Fatalf("other pod must not be trusted: %s", got)
	}
	// inspect the set directly: contains() would start a background refresh after the failure
	has := func(a string) bool { p.mu.Lock(); defer p.mu.Unlock(); return p.addrs[netip.MustParseAddr(a)] }
	fail = true
	p.resolve()
	if !has("10.244.1.17") {
		t.Fatal("a failed lookup must keep the previous addresses")
	}
	fail = false
	answers["console.aegis.svc.cluster.local"] = []netip.Addr{netip.MustParseAddr("10.244.5.5")}
	p.resolve()
	if has("10.244.1.17") || !has("10.244.5.5") {
		t.Fatal("a successful lookup must replace the addresses (pods were rescheduled)")
	}
	var none *proxyHostSet
	if none.contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("no hosts configured must trust nothing")
	}
}
