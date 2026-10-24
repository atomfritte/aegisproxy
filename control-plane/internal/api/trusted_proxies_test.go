package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
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

// A failing lookup keeps only that host's previous addresses, and only for a bounded time: an address
// recycled for another pod must not stay trusted forever while DNS is broken.
func TestTrustedProxyHostsExpireWhileLookupsFail(t *testing.T) {
	answers := map[string][]netip.Addr{
		"console.aegis.svc.cluster.local":         {netip.MustParseAddr("10.244.1.17")},
		"ingress.ingress-nginx.svc.cluster.local": {netip.MustParseAddr("10.244.9.9")},
	}
	failing := map[string]bool{}
	m := NewMetrics()
	p := &proxyHostSet{hosts: []string{"console.aegis.svc.cluster.local", "ingress.ingress-nginx.svc.cluster.local"}, refresh: time.Hour,
		maxStale: 5 * time.Minute, metrics: m, addrs: map[netip.Addr]bool{},
		lookup: func(_ context.Context, h string) ([]netip.Addr, error) {
			if failing[h] {
				return nil, errors.New("SERVFAIL")
			}
			return answers[h], nil
		}}
	p.resolve()
	has := func(a string) bool { p.mu.Lock(); defer p.mu.Unlock(); return p.addrs[netip.MustParseAddr(a)] }

	failing["console.aegis.svc.cluster.local"] = true
	answers["ingress.ingress-nginx.svc.cluster.local"] = []netip.Addr{netip.MustParseAddr("10.244.9.10")}
	p.resolve()
	if !has("10.244.1.17") || !has("10.244.9.10") || has("10.244.9.9") {
		t.Fatal("a failing host must keep its own addresses while the other host is updated")
	}
	p.mu.Lock()
	p.state["console.aegis.svc.cluster.local"].lastOK = time.Now().Add(-6 * time.Minute)
	p.mu.Unlock()
	p.resolve()
	if has("10.244.1.17") {
		t.Fatal("addresses of a host whose lookups fail longer than maxStale must expire")
	}
	if !has("10.244.9.10") {
		t.Fatal("the healthy host must stay trusted")
	}
	var b strings.Builder
	m.write(&b)
	if !strings.Contains(b.String(), `aegis_trusted_proxy_host_expired_total{host="console.aegis.svc.cluster.local"} 1`) {
		t.Fatalf("expiry not counted:\n%s", b.String())
	}
	st := p.hostStatus()
	if len(st) != 2 || st[0].addrs != 0 || st[1].addrs != 1 || st[1].age < 0 {
		t.Fatalf("host status %+v", st)
	}
}

// Qualified names are resolved as absolute names: with Kubernetes' ndots:5 a relative lookup would try
// the node's DNS search domains first, where somebody else may publish the same name.
func TestTrustedProxyHostNamesAreAbsolute(t *testing.T) {
	for in, want := range map[string]string{
		"aegis-console-headless.aegis.svc.cluster.local": "aegis-console-headless.aegis.svc.cluster.local.",
		"lb.example.": "lb.example.",
		"console":     "console", // single label: Docker Compose service names use the search list
	} {
		if got := absoluteName(in); got != want {
			t.Errorf("absoluteName(%q) = %q, want %q", in, got, want)
		}
	}
}
