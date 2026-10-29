package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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

// DEPLOY-1: loopback (or a bridge gateway) is shared by every local account. With AEGIS_TRUSTED_PROXY_SECRET
// forwarding headers count only from trusted peers that send the secret; other local users are identified
// as the peer itself (also for throttling, without the untrusted-proxy fallback keyed on their claims).
func TestProxySecretRequiredFromTrustedPeers(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	s := &Server{cfg: &config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, TrustedProxySecret: secret}}
	s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	req := func(peer string, auth ...string) *http.Request {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "10.20.30.7")
		for _, a := range auth {
			r.Header.Add(proxyAuthHeader, a)
		}
		return r
	}
	cases := []struct {
		name, client string
		r            *http.Request
	}{
		{"local user without the secret", "127.0.0.1", req("127.0.0.1:40000")},
		{"wrong secret", "127.0.0.1", req("127.0.0.1:40000", secret+"x")},
		{"secret prefix", "127.0.0.1", req("127.0.0.1:40000", secret[:16])},
		{"secret sent twice", "127.0.0.1", req("127.0.0.1:40000", secret, secret)},
		{"the proxy", "10.20.30.7", req("127.0.0.1:40000", secret)},
		{"untrusted peer with the secret", "192.0.2.5", req("192.0.2.5:40000", secret)},
	}
	for _, c := range cases {
		if got := s.clientIP(c.r); got != c.client {
			t.Errorf("%s: client %s, want %s", c.name, got, c.client)
		}
	}
	if src := s.throttleSource(req("127.0.0.1:40000")); src.label != "127.0.0.1" || src.proxy != "" {
		t.Errorf("local user without the secret is throttled as %+v, want the peer", src)
	}
	if src := s.throttleSource(req("127.0.0.1:40000", secret)); src.label != "10.20.30.7" || src.proxy != "" {
		t.Errorf("client of the proxy is throttled as %+v", src)
	}
	s.cfg.TrustedProxySecret = ""
	if got := s.clientIP(req("127.0.0.1:40000")); got != "10.20.30.7" {
		t.Errorf("without a configured secret the trusted peer asserts the client: %s", got)
	}
}

// DEPLOY4-1: a local user can also go THROUGH the proxy on the same host. A proxy that appends to
// X-Forwarded-For records that user's loopback address after the user's own entry and sends the secret; a
// loopback address inside the header is therefore never skipped as a proxy hop, but is the client. Chains
// through other trusted proxies (a load balancer in front of nginx) keep working.
func TestForwardedLoopbackIsALocalClient(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	s := &Server{cfg: &config.Config{TrustedProxySecret: secret, TrustedProxies: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("10.0.0.5/32")}}}
	s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	req := func(peer string, xff ...string) *http.Request {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = peer
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		r.Header.Set(proxyAuthHeader, secret)
		return r
	}
	for _, c := range []struct {
		name, peer string
		xff        []string
		client     string
	}{
		{"local user through nginx (appends 127.0.0.1)", "127.0.0.1:40000", []string{"10.20.30.7, 127.0.0.1"}, "127.0.0.1"},
		{"local user through nginx on ::1", "127.0.0.1:40000", []string{"10.20.30.7, ::1"}, "::1"},
		{"IPv4-mapped loopback hop", "127.0.0.1:40000", []string{"10.20.30.7, ::ffff:127.0.0.1"}, "127.0.0.1"},
		{"any 127/8 hop", "127.0.0.1:40000", []string{"10.20.30.7,127.0.0.2"}, "127.0.0.2"},
		{"loopback hop in its own header line", "127.0.0.1:40000", []string{"10.20.30.7", "127.0.0.1"}, "127.0.0.1"},
		{"proxy connects over ::1", "[::1]:40000", []string{"10.20.30.7, ::1"}, "::1"},
		{"proxy connects over IPv4-mapped loopback", "[::ffff:127.0.0.1]:40000", []string{"10.20.30.7, 127.0.0.1"}, "127.0.0.1"},
		{"local user through the load balancer and nginx", "127.0.0.1:40000", []string{"10.20.30.7, 10.0.0.5, 127.0.0.1"}, "127.0.0.1"},
		{"load balancer reached over loopback", "10.0.0.5:40000", []string{"10.20.30.7, 127.0.0.1"}, "127.0.0.1"},
		{"legit chain: client, load balancer (trusted)", "127.0.0.1:40000", []string{"203.0.113.5, 10.0.0.5"}, "203.0.113.5"},
		{"proxy replaces the header", "127.0.0.1:40000", []string{"203.0.113.5"}, "203.0.113.5"},
		{"remote client sends a loopback entry", "127.0.0.1:40000", []string{"127.0.0.1, 203.0.113.5"}, "203.0.113.5"},
		{"remote client claims loopback through the load balancer", "127.0.0.1:40000", []string{"::1, 203.0.113.5, 10.0.0.5"}, "203.0.113.5"},
		{"local user without forged entries", "127.0.0.1:40000", []string{"127.0.0.1"}, "127.0.0.1"},
	} {
		if got := s.clientIP(req(c.peer, c.xff...)); got != c.client {
			t.Errorf("%s (peer %s, X-Forwarded-For %q): client %s, want %s", c.name, c.peer, c.xff, got, c.client)
		}
	}
	if src := s.throttleSource(req("127.0.0.1:40000", "198.51.100.9, 127.0.0.1")); src.label != "127.0.0.1" || src.proxy != "" {
		t.Errorf("local user through nginx is throttled as %+v, want 127.0.0.1", src)
	}
	// Loopback trusted by name (AEGIS_TRUSTED_PROXY_HOSTS=localhost) and without a secret: same rule.
	p := &proxyHostSet{hosts: []string{"localhost"}, refresh: time.Hour, addrs: map[netip.Addr]bool{},
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
		}}
	p.resolve()
	byName := &Server{cfg: &config.Config{}, proxyHosts: p}
	if got := clientIPOf(byName, "127.0.0.1:40000", "10.20.30.7, 127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("loopback trusted by name: client %s, want 127.0.0.1", got)
	}
	if got := clientIPOf(byName, "127.0.0.1:40000", "203.0.113.5"); got != "203.0.113.5" {
		t.Errorf("loopback trusted by name, replaced header: client %s, want 203.0.113.5", got)
	}
}

// DEPLOY-1: the posture report warns when loopback or a broad range is trusted without the proxy secret.
// DEPLOY4-1: with the secret, trusted loopback passes (loopback hops are local clients), a broad range does not.
func TestTrustedProxyPosture(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	status := func(secret string, hosts []string, prefixes ...string) (string, string) {
		s := &Server{cfg: &config.Config{TrustedProxySecret: secret, TrustedProxyHosts: hosts}}
		for _, p := range prefixes {
			s.cfg.TrustedProxies = append(s.cfg.TrustedProxies, netip.MustParsePrefix(p))
		}
		var got, detail string
		s.trustedProxyPostureCheck(func(id, _, _, st, d, _, _ string) {
			if id == "trusted-proxies" {
				got, detail = st, d
			}
		})
		return got, detail
	}
	for _, c := range []struct {
		want, secret string
		hosts        []string
		prefixes     []string
	}{
		{"pass", "", nil, nil},
		{"warn", "", nil, []string{"127.0.0.1/32", "::1/128"}},
		{"warn", "", nil, []string{"10.0.0.0/8"}},
		{"warn", "", nil, []string{"fd00::/32"}},
		{"pass", "", nil, []string{"10.96.4.12/32"}},
		{"pass", "", []string{"ingress.ingress-nginx.svc.cluster.local"}, nil},
		{"pass", secret, nil, []string{"127.0.0.1/32"}},
		{"pass", secret, nil, []string{"127.0.0.0/8", "::1/128", "10.96.4.12/32"}},
		{"pass", secret, []string{"lb.corp.example"}, []string{"127.0.0.1/32"}},
		{"warn", secret, nil, []string{"127.0.0.1/32", "10.0.0.0/8"}},
		{"warn", secret, nil, []string{"fd00::/32"}},
	} {
		got, detail := status(c.secret, c.hosts, c.prefixes...)
		if got != c.want {
			t.Errorf("%v %v secret=%t: %s (%s), want %s", c.prefixes, c.hosts, c.secret != "", got, detail, c.want)
		}
		if c.secret != "" && got == "pass" && !strings.Contains(detail, "loopback address in X-Forwarded-For counts as a local client") {
			t.Errorf("%v: detail %q does not say how loopback hops are treated", c.prefixes, detail)
		}
		if c.secret != "" && got == "warn" && (strings.Contains(detail, "127.0.0.") || !strings.Contains(detail, "10.0.0.0/8") && !strings.Contains(detail, "fd00::/32")) {
			t.Errorf("%v: detail %q must name the broad range only", c.prefixes, detail)
		}
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
