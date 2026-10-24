package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Behind HTTPS_PROXY the SSRF guard checks the target before handing it to the proxy, and still
// connects to an operator-configured proxy on an internal address.
func TestProxyGuard(t *testing.T) {
	var mu sync.Mutex
	var connects []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connects = append(connects, r.Method+" "+r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	internal := func(a netip.Addr) bool {
		a = a.Unmap()
		return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified()
	}
	g := &ProxyGuard{Proxy: http.ProxyURL(pu), Blocked: internal, What: "webhook host", Dialer: &net.Dialer{Timeout: 2 * time.Second}}
	c := &http.Client{Transport: &http.Transport{Proxy: g.ProxyFunc, DialContext: g.DialContext}, Timeout: 5 * time.Second}

	for _, target := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://[::ffff:169.254.169.254]/",
		"https://10.0.0.5/",
		"https://localhost/",
	} {
		_, err := c.Get(target)
		if err == nil || !strings.Contains(err.Error(), "disallowed internal address") {
			t.Errorf("%s: %v", target, err)
		}
	}
	mu.Lock()
	if len(connects) != 0 {
		t.Errorf("internal targets reached the proxy: %v", connects)
	}
	mu.Unlock()

	// A name the control plane cannot resolve is the proxy's to resolve (and to police).
	if _, err := c.Get("https://feeds.unresolvable.invalid/list.txt"); err == nil {
		t.Error("expected the proxy's 403")
	}
	mu.Lock()
	if len(connects) != 1 || connects[0] != "CONNECT feeds.unresolvable.invalid:443" {
		t.Errorf("proxy requests: %v", connects)
	}
	mu.Unlock()

	// Without a proxy the resolved address is checked at dial time.
	direct := &ProxyGuard{Blocked: internal, What: "webhook host", Dialer: &net.Dialer{Timeout: 2 * time.Second}}
	dc := &http.Client{Transport: &http.Transport{Proxy: direct.ProxyFunc, DialContext: direct.DialContext}, Timeout: 5 * time.Second}
	if _, err := dc.Get(proxy.URL); err == nil || !strings.Contains(err.Error(), "disallowed internal address") {
		t.Errorf("direct loopback connection: %v", err)
	}
}

func TestProxyDialAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"http://proxy.corp:3128": "proxy.corp:3128",
		"http://Proxy.Corp":      "proxy.corp:80",
		"https://proxy.corp":     "proxy.corp:443",
		"socks5://10.0.0.1":      "10.0.0.1:1080",
		"http://[fd00::1]:8080/": "[fd00::1]:8080",
	} {
		u, _ := url.Parse(raw)
		if got := proxyDialAddr(u); got != want {
			t.Errorf("proxyDialAddr(%s) = %s, want %s", raw, got, want)
		}
	}
}
