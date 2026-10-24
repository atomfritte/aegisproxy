package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

// ProxyGuard applies an SSRF policy to an http.Transport that may send requests through a forward
// proxy (HTTPS_PROXY or an explicit proxy URL): use ProxyFunc as the transport's Proxy and
// DialContext as its DialContext.
//
// Direct connections are checked at dial time on the resolved address (no DNS rebinding). A proxied
// request cannot be checked there (the transport dials the proxy, and the proxy resolves the target),
// so ProxyFunc checks the target before handing it over: an IP literal must be allowed, and so must
// every address the name resolves to from the control plane. A name the control plane cannot
// resolve is left to the proxy and its egress policy (split-horizon DNS behind corporate proxies).
type ProxyGuard struct {
	// Proxy selects the proxy for a request (http.ProxyFromEnvironment, http.ProxyURL); nil: none.
	Proxy func(*http.Request) (*url.URL, error)
	// Blocked reports addresses the integration must never reach.
	Blocked func(netip.Addr) bool
	// What names the destination in errors, e.g. "webhook host".
	What   string
	Dialer *net.Dialer

	proxies sync.Map // dial addresses of the proxies ProxyFunc handed out (operator-configured, trusted)
}

// ProxyFunc returns the proxy for req after checking its target.
func (g *ProxyGuard) ProxyFunc(req *http.Request) (*url.URL, error) {
	if g.Proxy == nil {
		return nil, nil
	}
	pu, err := g.Proxy(req)
	if err != nil || pu == nil {
		return pu, err
	}
	if _, err := g.check(req.Context(), req.URL.Hostname(), true); err != nil {
		return nil, err
	}
	g.proxies.Store(proxyDialAddr(pu), true)
	return pu, nil
}

// DialContext connects to a proxy handed out by ProxyFunc, or to a checked address of addr.
func (g *ProxyGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if _, ok := g.proxies.Load(strings.ToLower(addr)); ok {
		return g.Dialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := g.check(ctx, host, false)
	if err != nil {
		return nil, err
	}
	// Dial the checked address (no second lookup an attacker's DNS could answer differently).
	return g.Dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// check resolves host and refuses blocked addresses. With lenient, a name that does not resolve
// passes (the proxy resolves it).
func (g *ProxyGuard) check(ctx context.Context, host string, lenient bool) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if g.Blocked(a) {
			return nil, fmt.Errorf("%s %s is a disallowed internal address", g.What, host)
		}
		return []netip.Addr{a}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if lenient {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve %s %s: %v", g.What, host, err)
	}
	for _, ip := range ips {
		if g.Blocked(ip) {
			return nil, fmt.Errorf("%s %s resolves to disallowed internal address %s", g.What, host, ip)
		}
	}
	return ips, nil
}

// proxyDialAddr is the address net/http dials for proxy u.
func proxyDialAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}
