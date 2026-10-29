package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
)

// breakGlassFactor and breakGlassMaxLock bound the account-wide throttle of break-glass accounts: they
// are locked per source address, and only a sustained flood from many sources (5 × 200 failures within
// a lockout window) delays every sign-in, by at most one minute at a time. The per-proxy ceiling is
// capped the same way, as break-glass sign-ins behind that proxy depend on it as well.
const (
	breakGlassFactor  = 200
	breakGlassMaxLock = time.Minute
)

// publicProxyFactor is the ceiling of the public rate limits for everything behind one forwarding peer
// that is not trusted, as a multiple of the per-client limit. Any direct client can claim to be such a
// proxy by sending X-Forwarded-For, so this is also how far it can lift its own limit.
const publicProxyFactor = 5

// throttleSource identifies the client of a failed authentication for throttling.
//
// The client address is attributable when the TCP peer connected without forwarding headers or is a
// trusted reverse proxy (then clientIP is the forwarded address). Behind a reverse proxy that is not
// trusted every client shares the proxy's address: keying on it alone would let one client lock out
// everybody (including break-glass sign-ins and SCIM deprovisioning). The key then combines the proxy
// with the client it claims, and a higher per-proxy ceiling bounds spraying with invented addresses.
// IPv6 addresses are keyed on their /64, which a single host can fill with addresses of its own.
type throttleSource struct {
	label string // client address, or "<proxy>|<claimed client>"
	proxy string // untrusted forwarding peer ("" when the client is attributable)
}

func (s *Server) throttleSource(r *http.Request) throttleSource {
	ip := s.clientIP(r)
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = sourceKey(a)
	}
	peer, ok := peerAddr(r)
	if !ok || s.isTrustedProxy(peer) {
		return throttleSource{label: ip}
	}
	claimed, forwarded := forwardedClient(r.Header)
	if !forwarded {
		return throttleSource{label: ip}
	}
	s.warnUntrustedProxy(peer)
	return throttleSource{label: sourceKey(peer) + "|" + claimed, proxy: sourceKey(peer)}
}

// sourceKey is the throttling key of an address: IPv6 addresses count per /64.
func sourceKey(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// keys are the source dimensions of an attempt; prefix separates the throttled endpoints. The per-proxy
// ceiling never locks longer than breakGlassMaxLock, and a full limiter keeps only that ceiling for
// claimed clients it does not track yet.
func (t throttleSource) keys(prefix string) []auth.Key {
	keys := []auth.Key{{Name: prefix + "ip:" + t.label, Factor: auth.FactorSource, Shed: t.proxy != ""}}
	if t.proxy != "" {
		keys = append(keys, auth.Key{Name: prefix + "proxy:" + t.proxy, Factor: auth.FactorProxy, MaxLock: breakGlassMaxLock})
	}
	return keys
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// forwardedClient returns the client a forwarding header claims (right-most entry, as the nearest
// proxy appended it), normalized to its sourceKey; unparsable claims share one key.
func forwardedClient(h http.Header) (string, bool) {
	var raw string
	if v := strings.Join(h.Values("X-Forwarded-For"), ","); strings.TrimSpace(v) != "" {
		parts := strings.Split(v, ",")
		raw = parts[len(parts)-1]
	} else if v := strings.Join(h.Values("Forwarded"), ","); strings.TrimSpace(v) != "" {
		elems := strings.Split(v, ",")
		for _, pair := range strings.Split(elems[len(elems)-1], ";") {
			if k, val, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.EqualFold(k, "for") {
				raw = val
			}
		}
		if raw == "" {
			raw = "unknown"
		}
	} else if v := strings.TrimSpace(h.Get("X-Real-IP")); v != "" {
		raw = v
	} else {
		return "", false
	}
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return sourceKey(ap.Addr()), true
	}
	if a, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return sourceKey(a), true
	}
	return "unparsed", true
}

// maxUntrustedProxyWarnings bounds the "proxy not trusted" log lines (one per peer, at most 32 peers).
const maxUntrustedProxyWarnings = 32

func (s *Server) warnUntrustedProxy(peer netip.Addr) {
	if _, seen := s.untrustedProxies.Load(peer); seen || s.untrustedWarned.Load() >= maxUntrustedProxyWarnings {
		return
	}
	if _, loaded := s.untrustedProxies.LoadOrStore(peer, true); loaded {
		return
	}
	s.untrustedWarned.Add(1)
	s.log.Warn("request with forwarding headers from a proxy that is not trusted: the client address is not attributable, "+
		"sign-in throttling falls back to the proxy and the client it claims; list the proxy in AEGIS_TRUSTED_PROXIES or AEGIS_TRUSTED_PROXY_HOSTS",
		"proxy", peer.String())
}
