package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// middleware wires request IDs, panic recovery, access logging, metrics, security headers,
// CORS and body size limits around every handler.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-ID")
		if !validRequestID(reqID) {
			reqID = newRequestID()
		}
		rec := &statusRecorder{ResponseWriter: w}
		h := rec.Header()
		h.Set("X-Request-ID", reqID)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if s.cfg.TLSCertFile != "" || strings.HasPrefix(s.cfg.PublicURL, "https://") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		if isAPI {
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}

		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic in handler", "panic", p, "path", r.URL.Path, "request_id", reqID, "stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(rec, http.StatusInternalServerError, "internal server error")
				}
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			dur := time.Since(start)
			s.metrics.ObserveHTTP(r.Method, routeLabel(r), status, dur)
			if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.URL.Path != "/metrics" {
				s.log.Info("http request", "request_id", reqID, "method", r.Method, "path", r.URL.Path,
					"status", status, "bytes", rec.bytes, "duration_ms", dur.Milliseconds(), "client_ip", s.clientIP(r))
			}
		}()

		if isAPI && !s.applyCORS(rec, r) {
			return
		}
		limit := int64(1 << 20)
		if strings.HasPrefix(r.URL.Path, "/api/dataplane/") || strings.HasPrefix(r.URL.Path, "/api/security/indicators") {
			limit = 16 << 20
		} else if strings.HasPrefix(r.URL.Path, scimPrefix+"/") {
			limit = 8 << 20 // SCIM group documents with many members
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(rec, r.Body, limit)
		}
		next.ServeHTTP(rec, r)
	})
}

func routeLabel(r *http.Request) string {
	if r.Pattern != "" {
		if _, p, ok := strings.Cut(r.Pattern, " "); ok {
			return p
		}
		return r.Pattern
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return "unmatched"
	}
	return "/ui"
}

// applyCORS allows credentialed cross-origin access only for explicitly configured origins.
// The public access-request endpoint is additionally reachable from any origin without
// credentials (the block page is served on the blocked site's origin).
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	h := w.Header()
	h.Add("Vary", "Origin")
	if r.URL.Path == "/api/public/requests" || strings.HasPrefix(r.URL.Path, "/api/public/ca/") {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		return true
	}
	if slices.Contains(s.cfg.CORSOrigins, origin) {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, If-None-Match, X-Requested-With, X-Request-ID")
		h.Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return false
		}
	}
	return true
}

// clientIP returns the TCP peer, or the right-most untrusted X-Forwarded-For hop when the peer
// is a configured trusted reverse proxy (that sends the proxy secret, when one is configured).
//
// A loopback address in X-Forwarded-For is never skipped as a proxy hop, even when loopback is trusted:
// it is what a proxy that appends to the header records for a client on its own host, i.e. any local
// account that connects through it. The walk stops there and the request counts as coming from that
// loopback address; otherwise a local user who sends "X-Forwarded-For: <any address>" through the proxy
// would have the trusted loopback hop skipped and choose the client address.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !s.isTrustedProxy(peer) || !s.proxySecretOK(r, peer) {
		return peer.String()
	}
	xff := r.Header.Values("X-Forwarded-For")
	hops := strings.Split(strings.Join(xff, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap() // ::ffff:127.0.0.1 is 127.0.0.1
		if a.IsLoopback() || !s.isTrustedProxy(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) isTrustedProxy(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return s.proxyHosts.contains(a)
}

// proxyAuthHeader carries AEGIS_TRUSTED_PROXY_SECRET from the trusted reverse proxies.
const proxyAuthHeader = "X-Aegis-Proxy-Auth"

// proxySecretOK reports whether a request from a trusted peer may assert the client address: always
// without a configured proxy secret, otherwise only with exactly that secret in X-Aegis-Proxy-Auth. Other
// local accounts share the proxy's address (loopback, a bridge gateway) but not the secret; their
// forwarding headers are ignored and the peer counts as the client.
func (s *Server) proxySecretOK(r *http.Request, peer netip.Addr) bool {
	if s.cfg.TrustedProxySecret == "" {
		return true
	}
	got := r.Header.Values(proxyAuthHeader)
	want := sha256.Sum256([]byte(s.cfg.TrustedProxySecret))
	var have [sha256.Size]byte
	if len(got) == 1 {
		have = sha256.Sum256([]byte(strings.TrimSpace(got[0])))
	}
	if len(got) == 1 && subtle.ConstantTimeCompare(have[:], want[:]) == 1 {
		return true
	}
	if _, forwarded := forwardedClient(r.Header); forwarded && !s.proxySecretWarned.Swap(true) {
		s.log.Warn("forwarding headers from a trusted proxy address without the proxy secret are ignored: configure the proxy to send "+
			proxyAuthHeader+" with AEGIS_TRUSTED_PROXY_SECRET (deploy/nginx/aegis-console.conf)", "peer", peer.String())
	}
	return false
}

// rateLimiter is a fixed-window per-key limiter with bounded memory: expired windows are swept once per
// window, and at most maxRateKeys keys are tracked.
type rateLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	hits      map[string]*rlEntry
	lastSweep time.Time
}

type rlEntry struct {
	start time.Time
	count int
}

// maxRateKeys bounds the keys of one rate limiter; overflowKey is shared by the clients a full limiter
// does not track (with the per-proxy ceiling as its limit).
const (
	maxRateKeys = 100_000
	overflowKey = "overflow|"
)

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string]*rlEntry)}
}

func (l *rateLimiter) Allow(key string) bool { return l.allowSource(throttleSource{label: key}) }

// allowSource limits one client. Behind a forwarding proxy that is not trusted, the key is the proxy and the
// client it claims (one client cannot use up the limit of everybody behind the proxy), and everything behind
// that proxy shares publicProxyFactor times the limit (inventing client addresses does not lift it further).
// A full limiter counts claimed clients it does not track against the proxy only.
func (l *rateLimiter) allowSource(src throttleSource) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	ceiling := l.limit * publicProxyFactor
	var proxy *rlEntry
	if src.proxy != "" {
		if proxy = l.entryLocked("proxy|"+src.proxy, now, true); proxy.count >= ceiling {
			return false
		}
	}
	client := l.entryLocked(src.label, now, false)
	limit := l.limit
	if client == nil && proxy == nil {
		client, limit = l.entryLocked(overflowKey, now, true), ceiling
	}
	if client != nil {
		if client.count >= limit {
			return false
		}
		client.count++
	}
	if proxy != nil {
		proxy.count++
	}
	return true
}

// entryLocked returns the current window of key. A new key is added only while the limiter has room,
// unless force is set (nil otherwise).
func (l *rateLimiter) entryLocked(key string, now time.Time, force bool) *rlEntry {
	e := l.hits[key]
	if e == nil {
		if !force && len(l.hits) >= maxRateKeys {
			return nil
		}
		e = &rlEntry{start: now}
		l.hits[key] = e
	} else if now.Sub(e.start) > l.window {
		e.start, e.count = now, 0
	}
	return e
}

func (l *rateLimiter) sweepLocked(now time.Time) {
	if len(l.hits) <= 1024 || now.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = now
	for k, e := range l.hits {
		if now.Sub(e.start) > l.window {
			delete(l.hits, k)
		}
	}
}
