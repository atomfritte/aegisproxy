package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/config"
)

// rawLogin posts a sign-in without the harness helpers (safe in goroutines).
func rawLogin(h *harness, user, pw string, headers map[string]string) (int, error) {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func countParallel(t *testing.T, n int, call func() (int, error)) map[int]int {
	t.Helper()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		got = map[int]int{}
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := call()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				got[-1]++
				return
			}
			got[st]++
		}()
	}
	wg.Wait()
	if got[-1] > 0 {
		t.Fatalf("%d requests failed: %v", got[-1], got)
	}
	return got
}

// A burst of parallel wrong passwords must not get more password checks than the lockout threshold
// (previously 60 parallel attempts all reached the check and returned 401).
func TestLoginBurstIsThrottled(t *testing.T) {
	h := newHarness(t)
	for _, user := range []string{"carol", "admin"} { // a normal account and the break-glass admin
		got := countParallel(t, 60, func() (int, error) { return rawLogin(h, user, "wrong-password", nil) })
		if got[http.StatusUnauthorized] > 5 || got[http.StatusUnauthorized]+got[http.StatusTooManyRequests] != 60 {
			t.Fatalf("%s: 60 parallel wrong passwords → %v; at most 5 may reach the password check", user, got)
		}
	}
}

// SCIM bearer guessing is reserved the same way (threshold 5 × FactorSource per source address).
func TestSCIMBurstIsThrottled(t *testing.T) {
	h := newSCIMHarness(t)
	got := countParallel(t, 60, func() (int, error) {
		req, _ := http.NewRequest("GET", h.srv.URL+"/api/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer aegis_scim_guess")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	})
	if got[http.StatusTooManyRequests] < 60-5*auth.FactorSource {
		t.Fatalf("60 parallel SCIM guesses → %v; at most %d may reach the token check", got, 5*auth.FactorSource)
	}
}

// Behind a reverse proxy that is not trusted every client arrives from the proxy's address. Failures of
// one claimed client must not lock out the others; the break-glass admin stays reachable from another
// source, while a normal account keeps its account-wide lockout.
func TestUntrustedProxyLockoutIsAttributedToClaimedClient(t *testing.T) {
	h := newHarness(t)
	from := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }
	for i := 0; i < 5*auth.FactorSource; i++ { // different accounts: only the source keys accumulate
		if _, err := rawLogin(h, fmt.Sprintf("nobody%d", i), "wrong", from("203.0.113.66")); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := rawLogin(h, "someone", "wrong", from("203.0.113.66")); st != http.StatusTooManyRequests {
		t.Fatalf("the spraying client itself must be throttled, got %d", st)
	}
	if st, _ := rawLogin(h, "admin", h.adminPW, from("203.0.113.77")); st != http.StatusOK {
		t.Fatalf("another client behind the same proxy was locked out: %d", st)
	}

	for i := 0; i < 6; i++ {
		_, _ = rawLogin(h, "admin", "wrong", from("203.0.113.88"))
	}
	if st, _ := rawLogin(h, "admin", h.adminPW, from("203.0.113.88")); st != http.StatusTooManyRequests {
		t.Fatalf("break-glass failures must lock their own source, got %d", st)
	}
	if st, _ := rawLogin(h, "admin", h.adminPW, from("203.0.113.99")); st != http.StatusOK {
		t.Fatalf("break-glass admin locked out by failures from another source: %d", st)
	}

	for i := 0; i < 5; i++ {
		_, _ = rawLogin(h, "carol", "wrong", from("203.0.113.10"))
	}
	if st, _ := rawLogin(h, "carol", "wrong", from("203.0.113.11")); st != http.StatusTooManyRequests {
		t.Fatalf("a normal account keeps its account-wide lockout, got %d", st)
	}
}

func TestThrottleSourceKeys(t *testing.T) {
	trusted := netip.MustParsePrefix("10.96.4.0/24")
	s := &Server{cfg: &config.Config{TrustedProxies: []netip.Prefix{trusted}}}
	s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	src := func(peer string, hdr map[string]string) throttleSource {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = peer
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return s.throttleSource(r)
	}
	cases := []struct {
		name, peer   string
		hdr          map[string]string
		label, proxy string
	}{
		{"direct client", "198.51.100.4:5000", nil, "198.51.100.4", ""},
		{"trusted proxy", "10.96.4.12:5000", map[string]string{"X-Forwarded-For": "203.0.113.5"}, "203.0.113.5", ""},
		{"untrusted proxy, X-Forwarded-For (right-most)", "10.20.1.15:5000", map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.5"}, "10.20.1.15|203.0.113.5", "10.20.1.15"},
		{"untrusted proxy, Forwarded", "10.20.1.15:5000", map[string]string{"Forwarded": `for=192.0.2.1, for="[2001:db8::7]:4711";proto=https`}, "10.20.1.15|2001:db8::7", "10.20.1.15"},
		{"untrusted proxy, X-Real-IP", "10.20.1.15:5000", map[string]string{"X-Real-IP": "203.0.113.9"}, "10.20.1.15|203.0.113.9", "10.20.1.15"},
		{"untrusted proxy, junk", "10.20.1.15:5000", map[string]string{"X-Forwarded-For": "<script>"}, "10.20.1.15|unparsed", "10.20.1.15"},
	}
	for _, c := range cases {
		got := src(c.peer, c.hdr)
		if got.label != c.label || got.proxy != c.proxy {
			t.Errorf("%s: %+v, want label %q proxy %q", c.name, got, c.label, c.proxy)
		}
		keys := got.keys("")
		if (c.proxy != "") != (len(keys) == 2) || keys[0].Factor != auth.FactorSource {
			t.Errorf("%s: keys %+v", c.name, keys)
		}
		if c.proxy != "" && (keys[1].Name != "proxy:"+c.proxy || keys[1].Factor != auth.FactorProxy) {
			t.Errorf("%s: proxy ceiling key %+v", c.name, keys[1])
		}
	}
}

// Public endpoints (CA download, self-service requests) behind a proxy that is not trusted: one client cannot
// use up the limit of everybody behind it, and invented client addresses share the proxy's ceiling.
func TestPublicRateLimitBehindUntrustedProxy(t *testing.T) {
	l := newRateLimiter(3, time.Minute)
	proxied := func(client string) throttleSource {
		return throttleSource{label: "10.20.1.15|" + client, proxy: "10.20.1.15"}
	}
	for i := 0; i < 3; i++ {
		if !l.allowSource(proxied("203.0.113.5")) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.allowSource(proxied("203.0.113.5")) {
		t.Fatal("the client behind the proxy exceeded its limit")
	}
	if !l.allowSource(proxied("203.0.113.6")) {
		t.Fatal("another client behind the same proxy was refused")
	}
	allowed := 4 // 3 + 1 above
	for i := 0; i < 10*auth.FactorProxy; i++ {
		if l.allowSource(proxied(fmt.Sprintf("198.51.100.%d", i))) {
			allowed++
		}
	}
	if allowed != 3*auth.FactorProxy {
		t.Fatalf("%d requests behind one untrusted proxy, want the ceiling %d", allowed, 3*auth.FactorProxy)
	}
	if !l.allowSource(throttleSource{label: "198.51.100.200"}) {
		t.Fatal("a direct client was refused")
	}
}
