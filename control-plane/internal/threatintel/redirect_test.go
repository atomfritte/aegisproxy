package threatintel

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A feed's custom auth header belongs to the configured host: redirects to another host do not
// carry it (net/http only strips Authorization and Cookie, and keeps them for subdomains).
func TestFeedRedirectKeepsCredentialsOnHost(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]http.Header{}
	record := func(name string, r *http.Request) {
		mu.Lock()
		seen[name] = r.Header.Clone()
		mu.Unlock()
	}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("other", r)
		_, _ = w.Write([]byte("evil.example\n"))
	}))
	defer other.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/list.txt", http.StatusFound)
		case "/away":
			http.Redirect(w, r, other.URL+"/list.txt", http.StatusFound)
		default:
			record("origin", r)
			_, _ = w.Write([]byte("bad.example\n"))
		}
	}))
	defer origin.Close()

	c := newFeedClient("")
	c.Transport = origin.Client().Transport // same CheckRedirect, without the SSRF guard (loopback test servers)
	get := func(path string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, origin.URL+path, nil)
		req.Header.Set("User-Agent", "AegisProxy-ThreatIntel/2.0 (+feed-sync)")
		req.Header.Set("If-None-Match", `"v1"`)
		req.Header.Set("X-Api-Key", "feed-secret")
		req.Header.Set("Authorization", "Bearer feed-token")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	get("/moved")
	if h := seen["origin"]; h.Get("X-Api-Key") != "feed-secret" || h.Get("Authorization") != "Bearer feed-token" {
		t.Errorf("same-host redirect lost the credentials: %v", h)
	}
	get("/away")
	h := seen["other"]
	if h == nil {
		t.Fatal("cross-host redirect not followed")
	}
	if h.Get("X-Api-Key") != "" || h.Get("Authorization") != "" {
		t.Errorf("credentials followed the redirect to %s: %v", other.URL, h)
	}
	if h.Get("User-Agent") == "" || h.Get("If-None-Match") == "" {
		t.Errorf("standard headers dropped: %v", h)
	}
}
