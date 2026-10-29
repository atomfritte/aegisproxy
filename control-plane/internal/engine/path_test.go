package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Path pattern semantics shared with the data-plane's match_path (testdata/path_vectors.json).
func TestPathVectorsSharedWithDataPlane(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "path_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Match []struct {
			Pattern string `json:"pattern"`
			Path    string `json:"path"`
			Match   bool   `json:"match"`
		} `json:"match"`
		Legacy []struct {
			In          string  `json:"in"`
			Out         string  `json:"out"`
			Changed     bool    `json:"changed"`
			LiteralStar bool    `json:"literal_star"`
			Old         [][]any `json:"old"`
		} `json:"legacy"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Match) == 0 || len(v.Legacy) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Match {
		if got := MatchPath(c.Pattern, c.Path); got != c.Match {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", c.Pattern, c.Path, got, c.Match)
		}
	}
	for _, c := range v.Legacy {
		out, changed, literal := LegacyPathPattern(c.In)
		if out != c.Out || changed != c.Changed || literal != c.LiteralStar {
			t.Errorf("LegacyPathPattern(%q) = (%q, %v, %v), want (%q, %v, %v)", c.In, out, changed, literal, c.Out, c.Changed, c.LiteralStar)
		}
		for _, o := range c.Old {
			if got := MatchPath(c.Out, o[0].(string)); got != o[1].(bool) {
				t.Errorf("rewritten %q -> %q changed its meaning for %q: %v", c.In, c.Out, o[0], got)
			}
		}
	}
}

func TestMatchPathLinearTime(t *testing.T) {
	start := time.Now()
	if MatchPath("/"+strings.Repeat("*a", 40)+"/x", "/"+strings.Repeat("a", 8000)) {
		t.Fatal("unexpected match")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("wildcard-heavy pattern took %v", d)
	}
}

// Redirect grants belong to the server identity: another server (or the bare source address) cannot use them.
func TestRedirectGrantsKeyedByServerID(t *testing.T) {
	e := NewPolicyEngine()
	e.RegisterRedirectGrant("srv-a", "https://objects.example/asset.tgz", "https://github.com/x", "r1", "gh", nil)
	e.RegisterRedirectGrant("", "https://objects.example/other.tgz", "https://github.com/x", "r1", "gh", nil)
	if _, ok := e.CheckRedirectGrant("srv-a", "https", "objects.example", 443, "/asset.tgz", "GET"); !ok {
		t.Fatal("grant of srv-a not found")
	}
	if _, ok := e.CheckRedirectGrant("srv-a", "https", "objects.example", 443, "/", "CONNECT"); !ok {
		t.Fatal("CONNECT pre-flight of srv-a not found")
	}
	for _, id := range []string{"srv-b", "203.0.113.10", ""} {
		if _, ok := e.CheckRedirectGrant(id, "https", "objects.example", 443, "/asset.tgz", "GET"); ok {
			t.Errorf("grant of srv-a usable by %q", id)
		}
	}
	if _, ok := e.CheckRedirectGrant("", "https", "objects.example", 443, "/other.tgz", "GET"); ok {
		t.Error("grant without server identity registered")
	}
}

// A grant covers exactly the redirect target's origin: scheme, host and effective port.
func TestRedirectGrantsKeyedByOrigin(t *testing.T) {
	e := NewPolicyEngine()
	e.RegisterRedirectGrant("srv-a", "https://objects.example:8443/asset.tgz", "https://github.com/x", "r1", "gh", nil)
	e.RegisterRedirectGrant("srv-a", "//plain.example/pkg.tgz", "http://github.com/x", "r1", "gh", nil)
	e.RegisterRedirectGrant("srv-a", "https://bad-port.example:99999/x", "https://github.com/x", "r1", "gh", nil)
	cases := []struct {
		scheme, host string
		port         int
		path, method string
		want         bool
	}{
		{"https", "objects.example", 8443, "/asset.tgz", "GET", true},
		{"http", "objects.example", 80, "/asset.tgz", "GET", false},
		{"https", "objects.example", 443, "/asset.tgz", "GET", false},
		{"http", "objects.example", 8443, "/asset.tgz", "GET", false},
		{"https", "objects.example", 8443, "/", "CONNECT", true},
		{"https", "objects.example", 443, "/", "CONNECT", false},
		{"http", "plain.example", 80, "/pkg.tgz", "GET", true},
		{"http", "plain.example", 0, "/pkg.tgz", "HEAD", true},
		{"https", "plain.example", 443, "/pkg.tgz", "GET", false},
		{"https", "plain.example", 80, "/pkg.tgz", "GET", false},
		{"https", "plain.example", 443, "/", "CONNECT", false},
		{"http", "plain.example", 80, "/", "CONNECT", true},
		{"ftp", "plain.example", 80, "/pkg.tgz", "GET", false},
		{"https", "bad-port.example", 443, "/x", "GET", false},
	}
	for _, c := range cases {
		if _, ok := e.CheckRedirectGrant("srv-a", c.scheme, c.host, c.port, c.path, c.method); ok != c.want {
			t.Errorf("%s %s://%s:%d%s: granted=%v, want %v", c.method, c.scheme, c.host, c.port, c.path, ok, c.want)
		}
	}
	for _, c := range []struct {
		url, scheme string
		port        int
		wantScheme  string
		wantPort    int
	}{
		{"https://h.example:8443/x", "", 8443, "https", 8443},
		{"http://h.example/x", "", 80, "http", 80},
		{"", "http", 0, "http", 80},
		{"", "", 80, "http", 80},
		{"", "", 0, "https", 443},
		{"", "ftp", 21, "https", 21},
	} {
		if s, p := RequestOrigin(c.url, c.scheme, c.port); s != c.wantScheme || p != c.wantPort {
			t.Errorf("RequestOrigin(%q, %q, %d) = %s, %d", c.url, c.scheme, c.port, s, p)
		}
	}
}
