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
	if _, ok := e.CheckRedirectGrant("srv-a", "objects.example", "/asset.tgz", "GET"); !ok {
		t.Fatal("grant of srv-a not found")
	}
	if _, ok := e.CheckRedirectGrant("srv-a", "objects.example", "/", "CONNECT"); !ok {
		t.Fatal("CONNECT pre-flight of srv-a not found")
	}
	for _, id := range []string{"srv-b", "203.0.113.10", ""} {
		if _, ok := e.CheckRedirectGrant(id, "objects.example", "/asset.tgz", "GET"); ok {
			t.Errorf("grant of srv-a usable by %q", id)
		}
	}
	if _, ok := e.CheckRedirectGrant("", "objects.example", "/other.tgz", "GET"); ok {
		t.Error("grant without server identity registered")
	}
}
