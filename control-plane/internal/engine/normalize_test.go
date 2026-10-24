package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The data-plane enforces with normalize_host/canonicalize_path (Python); policy simulation, learning and request
// handling use NormalizeHost/CanonicalizePath. Both suites run the same vectors so the two cannot drift apart.
func TestNormalizationVectorsSharedWithDataPlane(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "normalization_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Hosts []struct {
			In  string `json:"in"`
			Out string `json:"out"`
		} `json:"hosts"`
		Paths []struct {
			In  string `json:"in"`
			Out string `json:"out"`
			OK  bool   `json:"ok"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Hosts) == 0 || len(v.Paths) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Hosts {
		if got := NormalizeHost(c.In); got != c.Out {
			t.Errorf("NormalizeHost(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
	for _, c := range v.Paths {
		if got, ok := CanonicalizePath(c.In); got != c.Out || ok != c.OK {
			t.Errorf("CanonicalizePath(%q) = (%q, %v), want (%q, %v)", c.In, got, ok, c.Out, c.OK)
		}
	}
}
