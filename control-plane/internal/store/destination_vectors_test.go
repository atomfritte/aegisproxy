package store

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Destinations no rule may open: the same classification as the data-plane's is_forbidden_addr
// (testdata/destination_vectors.json), including cloud metadata endpoints outside the link-local range.
func TestForbiddenDestinationVectorsSharedWithDataPlane(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "destination_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Addresses []struct {
			Addr      string `json:"addr"`
			Forbidden bool   `json:"forbidden"`
		} `json:"addresses"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Addresses) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, c := range v.Addresses {
		if got := alwaysForbiddenAddr(netip.MustParseAddr(c.Addr)); got != c.Forbidden {
			t.Errorf("alwaysForbiddenAddr(%s) = %v, want %v", c.Addr, got, c.Forbidden)
		}
	}
}
