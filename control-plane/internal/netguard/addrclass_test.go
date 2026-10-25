package netguard

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The address tables are shared with the data-plane (testdata/destination_vectors.json); outbound integrations
// refuse the forbidden destinations except loopback.
func TestAddressClassificationVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "destination_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Addresses []struct {
			Addr      string `json:"addr"`
			Internal  bool   `json:"internal"`
			Forbidden bool   `json:"forbidden"`
		} `json:"addresses"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Addresses) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, c := range v.Addresses {
		a := netip.MustParseAddr(c.Addr)
		if got := IsInternal(a); got != c.Internal {
			t.Errorf("IsInternal(%s) = %v, want %v", c.Addr, got, c.Internal)
		}
		if got := IsForbiddenDestination(a); got != c.Forbidden {
			t.Errorf("IsForbiddenDestination(%s) = %v, want %v", c.Addr, got, c.Forbidden)
		}
		if got, want := Forbidden(a), c.Forbidden && !IsLoopback(a); got != want {
			t.Errorf("Forbidden(%s) = %v, want %v", c.Addr, got, want)
		}
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"64:ff9b::a9fe:a9fe": "169.254.169.254", "64:ff9b:1::a00:5": "10.0.0.5", "::a00:5": "10.0.0.5",
		"2002:a83f:8110::1": "168.63.129.16", "::ffff:127.0.0.1": "127.0.0.1", "2001:db8::1": "", "10.0.0.1": "",
	} {
		got, ok := EmbeddedIPv4(netip.MustParseAddr(in))
		if (want == "") == ok || (ok && got.String() != want) {
			t.Errorf("EmbeddedIPv4(%s) = %v %v, want %q", in, got, ok, want)
		}
	}
	if !IsForbiddenDestination(netip.MustParseAddr("fe80::1%eth0")) {
		t.Error("zoned link-local address not forbidden")
	}
}
