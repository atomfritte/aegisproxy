package netguard

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestForbidden(t *testing.T) {
	for addr, want := range map[string]bool{"169.254.169.254": true, "::ffff:169.254.169.254": true, "fe80::1": true, "0.0.0.0": true,
		"224.0.0.1": true, "127.0.0.1": false, "10.1.2.3": false, "20.190.1.1": false} {
		if got := Forbidden(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Forbidden(%s) = %v", addr, got)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Dialer(time.Second).DialContext(ctx, "tcp", "169.254.169.254:80"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("metadata address dialed: %v", err)
	}
}
