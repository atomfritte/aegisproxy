//go:build live

package defender

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A token request for a tenant that does not exist: Entra answers with an AADSTS error, which must be
// reported readably and without echoing the secret.
func TestLiveEntraTokenErrorForUnknownTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := New(Config{TenantID: "00000000-0000-4000-8000-00000000a315", ClientID: "00000000-0000-4000-8000-000000000001", ClientSecret: "not-a-real-secret-0815"}, nil)
	_, err := c.accessToken(ctx)
	if err == nil || !strings.Contains(err.Error(), "AADSTS") || strings.Contains(err.Error(), "not-a-real-secret") {
		t.Fatalf("token error: %v", err)
	}
	t.Logf("%v", err)
}

// The real Defender API (current, regional and legacy hosts) rejects an invalid token with 401; the client
// reports it as a permission/consent problem and forgets the token.
func TestLiveDefenderAPIRejectsInvalidToken(t *testing.T) {
	for _, base := range []string{DefaultAPIBase, "https://eu.api.security.microsoft.com", "https://api.securitycenter.microsoft.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c := New(Config{TenantID: "t", ClientID: "c", ClientSecret: "s", APIBase: base}, nil)
		c.token, c.tokenExp = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.e30.", time.Now().Add(time.Hour)
		_, err := c.Machines(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "unauthorized") {
			t.Fatalf("%s: %v", base, err)
		}
		if c.token != "" {
			t.Fatalf("%s: the rejected token must be dropped", base)
		}
	}
}
