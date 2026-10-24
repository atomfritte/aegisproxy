//go:build live

// Live conformance against Microsoft Entra ID's public endpoints (no tenant or credentials needed):
//
//	go -C control-plane test -tags live -run Live ./internal/...
package oidc

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// Microsoft's own tenant: its OpenID metadata is public and used throughout Microsoft's documentation.
const liveEntraIssuer = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"

func TestLiveEntraDiscoveryAndSigningKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(Config{Issuer: liveEntraIssuer, ClientID: "00000000-0000-0000-0000-000000000001", RedirectURI: "https://aegis.example/api/auth/sso/callback"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Discover(ctx); err != nil {
		t.Fatalf("Entra discovery (issuer match, https endpoints): %v", err)
	}
	methods, _ := p.TokenAuthMethods(ctx)
	for _, m := range []string{"client_secret_post", "private_key_jwt", "client_secret_basic"} {
		if !slices.Contains(methods, m) {
			t.Errorf("Entra no longer advertises %s: %v", m, methods)
		}
	}
	n, err := p.CheckSigningKeys(ctx)
	if err != nil || n < 2 {
		t.Fatalf("Entra JWKS: %d usable RSA keys, %v", n, err)
	}
	_, challenge := NewPKCE()
	raw, err := p.AuthCodeURL(ctx, "state-1", "nonce-1", challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Host != "login.microsoftonline.com" || !strings.HasSuffix(u.Path, "/oauth2/v2.0/authorize") || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Fatalf("authorization URL: %s", raw)
	}
	t.Logf("Entra: %d signing keys, token auth methods %v", n, methods)
}
