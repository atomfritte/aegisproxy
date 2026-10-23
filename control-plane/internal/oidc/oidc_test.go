package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/oidc"
	"aegisproxy/control-plane/internal/oidc/oidctest"
)

func TestVerifyIDToken(t *testing.T) {
	idp := oidctest.New("client-1", "s")
	defer idp.Close()
	p, err := oidc.New(oidc.Config{Issuer: idp.Server.URL, ClientID: "client-1", RedirectURI: "http://127.0.0.1/api/auth/sso/callback"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := func() map[string]any {
		return map[string]any{"iss": idp.Server.URL, "aud": "client-1", "sub": "u1", "nonce": "n1",
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "groups": []string{"g1", "g2"}}
	}
	c, err := p.Verify(ctx, idp.Sign(base()), "n1")
	if err != nil || len(c.Strings("groups")) != 2 {
		t.Fatalf("valid token: %v", err)
	}
	cases := map[string]func(m map[string]any){
		"wrong issuer":   func(m map[string]any) { m["iss"] = "https://evil.example" },
		"wrong audience": func(m map[string]any) { m["aud"] = "other" },
		"expired":        func(m map[string]any) { m["exp"] = time.Now().Add(-10 * time.Minute).Unix() },
		"future iat":     func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() },
		"nonce replay":   func(m map[string]any) { m["nonce"] = "other" },
		"no subject":     func(m map[string]any) { delete(m, "sub") },
		"azp mismatch":   func(m map[string]any) { m["aud"] = []string{"client-1", "x"}; m["azp"] = "x" },
	}
	for name, mutate := range cases {
		m := base()
		mutate(m)
		if _, err := p.Verify(ctx, idp.Sign(m), "n1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	tok := idp.Sign(base())
	parts := strings.Split(tok, ".")
	if _, err := p.Verify(ctx, parts[0]+"."+parts[1]+"x."+parts[2], "n1"); err == nil {
		t.Error("tampered payload accepted")
	}
	idp.Alg = "none"
	if _, err := p.Verify(ctx, idp.Sign(base()), "n1"); err == nil {
		t.Error("alg=none accepted")
	}
	idp.Alg = "HS256"
	if _, err := p.Verify(ctx, idp.Sign(base()), "n1"); err == nil {
		t.Error("HS256 accepted")
	}
	idp.Alg = ""
	// Key rotation: a token signed by an unknown key is rejected; after JWKS rotation it is accepted.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	old := idp.Key
	idp.Key = other
	if _, err := p.Verify(ctx, idp.Sign(base()), "n1"); err == nil {
		t.Error("token signed with a non-published key accepted")
	}
	idp.Key = old
	if _, err := p.Verify(ctx, idp.Sign(base()), "n1"); err != nil {
		t.Errorf("published key after attack attempt: %v", err)
	}
	if _, err := oidc.New(oidc.Config{Issuer: "http://example.com", ClientID: "x", RedirectURI: "y"}, nil); err == nil {
		t.Error("plain-http issuer accepted")
	}
}

func TestTokenEndpointClientAuthentication(t *testing.T) {
	const secret = "s:e/c r+t%" // exercises the form-encoding of client_secret_basic
	for _, tc := range []struct {
		advertised []string
		method     string
		ok         bool
	}{
		{[]string{"client_secret_post"}, "", true},
		{[]string{"client_secret_basic"}, "", true},
		{[]string{"client_secret_basic"}, "client_secret_basic", true},
		{[]string{"client_secret_basic"}, "client_secret_post", false},
		{[]string{"client_secret_post", "client_secret_basic"}, "", true},
		{[]string{"client_secret_post", "client_secret_basic"}, "client_secret_basic", false},
	} {
		idp := oidctest.New("client-1", secret)
		idp.AuthMethods = tc.advertised
		p, err := oidc.New(oidc.Config{Issuer: idp.Server.URL, ClientID: "client-1", ClientSecret: secret, TokenAuthMethod: tc.method,
			RedirectURI: "http://127.0.0.1/api/auth/sso/callback"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		verifier, challenge := oidc.NewPKCE()
		target, err := p.AuthCodeURL(ctx, "st", "n1", challenge, nil)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		_, err = p.Exchange(ctx, loc.Query().Get("code"), verifier)
		if (err == nil) != tc.ok {
			t.Errorf("advertised %v, method %q: err=%v, want ok=%v", tc.advertised, tc.method, err, tc.ok)
		}
		idp.Close()
	}
}
