package oidc_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/oidc"
	"aegisproxy/control-plane/internal/oidc/oidctest"
)

func genKey(t *testing.T, alg string) (*oidc.GeneratedClientKey, *oidc.ClientKey, *x509.Certificate) {
	t.Helper()
	g, err := oidc.GenerateClientKey(alg, "AegisProxy test", time.Now(), 730*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := oidc.ParseClientKey(g.KID, g.Alg, g.PrivateKeyPEM, g.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(g.CertificatePEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return g, ck, cert
}

func TestGenerateClientKey(t *testing.T) {
	for _, alg := range []string{oidc.AlgRS256, oidc.AlgES256} {
		g, ck, cert := genKey(t, alg)
		if !strings.Contains(g.PrivateKeyPEM, "BEGIN PRIVATE KEY") {
			t.Errorf("%s: private key is not PKCS#8 PEM", alg)
		}
		if alg == oidc.AlgRS256 && cert.PublicKey.(*rsa.PublicKey).N.BitLen() != 3072 {
			t.Errorf("RSA key size %d, want 3072", cert.PublicKey.(*rsa.PublicKey).N.BitLen())
		}
		kid, err := oidc.JWKThumbprint(cert.PublicKey)
		if err != nil || kid != g.KID {
			t.Errorf("%s: kid %q is not the JWK thumbprint %q (%v)", alg, g.KID, kid, err)
		}
		s1, s256 := sha1.Sum(cert.Raw), sha256.Sum256(cert.Raw)
		if g.X5t != base64.RawURLEncoding.EncodeToString(s1[:]) || g.X5tS256 != base64.RawURLEncoding.EncodeToString(s256[:]) {
			t.Errorf("%s: certificate thumbprints wrong", alg)
		}
		if cert.NotAfter.Sub(cert.NotBefore) < 729*24*time.Hour || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			t.Errorf("%s: certificate validity/usage %v %v", alg, cert.NotAfter, cert.KeyUsage)
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			t.Errorf("%s: not self-signed: %v", alg, err)
		}
		jwk, err := oidc.PublicJWK(ck.KID, ck.Alg, ck.Signer.Public(), ck.CertDER)
		if err != nil || jwk["kid"] != g.KID || jwk["use"] != "sig" || jwk["alg"] != alg || jwk["x5t"] != g.X5t || jwk["x5t#S256"] != g.X5tS256 {
			t.Errorf("%s: JWK %v (%v)", alg, jwk, err)
		}
		if _, ok := jwk["d"]; ok {
			t.Fatalf("%s: private member in public JWK", alg)
		}
	}
	if _, err := oidc.GenerateClientKey("HS256", "x", time.Now(), time.Hour); err == nil {
		t.Error("HS256 client key accepted")
	}
}

// RFC 7638 section 3.1 test vector.
func TestJWKThumbprintRFC7638(t *testing.T) {
	n, _ := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	kid, err := oidc.JWKThumbprint(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537})
	if err != nil || kid != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %q (%v)", kid, err)
	}
}

func TestSignClientAssertion(t *testing.T) {
	now := time.Now()
	for _, alg := range []string{oidc.AlgRS256, oidc.AlgES256} {
		g, ck, cert := genKey(t, alg)
		const aud = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token"
		a1, err := oidc.SignClientAssertion(ck, "client-1", aud, now)
		if err != nil {
			t.Fatal(err)
		}
		hdr, claims, err := oidc.VerifyClientAssertionSignature(a1, cert.PublicKey)
		if err != nil {
			t.Fatalf("%s: signature does not verify with the certificate key: %v", alg, err)
		}
		if hdr["alg"] != alg || hdr["kid"] != g.KID || hdr["typ"] != "JWT" || hdr["x5t"] != g.X5t || hdr["x5t#S256"] != g.X5tS256 {
			t.Errorf("%s: header %v", alg, hdr)
		}
		iat, exp, nbf := claims["iat"].(float64), claims["exp"].(float64), claims["nbf"].(float64)
		if claims["iss"] != "client-1" || claims["sub"] != "client-1" || claims["aud"] != aud || claims["jti"] == "" ||
			int64(iat) != now.Unix() || nbf != iat || exp-iat != 300 {
			t.Errorf("%s: claims %v", alg, claims)
		}
		a2, _ := oidc.SignClientAssertion(ck, "client-1", aud, now)
		_, c2, _ := oidc.VerifyClientAssertionSignature(a2, cert.PublicKey)
		if c2["jti"] == claims["jti"] {
			t.Errorf("%s: jti reused", alg)
		}
		// Tampering and a foreign key are detected.
		parts := strings.Split(a1, ".")
		forged, _ := json.Marshal(map[string]any{"iss": "client-1", "sub": "client-1", "aud": "https://evil.example/token", "exp": exp})
		if _, _, err := oidc.VerifyClientAssertionSignature(parts[0]+"."+base64.RawURLEncoding.EncodeToString(forged)+"."+parts[2], cert.PublicKey); err == nil {
			t.Errorf("%s: tampered assertion verified", alg)
		}
		_, _, other := genKey(t, alg)
		if _, _, err := oidc.VerifyClientAssertionSignature(a1, other.PublicKey); err == nil {
			t.Errorf("%s: assertion verified with another key", alg)
		}
		// Without a certificate there are no thumbprint headers.
		bare := *ck
		bare.CertDER = nil
		a3, _ := oidc.SignClientAssertion(&bare, "client-1", aud, now)
		h3, _, _ := oidc.VerifyClientAssertionSignature(a3, cert.PublicKey)
		if _, ok := h3["x5t"]; ok {
			t.Errorf("%s: x5t without certificate", alg)
		}
	}
	if _, err := oidc.SignClientAssertion(nil, "c", "a", now); err == nil {
		t.Error("nil key accepted")
	}
}

func TestParseClientKeyRejectsMismatch(t *testing.T) {
	g1, _, _ := genKey(t, oidc.AlgRS256)
	g2, _, _ := genKey(t, oidc.AlgES256)
	if _, err := oidc.ParseClientKey(g1.KID, oidc.AlgRS256, g1.PrivateKeyPEM, g2.CertificatePEM); err == nil {
		t.Error("certificate of another key accepted")
	}
	if _, err := oidc.ParseClientKey(g1.KID, oidc.AlgES256, g1.PrivateKeyPEM, ""); err == nil {
		t.Error("RSA key accepted for ES256")
	}
	if _, err := oidc.ParseClientKey(g1.KID, oidc.AlgRS256, "garbage", ""); err == nil {
		t.Error("garbage accepted")
	}
}

// codeFor runs the authorization request against the mock IdP and returns the code.
func codeFor(t *testing.T, p *oidc.Provider) (code, verifier string) {
	t.Helper()
	verifier, challenge := oidc.NewPKCE()
	target, err := p.AuthCodeURL(context.Background(), "st", "n1", challenge, nil)
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
	return loc.Query().Get("code"), verifier
}

func TestExchangeWithPrivateKeyJWT(t *testing.T) {
	ctx := context.Background()
	_, rsaKey, rsaCert := genKey(t, oidc.AlgRS256)
	_, ecKey, _ := genKey(t, oidc.AlgES256)

	// Entra-style: registered certificate (key looked up by kid), RS256.
	idp := oidctest.New("client-1", "unused-secret")
	defer idp.Close()
	idp.AuthMethods = []string{"private_key_jwt"}
	idp.ClientKeys = map[string]crypto.PublicKey{rsaKey.KID: rsaCert.PublicKey}
	cfg := oidc.Config{Issuer: idp.Server.URL, ClientID: "client-1", ClientSecret: "unused-secret", TokenAuthMethod: oidc.TokenAuthPrivateKeyJWT,
		ClientKey: rsaKey, RedirectURI: "http://127.0.0.1/api/auth/sso/callback"}
	p, err := oidc.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := codeFor(t, p)
	if _, err := p.Exchange(ctx, code, verifier); err != nil {
		t.Fatalf("RS256 assertion rejected: %v", err)
	}
	if idp.LastAssertion.Header["x5t"] == nil || idp.LastAssertion.Claims["aud"] != idp.Server.URL+"/token" {
		t.Errorf("assertion %+v", idp.LastAssertion)
	}

	// Keycloak/Okta-style: the IdP fetches the client's JWKS URL; ES256.
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j, _ := oidc.PublicJWK(ecKey.KID, ecKey.Alg, ecKey.Signer.Public(), ecKey.CertDER)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{j}})
	}))
	defer jwks.Close()
	idp.ClientKeys, idp.ClientJWKSURL = nil, jwks.URL
	cfg.ClientKey = ecKey
	p, _ = oidc.New(cfg, nil)
	code, verifier = codeFor(t, p)
	if _, err := p.Exchange(ctx, code, verifier); err != nil {
		t.Fatalf("ES256 assertion rejected: %v", err)
	}

	// A key the IdP does not know is refused.
	cfg.ClientKey = rsaKey
	p, _ = oidc.New(cfg, nil)
	code, verifier = codeFor(t, p)
	if _, err := p.Exchange(ctx, code, verifier); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("unregistered key: %v", err)
	}
	cfg.ClientKey = nil
	if _, err := oidc.New(cfg, nil); err == nil {
		t.Error("private_key_jwt without a key accepted")
	}
}
