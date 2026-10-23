// Package oidctest provides an in-process OpenID provider for tests.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// IdP is a minimal authorization server: it "authenticates" whoever is configured in User.
type IdP struct {
	Server   *httptest.Server
	Key      *rsa.PrivateKey
	KeyID    string
	ClientID string
	Secret   string

	mu     sync.Mutex
	User   map[string]any // claims added to the ID token
	codes  map[string]codeInfo
	Tamper func(claims map[string]any) // optional manipulation of the next tokens
	Alg    string                      // header alg override (attack tests)
	// AuthMethods is published as token_endpoint_auth_methods_supported; the token endpoint
	// accepts the client secret only in the advertised way (default client_secret_post).
	AuthMethods []string

	// private_key_jwt (RFC 7523): the client's public keys come from ClientJWKSURL (fetched on every
	// token request, like an IdP configured with a JWKS URL) or ClientKeys (kid -> key, like an
	// uploaded certificate). LastAssertion records the header and claims of the last accepted one.
	ClientJWKSURL string
	ClientKeys    map[string]crypto.PublicKey
	LastAssertion struct{ Header, Claims map[string]any }
	usedJTI       map[string]bool
}

type codeInfo struct {
	nonce, challenge, redirect string
}

func New(clientID, secret string) *IdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := &IdP{Key: key, KeyID: "k1", ClientID: clientID, Secret: secret, codes: map[string]codeInfo{}, AuthMethods: []string{"client_secret_post"}}
	mux := http.NewServeMux()
	idp.Server = httptest.NewServer(mux)
	iss := idp.Server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize",
			"token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks", "token_endpoint_auth_methods_supported": idp.AuthMethods})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": idp.KeyID, "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(idp.Key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idp.Key.E)).Bytes())}}})
	})
	// /authorize immediately redirects back with a code (the user is "already signed in").
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != idp.ClientID || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad request", 400)
			return
		}
		code := base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
		idp.mu.Lock()
		idp.codes[code] = codeInfo{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		idp.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		ci, ok := idp.codes[r.Form.Get("code")]
		delete(idp.codes, r.Form.Get("code"))
		idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		secret := r.Form.Get("client_secret")
		if slices.Contains(idp.AuthMethods, "private_key_jwt") && (r.Form.Get("client_assertion") != "" || len(idp.AuthMethods) == 1) {
			if err := idp.verifyAssertion(r, iss+"/token"); err != nil {
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": err.Error()})
				return
			}
			secret = idp.Secret
		} else if slices.Contains(idp.AuthMethods, "client_secret_basic") && !slices.Contains(idp.AuthMethods, "client_secret_post") {
			user, pass, _ := r.BasicAuth()
			u, _ := url.QueryUnescape(user)
			p, _ := url.QueryUnescape(pass)
			if u != idp.ClientID || r.Form.Get("client_secret") != "" {
				p = ""
			}
			secret = p
		}
		if !ok || secret != idp.Secret || base64.RawURLEncoding.EncodeToString(sum[:]) != ci.challenge || r.Form.Get("redirect_uri") != ci.redirect {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		claims := map[string]any{"iss": iss, "aud": idp.ClientID, "exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(), "nonce": ci.nonce, "sub": "subject-1"}
		idp.mu.Lock()
		for k, v := range idp.User {
			claims[k] = v
		}
		if idp.Tamper != nil {
			idp.Tamper(claims)
		}
		idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idp.Sign(claims), "token_type": "Bearer"})
	})
	return idp
}

// Sign creates an RS256 token (or uses Alg for attack tests).
func (idp *IdP) Sign(claims map[string]any) string {
	alg := "RS256"
	if idp.Alg != "" {
		alg = idp.Alg
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": idp.KeyID, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	if alg == "none" {
		return signing + "."
	}
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, idp.Key, crypto.SHA256, sum[:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (idp *IdP) Close() { idp.Server.Close() }

// verifyAssertion checks a private_key_jwt client assertion as an authorization server must
// (RFC 7523 section 3): type, signature with a registered key, iss = sub = client_id, aud = token
// endpoint, a short lifetime and single use of the jti.
func (idp *IdP) verifyAssertion(r *http.Request, tokenEndpoint string) error {
	if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return errors.New("client_assertion_type missing or wrong")
	}
	if r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
		return errors.New("more than one client authentication method")
	}
	parts := strings.Split(r.Form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return errors.New("malformed client assertion")
	}
	var hdr, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(cb, &claims) != nil {
		return errors.New("malformed client assertion")
	}
	kid, _ := hdr["kid"].(string)
	alg, _ := hdr["alg"].(string)
	keys, err := idp.clientKeys()
	if err != nil {
		return err
	}
	pub, ok := keys[kid]
	if !ok {
		return fmt.Errorf("unknown client key %q", kid)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return errors.New("client assertion signature invalid")
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("client assertion signature invalid")
		}
	default:
		return errors.New("unsupported client key")
	}
	now := float64(time.Now().Unix())
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	jti, _ := claims["jti"].(string)
	switch {
	case claims["iss"] != idp.ClientID || claims["sub"] != idp.ClientID:
		return errors.New("iss and sub must be the client ID")
	case claims["aud"] != tokenEndpoint:
		return fmt.Errorf("aud %v is not the token endpoint", claims["aud"])
	case exp < now || exp-iat > 600 || iat > now+60:
		return errors.New("client assertion expired or too long-lived")
	case jti == "":
		return errors.New("jti missing")
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if idp.usedJTI == nil {
		idp.usedJTI = map[string]bool{}
	}
	if idp.usedJTI[jti] {
		return errors.New("client assertion replayed")
	}
	idp.usedJTI[jti] = true
	idp.LastAssertion.Header, idp.LastAssertion.Claims = hdr, claims
	return nil
}

func (idp *IdP) clientKeys() (map[string]crypto.PublicKey, error) {
	if idp.ClientJWKSURL == "" {
		return idp.ClientKeys, nil
	}
	resp, err := http.Get(idp.ClientJWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&set) != nil {
		return nil, fmt.Errorf("client JWKS: HTTP %d", resp.StatusCode)
	}
	keys := map[string]crypto.PublicKey{}
	dec := func(v string) *big.Int {
		b, _ := base64.RawURLEncoding.DecodeString(v)
		return new(big.Int).SetBytes(b)
	}
	for _, k := range set.Keys {
		switch {
		case k.Use != "sig":
		case k.Kty == "RSA":
			keys[k.Kid] = &rsa.PublicKey{N: dec(k.N), E: int(dec(k.E).Int64())}
		case k.Kty == "EC" && k.Crv == "P-256":
			x, _ := base64.RawURLEncoding.DecodeString(k.X)
			y, _ := base64.RawURLEncoding.DecodeString(k.Y)
			if pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...)); err == nil {
				keys[k.Kid] = pub
			}
		}
	}
	return keys, nil
}
