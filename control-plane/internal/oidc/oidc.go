// Package oidc implements the OpenID Connect authorization code flow with PKCE for the console
// (Microsoft Entra ID, Okta, Keycloak, ADFS, Ping, Google Workspace …) using only the standard
// library: discovery, JWKS (with key rotation), ID-token signature and claim validation.
package oidc

import (
	"aegisproxy/control-plane/internal/netguard"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config describes one relying-party registration.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	// TokenAuthMethod is client_secret_post, client_secret_basic, private_key_jwt or "" (auto: post
	// when the provider advertises it, otherwise basic, the OIDC default).
	TokenAuthMethod string
	// ClientKey signs the client assertion for private_key_jwt (OIDC Core section 9, RFC 7523).
	ClientKey *ClientKey
}

// TokenAuthPrivateKeyJWT authenticates the client with a signed JWT instead of a shared secret.
const TokenAuthPrivateKeyJWT = "private_key_jwt"

type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// useBasicAuth decides how the client secret is sent to the token endpoint.
func (p *Provider) useBasicAuth(d *discovery) bool {
	switch p.cfg.TokenAuthMethod {
	case "client_secret_basic":
		return true
	case "client_secret_post":
		return false
	}
	return !slices.Contains(d.TokenAuthMethods, "client_secret_post")
}

// Provider caches discovery metadata and signing keys of one issuer.
type Provider struct {
	cfg    Config
	client *http.Client

	mu       sync.Mutex
	disc     *discovery
	discAt   time.Time
	keys     map[string]crypto.PublicKey
	keysAt   time.Time
	now      func() time.Time
	maxClock time.Duration
}

// IsLoopback reports whether a URL points to the local machine (http allowed only there).
func IsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ValidateIssuer requires https (http only for loopback test providers).
func ValidateIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("issuer must be an absolute URL without query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && IsLoopback(raw)) {
		return errors.New("issuer must use https")
	}
	return nil
}

func New(cfg Config, client *http.Client) (*Provider, error) {
	if err := ValidateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, errors.New("client id and redirect URI are required")
	}
	if cfg.TokenAuthMethod == TokenAuthPrivateKeyJWT && cfg.ClientKey == nil {
		return nil, errors.New("private_key_jwt requires a client key")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			DialContext: netguard.Dialer(10 * time.Second).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Provider{cfg: cfg, client: client, now: time.Now, maxClock: 2 * time.Minute}, nil
}

func (p *Provider) getJSON(ctx context.Context, target string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", target, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func (p *Provider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disc != nil && time.Since(p.discAt) < time.Hour {
		return p.disc, nil
	}
	var d discovery
	if err := p.getJSON(ctx, strings.TrimRight(p.cfg.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(p.cfg.Issuer, "/") {
		return nil, fmt.Errorf("OIDC discovery: issuer mismatch (%s)", d.Issuer)
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		u, err := url.Parse(e)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && IsLoopback(e))) {
			return nil, fmt.Errorf("OIDC discovery: endpoint %q must use https", e)
		}
	}
	p.disc, p.discAt = &d, time.Now()
	return p.disc, nil
}

// Discover verifies the provider configuration (used by the "test connection" button).
func (p *Provider) Discover(ctx context.Context) error {
	_, err := p.discover(ctx)
	return err
}

// TokenAuthMethods returns the token_endpoint_auth_methods_supported of the discovery document.
func (p *Provider) TokenAuthMethods(ctx context.Context) ([]string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), d.TokenAuthMethods...), nil
}

// CheckSigningKeys fetches the JWKS and returns the number of usable signature keys.
func (p *Provider) CheckSigningKeys(ctx context.Context) (int, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return 0, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return 0, fmt.Errorf("JWKS: %w", err)
	}
	n := 0
	for _, j := range set.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		if _, err := parseJWK(j); err == nil {
			n++
		}
	}
	if n == 0 {
		return 0, errors.New("JWKS contains no usable signing key (RSA ≥ 2048 bits, P-256 or P-384)")
	}
	return n, nil
}

// NewPKCE returns a code verifier and its S256 challenge.
func NewPKCE() (verifier, challenge string) {
	verifier = RandomString(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthCodeURL builds the authorization request.
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, challenge string, extra url.Values) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURI},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"response_mode":         {"query"},
	}
	for k, v := range extra {
		q[k] = v
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return d.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange redeems an authorization code and returns the raw ID token.
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.cfg.RedirectURI},
		"client_id": {p.cfg.ClientID}, "code_verifier": {verifier}}
	jwtAuth := p.cfg.TokenAuthMethod == TokenAuthPrivateKeyJWT
	basic := !jwtAuth && p.cfg.ClientSecret != "" && p.useBasicAuth(d)
	switch {
	case jwtAuth:
		// The client secret (if any is still stored) is never sent together with an assertion.
		assertion, err := SignClientAssertion(p.cfg.ClientKey, p.cfg.ClientID, d.TokenEndpoint, p.now())
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", ClientAssertionType)
		form.Set("client_assertion", assertion)
	case p.cfg.ClientSecret != "" && !basic:
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	if basic { // RFC 6749 section 2.3.1: form-encode before Base64
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return "", fmt.Errorf("token endpoint: invalid response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		return "", fmt.Errorf("token endpoint: %s %s", tok.Error, truncate(tok.Description, 200))
	}
	return tok.IDToken, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64int(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64int(k.E)
		if err != nil || !e.IsInt64() {
			return nil, errors.New("bad exponent")
		}
		if n.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported curve %s", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, errX := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
		y, errY := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.Y, "="))
		if errX != nil || errY != nil || len(x) != size || len(y) != size {
			return nil, errors.New("invalid EC coordinates")
		}
		// ParseUncompressedPublicKey rejects points that are not on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, fmt.Errorf("invalid EC key: %w", err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %s", k.Kty)
}

// key returns the signing key for kid, refreshing the JWKS (rate limited) on unknown key ids.
func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	k, ok := p.keys[kid]
	fresh := time.Since(p.keysAt) < time.Minute
	p.mu.Unlock()
	if ok {
		return k, nil
	}
	if fresh {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range set.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		if pk, err := parseJWK(j); err == nil {
			keys[j.Kid] = pk
		}
	}
	p.mu.Lock()
	p.keys, p.keysAt = keys, time.Now()
	p.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

// Claims are the validated ID-token claims.
type Claims map[string]any

func (c Claims) String(name string) string {
	if v, ok := c[name].(string); ok {
		return v
	}
	return ""
}

// Strings returns a string or string-array claim as a slice.
func (c Claims) Strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func numericTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0), true
	case json.Number:
		i, err := x.Int64()
		return time.Unix(i, 0), err == nil
	}
	return time.Time{}, false
}

// Verify validates signature, issuer, audience, expiry and nonce of an ID token.
func (p *Provider) Verify(ctx context.Context, raw, nonce string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed ID token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("malformed ID token header")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed ID token signature")
	}
	pub, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(hdr.Alg, pub, signed, sig); err != nil {
		return nil, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	var claims Claims
	if err := dec.Decode(&claims); err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	for k, v := range claims { // normalize numbers for callers
		if n, ok := v.(json.Number); ok {
			if f, err := n.Float64(); err == nil {
				claims[k] = f
			}
		}
	}
	now := p.now()
	if strings.TrimRight(claims.String("iss"), "/") != strings.TrimRight(p.cfg.Issuer, "/") {
		return nil, fmt.Errorf("ID token issuer %q does not match", claims.String("iss"))
	}
	aud := claims.Strings("aud")
	audOK := false
	for _, a := range aud {
		if a == p.cfg.ClientID {
			audOK = true
		}
	}
	if !audOK {
		return nil, errors.New("ID token audience does not contain this client")
	}
	if len(aud) > 1 && claims.String("azp") != "" && claims.String("azp") != p.cfg.ClientID {
		return nil, errors.New("ID token authorized party mismatch")
	}
	exp, ok := numericTime(claims["exp"])
	if !ok || now.After(exp.Add(p.maxClock)) {
		return nil, errors.New("ID token expired")
	}
	if iat, ok := numericTime(claims["iat"]); ok && iat.After(now.Add(p.maxClock)) {
		return nil, errors.New("ID token issued in the future")
	}
	if nbf, ok := numericTime(claims["nbf"]); ok && nbf.After(now.Add(p.maxClock)) {
		return nil, errors.New("ID token not yet valid")
	}
	if nonce == "" || claims.String("nonce") != nonce {
		return nil, errors.New("ID token nonce mismatch (possible replay)")
	}
	if claims.String("sub") == "" {
		return nil, errors.New("ID token without subject")
	}
	return claims, nil
}

func verifySignature(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	var h hash.Hash
	var ch crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		h, ch = sha256.New(), crypto.SHA256
	case "RS384", "PS384", "ES384":
		h, ch = sha512.New384(), crypto.SHA384
	case "RS512", "PS512":
		h, ch = sha512.New(), crypto.SHA512
	default:
		return fmt.Errorf("ID token algorithm %q is not allowed", alg)
	}
	h.Write(signed)
	digest := h.Sum(nil)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch alg[:2] {
		case "RS":
			if rsa.VerifyPKCS1v15(k, ch, digest, sig) == nil {
				return nil
			}
		case "PS":
			if rsa.VerifyPSS(k, ch, digest, sig, nil) == nil {
				return nil
			}
		}
	case *ecdsa.PublicKey:
		// The curve is bound to the algorithm (RFC 7518 section 3.4).
		if (alg == "ES256" && k.Curve == elliptic.P256()) || (alg == "ES384" && k.Curve == elliptic.P384()) {
			size := (k.Curve.Params().BitSize + 7) / 8
			if len(sig) == 2*size {
				r := new(big.Int).SetBytes(sig[:size])
				s := new(big.Int).SetBytes(sig[size:])
				if ecdsa.Verify(k, digest, r, s) {
					return nil
				}
			}
		}
	}
	return errors.New("ID token signature invalid")
}
