package oidc

// Client authentication with a private key (OpenID Connect Core 1.0 section 9 "private_key_jwt",
// RFC 7523 section 2.2): the client proves its identity at the token endpoint with a short-lived
// JWT signed by a key whose public half the IdP knows from a JWKS URL (Keycloak, Okta, Ping) or an
// uploaded certificate (Microsoft Entra ID). No shared secret leaves the control-plane.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // x5t is defined as the SHA-1 certificate thumbprint (RFC 7515 section 4.1.7)
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Client assertion algorithms: RS256 with an RSA-3072 key or ES256 with a P-256 key.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"

	// ClientAssertionType is the client_assertion_type of RFC 7523 section 2.2.
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// AssertionLifetime bounds the validity of a client assertion (IdPs reject long-lived ones).
	AssertionLifetime = 5 * time.Minute

	rsaClientKeyBits = 3072
)

// ClientKey signs client assertions.
type ClientKey struct {
	KID    string
	Alg    string
	Signer crypto.Signer
	// CertDER is the self-signed certificate of the key; when present the assertion header carries
	// x5t and x5t#S256 (Entra ID identifies the uploaded certificate by its SHA-1 thumbprint).
	CertDER []byte
}

// GeneratedClientKey is a new key pair with its self-signed certificate.
type GeneratedClientKey struct {
	KID            string
	Alg            string
	PrivateKeyPEM  string // PKCS#8
	CertificatePEM string
	X5t            string // base64url SHA-1 of the DER certificate
	X5tS256        string // base64url SHA-256 of the DER certificate
	NotBefore      time.Time
	NotAfter       time.Time
}

// GenerateClientKey creates an RS256 (RSA-3072) or ES256 (P-256) key pair and a self-signed
// certificate valid for validity (IdPs that require a certificate upload only use its public key
// and thumbprint; the certificate is never used for TLS).
func GenerateClientKey(alg, commonName string, now time.Time, validity time.Duration) (*GeneratedClientKey, error) {
	var signer crypto.Signer
	var err error
	switch alg {
	case AlgRS256:
		signer, err = rsa.GenerateKey(rand.Reader, rsaClientKeyBits)
	case AlgES256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported client key algorithm %q (RS256 or ES256)", alg)
	}
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-5 * time.Minute).UTC().Truncate(time.Second)
	notAfter := now.Add(validity).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"AegisProxy"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("self-signed certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	kid, err := JWKThumbprint(signer.Public())
	if err != nil {
		return nil, err
	}
	x5t, x5tS256 := CertThumbprints(der)
	return &GeneratedClientKey{
		KID: kid, Alg: alg,
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		X5t:            x5t, X5tS256: x5tS256, NotBefore: notBefore, NotAfter: notAfter,
	}, nil
}

// CertThumbprints returns the base64url SHA-1 (x5t) and SHA-256 (x5t#S256) thumbprints.
func CertThumbprints(der []byte) (x5t, x5tS256 string) {
	s1 := sha1.Sum(der)
	s256 := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(s1[:]), base64.RawURLEncoding.EncodeToString(s256[:])
}

// ParseClientKey loads a key stored as PKCS#8 PEM with its PEM certificate (optional).
func ParseClientKey(kid, alg, privateKeyPEM, certificatePEM string) (*ClientKey, error) {
	blk, _ := pem.Decode([]byte(privateKeyPEM))
	if blk == nil {
		return nil, errors.New("client key: no PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("client key: unsupported key type")
	}
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if alg != AlgRS256 || key.N.BitLen() < 2048 {
			return nil, errors.New("client key: RSA keys need RS256 and at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if alg != AlgES256 || key.Curve != elliptic.P256() {
			return nil, errors.New("client key: EC keys need ES256 and the P-256 curve")
		}
	default:
		return nil, errors.New("client key: unsupported key type")
	}
	ck := &ClientKey{KID: kid, Alg: alg, Signer: signer}
	if certificatePEM != "" {
		cb, _ := pem.Decode([]byte(certificatePEM))
		if cb == nil || cb.Type != "CERTIFICATE" {
			return nil, errors.New("client key: invalid certificate")
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("client key certificate: %w", err)
		}
		if !publicKeysEqual(cert.PublicKey, signer.Public()) {
			return nil, errors.New("client key: certificate does not match the private key")
		}
		ck.CertDER = cb.Bytes
	}
	return ck, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

// PublicJWK returns the JWK (RFC 7517) of a public key, with x5c/x5t/x5t#S256 when a certificate
// is given.
func PublicJWK(kid, alg string, pub crypto.PublicKey, certDER []byte) (map[string]any, error) {
	j, err := jwkMembers(pub)
	if err != nil {
		return nil, err
	}
	j["kid"], j["alg"], j["use"] = kid, alg, "sig"
	if len(certDER) > 0 {
		x5t, x5tS256 := CertThumbprints(certDER)
		j["x5c"] = []string{base64.StdEncoding.EncodeToString(certDER)}
		j["x5t"], j["x5t#S256"] = x5t, x5tS256
	}
	return j, nil
}

// jwkMembers returns the required members of a public JWK (the input of the RFC 7638 thumbprint).
func jwkMembers(pub crypto.PublicKey) (map[string]any, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("only P-256 EC keys are supported")
		}
		raw, err := k.Bytes() // 0x04 || X || Y, fixed length
		if err != nil {
			return nil, err
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:])}, nil
	}
	return nil, errors.New("unsupported public key type")
}

// JWKThumbprint is the RFC 7638 SHA-256 thumbprint of a public key, used as key ID.
func JWKThumbprint(pub crypto.PublicKey) (string, error) {
	m, err := jwkMembers(pub)
	if err != nil {
		return "", err
	}
	// encoding/json sorts map keys lexicographically and emits no whitespace: exactly the
	// canonical form RFC 7638 section 3 requires.
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// SignClientAssertion creates the client_assertion for the token endpoint: iss = sub = client ID,
// aud = the token endpoint (OIDC Core section 9; accepted by Entra ID, Okta and Keycloak), a random
// jti, iat/nbf = now and exp = now + 5 minutes.
func SignClientAssertion(key *ClientKey, clientID, audience string, now time.Time) (string, error) {
	if key == nil || key.Signer == nil {
		return "", errors.New("private_key_jwt: no client key configured")
	}
	if clientID == "" || audience == "" {
		return "", errors.New("private_key_jwt: client ID and audience are required")
	}
	hdr := map[string]string{"alg": key.Alg, "typ": "JWT", "kid": key.KID}
	if len(key.CertDER) > 0 {
		hdr["x5t"], hdr["x5t#S256"] = CertThumbprints(key.CertDER)
	}
	iat := now.Unix()
	claims := map[string]any{"iss": clientID, "sub": clientID, "aud": audience, "jti": RandomString(24),
		"iat": iat, "nbf": iat, "exp": now.Add(AssertionLifetime).Unix()}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signing))
	var sig []byte
	switch k := key.Signer.(type) {
	case *rsa.PrivateKey:
		if key.Alg != AlgRS256 {
			return "", errors.New("private_key_jwt: RSA keys sign with RS256")
		}
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		if key.Alg != AlgES256 || k.Curve != elliptic.P256() {
			return "", errors.New("private_key_jwt: EC keys sign with ES256 on P-256")
		}
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, digest[:])
		if err == nil { // JWS uses the fixed-length R || S encoding, not ASN.1 (RFC 7518 section 3.4)
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	default:
		return "", errors.New("private_key_jwt: unsupported key type")
	}
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyClientAssertionSignature checks the signature of a compact JWS against a public key (the
// authorization server's view; used by tests).
func VerifyClientAssertionSignature(token string, pub crypto.PublicKey) (header, claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("malformed assertion")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, nil, errors.New("malformed assertion")
	}
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil {
		return nil, nil, errors.New("malformed assertion")
	}
	alg, _ := header["alg"].(string)
	if err := verifySignature(alg, pub, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

// ParseCertificateKey parses a PEM certificate (the public half of a client key).
func ParseCertificateKey(certificatePEM string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(certificatePEM))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}
