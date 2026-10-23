package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestECJWK(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := priv.PublicKey.Bytes() // 0x04 || X || Y
	enc := base64.RawURLEncoding.EncodeToString
	k := jwk{Kty: "EC", Crv: "P-256", X: enc(raw[1:33]), Y: enc(raw[33:])}
	pub, err := parseJWK(k)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if err := verifySignature("ES256", pub, []byte("header.payload"), sig); err != nil {
		t.Fatalf("valid ES256 signature rejected: %v", err)
	}
	if verifySignature("ES384", pub, []byte("header.payload"), sig) == nil {
		t.Fatal("P-256 key accepted for ES384")
	}
	// Padded coordinates (some IdPs) are accepted.
	padded := k
	padded.X += "="
	if _, err := parseJWK(padded); err != nil {
		t.Fatalf("padded coordinate: %v", err)
	}
	// A point that is not on the curve, short coordinates and unknown curves are rejected.
	bad := k
	y := append([]byte(nil), raw[33:]...)
	y[31] ^= 1
	bad.Y = enc(y)
	if _, err := parseJWK(bad); err == nil {
		t.Fatal("off-curve point accepted")
	}
	short := k
	short.X = enc(raw[2:33])
	if _, err := parseJWK(short); err == nil {
		t.Fatal("short coordinate accepted")
	}
	if _, err := parseJWK(jwk{Kty: "EC", Crv: "P-521", X: k.X, Y: k.Y}); err == nil {
		t.Fatal("unsupported curve accepted")
	}
	var _ crypto.PublicKey = pub
}
