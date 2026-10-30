// Package provenance verifies the signatures and the build provenance that package registries publish, using
// only the standard library:
//
//   - npm registry signatures (what `npm audit signatures` checks),
//   - npm attestations: the publish attestation signed with an npm registry key and the SLSA provenance signed
//     with a Sigstore (Fulcio) certificate,
//   - PyPI PEP 740 attestations (Integrity API provenance) including the Trusted Publisher identity.
//
// Sigstore bundles are verified offline against the embedded public-good trusted root: the Fulcio certificate
// chain at the transparency log's signed integrated time, the certificate's embedded SCTs, the Rekor signed entry
// timestamp and inclusion proof with its signed checkpoint, the correspondence of the log entry with the
// envelope and the certificate, the DSSE signature and the in-toto statement subject. README.md lists what is
// deliberately not verified.
//
// Every input is a registry response and therefore attacker-controlled: sizes are bounded, nothing panics and
// every failure is returned as an error that wraps one of the Err* sentinels.
package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Limits on attacker-controlled input.
const (
	MaxDocumentSize = 4 << 20 // bytes of a keys, attestations or provenance document or a bundle
	MaxAttestations = 10      // attestations per document
	MaxCertificates = 10      // certificates in a bundle's chain
	maxSignatures   = 10      // registry signatures of a version, DSSE / checkpoint signatures
	maxTlogEntries  = 10      // transparency log entries per bundle
	maxProofHashes  = 64      // a Merkle audit path is at most as long as the tree is high
	maxSubjects     = 1024    // in-toto statement subjects
	maxKeys         = 64      // npm registry keys
	maxFutureSkew   = 5 * time.Minute
)

// Error classes. Every error returned by this package wraps exactly one of them (errors.Is).
var (
	ErrMalformed        = errors.New("malformed input")
	ErrLimit            = errors.New("input exceeds limits")
	ErrUnsupported      = errors.New("unsupported format")
	ErrNoSignature      = errors.New("no signature")
	ErrUnknownKey       = errors.New("unknown signing key")
	ErrKeyExpired       = errors.New("signing key expired")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrUntrustedCert    = errors.New("untrusted certificate")
	ErrTransparencyLog  = errors.New("transparency log verification failed")
	ErrNoAttestations   = errors.New("no attestations")
	ErrSubjectMismatch  = errors.New("attestation subject does not match the artifact")
	ErrIdentityMismatch = errors.New("signing identity does not match the publisher")
)

func failf(class error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", class, fmt.Sprintf(format, args...))
}

// Options adjusts verification; the zero value is the default. The package-level functions use Options{}.
type Options struct {
	// Now returns the current time (default time.Now). It only bounds the transparency log's integrated time:
	// entries more than five minutes in the future are rejected. Certificates and keys are checked at the
	// integrated time, so stored registry responses keep verifying after their certificates expired.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Digest is an artifact digest as in-toto statements carry it.
type Digest struct {
	Algorithm string `json:"algorithm"` // sha256, sha384, sha512
	Value     string `json:"value"`     // lowercase hex
}

var digestSizes = map[string]int{"sha256": sha256.Size, "sha384": sha512.Size384, "sha512": sha512.Size}

func (d Digest) normalized() (Digest, error) {
	n, ok := digestSizes[d.Algorithm]
	if !ok {
		return Digest{}, failf(ErrUnsupported, "digest algorithm %q", d.Algorithm)
	}
	v := strings.ToLower(d.Value)
	if b, err := hex.DecodeString(v); err != nil || len(b) != n {
		return Digest{}, failf(ErrMalformed, "%s digest is not %d hex-encoded bytes", d.Algorithm, n)
	}
	return Digest{Algorithm: d.Algorithm, Value: v}, nil
}

// DigestFromSRI converts a Subresource Integrity string (npm `dist.integrity`, "sha512-<base64>") into the hex
// digest that npm attestations carry. Of several hashes the strongest supported one is used; sha1 alone is
// rejected.
func DigestFromSRI(integrity string) (Digest, error) {
	best, rank := Digest{}, 0
	for _, tok := range strings.Fields(integrity) {
		alg, val, ok := strings.Cut(tok, "-")
		if !ok {
			continue
		}
		val, _, _ = strings.Cut(val, "?") // SRI options
		r := map[string]int{"sha256": 1, "sha384": 2, "sha512": 3}[alg]
		if r == 0 || r <= rank {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil || len(raw) != digestSizes[alg] {
			return Digest{}, failf(ErrMalformed, "integrity %s value is not a base64 %s digest", alg, alg)
		}
		best, rank = Digest{Algorithm: alg, Value: hex.EncodeToString(raw)}, r
	}
	if rank == 0 {
		return Digest{}, failf(ErrUnsupported, "integrity %q has no sha256/sha384/sha512 hash", integrity)
	}
	return best, nil
}

// b64 is a protobuf-JSON bytes field (standard or URL-safe base64, padding optional).
type b64 []byte

func (b *b64) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	raw, err := decodeB64(s)
	if err != nil {
		return err
	}
	*b = raw
	return nil
}

func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// int64s is a protobuf-JSON int64 (a decimal string or a number); negative values are rejected.
type int64s int64

func (n *int64s) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		*n = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return fmt.Errorf("invalid non-negative integer %.40q", s)
	}
	*n = int64s(v)
	return nil
}

func decodeJSON(data []byte, v any, what string) error {
	if len(data) > MaxDocumentSize {
		return failf(ErrLimit, "%s is larger than %d bytes", what, MaxDocumentSize)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return failf(ErrMalformed, "%s: %v", what, err)
	}
	return nil
}

// verifySignature checks sig over msg: ECDSA (ASN.1) with the hash that matches the curve (P-256/SHA-256,
// P-384/SHA-384, P-521/SHA-512) or Ed25519. Other key types never verify.
func verifySignature(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var digest []byte
		switch k.Curve {
		case elliptic.P256():
			h := sha256.Sum256(msg)
			digest = h[:]
		case elliptic.P384():
			h := sha512.Sum384(msg)
			digest = h[:]
		case elliptic.P521():
			h := sha512.Sum512(msg)
			digest = h[:]
		default:
			return false
		}
		return ecdsa.VerifyASN1(k, digest, sig)
	case ed25519.PublicKey:
		// ed25519.Verify panics on a key of the wrong length.
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	}
	return false
}

func supportedKey(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	}
	return false
}
