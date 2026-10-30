package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"sync"
	"time"
)

// publicGoodRoot is targets/trusted_root.json of the Sigstore public-good TUF repository (see README.md).
//
//go:embed trusted_root.json
var publicGoodRoot []byte

var parsedPublicGoodRoot = sync.OnceValues(func() (*TrustedRoot, error) { return ParseTrustedRoot(publicGoodRoot) })

// PublicGoodTrustedRoot returns the embedded Sigstore public-good trusted root (Fulcio, Rekor, CT log). It is
// static: updates ship with AegisProxy releases, the TUF update protocol is not implemented. The root is shared
// and must not be modified.
func PublicGoodTrustedRoot() (*TrustedRoot, error) { return parsedPublicGoodRoot() }

// TimeRange is a validity window; a zero End is open-ended.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end,omitzero"`
}

// Contains reports whether t lies in the window (both ends inclusive).
func (r TimeRange) Contains(t time.Time) bool {
	return !t.Before(r.Start) && (r.End.IsZero() || !t.After(r.End))
}

// CertificateAuthority is a Fulcio CA: the trust anchor, its intermediates and the window in which it issued
// certificates.
type CertificateAuthority struct {
	URI           string
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
	ValidFor      TimeRange
}

// TransparencyLog is the key of a Rekor or certificate transparency log.
type TransparencyLog struct {
	BaseURL string
	// LogID is the log ID the trusted root assigns; for Rekor v1 and CT logs it is the SHA-256 of DER.
	LogID     []byte
	PublicKey crypto.PublicKey
	DER       []byte // SubjectPublicKeyInfo
	ValidFor  TimeRange
}

// TrustedRoot is parsed Sigstore trust material.
type TrustedRoot struct {
	MediaType              string
	CertificateAuthorities []CertificateAuthority
	TransparencyLogs       map[string]*TransparencyLog // Rekor, keyed by hex log ID
	CTLogs                 map[string]*TransparencyLog // certificate transparency, keyed by hex log ID
}

type validForJSON struct {
	Start *time.Time `json:"start"`
	End   *time.Time `json:"end"`
}

func (v validForJSON) timeRange() TimeRange {
	var r TimeRange
	if v.Start != nil {
		r.Start = v.Start.UTC()
	}
	if v.End != nil {
		r.End = v.End.UTC()
	}
	return r
}

type logJSON struct {
	BaseURL       string `json:"baseUrl"`
	HashAlgorithm string `json:"hashAlgorithm"`
	PublicKey     struct {
		RawBytes   b64          `json:"rawBytes"`
		KeyDetails string       `json:"keyDetails"`
		ValidFor   validForJSON `json:"validFor"`
	} `json:"publicKey"`
	LogID struct {
		KeyID b64 `json:"keyId"`
	} `json:"logId"`
}

type trustedRootJSON struct {
	MediaType              string    `json:"mediaType"`
	Tlogs                  []logJSON `json:"tlogs"`
	CTLogs                 []logJSON `json:"ctlogs"`
	CertificateAuthorities []struct {
		URI       string `json:"uri"`
		CertChain struct {
			Certificates []struct {
				RawBytes b64 `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor validForJSON `json:"validFor"`
	} `json:"certificateAuthorities"`
}

// ParseTrustedRoot parses a Sigstore trusted root (application/vnd.dev.sigstore.trustedroot+json). Logs with a
// key type this package cannot verify are skipped; timestamp authorities are ignored (RFC 3161 timestamps are
// not verified).
func ParseTrustedRoot(data []byte) (*TrustedRoot, error) {
	var j trustedRootJSON
	if err := decodeJSON(data, &j, "trusted root"); err != nil {
		return nil, err
	}
	switch j.MediaType {
	case "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "application/vnd.dev.sigstore.trustedroot.v0.2+json":
	default:
		return nil, failf(ErrUnsupported, "trusted root media type %q", j.MediaType)
	}
	r := &TrustedRoot{MediaType: j.MediaType, TransparencyLogs: map[string]*TransparencyLog{}, CTLogs: map[string]*TransparencyLog{}}
	for i, ca := range j.CertificateAuthorities {
		certs := ca.CertChain.Certificates
		if len(certs) == 0 || len(certs) > MaxCertificates {
			return nil, failf(ErrMalformed, "certificate authority %d has %d certificates", i, len(certs))
		}
		parsed := make([]*x509.Certificate, 0, len(certs))
		for _, c := range certs {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return nil, failf(ErrMalformed, "certificate authority %d: %v", i, err)
			}
			if !cert.IsCA {
				return nil, failf(ErrMalformed, "certificate authority %d: %q is not a CA certificate", i, cert.Subject)
			}
			parsed = append(parsed, cert)
		}
		// The chain is ordered from the issuing intermediate to the self-signed root.
		r.CertificateAuthorities = append(r.CertificateAuthorities, CertificateAuthority{
			URI: ca.URI, Root: parsed[len(parsed)-1], Intermediates: parsed[:len(parsed)-1], ValidFor: ca.ValidFor.timeRange(),
		})
	}
	for _, set := range []struct {
		in  []logJSON
		out map[string]*TransparencyLog
	}{{j.Tlogs, r.TransparencyLogs}, {j.CTLogs, r.CTLogs}} {
		for _, l := range set.in {
			if l.HashAlgorithm != "SHA2_256" {
				continue
			}
			pub, err := x509.ParsePKIXPublicKey(l.PublicKey.RawBytes)
			if err != nil || !keyMatchesDetails(pub, l.PublicKey.KeyDetails) {
				continue // a key type this package cannot verify never verifies anything
			}
			id := []byte(l.LogID.KeyID)
			if len(id) == 0 {
				sum := sha256.Sum256(l.PublicKey.RawBytes)
				id = sum[:]
			}
			set.out[hex.EncodeToString(id)] = &TransparencyLog{
				BaseURL: l.BaseURL, LogID: id, PublicKey: pub, DER: l.PublicKey.RawBytes, ValidFor: l.PublicKey.ValidFor.timeRange(),
			}
		}
	}
	if len(r.CertificateAuthorities) == 0 || len(r.TransparencyLogs) == 0 {
		return nil, failf(ErrMalformed, "trusted root has no certificate authority or no usable transparency log")
	}
	return r, nil
}

func keyMatchesDetails(pub crypto.PublicKey, details string) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return (details == "PKIX_ECDSA_P256_SHA_256" && k.Curve == elliptic.P256()) ||
			(details == "PKIX_ECDSA_P384_SHA_384" && k.Curve == elliptic.P384()) ||
			(details == "PKIX_ECDSA_P521_SHA_512" && k.Curve == elliptic.P521())
	case ed25519.PublicKey:
		return details == "PKIX_ED25519"
	}
	return false
}
