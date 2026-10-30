package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const npmKeyType = "ecdsa-sha2-nistp256"

// NPMKey is a registry signing key from GET /-/npm/v1/keys.
type NPMKey struct {
	KeyID     string
	Expires   *time.Time // nil: does not expire
	PublicKey *ecdsa.PublicKey
	DER       []byte // SubjectPublicKeyInfo
}

// validAt mirrors npm (pacote): a key signs only what was published (or logged) before it expired.
func (k *NPMKey) validAt(t time.Time) bool {
	return k.Expires == nil || (!t.IsZero() && t.Before(*k.Expires))
}

// ParseNPMKeys parses the npm registry keys document. Keys of a type other than ecdsa-sha2-nistp256 are skipped
// (they cannot verify anything); a malformed key of that type is an error.
func ParseNPMKeys(data []byte) ([]NPMKey, error) {
	var doc struct {
		Keys []struct {
			Expires *string `json:"expires"`
			KeyID   string  `json:"keyid"`
			KeyType string  `json:"keytype"`
			Scheme  string  `json:"scheme"`
			Key     string  `json:"key"`
		} `json:"keys"`
	}
	if err := decodeJSON(data, &doc, "npm keys"); err != nil {
		return nil, err
	}
	if len(doc.Keys) > maxKeys {
		return nil, failf(ErrLimit, "%d npm keys", len(doc.Keys))
	}
	var keys []NPMKey
	seen := map[string]bool{}
	for _, k := range doc.Keys {
		if k.KeyType != npmKeyType || k.Scheme != npmKeyType {
			continue
		}
		if k.KeyID == "" || seen[k.KeyID] {
			return nil, failf(ErrMalformed, "npm key without or with a duplicate keyid %.100q", k.KeyID)
		}
		seen[k.KeyID] = true
		der, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, failf(ErrMalformed, "npm key %s: %v", k.KeyID, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		ec, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok || ec.Curve != elliptic.P256() {
			return nil, failf(ErrMalformed, "npm key %s is not an ECDSA P-256 key", k.KeyID)
		}
		key := NPMKey{KeyID: k.KeyID, PublicKey: ec, DER: der}
		if k.Expires != nil {
			t, err := time.Parse(time.RFC3339, *k.Expires)
			if err != nil {
				return nil, failf(ErrMalformed, "npm key %s expiry: %v", k.KeyID, err)
			}
			key.Expires = &t
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func findNPMKey(keys []NPMKey, id string) *NPMKey {
	for i := range keys {
		if keys[i].KeyID == id {
			return &keys[i]
		}
	}
	return nil
}

// NPMSignature is an entry of a version's dist.signatures.
type NPMSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// VerifyNPMRegistrySignature verifies the registry signatures of a version: ECDSA P-256 / SHA-256 over
// "<name>@<version>:<integrity>" with a key that had not expired when the version was published. Like npm, every
// signature must verify and at least one is required. Errors wrap ErrNoSignature, ErrUnknownKey, ErrKeyExpired or
// ErrInvalidSignature.
func VerifyNPMRegistrySignature(keys []NPMKey, name, version, integrity string, sigs []NPMSignature, publishedAt time.Time) (keyID string, err error) {
	if len(sigs) == 0 {
		return "", failf(ErrNoSignature, "%s@%s has no registry signature", name, version)
	}
	if len(sigs) > maxSignatures {
		return "", failf(ErrLimit, "%d registry signatures", len(sigs))
	}
	if name == "" || version == "" || integrity == "" {
		return "", failf(ErrMalformed, "name, version and integrity are required")
	}
	digest := sha256.Sum256([]byte(name + "@" + version + ":" + integrity))
	for _, s := range sigs {
		k := findNPMKey(keys, s.KeyID)
		if k == nil {
			return "", failf(ErrUnknownKey, "%s@%s is signed with keyid %.100q", name, version, s.KeyID)
		}
		if !k.validAt(publishedAt) {
			return "", failf(ErrKeyExpired, "key %s expired %s, before %s@%s was published (%s)", k.KeyID,
				k.Expires.Format(time.RFC3339), name, version, publishedAt.Format(time.RFC3339))
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || !ecdsa.VerifyASN1(k.PublicKey, digest[:], sig) {
			return "", failf(ErrInvalidSignature, "registry signature of %s@%s with key %s does not verify", name, version, k.KeyID)
		}
	}
	return sigs[0].KeyID, nil
}

// NPMAttestations are the verified attestations of an npm version; either may be absent.
type NPMAttestations struct {
	// Publish is the registry's publish attestation, signed with an npm registry key (Result.KeyID).
	Publish *Result `json:"publish,omitempty"`
	// Provenance is the SLSA provenance signed with a Fulcio certificate of the build (Result.Identity).
	Provenance *Result `json:"provenance,omitempty"`
	// Source is the build origin the provenance certificate states (zero without provenance).
	Source Source `json:"source,omitzero"`
}

// VerifyNPMAttestations verifies GET /-/npm/v1/attestations/<name>@<version>: the publish attestation with the
// npm registry key its bundle names, the SLSA provenance with the Fulcio CA, both against the Rekor log, and
// requires the subject pkg:npm/<name>@<version> with the tarball's sha512 (from integrity). Every present
// attestation of a known predicate type must verify; others are ignored.
func VerifyNPMAttestations(doc []byte, keys []NPMKey, root *TrustedRoot, name, version, integrity string) (*NPMAttestations, error) {
	return Options{}.VerifyNPMAttestations(doc, keys, root, name, version, integrity)
}

// VerifyNPMAttestations is VerifyNPMAttestations with options.
func (o Options) VerifyNPMAttestations(doc []byte, keys []NPMKey, root *TrustedRoot, name, version, integrity string) (*NPMAttestations, error) {
	var d struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := decodeJSON(doc, &d, "npm attestations"); err != nil {
		return nil, err
	}
	if len(d.Attestations) == 0 {
		return nil, failf(ErrNoAttestations, "%s@%s", name, version)
	}
	if len(d.Attestations) > MaxAttestations {
		return nil, failf(ErrLimit, "%d attestations", len(d.Attestations))
	}
	digest, err := DigestFromSRI(integrity)
	if err != nil {
		return nil, err
	}
	if digest.Algorithm != "sha512" {
		return nil, failf(ErrUnsupported, "npm attestations name the sha512 digest, integrity has %s", digest.Algorithm)
	}
	x := expectation{subjectName: npmPURL(name, version), digest: digest}
	keyFor := func(hint string, at time.Time) (crypto.PublicKey, []byte, error) {
		k := findNPMKey(keys, hint)
		if k == nil {
			return nil, nil, failf(ErrUnknownKey, "publish attestation is signed with keyid %.100q", hint)
		}
		if !k.validAt(at) {
			return nil, nil, failf(ErrKeyExpired, "key %s expired %s, before the publish attestation was logged (%s)",
				k.KeyID, k.Expires.Format(time.RFC3339), at.Format(time.RFC3339))
		}
		return k.PublicKey, k.DER, nil
	}
	out := &NPMAttestations{}
	for _, a := range d.Attestations {
		var slot **Result
		xa := x
		switch a.PredicateType {
		case PredicateNPMPublish:
			slot, xa.key = &out.Publish, keyFor
		case PredicateSLSAv02, PredicateSLSAv1:
			slot = &out.Provenance
		default:
			continue
		}
		if *slot != nil {
			return nil, failf(ErrMalformed, "more than one %s attestation", a.PredicateType)
		}
		m, err := parseBundle(a.Bundle)
		if err != nil {
			return nil, err
		}
		r, err := o.verify(m, root, xa)
		if err != nil {
			return nil, err
		}
		// The listed predicate type is unauthenticated; the signed statement must agree.
		if r.PredicateType != a.PredicateType {
			return nil, failf(ErrSubjectMismatch, "attestation listed as %s carries a %.100s statement", a.PredicateType, r.PredicateType)
		}
		if a.PredicateType == PredicateNPMPublish {
			var p struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(r.Predicate, &p) != nil || p.Name != name || p.Version != version {
				return nil, failf(ErrSubjectMismatch, "publish attestation is for %.100s@%.100s", p.Name, p.Version)
			}
		}
		*slot = r
	}
	if out.Publish == nil && out.Provenance == nil {
		return nil, failf(ErrNoAttestations, "%s@%s has no publish or provenance attestation", name, version)
	}
	if out.Provenance != nil {
		out.Source = out.Provenance.Identity.Source()
	}
	return out, nil
}

// npmPURL is the package URL npm puts into statement subjects (npm-package-arg toPurl): the leading "@" of a
// scope is percent-encoded.
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		name = "%40" + name[1:]
	}
	return "pkg:npm/" + name + "@" + version
}
