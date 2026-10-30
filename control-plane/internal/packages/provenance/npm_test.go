package provenance_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/packages/provenance"
)

func TestParseNPMKeys(t *testing.T) {
	keys := npmKeys(t)
	if len(keys) != 2 {
		t.Fatalf("%d keys", len(keys))
	}
	if keys[0].KeyID != "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA" || keys[0].Expires == nil ||
		!keys[0].Expires.Equal(time.Date(2025, 1, 29, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first key: %+v", keys[0])
	}
	if keys[1].KeyID != "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U" || keys[1].Expires != nil {
		t.Errorf("second key: %+v", keys[1])
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	valid := `"keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"` + base64.StdEncoding.EncodeToString(keys[1].DER) + `"`
	cases := map[string]struct {
		doc  string
		err  error
		keys int
	}{
		"unsupported key type skipped": {doc: `{"keys":[{"keyid":"a","keytype":"ed25519","scheme":"ed25519","key":"AAAA"},{"keyid":"b",` + valid + `}]}`, keys: 1},
		"empty":                        {doc: `{"keys":[]}`},
		"not JSON":                     {doc: `<html>`, err: provenance.ErrMalformed},
		"bad base64":                   {doc: `{"keys":[{"keyid":"a","keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"%%%"}]}`, err: provenance.ErrMalformed},
		"P-384 key":                    {doc: `{"keys":[{"keyid":"a","keytype":"ecdsa-sha2-nistp256","scheme":"ecdsa-sha2-nistp256","key":"` + base64.StdEncoding.EncodeToString(p384DER) + `"}]}`, err: provenance.ErrMalformed},
		"duplicate keyid":              {doc: `{"keys":[{"keyid":"a",` + valid + `},{"keyid":"a",` + valid + `}]}`, err: provenance.ErrMalformed},
		"missing keyid":                {doc: `{"keys":[{` + valid + `}]}`, err: provenance.ErrMalformed},
		"bad expiry":                   {doc: `{"keys":[{"keyid":"a","expires":"tomorrow",` + valid + `}]}`, err: provenance.ErrMalformed},
		"too many keys":                {doc: `{"keys":[` + strings.Repeat(`{},`, 64) + `{}]}`, err: provenance.ErrLimit},
		"too large":                    {doc: `{"keys":[],"x":"` + strings.Repeat("a", provenance.MaxDocumentSize) + `"}`, err: provenance.ErrLimit},
	}
	for name, c := range cases {
		keys, err := provenance.ParseNPMKeys([]byte(c.doc))
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: got %v, want %v", name, err, c.err)
			}
			continue
		}
		if err != nil || len(keys) != c.keys {
			t.Errorf("%s: %d keys, %v", name, len(keys), err)
		}
	}
}

func TestVerifyNPMRegistrySignature(t *testing.T) {
	keys := npmKeys(t)
	for _, c := range []struct{ file, key string }{
		{"left-pad-1.3.0", "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"}, // no provenance
		{"semver-7.6.3", "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"},
		{"sigstore-1.5.0", "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"},
		{"sigstore-core-4.0.1", "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"}, // scoped
	} {
		v, published := npmPackage(t, c.file)
		kid, err := provenance.VerifyNPMRegistrySignature(keys, v.Name, v.Version, v.Dist.Integrity, v.Dist.Signatures, published)
		if err != nil || kid != c.key {
			t.Errorf("%s: %s, %v", c.file, kid, err)
		}
	}

	v, published := npmPackage(t, "semver-7.6.3")
	sig := v.Dist.Signatures[0]
	flipped := func() string {
		raw, _ := base64.StdEncoding.DecodeString(sig.Sig)
		raw[len(raw)-1] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}()
	other, _ := npmPackage(t, "left-pad-1.3.0")
	type input struct {
		pkg, version, integrity string
		sigs                    []provenance.NPMSignature
		publishedAt             time.Time
		keys                    []provenance.NPMKey
	}
	cases := []struct {
		name string
		mod  func(in *input)
		err  error
	}{
		{"no signature", func(in *input) { in.sigs = nil }, provenance.ErrNoSignature},
		{"unknown keyid", func(in *input) { in.sigs = []provenance.NPMSignature{{KeyID: "SHA256:unknown", Sig: sig.Sig}} }, provenance.ErrUnknownKey},
		{"no keys", func(in *input) { in.keys = nil }, provenance.ErrUnknownKey},
		{"key expired before publication", func(in *input) { in.publishedAt = time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC) }, provenance.ErrKeyExpired},
		{"published exactly at expiry", func(in *input) { in.publishedAt = time.Date(2025, 1, 29, 0, 0, 0, 0, time.UTC) }, provenance.ErrKeyExpired},
		{"unknown publish time, expiring key", func(in *input) { in.publishedAt = time.Time{} }, provenance.ErrKeyExpired},
		{"tampered integrity", func(in *input) { in.integrity = other.Dist.Integrity }, provenance.ErrInvalidSignature},
		{"other version", func(in *input) { in.version = "7.6.2" }, provenance.ErrInvalidSignature},
		{"other package", func(in *input) { in.pkg = "semver2" }, provenance.ErrInvalidSignature},
		{"signature bit flip", func(in *input) { in.sigs = []provenance.NPMSignature{{KeyID: sig.KeyID, Sig: flipped}} }, provenance.ErrInvalidSignature},
		{"signature not base64", func(in *input) { in.sigs = []provenance.NPMSignature{{KeyID: sig.KeyID, Sig: "%%%"}} }, provenance.ErrInvalidSignature},
		{"valid and unknown signature", func(in *input) {
			in.sigs = append(in.sigs, provenance.NPMSignature{KeyID: "SHA256:unknown", Sig: sig.Sig})
		}, provenance.ErrUnknownKey},
		{"valid and invalid signature", func(in *input) { in.sigs = append(in.sigs, provenance.NPMSignature{KeyID: sig.KeyID, Sig: flipped}) }, provenance.ErrInvalidSignature},
		{"too many signatures", func(in *input) { in.sigs = make([]provenance.NPMSignature, 11) }, provenance.ErrLimit},
		{"empty integrity", func(in *input) { in.integrity = "" }, provenance.ErrMalformed},
	}
	for _, c := range cases {
		in := input{v.Name, v.Version, v.Dist.Integrity, v.Dist.Signatures, published, keys}
		c.mod(&in)
		if _, err := provenance.VerifyNPMRegistrySignature(in.keys, in.pkg, in.version, in.integrity, in.sigs, in.publishedAt); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}
}

func TestVerifyNPMAttestations(t *testing.T) {
	root, keys := trustedRoot(t), npmKeys(t)
	cases := []struct {
		file, mediaType, slsa, repo, commit, workflow, key string
	}{
		{"semver-7.6.3", "application/vnd.dev.sigstore.bundle+json;version=0.2", "v1", "https://github.com/npm/node-semver",
			"0a12d6c7debb1dc82d8645c770e77c47bac5e1ea", "https://github.com/npm/node-semver/.github/workflows/release.yml@refs/heads/main",
			"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"},
		{"sigstore-core-4.0.1", "application/vnd.dev.sigstore.bundle.v0.3+json", "v1", "https://github.com/sigstore/sigstore-js",
			"d406ea60b342ca37cdeecd7afedb992cd189db92", "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
			"SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"},
		{"sigstore-1.5.0", "application/vnd.dev.sigstore.bundle+json;version=0.1", "v0.2", "https://github.com/sigstore/sigstore-js",
			"b83096d2e93b10ff41b62133831c6e345877560b", "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
			"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"},
	}
	for _, c := range cases {
		v, _ := npmPackage(t, c.file)
		a, err := provenance.VerifyNPMAttestations(fixture(t, "npm/"+c.file+".attestations.json"), keys, root, v.Name, v.Version, v.Dist.Integrity)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if a.Publish == nil || a.Publish.KeyID != c.key || a.Publish.Identity != nil || a.Publish.PredicateType != provenance.PredicateNPMPublish {
			t.Errorf("%s publish: %+v", c.file, a.Publish)
		}
		p := a.Provenance
		if p == nil || p.MediaType != c.mediaType || p.Identity == nil || p.SLSA == nil || p.SLSA.Version != c.slsa || p.SLSA.Commit != c.commit ||
			p.SLSA.Repository != c.repo || p.Identity.Issuer != "https://token.actions.githubusercontent.com" {
			t.Errorf("%s provenance: %+v", c.file, p)
		}
		if a.Source != (provenance.Source{Repository: c.repo, Commit: c.commit, Ref: "refs/heads/main", Workflow: c.workflow}) {
			t.Errorf("%s source: %+v", c.file, a.Source)
		}
		if p.IntegratedTime.IsZero() || p.LogIndex == 0 || p.LogID != "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d" {
			t.Errorf("%s log: %v %d %s", c.file, p.IntegratedTime, p.LogIndex, p.LogID)
		}
	}

	v, _ := npmPackage(t, "semver-7.6.3")
	doc := fixture(t, "npm/semver-7.6.3.attestations.json")
	other, _ := npmPackage(t, "left-pad-1.3.0")
	expired := append([]provenance.NPMKey{}, keys...)
	early := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	expired[0].Expires = &early
	reorder := func(f func(atts []any) []any) []byte {
		return mutate(t, doc, func(d map[string]any) { d["attestations"] = f(d["attestations"].([]any)) })
	}
	neg := []struct {
		name                    string
		doc                     []byte
		keys                    []provenance.NPMKey
		pkg, version, integrity string
		err                     error
	}{
		{name: "tampered digest", integrity: other.Dist.Integrity, err: provenance.ErrSubjectMismatch},
		{name: "other package name", pkg: "semver-fork", err: provenance.ErrSubjectMismatch},
		{name: "other version", version: "7.6.2", err: provenance.ErrSubjectMismatch},
		{name: "registry key expired before logging", keys: expired, err: provenance.ErrKeyExpired},
		{name: "unknown registry key", keys: keys[1:], err: provenance.ErrUnknownKey},
		{name: "sha256 integrity", integrity: "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, 32)), err: provenance.ErrUnsupported},
		{name: "provenance listed as publish attestation", doc: reorder(func(a []any) []any {
			set(a[1], provenance.PredicateNPMPublish, "predicateType")
			return a[1:]
		}), err: provenance.ErrUntrustedCert},
		{name: "publish listed as provenance", doc: reorder(func(a []any) []any {
			set(a[0], provenance.PredicateSLSAv1, "predicateType")
			return a[:1]
		}), err: provenance.ErrUntrustedCert},
		{name: "duplicate provenance", doc: reorder(func(a []any) []any { return append(a, a[1]) }), err: provenance.ErrMalformed},
		{name: "only unknown predicate types", doc: reorder(func(a []any) []any {
			set(a[0], "https://example.com/other", "predicateType")
			return a[:1]
		}), err: provenance.ErrNoAttestations},
		{name: "no attestations", doc: []byte(`{"attestations":[]}`), err: provenance.ErrNoAttestations},
		{name: "too many attestations", doc: reorder(func(a []any) []any {
			for len(a) <= provenance.MaxAttestations {
				a = append(a, a[0])
			}
			return a
		}), err: provenance.ErrLimit},
		{name: "too large", doc: append(bytes.TrimSuffix(bytes.TrimSpace(doc), []byte("}")), []byte(`,"pad":"`+strings.Repeat("a", provenance.MaxDocumentSize)+`"}`)...), err: provenance.ErrLimit},
		{name: "not JSON", doc: []byte("Not Found"), err: provenance.ErrMalformed},
	}
	for _, c := range neg {
		d, k, pkg, version, integrity := doc, keys, v.Name, v.Version, v.Dist.Integrity
		if c.doc != nil {
			d = c.doc
		}
		if c.keys != nil {
			k = c.keys
		}
		if c.pkg != "" {
			pkg = c.pkg
		}
		if c.version != "" {
			version = c.version
		}
		if c.integrity != "" {
			integrity = c.integrity
		}
		if _, err := provenance.VerifyNPMAttestations(d, k, trustedRoot(t), pkg, version, integrity); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}

	// The subject of a scoped package percent-encodes the scope's "@" (npm-package-arg toPurl).
	core, _ := npmPackage(t, "sigstore-core-4.0.1")
	if _, err := provenance.VerifyNPMAttestations(fixture(t, "npm/sigstore-core-4.0.1.attestations.json"), keys, root, "sigstore/core", core.Version, core.Dist.Integrity); !errors.Is(err, provenance.ErrSubjectMismatch) {
		t.Errorf("unscoped name: %v", err)
	}
}

func TestDigestFromSRI(t *testing.T) {
	v, _ := npmPackage(t, "semver-7.6.3")
	d, err := provenance.DigestFromSRI(v.Dist.Integrity)
	if err != nil || d.Algorithm != "sha512" || d.Value != "a157a43f570ab48f824c3bc759815470cb6c2bfd34c260047f2a8a7cd740466f2ed7035585281a5fb03c77852e225508e5ef38884c0e86ced93d8466cd4f54e8" {
		t.Fatalf("%+v %v", d, err)
	}
	sha256 := "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]struct {
		in, alg string
		err     error
	}{
		"strongest wins": {in: sha256 + " " + v.Dist.Integrity + "?opt", alg: "sha512"},
		"sha256":         {in: sha256, alg: "sha256"},
		"sha1 only":      {in: "sha1-" + base64.StdEncoding.EncodeToString(make([]byte, 20)), err: provenance.ErrUnsupported},
		"empty":          {in: "", err: provenance.ErrUnsupported},
		"wrong length":   {in: "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 32)), err: provenance.ErrMalformed},
		"not base64":     {in: "sha512-%%%", err: provenance.ErrMalformed},
	}
	for name, c := range cases {
		d, err := provenance.DigestFromSRI(c.in)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: got %v, want %v", name, err, c.err)
			}
			continue
		}
		if err != nil || d.Algorithm != c.alg {
			t.Errorf("%s: %+v %v", name, d, err)
		}
	}
}
