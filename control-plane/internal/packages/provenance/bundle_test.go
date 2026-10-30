package provenance_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/packages/provenance"
)

// provenanceBundles are the Fulcio-signed SLSA provenance bundles of the npm fixtures (v0.1, v0.2, v0.3).
var provenanceBundles = []struct{ file, predicate string }{
	{"sigstore-1.5.0", provenance.PredicateSLSAv02},
	{"semver-7.6.3", provenance.PredicateSLSAv1},
	{"sigstore-core-4.0.1", provenance.PredicateSLSAv1},
}

func npmDigest(t *testing.T, file string) provenance.Digest {
	t.Helper()
	v, _ := npmPackage(t, file)
	d, err := provenance.DigestFromSRI(v.Dist.Integrity)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// flipB64 flips the lowest bit of the last byte of a base64 value.
func flipB64(t *testing.T, v any) string {
	raw, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	return base64.StdEncoding.EncodeToString(raw)
}

// leafPath is where a bundle keeps its leaf certificate.
func leafPath(doc map[string]any) []any {
	if _, ok := doc["verificationMaterial"].(map[string]any)["certificate"]; ok {
		return []any{"verificationMaterial", "certificate", "rawBytes"}
	}
	return []any{"verificationMaterial", "x509CertificateChain", "certificates", 0, "rawBytes"}
}

func TestVerifyBundle(t *testing.T) {
	root := trustedRoot(t)
	for _, b := range provenanceBundles {
		r, err := provenance.VerifyBundle(npmBundle(t, b.file, b.predicate), root, npmDigest(t, b.file))
		if err != nil {
			t.Errorf("%s: %v", b.file, err)
			continue
		}
		if r.PredicateType != b.predicate || r.Identity == nil || r.SLSA == nil || len(r.Subjects) != 1 {
			t.Errorf("%s: %+v", b.file, r)
		}
		// Certificates are checked at the integrated time: the fixtures keep verifying.
		later := provenance.Options{Now: func() time.Time { return time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC) }}
		if _, err := later.VerifyBundle(npmBundle(t, b.file, b.predicate), root, npmDigest(t, b.file)); err != nil {
			t.Errorf("%s in 2045: %v", b.file, err)
		}
		before := provenance.Options{Now: func() time.Time { return r.IntegratedTime.Add(-10 * time.Minute) }}
		if _, err := before.VerifyBundle(npmBundle(t, b.file, b.predicate), root, npmDigest(t, b.file)); !errors.Is(err, provenance.ErrTransparencyLog) {
			t.Errorf("%s: integrated time in the future: %v", b.file, err)
		}
	}
	if r, _ := provenance.VerifyBundle(npmBundle(t, "sigstore-1.5.0", provenance.PredicateSLSAv02), root, npmDigest(t, "sigstore-1.5.0")); r == nil ||
		r.SLSA.Version != "v0.2" || r.SLSA.BuilderID != "https://github.com/actions/runner" || r.SLSA.Workflow != ".github/workflows/release.yml" ||
		r.SLSA.Repository != "https://github.com/sigstore/sigstore-js" || r.SLSA.Ref != "refs/heads/main" || r.SLSA.InvocationID != "4950330706-1" {
		t.Errorf("SLSA v0.2 fields: %+v", r)
	}
}

func TestVerifyBundleTampering(t *testing.T) {
	root := trustedRoot(t)
	tlog := []any{"verificationMaterial", "tlogEntries", 0}
	at := func(keys ...any) []any { return append(append([]any{}, tlog...), keys...) }
	coreBundle := npmBundle(t, "sigstore-core-4.0.1", provenance.PredicateSLSAv1)
	// The leaf and log entry of another valid bundle (set per bundle below).
	var otherLeaf, otherEntry any
	from := func(bundle []byte) {
		mutate(t, bundle, func(d map[string]any) { otherLeaf, otherEntry = path(d, leafPath(d)...), path(d, tlog...) })
	}

	cases := []struct {
		name   string
		proof  bool // needs an inclusion proof (v0.2 and later)
		mod    func(t *testing.T, d map[string]any)
		digest func(d provenance.Digest) provenance.Digest
		err    error
	}{
		{name: "tampered digest", digest: func(d provenance.Digest) provenance.Digest { d.Value = "00" + d.Value[2:]; return d }, err: provenance.ErrSubjectMismatch},
		{name: "other digest algorithm", digest: func(provenance.Digest) provenance.Digest {
			return provenance.Digest{Algorithm: "sha256", Value: strings.Repeat("ab", 32)}
		}, err: provenance.ErrSubjectMismatch},
		{name: "malformed expected digest", digest: func(provenance.Digest) provenance.Digest { return provenance.Digest{Algorithm: "sha512", Value: "xyz"} }, err: provenance.ErrMalformed},
		{name: "modified SET", mod: func(t *testing.T, d map[string]any) {
			set(d, flipB64(t, path(d, at("inclusionPromise", "signedEntryTimestamp")...)), at("inclusionPromise", "signedEntryTimestamp")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "SET removed", mod: func(t *testing.T, d map[string]any) { delete(path(d, tlog...).(map[string]any), "inclusionPromise") }, err: provenance.ErrUnsupported},
		{name: "integrated time moved", mod: func(t *testing.T, d map[string]any) {
			n, _ := strconv.ParseInt(path(d, at("integratedTime")...).(string), 10, 64)
			set(d, strconv.FormatInt(n-60, 10), at("integratedTime")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "log index changed", mod: func(t *testing.T, d map[string]any) { set(d, "1", at("logIndex")...) }, err: provenance.ErrTransparencyLog},
		{name: "unknown log", mod: func(t *testing.T, d map[string]any) {
			set(d, base64.StdEncoding.EncodeToString(make([]byte, 32)), at("logId", "keyId")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "body of another entry", mod: func(t *testing.T, d map[string]any) {
			set(d, otherEntry.(map[string]any)["canonicalizedBody"], at("canonicalizedBody")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified inclusion proof hash", proof: true, mod: func(t *testing.T, d map[string]any) {
			set(d, flipB64(t, path(d, at("inclusionProof", "hashes", 0)...)), at("inclusionProof", "hashes", 0)...)
		}, err: provenance.ErrTransparencyLog},
		{name: "inclusion proof hash dropped", proof: true, mod: func(t *testing.T, d map[string]any) {
			h := path(d, at("inclusionProof", "hashes")...).([]any)
			set(d, h[1:], at("inclusionProof", "hashes")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified root hash", proof: true, mod: func(t *testing.T, d map[string]any) {
			set(d, flipB64(t, path(d, at("inclusionProof", "rootHash")...)), at("inclusionProof", "rootHash")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified tree size", proof: true, mod: func(t *testing.T, d map[string]any) {
			n, _ := strconv.ParseInt(path(d, at("inclusionProof", "treeSize")...).(string), 10, 64)
			set(d, strconv.FormatInt(n+1, 10), at("inclusionProof", "treeSize")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified checkpoint signature", proof: true, mod: func(t *testing.T, d map[string]any) {
			note := path(d, at("inclusionProof", "checkpoint", "envelope")...).(string)
			i := strings.LastIndex(note, " ")
			set(d, note[:i+1]+flipB64(t, strings.TrimSuffix(note[i+1:], "\n"))+"\n", at("inclusionProof", "checkpoint", "envelope")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "checkpoint removed", proof: true, mod: func(t *testing.T, d map[string]any) {
			delete(path(d, at("inclusionProof")...).(map[string]any), "checkpoint")
		}, err: provenance.ErrTransparencyLog},
		{name: "inclusion proof removed", proof: true, mod: func(t *testing.T, d map[string]any) {
			delete(path(d, tlog...).(map[string]any), "inclusionProof")
		}, err: provenance.ErrTransparencyLog},
		{name: "envelope signature bit flip", mod: func(t *testing.T, d map[string]any) {
			set(d, flipB64(t, path(d, "dsseEnvelope", "signatures", 0, "sig")), "dsseEnvelope", "signatures", 0, "sig")
		}, err: provenance.ErrTransparencyLog},
		{name: "envelope payload replaced", mod: func(t *testing.T, d map[string]any) {
			set(d, base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`)), "dsseEnvelope", "payload")
		}, err: provenance.ErrTransparencyLog},
		{name: "payload type changed", mod: func(t *testing.T, d map[string]any) {
			set(d, "application/json", "dsseEnvelope", "payloadType")
		}, err: provenance.ErrUnsupported},
		{name: "second envelope signature", mod: func(t *testing.T, d map[string]any) {
			s := path(d, "dsseEnvelope", "signatures").([]any)
			set(d, append(s, s[0]), "dsseEnvelope", "signatures")
		}, err: provenance.ErrUnsupported},
		{name: "swapped certificate", mod: func(t *testing.T, d map[string]any) {
			set(d, otherLeaf, leafPath(d)...)
		}, err: provenance.ErrUntrustedCert},
		{name: "swapped certificate and log entry", mod: func(t *testing.T, d map[string]any) {
			set(d, otherLeaf, leafPath(d)...)
			set(d, []any{otherEntry}, "verificationMaterial", "tlogEntries")
		}, err: provenance.ErrTransparencyLog},
		{name: "certificate is not DER", mod: func(t *testing.T, d map[string]any) { set(d, "AAAA", leafPath(d)...) }, err: provenance.ErrMalformed},
		{name: "no log entry", mod: func(t *testing.T, d map[string]any) { set(d, []any{}, "verificationMaterial", "tlogEntries") }, err: provenance.ErrTransparencyLog},
		{name: "too many log entries", mod: func(t *testing.T, d map[string]any) {
			e := path(d, tlog...)
			set(d, []any{e, e, e, e, e, e, e, e, e, e, e}, "verificationMaterial", "tlogEntries")
		}, err: provenance.ErrLimit},
		{name: "chain longer than ten certificates", mod: func(t *testing.T, d map[string]any) {
			c := map[string]any{"rawBytes": path(d, leafPath(d)...)}
			vm := path(d, "verificationMaterial").(map[string]any)
			delete(vm, "certificate")
			vm["x509CertificateChain"] = map[string]any{"certificates": []any{c, c, c, c, c, c, c, c, c, c, c}}
		}, err: provenance.ErrLimit},
		{name: "certificate and public key", mod: func(t *testing.T, d map[string]any) {
			path(d, "verificationMaterial").(map[string]any)["publicKey"] = map[string]any{"hint": "x"}
		}, err: provenance.ErrMalformed},
		{name: "unknown media type", mod: func(t *testing.T, d map[string]any) {
			d["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.9"
		}, err: provenance.ErrUnsupported},
		{name: "message signature", mod: func(t *testing.T, d map[string]any) {
			delete(d, "dsseEnvelope")
			d["messageSignature"] = map[string]any{}
		}, err: provenance.ErrUnsupported},
	}
	for _, b := range provenanceBundles {
		orig := npmBundle(t, b.file, b.predicate)
		if b.file == "sigstore-core-4.0.1" {
			from(npmBundle(t, "semver-7.6.3", provenance.PredicateSLSAv1))
		} else {
			from(coreBundle)
		}
		for _, c := range cases {
			if c.proof && b.file == "sigstore-1.5.0" {
				continue // v0.1 bundles carry no inclusion proof
			}
			bundle := orig
			if c.mod != nil {
				bundle = mutate(t, orig, func(d map[string]any) { c.mod(t, d) })
			}
			digest := npmDigest(t, b.file)
			if c.digest != nil {
				digest = c.digest(digest)
			}
			if _, err := provenance.VerifyBundle(bundle, root, digest); !errors.Is(err, c.err) {
				t.Errorf("%s, %s: got %v, want %v", b.file, c.name, err, c.err)
			}
		}
	}

	// The registry-signed publish attestation has no Fulcio certificate.
	if _, err := provenance.VerifyBundle(npmBundle(t, "semver-7.6.3", provenance.PredicateNPMPublish), root, npmDigest(t, "semver-7.6.3")); !errors.Is(err, provenance.ErrUntrustedCert) {
		t.Errorf("key-signed bundle: %v", err)
	}
	if _, err := provenance.VerifyBundle(coreBundle, nil, npmDigest(t, "sigstore-core-4.0.1")); !errors.Is(err, provenance.ErrMalformed) {
		t.Errorf("no trusted root: %v", err)
	}
	huge := []byte(`{"mediaType":"` + strings.Repeat("x", provenance.MaxDocumentSize) + `"}`)
	if _, err := provenance.VerifyBundle(huge, root, npmDigest(t, "semver-7.6.3")); !errors.Is(err, provenance.ErrLimit) {
		t.Errorf("oversized bundle: %v", err)
	}
}
