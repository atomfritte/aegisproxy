package provenance_test

import (
	"encoding/json"
	"testing"

	"aegisproxy/control-plane/internal/packages/provenance"
)

// FuzzVerifyBundle feeds mutated real bundles to the verifier: it must never panic, and a nil error must come
// with a result. Run: go test -run '^$' -fuzz FuzzVerifyBundle -fuzztime 20s -fuzzminimizetime 0 ./internal/packages/provenance/
func FuzzVerifyBundle(f *testing.F) {
	root := trustedRoot(f)
	for _, file := range []string{"semver-7.6.3", "sigstore-core-4.0.1", "sigstore-1.5.0"} {
		var doc struct {
			Attestations []struct {
				Bundle json.RawMessage `json:"bundle"`
			} `json:"attestations"`
		}
		if err := json.Unmarshal(fixture(f, "npm/"+file+".attestations.json"), &doc); err != nil {
			f.Fatal(err)
		}
		for _, a := range doc.Attestations {
			f.Add([]byte(a.Bundle), npmIntegrity(f, file))
		}
	}
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":""},"tlogEntries":[{"inclusionProof":null}]},"dsseEnvelope":{"signatures":[{}]}}`), "")
	fallback, err := provenance.DigestFromSRI(npmIntegrity(f, "semver-7.6.3"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, bundle []byte, integrity string) {
		d, err := provenance.DigestFromSRI(integrity)
		if err != nil {
			d = fallback
		}
		if r, err := provenance.VerifyBundle(bundle, root, d); err == nil && r == nil {
			t.Fatal("nil result without error")
		}
	})
}

// FuzzVerifyDocuments covers the npm attestations and PyPI provenance documents around the bundles.
func FuzzVerifyDocuments(f *testing.F) {
	root, keys, integrity := trustedRoot(f), npmKeys(f), npmIntegrity(f, "semver-7.6.3")
	f.Add(fixture(f, "npm/semver-7.6.3.attestations.json"), fixture(f, "pypi/sampleproject-4.0.0.tar.gz.provenance.json"))
	f.Add(fixture(f, "npm/sigstore-1.5.0.attestations.json"), fixture(f, "pypi/pip_audit-2.10.1-py3-none-any.whl.provenance.json"))
	f.Fuzz(func(t *testing.T, npmDoc, pypiDoc []byte) {
		if r, err := provenance.VerifyNPMAttestations(npmDoc, keys, root, "semver", "7.6.3", integrity); err == nil && r == nil {
			t.Fatal("nil npm result without error")
		}
		if r, err := provenance.VerifyPyPIProvenance(pypiDoc, root, "sampleproject-4.0.0.tar.gz", "0ace7980f82c5815ede4cd7bf9f6693684cec2ae47b9b7ade9add533b8627c6b"); err == nil && r == nil {
			t.Fatal("nil PyPI result without error")
		}
		_, _ = provenance.ParseNPMKeys(npmDoc)
	})
}

func npmIntegrity(t testing.TB, file string) string {
	v, _ := npmPackage(t, file)
	return v.Dist.Integrity
}
