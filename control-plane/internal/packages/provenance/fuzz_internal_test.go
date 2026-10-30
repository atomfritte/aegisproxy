package provenance

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"os"
	"testing"
)

// FuzzParsers covers the hand-written parsers: signed-note checkpoints, TLS-encoded SCT lists and the DER
// re-encoding of a TBSCertificate. None may panic.
func FuzzParsers(f *testing.F) {
	root, err := PublicGoodTrustedRoot()
	if err != nil {
		f.Fatal(err)
	}
	rekor := root.TransparencyLogs["c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"]
	raw, err := os.ReadFile("testdata/npm/sigstore-core-4.0.1.attestations.json")
	if err != nil {
		f.Fatal(err)
	}
	var doc struct {
		Attestations []struct {
			Bundle bundleJSON `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		f.Fatal(err)
	}
	b := doc.Attestations[1].Bundle
	leaf, err := x509.ParseCertificate(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		f.Fatal(err)
	}
	var sctList []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSCTList) {
			if _, err := asn1.Unmarshal(e.Value, &sctList); err != nil {
				f.Fatal(err)
			}
		}
	}
	p := b.VerificationMaterial.TlogEntries[0].InclusionProof
	f.Add(p.Checkpoint.Envelope, sctList, leaf.RawTBSCertificate)
	f.Fuzz(func(t *testing.T, note string, sctList, tbs []byte) {
		_ = verifyCheckpoint(rekor, note, uint64(p.TreeSize), p.RootHash)
		_, _ = parseSCTList(sctList)
		if out, err := removeExtension(tbs, oidSCTList); err == nil && len(out) == 0 {
			t.Fatal("empty TBSCertificate without error")
		}
	})
}
