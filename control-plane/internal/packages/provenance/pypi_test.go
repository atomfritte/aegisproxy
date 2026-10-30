package provenance_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/packages/provenance"
)

func TestVerifyPyPIProvenance(t *testing.T) {
	root := trustedRoot(t)
	cases := []struct {
		release, file, repo, environment, san string
	}{
		{"sampleproject-4.0.0", "sampleproject-4.0.0.tar.gz", "pypa/sampleproject", "", "https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/heads/main"},
		{"sampleproject-4.0.0", "sampleproject-4.0.0-py3-none-any.whl", "pypa/sampleproject", "", "https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/heads/main"},
		{"sigstore-4.5.1", "sigstore-4.5.1-py3-none-any.whl", "sigstore/sigstore-python", "", "https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.5.1"},
		{"sigstore-4.5.1", "sigstore-4.5.1.tar.gz", "sigstore/sigstore-python", "", "https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.5.1"},
		{"pip-audit-2.10.1", "pip_audit-2.10.1-py3-none-any.whl", "pypa/pip-audit", "release", "https://github.com/pypa/pip-audit/.github/workflows/release.yml@refs/tags/v2.10.1"},
	}
	for _, c := range cases {
		r, err := provenance.VerifyPyPIProvenance(fixture(t, "pypi/"+c.file+".provenance.json"), root, c.file, pypiDigest(t, c.release, c.file))
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if len(r.Attestations) != 1 {
			t.Fatalf("%s: %d attestations", c.file, len(r.Attestations))
		}
		a := r.Attestations[0]
		if a.Publisher.Kind != "GitHub" || a.Publisher.Repository != c.repo || a.Publisher.Workflow != "release.yml" || a.Publisher.Environment != c.environment {
			t.Errorf("%s publisher: %+v", c.file, a.Publisher)
		}
		if a.Result.PredicateType != provenance.PredicatePyPIPublish || a.Result.Identity.SAN != c.san ||
			a.Result.Identity.SourceRepositoryURI != "https://github.com/"+c.repo || a.Result.Subjects[0].Name != c.file {
			t.Errorf("%s result: %+v %+v", c.file, a.Result, a.Result.Identity)
		}
	}

	const file, release = "sampleproject-4.0.0.tar.gz", "sampleproject-4.0.0"
	doc := fixture(t, "pypi/"+file+".provenance.json")
	digest := pypiDigest(t, release, file)
	wheel := "sampleproject-4.0.0-py3-none-any.whl"
	att := []any{"attestation_bundles", 0, "attestations", 0}
	at := func(keys ...any) []any { return append(append([]any{}, att...), keys...) }
	publisher := func(f func(p map[string]any)) func(t *testing.T, d map[string]any) {
		return func(t *testing.T, d map[string]any) {
			f(path(d, "attestation_bundles", 0, "publisher").(map[string]any))
		}
	}
	var foreignCert any
	mutate(t, fixture(t, "pypi/sigstore-4.5.1.tar.gz.provenance.json"), func(d map[string]any) { foreignCert = path(d, at("verification_material", "certificate")...) })

	neg := []struct {
		name     string
		doc      []byte
		mod      func(t *testing.T, d map[string]any)
		filename string
		sha256   string
		err      error
	}{
		{name: "wrong filename", filename: wheel, err: provenance.ErrSubjectMismatch},
		{name: "tampered digest", sha256: "00" + digest[2:], err: provenance.ErrSubjectMismatch},
		{name: "attestation of another file", doc: fixture(t, "pypi/"+wheel+".provenance.json"), err: provenance.ErrSubjectMismatch},
		{name: "digest not hex", sha256: "xyz", err: provenance.ErrMalformed},
		{name: "publisher repository", mod: publisher(func(p map[string]any) { p["repository"] = "evil/sampleproject" }), err: provenance.ErrIdentityMismatch},
		{name: "publisher repository case", mod: publisher(func(p map[string]any) { p["repository"] = "PyPA/sampleproject" }), err: provenance.ErrIdentityMismatch},
		{name: "publisher workflow", mod: publisher(func(p map[string]any) { p["workflow"] = "other.yml" }), err: provenance.ErrIdentityMismatch},
		{name: "publisher on GitLab", mod: publisher(func(p map[string]any) {
			p["kind"], p["workflow_filepath"] = "GitLab", ".gitlab-ci.yml"
		}), err: provenance.ErrIdentityMismatch},
		{name: "publisher on Google", mod: publisher(func(p map[string]any) {
			p["kind"], p["email"] = "Google", "release@project.iam.gserviceaccount.com"
		}), err: provenance.ErrIdentityMismatch},
		{name: "publisher on CircleCI", mod: publisher(func(p map[string]any) {
			p["kind"], p["project_id"], p["pipeline_definition_id"] = "CircleCI", "p", "d"
		}), err: provenance.ErrIdentityMismatch},
		{name: "unknown publisher kind", mod: publisher(func(p map[string]any) { p["kind"] = "ActiveState" }), err: provenance.ErrUnsupported},
		{name: "publisher without workflow", mod: publisher(func(p map[string]any) { delete(p, "workflow") }), err: provenance.ErrMalformed},
		{name: "no publisher", mod: func(t *testing.T, d map[string]any) {
			delete(path(d, "attestation_bundles", 0).(map[string]any), "publisher")
		}, err: provenance.ErrMalformed},
		{name: "swapped certificate", mod: func(t *testing.T, d map[string]any) {
			set(d, foreignCert, at("verification_material", "certificate")...)
		}, err: provenance.ErrUntrustedCert},
		{name: "statement modified", mod: func(t *testing.T, d map[string]any) {
			st, _ := base64.StdEncoding.DecodeString(path(d, at("envelope", "statement")...).(string))
			st = []byte(strings.Replace(string(st), "sampleproject-4.0.0.tar.gz", "sampleproject-4.0.1.tar.gz", 1))
			set(d, base64.StdEncoding.EncodeToString(st), at("envelope", "statement")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "envelope signature bit flip", mod: func(t *testing.T, d map[string]any) {
			set(d, flipB64(t, path(d, at("envelope", "signature")...)), at("envelope", "signature")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified SET", mod: func(t *testing.T, d map[string]any) {
			k := at("verification_material", "transparency_entries", 0, "inclusionPromise", "signedEntryTimestamp")
			set(d, flipB64(t, path(d, k...)), k...)
		}, err: provenance.ErrTransparencyLog},
		{name: "modified inclusion proof hash", mod: func(t *testing.T, d map[string]any) {
			k := at("verification_material", "transparency_entries", 0, "inclusionProof", "hashes", 3)
			set(d, flipB64(t, path(d, k...)), k...)
		}, err: provenance.ErrTransparencyLog},
		{name: "inclusion proof removed", mod: func(t *testing.T, d map[string]any) {
			delete(path(d, at("verification_material", "transparency_entries", 0)...).(map[string]any), "inclusionProof")
		}, err: provenance.ErrTransparencyLog},
		{name: "no transparency entry", mod: func(t *testing.T, d map[string]any) {
			set(d, []any{}, at("verification_material", "transparency_entries")...)
		}, err: provenance.ErrTransparencyLog},
		{name: "valid and tampered attestation", mod: func(t *testing.T, d map[string]any) {
			a := path(d, "attestation_bundles", 0, "attestations").([]any)
			bad := mutate(t, mustJSON(t, a[0]), func(x map[string]any) {
				set(x, flipB64(t, path(x, "envelope", "signature")), "envelope", "signature")
			})
			set(d, append(a, unJSON(t, bad)), "attestation_bundles", 0, "attestations")
		}, err: provenance.ErrTransparencyLog},
		{name: "provenance version", mod: func(t *testing.T, d map[string]any) { d["version"] = 2 }, err: provenance.ErrUnsupported},
		{name: "attestation version", mod: func(t *testing.T, d map[string]any) { set(d, 2, at("version")...) }, err: provenance.ErrUnsupported},
		{name: "no attestations", mod: func(t *testing.T, d map[string]any) { d["attestation_bundles"] = []any{} }, err: provenance.ErrNoAttestations},
		{name: "too many attestations", mod: func(t *testing.T, d map[string]any) {
			a := path(d, "attestation_bundles", 0, "attestations").([]any)
			for len(a) <= provenance.MaxAttestations {
				a = append(a, a[0])
			}
			set(d, a, "attestation_bundles", 0, "attestations")
		}, err: provenance.ErrLimit},
		{name: "too large", mod: func(t *testing.T, d map[string]any) { d["pad"] = strings.Repeat("a", provenance.MaxDocumentSize) }, err: provenance.ErrLimit},
		{name: "not JSON", doc: []byte("<html>"), err: provenance.ErrMalformed},
	}
	for _, c := range neg {
		d, name, sum := doc, file, digest
		if c.doc != nil {
			d = c.doc
		}
		if c.mod != nil {
			d = mutate(t, d, func(m map[string]any) { c.mod(t, m) })
		}
		if c.filename != "" {
			name = c.filename
		}
		if c.sha256 != "" {
			sum = c.sha256
		}
		if _, err := provenance.VerifyPyPIProvenance(d, root, name, sum); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}
}
