package provenance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/packages/provenance"
)

func fixture(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func trustedRoot(t testing.TB) *provenance.TrustedRoot {
	t.Helper()
	r, err := provenance.PublicGoodTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func npmKeys(t testing.TB) []provenance.NPMKey {
	t.Helper()
	keys, err := provenance.ParseNPMKeys(fixture(t, "npm/keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// npmVersion is the part of a packument version document the tests use.
type npmVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Integrity  string                    `json:"integrity"`
		Signatures []provenance.NPMSignature `json:"signatures"`
	} `json:"dist"`
}

func npmPackage(t testing.TB, file string) (npmVersion, time.Time) {
	t.Helper()
	var v npmVersion
	if err := json.Unmarshal(fixture(t, "npm/"+file+".json"), &v); err != nil {
		t.Fatal(err)
	}
	var times map[string]time.Time
	if err := json.Unmarshal(fixture(t, "npm/published.json"), &times); err != nil {
		t.Fatal(err)
	}
	pub, ok := times[v.Name+"@"+v.Version]
	if !ok {
		t.Fatalf("no publish time for %s@%s", v.Name, v.Version)
	}
	return v, pub
}

// npmBundle returns the bundle of the attestation with the given predicate type.
func npmBundle(t testing.TB, file, predicateType string) []byte {
	t.Helper()
	var doc struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(fixture(t, "npm/"+file+".attestations.json"), &doc); err != nil {
		t.Fatal(err)
	}
	for _, a := range doc.Attestations {
		if a.PredicateType == predicateType {
			return a.Bundle
		}
	}
	t.Fatalf("%s has no %s attestation", file, predicateType)
	return nil
}

// pypiDigest returns the sha256 PyPI lists for a file of a release (the per-version JSON API document).
func pypiDigest(t testing.TB, release, filename string) string {
	t.Helper()
	var doc struct {
		URLs []struct {
			Filename string            `json:"filename"`
			Digests  map[string]string `json:"digests"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(fixture(t, "pypi/"+release+".json"), &doc); err != nil {
		t.Fatal(err)
	}
	for _, u := range doc.URLs {
		if u.Filename == filename {
			return u.Digests["sha256"]
		}
	}
	t.Fatalf("%s has no file %s", release, filename)
	return ""
}

// mutate decodes a JSON document, applies f and encodes it again.
func mutate(t testing.TB, data []byte, f func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	f(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// path walks maps and slices: path(doc, "a", 0, "b").
func path(v any, keys ...any) any {
	for _, k := range keys {
		switch k := k.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func set(doc any, value any, keys ...any) {
	parent := path(doc, keys[:len(keys)-1]...)
	switch k := keys[len(keys)-1].(type) {
	case string:
		parent.(map[string]any)[k] = value
	case int:
		parent.([]any)[k] = value
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unJSON(t testing.TB, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
