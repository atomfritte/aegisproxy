package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The public copy must never contain the private key, and a control-plane started on the public
// directory alone must load the same CA instead of generating a new one.
func TestWritePublicHasNoKey(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCAManager(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "public")
	if err := m.WritePublic(pub); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(pub)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(pub, e.Name()))
		if e.Name() == "mitmproxy-ca.pem" || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("%s: private key in the public directory", e.Name())
		}
	}
	again, err := NewCAManager(pub)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint != m.Fingerprint {
		t.Fatalf("public directory loads another CA: %s != %s", again.Fingerprint, m.Fingerprint)
	}
	if _, err := os.Stat(filepath.Join(pub, "mitmproxy-ca.pem")); err == nil {
		t.Fatal("loading the public directory must not create a key")
	}
}
