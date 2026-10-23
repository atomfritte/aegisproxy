package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func signCSR(t *testing.T, csrPath string, isCA bool, rootKey *rsa.PrivateKey, root *x509.Certificate) []byte {
	t.Helper()
	data, _ := os.ReadFile(csrPath)
	b, _ := pem.Decode(data)
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: isCA, BasicConstraintsValid: true, MaxPathLenZero: isCA,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCorporatePKIImport(t *testing.T) {
	dir := t.TempDir()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	csr, err := GenerateCSR(dir, "CN=AegisProxy Issuing CA,O=Corp,C=DE")
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no permission bits; the installer's ACL on the data directory protects the keys.
	if fi, _ := os.Stat(filepath.Join(dir, pendingKey)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Error("pending key permissions")
	}
	// A non-CA certificate is rejected.
	leafPath := filepath.Join(dir, "leaf.pem")
	_ = os.WriteFile(leafPath, signCSR(t, csr, false, rootKey, root), 0o600)
	if _, err := ImportSignedCA(dir, leafPath, ""); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("non-CA accepted: %v", err)
	}
	// A certificate for another key is rejected.
	other := t.TempDir()
	otherCSR, _ := GenerateCSR(other, "CN=Other")
	otherPath := filepath.Join(dir, "other.pem")
	_ = os.WriteFile(otherPath, signCSR(t, otherCSR, true, rootKey, root), 0o600)
	if _, err := ImportSignedCA(dir, otherPath, ""); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("foreign certificate accepted: %v", err)
	}
	// The issued subordinate CA with its root chain is installed; the root is not sent to clients.
	subPath := filepath.Join(dir, "sub.pem")
	_ = os.WriteFile(subPath, signCSR(t, csr, true, rootKey, root), 0o600)
	chainPath := filepath.Join(dir, "chain.pem")
	_ = os.WriteFile(chainPath, rootPEM, 0o600)
	cert, err := ImportSignedCA(dir, subPath, chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "AegisProxy Issuing CA" {
		t.Errorf("subject: %s", cert.Subject)
	}
	combined, _ := os.ReadFile(filepath.Join(dir, "mitmproxy-ca.pem"))
	if strings.Count(string(combined), "BEGIN CERTIFICATE") != 1 || !strings.Contains(string(combined), "PRIVATE KEY") {
		t.Errorf("combined file: %d certs", strings.Count(string(combined), "BEGIN CERTIFICATE"))
	}
	if fi, _ := os.Stat(filepath.Join(dir, "mitmproxy-ca.pem")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Error("CA key file permissions")
	}
	m, err := NewCAManager(dir)
	if err != nil || !strings.Contains(m.Subject, "AegisProxy Issuing CA") || !strings.Contains(m.Issuer, "Corp Root CA") {
		t.Fatalf("CA manager: %v %s", err, m.Subject)
	}
	if _, err := os.Stat(filepath.Join(dir, pendingKey)); !os.IsNotExist(err) {
		t.Error("pending key not removed after import")
	}
	// A broken chain is rejected.
	csr2, _ := GenerateCSR(dir, "CN=Second")
	otherRootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherRootTmpl := *rootTmpl
	otherRootTmpl.Subject = pkix.Name{CommonName: "Rogue Root"}
	otherDER, _ := x509.CreateCertificate(rand.Reader, &otherRootTmpl, &otherRootTmpl, &otherRootKey.PublicKey, otherRootKey)
	otherRoot, _ := x509.ParseCertificate(otherDER)
	sub2 := filepath.Join(dir, "sub2.pem")
	_ = os.WriteFile(sub2, signCSR(t, csr2, true, otherRootKey, otherRoot), 0o600)
	if _, err := ImportSignedCA(dir, sub2, chainPath); err == nil {
		t.Error("certificate with an invalid chain accepted")
	}
}
