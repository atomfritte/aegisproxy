package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// tlv builds a single DER TLV (definite length) from a tag byte and content.
func derTLVb(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func selfSignedCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Acme Signing"}},
		Issuer:       pkix.Name{CommonName: "Acme Root CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildPKCS7 assembles a minimal CMS SignedData carrying one certificate.
func buildPKCS7(certDER []byte) []byte {
	oidSignedData := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	encap := derTLVb(0x30, []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}) // SEQUENCE{ OID data }
	version := []byte{0x02, 0x01, 0x01}
	digestAlgos := []byte{0x31, 0x00}
	certs := derTLVb(0xA0, certDER) // [0] IMPLICIT certificates
	signerInfos := []byte{0x31, 0x00}

	signedData := derTLVb(0x30, concat(version, digestAlgos, encap, certs, signerInfos))
	content := derTLVb(0xA0, signedData) // [0] EXPLICIT
	return derTLVb(0x30, concat(oidSignedData, content))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParsePKCS7Signer(t *testing.T) {
	certDER := selfSignedCertDER(t, "code-signer.acme.test")
	p7 := buildPKCS7(certDER)
	subj, iss, ok := parsePKCS7Signer(p7)
	if !ok {
		t.Fatal("parsePKCS7Signer returned ok=false")
	}
	if !strings.Contains(subj, "code-signer.acme.test") {
		t.Errorf("subject = %q", subj)
	}
	// Self-signed, so the issuer equals the subject; just confirm it was extracted.
	if !strings.Contains(iss, "Acme Signing") {
		t.Errorf("issuer = %q", iss)
	}
}

func TestParsePKCS7Garbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30}, {0x30, 0x80}, {0xff, 0xff, 0xff}, []byte("not der at all")} {
		if _, _, ok := parsePKCS7Signer(b); ok {
			t.Errorf("garbage %v should not parse", b)
		}
	}
}

func TestAuthenticodeBlockDetection(t *testing.T) {
	certDER := selfSignedCertDER(t, "ps-signer.acme.test")
	p7 := buildPKCS7(certDER)
	b64 := base64.StdEncoding.EncodeToString(p7)
	var sb strings.Builder
	sb.WriteString("function Get-Thing {}\n")
	sb.WriteString("# SIG # Begin signature block\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString("# " + b64[i:end] + "\n")
	}
	sb.WriteString("# SIG # End signature block\n")

	root, inv := writeTree(t, map[string]string{"Demo.psm1": sb.String()})
	sigs := ScanSignatures(root, inv)
	if len(sigs) != 1 || sigs[0].Kind != "authenticode" {
		t.Fatalf("signatures = %+v", sigs)
	}
	if !strings.Contains(sigs[0].Signer, "ps-signer.acme.test") {
		t.Errorf("signer = %q", sigs[0].Signer)
	}
	if sigs[0].Verified != nil {
		t.Errorf("Verified should be nil (not verifiable in sandbox), got %v", *sigs[0].Verified)
	}
}
