package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Enterprise PKI: let a corporate CA (Active Directory Certificate Services, HashiCorp Vault,
// EJBCA, …) issue the interception CA as a subordinate CA. Clients that already trust the corporate
// root (GPO, MDM) then trust AegisProxy without any CA roll-out.
//
//   aegis-control-plane gen-csr <certs-dir> "CN=AegisProxy Issuing CA,O=Corp,C=DE"
//   (submit pending.csr to the corporate CA with a subordinate-CA template)
//   aegis-control-plane import-ca <certs-dir> issued.pem [chain.pem]

const pendingKey = "pending-ca.key"

// ParseSubject parses "CN=…,O=…,OU=…,C=…,L=…,ST=…".
func ParseSubject(s string) (pkix.Name, error) {
	var n pkix.Name
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(v) == "" {
			return n, fmt.Errorf("invalid subject component %q", part)
		}
		v = strings.TrimSpace(v)
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "CN":
			n.CommonName = v
		case "O":
			n.Organization = append(n.Organization, v)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, v)
		case "C":
			n.Country = append(n.Country, v)
		case "L":
			n.Locality = append(n.Locality, v)
		case "ST":
			n.Province = append(n.Province, v)
		default:
			return n, fmt.Errorf("unsupported subject attribute %q", k)
		}
	}
	if n.CommonName == "" {
		return n, errors.New("subject needs a CN")
	}
	return n, nil
}

// GenerateCSR creates a new RSA-3072 key (kept in the certs directory, 0600) and a CSR requesting a
// CA certificate with path length 0.
func GenerateCSR(certsDir, subject string) (string, error) {
	name, err := ParseSubject(subject)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(certsDir, 0o750); err != nil {
		return "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", err
	}
	bc, _ := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{true, 0})
	ku, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}) // keyCertSign | cRLSign
	tmpl := &x509.CertificateRequest{
		Subject: name, SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: ku},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(certsDir, pendingKey), keyPEM, 0o600); err != nil {
		return "", err
	}
	csrPath := filepath.Join(certsDir, "pending.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	return csrPath, nil
}

func readCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		// DER (AD CS "Base 64 / DER" downloads)
		raw, _ := os.ReadFile(path)
		if c, err := x509.ParseCertificate(raw); err == nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contains no certificate", path)
	}
	return out, nil
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if k, ok := a.(eq); ok {
		return k.Equal(b)
	}
	return false
}

// ImportSignedCA installs a certificate issued for the pending key (plus optional chain) as the
// interception CA. Existing CA files are kept as *.bak.
func ImportSignedCA(certsDir, certPath, chainPath string) (*x509.Certificate, error) {
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, pendingKey))
	if err != nil {
		return nil, errors.New("no pending key found: run gen-csr first")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("pending key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	certs, err := readCerts(certPath)
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	if !publicKeyEqual(&key.PublicKey, leaf.PublicKey) {
		return nil, errors.New("the certificate was not issued for the pending key (public key mismatch)")
	}
	if !leaf.IsCA || !leaf.BasicConstraintsValid {
		return nil, errors.New("the certificate is not a CA certificate (use a subordinate-CA template)")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the certificate does not allow certificate signing (keyCertSign)")
	}
	if !(leaf.MaxPathLen == 0 && leaf.MaxPathLenZero) {
		fmt.Fprintln(os.Stderr, "warning: the CA certificate has no path length constraint 0; prefer a template with pathlen:0")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("the certificate is not currently valid")
	}
	if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
		fmt.Fprintln(os.Stderr, "warning: the CA certificate expires within 30 days")
	}
	chain := certs[1:]
	if chainPath != "" {
		extra, err := readCerts(chainPath)
		if err != nil {
			return nil, err
		}
		chain = append(chain, extra...)
	}
	// Verify the chain when intermediates/root are supplied.
	if len(chain) > 0 {
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		for _, c := range chain {
			if bytes.Equal(c.RawIssuer, c.RawSubject) {
				roots.AddCert(c)
			} else {
				inters.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, fmt.Errorf("chain verification failed: %w", err)
		}
	}
	var combined, certOnly bytes.Buffer
	combined.Write(keyPEM)
	for _, c := range append([]*x509.Certificate{leaf}, chain...) {
		if bytes.Equal(c.RawIssuer, c.RawSubject) && c != leaf {
			continue // the root is never sent; clients have it
		}
		_ = pem.Encode(&combined, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	_ = pem.Encode(&certOnly, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	for _, name := range []string{"mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "aegis-enterprise-ca.crt", "aegis-enterprise-ca.der"} {
		p := filepath.Join(certsDir, name)
		if _, err := os.Stat(p); err == nil {
			_ = os.Rename(p, p+".bak")
		}
	}
	if err := os.WriteFile(filepath.Join(certsDir, "mitmproxy-ca.pem"), combined.Bytes(), 0o600); err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{"mitmproxy-ca-cert.pem": certOnly.Bytes(), "aegis-enterprise-ca.crt": certOnly.Bytes(), "aegis-enterprise-ca.der": leaf.Raw} {
		if err := os.WriteFile(filepath.Join(certsDir, name), data, 0o644); err != nil {
			return nil, err
		}
	}
	_ = os.Remove(filepath.Join(certsDir, pendingKey))
	_ = os.Remove(filepath.Join(certsDir, "pending.csr"))
	return leaf, nil
}
