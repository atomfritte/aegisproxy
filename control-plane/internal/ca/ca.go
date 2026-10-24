package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CAManager struct {
	CertsDir    string
	CertPEM     []byte
	CertDER     []byte
	Subject     string
	Issuer      string
	SerialHex   string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
}

func NewCAManager(certsDir string) (*CAManager, error) {
	if err := os.MkdirAll(certsDir, 0o750); err != nil {
		return nil, err
	}
	mgr := &CAManager{CertsDir: certsDir}
	if err := mgr.ensureCA(); err != nil {
		return nil, err
	}
	return mgr, nil
}

func (m *CAManager) ensureCA() error {
	combinedPath := filepath.Join(m.CertsDir, "mitmproxy-ca.pem")
	certPEMPath := filepath.Join(m.CertsDir, "mitmproxy-ca-cert.pem")
	certCRTPath := filepath.Join(m.CertsDir, "aegis-enterprise-ca.crt")
	certDERPath := filepath.Join(m.CertsDir, "aegis-enterprise-ca.der")

	if data, err := os.ReadFile(certPEMPath); err == nil && len(data) > 0 {
		block, _ := pem.Decode(data)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				if !cert.IsCA {
					return fmt.Errorf("%s is not a CA certificate", certPEMPath)
				}
				m.CertPEM = data
				m.CertDER = block.Bytes
				m.populateMetadata(cert)
				if fi, err := os.Stat(combinedPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
					_ = os.Chmod(combinedPath, 0o600)
				}
				return nil
			}
		}
	}

	// Generate a fresh 3072-bit RSA Root CA (NIST SP 800-57: 128-bit security beyond 2030) compatible with mitmproxy
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Add(-1 * time.Hour)
	notAfter := now.Add(10 * 365 * 24 * time.Hour) // 10 years validity

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"AegisProxy Enterprise InfoSec"},
			OrganizationalUnit: []string{"Outbound Server Inspection & Zero-Trust Gateway"},
			CommonName:         "AegisProxy Enterprise Root CA",
			Country:            []string{"DE"},
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// mitmproxy signs leaf certificates directly with the root: no intermediates are needed.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}); err != nil {
		return err
	}

	var combinedBuf bytes.Buffer
	combinedBuf.Write(keyBuf.Bytes())
	combinedBuf.Write(certBuf.Bytes())

	m.CertPEM = certBuf.Bytes()
	m.CertDER = derBytes

	// The combined key+cert file is what mitmproxy loads (confdir). It never leaves disk with
	// anything but owner-only permissions, and the control-plane does not keep the key in memory.
	if err := os.WriteFile(combinedPath, combinedBuf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	for path, data := range map[string][]byte{certPEMPath: m.CertPEM, certCRTPath: m.CertPEM, certDERPath: m.CertDER} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("write CA certificate: %w", err)
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err == nil {
		m.populateMetadata(cert)
	}
	return nil
}

// WritePublic writes the public certificate files (never the key) into dir, replacing older copies.
func (m *CAManager) WritePublic(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"mitmproxy-ca-cert.pem": m.CertPEM, "aegis-enterprise-ca.crt": m.CertPEM, "aegis-enterprise-ca.der": m.CertDER} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return fmt.Errorf("write CA certificate: %w", err)
		}
	}
	return nil
}

func (m *CAManager) populateMetadata(cert *x509.Certificate) {
	m.Subject = cert.Subject.String()
	m.Issuer = cert.Issuer.String()
	m.SerialHex = strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
	m.NotBefore = cert.NotBefore
	m.NotAfter = cert.NotAfter
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	m.Fingerprint = strings.Join(parts, ":")
}
