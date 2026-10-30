package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// SandboxCA is a throwaway certificate authority created fresh for one analysis run. The analyzed runtimes are
// told to trust it (NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, ...) so the HTTPS sink can terminate
// TLS and the full URL of every request becomes visible. The key never leaves the sandbox and the sandbox is
// discarded after the run.
type SandboxCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// NewSandboxCA generates a new ECDSA P-256 CA.
func NewSandboxCA() (*SandboxCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AegisProxy Sandbox Root (throwaway)", Organization: []string{"AegisProxy Sandbox"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &SandboxCA{
		key:     key,
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:  map[string]*tls.Certificate{},
	}, nil
}

// CertPEM is the CA certificate in PEM form, written into the sandbox trust store.
func (c *SandboxCA) CertPEM() []byte { return c.certPEM }

// GetCertificate issues (and caches) a leaf certificate for the requested SNI; it is wired into tls.Config so the
// HTTPS sink answers for whatever host the client asks for.
func (c *SandboxCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		name = "sandbox.invalid"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[name]; ok {
		return leaf, nil
	}
	leaf, err := c.issue(name)
	if err != nil {
		return nil, err
	}
	c.leaves[name] = leaf
	return leaf, nil
}

func (c *SandboxCA) issue(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}, nil
}
