package export

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

// Ambient identities (managed / workload identity) send platform tokens: the Microsoft host pin must
// not be defeated by IPv6 zone tricks or by switching off the certificate check that backs it.
func TestSentinelAmbientIdentityTLSAndZones(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	base := models.ExportSink{Name: "s", Type: "sentinel", Streams: []string{"audit"}, DCRImmutableID: "dcr-1", TenantID: "t", ClientID: "c"}
	for _, c := range []struct {
		name, auth, endpoint, authority string
		skip                            bool
		ca                              string
		ok                              bool
	}{
		// Reviewer vector: zone suffixes that look like the pinned domains.
		{"zone endpoint", "workload_identity", "https://[fc00:f853:ccd:e793::1%25.monitor.azure.com]:19142", "https://[::ffff:172.17.0.1%25.login.microsoftonline.com]:19142", true, "", false},
		{"zone authority", "workload_identity", "https://dce-1.westeurope-1.ingest.monitor.azure.com", "https://[::ffff:172.17.0.1%25.login.microsoftonline.com]", false, "", false},
		{"zone loopback", "managed_identity", "https://[::ffff:127.0.0.2%25x.monitor.azure.com]/", "", false, "", false},
		{"skip verify", "workload_identity", "https://dce-1.westeurope-1.ingest.monitor.azure.com", "", true, "", false},
		{"custom CA", "managed_identity", "https://dce-1.westeurope-1.ingest.monitor.azure.com", "", false, ca, false},
		{"skip verify, real authority, local endpoint", "workload_identity", "https://127.0.0.1:8443", "", true, "", false},
		{"system trust", "workload_identity", "https://dce-1.westeurope-1.ingest.monitor.azure.com", "https://login.microsoftonline.com", false, "", true},
		{"local doubles", "workload_identity", "https://127.0.0.1:8443", "https://localhost:8443", true, "", true},
		{"local managed identity double", "managed_identity", "https://[::1]:8443", "", true, ca, true},
	} {
		s := base
		s.AzureAuth, s.Endpoint, s.AuthorityURL, s.TLSSkipVerify, s.CACertPEM = c.auth, c.endpoint, c.authority, c.skip, c.ca
		if err := Validate(&s); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// The author's own client secret keeps the TLS options (private collectors, inspection proxies).
	s := base
	s.AzureAuth, s.Endpoint, s.Secret, s.TLSSkipVerify, s.CACertPEM = "client_secret", "https://collector.corp.example", "secret", true, ca
	if err := Validate(&s); err != nil {
		t.Errorf("client secret with tls_skip_verify and ca_cert_pem: %v", err)
	}
}
