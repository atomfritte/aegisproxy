package threatintel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

func waitSnapshot(t *testing.T, m *Manager, cond func(*Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := m.Snapshot(); s != nil && cond(s) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("snapshot condition not met")
}

func TestTAXIIAndMISPSources(t *testing.T) {
	var mispBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/taxii/api1/collections/c1/objects/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer taxii-token" || !strings.Contains(r.Header.Get("Accept"), "taxii+json;version=2.1") ||
			r.URL.Query().Get("match[type]") != "indicator" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		if r.URL.Query().Get("next") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"more": true, "next": "page2", "objects": []map[string]any{
				{"type": "indicator", "pattern_type": "stix", "pattern": "[domain-name:value = 'c2.taxii.example']"},
				{"type": "indicator", "pattern_type": "stix", "pattern": "[url:value = 'https://dl.taxii.example/x.exe'] OR [ipv4-addr:value = '203.0.113.66']"},
				{"type": "indicator", "pattern_type": "stix", "pattern": "[domain-name:value = 'revoked.taxii.example']", "revoked": true},
				{"type": "indicator", "pattern_type": "stix", "pattern": "[domain-name:value = 'expired.taxii.example']", "valid_until": "2001-01-01T00:00:00Z"},
				{"type": "indicator", "pattern_type": "sigma", "pattern": "title: x"},
				{"type": "malware", "name": "x"},
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"more": false, "objects": []map[string]any{
			{"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + strings.Repeat("ab", 32) + "']"},
			{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.0/24']"},
		}})
	})
	mux.HandleFunc("/misp/attributes/restSearch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "misp-key" {
			w.WriteHeader(403)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &mispBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"Attribute": []map[string]string{
			{"type": "domain", "value": "phish.misp.example"},
			{"type": "ip-dst|port", "value": "192.0.2.77|443"},
			{"type": "domain|ip", "value": "both.misp.example|192.0.2.78"},
			{"type": "filename|sha256", "value": "evil.dll|" + strings.Repeat("cd", 32)},
			{"type": "url", "value": "http://misp.example/payload"},
		}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, err := NewManager(Options{CacheDir: filepath.Join(t.TempDir(), "ti"), AllowLoopbackSources: true})
	if err != nil {
		t.Fatal(err)
	}
	m.Configure([]models.ThreatFeed{
		{ID: "taxii", Name: "TAXII", Enabled: true, Format: FeedFormatTAXII, URL: srv.URL + "/taxii/api1/collections/c1/", Category: "malware",
			AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer taxii-token", MatchSubdomains: true},
		{ID: "misp", Name: "MISP", Enabled: true, Format: FeedFormatMISP, URL: srv.URL + "/misp", Category: "phishing", AuthHeaderValue: "misp-key"},
	}, nil, nil)
	m.refreshDue(t.Context(), "", true)
	waitSnapshot(t, m, func(s *Snapshot) bool { _, hit := s.MatchHost("c2.taxii.example"); return hit })
	s := m.Snapshot()
	for _, host := range []string{"c2.taxii.example", "sub.c2.taxii.example", "phish.misp.example", "both.misp.example", "203.0.113.66", "198.51.100.9", "192.0.2.77"} {
		if _, hit := s.MatchHost(host); !hit {
			t.Errorf("%s not blocked", host)
		}
	}
	for _, host := range []string{"revoked.taxii.example", "expired.taxii.example"} {
		if _, hit := s.MatchHost(host); hit {
			t.Errorf("%s should not be blocked", host)
		}
	}
	if _, hit := s.MatchURL("https://dl.taxii.example/x.exe"); !hit {
		t.Error("TAXII URL indicator missing")
	}
	if _, hit := s.MatchHash(strings.Repeat("ab", 32)); !hit {
		t.Error("TAXII hash indicator missing")
	}
	if _, hit := s.MatchHash(strings.Repeat("cd", 32)); !hit {
		t.Error("MISP hash indicator missing")
	}
	if mispBody["to_ids"] != true || mispBody["enforceWarninglist"] != true {
		t.Errorf("MISP query: %v", mispBody)
	}
	// Production validation refuses loopback, link-local and plain http.
	for _, u := range []string{"http://misp.corp.example", "https://127.0.0.1/misp", "https://169.254.169.254/x"} {
		if ValidateSourceURL(u, false) == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if ValidateSourceURL("https://10.20.0.5/misp", false) != nil {
		t.Error("internal MISP server rejected")
	}
}
