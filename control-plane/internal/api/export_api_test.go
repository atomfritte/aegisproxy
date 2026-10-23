package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

func TestLogExportAPI(t *testing.T) {
	var mu sync.Mutex
	var batches []string
	var sigOK bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		batches = append(batches, string(b))
		sigOK = r.Header.Get("X-Aegis-Signature") == export.WebhookSignature("hook-secret", r.Header.Get("X-Aegis-Timestamp"), b)
		mu.Unlock()
	}))
	defer sink.Close()
	h := newHarness(t)
	h.login(t)
	body := map[string]any{"name": "SOAR webhook", "type": "webhook", "enabled": true, "streams": []string{"audit", "traffic"},
		"endpoint": sink.URL, "secret": "hook-secret", "flush_seconds": 1, "headers": map[string]string{"X-Api-Key": "k1"}}
	test := decode[map[string]any](t, h.do(t, "POST", "/api/integrations/exports/test", body, ui).Body)
	if test["ok"] != true {
		t.Fatalf("test delivery: %+v", test)
	}
	resp := h.do(t, "POST", "/api/integrations/exports", body, ui)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	created := decode[models.ExportSink](t, resp.Body)
	if created.Secret != "" || !created.HasSecret || created.Headers["X-Api-Key"] != "" {
		t.Fatalf("secrets leaked or lost: %+v", created)
	}
	// Update without re-sending secrets keeps them.
	created.Name = "SOAR webhook (renamed)"
	if r := h.do(t, "PUT", "/api/integrations/exports/"+created.ID, created, ui); r.StatusCode != 200 {
		t.Fatalf("update: %d", r.StatusCode)
	}
	if merged := h.st.MergeExportSecrets(models.ExportSink{ID: created.ID, Headers: sealed.Map{"X-Api-Key": ""}}); merged.Secret != "hook-secret" || merged.Headers["X-Api-Key"] != "k1" {
		t.Fatalf("secrets not kept: %+v", merged)
	}
	// Audit events (the update itself) and traffic reach the destination.
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "x.example", FullURL: "https://x.example/?q=1", Verdict: models.VerdictBlocked})
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		all := strings.Join(batches, "\n")
		mu.Unlock()
		if strings.Contains(all, "EXPORT_SINK_UPDATED") && strings.Contains(all, `"stream":"traffic"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("records not delivered: %s", all)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	if !sigOK {
		t.Error("webhook signature invalid")
	}
	mu.Unlock()
	list := decode[map[string]json.RawMessage](t, h.do(t, "GET", "/api/integrations/exports", nil, nil).Body)
	if strings.Contains(string(list["sinks"]), "hook-secret") || !strings.Contains(string(list["status"]), `"sent"`) {
		t.Errorf("list: %s / %s", list["sinks"], list["status"])
	}
	metrics := h.do(t, "GET", "/metrics", nil, nil)
	mb, _ := io.ReadAll(metrics.Body)
	if !strings.Contains(string(mb), "aegis_export_records_sent_total{sink=\""+created.ID+"\"}") {
		t.Error("export metrics missing")
	}
	if r := h.do(t, "DELETE", "/api/integrations/exports/"+created.ID, nil, ui); r.StatusCode != 200 {
		t.Fatalf("delete: %d", r.StatusCode)
	}
}
