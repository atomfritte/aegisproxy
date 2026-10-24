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

// Delivery errors name the destination without the token a URL may carry (webhook path, query).
func TestExportStatusNeverShowsEndpointSecrets(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	dead := closed.URL // nothing listens here any more: transport errors quote the request URL
	closed.Close()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "upstream failed for "+r.URL.String())
	}))
	defer echo.Close()
	h := newHarness(t)
	h.login(t)
	for _, s := range []map[string]any{
		{"name": "hook", "type": "webhook", "endpoint": dead + "/hooks/T000/B000/PathSecret1?token=QuerySecret1"},
		{"name": "otel", "type": "otlp", "endpoint": dead + "/v1/logs?api_key=QuerySecret2"},
		{"name": "echo", "type": "webhook", "endpoint": echo.URL + "/hooks/PathSecret3?sig=QuerySecret3"},
	} {
		s["enabled"], s["streams"], s["flush_seconds"] = true, []string{"audit"}, 1
		if r := h.do(t, "POST", "/api/integrations/exports", s, ui); r.StatusCode != 200 {
			t.Fatalf("create %s: %d", s["name"], r.StatusCode)
		}
	}
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-x", "name": "X"}, ui) // an audit event to deliver
	var status []models.ExportSinkStatus
	for deadline := time.Now().Add(15 * time.Second); ; {
		list := decode[struct {
			Status []models.ExportSinkStatus `json:"status"`
		}](t, h.do(t, "GET", "/api/integrations/exports", nil, nil).Body)
		status = list.Status
		failed := 0
		for _, st := range status {
			if st.LastError != "" {
				failed++
			}
		}
		if failed == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery errors not recorded: %+v", status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	key := infosecKey(t, h)
	views := map[string]string{
		"super admin": body(t, h.do(t, "GET", "/api/integrations/exports", nil, nil).Body),
		"infosec":     body(t, h.bearer(t, "GET", "/api/integrations/exports", key, nil).Body),
	}
	for who, v := range views {
		for _, secret := range []string{"PathSecret1", "QuerySecret1", "QuerySecret2", "PathSecret3", "QuerySecret3"} {
			if who == "super admin" && strings.HasSuffix(secret, "3") {
				continue // the echoing destination's response body is shown to the sink owner only
			}
			if strings.Contains(v, secret) {
				t.Errorf("%s view leaks %s: %s", who, secret, v)
			}
		}
	}
	if !strings.Contains(views["infosec"], "HTTP 503 from "+echo.URL+"/"+models.MaskedSecretMarker) {
		t.Errorf("destination missing from the infosec view: %s", views["infosec"])
	}
	// The masked webhook endpoint round-trips: saving it back keeps the stored URL.
	sinks := decode[struct {
		Sinks []models.ExportSink `json:"sinks"`
	}](t, h.do(t, "GET", "/api/integrations/exports", nil, nil).Body).Sinks
	for _, s := range sinks {
		if s.Name != "hook" {
			continue
		}
		if s.Endpoint != dead+"/"+models.MaskedSecretMarker {
			t.Fatalf("webhook endpoint not masked: %s", s.Endpoint)
		}
		s.Enabled = false
		if r := h.do(t, "PUT", "/api/integrations/exports/"+s.ID, s, ui); r.StatusCode != 200 {
			t.Fatalf("update: %d", r.StatusCode)
		}
		if got, _ := h.st.ExportSinkWithSecrets(s.ID); got.Endpoint != dead+"/hooks/T000/B000/PathSecret1?token=QuerySecret1" {
			t.Errorf("stored endpoint lost: %s", got.Endpoint)
		}
	}
}
