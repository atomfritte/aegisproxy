package api

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func telemetryBatch(prefix string, n int) map[string]any {
	flows := make([]map[string]any, n)
	for i := range flows {
		flows[i] = map[string]any{"id": prefix + "-" + itoa(i), "timestamp": time.Now().UTC(), "server_ip": "10.1.0.5",
			"method": "GET", "scheme": "https", "host": "pkg.example", "path": "/", "full_url": "https://pkg.example/?sig=abc&x=1",
			"verdict": "ALLOWED", "status_code": 200}
	}
	return map[string]any{"flows": flows}
}

// The batch endpoint acknowledges only stored flows: 503 + Retry-After while the flow journal cannot be written,
// and a resend is recognized by flow ID.
func TestFlowBatchAcknowledgedOnlyWhenStored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	h := newHarness(t)
	dp := map[string]string{"X-Aegis-DataPlane-Key": testDPKey, "X-Aegis-DataPlane-ID": "dp-1"}
	journal := filepath.Join(h.dir, "flow-journal")
	if err := os.Chmod(journal, 0o500); err != nil {
		t.Fatal(err)
	}
	resp := h.do(t, "POST", "/api/dataplane/flows/batch", telemetryBatch("ack", 2), dp)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("unwritable journal: %d (Retry-After %q)", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if err := os.Chmod(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	resp = h.do(t, "POST", "/api/dataplane/flows/batch", telemetryBatch("ack", 2), dp)
	body := decode[map[string]float64](t, resp.Body)
	if resp.StatusCode != 201 || body["recorded_count"] != 2 || body["duplicate_count"] != 0 {
		t.Fatalf("retry: %d %v", resp.StatusCode, body)
	}
	resp = h.do(t, "POST", "/api/dataplane/flows/batch", telemetryBatch("ack", 2), dp)
	body = decode[map[string]float64](t, resp.Body)
	if resp.StatusCode != 201 || body["recorded_count"] != 0 || body["duplicate_count"] != 2 {
		t.Fatalf("resend: %d %v", resp.StatusCode, body)
	}
	if resp := h.do(t, "POST", "/api/dataplane/flows/batch", telemetryBatch("big", maxFlowBatch+1), dp); resp.StatusCode != 413 {
		t.Fatalf("oversized batch: %d", resp.StatusCode)
	}

	resp = h.do(t, "GET", "/metrics", nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	for _, want := range []string{
		`aegis_flow_duplicates_total 2`,
		`aegis_flows_dropped_total{reason="batch_too_large"} 1001`,
		`aegis_flow_batches_refused_total 1`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}

func TestHeartbeatReportsPolicyAgeAndTelemetryLoss(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	bundle := func(id string, extra map[string]string) {
		hdr := map[string]string{"X-Aegis-DataPlane-Key": testDPKey, "X-Aegis-DataPlane-ID": id}
		for k, v := range extra {
			hdr[k] = v
		}
		if resp := h.do(t, "GET", "/api/dataplane/bundle", nil, hdr); resp.StatusCode != 200 {
			t.Fatalf("bundle: %d", resp.StatusCode)
		}
	}
	posture := func() map[string]map[string]any {
		resp := h.do(t, "GET", "/api/system/posture", nil, nil)
		body := decode[struct{ Checks []map[string]any }](t, resp.Body)
		out := map[string]map[string]any{}
		for _, c := range body.Checks {
			out[c["id"].(string)] = c
		}
		return out
	}

	bundle("dp-old", nil) // older worker: reports nothing
	if c := posture()["worker-policy-age"]; c["status"] != "warn" || !strings.Contains(c["detail"].(string), "dp-old") {
		t.Fatalf("worker without policy age report: %v", c)
	}

	srv := h.srv.Config.Handler.(*Server)
	srv.dpMu.Lock()
	delete(srv.dataPlanes, "dp-old")
	srv.dpMu.Unlock()
	bundle("dp-a", map[string]string{"X-Aegis-Policy-Age": "12", "X-Aegis-Policy-Max-Age": "600",
		"X-Aegis-Flows-Dropped": "overflow=3,spool_full=2,Bad Reason=9", "X-Aegis-Flow-Backlog": "42"})
	checks := posture()
	if c := checks["worker-policy-age"]; c["status"] != "pass" {
		t.Fatalf("worker within its policy age: %v", c)
	}
	if c := checks["telemetry-loss"]; c["status"] != "warn" || !strings.Contains(c["detail"].(string), "dp-a (5)") {
		t.Fatalf("telemetry loss: %v", c)
	}
	raw, _ := io.ReadAll(h.do(t, "GET", "/api/state", nil, nil).Body)
	for _, want := range []string{`"policy_age_seconds":12`, `"policy_max_age_seconds":600`, `"flow_backlog":42`, `"flows_dropped_total":5`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("data-plane status lacks %s", want)
		}
	}
	raw, _ = io.ReadAll(h.do(t, "GET", "/metrics", nil, nil).Body)
	for _, want := range []string{
		`aegis_dataplane_flows_dropped_total{dataplane="dp-a",reason="overflow"} 3`,
		`aegis_dataplane_flow_backlog{dataplane="dp-a"} 42`,
		`aegis_dataplane_policy_age_seconds{dataplane="dp-a"} 12`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(string(raw), "Bad Reason") {
		t.Error("unvalidated drop reason exported")
	}

	bundle("dp-a", map[string]string{"X-Aegis-Policy-Age": "900", "X-Aegis-Policy-Max-Age": "600"})
	if c := posture()["worker-policy-age"]; c["status"] != "fail" {
		t.Fatalf("worker past its policy age: %v", c)
	}
}

func TestBundleNormalizesQueryRedaction(t *testing.T) {
	h := newHarness(t)
	resp := h.do(t, "GET", "/api/dataplane/bundle", nil, map[string]string{"X-Aegis-DataPlane-Key": testDPKey})
	body := decode[struct {
		SecurityPolicy map[string]any `json:"security_policy"`
	}](t, resp.Body)
	if got := body.SecurityPolicy["telemetry_query_redaction"]; got != "sensitive" {
		t.Fatalf("telemetry_query_redaction in bundle: %v", got)
	}
}
