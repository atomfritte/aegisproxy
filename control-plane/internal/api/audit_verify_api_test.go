package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/ca"
	"aegisproxy/control-plane/internal/config"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/notify"
	"aegisproxy/control-plane/internal/store"
	"aegisproxy/control-plane/internal/threatintel"
)

// auditLogHarness is newHarness with an audit log file and the background verification of the
// complete trail.
func auditLogHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	caMgr, err := ca.NewCAManager(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := store.NewAuditSink(filepath.Join(dir, "audit.jsonl"), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti"), Logger: logger})
	notifier := notify.NewDispatcher(models.NotificationConfig{}, logger)
	exporter := export.New(export.Options{SpoolDir: filepath.Join(dir, "export-spool"), ExportDir: filepath.Join(dir, "export"), Node: "test", Version: "test", Logger: logger})
	t.Cleanup(exporter.Close)
	st, err := store.NewStore(store.Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, Notifier: notifier,
		Logger: logger, BootstrapAdminPassword: "Harness-Secret-Pass-7", Exporter: exporter, AuditSink: sink, AuditVerifyInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	cfg := &config.Config{PublicURL: "https://aegis.example", DashboardURL: "https://aegis.example", DataPlaneKey: testDPKey,
		SessionTTL: time.Hour, CookieSameSite: http.SameSiteStrictMode, UIDir: filepath.Join(dir, "no-ui"), AuditLogPath: filepath.Join(dir, "audit.jsonl")}
	am := auth.NewAuthManager([]byte(strings.Repeat("j", 40)), time.Hour)
	am.SetRevocationChecker(st)
	s := NewServer(Deps{Store: st, Auth: am, CA: caMgr, Notifier: notifier, Config: cfg, Logger: logger, Version: "test", Exporter: exporter})
	h := &harness{srv: httptest.NewServer(s), st: st, adminPW: "Harness-Secret-Pass-7", cfg: cfg, dir: dir}
	t.Cleanup(h.srv.Close)
	return h
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

// Round-3 F1: posture and metrics report the complete verification of the trail, and a modified
// trail found by GET /api/audit/verify is recorded (posture fails, aegis_audit_trail_intact drops).
func TestAuditChainPostureFollowsCompleteVerification(t *testing.T) {
	h := auditLogHarness(t)
	h.login(t)
	waitFor(t, "complete verification at start-up", func() bool { return h.st.AuditFullCheck().At != nil })
	if c := postureByID(t, h)["audit-chain"]; c.Status != "pass" || !strings.Contains(c.Detail, "verified completely") {
		t.Fatalf("posture after the complete verification: %+v", c)
	}
	metrics := func() string { return body(t, h.do(t, "GET", "/metrics", nil, nil).Body) }
	if m := metrics(); !strings.Contains(m, "aegis_audit_full_verify_ok 1") || !strings.Contains(m, "aegis_audit_full_verify_timestamp_seconds ") {
		t.Fatalf("metrics: %s", m)
	}

	// An insider edits an event in the middle of audit.jsonl.
	path := filepath.Join(h.dir, "audit.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("audit log too short: %d lines", len(lines))
	}
	var ev map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &ev)
	ev["summary"] = "(edited by insider)"
	b, _ := json.Marshal(ev)
	lines[0] = string(b)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := decode[verifyJSON](t, h.do(t, "GET", "/api/audit/verify", nil, nil).Body)
	if v.Valid || !strings.Contains(v.Error, "hash mismatch") {
		t.Fatalf("verify: %+v", v)
	}
	if c := postureByID(t, h)["audit-chain"]; c.Status != "fail" || !strings.Contains(c.Detail, "hash mismatch") {
		t.Fatalf("posture after the failed verification: %+v", c)
	}
	if m := metrics(); !strings.Contains(m, "aegis_audit_trail_intact 0") || !strings.Contains(m, "aegis_audit_full_verify_ok 0") {
		t.Fatalf("metrics after the failed verification: %s", m)
	}
}

// Round-3 F4: an audit sink that cannot deliver does not count as forwarding the trail.
func TestAuditExportPostureRequiresDelivery(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + l.Addr().String()
	l.Close() // nothing listens there any more
	if r := h.do(t, "POST", "/api/integrations/exports", map[string]any{"name": "siem", "type": "otlp", "enabled": true, "format": "json",
		"endpoint": dead, "streams": []string{"audit"}, "flush_seconds": 1, "spool_mb": 16}, ui); r.StatusCode >= 300 {
		t.Fatalf("create sink: %d %s", r.StatusCode, body(t, r.Body))
	}
	waitFor(t, "posture reports the failing destination", func() bool {
		if _, err := h.st.UpsertGroup(models.ServerGroup{ID: "grp-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""), Name: "g"}, adminClaimsFor(h)); err != nil {
			t.Fatal(err)
		}
		c := postureByID(t, h)["audit-export"]
		return c.Status == "fail" && strings.Contains(c.Detail, "no destination receives it") && strings.Contains(c.Detail, "siem: retrying")
	})
}

// RD4-4: a mixed sink (audit + traffic) whose destination accepts the traffic records but rejects every audit
// record does not forward the audit trail. The sink-wide last success is the traffic's; the posture counts the
// audit stream's own deliveries, and passes again once the destination takes the audit records.
func TestAuditExportPostureCountsOnlyAuditDeliveries(t *testing.T) {
	var acceptAudit atomic.Bool
	var auditSeen, trafficSeen atomic.Int64
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rd = zr
		}
		b, _ := io.ReadAll(rd)
		var items []string
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		for i := 1; i < len(lines); i += 2 { // action line, document line
			if strings.Contains(lines[i], "aegisproxy.audit") {
				auditSeen.Add(1)
				if !acceptAudit.Load() {
					items = append(items, `{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [aegisproxy.audit.after]"}}}`)
					continue
				}
			} else {
				trafficSeen.Add(1)
			}
			items = append(items, `{"create":{"status":201}}`)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"items":[%s]}`, strings.Join(items, ","))
	}))
	defer es.Close()
	h := newHarness(t)
	h.login(t)
	if r := h.do(t, "POST", "/api/integrations/exports", map[string]any{"name": "siem", "type": "elasticsearch", "enabled": true,
		"endpoint": es.URL, "streams": []string{"audit", "traffic"}, "flush_seconds": 1, "spool_mb": 16}, ui); r.StatusCode >= 300 {
		t.Fatalf("create sink: %d %s", r.StatusCode, body(t, r.Body))
	}
	n := 0
	activity := func() { // one audit event and one traffic record
		n++
		if _, err := h.st.UpsertGroup(models.ServerGroup{ID: fmt.Sprintf("grp-rd44-%d", n), Name: "g"}, adminClaimsFor(h)); err != nil {
			t.Fatal(err)
		}
		h.st.RecordFlow(models.TrafficFlow{Timestamp: time.Now().UTC(), ServerIP: "10.1.0.5", Method: "GET", Scheme: "https",
			Host: "pkgs.example.org", Port: 443, Path: "/", FullURL: "https://pkgs.example.org/", Verdict: models.VerdictAllowed})
	}
	waitFor(t, "posture reports the sink that rejects the audit records", func() bool {
		activity()
		c := postureByID(t, h)["audit-export"]
		return auditSeen.Load() > 0 && trafficSeen.Load() > 0 && c.Status == "fail" &&
			strings.Contains(c.Detail, "audit records rejected") && strings.Contains(c.Detail, "mapper_parsing_exception") &&
			strings.Contains(c.Detail, "no audit record delivered yet")
	})
	var st models.ExportSinkStatus
	for _, s := range h.exportStatus(t) {
		st = s
	}
	if tr := st.Streams[models.StreamTraffic]; tr.LastSuccessAt == nil || tr.Failing() || st.LastSuccessAt == nil {
		t.Fatalf("traffic must be delivered (the sink-wide last success): %+v", st)
	}
	if a := st.Streams[models.StreamAudit]; !a.Failing() || !a.Rejected || a.LastSuccessAt != nil {
		t.Fatalf("audit stream status: %+v", a)
	}
	acceptAudit.Store(true)
	waitFor(t, "posture passes once the audit records are accepted", func() bool {
		activity()
		c := postureByID(t, h)["audit-export"]
		return c.Status == "pass" && strings.Contains(c.Detail, "1 destination(s) receive the audit stream")
	})
}

// exportStatus is the Log export status of the API.
func (h *harness) exportStatus(t *testing.T) []models.ExportSinkStatus {
	t.Helper()
	r := h.do(t, "GET", "/api/integrations/exports", nil, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("export status: %d %s", r.StatusCode, body(t, r.Body))
	}
	var out struct {
		Status []models.ExportSinkStatus `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Status
}

// RD4-4: which status of a sink with the audit stream counts as forwarding the trail.
func TestAuditSinkDelivering(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	audit := func(a models.ExportStreamStatus) map[string]models.ExportStreamStatus {
		return map[string]models.ExportStreamStatus{models.StreamAudit: a, models.StreamTraffic: {LastSuccessAt: ago(0)}}
	}
	for _, c := range []struct {
		name    string
		st      models.ExportSinkStatus
		running bool
		want    bool
	}{
		{"not running yet", models.ExportSinkStatus{State: "error"}, false, true},
		{"idle, no audit record yet", models.ExportSinkStatus{State: "idle"}, true, true},
		{"failing sink, no audit record yet", models.ExportSinkStatus{State: "error", LastErrorAt: ago(0)}, true, false},
		{"retrying, recent success, no audit record yet", models.ExportSinkStatus{State: "retrying", LastSuccessAt: ago(time.Minute)}, true, true},
		{"retrying for long, no audit record yet", models.ExportSinkStatus{State: "retrying", LastSuccessAt: ago(time.Hour)}, true, false},
		{"every audit record rejected, traffic delivered", models.ExportSinkStatus{State: "ok", LastSuccessAt: ago(0),
			Streams: audit(models.ExportStreamStatus{LastErrorAt: ago(time.Second), Rejected: true})}, true, false},
		{"audit rejected after an earlier audit delivery", models.ExportSinkStatus{State: "ok", LastSuccessAt: ago(0),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(time.Minute), LastErrorAt: ago(time.Second), Rejected: true})}, true, false},
		{"audit delivered and rejected in one batch", models.ExportSinkStatus{State: "ok", LastSuccessAt: ago(time.Second),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(time.Second), LastErrorAt: ago(time.Second), Rejected: true})}, true, false},
		{"audit delivered after a rejection", models.ExportSinkStatus{State: "ok", LastSuccessAt: ago(0),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(0), LastErrorAt: ago(time.Minute), Rejected: true})}, true, true},
		{"destination briefly unavailable", models.ExportSinkStatus{State: "retrying", LastSuccessAt: ago(time.Minute),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(time.Minute), LastErrorAt: ago(time.Second)})}, true, true},
		{"audit not delivered for long, traffic delivered", models.ExportSinkStatus{State: "retrying", LastSuccessAt: ago(0),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(time.Hour), LastErrorAt: ago(time.Second)})}, true, false},
		{"audit delivered, traffic rejected", models.ExportSinkStatus{State: "error", LastSuccessAt: ago(time.Hour), LastErrorAt: ago(0),
			Streams: map[string]models.ExportStreamStatus{models.StreamAudit: {LastSuccessAt: ago(time.Hour)}, models.StreamTraffic: {LastErrorAt: ago(0), Rejected: true}}}, true, true},
		{"audit delivered, destination down for long", models.ExportSinkStatus{State: "retrying", LastSuccessAt: ago(time.Hour),
			Streams: audit(models.ExportStreamStatus{LastSuccessAt: ago(time.Hour)})}, true, false},
	} {
		if got := auditSinkDelivering(c.st, c.running); got != c.want {
			t.Errorf("%s: delivering=%t, want %t", c.name, got, c.want)
		}
	}
}
