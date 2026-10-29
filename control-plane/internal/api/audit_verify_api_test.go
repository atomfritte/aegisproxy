package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
