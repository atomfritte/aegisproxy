package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/store"
	"aegisproxy/control-plane/internal/threatintel"
)

// legacyHarness starts the API on the data directory of a pre-2.1 installation: one unkeyed audit
// event, no audit chain key, anchor or checkpoint.
func legacyHarness(t *testing.T) (*harness, models.AuditEvent) {
	t.Helper()
	dir := t.TempDir()
	ev := models.AuditEvent{ID: "aud-legacy", Revision: 4, Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Actor: "admin", ActorRole: "SUPER_ADMIN", Action: "GROUP_CREATED", Category: "FLEET", EntityType: "server_group",
		EntityID: "grp-old", EntityName: "Old", Summary: "created before 2.1", PrevHash: strings.Repeat("0", 64)}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s||||", ev.PrevHash, ev.ID, ev.Revision,
		ev.Timestamp.Format(time.RFC3339Nano), ev.Actor, ev.ActorRole, ev.Action, ev.Category, ev.EntityType, ev.EntityID, ev.EntityName, ev.Summary)))
	ev.EventHash = hex.EncodeToString(sum[:])
	state, _ := json.Marshal(map[string]any{"schema_version": 3, "revision": 4, "audit_events": []models.AuditEvent{ev}})
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	caMgr, err := ca.NewCAManager(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti"), Logger: logger})
	notifier := notify.NewDispatcher(models.NotificationConfig{}, logger)
	exporter := export.New(export.Options{SpoolDir: filepath.Join(dir, "export-spool"), ExportDir: filepath.Join(dir, "export"), Node: "test", Version: "test", Logger: logger})
	t.Cleanup(exporter.Close)
	st, err := store.NewStore(store.Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, Notifier: notifier,
		Logger: logger, BootstrapAdminPassword: "Harness-Secret-Pass-7", Exporter: exporter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	cfg := &config.Config{PublicURL: "https://aegis.example", DashboardURL: "https://aegis.example", DataPlaneKey: testDPKey,
		SessionTTL: time.Hour, CookieSameSite: http.SameSiteStrictMode, UIDir: filepath.Join(dir, "no-ui")}
	am := auth.NewAuthManager([]byte(strings.Repeat("j", 40)), time.Hour)
	am.SetRevocationChecker(st)
	s := NewServer(Deps{Store: st, Auth: am, CA: caMgr, Notifier: notifier, Config: cfg, Logger: logger, Version: "test", Exporter: exporter})
	h := &harness{srv: httptest.NewServer(s), st: st, adminPW: "Harness-Secret-Pass-7", cfg: cfg, dir: dir}
	t.Cleanup(h.srv.Close)
	return h, ev
}

func postureByID(t *testing.T, h *harness) map[string]PostureCheck {
	t.Helper()
	res := decode[struct {
		Checks []PostureCheck `json:"checks"`
	}](t, h.do(t, "GET", "/api/system/posture", nil, nil).Body)
	out := map[string]PostureCheck{}
	for _, c := range res.Checks {
		out[c.ID] = c
	}
	return out
}

type verifyJSON struct {
	Valid         bool   `json:"valid"`
	Error         string `json:"error"`
	LegacyEvents  int    `json:"legacy_events"`
	LegacyPending bool   `json:"legacy_pending"`
	LegacyHead    string `json:"legacy_head"`
}

// Round-2 finding 1: the unkeyed prefix of an upgraded installation fails verification and posture
// until a Super Admin accepts it with the expected count and last hash.
func TestAuditLegacyAcceptanceAPI(t *testing.T) {
	h, legacy := legacyHarness(t)
	h.login(t)
	v := decode[verifyJSON](t, h.do(t, "GET", "/api/audit/verify", nil, nil).Body)
	if v.Valid || !v.LegacyPending || v.LegacyEvents != 1 || v.LegacyHead != legacy.EventHash || !strings.HasPrefix(v.Error, "legacy_pending") {
		t.Fatalf("verify before acceptance: %+v", v)
	}
	if c := postureByID(t, h)["audit-chain"]; c.Status != "fail" || !strings.Contains(c.Detail, "not trusted") {
		t.Fatalf("posture before acceptance: %+v", c)
	}

	if _, _, err := h.st.UpsertUser(storeUserInput("infosec", models.RoleInfoSecApprover), adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	infosec := h.loginAs(t, "infosec", "Ops-Password-123!")
	accept := func(hh *harness, n int, head string) *http.Response {
		return hh.do(t, "POST", "/api/audit/anchor/accept-legacy", map[string]any{"legacy_events": n, "legacy_head": head}, ui)
	}
	if r := accept(infosec, 1, legacy.EventHash); r.StatusCode != http.StatusForbidden {
		t.Fatalf("InfoSec Approver accepted legacy events: %d", r.StatusCode)
	}
	if r := accept(h, 2, legacy.EventHash); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong count: %d", r.StatusCode)
	}
	if r := accept(h, 1, strings.Repeat("ab", 32)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong hash: %d", r.StatusCode)
	}
	if r := h.do(t, "POST", "/api/audit/anchor/accept-legacy", map[string]any{"legacy_head": legacy.EventHash}, ui); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing count: %d", r.StatusCode)
	}
	if r := accept(h, 1, legacy.EventHash); r.StatusCode != http.StatusOK {
		t.Fatalf("accept: %d %s", r.StatusCode, body(t, r.Body))
	}
	v = decode[verifyJSON](t, h.do(t, "GET", "/api/audit/verify", nil, nil).Body)
	if !v.Valid || v.LegacyPending || v.LegacyEvents != 1 {
		t.Fatalf("verify after acceptance: %+v", v)
	}
	if c := postureByID(t, h)["audit-chain"]; c.Status != "warn" {
		t.Fatalf("posture after acceptance: %+v", c)
	}
	if r := accept(h, 1, legacy.EventHash); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("accepted twice: %d", r.StatusCode)
	}
	found := false
	for _, ev := range h.st.GetSnapshot().SecurityEvents {
		found = found || ev.Type == store.SecurityEventAuditLegacyAccepted && ev.Severity == "high"
	}
	if !found {
		t.Fatal("acceptance raised no alert")
	}
}

// Round-2 findings 3 and 8: production posture fails without an exported audit stream, and an
// encryption key kept in the data directory is a warning.
func TestAuditAndEncryptionPosture(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	if c := postureByID(t, h)["audit-export"]; c.Status != "fail" {
		t.Fatalf("audit-export without a sink in production: %+v", c)
	}
	if r := h.do(t, "POST", "/api/integrations/exports", map[string]any{"name": "siem", "type": "file", "enabled": true, "format": "json",
		"endpoint": "audit.jsonl", "streams": []string{"audit"}}, ui); r.StatusCode >= 300 {
		t.Fatalf("create sink: %d %s", r.StatusCode, body(t, r.Body))
	}
	if c := postureByID(t, h)["audit-export"]; c.Status != "pass" {
		t.Fatalf("audit-export with a sink: %+v", c)
	}

	key, _ := sealed.DeriveKey(strings.Repeat("k", 48))
	if err := sealed.Configure(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	if c := postureByID(t, h)["encryption"]; c.Status != "pass" {
		t.Fatalf("encryption with an external key: %+v", c)
	}
	h.cfg.EncryptionKeyInDataDir = true
	if c := postureByID(t, h)["encryption"]; c.Status != "warn" || !strings.Contains(c.Detail, "data directory") || !strings.Contains(c.Remediation, "AEGIS_ENCRYPTION_KEY_FILE") {
		t.Fatalf("encryption with the key in DATA_DIR: %+v", c)
	}
}
