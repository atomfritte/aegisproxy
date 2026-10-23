package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"aegisproxy/control-plane/internal/defender"
	"aegisproxy/control-plane/internal/models"
)

type fakeDefender struct {
	mu       sync.Mutex
	risk     string
	isolated bool
	srv      *httptest.Server
}

func newFakeDefender(t *testing.T) *fakeDefender {
	f := &fakeDefender{risk: "High"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-a/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "mde-secret" || !strings.HasSuffix(r.Form.Get("scope"), "/.default") {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"mde-token","expires_in":3600}`))
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer mde-token" {
				w.WriteHeader(401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/indicators", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"@odata.nextLink": f.srv.URL + "/api/indicators?page=2", "value": []map[string]any{
				{"indicatorValue": "c2.defender.example", "indicatorType": "DomainName", "action": "Block"},
				{"indicatorValue": "audit-only.example", "indicatorType": "DomainName", "action": "Audit"},
				{"indicatorValue": "expired.defender.example", "indicatorType": "DomainName", "action": "Block", "expirationTime": "2001-01-01T00:00:00Z"},
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
			{"indicatorValue": "203.0.113.99", "indicatorType": "IpAddress", "action": "AlertAndBlock"},
			{"indicatorValue": strings.Repeat("ef", 32), "indicatorType": "FileSha256", "action": "BlockAndRemediate"},
		}})
	}))
	mux.HandleFunc("GET /api/machines", auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
			{"id": "m-ci", "computerDnsName": "ci-1.corp.local", "riskScore": f.risk, "exposureLevel": "Medium", "healthStatus": "Active"},
			{"id": "m-vault", "computerDnsName": "unknown-host", "lastIpAddress": "10.9.0.5", "riskScore": "Low"},
			{"id": "m-other", "computerDnsName": "not-registered", "riskScore": "High"},
		}})
	}))
	mux.HandleFunc("GET /api/machineactions", auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		acts := []map[string]any{}
		if f.isolated {
			acts = append(acts, map[string]any{"machineId": "m-vault", "type": "Isolate", "status": "Succeeded", "creationDateTimeUtc": "2026-01-01T00:00:00Z"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": acts})
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestDefenderIntegration(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	fd := newFakeDefender(t)
	cfg := models.DefenderConfig{Enabled: true, TenantID: "tenant-a", ClientID: "app-1", ClientSecret: "mde-secret",
		APIBaseURL: fd.srv.URL, AuthorityURL: fd.srv.URL, ImportIndicators: true, DeviceSync: true,
		QuarantineOnRisk: "high", QuarantineOnIsolation: true, AutoRelease: true}
	if _, err := st.UpdateDefenderConfig(cfg, infosecClaims); err == nil {
		t.Fatal("InfoSec configured tenant credentials")
	}
	pub, err := st.UpdateDefenderConfig(cfg, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if pub.ClientSecret != "" || !pub.HasClientSecret {
		t.Fatal("secret leaked")
	}
	res, err := st.TestDefender(context.Background(), models.DefenderConfig{TenantID: "tenant-a", ClientID: "app-1", APIBaseURL: fd.srv.URL, AuthorityURL: fd.srv.URL})
	if err != nil || res["ok"] != true || res["devices"] != 3 || res["indicators"] != 5 {
		t.Fatalf("test connection: %v %v", res, err)
	}
	// Indicators (block actions only, not expired) via the collector.
	body, err := st.defenderCollector(context.Background(), models.ThreatFeed{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, want := range []string{"domain\tc2.defender.example", "ip\t203.0.113.99", "sha256\t" + strings.Repeat("ef", 32)} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "audit-only") || strings.Contains(got, "expired") {
		t.Errorf("non-blocking or expired indicator imported: %q", got)
	}
	// Device sync: hostname match (short name) with risk High -> quarantine; IP match without risk -> none.
	if err := st.SyncDefenderDevices(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	srvs := map[string]models.Server{}
	for _, s := range st.Servers() {
		srvs[s.ID] = s
	}
	ci, vault := srvs["srv-ci-1"], srvs["srv-vault-1"]
	if !ci.Quarantined || ci.QuarantinedBy != defenderActor || ci.Defender == nil || ci.Defender.RiskScore != "High" {
		t.Fatalf("ci server: %+v / %+v", ci, ci.Defender)
	}
	if vault.Quarantined || vault.Defender == nil || vault.Defender.MatchedBy != "ip" {
		t.Fatalf("vault server: %+v", vault)
	}
	if d := st.DefenderConfig(); d.LastSyncDevices != 3 || d.MatchedServers != 2 {
		t.Errorf("sync status: %+v", d)
	}
	// Isolation in Defender quarantines; risk dropping releases only Defender-initiated quarantines.
	fd.mu.Lock()
	fd.isolated, fd.risk = true, "Low"
	fd.mu.Unlock()
	if _, err := st.SetQuarantine("srv-vault-1", false, "", adminClaims); err != nil {
		t.Fatal(err)
	}
	_ = st.SyncDefenderDevices(context.Background(), true)
	for _, s := range st.Servers() {
		srvs[s.ID] = s
	}
	if srvs["srv-ci-1"].Quarantined {
		t.Error("Defender quarantine not released after the risk dropped")
	}
	if !srvs["srv-vault-1"].Quarantined || !srvs["srv-vault-1"].Defender.Isolated {
		t.Error("isolated device not quarantined")
	}
	// A manual quarantine is never released by the integration.
	if _, err := st.SetQuarantine("srv-ci-1", true, "manual incident", adminClaims); err != nil {
		t.Fatal(err)
	}
	_ = st.SyncDefenderDevices(context.Background(), true)
	for _, s := range st.Servers() {
		if s.ID == "srv-ci-1" && !s.Quarantined {
			t.Error("manual quarantine released by Defender sync")
		}
	}
	// The client refuses to follow pagination links to another host (token leak).
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"@odata.nextLink": "https://attacker.example/steal", "value": []any{}})
	}))
	defer evil.Close()
	c := defender.New(defender.Config{TenantID: "tenant-a", ClientID: "app-1", ClientSecret: "mde-secret", APIBase: evil.URL, Authority: fd.srv.URL}, nil)
	if _, err := c.Indicators(context.Background()); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Errorf("foreign nextLink: %v", err)
	}
}
