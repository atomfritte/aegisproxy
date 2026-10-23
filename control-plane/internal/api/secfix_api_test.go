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

	"aegisproxy/control-plane/internal/models"
)

// Regression tests for the 2.1 security review (secrets must never be sent to a caller-chosen host).

type captureServer struct {
	*httptest.Server
	mu  sync.Mutex
	got []string
}

func newCapture(t *testing.T) *captureServer {
	c := &captureServer{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.got = append(c.got, r.Header.Get("Authorization")+" "+r.Header.Get("X-Api-Key")+" "+string(b))
		c.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("internal-only response body with details"))
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *captureServer) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.got, "\n")
}

func infosecKey(t *testing.T, h *harness) string {
	t.Helper()
	resp := h.do(t, "POST", "/api/service-accounts", map[string]any{"name": "is-bot", "role": "INFOSEC_APPROVER",
		"expires_at": time.Now().Add(24 * time.Hour)}, ui)
	if resp.StatusCode != 201 {
		t.Fatalf("service account: %d", resp.StatusCode)
	}
	return decode[struct {
		Key string `json:"api_key"`
	}](t, resp.Body).Key
}

func TestExportTestNeverLeaksStoredSecrets(t *testing.T) {
	legit, attacker := newCapture(t), newCapture(t)
	h := newHarness(t)
	h.login(t)
	stored := decode[models.ExportSink](t, h.do(t, "POST", "/api/integrations/exports", map[string]any{"name": "HEC", "type": "splunk_hec",
		"enabled": false, "streams": []string{"audit"}, "endpoint": legit.URL, "secret": "hec-token-SECRET",
		"headers": map[string]string{"X-Api-Key": "hdr-SECRET"}}, ui).Body)
	key := infosecKey(t, h)

	// InfoSec tries to redirect the stored sink to its own listener: the saved destination is tested instead.
	evil := map[string]any{"id": stored.ID, "name": "HEC", "type": "splunk_hec", "streams": []string{"audit"}, "endpoint": attacker.URL,
		"headers": map[string]string{"X-Api-Key": ""}}
	res := decode[map[string]any](t, h.bearer(t, "POST", "/api/integrations/exports/test", key, evil).Body)
	if strings.Contains(attacker.all(), "SECRET") || attacker.all() != "" {
		t.Fatalf("stored secrets sent to the attacker: %q", attacker.all())
	}
	if !strings.Contains(legit.all(), "hec-token-SECRET") {
		t.Fatalf("saved destination not tested: %q", legit.all())
	}
	if msg, _ := res["error"].(string); strings.Contains(msg, "internal-only") || !strings.Contains(msg, "HTTP 401") {
		t.Fatalf("response body of the destination shown to InfoSec: %q", msg)
	}
	// InfoSec cannot test unsaved destinations at all.
	if r := h.bearer(t, "POST", "/api/integrations/exports/test", key, map[string]any{"name": "x", "type": "webhook", "streams": []string{"audit"}, "endpoint": attacker.URL}); r.StatusCode != 403 {
		t.Fatalf("InfoSec tested an unsaved destination: %d", r.StatusCode)
	}
	// Super Admin changing the destination must re-enter the credentials.
	if r := h.do(t, "POST", "/api/integrations/exports/test", evil, ui); r.StatusCode != 400 || strings.Contains(attacker.all(), "SECRET") {
		t.Fatalf("super admin test with changed destination reused stored secrets: %d %q", r.StatusCode, attacker.all())
	}
}

func TestDefenderTestNeverLeaksStoredSecret(t *testing.T) {
	attacker := newCapture(t)
	h := newHarness(t)
	h.login(t)
	if r := h.do(t, "PUT", "/api/integrations/defender", map[string]any{"enabled": false, "tenant_id": "11111111-2222-3333-4444-555555555555",
		"client_id": "app", "client_secret": "mde-SECRET"}, ui); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("save: %d %s", r.StatusCode, b)
	}
	key := infosecKey(t, h)
	evil := map[string]any{"tenant_id": "x", "client_id": "x", "authority_url": attacker.URL, "api_base_url": attacker.URL}
	h.bearer(t, "POST", "/api/integrations/defender/test", key, evil)
	// Super Admin: a changed authority without a new secret is refused, a foreign host is refused.
	h.do(t, "POST", "/api/integrations/defender/test", evil, ui)
	if strings.Contains(attacker.all(), "SECRET") {
		t.Fatalf("Defender secret sent to a caller-chosen authority: %q", attacker.all())
	}
	if r := h.do(t, "PUT", "/api/integrations/defender", map[string]any{"enabled": false, "tenant_id": "t", "client_id": "app",
		"authority_url": "https://login.attacker.example"}, ui); r.StatusCode != 400 {
		t.Fatalf("non-Microsoft authority accepted: %d", r.StatusCode)
	}
}

func TestAPIErrorsAreJSON(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	for _, c := range []struct {
		method, path string
		status       int
	}{{"GET", "/api/does-not-exist", 404}, {"DELETE", "/api/state", 405}, {"POST", "/api/nope", 404}} {
		resp := h.do(t, c.method, c.path, nil, ui)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != c.status || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || !strings.Contains(string(b), `"error"`) {
			t.Errorf("%s %s: %d %s %s", c.method, c.path, resp.StatusCode, resp.Header.Get("Content-Type"), b)
		}
	}
}

func TestTeamLeadNeedToKnow(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	for _, g := range []string{"grp-a", "grp-b"} {
		h.do(t, "POST", "/api/groups", map[string]any{"id": g, "name": g}, ui)
	}
	h.do(t, "POST", "/api/servers", map[string]any{"id": "srv-a", "hostname": "a", "ip": "10.0.0.1", "group_ids": []string{"grp-a"}}, ui)
	h.do(t, "POST", "/api/servers", map[string]any{"id": "srv-b", "hostname": "b", "ip": "10.0.0.2", "group_ids": []string{"grp-b"}}, ui)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, _, err := h.st.CreateAccessRequest(models.AccessRequest{ServerIP: ip, RequestedURL: "https://x.example/" + ip, Host: "x.example", Path: "/" + ip,
			Requester: "dev", Reason: "r", Duration: "7d"}); err != nil {
			t.Fatal(err)
		}
		h.st.RecordFlow(models.TrafficFlow{ServerIP: ip, Method: "GET", Host: "y.example", FullURL: "https://y.example/", Verdict: models.VerdictBlocked})
	}
	in := storeUserInput("lead-a", models.RoleTeamLead)
	in.AllowedGroups = []string{"grp-a"}
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	lead := &harness{srv: h.srv, st: h.st, cfg: h.cfg}
	resp := lead.do(t, "POST", "/api/auth/login", map[string]string{"username": "lead-a", "password": "Ops-Password-123!"}, ui)
	if resp.StatusCode != 200 {
		t.Fatalf("lead login: %d", resp.StatusCode)
	}
	lead.jar = resp.Cookies()
	state := decode[map[string]any](t, lead.do(t, "GET", "/api/state", nil, nil).Body)
	for _, key := range []string{"servers", "requests", "flows"} {
		items, _ := state[key].([]any)
		if len(items) != 1 {
			t.Errorf("%s visible to the grp-a lead: %d entries", key, len(items))
		}
		for _, it := range items {
			if strings.Contains(strings.ToLower(fmtJSON(it)), "10.0.0.2") {
				t.Errorf("%s of grp-b leaked: %s", key, fmtJSON(it))
			}
		}
	}
	if r := lead.do(t, "GET", "/api/audit/export", nil, nil); r.StatusCode != 403 {
		t.Errorf("team lead exported the complete audit trail: %d", r.StatusCode)
	}
	list := decode[struct {
		Total int `json:"total"`
	}](t, lead.do(t, "GET", "/api/requests", nil, nil).Body)
	if list.Total != 1 {
		t.Errorf("requests API returned %d requests to the grp-a lead", list.Total)
	}
}

func fmtJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestSealedValuesRejectedInInput(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	r := h.do(t, "POST", "/api/integrations/exports", map[string]any{"name": "x", "type": "webhook", "streams": []string{"audit"},
		"endpoint": "https://siem.example/hook", "secret": "enc:v1:deadbeef:AAAA"}, ui)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 400 || !strings.Contains(string(b), "encrypted values") {
		t.Fatalf("sealed input accepted: %d %s", r.StatusCode, b)
	}
}
