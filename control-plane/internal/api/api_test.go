package api

import (
	"bytes"
	"encoding/json"
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
	"aegisproxy/control-plane/internal/store"
	"aegisproxy/control-plane/internal/threatintel"
)

const testDPKey = "test-dataplane-key-0123456789abcdef0123456789"

type harness struct {
	srv     *httptest.Server
	st      *store.Store
	adminPW string
	cfg     *config.Config
	jar     []*http.Cookie
	dir     string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
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
	return h
}

func (h *harness) do(t *testing.T, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range h.jar {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *harness) login(t *testing.T) {
	t.Helper()
	resp := h.do(t, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": h.adminPW}, map[string]string{"X-Requested-With": "aegis-ui"})
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if _, leaked := body["token"]; leaked {
		t.Error("browser login response must not expose the session token")
	}
	h.jar = resp.Cookies()
	found := false
	for _, c := range h.jar {
		if c.Name == sessionCookie {
			found = c.HttpOnly && c.SameSite == http.SameSiteStrictMode
		}
	}
	if !found {
		t.Fatal("session cookie missing or not HttpOnly+SameSite=Strict")
	}
}

func TestSessionCookieAndCSRF(t *testing.T) {
	h := newHarness(t)
	if resp := h.do(t, "GET", "/api/state", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("unauthenticated state: %d", resp.StatusCode)
	}
	h.login(t)
	resp := h.do(t, "GET", "/api/state", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("state with cookie: %d", resp.StatusCode)
	}
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "X-Request-ID"} {
		if resp.Header.Get(hdr) == "" {
			t.Errorf("missing security header %s", hdr)
		}
	}
	rule := map[string]any{"kind": "baseline", "spec": map[string]any{"name": "x", "enabled": true,
		"rules": []map[string]any{{"name": "x", "action": "ALLOW", "host_pattern": "example.org", "enabled": true}}}}
	if resp := h.do(t, "POST", "/api/policy-sets", rule, nil); resp.StatusCode != 403 {
		t.Errorf("cookie POST without X-Requested-With must be rejected (CSRF), got %d", resp.StatusCode)
	}
	if resp := h.do(t, "POST", "/api/policy-sets", rule, map[string]string{"X-Requested-With": "aegis-ui", "Origin": "https://evil.example"}); resp.StatusCode != 403 {
		t.Errorf("cross-origin cookie POST must be rejected, got %d", resp.StatusCode)
	}
	if resp := h.do(t, "POST", "/api/policy-sets", rule, map[string]string{"X-Requested-With": "aegis-ui"}); resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("legit cookie POST failed: %d %s", resp.StatusCode, b)
	}
	// Logout revokes the token server-side.
	old := h.jar
	h.do(t, "POST", "/api/auth/logout", nil, map[string]string{"X-Requested-With": "aegis-ui"})
	h.jar = old
	if resp := h.do(t, "GET", "/api/state", nil, nil); resp.StatusCode != 401 {
		t.Errorf("revoked session still accepted: %d", resp.StatusCode)
	}
}

func TestLoginThrottling(t *testing.T) {
	h := newHarness(t)
	var last int
	for i := 0; i < 6; i++ {
		last = h.do(t, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password"}, nil).StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
}

func TestDataPlaneAuthAndBundle(t *testing.T) {
	h := newHarness(t)
	if resp := h.do(t, "GET", "/api/dataplane/bundle", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("bundle without key: %d", resp.StatusCode)
	}
	if resp := h.do(t, "GET", "/api/dataplane/bundle", nil, map[string]string{"X-Aegis-DataPlane-Key": "aegis-dp-internal-key-2026-v1"}); resp.StatusCode != 401 {
		t.Fatalf("legacy default key accepted: %d", resp.StatusCode)
	}
	resp := h.do(t, "GET", "/api/dataplane/bundle", nil, map[string]string{"X-Aegis-DataPlane-Key": testDPKey, "X-Aegis-DataPlane-ID": "dp-test"})
	if resp.StatusCode != 200 {
		t.Fatalf("bundle with key: %d", resp.StatusCode)
	}
	var bundle map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&bundle)
	for _, k := range []string{"rules", "security_policy", "threat_intel_version", "servers", "groups"} {
		if _, ok := bundle[k]; !ok {
			t.Errorf("bundle missing %q", k)
		}
	}
	etag := resp.Header.Get("ETag")
	if r2 := h.do(t, "GET", "/api/dataplane/bundle", nil, map[string]string{"X-Aegis-DataPlane-Key": testDPKey, "X-Aegis-DataPlane-ID": "dp-test", "If-None-Match": etag}); r2.StatusCode != 304 {
		t.Errorf("ETag revalidation: %d", r2.StatusCode)
	}
	ti := h.do(t, "GET", "/api/dataplane/threatintel", nil, map[string]string{"X-Aegis-DataPlane-Key": testDPKey, "X-Aegis-DataPlane-ID": "dp-test"})
	if ti.StatusCode != 200 {
		t.Errorf("threatintel export: %d", ti.StatusCode)
	}
	if dps := h.srvDataPlanes(t); len(dps) != 1 || dps[0].ID != "dp-test" || !dps[0].Healthy {
		t.Errorf("data-plane heartbeat not recorded: %+v", dps)
	}
}

func (h *harness) srvDataPlanes(t *testing.T) []DataPlaneStatus {
	h.login(t)
	resp := h.do(t, "GET", "/api/state?exclude_flows=1", nil, nil)
	var st struct {
		DataPlanes []DataPlaneStatus `json:"data_planes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	return st.DataPlanes
}

func TestPublicRequestAttestation(t *testing.T) {
	h := newHarness(t)
	// Without a block token, the server identity comes from the TCP peer, not the JSON body.
	resp := h.do(t, "POST", "/api/public/requests", map[string]string{
		"server_ip": "10.99.99.99", "requested_url": "https://example.org/x", "requester": "mallory", "reason": "please", "duration": "24h",
	}, nil)
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("public request: %d %s", resp.StatusCode, b)
	}
	reqs := h.st.GetSnapshot().Requests
	if reqs[0].ServerIP == "10.99.99.99" || reqs[0].Verified {
		t.Errorf("spoofed server_ip trusted: %+v", reqs[0])
	}
	// With a valid block token the attested identity is used.
	tok, _ := auth.SignBlockToken(testDPKey, auth.BlockClaims{ServerIP: "10.1.2.3", URL: "https://pkgs.example.org/a", Method: "GET", TraceID: "flw-x"})
	resp = h.do(t, "POST", "/api/public/requests", map[string]string{"block_token": tok, "requester": "ops", "reason": "release", "duration": "1h"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("token request: %d", resp.StatusCode)
	}
	reqs = h.st.GetSnapshot().Requests
	if reqs[0].ServerIP != "10.1.2.3" || !reqs[0].Verified || reqs[0].Host != "pkgs.example.org" {
		t.Errorf("attested request: %+v", reqs[0])
	}
	if resp := h.do(t, "POST", "/api/public/requests", map[string]string{"block_token": tok + "x", "requester": "a", "reason": "b", "duration": "1h"}, nil); resp.StatusCode != 400 {
		t.Errorf("forged token accepted: %d", resp.StatusCode)
	}
}

func TestInstallScriptsPinFingerprint(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/api/public/ca/install-linux.sh", "/api/public/ca/install-windows.ps1"} {
		resp := h.do(t, "GET", p, nil, map[string]string{"Host": "evil.example"})
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(string(b), "https://aegis.example/api/public/ca/") || strings.Contains(string(b), "evil.example") {
			t.Errorf("%s: status %d or host header injection", p, resp.StatusCode)
		}
		if strings.Contains(p, "windows") && !strings.Contains(string(b), "`n") {
			t.Error("PowerShell newline escapes missing")
		}
	}
	_ = os.Getenv
}
