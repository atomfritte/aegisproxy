package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

func (h *harness) bearer(t *testing.T, method, path, key string, body any) *http.Response {
	t.Helper()
	saved := h.jar
	h.jar = nil
	defer func() { h.jar = saved }()
	return h.do(t, method, path, body, map[string]string{"Authorization": "Bearer " + key})
}

func TestServiceAccounts(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI"}, ui)
	if r := h.do(t, "POST", "/api/service-accounts", map[string]any{"name": "root-bot", "role": "SUPER_ADMIN"}, ui); r.StatusCode != 400 {
		t.Errorf("super admin service account: %d", r.StatusCode)
	}
	resp := h.do(t, "POST", "/api/service-accounts", map[string]any{"name": "sentinel-playbook", "role": "INFOSEC_APPROVER",
		"description": "SOAR quarantine", "expires_at": time.Now().Add(30 * 24 * time.Hour)}, ui)
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	created := decode[struct {
		SA  models.ServiceAccount `json:"service_account"`
		Key string                `json:"api_key"`
	}](t, resp.Body)
	if !strings.HasPrefix(created.Key, "aegis_sa_") || created.SA.KeyHash != "" || !strings.HasPrefix(created.Key, created.SA.KeyPrefix) {
		t.Fatalf("created: %+v", created.SA)
	}
	key := created.Key
	if r := h.bearer(t, "GET", "/api/policy-sets", key, nil); r.StatusCode != 200 {
		t.Fatalf("key auth: %d", r.StatusCode)
	}
	// No CSRF header needed for bearer keys; state-changing call works and is audited as the service account.
	set := decode[models.PolicySet](t, h.bearer(t, "POST", "/api/policy-sets", key, map[string]any{"spec": map[string]any{"name": "Bot set", "enabled": true,
		"group_ids": []string{"grp-ci"}, "rules": []map[string]any{{"name": "a", "action": "ALLOW", "host_pattern": "a.example", "enabled": true}}}}).Body)
	if set.CreatedBy != "sa:sentinel-playbook" {
		t.Errorf("actor: %q", set.CreatedBy)
	}
	// Service accounts cannot manage identities or log export, and cannot approve change requests.
	if r := h.bearer(t, "POST", "/api/service-accounts", key, map[string]any{"name": "x", "role": "OPERATOR_AUDITOR"}); r.StatusCode != 403 {
		t.Errorf("sa creating sa: %d", r.StatusCode)
	}
	if r := h.bearer(t, "POST", "/api/users", key, map[string]any{"username": "eve", "role": "SUPER_ADMIN"}); r.StatusCode == 200 || r.StatusCode == 201 {
		t.Errorf("sa creating users: %d", r.StatusCode)
	}
	cr := decode[models.ChangeRequest](t, h.do(t, "POST", "/api/policy-sets/"+set.ID+"/submit", map[string]any{"title": "x"}, ui).Body)
	if r := h.bearer(t, "POST", "/api/change-requests/"+cr.ID+"/review", key, map[string]any{"decision": "approve"}); r.StatusCode == 200 {
		t.Error("service account approved a change request")
	}
	if r := h.bearer(t, "GET", "/api/auth/me", key, nil); r.StatusCode != 200 {
		t.Errorf("me: %d", r.StatusCode)
	}
	// IP allowlist.
	upd := map[string]any{"name": "sentinel-playbook", "role": "INFOSEC_APPROVER", "allowed_cidrs": []string{"10.0.0.0/8"}, "expires_at": time.Now().Add(24 * time.Hour)}
	if r := h.do(t, "PUT", "/api/service-accounts/"+created.SA.ID, upd, ui); r.StatusCode != 200 {
		t.Fatalf("update: %d", r.StatusCode)
	}
	if r := h.bearer(t, "GET", "/api/policy-sets", key, nil); r.StatusCode != 401 {
		t.Errorf("key used outside allowed CIDRs: %d", r.StatusCode)
	}
	upd["allowed_cidrs"] = []string{"127.0.0.1"}
	h.do(t, "PUT", "/api/service-accounts/"+created.SA.ID, upd, ui)
	if r := h.bearer(t, "GET", "/api/policy-sets", key, nil); r.StatusCode != 200 {
		t.Errorf("key from allowed address: %d", r.StatusCode)
	}
	// Rotation revokes the old key.
	rot := decode[struct {
		Key string `json:"api_key"`
	}](t, h.do(t, "POST", "/api/service-accounts/"+created.SA.ID+"/rotate", nil, ui).Body)
	if r := h.bearer(t, "GET", "/api/policy-sets", key, nil); r.StatusCode != 401 {
		t.Errorf("old key after rotation: %d", r.StatusCode)
	}
	if r := h.bearer(t, "GET", "/api/policy-sets", rot.Key, nil); r.StatusCode != 200 {
		t.Errorf("new key: %d", r.StatusCode)
	}
	upd["disabled"] = true
	h.do(t, "PUT", "/api/service-accounts/"+created.SA.ID, upd, ui)
	if r := h.bearer(t, "GET", "/api/policy-sets", rot.Key, nil); r.StatusCode != 401 {
		t.Errorf("disabled account: %d", r.StatusCode)
	}
	if r := h.bearer(t, "GET", "/api/policy-sets", "aegis_sa_forged", nil); r.StatusCode != 401 {
		t.Errorf("forged key: %d", r.StatusCode)
	}
	if r := h.do(t, "DELETE", "/api/service-accounts/"+created.SA.ID, nil, ui); r.StatusCode != 200 {
		t.Errorf("delete: %d", r.StatusCode)
	}
}

func TestSecurityPosture(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	res := decode[struct {
		Score  int            `json:"score"`
		Checks []PostureCheck `json:"checks"`
	}](t, h.do(t, "GET", "/api/system/posture", nil, nil).Body)
	byID := map[string]PostureCheck{}
	for _, c := range res.Checks {
		byID[c.ID] = c
	}
	if byID["tls"].Status != "pass" || byID["sso"].Status != "warn" || byID["audit-chain"].Status != "pass" || byID["demo"].Status != "pass" {
		t.Errorf("checks: %+v", byID)
	}
	if res.Score <= 0 || res.Score >= 100 || len(res.Checks) < 20 {
		t.Errorf("score %d with %d checks", res.Score, len(res.Checks))
	}
}

// Enforcing DLP/AV with oversize "allow" lets padded content through unscanned: the posture warns (review round 2).
func TestPostureWarnsAboutOversizeAllowWithEnforcingInspection(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	posture := func() map[string]PostureCheck {
		res := decode[struct {
			Checks []PostureCheck `json:"checks"`
		}](t, h.do(t, "GET", "/api/system/posture", nil, nil).Body)
		byID := map[string]PostureCheck{}
		for _, c := range res.Checks {
			byID[c.ID] = c
		}
		return byID
	}
	set := func(change func(p *models.SecurityPolicy)) {
		p := h.st.GetSnapshot().SecurityPolicy
		change(&p)
		if r := h.do(t, "POST", "/api/security/policy", p, ui); r.StatusCode != 200 {
			t.Fatalf("update policy: %d", r.StatusCode)
		}
	}
	set(func(p *models.SecurityPolicy) {
		p.DLPMode, p.DLPOversizeAction = "block", "allow"
		p.AVEnabled, p.AVMode, p.AVOversizeAction = true, "block", "allow"
	})
	byID := posture()
	if c := byID["dlp-oversize"]; c.Status != "warn" || !strings.Contains(c.Remediation, "dlp_oversize_action") {
		t.Errorf("dlp-oversize: %+v", c)
	}
	if c := byID["scan-oversize"]; c.Status != "warn" {
		t.Errorf("scan-oversize: %+v", c)
	}
	set(func(p *models.SecurityPolicy) { p.DLPOversizeAction, p.AVOversizeAction = "block", "block" })
	byID = posture()
	if byID["dlp-oversize"].Status != "pass" || byID["scan-oversize"].Status != "pass" {
		t.Errorf("block: %+v %+v", byID["dlp-oversize"], byID["scan-oversize"])
	}
	set(func(p *models.SecurityPolicy) {
		p.DLPMode, p.DLPOversizeAction = "monitor", "allow"
		p.AVMode, p.AVOversizeAction = "monitor", "allow"
	})
	byID = posture()
	if _, ok := byID["dlp-oversize"]; ok || byID["scan-oversize"].Status != "info" {
		t.Errorf("monitor only: %+v %+v", byID["dlp-oversize"], byID["scan-oversize"])
	}
}

func TestPublicRequestOptions(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI", "cidrs": []string{"10.1.0.0/16"}}, ui)
	tpl := decode[models.BlockPageTemplate](t, h.do(t, "POST", "/api/block-pages", map[string]any{"name": "Strict", "show_request_form": true,
		"allowed_scopes": []string{"exact_path"}, "allowed_durations": []string{"1h"}}, ui).Body)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI", "cidrs": []string{"10.1.0.0/16"}, "block_page_template_id": tpl.ID}, ui)
	tok, _ := auth.SignBlockToken(testDPKey, auth.BlockClaims{ServerIP: "10.1.0.9", URL: "https://x.example/a", Method: "GET", TraceID: "t", Verdict: "BLOCKED"})
	h.jar = nil
	opts := decode[map[string]any](t, h.do(t, "GET", "/api/public/request-options?bt="+tok, nil, nil).Body)
	if opts["verified"] != true || opts["request_form"] != true || len(opts["allowed_scopes"].([]any)) != 1 || opts["allowed_durations"].([]any)[0] != "1h" {
		t.Errorf("options: %+v", opts)
	}
	threat, _ := auth.SignBlockToken(testDPKey, auth.BlockClaims{ServerIP: "10.1.0.9", URL: "https://evil/", Method: "GET", TraceID: "t", Verdict: "THREAT_BLOCKED"})
	if o := decode[map[string]any](t, h.do(t, "GET", "/api/public/request-options?bt="+threat, nil, nil).Body); o["request_form"] != false {
		t.Error("self-service offered for a threat block")
	}
	if r := h.do(t, "GET", "/api/public/request-options?bt=forged", nil, nil); r.StatusCode != 400 {
		t.Errorf("forged token: %d", r.StatusCode)
	}
}
