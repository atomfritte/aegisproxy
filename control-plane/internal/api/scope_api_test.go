package api

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// loginAs signs in a second browser session on the same server.
func (h *harness) loginAs(t *testing.T, username, password string) *harness {
	t.Helper()
	other := &harness{srv: h.srv, st: h.st, cfg: h.cfg, dir: h.dir}
	resp := other.do(t, "POST", "/api/auth/login", map[string]string{"username": username, "password": password}, ui)
	if resp.StatusCode != 200 {
		t.Fatalf("login %s: %d", username, resp.StatusCode)
	}
	other.jar = resp.Cookies()
	return other
}

func body(t *testing.T, r io.Reader) string {
	t.Helper()
	b, _ := io.ReadAll(r)
	return string(b)
}

// Team Leads read policy objects of their own groups only and never see proxy credential digests.
func TestTeamLeadPolicyScope(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	for _, g := range []string{"grp-a", "grp-b"} {
		h.do(t, "POST", "/api/groups", map[string]any{"id": g, "name": g}, ui)
	}
	hashes := map[string]string{}
	for _, srv := range []struct{ id, ip, group string }{{"srv-a", "10.0.0.1", "grp-a"}, {"srv-b", "10.0.0.2", "grp-b"}} {
		h.do(t, "POST", "/api/servers", map[string]any{"id": srv.id, "hostname": srv.id, "ip": srv.ip, "group_ids": []string{srv.group}}, ui)
		rot := decode[map[string]any](t, h.do(t, "POST", "/api/servers/"+srv.id+"/rotate-token", nil, ui).Body)
		tok, _ := rot["token"].(string)
		if tok == "" {
			t.Fatalf("rotate %s: %v", srv.id, rot)
		}
		hashes[srv.id] = engine.HashProxyToken(tok)
	}
	mkSet := func(name, kind, group, host string) models.PolicySet {
		spec := map[string]any{"name": name, "enabled": true,
			"rules": []map[string]any{{"name": host, "action": "ALLOW", "host_pattern": host, "path_pattern": "/**", "enabled": true}}}
		if group != "" {
			spec["group_ids"] = []string{group}
		}
		r := h.do(t, "POST", "/api/policy-sets", map[string]any{"kind": kind, "spec": spec}, ui)
		if r.StatusCode != 201 {
			t.Fatalf("create %s: %d %s", name, r.StatusCode, body(t, r.Body))
		}
		set := decode[models.PolicySet](t, r.Body)
		if r := h.do(t, "POST", "/api/policy-sets/"+set.ID+"/publish", map[string]any{"comment": "go"}, ui); r.StatusCode != 200 {
			t.Fatalf("publish %s: %d", name, r.StatusCode)
		}
		return set
	}
	setA := mkSet("A tools", "standard", "grp-a", "a-tools.example")
	setB := mkSet("B secrets", "standard", "grp-b", "b-secret.example")
	base := mkSet("Base", "baseline", "", "base.example")
	h.do(t, "PUT", "/api/policy-sets/"+setB.ID+"/draft", map[string]any{"spec": map[string]any{"name": "B secrets", "enabled": true, "group_ids": []string{"grp-b"},
		"rules": []map[string]any{{"name": "b2", "action": "ALLOW", "host_pattern": "b-secret-draft.example", "path_pattern": "/**", "enabled": true}}}}, ui)
	crB := decode[models.ChangeRequest](t, h.do(t, "POST", "/api/policy-sets/"+setB.ID+"/submit", map[string]any{"title": "b change"}, ui).Body)
	if crB.ID == "" {
		t.Fatal("change request not created")
	}
	for _, tb := range []map[string]any{
		{"pattern": "b-pinned.example", "category": "pinning", "reason": "b only", "group_ids": []string{"grp-b"}},
		{"pattern": "global-pinned.example", "category": "pinning", "reason": "all"},
	} {
		if r := h.do(t, "POST", "/api/tls-bypass", tb, ui); r.StatusCode >= 300 {
			t.Fatalf("tls bypass: %d %s", r.StatusCode, body(t, r.Body))
		}
	}
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.2", Method: "GET", Host: "b-flow.example", Path: "/secret", FullURL: "https://b-flow.example/secret?k=1", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.1", Method: "GET", Host: "a-flow.example", Path: "/", FullURL: "https://a-flow.example/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})

	// Admin view: effective policy without the proxy credential digest.
	if s := body(t, h.do(t, "GET", "/api/servers/srv-a/effective-policy", nil, nil).Body); strings.Contains(s, hashes["srv-a"]) || strings.Contains(s, "proxy_auth_token_hash") {
		t.Errorf("effective policy exposes the proxy token digest: %s", s)
	}

	in := storeUserInput("lead-a", models.RoleTeamLead)
	in.AllowedGroups = []string{"grp-a"}
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	lead := h.loginAs(t, "lead-a", "Ops-Password-123!")

	if r := lead.do(t, "GET", "/api/servers/srv-b/effective-policy", nil, nil); r.StatusCode != 404 {
		t.Errorf("foreign effective policy: %d", r.StatusCode)
	}
	r := lead.do(t, "GET", "/api/servers/srv-a/effective-policy", nil, nil)
	if s := body(t, r.Body); r.StatusCode != 200 || strings.Contains(s, hashes["srv-a"]) || !strings.Contains(s, "a-tools.example") {
		t.Errorf("own effective policy: %d %s", r.StatusCode, s)
	}

	for _, path := range []string{"/api/policy-sets/" + setB.ID, "/api/policy-sets/" + setB.ID + "/diff", "/api/policy-sets/" + setB.ID + "/versions",
		"/api/policy-sets/" + setB.ID + "/versions/1", "/api/change-requests/" + crB.ID} {
		if r := lead.do(t, "GET", path, nil, nil); r.StatusCode != 404 {
			t.Errorf("GET %s by foreign Team Lead: %d", path, r.StatusCode)
		}
	}
	for _, path := range []string{"/api/policy-sets/" + setA.ID, "/api/policy-sets/" + base.ID, "/api/policy-sets/" + setA.ID + "/versions/1"} {
		if r := lead.do(t, "GET", path, nil, nil); r.StatusCode != 200 {
			t.Errorf("GET %s by own Team Lead: %d", path, r.StatusCode)
		}
	}
	for _, path := range []string{"/api/policy-sets", "/api/rules", "/api/change-requests", "/api/policy-sets/export", "/api/policy-sets/export?id=" + setB.ID, "/api/state"} {
		s := body(t, lead.do(t, "GET", path, nil, nil).Body)
		for _, leak := range []string{"b-secret", setB.ID, crB.ID, "b-pinned.example", hashes["srv-b"], hashes["srv-a"]} {
			if strings.Contains(s, leak) {
				t.Errorf("GET %s leaks %q to the grp-a Team Lead", path, leak)
			}
		}
	}
	sets := decode[[]models.PolicySet](t, lead.do(t, "GET", "/api/policy-sets", nil, nil).Body)
	if len(sets) != 2 {
		t.Errorf("visible sets: %d (want own + baseline)", len(sets))
	}

	state := decode[map[string]json.RawMessage](t, lead.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body)
	if !strings.Contains(string(state["tls_bypass"]), "global-pinned.example") || !strings.Contains(string(state["rules"]), "a-tools.example") {
		t.Errorf("own/global policy objects missing from state: %s %s", state["tls_bypass"], state["rules"])
	}

	// Simulation: only sets the Team Lead could change, only their traffic.
	foreign := map[string]any{"spec": map[string]any{"name": "x", "enabled": true, "group_ids": []string{"grp-b"},
		"rules": []map[string]any{{"name": "all", "action": "BLOCK", "host_pattern": "*", "path_pattern": "/**", "enabled": true}}}}
	for _, path := range []string{"/api/policy-sets/nonexistent/simulate", "/api/policy-sets/" + setB.ID + "/simulate"} {
		r := lead.do(t, "POST", path, foreign, ui)
		if s := body(t, r.Body); r.StatusCode == 200 || strings.Contains(s, "b-flow.example") {
			t.Errorf("POST %s with a foreign scope: %d %s", path, r.StatusCode, s)
		}
	}
	if r := lead.do(t, "POST", "/api/policy-sets/"+setB.ID+"/simulate", nil, ui); r.StatusCode == 200 {
		t.Errorf("simulate foreign set: %d", r.StatusCode)
	}
	own := map[string]any{"spec": map[string]any{"name": "A tools", "enabled": true, "group_ids": []string{"grp-a"},
		"rules": []map[string]any{{"name": "all", "action": "ALLOW", "host_pattern": "*", "path_pattern": "/**", "enabled": true}}}}
	r = lead.do(t, "POST", "/api/policy-sets/"+setA.ID+"/simulate", own, ui)
	if s := body(t, r.Body); r.StatusCode != 200 || strings.Contains(s, "b-flow.example") || !strings.Contains(s, "a-flow.example") {
		t.Errorf("simulate own set: %d %s", r.StatusCode, s)
	}
}

// The notification log belongs to the webhook integrations: only InfoSec and Super Admins read it.
func TestNotificationLogsOnlyForSystemManagers(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-a", "name": "A", "cidrs": []string{"10.0.0.0/24"}}, ui)
	if _, _, err := h.st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.0.0.1", RequestedURL: "https://x.example/", Host: "x.example", Path: "/",
		Requester: "dev", Reason: "r", Duration: "7d"}); err != nil {
		t.Fatal(err)
	}
	logsOf := func(c *harness) []models.NotificationLog {
		return decode[struct {
			Logs []models.NotificationLog `json:"notification_logs"`
		}](t, c.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body).Logs
	}
	for deadline := time.Now().Add(5 * time.Second); len(logsOf(h)) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("no notification recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, role := range []models.Role{models.RoleAuditorOperator, models.RoleTeamLead} {
		in := storeUserInput("u-"+strings.ToLower(string(role)), role)
		in.AllowedGroups = []string{"grp-a"}
		if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h)); err != nil {
			t.Fatal(err)
		}
		if logs := logsOf(h.loginAs(t, in.Username, in.Password)); len(logs) != 0 {
			t.Errorf("%s reads the notification log: %+v", role, logs)
		}
	}
}
