package api

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

var ui = map[string]string{"X-Requested-With": "aegis-ui"}

func decode[T any](t *testing.T, body io.Reader) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPolicySetAPIFlow(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	if r := h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI", "cidrs": []string{"10.1.0.0/16"}}, ui); r.StatusCode != 200 {
		t.Fatalf("group: %d", r.StatusCode)
	}
	resp := h.do(t, "POST", "/api/policy-sets", map[string]any{"spec": map[string]any{"name": "Dev", "enabled": true, "group_ids": []string{"grp-ci"},
		"rules": []map[string]any{{"name": "pypi", "action": "ALLOW", "host_pattern": "pypi.org", "path_pattern": "/**", "enabled": true, "access_request_id": "forged"}}}}, ui)
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	set := decode[models.PolicySet](t, resp.Body)
	if set.Draft == nil || set.Draft.Spec.Rules[0].AccessRequestID != "" {
		t.Fatalf("draft / forged bookkeeping: %+v", set.Draft)
	}
	diff := decode[models.PolicyDiff](t, h.do(t, "GET", "/api/policy-sets/"+set.ID+"/diff", nil, nil).Body)
	if diff.Added != 1 {
		t.Errorf("diff: %+v", diff)
	}
	if r := h.do(t, "POST", "/api/policy-sets/"+set.ID+"/simulate", nil, ui); r.StatusCode != 200 {
		t.Errorf("simulate: %d", r.StatusCode)
	}
	if r := h.do(t, "POST", "/api/policy-sets/"+set.ID+"/publish", map[string]any{"comment": "go"}, ui); r.StatusCode != 200 {
		t.Fatalf("publish: %d", r.StatusCode)
	}
	if r := h.do(t, "PUT", "/api/settings/governance", map[string]any{"require_policy_review": true, "request_sla_hours": 8, "default_review_interval_days": 90, "max_temporary_access_days": 30}, ui); r.StatusCode != 200 {
		t.Fatalf("governance: %d", r.StatusCode)
	}
	if r := h.do(t, "PUT", "/api/policy-sets/"+set.ID+"/draft", map[string]any{"spec": map[string]any{"name": "Dev", "enabled": true, "group_ids": []string{"grp-ci"}}}, ui); r.StatusCode != 200 {
		t.Fatalf("draft: %d", r.StatusCode)
	}
	if r := h.do(t, "POST", "/api/policy-sets/"+set.ID+"/publish", map[string]any{}, ui); r.StatusCode != 409 {
		t.Errorf("publish with review required: %d", r.StatusCode)
	}
	cr := decode[models.ChangeRequest](t, h.do(t, "POST", "/api/policy-sets/"+set.ID+"/submit", map[string]any{"title": "remove pypi"}, ui).Body)
	if cr.Status != "open" || cr.Diff == nil || cr.Diff.Removed != 1 || cr.Impact == nil {
		t.Fatalf("change request: %+v", cr)
	}
	if r := h.do(t, "POST", "/api/change-requests/"+cr.ID+"/review", map[string]any{"decision": "approve"}, ui); r.StatusCode != 400 {
		t.Errorf("self-approval: %d", r.StatusCode)
	}
	detail := decode[map[string]json.RawMessage](t, h.do(t, "GET", "/api/policy-sets/"+set.ID, nil, nil).Body)
	for _, k := range []string{"policy_set", "versions", "change_requests", "draft_diff"} {
		if _, ok := detail[k]; !ok {
			t.Errorf("set detail missing %s", k)
		}
	}
	state := decode[map[string]json.RawMessage](t, h.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body)
	var ov map[string]int
	_ = json.Unmarshal(state["overview"], &ov)
	if ov["open_change_requests"] != 1 {
		t.Errorf("overview: %+v", ov)
	}
	if r := h.do(t, "POST", "/api/rules", map[string]any{}, ui); r.StatusCode != 405 && r.StatusCode != 404 {
		t.Errorf("legacy rule CRUD still routed: %d", r.StatusCode)
	}
}

func TestFleetAPI(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI", "cidrs": []string{"10.1.0.0/16"}}, ui)
	csv := "id,hostname,ip,group_ids,labels,description\nsrv-a,a.example,10.1.0.7,grp-ci,env=prod;tier=web,\"=HYPERLINK(\"\"http://x\"\")\"\n"
	res := decode[map[string]any](t, h.do(t, "POST", "/api/servers/import", map[string]any{"csv": csv, "dry_run": true}, ui).Body)
	if res["error"] != nil {
		t.Fatalf("dry run: %+v", res)
	}
	if r := h.do(t, "POST", "/api/servers/import", map[string]any{"csv": csv}, ui); r.StatusCode != 200 {
		t.Fatalf("import: %d", r.StatusCode)
	}
	exp := h.do(t, "GET", "/api/servers/export", nil, nil)
	b, _ := io.ReadAll(exp.Body)
	if !strings.Contains(string(b), "env=prod;tier=web") || strings.Contains(string(b), ",=HYPERLINK") {
		t.Errorf("export: %s", b)
	}
	rot := decode[map[string]any](t, h.do(t, "POST", "/api/servers/srv-a/rotate-token", nil, ui).Body)
	ob, _ := rot["onboarding"].(map[string]any)
	if ob == nil || !strings.Contains(ob["linux"].(string), "install-linux.sh") || !strings.Contains(ob["windows"].(string), "netsh winhttp") {
		t.Errorf("onboarding snippets: %+v", rot)
	}
	if r := h.do(t, "POST", "/api/servers/srv-a/quarantine", map[string]any{"quarantined": true, "reason": "INC-1 beaconing"}, ui); r.StatusCode != 200 {
		t.Fatalf("quarantine: %d", r.StatusCode)
	}
	bundle := decode[map[string]json.RawMessage](t, h.do(t, "GET", "/api/dataplane/bundle", nil, map[string]string{"X-Aegis-DataPlane-Key": testDPKey}).Body)
	if !strings.Contains(string(bundle["servers"]), `"quarantined":true`) {
		t.Error("bundle does not carry the quarantine flag")
	}
	var bp struct {
		Default   string                    `json:"default_template_id"`
		Templates map[string]map[string]any `json:"templates"`
	}
	_ = json.Unmarshal(bundle["block_pages"], &bp)
	if bp.Default == "" || bp.Templates[bp.Default]["shells"] == nil {
		t.Errorf("bundle block pages: %+v", bp)
	}
	ep := decode[models.EffectivePolicy](t, h.do(t, "GET", "/api/servers/srv-a/effective-policy", nil, nil).Body)
	if !ep.Quarantined || ep.Server.Labels["tier"] != "web" {
		t.Errorf("effective policy: %+v", ep)
	}
}

func TestBlockPagePreviewAPI(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	tpl := map[string]any{"name": "Brand", "company_name": "ACME", "show_request_form": true, "allowed_scopes": []string{"exact_path"},
		"allowed_durations": []string{"1h"}, "title": "Hello {hostname}"}
	out := decode[map[string]string](t, h.do(t, "POST", "/api/block-pages/preview", map[string]any{"template": tpl, "locale": "de"}, ui).Body)
	if !strings.Contains(out["html"], "Hello build-agent-07") || !strings.Contains(out["html"], `lang="de"`) || out["cli"] == "" {
		t.Errorf("preview: %.200s", out["html"])
	}
	saved := decode[models.BlockPageTemplate](t, h.do(t, "POST", "/api/block-pages", tpl, ui).Body)
	r := h.do(t, "GET", "/api/block-pages/"+saved.ID+"/preview?variant=threat", nil, nil)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("rendered preview: %d %s", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}
}

// A simulated request with invalid proxy credentials shows the data-plane's answer: 407 with the
// credentials help, no self-service form and no block token.
func TestSimulateInvalidProxyTokenAnswers407(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	r := h.do(t, "POST", "/api/simulate/request", map[string]any{"server_ip": "10.9.8.7", "proxy_auth_user": "web-01:not-a-token",
		"method": "GET", "full_url": "https://pypi.org/simple/"}, map[string]string{"X-Requested-With": "aegis-ui"})
	if r.StatusCode != 200 {
		t.Fatalf("simulate: %d", r.StatusCode)
	}
	var out struct {
		Flow struct {
			Verdict    string `json:"verdict"`
			StatusCode int    `json:"status_code"`
		} `json:"flow"`
		CLIOutput string `json:"cli_output"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Flow.Verdict != models.VerdictAuthFailed || out.Flow.StatusCode != 407 {
		t.Errorf("flow: %+v", out.Flow)
	}
	if !strings.Contains(out.CLIOutput, "(HTTP 407)") || !strings.Contains(out.CLIOutput, "Proxy-Authorization") ||
		strings.Contains(out.CLIOutput, "/api/public/requests") || strings.Contains(out.CLIOutput, "bt=") {
		t.Errorf("cli output:\n%s", out.CLIOutput)
	}
}
