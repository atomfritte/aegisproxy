package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// twoTeams sets up grp-a/srv-a (10.0.0.1) and grp-b/srv-b (10.0.0.2) with recorded traffic and
// returns the admin harness plus a signed-in Team Lead of grp-a.
func twoTeams(t *testing.T) (*harness, *harness) {
	t.Helper()
	h := newHarness(t)
	h.login(t)
	for _, g := range []string{"grp-a", "grp-b"} {
		h.do(t, "POST", "/api/groups", map[string]any{"id": g, "name": g}, ui)
	}
	for _, srv := range []struct{ id, ip, group string }{{"srv-a", "10.0.0.1", "grp-a"}, {"srv-b", "10.0.0.2", "grp-b"}} {
		if r := h.do(t, "POST", "/api/servers", map[string]any{"id": srv.id, "hostname": srv.id + ".corp.example", "ip": srv.ip, "group_ids": []string{srv.group}}, ui); r.StatusCode >= 300 {
			t.Fatalf("server %s: %d", srv.id, r.StatusCode)
		}
	}
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.2", Method: "GET", Host: "b-flow.example", Path: "/secret", FullURL: "https://b-flow.example/secret", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.1", Method: "GET", Host: "a-flow.example", Path: "/", FullURL: "https://a-flow.example/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})
	in := storeUserInput("lead-a", models.RoleTeamLead)
	in.AllowedGroups = []string{"grp-a"}
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	return h, h.loginAs(t, "lead-a", "Ops-Password-123!")
}

func createSet(t *testing.T, h *harness, kind string, spec map[string]any) models.PolicySet {
	t.Helper()
	r := h.do(t, "POST", "/api/policy-sets", map[string]any{"kind": kind, "spec": spec}, ui)
	if r.StatusCode != 201 {
		t.Fatalf("create set: %d %s", r.StatusCode, body(t, r.Body))
	}
	return decode[models.PolicySet](t, r.Body)
}

// Out-of-scope objects answer exactly like unknown ones (no 403 oracle, no data).
func TestTeamLeadForeignObjectsAre404(t *testing.T) {
	h, lead := twoTeams(t)
	setB := createSet(t, h, "standard", map[string]any{"name": "B secrets", "enabled": true, "group_ids": []string{"grp-b"},
		"rules": []map[string]any{{"name": "b", "action": "ALLOW", "host_pattern": "b-secret.example", "path_pattern": "/**", "enabled": true}}})
	crB := decode[models.ChangeRequest](t, h.do(t, "POST", "/api/policy-sets/"+setB.ID+"/submit", map[string]any{"title": "b"}, ui).Body)
	if crB.ID == "" {
		t.Fatal("change request not created")
	}
	draft := map[string]any{"spec": map[string]any{"name": "B secrets", "enabled": true, "group_ids": []string{"grp-a"}}}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/simulate", nil}, {"PUT", "/draft", draft}, {"DELETE", "/draft", nil}, {"POST", "/publish", map[string]any{}},
		{"POST", "/submit", map[string]any{}}, {"POST", "/rollback", map[string]any{"version": 1}}, {"POST", "/recertify", map[string]any{}}, {"DELETE", "", nil},
	} {
		for _, id := range []string{setB.ID, "ps-unknown"} {
			if r := lead.do(t, c.method, "/api/policy-sets/"+id+c.path, c.body, ui); r.StatusCode != 404 {
				t.Errorf("%s %s%s by a foreign Team Lead: %d", c.method, id, c.path, r.StatusCode)
			}
		}
	}
	for _, id := range []string{crB.ID, "cr-unknown"} {
		if r := lead.do(t, "POST", "/api/change-requests/"+id+"/review", map[string]any{"decision": "comment", "comment": "peek"}, ui); r.StatusCode != 404 {
			t.Errorf("comment on %s: %d", id, r.StatusCode)
		}
		if r := lead.do(t, "POST", "/api/change-requests/"+id+"/withdraw", nil, ui); r.StatusCode != 404 {
			t.Errorf("withdraw %s: %d", id, r.StatusCode)
		}
	}
	for _, id := range []string{"srv-b", "srv-unknown"} {
		if r := lead.do(t, "POST", "/api/servers/"+id+"/quarantine", map[string]any{"quarantined": true, "reason": "test"}, ui); r.StatusCode != 404 {
			t.Errorf("quarantine %s: %d", id, r.StatusCode)
		}
	}
	for _, ident := range []map[string]any{{"hostname": "srv-b.corp.example"}, {"ip": "10.0.0.2"}, {"hostname": "nope.corp.example"}} {
		ident["reason"] = "test"
		if r := lead.do(t, "POST", "/api/servers/quarantine", ident, ui); r.StatusCode != 404 {
			t.Errorf("quarantine by identity %v: %d", ident, r.StatusCode)
		}
	}
	// Policy simulator: own servers only, same answer for foreign and unknown addresses.
	for ip, want := range map[string]int{"10.0.0.1": 200, "10.0.0.2": 404, "192.0.2.9": 404} {
		r := lead.do(t, "POST", "/api/simulate/request", map[string]any{"server_ip": ip, "full_url": "https://x.example/"}, ui)
		if s := body(t, r.Body); r.StatusCode != want || (want == 404 && (strings.Contains(s, "srv-b") || strings.Contains(s, "grp-b"))) {
			t.Errorf("simulate %s: %d %s", ip, r.StatusCode, s)
		}
	}
	// Access requests of other groups: 404 without data; bulk review cannot tell them apart.
	req, _, err := h.st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.0.0.2", RequestedURL: "https://b-only.example/x", Host: "b-only.example",
		Path: "/x", Method: "GET", Requester: "b-operator", Reason: "secret project", Duration: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	for path, payload := range map[string]any{
		"/review":   map[string]any{"approve": false, "comment": "no"},
		"/comments": map[string]string{"text": "x"},
		"/assign":   map[string]string{"assignee": ""},
		"/revoke":   map[string]string{"reason": "x"},
		"/extend":   map[string]string{"duration": "1h"},
	} {
		r := lead.do(t, "POST", "/api/requests/"+req.ID+path, payload, ui)
		if s := body(t, r.Body); r.StatusCode != 404 || strings.Contains(s, "b-operator") || strings.Contains(s, "b-only") {
			t.Errorf("POST %s on a foreign request: %d %s", path, r.StatusCode, s)
		}
	}
	bulk := decode[struct {
		Results []struct{ ID, Status, Error string } `json:"results"`
	}](t, lead.do(t, "POST", "/api/requests/bulk-review", map[string]any{"ids": []string{req.ID, "req-unknown"}, "approve": false, "comment": "no"}, ui).Body)
	if len(bulk.Results) != 2 || bulk.Results[0].Error == "" || bulk.Results[0].Error != bulk.Results[1].Error {
		t.Errorf("bulk review oracle: %+v", bulk.Results)
	}
	if got := decode[models.AccessRequest](t, h.do(t, "GET", "/api/requests/"+req.ID, nil, nil).Body); got.Status != "pending" {
		t.Errorf("foreign request changed: %s", got.Status)
	}
}

// Change-request impact is narrowed to the Team Lead's groups wherever it is served.
func TestChangeRequestImpactScopedForTeamLeads(t *testing.T) {
	h, lead := twoTeams(t)
	base := createSet(t, h, "baseline", map[string]any{"name": "Base", "enabled": true, "rules": []map[string]any{
		{"name": "a", "action": "ALLOW", "host_pattern": "a-flow.example", "path_pattern": "/**", "enabled": true},
		{"name": "b", "action": "ALLOW", "host_pattern": "b-flow.example", "path_pattern": "/**", "enabled": true}}})
	r := lead.do(t, "POST", "/api/policy-sets/"+base.ID+"/submit", map[string]any{}, ui)
	if r.StatusCode != 403 {
		t.Fatalf("team lead submitted a baseline change: %d", r.StatusCode)
	}
	cr := decode[models.ChangeRequest](t, h.do(t, "POST", "/api/policy-sets/"+base.ID+"/submit", map[string]any{"title": "base"}, ui).Body)
	if cr.Impact == nil || cr.Impact.NewlyAllowed != 2 || strings.Contains(body(t, h.do(t, "GET", "/api/change-requests/"+cr.ID, nil, nil).Body), `"scopes"`) {
		t.Fatalf("admin impact: %+v", cr.Impact)
	}
	got := decode[models.ChangeRequest](t, lead.do(t, "GET", "/api/change-requests/"+cr.ID, nil, nil).Body)
	if got.Impact == nil || got.Impact.NewlyAllowed != 1 || got.Impact.FlowsEvaluated != 1 || got.Impact.TargetServers != 1 || len(got.Impact.Samples) != 1 ||
		!strings.Contains(got.Impact.Samples[0].URL, "a-flow.example") {
		t.Fatalf("team lead impact: %+v", got.Impact)
	}
	for _, path := range []string{"/api/change-requests", "/api/change-requests/" + cr.ID, "/api/policy-sets/" + base.ID, "/api/state?exclude_flows=1"} {
		s := body(t, lead.do(t, "GET", path, nil, nil).Body)
		if strings.HasPrefix(path, "/api/state") {
			var st map[string]json.RawMessage
			_ = json.Unmarshal([]byte(s), &st)
			s = string(st["change_requests"]) // the state lists all group names and the SSO scopes
		}
		if !strings.Contains(s, cr.ID) {
			t.Errorf("GET %s misses the change request", path)
		}
		for _, leak := range []string{"b-flow.example/secret", "srv-b", "grp-b", `"scopes"`} {
			if strings.Contains(s, leak) {
				t.Errorf("GET %s leaks %q", path, leak)
			}
		}
	}
	var state map[string]json.RawMessage
	_ = json.Unmarshal([]byte(body(t, h.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body)), &state)
	if !strings.Contains(string(state["change_requests"]), "b-flow.example/secret") || strings.Contains(string(state["change_requests"]), `"scopes"`) {
		t.Errorf("admin state change requests: %s", state["change_requests"])
	}
}

// An open flow stream follows role and group changes of a service account.
func TestFlowStreamFollowsScopeChanges(t *testing.T) {
	old := flowStreamRecheck
	flowStreamRecheck = 50 * time.Millisecond
	t.Cleanup(func() { flowStreamRecheck = old })
	h, _ := twoTeams(t)
	expires := time.Now().Add(24 * time.Hour)
	created := decode[struct {
		SA  models.ServiceAccount `json:"service_account"`
		Key string                `json:"api_key"`
	}](t, h.do(t, "POST", "/api/service-accounts", map[string]any{"name": "siem-tap", "role": "INFOSEC_APPROVER", "expires_at": expires}, ui).Body)
	if created.Key == "" {
		t.Fatal("service account not created")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.srv.URL+"/api/flows/stream", nil)
	req.Header.Set("Authorization", "Bearer "+created.Key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()
	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	until := func(want string) []string {
		t.Helper()
		var seen []string
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("stream closed before %q (saw %v)", want, seen)
				}
				seen = append(seen, l)
				if strings.Contains(l, want) {
					return seen
				}
			case <-ctx.Done():
				t.Fatalf("timeout waiting for %q (saw %v)", want, seen)
			}
		}
	}
	until("connected")
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.2", Method: "GET", Host: "before-b.example", Path: "/", FullURL: "https://before-b.example/", Verdict: models.VerdictAllowed})
	until("before-b.example")

	if r := h.do(t, "PUT", "/api/service-accounts/"+created.SA.ID, map[string]any{"name": "siem-tap", "role": "TEAM_LEAD_APPROVER",
		"allowed_groups": []string{"grp-a"}, "expires_at": expires}, ui); r.StatusCode != 200 {
		t.Fatalf("narrow service account: %d %s", r.StatusCode, body(t, r.Body))
	}
	time.Sleep(10 * flowStreamRecheck) // several re-checks
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.2", Method: "GET", Host: "after-b.example", Path: "/", FullURL: "https://after-b.example/", Verdict: models.VerdictAllowed})
	h.st.RecordFlow(models.TrafficFlow{ServerIP: "10.0.0.1", Method: "GET", Host: "after-a.example", Path: "/", FullURL: "https://after-a.example/", Verdict: models.VerdictAllowed})
	for _, l := range until("after-a.example") {
		if strings.Contains(l, "after-b.example") {
			t.Fatal("narrowed service account still receives other groups' flows")
		}
	}
}
