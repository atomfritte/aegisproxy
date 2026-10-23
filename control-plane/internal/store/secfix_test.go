package store

import (
	"strings"
	"testing"

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
	// A Team Lead of another group names their own group as target: refused (server is outside their scope).
	if _, _, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true, TargetGroupIDs: []string{"grp-ci"}}, teamLeadCI); err == nil || !strings.Contains(err.Error(), "RBAC") {
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
