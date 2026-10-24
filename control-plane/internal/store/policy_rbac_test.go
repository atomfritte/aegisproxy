package store

import (
	"slices"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

// Regression tests for the round-2 policy / access-request RBAC review.

func requirePolicyReview(t *testing.T, st *Store) {
	t.Helper()
	gov := st.Governance()
	gov.RequirePolicyReview = true
	if _, err := st.UpdateGovernance(gov, adminClaims); err != nil {
		t.Fatal(err)
	}
}

func newRequest(t *testing.T, st *Store, ip, host, path, duration string, verified bool) models.AccessRequest {
	t.Helper()
	req, _, err := st.CreateAccessRequest(models.AccessRequest{ServerIP: ip, RequestedURL: "https://" + host + path, Host: host, Path: path,
		Method: "GET", Requester: "ops", Reason: "build needs it", Duration: duration, Verified: verified})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Clients cannot choose rule attribution: created_by/at, approved_by and the request/session links.
func TestRuleAttributionIsServerSide(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	forged := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "CI tools", Enabled: true, GroupIDs: []string{"grp-ci"},
		Rules: []models.PolicyRule{{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: "/**", Enabled: true,
			CreatedBy: "ciso", CreatedAt: forged, ApprovedBy: "ciso", AccessRequestID: "req-forged", SourceSessionID: "sess-forged"}}}, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	r := set.Draft.Spec.Rules[0]
	if r.CreatedBy != "tl" || r.ApprovedBy != "tl" || r.CreatedAt.Equal(forged) || r.AccessRequestID != "" || r.SourceSessionID != "" {
		t.Fatalf("create kept client attribution: %+v", r)
	}
	// Second save of the draft-only rule: the draft's values win over the client's.
	spec := cloneSpec(set.Draft.Spec)
	spec.Rules[0].CreatedBy, spec.Rules[0].ApprovedBy, spec.Rules[0].CreatedAt = "ciso", "ciso", forged
	spec.Rules[0].AccessRequestID, spec.Rules[0].SourceSessionID = "req-forged", "sess-forged"
	set, err = st.SaveDraft(set.ID, spec, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	if r2 := set.Draft.Spec.Rules[0]; r2.CreatedBy != "tl" || r2.ApprovedBy != "tl" || !r2.CreatedAt.Equal(r.CreatedAt) || r2.AccessRequestID != "" || r2.SourceSessionID != "" {
		t.Fatalf("second save kept client attribution: %+v", r2)
	}
	// Published rules keep their published attribution.
	set, err = st.PublishDraft(set.ID, "", false, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	spec = cloneSpec(set.PolicySetSpec)
	spec.Rules[0].CreatedBy, spec.Rules[0].AccessRequestID = "ciso", "req-forged"
	spec.Rules = append(spec.Rules, models.PolicyRule{Name: "npm", Action: "ALLOW", HostPattern: "registry.npmjs.org", PathPattern: "/**", Enabled: true,
		CreatedBy: "ciso", ApprovedBy: "ciso", CreatedAt: forged})
	set, err = st.SaveDraft(set.ID, spec, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	if p := set.Draft.Spec.Rules[0]; p.CreatedBy != "tl" || p.AccessRequestID != "" {
		t.Fatalf("published rule attribution overwritten: %+v", p)
	}
	if n := set.Draft.Spec.Rules[1]; n.CreatedBy != "tl" || n.ApprovedBy != "tl" || n.CreatedAt.Equal(forged) {
		t.Fatalf("new rule kept client attribution: %+v", n)
	}
	// Import uses the same rules.
	res, err := st.ImportPolicySets(models.PolicySetBundle{PolicySets: []models.PolicySetDocument{{Kind: models.PolicySetKindStandard,
		PolicySetSpec: models.PolicySetSpec{Name: "Imported", Enabled: true, GroupIDs: []string{"grp-ci"}, Rules: []models.PolicyRule{{Name: "x",
			Action: "ALLOW", HostPattern: "x.example", Enabled: true, CreatedBy: "ciso", ApprovedBy: "ciso", CreatedAt: forged, AccessRequestID: "req-forged"}}}}}}, false, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	imp, _ := st.PolicySet(res[0].ID)
	if x := imp.Draft.Spec.Rules[0]; x.CreatedBy != "tl" || x.ApprovedBy != "tl" || x.AccessRequestID != "" || x.CreatedAt.Equal(forged) {
		t.Fatalf("import kept client attribution: %+v", x)
	}
}

// Team Leads cannot act on requests of other groups; those requests do not exist for them.
func TestAccessRequestReviewNeedToKnow(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	vault := newRequest(t, st, "10.9.0.5", "vault-updates.example", "/v1/", "24h", true)
	unregistered := newRequest(t, st, "192.0.2.50", "anything.example", "/", "24h", false)
	for _, id := range []string{vault.ID, unregistered.ID, "req-unknown"} {
		if _, _, err := st.ReviewAccessRequest(id, ReviewOptions{Approve: false, Comment: "no"}, teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("reject %s: %v", id, err)
		}
		if _, _, err := st.ReviewAccessRequest(id, ReviewOptions{Approve: true, TargetGroupIDs: []string{"grp-ci"}, Duration: "1h"}, teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("approve %s into the own group: %v", id, err)
		}
		if _, err := st.CommentRequest(id, "hi", teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("comment %s: %v", id, err)
		}
		if _, err := st.AssignRequest(id, "", teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("assign %s: %v", id, err)
		}
		if _, err := st.RevokeAccessRequest(id, "x", teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("revoke %s: %v", id, err)
		}
		if _, err := st.ExtendAccessRequest(id, "1h", teamLeadCI); err == nil || err.Error() != "request not found" {
			t.Errorf("extend %s: %v", id, err)
		}
	}
	bulk, err := st.BulkReviewRequests([]string{vault.ID, "req-unknown"}, false, "no", teamLeadCI)
	if err != nil || bulk[0].Error != bulk[1].Error || bulk[0].Error != "request not found" {
		t.Errorf("bulk review distinguishes foreign from unknown requests: %+v %v", bulk, err)
	}
	if r := st.GetSnapshot().Requests; slices.IndexFunc(r, func(x models.AccessRequest) bool { return x.ID == vault.ID && x.Status == "pending" }) < 0 {
		t.Fatal("foreign request was changed")
	}

	// A Team Lead of both groups may retarget; the audit entry is visible to both teams.
	both := &auth.TokenClaims{UserID: "u-both", Username: "both", Role: models.RoleTeamLead, AllowedGroups: []string{"grp-ci", "grp-vault"}}
	if _, _, err := st.ReviewAccessRequest(vault.ID, ReviewOptions{Approve: true, TargetGroupIDs: []string{"grp-ci"}, Duration: "1h"}, both); err != nil {
		t.Fatal(err)
	}
	var ev models.AuditEvent
	for _, e := range st.GetSnapshot().AuditEvents {
		if e.Action == "REQUEST_APPROVED" && e.EntityID == vault.ID {
			ev = e
		}
	}
	if !slices.Contains(ev.ScopeGroups, "grp-ci") || !slices.Contains(ev.ScopeGroups, "grp-vault") {
		t.Fatalf("audit scope: %+v", ev.ScopeGroups)
	}
	// Unregistered sources have no group: only InfoSec decides.
	if _, _, err := st.ReviewAccessRequest(unregistered.ID, ReviewOptions{Approve: false, Comment: "unknown source"}, infosecClaims); err != nil {
		t.Fatal(err)
	}
}

// With four-eyes review required, a Team Lead's approval publishes only what an attested request
// asked for; everything else becomes a change request that someone else must approve.
func TestFourEyesForWidenedApprovals(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	requirePolicyReview(t, st)

	// Self-reported request approved as-is: change request instead of a published rule.
	unverified := newRequest(t, st, "10.1.0.5", "evil.example", "/payload", "24h", false)
	got, rules, err := st.ReviewAccessRequest(unverified.ID, ReviewOptions{Approve: true, Comment: "ok"}, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || len(got.ChangeRequestIDs) != 1 || len(rules) != 0 {
		t.Fatalf("unverified approval: %+v", got)
	}
	if res := evalCI(st, "evil.example", "/payload"); res.Allowed {
		t.Fatal("unreviewed approval enforced")
	}
	crID := got.ChangeRequestIDs[0]
	cr, _ := st.ChangeRequest(crID)
	if cr.AccessRequestID != unverified.ID || cr.SubmittedBy != "tl" || cr.Status != "open" || cr.PolicySetID != "approvals-grp-ci" {
		t.Fatalf("change request: %+v", cr)
	}
	if set, _ := st.PolicySet("approvals-grp-ci"); set.Draft != nil || len(set.Rules) != 0 {
		t.Fatalf("approvals set touched before review: %+v", set)
	}
	if _, _, err := st.ReviewAccessRequest(unverified.ID, ReviewOptions{Approve: true}, teamLeadCI2); err == nil || !strings.Contains(err.Error(), "four-eyes") {
		t.Fatalf("second approval while in review: %v", err)
	}
	if _, err := st.ReviewChangeRequest(crID, "approve", "", teamLeadCI); err == nil {
		t.Fatal("team lead approved their own approval")
	}

	// A direct approval moves the approvals set meanwhile: the change request is rebased, not superseded.
	plain := newRequest(t, st, "10.1.0.5", "pkgs.example.org", "/simple/", "24h", true)
	if got, rules, err := st.ReviewAccessRequest(plain.ID, ReviewOptions{Approve: true}, teamLeadCI); err != nil || got.Status != "approved" || len(rules) != 1 {
		t.Fatalf("attested approval as requested: %v %+v", err, got)
	}
	approved, err := st.ReviewChangeRequest(crID, "approve", "verified with the team", teamLeadCI2)
	if err != nil || approved.Status != "approved" {
		t.Fatalf("four-eyes approval: %v %+v", err, approved)
	}
	if res := evalCI(st, "evil.example", "/payload"); !res.Allowed {
		t.Fatalf("approved access not enforced: %+v", res)
	}
	if res := evalCI(st, "pkgs.example.org", "/simple/x"); !res.Allowed {
		t.Fatal("rebase dropped the other approval")
	}
	req := requestByID(t, st, unverified.ID)
	if req.Status != "approved" || req.ReviewedBy != "tl2" || len(req.CreatedRuleIDs) != 1 || req.ExpiresAt == nil || time.Until(*req.ExpiresAt) > 25*time.Hour {
		t.Fatalf("request after four-eyes approval: %+v", req)
	}

	// Overrides on an attested request: change request; rejecting it returns the request to the queue.
	widened := newRequest(t, st, "10.1.0.5", "github.com", "/acme/tool", "24h", true)
	for name, o := range map[string]ReviewOptions{
		"host":     {Approve: true, HostPattern: "objects.example.org"},
		"methods":  {Approve: true, Methods: []string{"GET", "POST", "PUT"}},
		"duration": {Approve: true, Duration: "30d"},
	} {
		got, _, err := st.ReviewAccessRequest(widened.ID, o, teamLeadCI)
		if err != nil || got.Status != "pending" || len(got.ChangeRequestIDs) != 1 {
			t.Fatalf("%s override: %v %+v", name, err, got)
		}
		if _, err := st.ReviewChangeRequest(got.ChangeRequestIDs[0], "reject", "too broad", infosecClaims); err != nil {
			t.Fatal(err)
		}
		if r := requestByID(t, st, widened.ID); r.Status != "pending" || len(r.ChangeRequestIDs) != 0 {
			t.Fatalf("%s: request after rejected change: %+v", name, r)
		}
	}
	// Rejecting the request withdraws an open change request.
	got, _, err = st.ReviewAccessRequest(widened.ID, ReviewOptions{Approve: true, PathPattern: "/**"}, teamLeadCI)
	if err != nil || len(got.ChangeRequestIDs) != 1 {
		t.Fatalf("path override: %v %+v", err, got)
	}
	if _, _, err := st.ReviewAccessRequest(widened.ID, ReviewOptions{Approve: false, Comment: "no"}, teamLeadCI); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.ChangeRequest(got.ChangeRequestIDs[0]); c.Status != "withdrawn" {
		t.Fatalf("change request of a rejected request: %s", c.Status)
	}
	// InfoSec approvals with overrides publish directly.
	byInfoSec := newRequest(t, st, "10.1.0.5", "github.com", "/acme/other", "24h", true)
	if got, _, err := st.ReviewAccessRequest(byInfoSec.ID, ReviewOptions{Approve: true, PathPattern: "/acme/**", Duration: "30d"}, infosecClaims); err != nil || got.Status != "approved" {
		t.Fatalf("infosec approval: %v %+v", err, got)
	}

	// Extensions by Team Leads share one budget counted from the original approval.
	if _, err := st.ExtendAccessRequest(plain.ID, "7d", teamLeadCI); err != nil {
		t.Fatalf("extension within the budget: %v", err)
	}
	if _, err := st.ExtendAccessRequest(plain.ID, "30d", teamLeadCI); err == nil || !strings.Contains(err.Error(), "original approval") {
		t.Fatalf("extension beyond the budget: %v", err)
	}
	if _, err := st.ExtendAccessRequest(plain.ID, "90d", infosecClaims); err != nil {
		t.Fatalf("infosec extension: %v", err)
	}
}

func requestByID(t *testing.T, st *Store, id string) models.AccessRequest {
	t.Helper()
	for _, r := range st.GetSnapshot().Requests {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("request %s not found", id)
	return models.AccessRequest{}
}

// Change-request decisions, comments included, need the rights to manage the set; out-of-scope
// change requests do not exist for Team Leads.
func TestChangeRequestDecisionsNeedScope(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	requirePolicyReview(t, st)
	vaultSet, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "Vault", Enabled: true, GroupIDs: []string{"grp-vault"},
		Rules: []models.PolicyRule{{Name: "hsm", Action: "ALLOW", HostPattern: "hsm.example", PathPattern: "/**", Enabled: true}}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := st.SubmitChangeRequest(vaultSet.ID, "", "", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"comment", "reject", "approve"} {
		if _, err := st.ReviewChangeRequest(cr.ID, d, "x", teamLeadCI); err == nil || err.Error() != "change request not found" {
			t.Errorf("%s by a foreign team lead: %v", d, err)
		}
	}
	if err := st.WithdrawChangeRequest(cr.ID, teamLeadCI); err == nil || err.Error() != "change request not found" {
		t.Errorf("withdraw by a foreign team lead: %v", err)
	}
	if _, err := st.ReviewChangeRequest(cr.ID, "comment", "x", auditorClaims); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("auditor comment: %v", err)
	}
	if _, err := st.ReviewChangeRequest(cr.ID, "comment", "looks fine", teamLeadVault); err != nil {
		t.Errorf("team lead of the set's group: %v", err)
	}
	// Baseline change requests are visible to every Team Lead, but only InfoSec may comment.
	base, err := st.CreatePolicySet(models.PolicySetKindBaseline, models.PolicySetSpec{Name: "Base", Enabled: true,
		Rules: []models.PolicyRule{{Name: "os", Action: "ALLOW", HostPattern: "archive.ubuntu.com", PathPattern: "/**", Enabled: true}}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	bcr, err := st.SubmitChangeRequest(base.ID, "", "", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReviewChangeRequest(bcr.ID, "comment", "x", teamLeadCI); err == nil || !strings.HasPrefix(err.Error(), "RBAC") {
		t.Errorf("team lead comment on a baseline change: %v", err)
	}
}

// The stored impact of a change request carries a per-group breakdown and attributed samples, so
// the API can narrow it to a Team Lead's groups.
func TestChangeRequestImpactIsAttributed(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	requirePolicyReview(t, st)
	st.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "ci-only.example", Path: "/", FullURL: "https://ci-only.example/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})
	st.RecordFlow(models.TrafficFlow{ServerIP: "10.9.0.5", Method: "GET", Host: "vault-only.example", Path: "/", FullURL: "https://vault-only.example/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"})
	base, err := st.CreatePolicySet(models.PolicySetKindBaseline, models.PolicySetSpec{Name: "Base", Enabled: true, Rules: []models.PolicyRule{
		{Name: "ci", Action: "ALLOW", HostPattern: "ci-only.example", PathPattern: "/**", Enabled: true},
		{Name: "vault", Action: "ALLOW", HostPattern: "vault-only.example", PathPattern: "/**", Enabled: true}}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := st.SubmitChangeRequest(base.ID, "", "", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	imp := cr.Impact
	if imp == nil || imp.NewlyAllowed != 2 || len(imp.Scopes) != 2 || len(imp.Samples) != 2 {
		t.Fatalf("impact: %+v", imp)
	}
	for _, sc := range imp.Scopes {
		if sc.NewlyAllowed != 1 || sc.AffectedServers != 1 || sc.TargetServers != 1 || len(sc.GroupIDs) != 1 {
			t.Errorf("scope: %+v", sc)
		}
	}
	for _, s := range imp.Samples {
		if s.ServerID == "" || len(s.GroupIDs) != 1 {
			t.Errorf("sample without attribution: %+v", s)
		}
	}
}

// Import planning treats sets outside the actor's view as nonexistent.
func TestImportIgnoresHiddenSets(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	hidden := publishSet(t, st, adminClaims, "Vault secrets", []string{"grp-vault"},
		models.PolicyRule{Name: "hsm", Action: "ALLOW", HostPattern: "hsm.example", PathPattern: "/**", Enabled: true})
	doc := func(id, name string) models.PolicySetDocument {
		return models.PolicySetDocument{ID: id, Kind: models.PolicySetKindStandard, PolicySetSpec: models.PolicySetSpec{Name: name, Enabled: true,
			GroupIDs: []string{"grp-ci"}, Rules: []models.PolicyRule{{Name: "a", Action: "ALLOW", HostPattern: "a.example", Enabled: true}}}}
	}
	res, err := st.ImportPolicySets(models.PolicySetBundle{PolicySets: []models.PolicySetDocument{doc(hidden.ID, "Renamed")}}, true, teamLeadCI)
	if err != nil || res[0].Action != "create" || res[0].ID != "" || res[0].Diff == nil || res[0].Diff.Removed != 0 {
		t.Fatalf("hidden set matched by id: %+v %v", res, err)
	}
	unknown, _ := st.ImportPolicySets(models.PolicySetBundle{PolicySets: []models.PolicySetDocument{doc("ps-unknown", "Renamed")}}, true, teamLeadCI)
	if unknown[0].Action != res[0].Action || unknown[0].ID != res[0].ID {
		t.Fatalf("hidden and unknown ids differ: %+v vs %+v", res[0], unknown[0])
	}
	res, _ = st.ImportPolicySets(models.PolicySetBundle{PolicySets: []models.PolicySetDocument{doc("", "vault SECRETS")}}, true, teamLeadCI)
	if res[0].Action != "error" || res[0].ID != "" || strings.Contains(res[0].Error, hidden.ID) || strings.Contains(res[0].Error, "grp-vault") {
		t.Fatalf("hidden set matched by name: %+v", res[0])
	}
}
