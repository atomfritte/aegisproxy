package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

var (
	infosecClaims = &auth.TokenClaims{UserID: "u-is", Username: "infosec", Role: models.RoleInfoSecApprover, AllowedGroups: []string{"*"}}
	teamLeadCI    = &auth.TokenClaims{UserID: "u-tl", Username: "tl", Role: models.RoleTeamLead, AllowedGroups: []string{"grp-ci"}}
	auditorClaims = &auth.TokenClaims{UserID: "u-au", Username: "auditor", Role: models.RoleAuditorOperator}
)

func evalCI(st *Store, host, path string) engine.EvaluationResult {
	return st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Scheme: "https", Host: host, Path: path, Port: 443})
}

func TestPolicySetFourEyesLifecycle(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	gov := st.Governance()
	gov.RequirePolicyReview = true
	if _, err := st.UpdateGovernance(gov, adminClaims); err != nil {
		t.Fatal(err)
	}
	set, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "Dev tools", Enabled: true, GroupIDs: []string{"grp-ci"}, ReviewIntervalDays: 90,
		Rules: []models.PolicyRule{{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: "/simple/**", Enabled: true}}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "pypi.org", "/simple/x/"); res.Allowed {
		t.Fatal("draft rules must not be enforced")
	}
	if _, err := st.PublishDraft(set.ID, "", false, adminClaims); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("direct publish with review required: %v", err)
	}
	if _, err := st.PublishDraft(set.ID, "too short", true, infosecClaims); err == nil {
		t.Fatal("emergency publish by non-super-admin accepted")
	}
	cr, err := st.SubmitChangeRequest(set.ID, "", "initial", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Diff == nil || cr.Diff.Added != 1 {
		t.Fatalf("diff: %+v", cr.Diff)
	}
	if _, err := st.SaveDraft(set.ID, models.PolicySetSpec{Name: "Dev tools"}, adminClaims); !errors.Is(err, ErrDraftLocked) {
		t.Fatalf("editing a draft in review: %v", err)
	}
	if _, err := st.ReviewChangeRequest(cr.ID, "approve", "lgtm", adminClaims); err == nil {
		t.Fatal("author approved own change request")
	}
	if _, err := st.ReviewChangeRequest(cr.ID, "comment", "please double-check the path", auditorClaims); err != nil {
		t.Fatalf("auditor comment: %v", err)
	}
	if _, err := st.ReviewChangeRequest(cr.ID, "approve", "lgtm", auditorClaims); err == nil {
		t.Fatal("auditor approved a change request")
	}
	if got, err := st.ReviewChangeRequest(cr.ID, "approve", "lgtm", infosecClaims); err != nil || got.Status != "approved" || got.PublishedVer != 1 {
		t.Fatalf("approve: %v %+v", err, got)
	}
	if res := evalCI(st, "pypi.org", "/simple/x/"); !res.Allowed {
		t.Fatalf("approved change not enforced: %+v", res)
	}
	set, _ = st.PolicySet(set.ID)
	if set.Version != 1 || set.Draft != nil || set.ReviewState != "ok" {
		t.Fatalf("after approval: v%d draft=%v review=%s", set.Version, set.Draft != nil, set.ReviewState)
	}
	// v2 via emergency publish by a Super Admin.
	spec := set.PolicySetSpec
	spec.Rules = append(spec.Rules, models.PolicyRule{Name: "npm", Action: "ALLOW", HostPattern: "registry.npmjs.org", PathPattern: "/**", Enabled: true})
	if _, err := st.SaveDraft(set.ID, spec, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PublishDraft(set.ID, "incident INC-42: build outage", true, adminClaims); err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "registry.npmjs.org", "/left-pad"); !res.Allowed {
		t.Fatal("emergency change not enforced")
	}
	vs := st.PolicyVersions(set.ID)
	if len(vs) != 2 || !vs[0].Emergency {
		t.Fatalf("versions: %+v", vs)
	}
	// Rollback with review required prepares a draft instead of publishing.
	rolled, published, err := st.RollbackPolicySet(set.ID, 1, "undo", adminClaims)
	if err != nil || published || rolled.Draft == nil || len(rolled.Draft.Spec.Rules) != 1 {
		t.Fatalf("rollback: published=%v err=%v", published, err)
	}
	cr2, err := st.SubmitChangeRequest(set.ID, "rollback", "", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithdrawChangeRequest(cr2.ID, teamLeadCI); err == nil {
		t.Fatal("foreign team lead withdrew a change request")
	}
	if err := st.WithdrawChangeRequest(cr2.ID, adminClaims); err != nil {
		t.Fatal(err)
	}
	if set, _ := st.PolicySet(set.ID); set.Draft == nil || set.Draft.Status != "editing" {
		t.Fatal("withdrawn change request should unlock the draft")
	}
}

func TestTeamLeadCannotTouchGuardrailsInSets(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	set := publishSet(t, st, infosecClaims, "CI", []string{"grp-ci"},
		models.PolicyRule{Name: "deny paste", Action: "BLOCK", HostPattern: "pastebin.com", PathPattern: "/**", Enabled: true},
		models.PolicyRule{Name: "gh", Action: "ALLOW", HostPattern: "github.com", PathPattern: "/acme/**", Enabled: true})
	// Adding an ALLOW rule next to an unchanged BLOCK rule is fine for the Team Lead.
	spec := set.PolicySetSpec
	spec.Rules = append(spec.Rules, models.PolicyRule{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: "/**", Enabled: true})
	if _, err := st.SaveDraft(set.ID, spec, teamLeadCI); err != nil {
		t.Fatalf("team lead add allow: %v", err)
	}
	// Removing the BLOCK rule is not.
	spec2 := set.PolicySetSpec
	spec2.Rules = spec2.Rules[1:]
	if _, err := st.SaveDraft(set.ID, spec2, teamLeadCI); err == nil {
		t.Fatal("team lead removed a BLOCK guardrail")
	}
	// Nor is changing it.
	spec3 := set.PolicySetSpec
	spec3.Rules = append([]models.PolicyRule(nil), set.Rules...)
	spec3.Rules[0].HostPattern = "example.com"
	if _, err := st.SaveDraft(set.ID, spec3, teamLeadCI); err == nil {
		t.Fatal("team lead modified a BLOCK guardrail")
	}
	if _, err := st.CreatePolicySet(models.PolicySetKindBaseline, models.PolicySetSpec{Name: "x", Enabled: true}, teamLeadCI); err == nil {
		t.Fatal("team lead created a baseline set")
	}
	if _, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "y", Enabled: true, GroupIDs: []string{"grp-vault"},
		Rules: []models.PolicyRule{{Name: "a", Action: "ALLOW", HostPattern: "a.example", Enabled: true}}}, teamLeadCI); err == nil {
		t.Fatal("team lead created a set for a foreign group")
	}
}

func TestBaselineNeverAppliesToUnknownSources(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	publishSet(t, st, adminClaims, "updates", nil, models.PolicyRule{Name: "ubuntu", Action: "ALLOW", HostPattern: "archive.ubuntu.com", PathPattern: "/**", Enabled: true})
	if res := evalCI(st, "archive.ubuntu.com", "/ubuntu/"); !res.Allowed {
		t.Fatalf("baseline not applied to registered server: %+v", res)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "192.0.2.77", Method: "GET", Host: "archive.ubuntu.com", Path: "/"}); res.Allowed {
		t.Fatal("baseline allow applied to an unregistered source")
	}
}

func TestApprovalsSetExtendRevoke(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	req, _, err := st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.1.0.5", RequestedURL: "https://pkgs.example.org/a/b", Host: "pkgs.example.org",
		Path: "/a/b", Method: "GET", Requester: "ops", Reason: "need it", Duration: "permanent"})
	if err != nil {
		t.Fatal(err)
	}
	if req.DueAt == nil {
		t.Error("SLA due date missing")
	}
	if _, err := st.CommentRequest(req.ID, "checking with the vendor", teamLeadCI); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AssignRequest(req.ID, "admin", teamLeadCI); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true}, teamLeadCI); err == nil {
		t.Fatal("team lead granted permanent access")
	}
	_, rules, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true, Duration: "7d"}, teamLeadCI)
	if err != nil {
		t.Fatal(err)
	}
	set, ok := st.PolicySet("approvals-grp-ci")
	if !ok || set.Kind != models.PolicySetKindApprovals || len(set.Rules) != 1 || set.Rules[0].AccessRequestID != req.ID || set.Rules[0].ID != rules[0].ID {
		t.Fatalf("approvals set: %+v", set)
	}
	if res := evalCI(st, "pkgs.example.org", "/a/b"); !res.Allowed || res.MatchedRuleID != rules[0].ID {
		t.Fatalf("approved access not enforced: %+v", res)
	}
	got, err := st.ExtendAccessRequest(req.ID, "30d", teamLeadCI)
	if err != nil || got.ExpiresAt == nil || time.Until(*got.ExpiresAt) < 29*24*time.Hour {
		t.Fatalf("extend: %v %+v", err, got.ExpiresAt)
	}
	if _, err := st.ExtendAccessRequest(req.ID, "90d", teamLeadCI); err == nil {
		t.Fatal("team lead extended beyond the governance cap")
	}
	if _, err := st.RevokeAccessRequest(req.ID, "project finished", teamLeadCI); err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "pkgs.example.org", "/a/b"); res.Allowed {
		t.Fatal("revoked access still enforced")
	}
	r := st.GetSnapshot().Requests[0]
	if r.Status != "revoked" || len(r.Comments) < 2 || r.AssignedTo != "admin" {
		t.Fatalf("request after revoke: %+v", r)
	}
}

func TestQuarantine(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	publishSet(t, st, adminClaims, "CI", []string{"grp-ci"}, models.PolicyRule{Name: "all", Action: "ALLOW", HostPattern: "example.org", PathPattern: "/**", Enabled: true})
	if _, err := st.SetQuarantine("srv-ci-1", true, "", teamLeadCI); err == nil {
		t.Fatal("quarantine without reason accepted")
	}
	if _, err := st.SetQuarantine("srv-ci-1", true, "beaconing to C2 (INC-7)", teamLeadCI); err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "example.org", "/"); res.Verdict != models.VerdictQuarantined {
		t.Fatalf("quarantined server: %+v", res)
	}
	if _, err := st.SetQuarantine("srv-ci-1", false, "", teamLeadCI); err == nil {
		t.Fatal("team lead released a quarantine")
	}
	if _, err := st.SetQuarantine("srv-ci-1", false, "reimaged", infosecClaims); err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "example.org", "/"); !res.Allowed {
		t.Fatalf("released server: %+v", res)
	}
}

func TestDynamicGroupsAndEffectivePolicy(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	if _, err := st.UpsertGroup(models.ServerGroup{ID: "grp-pci", Name: "PCI", MatchLabels: map[string]string{"compliance": "pci"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	publishSet(t, st, adminClaims, "PCI processors", []string{"grp-pci"}, models.PolicyRule{Name: "psp", Action: "ALLOW", HostPattern: "api.psp.example", PathPattern: "/**", Enabled: true})
	if res := evalCI(st, "api.psp.example", "/v1/charge"); res.Allowed {
		t.Fatal("unlabelled server got the PCI policy")
	}
	if _, err := st.UpsertServer(models.Server{ID: "srv-ci-1", Hostname: "ci-1", IP: "10.1.0.5", ProxyAuthUser: "svc-ci-1", GroupIDs: []string{"grp-ci"},
		Labels: map[string]string{"compliance": "pci", "env": "prod"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if res := evalCI(st, "api.psp.example", "/v1/charge"); !res.Allowed {
		t.Fatalf("labelled server did not get the PCI policy: %+v", res)
	}
	ep, err := st.EffectivePolicy("srv-ci-1")
	if err != nil || len(ep.DynamicGroupIDs) != 1 || ep.DynamicGroupIDs[0] != "grp-pci" || ep.AllowRules != 1 {
		t.Fatalf("effective policy: %+v %v", ep, err)
	}
	if _, err := st.UpsertServer(models.Server{ID: "srv-x", Hostname: "x", Labels: map[string]string{"Bad Key!": "v"}}, adminClaims); err == nil {
		t.Fatal("invalid label key accepted")
	}
}

func TestImpactSimulation(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	set := publishSet(t, st, adminClaims, "CI", []string{"grp-ci"}, models.PolicyRule{Name: "gh", Action: "ALLOW", HostPattern: "github.com", PathPattern: "/**", Enabled: true})
	for _, f := range []models.TrafficFlow{
		{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Path: "/acme/x", FullURL: "https://github.com/acme/x", Verdict: models.VerdictAllowed},
		{ServerIP: "10.1.0.5", Method: "GET", Host: "pypi.org", Path: "/simple/", FullURL: "https://pypi.org/simple/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"},
		{ServerIP: "10.1.0.5", Method: "GET", Host: "evil.example", Path: "/", FullURL: "https://evil.example/", Verdict: models.VerdictThreatBlocked},
	} {
		st.RecordFlow(f)
	}
	spec := set.PolicySetSpec
	spec.Rules = []models.PolicyRule{{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: "/**", Enabled: true}}
	imp, err := st.SimulateSpec(set.ID, &spec, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if imp.FlowsEvaluated != 2 || imp.NewlyAllowed != 1 || imp.NewlyBlocked != 1 || imp.AffectedServers != 1 || imp.TargetServers != 1 {
		t.Fatalf("impact: %+v", imp)
	}
}

// A Team Lead may only simulate sets of their groups and only sees their groups' servers and traffic.
func TestImpactSimulationTeamLeadScope(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	ciSet := publishSet(t, st, adminClaims, "CI", []string{"grp-ci"}, models.PolicyRule{Name: "gh", Action: "ALLOW", HostPattern: "github.com", PathPattern: "/**", Enabled: true})
	vaultSet := publishSet(t, st, adminClaims, "Vault", []string{"grp-vault"}, models.PolicyRule{Name: "hv", Action: "ALLOW", HostPattern: "releases.hashicorp.com", PathPattern: "/**", Enabled: true})
	for _, f := range []models.TrafficFlow{
		{ServerIP: "10.1.0.5", Method: "GET", Host: "pypi.org", Path: "/simple/", FullURL: "https://pypi.org/simple/", Verdict: models.VerdictBlocked, BlockReason: "default_deny"},
		{ServerIP: "10.9.0.5", Method: "GET", Host: "secret.vault.example", Path: "/v1/token", FullURL: "https://secret.vault.example/v1/token?x=1", Verdict: models.VerdictBlocked, BlockReason: "default_deny"},
	} {
		st.RecordFlow(f)
	}
	tl := &auth.TokenClaims{UserID: "u-tl", Username: "tl", Role: models.RoleTeamLead, AllowedGroups: []string{"grp-ci"}}
	catchAll := []models.PolicyRule{{Name: "all", Action: "ALLOW", HostPattern: "*", PathPattern: "/**", Enabled: true}}

	foreign := vaultSet.PolicySetSpec
	foreign.Rules = catchAll
	if _, err := st.SimulateSpec(vaultSet.ID, &foreign, tl); err == nil {
		t.Fatal("Team Lead simulated a set of a foreign group")
	}
	if _, err := st.SimulateSpec("new", &models.PolicySetSpec{Name: "x", GroupIDs: []string{"grp-vault"}, Rules: catchAll}, tl); err == nil {
		t.Fatal("Team Lead simulated a new set for a foreign group")
	}
	if _, err := st.SimulateSpec(ciSet.ID, &models.PolicySetSpec{Name: "x", GroupIDs: []string{"grp-vault"}, Rules: catchAll}, tl); err == nil {
		t.Fatal("Team Lead re-scoped their own set to a foreign group in a simulation")
	}
	if _, err := st.SimulateSpec("", &models.PolicySetSpec{Name: "x", Rules: catchAll}, tl); err == nil {
		t.Fatal("Team Lead simulated an unscoped set")
	}

	own := ciSet.PolicySetSpec
	own.Rules = catchAll
	imp, err := st.SimulateSpec(ciSet.ID, &own, tl)
	if err != nil {
		t.Fatal(err)
	}
	if imp.FlowsEvaluated != 1 || imp.TargetServers != 1 {
		t.Fatalf("Team Lead impact covers foreign traffic or servers: %+v", imp)
	}
	for _, s := range imp.Samples {
		if strings.Contains(s.URL, "vault") || s.ServerIP == "10.9.0.5" {
			t.Fatalf("foreign sample leaked: %+v", s)
		}
	}
	if full, err := st.SimulateSpec(ciSet.ID, &own, adminClaims); err != nil || full.FlowsEvaluated != 2 {
		t.Fatalf("admin impact: %+v %v", full, err)
	}
}

func TestMigrationToPolicySets(t *testing.T) {
	dir := t.TempDir()
	legacy := map[string]any{
		"schema_version": 2, "revision": 7,
		"users":   []map[string]any{{"id": "usr-admin", "username": "admin", "role": "SUPER_ADMIN", "allowed_groups": []string{"*"}}},
		"groups":  []map[string]any{{"id": "grp-a", "name": "Alpha", "cidrs": []string{"10.1.0.0/16"}}},
		"servers": []map[string]any{{"id": "srv-a", "hostname": "a", "ip": "10.1.0.5", "group_ids": []string{"grp-a"}}},
		"rules": []map[string]any{
			{"id": "r1", "name": "gh", "action": "ALLOW", "host_pattern": "github.com", "path_pattern": "/**", "group_ids": []string{"grp-a"}, "enabled": true, "hit_count": 42},
			{"id": "r2", "name": "guard", "action": "BLOCK", "host_pattern": "pastebin.com", "path_pattern": "/**", "group_ids": []string{"*"}, "enabled": true},
			{"id": "r3", "name": "Approved: x", "action": "ALLOW", "host_pattern": "x.example", "path_pattern": "/**", "group_ids": []string{"grp-a"}, "enabled": true},
		},
		"requests": []map[string]any{{"id": "req-1", "status": "approved", "created_rule_id": "r3", "target_group_ids": []string{"grp-a"}}},
	}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t, dir, false)
	sets := st.PolicySets()
	kinds := map[string]int{}
	for _, s := range sets {
		kinds[s.Kind]++
		if s.Version != 1 {
			t.Errorf("migrated set %s not published", s.Name)
		}
	}
	if len(sets) != 3 || kinds[models.PolicySetKindBaseline] != 1 || kinds[models.PolicySetKindApprovals] != 1 {
		t.Fatalf("migrated sets: %+v", kinds)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Path: "/"}); !res.Allowed {
		t.Fatal("migrated allow rule not enforced")
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "pastebin.com", Path: "/"}); res.Allowed || res.BlockReason != "block_rule" {
		t.Fatalf("migrated guardrail: %+v", res)
	}
	for _, r := range st.GetSnapshot().Rules {
		if r.ID == "r1" && r.HitCount != 42 {
			t.Errorf("hit counter lost in migration: %d", r.HitCount)
		}
	}
	if st.GetSnapshot().SchemaVersion != currentSchemaVersion {
		t.Error("schema version not bumped")
	}
}

func TestImportServersDryRunAndAtomicity(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	rows := []models.Server{
		{ID: "srv-new-1", Hostname: "new-1", IP: "10.1.0.20", GroupIDs: []string{"grp-ci"}, Labels: map[string]string{"env": "prod"}},
		{ID: "srv-ci-1", Hostname: "ci-1-renamed", IP: "10.1.0.5", ProxyAuthUser: "svc-ci-1", GroupIDs: []string{"grp-ci"}},
	}
	res, err := st.ImportServers(rows, true, adminClaims)
	if err != nil || res[0].Action != "create" || res[1].Action != "update" {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if len(st.Servers()) != 2 {
		t.Fatal("dry run changed the inventory")
	}
	bad := append(rows, models.Server{ID: "srv-dup", Hostname: "dup", IP: "10.1.0.20"})
	if _, err := st.ImportServers(bad, false, adminClaims); err == nil {
		t.Fatal("import with a duplicate IP accepted")
	}
	if len(st.Servers()) != 2 {
		t.Fatal("failed import was not atomic")
	}
	if _, err := st.ImportServers(rows, false, adminClaims); err != nil {
		t.Fatal(err)
	}
	if len(st.Servers()) != 3 {
		t.Fatal("import did not apply")
	}
}

func TestBlockPageTemplateValidation(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	cases := map[string]models.BlockPageTemplate{
		"js link":    {Name: "a", Links: []models.LinkItem{{Label: "x", URL: "javascript:alert(1)"}}},
		"bad logo":   {Name: "b", LogoDataURL: "data:text/html;base64,PHNjcmlwdD4="},
		"bad color":  {Name: "c", PrimaryColor: "red;}body{display:none"},
		"bad scope":  {Name: "d", AllowedScopes: []string{"everything"}},
		"empty form": {Name: "e", ShowRequestForm: true},
		"bad email":  {Name: "f", Support: models.SupportContact{Email: "a@b.c\nBcc: x@y.z"}},
	}
	for name, tpl := range cases {
		if _, err := st.UpsertBlockPage(tpl, adminClaims); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := DefaultBlockPageTemplate()
	ok.ID, ok.IsDefault, ok.Name = "", false, "Ops"
	saved, err := st.UpsertBlockPage(ok, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertGroup(models.ServerGroup{ID: "grp-x", Name: "X", BlockPageTemplateID: saved.ID}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteBlockPage(saved.ID, adminClaims); err == nil || !strings.Contains(err.Error(), "assigned") {
		t.Fatalf("deleting an assigned template: %v", err)
	}
	if got := st.TemplateForGroups([]string{"grp-x"}); got.ID != saved.ID {
		t.Fatalf("template for group: %s", got.ID)
	}
}

func TestUntouchedRulesAreNotChanges(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	set := publishSet(t, st, infosecClaims, "CI", []string{"grp-ci"},
		models.PolicyRule{Name: "deny paste", Action: "BLOCK", HostPattern: "pastebin.com", PathPattern: "/**", Enabled: true})
	spec := set.PolicySetSpec
	spec.Rules = append([]models.PolicyRule(nil), set.Rules...)
	spec.Rules[0].CompanionRules, spec.Rules[0].Methods = nil, append([]string(nil), spec.Rules[0].Methods...)
	if d := DiffSpecs(set.PolicySetSpec, spec); d.Modified != 0 {
		t.Fatalf("null vs empty slices reported as change: %+v", d.Rules)
	}
	if _, err := st.SaveDraft(set.ID, spec, teamLeadCI); err != nil {
		t.Fatalf("team lead re-sending an untouched BLOCK rule: %v", err)
	}
	created, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "No recert", Enabled: true, GroupIDs: []string{"grp-ci"}}, adminClaims)
	if err != nil || created.Draft.Spec.ReviewIntervalDays != 0 || !created.Enabled {
		t.Fatalf("create: %v interval=%d enabled=%v", err, created.Draft.Spec.ReviewIntervalDays, created.Enabled)
	}
}

func TestHousekeepingPrunesExpiredAccessAndClaimsDigestOnce(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	req, _, err := st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.1.0.5", RequestedURL: "https://a.example/x/y", Host: "a.example",
		Path: "/x/y", Method: "GET", Requester: "ops", Reason: "r", Duration: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReviewAccessRequest(req.ID, ReviewOptions{Approve: true}, adminClaims); err != nil {
		t.Fatal(err)
	}
	// Not yet past the 7-day grace period.
	st.Housekeeping(time.Now().Add(2 * time.Hour))
	if set, _ := st.PolicySet("approvals-grp-ci"); len(set.Rules) != 1 {
		t.Fatal("rule pruned too early")
	}
	later := time.Now().Add(9 * 24 * time.Hour)
	st.Housekeeping(later)
	set, _ := st.PolicySet("approvals-grp-ci")
	if len(set.Rules) != 0 || set.Version != 2 {
		t.Fatalf("expired access not pruned: %d rules v%d", len(set.Rules), set.Version)
	}
	morning := time.Date(2030, 1, 2, 9, 0, 0, 0, time.Local)
	if _, ok := st.claimDigest(morning); ok {
		t.Log("digest due (non-empty)")
	}
	if st.Governance().LastDigestAt == nil {
		t.Fatal("digest not claimed")
	}
	if _, ok := st.claimDigest(morning.Add(time.Hour)); ok {
		t.Fatal("digest claimed twice within a day")
	}
}

func TestPolicySetExportImport(t *testing.T) {
	src := newTestStore(t, t.TempDir(), false)
	setupFleet(t, src)
	set := publishSet(t, src, adminClaims, "Dev tools", []string{"grp-ci"},
		models.PolicyRule{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: "/**", Enabled: true})
	publishSet(t, src, adminClaims, "Guardrails", nil, models.PolicyRule{Name: "paste", Action: "BLOCK", HostPattern: "pastebin.com", Enabled: true})
	bundle := src.ExportPolicySets(nil, adminClaims)
	if bundle.Format != PolicyBundleFormat || len(bundle.PolicySets) != 2 {
		t.Fatalf("export: %+v", bundle)
	}

	dst := newTestStore(t, t.TempDir(), false)
	setupFleet(t, dst)
	plan, err := dst.ImportPolicySets(bundle, true, adminClaims)
	if err != nil || plan[0].Action != "create" || plan[1].Action != "create" || len(dst.PolicySets()) != 0 {
		t.Fatalf("dry run: %+v %v", plan, err)
	}
	if _, err := dst.ImportPolicySets(bundle, false, teamLeadCI); err == nil {
		t.Fatal("team lead imported a baseline set")
	}
	if len(dst.PolicySets()) != 0 {
		t.Fatal("failed import was not atomic")
	}
	res, err := dst.ImportPolicySets(bundle, false, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range dst.PolicySets() {
		if s.Version != 0 || s.Draft == nil {
			t.Fatalf("import must create drafts, got v%d", s.Version)
		}
	}
	if res[0].ID == "" {
		t.Fatal("created id not reported")
	}
	// Re-importing into the source: matched by id, unchanged.
	again, err := src.ImportPolicySets(bundle, true, adminClaims)
	if err != nil || again[0].Action != "unchanged" || again[0].ID != set.ID {
		t.Fatalf("re-import plan: %+v %v", again, err)
	}
}

func TestSecretsEncryptedAtRest(t *testing.T) {
	key, _ := sealed.DeriveKey(strings.Repeat("k", 48))
	if err := sealed.Configure(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	if _, err := st.UpsertExportSink(models.ExportSink{Name: "hook", Type: "webhook", Streams: []string{"audit"},
		Endpoint: "https://hooks.example/x", Secret: "super-secret-hmac", Headers: sealed.Map{"X-Key": "header-secret"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateNotificationConfig(models.NotificationConfig{SlackEnabled: true, SlackWebhookURL: "https://hooks.slack.example/services/T1/B2/tok3n"}, adminClaims); err != nil {
		t.Fatal(err)
	}
	// Sending back the masked URL keeps the stored one.
	if err := st.UpdateNotificationConfig(models.NotificationConfig{SlackEnabled: true, SlackWebhookURL: sealed.String(models.MaskURL("https://hooks.slack.example/services/T1/B2/tok3n"))}, adminClaims); err != nil {
		t.Fatal(err)
	}
	st.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
	for _, secret := range []string{"super-secret-hmac", "header-secret", "tok3n"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q stored in plain text", secret)
		}
	}
	if !strings.Contains(string(raw), "enc:v1:") {
		t.Fatal("no sealed values in the state file")
	}
	st2 := newTestStore(t, dir, false)
	merged := st2.MergeExportSecrets(models.ExportSink{ID: st2.ExportSinks()[0].ID})
	if merged.Secret != "super-secret-hmac" || st2.GetSnapshot().NotifyConfig.SlackWebhookURL != "https://hooks.slack.example/services/T1/B2/tok3n" {
		t.Fatal("secrets not restored after reload")
	}
	st2.Close()
	// A wrong key must not silently drop secrets.
	other, _ := sealed.DeriveKey(strings.Repeat("z", 48))
	_ = sealed.Configure(other)
	if _, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine()}); err == nil {
		t.Fatal("state with secrets of another key loaded without error")
	}
}

func TestKeyRotationReencryptsAtStartup(t *testing.T) {
	oldKey, _ := sealed.DeriveKey(strings.Repeat("o", 48))
	newKey, _ := sealed.DeriveKey(strings.Repeat("n", 48))
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	_ = sealed.Configure(oldKey)
	oldID := sealed.KeyID()
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	if _, err := st.UpsertExportSink(models.ExportSink{Name: "hook", Type: "webhook", Streams: []string{"audit"},
		Endpoint: "https://hooks.example/x", Secret: "rotate-me"}, adminClaims); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Phase 2 of the rotation: new key current, old key previous -> everything re-sealed at start.
	_ = sealed.Configure(newKey, oldKey)
	newID := sealed.KeyID()
	st = newTestStore(t, dir, false)
	st.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
	if strings.Contains(string(raw), "enc:v1:"+oldID+":") || !strings.Contains(string(raw), "enc:v1:"+newID+":") {
		t.Fatal("secrets not re-encrypted with the new key at startup")
	}
	// Phase 3: the old key is removed; the state still loads with all secrets.
	_ = sealed.Configure(newKey)
	st = newTestStore(t, dir, false)
	if got := st.MergeExportSecrets(models.ExportSink{ID: st.ExportSinks()[0].ID}).Secret; got != "rotate-me" {
		t.Fatalf("secret after rotation: %q", got)
	}
}
