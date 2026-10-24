package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// State written by 2.0 (schema 3): trailing "/*" meant "this prefix and everything below". The v4 migration
// rewrites such patterns to "/**" everywhere they are stored and audits the list.
func TestPathPatternMigration(t *testing.T) {
	dir := t.TempDir()
	rule := func(id, action, path string, companions ...string) map[string]any {
		host := "example.com"
		if action == "BLOCK" {
			host = "blocked.example"
		}
		return map[string]any{"id": id, "version": 1, "name": "rule " + id, "action": action, "host_pattern": host,
			"path_pattern": path, "methods": []string{"GET"}, "companion_rules": companions, "enabled": true}
	}
	spec := map[string]any{"name": "Legacy", "enabled": true, "group_ids": []string{"grp-ci"}, "rules": []any{
		rule("r-simple", "ALLOW", "/simple/*", "files.example.com/packages/*", "cdn.example.com"),
		rule("r-block", "BLOCK", "/*"),
		rule("r-ok", "ALLOW", "/microsoft/**"),
		rule("r-mid", "ALLOW", "/repos/*/releases"),
	}}
	state := map[string]any{
		"schema_version": 3, "revision": 9,
		"groups":  []map[string]any{{"id": "grp-ci", "name": "CI", "cidrs": []string{"10.1.0.0/16"}}},
		"servers": []map[string]any{{"id": "srv-ci-1", "hostname": "ci-1", "ip": "10.1.0.5", "group_ids": []string{"grp-ci"}}},
		"policy_sets": []map[string]any{{"id": "ps-legacy", "kind": "standard", "version": 1, "name": spec["name"], "enabled": true,
			"group_ids": spec["group_ids"], "rules": spec["rules"],
			"draft": map[string]any{"spec": map[string]any{"name": "Legacy", "rules": []any{rule("r-draft", "ALLOW", "/draft/*")}}, "status": "editing"}}},
		"policy_versions": []map[string]any{{"policy_set_id": "ps-legacy", "version": 1, "spec": spec}},
		"requests":        []map[string]any{{"id": "req-1", "status": "pending", "suggested_host_pattern": "pypi.org", "suggested_path_pattern": "/simple/*"}},
		"sessions": []map[string]any{{"id": "sess-1", "server_id": "srv-ci-1", "status": "completed",
			"compiled_candidates": []map[string]any{{"id": "c1", "host_pattern": "a.example", "path_pattern": "/token*"}}}},
	}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t, dir, false)
	snap := st.GetSnapshot()
	if snap.SchemaVersion != currentSchemaVersion {
		t.Fatalf("schema %d", snap.SchemaVersion)
	}
	set := snap.PolicySets[0]
	got := map[string]string{}
	for _, r := range set.Rules {
		got[r.ID] = r.PathPattern
	}
	want := map[string]string{"r-simple": "/simple/**", "r-block": "/**", "r-ok": "/microsoft/**", "r-mid": "/repos/*/releases"}
	for id, p := range want {
		if got[id] != p {
			t.Errorf("%s: %q, want %q", id, got[id], p)
		}
	}
	if c := set.Rules[0].CompanionRules; len(c) != 2 || c[0] != "files.example.com/packages/**" || c[1] != "cdn.example.com" {
		t.Errorf("companions %q", c)
	}
	if p := set.Draft.Spec.Rules[0].PathPattern; p != "/draft/**" {
		t.Errorf("draft %q", p)
	}
	if v := st.PolicyVersions("ps-legacy"); len(v) != 1 || v[0].Spec.Rules[0].PathPattern != "/simple/**" {
		t.Errorf("version history (rollback target) %+v", v)
	}
	if p := snap.Requests[0].SuggestedPathPattern; p != "/simple/**" {
		t.Errorf("access request %q", p)
	}
	if p := snap.Sessions[0].CompiledCandidates[0].PathPattern; p != "/token**" {
		t.Errorf("session candidate %q", p)
	}
	var ev *models.AuditEvent
	for i := range snap.AuditEvents {
		if snap.AuditEvents[i].Action == "POLICY_PATH_PATTERNS_MIGRATED" {
			ev = &snap.AuditEvents[i]
		}
	}
	if ev == nil {
		t.Fatal("no audit event for the migration")
	}
	for _, s := range []string{"/simple/* → /simple/**", "review"} {
		if !strings.Contains(ev.Summary, s) {
			t.Errorf("summary misses %q: %s", s, ev.Summary)
		}
	}
	var list []pathRewrite
	if err := json.Unmarshal([]byte(ev.AfterState), &list); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, c := range list {
		listed[c.RuleID+" "+c.Before] = true
	}
	for _, k := range []string{"r-simple /simple/*", "r-block /*", "r-simple files.example.com/packages/*", "r-draft /draft/*", "r-mid /repos/*/releases"} {
		if !listed[k] {
			t.Errorf("audit list misses %s: %+v", k, list)
		}
	}
	// The effective (compiled) rules enforce the old meaning.
	if res := evalCI(st, "example.com", "/simple/a/b"); !res.Allowed {
		t.Errorf("migrated /simple/** rule: %+v", res)
	}
	if res := evalCI(st, "blocked.example", "/a/b"); res.Allowed || res.BlockReason != "block_rule" {
		t.Errorf("BLOCK /* (now /**) must still block the whole host: %+v", res)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "CONNECT", Host: "blocked.example"}); res.BlockReason != "block_rule" {
		t.Errorf("BLOCK /* (now /**) must still block the tunnel: %+v", res)
	}
	st.Close()

	// Loaded again: nothing left to migrate, no second audit event.
	st2 := newTestStore(t, dir, false)
	n := 0
	for _, e := range st2.GetSnapshot().AuditEvents {
		if e.Action == "POLICY_PATH_PATTERNS_MIGRATED" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d migration events after reload", n)
	}
}

// Bundles exported before 2.1 carry no path_syntax: their legacy patterns keep their meaning on import.
func TestImportLegacyBundleRewritesPathPatterns(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	doc := func(path string) models.PolicySetDocument {
		return models.PolicySetDocument{Kind: models.PolicySetKindStandard, PolicySetSpec: models.PolicySetSpec{Name: "Imported " + path, Enabled: true,
			GroupIDs: []string{"grp-ci"}, Rules: []models.PolicyRule{{Name: "pypi", Action: "ALLOW", HostPattern: "pypi.org", PathPattern: path, Enabled: true}}}}
	}
	if _, err := st.ImportPolicySets(models.PolicySetBundle{Format: PolicyBundleFormat, PolicySets: []models.PolicySetDocument{doc("/simple/*")}}, false, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ImportPolicySets(models.PolicySetBundle{Format: PolicyBundleFormat, PathSyntax: PolicyPathSyntax,
		PolicySets: []models.PolicySetDocument{doc("/one/*")}}, false, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ImportPolicySets(models.PolicySetBundle{PathSyntax: 3, PolicySets: []models.PolicySetDocument{doc("/x")}}, true, adminClaims); err == nil {
		t.Fatal("unknown path_syntax accepted")
	}
	paths := map[string]string{}
	for _, set := range st.GetSnapshot().PolicySets {
		if set.Draft != nil && len(set.Draft.Spec.Rules) > 0 {
			paths[set.Draft.Spec.Name] = set.Draft.Spec.Rules[0].PathPattern
		} else if len(set.Rules) > 0 {
			paths[set.Name] = set.Rules[0].PathPattern
		}
	}
	if paths["Imported /simple/*"] != "/simple/**" || paths["Imported /one/*"] != "/one/*" {
		t.Fatalf("imported patterns: %v", paths)
	}
	if b := st.ExportPolicySets(nil, adminClaims); b.PathSyntax != PolicyPathSyntax {
		t.Fatalf("export path_syntax %d", b.PathSyntax)
	}
}
