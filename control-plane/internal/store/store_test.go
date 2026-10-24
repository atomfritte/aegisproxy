package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

func newTestStore(t testing.TB, dir string, demo bool) *Store {
	t.Helper()
	ti, err := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti"), AutoUpdate: false})
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(Options{DataDir: dir, DemoMode: demo, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, DashboardURL: "https://aegis.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

var adminClaims = &auth.TokenClaims{UserID: "usr-admin", Username: "admin", Role: models.RoleSuperAdmin, AllowedGroups: []string{"*"}}

func setupFleet(t *testing.T, st *Store) {
	t.Helper()
	for _, g := range []models.ServerGroup{
		{ID: "grp-ci", Name: "CI", CIDRs: []string{"10.1.0.0/16"}},
		{ID: "grp-vault", Name: "Vault", CIDRs: []string{"10.9.0.0/16"}, StrictIsolation: true},
	} {
		if _, err := st.UpsertGroup(g, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []models.Server{
		{ID: "srv-ci-1", Hostname: "ci-1", IP: "10.1.0.5", ProxyAuthUser: "svc-ci-1", GroupIDs: []string{"grp-ci"}},
		{ID: "srv-vault-1", Hostname: "vault-1", IP: "10.9.0.5", GroupIDs: []string{"grp-vault"}},
	} {
		if _, err := st.UpsertServer(s, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
}

// publishSet creates and publishes a policy set holding rules (baseline when groups is nil).
func publishSet(t *testing.T, st *Store, actor *auth.TokenClaims, name string, groups []string, rules ...models.PolicyRule) models.PolicySet {
	t.Helper()
	kind := models.PolicySetKindStandard
	if groups == nil {
		kind = models.PolicySetKindBaseline
	}
	set, err := st.CreatePolicySet(kind, models.PolicySetSpec{Name: name, Enabled: true, GroupIDs: groups, Rules: rules}, actor)
	if err != nil {
		t.Fatalf("create set %s: %v", name, err)
	}
	set, err = st.PublishDraft(set.ID, "", false, actor)
	if err != nil {
		t.Fatalf("publish set %s: %v", name, err)
	}
	return set
}

func waitForThreatVersion(t *testing.T, st *Store, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second) // generous: loaded CI hosts, race detector
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("threat-intel snapshot was not rebuilt in time")
}

func TestBootstrapAdminProduction(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	pwFile := filepath.Join(dir, "secrets", "initial-admin-password")
	fi, err := os.Stat(pwFile)
	if err != nil {
		t.Fatalf("initial admin password file missing: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // Windows: the installer's ACL on the data directory
		t.Errorf("password file perms %v", fi.Mode().Perm())
	}
	pw, _ := os.ReadFile(pwFile)
	if _, err := st.AuthenticateLocal("admin", strings.TrimSpace(string(pw))); err != nil {
		t.Fatalf("bootstrap login failed: %v", err)
	}
	if _, err := st.AuthenticateLocal("admin", "admin123"); err == nil {
		t.Fatal("demo password must not work in production mode")
	}
	snap := st.GetSnapshot()
	if len(snap.Groups) != 0 || len(snap.Rules) != 0 {
		t.Error("production seed must not contain demo fleet/rules")
	}
	if len(snap.ThreatFeeds) == 0 || snap.SecurityPolicy.ThreatIntelMode != "block" {
		t.Error("production seed must enable threat protection defaults")
	}
	for _, u := range snap.Users {
		if u.PasswordHash != "" {
			t.Error("snapshot leaked a password hash")
		}
	}
}

func TestLegacyStateMigration(t *testing.T) {
	dir := t.TempDir()
	legacy := map[string]any{
		"revision": 25,
		"users":    []map[string]any{{"id": "usr-admin", "username": "admin", "role": "SUPER_ADMIN", "allowed_groups": []string{"*"}}},
		"groups":   []map[string]any{{"id": "grp-db-vault", "name": "Vault", "cidrs": []string{"10.60.0.0/16"}}},
		"servers": []map[string]any{{"id": "srv-1", "hostname": "h", "ip": "10.60.1.1", "proxy_auth_user": "svc-1",
			"proxy_auth_token": "tok-legacy-secret", "group_ids": []string{"grp-db-vault"}}},
	}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t, dir, false)
	snap := st.GetSnapshot()
	if snap.Servers[0].ProxyAuthTokenHash != engine.HashProxyToken("tok-legacy-secret") {
		t.Error("plaintext token was not migrated to a hash")
	}
	if !snap.Groups[0].StrictIsolation {
		t.Error("legacy grp-db-vault should become strict isolation")
	}
	if id, _, _ := st.ResolveServer("192.0.2.1", "svc-1:tok-legacy-secret"); id != "srv-1" {
		t.Errorf("token auth after migration resolved to %q", id)
	}
	st.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
	if strings.Contains(string(raw), "tok-legacy-secret") {
		t.Error("plaintext token still persisted")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "aegis_state.json")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("state file perms %v, want 0600", fi.Mode().Perm())
	}
	if !strings.Contains(string(raw), "pbkdf2-sha256$") {
		t.Error("bootstrap admin hash was not persisted")
	}
}

func TestEvaluatePolicyOrder(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	publishSet(t, st, adminClaims, "ci", []string{"grp-ci"},
		models.PolicyRule{Name: "gh ms", Action: "ALLOW", HostPattern: "github.com", PathPattern: "/microsoft/**", Enabled: true},
		models.PolicyRule{Name: "evil allow", Action: "ALLOW", HostPattern: "evil.example", PathPattern: "/**", Enabled: true},
		models.PolicyRule{Name: "catchall", Action: "ALLOW", HostPattern: "*", PathPattern: "/**", Enabled: true})
	publishSet(t, st, adminClaims, "guardrails", nil,
		models.PolicyRule{Name: "block torvalds", Action: "BLOCK", HostPattern: "github.com", PathPattern: "/microsoft/secret/**", Enabled: true})
	if _, err := st.AddIndicator(models.Indicator{Type: "domain", Value: "evil.example", Category: "malware", Reason: "test"}, adminClaims); err != nil {
		t.Fatal(err)
	}
	waitForThreatVersion(t, st, func() bool {
		_, hit := st.ThreatIntel().Snapshot().MatchHost("evil.example")
		return hit
	})

	eval := func(host, path string, port int) engine.EvaluationResult {
		return st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Scheme: "https", Host: host, Path: path, Port: port, FullURL: "https://" + host + path})
	}
	cases := []struct {
		host, path string
		port       int
		verdict    string
		reason     string
	}{
		{"github.com", "/microsoft/vscode", 443, models.VerdictAllowed, ""},
		{"github.com", "/microsoft/secret/x", 443, models.VerdictBlocked, "block_rule"},
		{"evil.example", "/", 443, models.VerdictThreatBlocked, "threat_intel"},
		{"sub.evil.example", "/", 443, models.VerdictThreatBlocked, "threat_intel"},
		{"8.8.8.8", "/", 443, models.VerdictPolicyBlocked, "ip_literal"},
		{"169.254.169.254", "/latest/meta-data", 80, models.VerdictPolicyBlocked, "forbidden_destination"},
		{"localhost", "/", 80, models.VerdictPolicyBlocked, "forbidden_destination"},
		{"db.internal.corp", "/", 443, models.VerdictPolicyBlocked, "internal_destination"},
		{"10.0.0.1", "/", 443, models.VerdictPolicyBlocked, "ip_literal"},
		{"example.org", "/", 8443, models.VerdictPolicyBlocked, "port_not_allowed"},
		{"example.org", "/%2e%2e/%2e%2e/etc", 443, models.VerdictAllowed, ""}, // canonicalized; catch-all allows
		{"github.com", "/microsoft/%00x", 443, models.VerdictPolicyBlocked, "malformed_path"},
	}
	for _, c := range cases {
		res := eval(c.host, c.path, c.port)
		if res.Verdict != c.verdict || (c.reason != "" && res.BlockReason != c.reason) {
			t.Errorf("%s%s:%d => %s/%s (%s), want %s/%s", c.host, c.path, c.port, res.Verdict, res.BlockReason, res.MatchedRuleName, c.verdict, c.reason)
		}
	}
	// Unregistered sources get no groups and are denied even with a catch-all rule for grp-ci.
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "192.0.2.50", Method: "GET", Host: "github.com", Path: "/microsoft/x"}); res.Allowed {
		t.Errorf("unregistered source allowed: %+v", res)
	}
	// Monitor mode flags instead of blocking.
	p := st.SecurityPolicy()
	p.ThreatIntelMode = "monitor"
	if _, err := st.UpdateSecurityPolicy(p, adminClaims); err != nil {
		t.Fatal(err)
	}
	if res := eval("evil.example", "/", 443); res.Verdict != models.VerdictAllowed || len(res.SecurityFlags) == 0 {
		t.Errorf("monitor mode: %+v", res)
	}
}

func TestTLSBypassRespectsStrictIsolation(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	if _, err := st.AddTLSBypass(models.TLSBypassRule{Pattern: "*.windowsupdate.com", Reason: "pinning"}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddTLSBypass(models.TLSBypassRule{Pattern: "*.com", Reason: "too broad"}, adminClaims); err == nil {
		t.Error("TLD wildcard bypass accepted")
	}
	ci := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "CONNECT", Host: "x.windowsupdate.com"})
	if ci.Verdict != models.VerdictTLSBypass {
		t.Errorf("CI server should bypass, got %s", ci.Verdict)
	}
	vault := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.9.0.5", Method: "CONNECT", Host: "x.windowsupdate.com"})
	if vault.Allowed {
		t.Errorf("strict-isolation server must not bypass: %+v", vault)
	}
	if _, err := st.StartLearningSession("s", "", "srv-vault-1", 15, "record_and_allow", adminClaims); err == nil {
		t.Error("learning session allowed for strict-isolation server")
	}
}

func TestAccessRequestDedupAndSingleReview(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	in := models.AccessRequest{ServerIP: "10.1.0.5", RequestedURL: "https://pkgs.example.org/a/b/c", Host: "pkgs.example.org", Path: "/a/b/c",
		Method: "GET", Requester: "ops", Reason: "need it", Duration: "24h"}
	r1, isNew, err := st.CreateAccessRequest(in)
	if err != nil || !isNew {
		t.Fatalf("create: %v %v", err, isNew)
	}
	r2, isNew, _ := st.CreateAccessRequest(in)
	if isNew || r2.ID != r1.ID {
		t.Error("duplicate pending request was not de-duplicated")
	}
	if _, _, err := st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.1.0.5", Host: "x", Path: "/", Requester: "a", Reason: "", Duration: "24h"}); err == nil {
		t.Error("empty reason accepted")
	}
	_, rules, err := st.ReviewAccessRequest(r1.ID, ReviewOptions{Approve: true, Comment: "ok", FollowRedirects: true}, adminClaims)
	if err != nil || len(rules) != 1 {
		t.Fatalf("approve: %v", err)
	}
	if strings.Join(rules[0].Methods, ",") != "GET,HEAD" {
		t.Errorf("approved rule should be least-privilege GET/HEAD, got %v", rules[0].Methods)
	}
	if _, _, err := st.ReviewAccessRequest(r1.ID, ReviewOptions{Approve: true, Comment: "again"}, adminClaims); err == nil {
		t.Error("request approved twice")
	}
}

func TestTeamLeadCannotPublishCatchAll(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	tl := &auth.TokenClaims{UserID: "u-tl", Username: "tl", Role: models.RoleTeamLead, AllowedGroups: []string{"grp-ci"}}
	sess, err := st.StartLearningSession("rec", "", "srv-ci-1", 15, "record_and_allow", tl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.StopLearningSession(sess.ID, tl); err != nil {
		t.Fatal(err)
	}
	_, _, err = st.PublishSessionRules(sess.ID, SessionPublish{Candidates: []models.CompiledRuleCandidate{{HostPattern: "*", PathPattern: "/**", Methods: []string{"GET"}, Selected: true}},
		TargetGroupIDs: []string{"grp-ci"}, RulePrefix: "x", Publish: true}, tl)
	if err == nil || errors.Is(err, ErrSessionRecording) {
		t.Fatalf("team lead published a catch-all rule through a session (err %v)", err)
	}
	set, _, err := st.PublishSessionRules(sess.ID, SessionPublish{Candidates: []models.CompiledRuleCandidate{{HostPattern: "pypi.org", PathPattern: "/simple/**", Methods: []string{"GET"}, Selected: true}},
		TargetGroupIDs: []string{"grp-ci"}, RulePrefix: "x", NewSetName: "PyPI", Publish: true}, tl)
	if err != nil {
		t.Fatalf("legit publish failed: %v", err)
	}
	if set.Version != 1 || set.Draft != nil || len(set.Rules) != 1 {
		t.Errorf("session publish should create and publish a set: %+v", set)
	}
	if res := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "pypi.org", Path: "/simple/requests/"}); !res.Allowed {
		t.Errorf("published session rule not effective: %+v", res)
	}
}

func TestRuleValidation(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	bad := []models.PolicyRule{
		{Name: "scheme", Action: "ALLOW", HostPattern: "https://x.com", GroupIDs: []string{"grp-ci"}},
		{Name: "mid wildcard", Action: "ALLOW", HostPattern: "a.*.com", GroupIDs: []string{"grp-ci"}},
		{Name: "unknown group", Action: "ALLOW", HostPattern: "x.com", GroupIDs: []string{"nope"}},
		{Name: "no scope", Action: "ALLOW", HostPattern: "x.com"},
		{Name: "bad method", Action: "ALLOW", HostPattern: "x.com", Methods: []string{"TRACE"}, GroupIDs: []string{"grp-ci"}},
		{Name: "bad action", Action: "MAYBE", HostPattern: "x.com", GroupIDs: []string{"grp-ci"}},
		{Name: "", Action: "ALLOW", HostPattern: "x.com", GroupIDs: []string{"grp-ci"}},
	}
	for _, r := range bad {
		groups := r.GroupIDs
		if groups == nil {
			groups = []string{"grp-ci"}
		}
		r.GroupIDs = nil
		if r.Name == "no scope" {
			groups = []string{}
		}
		if r.Name == "unknown group" {
			groups = []string{"nope"}
		}
		if _, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "set " + r.Name, Enabled: true, GroupIDs: groups, Rules: []models.PolicyRule{r}}, adminClaims); err == nil {
			t.Errorf("invalid rule %q accepted", r.Name)
		}
	}
}

func TestSecurityEventsAndBurst(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	f := models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "evil.example", FullURL: "https://evil.example/", Verdict: models.VerdictThreatBlocked,
		ThreatCategory: "botnet_c2", ThreatSource: "Feodo", ProxyAuthUser: "svc:secret-token"}
	st.RecordFlow(f)
	st.RecordFlow(f)
	snap := st.GetSnapshot()
	if len(snap.SecurityEvents) != 1 || snap.SecurityEvents[0].Count != 2 || snap.SecurityEvents[0].Severity != "critical" {
		t.Fatalf("events: %+v", snap.SecurityEvents)
	}
	if strings.Contains(snap.Flows[0].ProxyAuthUser, "secret") {
		t.Error("proxy token leaked into stored flow")
	}
	for i := 0; i < 40; i++ {
		st.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "x.example", Verdict: models.VerdictBlocked})
	}
	found := false
	for _, ev := range st.GetSnapshot().SecurityEvents {
		if ev.Type == models.SecurityEventBlockBurst {
			found = true
		}
	}
	if !found {
		t.Error("block burst anomaly not detected")
	}
}

func TestUserManagementGuards(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	u, tmp, err := st.UpsertUser(UserInput{Username: "alice", DisplayName: "Alice", Role: models.RoleAuditorOperator}, adminClaims)
	if err != nil || tmp == "" {
		t.Fatalf("create: %v", err)
	}
	if _, err := st.AuthenticateLocal("alice", tmp); err != nil {
		t.Fatalf("temp password login: %v", err)
	}
	if err := st.DeleteUser("usr-admin", &auth.TokenClaims{UserID: "other", Role: models.RoleSuperAdmin}); err == nil {
		t.Error("last super admin deleted")
	}
	if _, _, err := st.UpsertUser(UserInput{Username: "bob", DisplayName: "B", Role: models.RoleSuperAdmin},
		&auth.TokenClaims{Role: models.RoleInfoSecApprover}); err == nil {
		t.Error("non-super-admin created a user")
	}
	if _, _, err := st.UpsertUser(UserInput{ID: u.ID, Username: "alice", DisplayName: "A", Role: models.RoleAuditorOperator, Disabled: true}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateLocal("alice", tmp); err == nil {
		t.Error("disabled user could sign in")
	}
}
