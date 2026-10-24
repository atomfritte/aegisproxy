package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// Server identification, NAT separation of temporary grants and proxy token enforcement, shared with the
// data-plane's Policy.identify/evaluate (testdata/identity_vectors.json).
func TestIdentityVectorsSharedWithDataPlane(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "identity_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Groups  []models.ServerGroup `json:"groups"`
		Servers []struct {
			models.Server
			Token string `json:"token"`
		} `json:"servers"`
		Rules    []models.PolicyRule      `json:"rules"`
		Sessions []models.LearningSession `json:"sessions"`
		Grants   []struct {
			ServerID  string `json:"server_id"`
			Location  string `json:"location"`
			ParentURL string `json:"parent_url"`
			RuleID    string `json:"rule_id"`
			RuleName  string `json:"rule_name"`
		} `json:"grants"`
		Cases []struct {
			Name        string `json:"name"`
			IP          string `json:"ip"`
			Auth        string `json:"auth"`
			Method      string `json:"method"`
			Host        string `json:"host"`
			Path        string `json:"path"`
			Verdict     string `json:"verdict"`
			ServerID    string `json:"server_id"`
			BlockReason *string `json:"block_reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no vectors")
	}
	st := newTestStore(t, t.TempDir(), false)
	now := time.Now().UTC()
	st.mu.Lock()
	st.state.Groups = v.Groups
	st.state.Servers = nil
	for _, s := range v.Servers {
		srv := s.Server
		srv.ProxyAuthTokenHash = engine.HashProxyToken(s.Token)
		st.state.Servers = append(st.state.Servers, srv)
	}
	st.state.PolicySets = nil
	for _, r := range v.Rules {
		r.Enabled, r.Version = true, 1
		groups := r.GroupIDs
		r.GroupIDs = nil
		st.state.PolicySets = append(st.state.PolicySets, models.PolicySet{ID: "ps-" + r.ID, Kind: models.PolicySetKindStandard, Version: 1,
			PolicySetSpec: models.PolicySetSpec{Name: r.Name, Enabled: true, GroupIDs: groups, Rules: []models.PolicyRule{r}}})
	}
	st.state.Sessions = nil
	for _, sess := range v.Sessions {
		sess.Status, sess.StartedAt, sess.ExpiresAt = "active", now, now.Add(time.Hour)
		st.state.Sessions = append(st.state.Sessions, sess)
	}
	st.state.TLSBypass = nil
	st.rebuildIndexLocked()
	st.mu.Unlock()
	for _, g := range v.Grants {
		st.engine.RegisterRedirectGrant(g.ServerID, g.Location, g.ParentURL, g.RuleID, g.RuleName, nil)
	}

	for _, c := range v.Cases {
		res := st.Evaluate(engine.EvaluationRequest{ServerIP: c.IP, ProxyAuthUser: c.Auth, Method: c.Method, Scheme: "https", Host: c.Host,
			Port: 443, Path: c.Path, FullURL: "https://" + c.Host + c.Path})
		if res.Verdict != c.Verdict || res.ServerID != c.ServerID {
			t.Errorf("%s: verdict %s, server %s; want %s, %s (%s)", c.Name, res.Verdict, res.ServerID, c.Verdict, c.ServerID, res.MatchedRuleName)
		}
		if c.BlockReason != nil && res.BlockReason != *c.BlockReason {
			t.Errorf("%s: block reason %q, want %q", c.Name, res.BlockReason, *c.BlockReason)
		}
		if res.Allowed != models.IsAllowedVerdict(c.Verdict) {
			t.Errorf("%s: allowed=%v", c.Name, res.Allowed)
		}
	}
}

// Grants are registered for the server identity the data-plane reported with the flow, not for its address.
func TestRecordedRedirectGrantBelongsToServer(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	res := publishSet(t, st, adminClaims, "CI", []string{"grp-ci"}, models.PolicyRule{Name: "gh", Action: "ALLOW", HostPattern: "github.com",
		PathPattern: "/**", FollowRedirects: true, Enabled: true})
	st.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", ServerID: "srv-ci-1", GroupIDs: []string{"grp-ci"}, Verdict: models.VerdictAllowed,
		MatchedRuleID: res.Rules[0].ID, MatchedRuleName: "gh", Method: "GET", Scheme: "https", Host: "github.com", Path: "/x",
		FullURL: "https://github.com/x", RedirectLocation: "https://objects.example/a", StatusCode: 302})
	if r := evalCI(st, "objects.example", "/a"); r.Verdict != models.VerdictRedirectObject {
		t.Fatalf("owner: %+v", r)
	}
	if _, ok := st.engine.CheckRedirectGrant("10.1.0.5", "objects.example", "/a", "GET"); ok {
		t.Fatal("grant registered for the source address")
	}
	// The same address with another server's credentials (here: an unknown token) never inherits it.
	if r := st.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", ProxyAuthUser: "svc-ci-1:wrong", Method: "GET", Host: "objects.example", Path: "/a"}); r.Allowed ||
		r.Verdict != models.VerdictAuthFailed {
		t.Fatalf("invalid token: %+v", r)
	}
}

func TestRequireProxyTokenGroupValidation(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	if _, err := st.UpsertGroup(models.ServerGroup{ID: "grp-pci", Name: "PCI", CIDRs: []string{"10.70.0.0/16"}, RequireProxyToken: true}, adminClaims); err == nil {
		t.Fatal("require_proxy_token with CIDRs accepted")
	}
	g, err := st.UpsertGroup(models.ServerGroup{ID: "grp-pci", Name: "PCI", RequireProxyToken: true}, adminClaims)
	if err != nil || !g.RequireProxyToken {
		t.Fatalf("require_proxy_token: %v %+v", err, g)
	}
	if _, err := st.UpsertServer(models.Server{ID: "srv-pci-1", Hostname: "pci-1", IP: "10.70.0.5", GroupIDs: []string{"grp-pci"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if id, _, _ := st.ResolveServer("10.70.0.5", ""); id != "srv-unregistered-10.70.0.5" {
		t.Fatalf("address identified a member of a token-only group: %s", id)
	}
	_, tok, err := st.RotateServerToken("srv-pci-1", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	if id := st.Identify("192.0.2.9", tok); id.ID != "srv-pci-1" || id.Method != "token" {
		t.Fatalf("token: %+v", id)
	}
	snap := st.GetSnapshot()
	if !snap.Groups[0].RequireProxyToken {
		t.Fatal("require_proxy_token not persisted")
	}
}
