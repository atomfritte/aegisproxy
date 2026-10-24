package store

import (
	"slices"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func TestDLPOversizeAction(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	if got := st.SecurityPolicy().DLPOversizeAction; got != "allow" {
		t.Fatalf("default dlp_oversize_action = %q", got)
	}
	p := st.SecurityPolicy()
	p.DLPOversizeAction = "maybe"
	if _, err := st.UpdateSecurityPolicy(p, adminClaims); err == nil {
		t.Fatal("invalid dlp_oversize_action accepted")
	}
	p.DLPOversizeAction = "block"
	if saved, err := st.UpdateSecurityPolicy(p, adminClaims); err != nil || saved.DLPOversizeAction != "block" {
		t.Fatalf("block: %v %q", err, saved.DLPOversizeAction)
	}
	p.DLPOversizeAction = "" // API clients that predate the field keep the default
	if saved, err := st.UpdateSecurityPolicy(p, adminClaims); err != nil || saved.DLPOversizeAction != "allow" {
		t.Fatalf("omitted: %v %q", err, saved.DLPOversizeAction)
	}
}

func TestRedirectHostsLimitGrants(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	for _, bad := range [][]string{{"https://cdn.example/"}, {"*"}, {"a*.cdn.example"}} {
		_, err := st.CreatePolicySet("", models.PolicySetSpec{Name: "bad", Enabled: true, GroupIDs: []string{"grp-ci"},
			Rules: []models.PolicyRule{{Name: "gh", Action: "ALLOW", HostPattern: "github.com", FollowRedirects: true, RedirectHosts: bad, Enabled: true}}}, adminClaims)
		if err == nil {
			t.Fatalf("redirect_hosts %q accepted", bad)
		}
	}
	set := publishSet(t, st, adminClaims, "CI", []string{"grp-ci"}, models.PolicyRule{Name: "gh", Action: "ALLOW", HostPattern: "github.com",
		PathPattern: "/**", FollowRedirects: true, RedirectHosts: []string{" *.CDN.example ", "", "*.cdn.example"}, Enabled: true})
	if got := set.Rules[0].RedirectHosts; !slices.Equal(got, []string{"*.cdn.example"}) {
		t.Fatalf("normalized redirect_hosts = %q", got)
	}
	res := evalCI(st, "github.com", "/x")
	if !res.Allowed || !res.FollowRedirects {
		t.Fatalf("rule not effective: %+v", res)
	}
	for _, loc := range []string{"https://objects.other.example/a", "https://eu.cdn.example/a"} {
		st.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Verdict: models.VerdictAllowed, MatchedRuleID: res.MatchedRuleID,
			MatchedRuleName: res.MatchedRuleName, Method: "GET", Scheme: "https", Host: "github.com", Path: "/x",
			FullURL: "https://github.com/x", RedirectLocation: loc, StatusCode: 302})
	}
	if r := evalCI(st, "objects.other.example", "/a"); r.Allowed {
		t.Fatalf("grant for a host outside redirect_hosts: %+v", r)
	}
	if r := evalCI(st, "eu.cdn.example", "/a"); r.Verdict != models.VerdictRedirectObject {
		t.Fatalf("listed redirect host: %+v", r)
	}
}
