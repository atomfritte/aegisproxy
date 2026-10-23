package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc/oidctest"
	"aegisproxy/control-plane/internal/store"
)

// ssoLogin runs the browser flow: /sso/login -> IdP /authorize -> /sso/callback, following redirects manually.
func (h *harness) ssoLogin(t *testing.T) (*http.Response, []*http.Cookie) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(h.srv.URL + "/api/auth/sso/login?next=/policies")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("login start: %d", resp.StatusCode)
	}
	stateCookies := resp.Cookies()
	authz, _ := client.Get(resp.Header.Get("Location"))
	authz.Body.Close()
	cb := authz.Header.Get("Location")
	cbURL, _ := url.Parse(cb)
	req, _ := http.NewRequest("GET", h.srv.URL+cbURL.RequestURI(), nil)
	for _, c := range stateCookies {
		req.AddCookie(c)
	}
	final, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	final.Body.Close()
	return final, final.Cookies()
}

func TestSingleSignOn(t *testing.T) {
	h := newHarness(t)
	idp := oidctest.New("aegis-console", "client-secret-1")
	defer idp.Close()
	h.cfg.PublicURL = h.srv.URL
	h.cfg.DashboardURL = h.srv.URL
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI"}, ui)
	cfg := map[string]any{"enabled": true, "provider": "oidc", "display_name": "Corp SSO", "issuer_url": idp.Server.URL,
		"client_id": "aegis-console", "client_secret": "client-secret-1", "allow_local_login": true,
		"group_role_map":  map[string]string{"aegis-admins": "INFOSEC_APPROVER", "aegis-ci-leads": "TEAM_LEAD_APPROVER"},
		"group_scope_map": map[string][]string{"aegis-ci-leads": {"grp-ci"}}}
	if r := h.do(t, "POST", "/api/settings/entra", cfg, ui); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("configure: %d %s", r.StatusCode, b)
	}
	state := decode[map[string]any](t, h.do(t, "GET", "/api/state?exclude_flows=1", nil, nil).Body)
	ec := state["entra_config"].(map[string]any)
	if v, ok := ec["client_secret"].(string); (ok && v != "") || ec["has_client_secret"] != true {
		t.Fatalf("client secret handling in API: %+v", ec)
	}
	if test := decode[map[string]any](t, h.do(t, "POST", "/api/settings/sso/test", map[string]any{}, ui).Body); test["ok"] != true {
		t.Fatalf("connectivity test: %+v", test)
	}

	// Team lead via group mapping.
	idp.User = map[string]any{"preferred_username": "alex@corp.example", "name": "Alex", "email": "alex@corp.example", "groups": []string{"aegis-ci-leads", "unrelated"}}
	resp, cookies := h.ssoLogin(t)
	if resp.StatusCode != 302 || !strings.HasSuffix(resp.Header.Get("Location"), "/policies") {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookie && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie after SSO")
	}
	saved := h.jar
	h.jar = []*http.Cookie{session}
	me := decode[struct {
		User models.User `json:"user"`
	}](t, h.do(t, "GET", "/api/auth/me", nil, nil).Body).User
	h.jar = saved
	if me.Role != models.RoleTeamLead || len(me.AllowedGroups) != 1 || me.AllowedGroups[0] != "grp-ci" || me.AuthProvider != "oidc" || me.Username != "alex.corp.example" {
		t.Fatalf("provisioned user: %+v", me)
	}

	// Removing the group in the IdP denies the next login and disables the account.
	idp.User["groups"] = []string{"unrelated"}
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=not_authorized") {
		t.Fatalf("unmapped user: %s", resp.Header.Get("Location"))
	}
	h.jar = []*http.Cookie{session}
	if r := h.do(t, "GET", "/api/state", nil, nil); r.StatusCode != 401 {
		t.Errorf("session of deprovisioned user still valid: %d", r.StatusCode)
	}
	h.jar = saved
	if ev := h.st.GetSnapshot().AuditEvents[0]; ev.Action != "USER_DEPROVISIONED_SSO" || ev.EntityID != me.ID {
		t.Errorf("deprovisioning not audited: %+v", ev)
	}

	// A manual lock-out by an administrator survives the next single sign-on (incident response).
	idp.User["groups"] = []string{"aegis-ci-leads"}
	h.ssoLogin(t)
	u, _ := h.st.GetUserByID(me.ID)
	in := store.UserInput{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Role: u.Role,
		AllowedGroups: u.AllowedGroups, Disabled: true}
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=account_disabled") {
		t.Fatalf("admin-disabled SSO user signed in again: %s", resp.Header.Get("Location"))
	}
	if u, _ := h.st.GetUserByID(me.ID); !u.Disabled {
		t.Fatal("lock-out lifted by single sign-on")
	}

	// Forged / replayed callbacks are rejected.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := client.Get(h.srv.URL + "/api/auth/sso/callback?code=x&state=y")
	if !strings.Contains(r.Header.Get("Location"), "sso_error=session") {
		t.Errorf("callback without state cookie: %s", r.Header.Get("Location"))
	}
	idp.User["groups"] = []string{"aegis-admins"}
	idp.Tamper = func(c map[string]any) { c["aud"] = "someone-else" }
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=id_token") {
		t.Errorf("token for another audience: %s", resp.Header.Get("Location"))
	}
	idp.Tamper = nil

	// Password login can only be disabled with a break-glass account; then only it may use a password.
	cfg["allow_local_login"] = false
	if r := h.do(t, "POST", "/api/settings/entra", cfg, ui); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("disable local login: %d %s", r.StatusCode, b) // bootstrap admin is break-glass
	}
	if _, _, err := h.st.UpsertUser(storeUserInput("auditor1", models.RoleAuditorOperator), adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	if r := h.do(t, "POST", "/api/auth/login", map[string]string{"username": "auditor1", "password": "Ops-Password-123!"}, ui); r.StatusCode != 401 {
		t.Errorf("non break-glass password login: %d", r.StatusCode)
	}
	h.login(t) // break-glass admin still works
	if r := h.do(t, "GET", "/api/public/meta", nil, nil); r.StatusCode != 200 {
		t.Error("meta")
	}
	// InfoSec cannot reconfigure SSO (would allow mapping itself to Super Admin).
	if err := h.st.UpdateEntraConfig(models.EntraIDConfig{Enabled: true}, infosecFor()); err == nil {
		t.Error("InfoSec changed SSO configuration")
	}
}

func storeUserInput(name string, role models.Role) store.UserInput {
	return store.UserInput{Username: name, DisplayName: name, Role: role, Password: "Ops-Password-123!"}
}

func adminClaimsFor(h *harness) *auth.TokenClaims {
	return &auth.TokenClaims{UserID: "usr-admin", Username: "admin", Role: models.RoleSuperAdmin, AllowedGroups: []string{"*"}}
}

func infosecFor() *auth.TokenClaims {
	return &auth.TokenClaims{UserID: "u-is", Username: "infosec", Role: models.RoleInfoSecApprover, AllowedGroups: []string{"*"}}
}
