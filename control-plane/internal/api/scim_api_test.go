package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/oidc/oidctest"
	"aegisproxy/control-plane/internal/store"
)

// Group object IDs as Entra ID sends them (SCIM externalId of a group = its objectId).
const (
	entraInfosecGroup = "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159"
	entraLeadsGroup   = "f1b0b6a1-27b4-4a43-9f53-7e8a2c33a8d2"
)

type scimHarness struct {
	*harness
	token string
	idp   *oidctest.IdP
}

// newSCIMHarness configures single sign-on (mock IdP), the group mapping and SCIM with one token.
func newSCIMHarness(t *testing.T) *scimHarness {
	t.Helper()
	h := newHarness(t)
	idp := oidctest.New("aegis-console", "client-secret-1")
	t.Cleanup(idp.Close)
	h.cfg.PublicURL, h.cfg.DashboardURL = h.srv.URL, h.srv.URL
	h.login(t)
	h.do(t, "POST", "/api/groups", map[string]any{"id": "grp-ci", "name": "CI"}, ui)
	cfg := map[string]any{"enabled": true, "provider": "oidc", "issuer_url": idp.Server.URL, "client_id": "aegis-console",
		"client_secret": "client-secret-1", "allow_local_login": true,
		// Object IDs match the SCIM externalId; Okta-style groups without externalId need name: keys.
		"group_role_map": map[string]string{entraInfosecGroup: "INFOSEC_APPROVER", "name:CI Leads": "TEAM_LEAD_APPROVER",
			"name:Aegis Platform Owners": "SUPER_ADMIN", "name:aegis-auditors": "OPERATOR_AUDITOR"},
		"group_scope_map": map[string][]string{"name:CI Leads": {"grp-ci"}, entraLeadsGroup: {"grp-ci"}}}
	if r := h.do(t, "POST", "/api/settings/entra", cfg, ui); r.StatusCode != 200 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("configure SSO: %d %s", r.StatusCode, b)
	}
	if r := h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": true}, ui); r.StatusCode != 200 {
		t.Fatalf("enable SCIM: %d", r.StatusCode)
	}
	r := h.do(t, "POST", "/api/settings/scim/tokens", map[string]any{"name": "entra-provisioning"}, ui)
	if r.StatusCode != 201 {
		t.Fatalf("create SCIM token: %d", r.StatusCode)
	}
	tok := decode[struct {
		Secret  string `json:"secret"`
		BaseURL string `json:"base_url"`
	}](t, r.Body)
	if !strings.HasPrefix(tok.Secret, "aegis_scim_") || tok.BaseURL != h.srv.URL+"/api/scim/v2" {
		t.Fatalf("token response %+v", tok)
	}
	return &scimHarness{harness: h, token: tok.Secret, idp: idp}
}

// scim sends a SCIM request with the provisioning token.
func (h *scimHarness) scim(t *testing.T, method, path string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	return h.scimAs(t, h.token, method, path, body)
}

func (h *scimHarness) scimAs(t *testing.T, token, method, path string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.srv.URL+"/api/scim/v2"+path, rdr)
	if rdr != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: non-JSON response %d %q", method, path, resp.StatusCode, raw)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/scim+json" {
			t.Errorf("%s %s: Content-Type %q", method, path, ct)
		}
	}
	return resp.StatusCode, out, resp.Header
}

func q(filter string) string { return url.QueryEscape(filter) }

func resources(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	list, _ := body["Resources"].([]any)
	out := []map[string]any{}
	for _, x := range list {
		out = append(out, x.(map[string]any))
	}
	return out
}

func (h *scimHarness) user(t *testing.T, id string) models.User {
	t.Helper()
	u, ok := h.st.GetUserByID(id)
	if !ok {
		t.Fatalf("user %s not in store", id)
	}
	return *u
}

func (h *scimHarness) lastAudit(action string) *models.AuditEvent {
	for _, ev := range h.st.GetSnapshot().AuditEvents {
		if ev.Action == action {
			return &ev
		}
	}
	return nil
}

func TestSCIMAuthentication(t *testing.T) {
	h := newSCIMHarness(t)
	// No credential, a console session cookie or a service-account key are refused.
	st, body, hdr := h.scimAs(t, "", "GET", "/Users", nil)
	if st != 401 || hdr.Get("WWW-Authenticate") == "" || body["schemas"].([]any)[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || body["status"] != "401" {
		t.Errorf("anonymous: %d %v", st, body)
	}
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/scim/v2/Users", nil)
	for _, c := range h.jar {
		req.AddCookie(c)
	}
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("console session accepted by SCIM: %d", resp.StatusCode)
	}
	_, saKey, err := h.st.CreateServiceAccount(store.ServiceAccountInput{Name: "automation", Role: models.RoleInfoSecApprover}, adminClaimsFor(h.harness))
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _ := h.scimAs(t, saKey, "GET", "/Users", nil); st != 401 {
		t.Errorf("service-account key accepted by SCIM: %d", st)
	}
	if st, _, _ := h.scimAs(t, "aegis_scim_forged", "GET", "/Users", nil); st != 401 {
		t.Errorf("forged token: %d", st)
	}
	// ... and the SCIM token is no console credential.
	r := h.do(t, "GET", "/api/state", nil, map[string]string{"Authorization": "Bearer " + h.token})
	if r.StatusCode != 401 {
		h.jar = nil
		t.Errorf("SCIM token accepted by the console API: %d", r.StatusCode)
	}

	// RBAC of the administration endpoints: Super Admins (people) only.
	if _, _, err := h.st.CreateSCIMToken("x", time.Time{}, infosecFor()); err == nil {
		t.Error("InfoSec created a SCIM token")
	}
	if _, err := h.st.UpdateSCIMConfig(false, infosecFor()); err == nil {
		t.Error("InfoSec disabled SCIM")
	}
	if r := h.do(t, "GET", "/api/settings/scim", nil, map[string]string{"Authorization": "Bearer " + saKey}); r.StatusCode != 200 {
		t.Errorf("InfoSec service account cannot view SCIM status: %d", r.StatusCode)
	}
	if r := h.do(t, "POST", "/api/settings/scim/tokens", map[string]any{"name": "sa"}, map[string]string{"Authorization": "Bearer " + saKey}); r.StatusCode != 403 {
		t.Errorf("service account created a SCIM token: %d", r.StatusCode)
	}

	// Rotation revokes the old value, revocation the token; disabled SCIM answers 403.
	status := decode[map[string]any](t, h.do(t, "GET", "/api/settings/scim", nil, nil).Body)
	tokID := status["status"].(map[string]any)["tokens"].([]any)[0].(map[string]any)["id"].(string)
	if _, ok := status["status"].(map[string]any)["tokens"].([]any)[0].(map[string]any)["hash"]; ok {
		t.Error("token digest exposed")
	}
	rot := decode[map[string]any](t, h.do(t, "POST", "/api/settings/scim/tokens/"+tokID+"/rotate", nil, ui).Body)
	if st, _, _ := h.scim(t, "GET", "/Users", nil); st != 401 {
		t.Errorf("rotated token still valid: %d", st)
	}
	h.token = rot["secret"].(string)
	if st, _, _ := h.scim(t, "GET", "/Users", nil); st != 200 {
		t.Errorf("new token: %d", st)
	}
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": false}, ui)
	if st, body, _ := h.scim(t, "GET", "/Users", nil); st != 403 || body["status"] != "403" {
		t.Errorf("disabled SCIM: %d %v", st, body)
	}
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": true}, ui)
	if r := h.do(t, "DELETE", "/api/settings/scim/tokens/"+tokID, nil, ui); r.StatusCode != 200 {
		t.Fatalf("revoke: %d", r.StatusCode)
	}
	if st, _, _ := h.scim(t, "GET", "/Users", nil); st != 401 {
		t.Errorf("revoked token: %d", st)
	}
	for _, a := range []string{"SCIM_TOKEN_CREATED", "SCIM_TOKEN_ROTATED", "SCIM_TOKEN_REVOKED", "SCIM_CONFIG_UPDATED"} {
		if h.lastAudit(a) == nil {
			t.Errorf("audit event %s missing", a)
		}
	}
}

func TestSCIMDiscovery(t *testing.T) {
	h := newSCIMHarness(t)
	st, spc, _ := h.scim(t, "GET", "/ServiceProviderConfig", nil)
	if st != 200 || spc["patch"].(map[string]any)["supported"] != true || spc["bulk"].(map[string]any)["supported"] != false ||
		spc["authenticationSchemes"].([]any)[0].(map[string]any)["type"] != "oauthbearertoken" {
		t.Fatalf("ServiceProviderConfig: %d %v", st, spc)
	}
	st, rts, _ := h.scim(t, "GET", "/ResourceTypes", nil)
	if st != 200 || rts["totalResults"] != float64(2) {
		t.Errorf("ResourceTypes: %v", rts)
	}
	if st, rt, _ := h.scim(t, "GET", "/ResourceTypes/User", nil); st != 200 || rt["endpoint"] != "/Users" {
		t.Errorf("ResourceTypes/User: %v", rt)
	}
	st, schemas, _ := h.scim(t, "GET", "/Schemas", nil)
	if st != 200 || schemas["totalResults"] != float64(3) {
		t.Errorf("Schemas: %v", schemas)
	}
	if st, s, _ := h.scim(t, "GET", "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", nil); st != 200 || s["name"] != "User" {
		t.Errorf("User schema: %d", st)
	}
	for _, p := range []string{"/Schemas/urn:x", "/ResourceTypes/Device", "/Users/does-not-exist", "/Groups/nope", "/0d3c2a8e-unknown"} {
		if st, body, _ := h.scim(t, "GET", p, nil); st != 404 || body["status"] != "404" {
			t.Errorf("GET %s: %d %v", p, st, body)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if st, body, _ := h.scim(t, m, "/ServiceProviderConfig", map[string]any{}); st != 405 || body["status"] != "405" {
			t.Errorf("%s /ServiceProviderConfig: %d %v", m, st, body)
		}
	}
	h.scim(t, "POST", "/Users", map[string]any{"userName": "root-search@corp.example"})
	h.scim(t, "POST", "/Groups", map[string]any{"displayName": "root-search"})
	if st, l, _ := h.scim(t, "POST", "/.search", map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"filter": `userName sw "root" or displayName sw "root"`}); st != 200 || l["totalResults"] != float64(2) {
		t.Errorf("root search: %d %v", st, l)
	}
}

// TestSCIMEntraID replays the requests the Microsoft Entra provisioning service sends (shapes from
// the Entra SCIM documentation: test connection, user create with the enterprise extension, group
// create, member add/remove, attribute PATCH incl. "False" as a string, delete).
func TestSCIMEntraID(t *testing.T) {
	h := newSCIMHarness(t)

	// "Test connection": a filter for a random userName must return an empty list.
	st, list, _ := h.scim(t, "GET", "/Users?filter="+q(`userName eq "non-existent user"`), nil)
	if st != 200 || list["totalResults"] != float64(0) || len(resources(t, list)) != 0 {
		t.Fatalf("test connection: %d %v", st, list)
	}

	const oid = "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"
	createUser := `{
	  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
	  "externalId": "` + oid + `",
	  "userName": "Test_User_ab6490ee@contoso.com",
	  "active": true,
	  "emails": [{"primary": true, "type": "work", "value": "Test_User_fd0ea19b@contoso.com"}],
	  "meta": {"resourceType": "User"},
	  "name": {"formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName"},
	  "title": "Security Engineer",
	  "roles": [],
	  "phoneNumbers": [{"type": "work", "value": "+1 425 555 0100"}],
	  "addresses": [{"type": "work", "country": "US"}],
	  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Security", "employeeNumber": "1234", "manager": {"value": "abc"}}
	}`
	st, u, hdr := h.scim(t, "POST", "/Users", createUser)
	if st != 201 {
		t.Fatalf("create user: %d %v", st, u)
	}
	uid := u["id"].(string)
	if hdr.Get("Location") != h.srv.URL+"/api/scim/v2/Users/"+uid || hdr.Get("ETag") == "" || u["userName"] != "Test_User_ab6490ee@contoso.com" ||
		u["externalId"] != oid || u["active"] != true || u["title"] != "Security Engineer" ||
		u["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)["department"] != "Security" {
		t.Fatalf("created user: %v %v", u, hdr)
	}
	cu := h.user(t, uid)
	if cu.AuthProvider != "oidc" || cu.Username != "test_user_ab6490ee.contoso.com" || cu.Email != "Test_User_fd0ea19b@contoso.com" ||
		cu.Department != "Security" || !cu.Disabled || cu.Role != "" {
		t.Fatalf("console account without a mapped group: %+v", cu)
	}
	if st, _, _ := h.scim(t, "POST", "/Users", createUser); st != 409 {
		t.Errorf("duplicate userName: %d", st)
	}
	// Matching queries Entra ID issues (userName is case-insensitive, externalId case-exact).
	for _, f := range []string{`userName eq "test_user_AB6490EE@contoso.com"`, `externalId eq "` + oid + `"`,
		`emails[type eq "work"].value eq "Test_User_fd0ea19b@contoso.com"`, `userName sw "Test" and active eq true`} {
		if _, l, _ := h.scim(t, "GET", "/Users?filter="+q(f), nil); l["totalResults"] != float64(1) {
			t.Errorf("filter %s: %v", f, l)
		}
	}
	if _, l, _ := h.scim(t, "GET", "/Users?filter="+q(`externalId eq "`+strings.ToUpper(oid)+`"`), nil); l["totalResults"] != float64(0) {
		t.Error("externalId must be compared case-exactly")
	}

	// Group create (externalId = objectId) and member add.
	st, g, _ := h.scim(t, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"`+entraInfosecGroup+`","displayName":"AegisProxy InfoSec","meta":{"resourceType":"Group"}}`)
	if st != 201 {
		t.Fatalf("create group: %d %v", st, g)
	}
	gid := g["id"].(string)
	st, gl, _ := h.scim(t, "GET", "/Groups?excludedAttributes=members&filter="+q(`displayName eq "AegisProxy InfoSec"`), nil)
	if st != 200 || gl["totalResults"] != float64(1) {
		t.Fatalf("group lookup: %v", gl)
	}
	st, g, _ = h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"members","value":[{"value":"`+uid+`"}]}]}`)
	if st != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("add member: %d %v", st, g)
	}
	cu = h.user(t, uid)
	if cu.Disabled || cu.Role != models.RoleInfoSecApprover || cu.AllowedGroups[0] != "*" {
		t.Fatalf("role from SCIM group externalId: %+v", cu)
	}
	_, u, _ = h.scim(t, "GET", "/Users/"+uid, nil)
	if grp := u["groups"].([]any)[0].(map[string]any); grp["value"] != gid || grp["display"] != "AegisProxy InfoSec" {
		t.Errorf("user groups attribute: %v", u["groups"])
	}

	// First single sign-on of the provisioned user lands on the same account (oid = externalId).
	h.idp.User = map[string]any{"sub": oid, "preferred_username": "Test_User_ab6490ee@contoso.com", "name": "Entra User", "groups": []string{"unrelated"}}
	h.idp.Tamper = func(c map[string]any) { c["sub"] = oid }
	resp, cookies := h.ssoLogin(t)
	h.idp.Tamper = nil
	if strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatalf("SSO after SCIM provisioning: %s", resp.Header.Get("Location"))
	}
	session := sessionFrom(cookies)
	me := h.meWith(t, session)
	if me.ID != uid || me.Role != models.RoleInfoSecApprover {
		t.Fatalf("SSO landed on %s (%s), want SCIM account %s: the token's groups must not override SCIM", me.ID, me.Role, uid)
	}
	if h.lastAudit("USER_LINKED_SSO") == nil {
		t.Error("USER_LINKED_SSO not audited")
	}

	// Attribute updates as Entra ID sends them.
	st, u, _ = h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	  {"op":"Replace","path":"displayName","value":"Updated Name"},
	  {"op":"Replace","path":"emails[type eq \"work\"].value","value":"updatedEmail@contoso.com"},
	  {"op":"Replace","path":"name.familyName","value":"updatedFamilyName"},
	  {"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Cyber Defense"},
	  {"op":"Add","path":"phoneNumbers[type eq \"mobile\"].value","value":"+1 555"},
	  {"op":"Replace","path":"title","value":"Lead"}]}`)
	if st != 200 || u["displayName"] != "Updated Name" || u["emails"].([]any)[0].(map[string]any)["value"] != "updatedEmail@contoso.com" ||
		u["name"].(map[string]any)["familyName"] != "updatedFamilyName" || u["name"].(map[string]any)["givenName"] != "givenName" {
		t.Fatalf("patch attributes: %d %v", st, u)
	}
	if cu = h.user(t, uid); cu.DisplayName != "Updated Name" || cu.Email != "updatedEmail@contoso.com" || cu.Department != "Cyber Defense" {
		t.Errorf("console account after patch: %+v", cu)
	}
	if h.meWith(t, session).ID != uid {
		t.Error("profile update revoked the session")
	}

	// Disable (Entra may send the boolean as a string): immediate session revocation.
	st, u, _ = h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if st != 200 || u["active"] != false {
		t.Fatalf("deactivate: %d %v", st, u)
	}
	if code := h.meStatus(t, session); code != 401 {
		t.Errorf("session after SCIM deactivation: %d", code)
	}
	if ev := h.lastAudit("USER_DEPROVISIONED_SCIM"); ev == nil || ev.EntityID != uid || !strings.Contains(ev.Summary, "active=false") {
		t.Errorf("deprovisioning audit: %+v", ev)
	}
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=account_disabled") {
		t.Errorf("deactivated user signed in: %s", resp.Header.Get("Location"))
	}
	h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":true}]}`)
	if cu = h.user(t, uid); cu.Disabled || h.lastAudit("USER_REACTIVATED_SCIM") == nil {
		t.Errorf("reactivation: %+v", cu)
	}

	// Removing the member (Entra: remove with a value list) takes the role away at once.
	_, cookies = h.ssoLogin(t)
	session = sessionFrom(cookies)
	st, g, _ = h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Remove","path":"members","value":[{"value":"`+uid+`"}]}]}`)
	if st != 200 || g["members"] != nil {
		t.Fatalf("remove member: %d %v", st, g)
	}
	if cu = h.user(t, uid); !cu.Disabled || h.meStatus(t, session) != 401 {
		t.Errorf("member removal did not revoke access: %+v", cu)
	}

	// Delete: account disabled, no SCIM resource any more, record kept for the audit trail.
	h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"members","value":[{"value":"`+uid+`"}]}]}`)
	if st, _, _ := h.scim(t, "DELETE", "/Users/"+uid, nil); st != 204 {
		t.Fatalf("delete user: %d", st)
	}
	if st, _, _ := h.scim(t, "GET", "/Users/"+uid, nil); st != 404 {
		t.Errorf("deleted user still served: %d", st)
	}
	if _, g, _ = h.scim(t, "GET", "/Groups/"+gid, nil); g["members"] != nil {
		t.Errorf("deleted user still a member: %v", g["members"])
	}
	if cu = h.user(t, uid); !cu.Disabled || cu.SCIM == nil || !cu.SCIM.Deleted {
		t.Errorf("deleted account: %+v", cu)
	}
	resp, _ = h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=account_disabled") {
		t.Errorf("deleted user signed in: %s", resp.Header.Get("Location"))
	}
	// Provisioning the same person again revives the account (one account, one audit trail).
	st, u, _ = h.scim(t, "POST", "/Users", createUser)
	if st != 201 || u["id"] != uid {
		t.Errorf("re-provisioning: %d id %v want %s", st, u["id"], uid)
	}
	if st, _, _ := h.scim(t, "DELETE", "/Groups/"+gid, nil); st != 204 {
		t.Errorf("delete group: %d", st)
	}
}

// TestSCIMOkta replays Okta's provisioning requests (SCIM 2.0 test app): user create with password
// and groups attributes, PUT updates, path-less PATCH deactivation, Group Push with rename via
// "replace" carrying the id, and member add/remove with value filters.
func TestSCIMOkta(t *testing.T) {
	h := newSCIMHarness(t)
	if st, l, _ := h.scim(t, "GET", "/Users?filter="+q(`userName eq "isabella.ruiz@corp.example"`)+"&startIndex=1&count=100", nil); st != 200 || l["totalResults"] != float64(0) {
		t.Fatalf("Okta lookup: %d %v", st, l)
	}
	st, u, _ := h.scim(t, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"isabella.ruiz@corp.example",
	  "name":{"givenName":"Isabella","familyName":"Ruiz"},"emails":[{"primary":true,"value":"isabella.ruiz@corp.example","type":"work"}],
	  "displayName":"Isabella Ruiz","locale":"en-US","externalId":"00ujl29u0le5T6Aj10h7","groups":[],"password":"1mz050nq","active":true}`)
	if st != 201 {
		t.Fatalf("Okta create: %d %v", st, u)
	}
	uid := u["id"].(string)
	if _, has := u["password"]; has {
		t.Fatal("password echoed")
	}
	raw, _ := json.Marshal(h.st.GetSnapshot().Users)
	if strings.Contains(string(raw), "1mz050nq") {
		t.Fatal("SCIM password stored")
	}

	// Group Push: create, rename (replace with id in the value), add member.
	st, g, _ := h.scim(t, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"CI Lead (old)","members":[]}`)
	if st != 201 {
		t.Fatalf("Okta group: %d %v", st, g)
	}
	gid := g["id"].(string)
	st, g, _ = h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"id":"`+gid+`","displayName":"CI Leads"}}]}`)
	if st != 200 || g["displayName"] != "CI Leads" {
		t.Fatalf("Okta rename: %d %v", st, g)
	}
	st, _, _ = h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"`+uid+`","display":"isabella.ruiz@corp.example"}]}]}`)
	if cu := h.user(t, uid); st != 200 || cu.Role != models.RoleTeamLead || len(cu.AllowedGroups) != 1 || cu.AllowedGroups[0] != "grp-ci" || cu.Disabled {
		t.Fatalf("Team Lead with scope from SCIM group name: %d %+v", st, cu)
	}
	if _, l, _ := h.scim(t, "GET", "/Groups?filter="+q(`displayName eq "CI Leads"`)+"&startIndex=1&count=100", nil); l["totalResults"] != float64(1) {
		t.Errorf("Okta group lookup: %v", l)
	}

	// PUT (profile update) keeps membership and role.
	st, u, _ = h.scim(t, "PUT", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"`+uid+`","userName":"isabella.ruiz@corp.example",
	  "name":{"givenName":"Isabella","familyName":"Ruiz-Garcia"},"emails":[{"primary":true,"value":"isabella.ruiz@corp.example","type":"work"}],
	  "displayName":"Isabella Ruiz-Garcia","externalId":"00ujl29u0le5T6Aj10h7","active":true}`)
	if st != 200 || u["displayName"] != "Isabella Ruiz-Garcia" || h.user(t, uid).Role != models.RoleTeamLead {
		t.Fatalf("Okta PUT: %d %v", st, u)
	}
	// SSO after SCIM: the Okta user id (externalId) is the sub claim.
	h.idp.User = map[string]any{"preferred_username": "isabella.ruiz@corp.example", "groups": []string{}}
	h.idp.Tamper = func(c map[string]any) { c["sub"] = "00ujl29u0le5T6Aj10h7" }
	resp, cookies := h.ssoLogin(t)
	h.idp.Tamper = nil
	session := sessionFrom(cookies)
	if me := h.meWith(t, session); strings.Contains(resp.Header.Get("Location"), "sso_error") || me.ID != uid || me.Role != models.RoleTeamLead {
		t.Fatalf("Okta SSO after SCIM: %s %+v", resp.Header.Get("Location"), me)
	}

	// Deactivation: path-less replace.
	st, u, _ = h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if st != 200 || u["active"] != false || !h.user(t, uid).Disabled || h.meStatus(t, session) != 401 {
		t.Fatalf("Okta deactivate: %d %v", st, u)
	}
	h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":true}}]}`)
	// Member removal with a value filter.
	st, g, _ = h.scim(t, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"`+uid+`\"]"}]}`)
	if st != 200 || g["members"] != nil || !h.user(t, uid).Disabled {
		t.Fatalf("Okta member removal: %d %v %+v", st, g, h.user(t, uid))
	}
	// Group PUT with members; renaming to a mapped name grants the mapped role.
	st, g, _ = h.scim(t, "PUT", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"aegis-auditors","members":[{"value":"`+uid+`"}]}`)
	if st != 200 || h.user(t, uid).Role != models.RoleAuditorOperator {
		t.Fatalf("group PUT: %d %v %+v", st, g, h.user(t, uid))
	}
}

func TestSCIMSafety(t *testing.T) {
	h := newSCIMHarness(t)
	admin := h.st.GetSnapshot().Users[0]

	// A SCIM userName equal to a local account never takes it over.
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "admin", "active": true})
	if st != 201 || u["id"] == admin.ID {
		t.Fatalf("local account claimed: %d %v", st, u)
	}
	if cu := h.user(t, u["id"].(string)); cu.Username == "admin" || !strings.HasPrefix(cu.Username, "admin-") {
		t.Errorf("username collision handling: %q", cu.Username)
	}
	if st, _, _ := h.scim(t, "GET", "/Users/"+admin.ID, nil); st != 404 {
		t.Errorf("local account is a SCIM resource: %d", st)
	}
	if st, _, _ := h.scim(t, "PATCH", "/Users/"+admin.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`); st != 404 {
		t.Errorf("local account patched: %d", st)
	}
	if st, _, _ := h.scim(t, "DELETE", "/Users/"+admin.ID, nil); st != 404 {
		t.Errorf("local account deleted: %d", st)
	}
	_, all, _ := h.scim(t, "GET", "/Users", nil)
	for _, r := range resources(t, all) {
		if r["id"] == admin.ID {
			t.Error("local account listed")
		}
	}
	// Local accounts in group members are ignored: no SCIM group can change a local role.
	st, g, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Aegis Platform Owners", "members": []map[string]string{{"value": admin.ID}, {"value": u["id"].(string)}}})
	if st != 201 || len(g["members"].([]any)) != 1 {
		t.Fatalf("group with a local member: %d %v", st, g)
	}
	if a, _ := h.st.GetUserByID(admin.ID); a.Disabled || a.Role != models.RoleSuperAdmin || a.AuthProvider != "local" {
		t.Errorf("local admin modified: %+v", a)
	}
	// Super Admin only through an explicit mapping.
	if cu := h.user(t, u["id"].(string)); cu.Role != models.RoleSuperAdmin {
		t.Errorf("mapped Super Admin group: %+v", cu)
	}
	st, other, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "nobody@corp.example"})
	h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Everyone", "members": []map[string]string{{"value": other["id"].(string)}}})
	if cu := h.user(t, other["id"].(string)); st != 201 || cu.Role != "" || !cu.Disabled {
		t.Errorf("member of an unmapped group got access: %+v", cu)
	}

	// Changing the SSO group mapping re-applies roles to SCIM-managed accounts immediately.
	cfg := h.st.SSOSettings("")
	cfg.GroupRoleMap = map[string]models.Role{"name:Aegis Platform Owners": models.RoleAuditorOperator, "name:Everyone": models.RoleAuditorOperator}
	cfg.ClientSecret = ""
	if err := h.st.UpdateEntraConfig(cfg, adminClaimsFor(h.harness)); err != nil {
		t.Fatal(err)
	}
	if cu := h.user(t, u["id"].(string)); cu.Role != models.RoleAuditorOperator {
		t.Errorf("mapping change not applied: %+v", cu)
	}
	if cu := h.user(t, other["id"].(string)); cu.Disabled || cu.Role != models.RoleAuditorOperator {
		t.Errorf("mapping change did not enable: %+v", cu)
	}

	// Administrators can lock a SCIM-managed account (incident response); SCIM cannot lift the lock,
	// and an administrator cannot enable an account the IdP deactivated.
	oid := other["id"].(string)
	cu := h.user(t, oid)
	in := store.UserInput{ID: oid, Username: cu.Username, DisplayName: cu.DisplayName, Email: cu.Email, Role: cu.Role, AllowedGroups: cu.AllowedGroups, Disabled: true}
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h.harness)); err != nil {
		t.Fatal(err)
	}
	h.scim(t, "PATCH", "/Users/"+oid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`)
	if cu = h.user(t, oid); !cu.Disabled || !cu.DisabledByAdmin {
		t.Errorf("SCIM lifted an administrator lock: %+v", cu)
	}
	h.scim(t, "PATCH", "/Users/"+oid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	in.Disabled = false
	if _, _, err := h.st.UpsertUser(in, adminClaimsFor(h.harness)); err != nil {
		t.Fatal(err)
	}
	if cu = h.user(t, oid); !cu.Disabled || cu.DisabledByAdmin {
		t.Errorf("administrator enabled an account the IdP deactivated: %+v", cu)
	}
	st, nr, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "norole@corp.example"})
	nu := h.user(t, nr["id"].(string))
	if _, _, err := h.st.UpsertUser(store.UserInput{ID: nu.ID, Username: nu.Username, DisplayName: "No Role", Role: "", AllowedGroups: []string{}, Disabled: true}, adminClaimsFor(h.harness)); st != 201 || err != nil {
		t.Errorf("editing a role-less SCIM account: %v", err)
	}
	if _, _, err := h.st.UpsertUser(store.UserInput{Username: "x-norole", DisplayName: "x", Role: ""}, adminClaimsFor(h.harness)); err == nil {
		t.Error("local user without role created")
	}

	// Validation errors use the SCIM error format.
	for name, body := range map[string]string{
		"missing userName": `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"x"}`,
		"bad active":       `{"userName":"a1@x","active":"maybe"}`,
		"bad emails":       `{"userName":"a2@x","emails":"x@y"}`,
		"control chars":    `{"userName":"a3\u0007@x"}`,
		"invalid JSON":     `{"userName":`,
	} {
		if st, body, _ := h.scim(t, "POST", "/Users", body); st != 400 || body["status"] != "400" {
			t.Errorf("%s: %d %v", name, st, body)
		}
	}
	if st, body, _ := h.scim(t, "GET", "/Users?filter="+q(`userName eq`), nil); st != 400 || body["scimType"] != "invalidFilter" {
		t.Errorf("invalid filter: %d %v", st, body)
	}
	if st, body, _ := h.scim(t, "PATCH", "/Users/"+other["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"id","value":"x"}]}`); st != 400 || body["scimType"] != "mutability" {
		t.Errorf("patch of id: %d %v", st, body)
	}
	if st, _, _ := h.scim(t, "PATCH", "/Users/"+other["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"move","path":"title","value":"x"}]}`); st != 400 {
		t.Errorf("unknown op: %d", st)
	}
	if st, _, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "everyone"}); st != 409 {
		t.Errorf("duplicate group name: %d", st)
	}
}

func TestSCIMListAndETags(t *testing.T) {
	h := newSCIMHarness(t)
	for i := range 7 {
		if st, _, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": fmt.Sprintf("user%d@corp.example", i), "displayName": fmt.Sprintf("User %d", i)}); st != 201 {
			t.Fatal("create")
		}
	}
	_, page, _ := h.scim(t, "GET", "/Users?startIndex=3&count=2", nil)
	rs := resources(t, page)
	if page["totalResults"] != float64(7) || page["itemsPerPage"] != float64(2) || page["startIndex"] != float64(3) || rs[0]["userName"] != "user2@corp.example" {
		t.Fatalf("pagination: %v", page)
	}
	if _, p, _ := h.scim(t, "GET", "/Users?count=0", nil); p["totalResults"] != float64(7) || len(resources(t, p)) != 0 {
		t.Errorf("count=0: %v", p)
	}
	if st, _, _ := h.scim(t, "GET", "/Users?count=abc", nil); st != 400 {
		t.Errorf("invalid count: %d", st)
	}
	_, p, _ := h.scim(t, "GET", "/Users?attributes=userName&filter="+q(`displayName co "User 5" or userName eq "user6@corp.example"`), nil)
	rs = resources(t, p)
	if len(rs) != 2 || rs[0]["displayName"] != nil || rs[0]["userName"] == nil || rs[0]["id"] == nil {
		t.Errorf("attributes projection: %v", p)
	}
	_, p, _ = h.scim(t, "GET", "/Users?excludedAttributes=meta,displayName&filter="+q(`not (userName ne "user1@corp.example")`), nil)
	if rs = resources(t, p); len(rs) != 1 || rs[0]["meta"] != nil || rs[0]["displayName"] != nil {
		t.Errorf("excludedAttributes / not: %v", p)
	}
	_, p, _ = h.scim(t, "POST", "/Users/.search", map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"filter": `userName ew "@corp.example"`, "count": 3, "attributes": []string{"userName"}})
	if p["totalResults"] != float64(7) || len(resources(t, p)) != 3 {
		t.Errorf(".search: %v", p)
	}

	// ETags: If-None-Match -> 304, If-Match mismatch -> 412.
	rs = resources(t, page)
	id := rs[0]["id"].(string)
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/scim/v2/Users/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, _ := http.DefaultClient.Do(req)
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	req.Header.Set("If-None-Match", etag)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 304 {
		t.Errorf("If-None-Match: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("PATCH", h.srv.URL+"/api/scim/v2/Users/"+id, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"x"}]}`))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("If-Match", `W/"999"`)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 412 {
		t.Errorf("If-Match mismatch: %d", resp.StatusCode)
	}
	status := decode[map[string]any](t, h.do(t, "GET", "/api/settings/scim", nil, nil).Body)["status"].(map[string]any)
	if status["users"] != float64(7) || status["last_sync_at"] == nil || status["last_request_at"] == nil {
		t.Errorf("SCIM status: %v", status)
	}
}

// TestSCIMClaimsJITAccount: SSO users that signed in before SCIM was set up are taken over, not
// duplicated.
func TestSCIMClaimsJITAccount(t *testing.T) {
	h := newSCIMHarness(t)
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": false}, ui)
	h.idp.User = map[string]any{"preferred_username": "dana@corp.example", "groups": []string{"aegis-auditors"}}
	resp, cookies := h.ssoLogin(t)
	if strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatal(resp.Header.Get("Location"))
	}
	jit := h.meWith(t, sessionFrom(cookies))
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": true}, ui)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "dana@corp.example", "externalId": "subject-1", "active": true})
	if st != 201 || u["id"] != jit.ID {
		t.Fatalf("JIT account not claimed: %d %v (jit %s)", st, u["id"], jit.ID)
	}
	if h.lastAudit("USER_LINKED_SCIM") == nil {
		t.Error("USER_LINKED_SCIM not audited")
	}
	h.scim(t, "POST", "/Groups", map[string]any{"displayName": "aegis-auditors", "members": []map[string]string{{"value": jit.ID}}})
	resp, cookies = h.ssoLogin(t)
	if me := h.meWith(t, sessionFrom(cookies)); me.ID != jit.ID || me.Role != models.RoleAuditorOperator || strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatalf("SSO after claim: %+v %s", me, resp.Header.Get("Location"))
	}
}

func sessionFrom(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func (h *scimHarness) meStatus(t *testing.T, session *http.Cookie) int {
	t.Helper()
	if session == nil {
		t.Fatal("no session cookie")
	}
	saved := h.jar
	h.jar = []*http.Cookie{session}
	defer func() { h.jar = saved }()
	return h.do(t, "GET", "/api/auth/me", nil, nil).StatusCode
}

func (h *scimHarness) meWith(t *testing.T, session *http.Cookie) models.User {
	t.Helper()
	if session == nil {
		t.Fatal("no session cookie")
	}
	saved := h.jar
	h.jar = []*http.Cookie{session}
	defer func() { h.jar = saved }()
	return decode[struct {
		User models.User `json:"user"`
	}](t, h.do(t, "GET", "/api/auth/me", nil, nil).Body).User
}

func TestSCIMTokenGuessingIsThrottled(t *testing.T) {
	h := newSCIMHarness(t)
	limited := false
	for i := 0; i < 30; i++ {
		st, _, hdr := h.scimAs(t, fmt.Sprintf("aegis_scim_guess%02d", i), "GET", "/Users", nil)
		if st == 429 {
			limited = hdr.Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Fatal("failed SCIM authentications are not throttled")
	}
}
