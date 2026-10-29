package api

import (
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// Round-3 finding R3-1: an SSO identity whose username claim equals the userName of a SCIM-provisioned
// account that has not signed in yet must not take that account over. Linking uses the immutable user ID
// (SCIM externalId = token subject) only; a name match without it refuses the sign-in.
func TestSSODoesNotLinkSCIMAccountByUsername(t *testing.T) {
	h := newSCIMHarness(t)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "victimadmin", "externalId": "real-subject", "active": true})
	if st != 201 {
		t.Fatalf("provision: %d %v", st, u)
	}
	uid := u["id"].(string)
	if st, g, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Aegis Platform Owners",
		"members": []map[string]string{{"value": uid}}}); st != 201 {
		t.Fatalf("group: %d %v", st, g)
	}
	if v := h.user(t, uid); v.Role != models.RoleSuperAdmin || v.ExternalID != "" {
		t.Fatalf("provisioned account: %+v", v)
	}

	for _, groups := range [][]string{{"attacker-personal-group"}, {entraInfosecGroup}} {
		h.idp.User = map[string]any{"sub": "attacker-sub-99999", "preferred_username": "victimadmin", "email": "attacker@evil.example", "groups": groups}
		resp, cookies := h.ssoLogin(t)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error=account_link") {
			t.Fatalf("groups %v: sign-in with another subject and the provisioned userName: %s", groups, loc)
		}
		if sessionFrom(cookies) != nil {
			t.Fatalf("groups %v: session issued", groups)
		}
		if v := h.user(t, uid); v.ExternalID != "" || v.Role != models.RoleSuperAdmin {
			t.Fatalf("groups %v: provisioned account was linked: %+v", groups, v)
		}
		if ev := h.lastAudit("LOGIN_SSO_DENIED"); ev == nil || !strings.Contains(ev.Summary, "externalId does not match") {
			t.Fatalf("denial not audited: %+v", ev)
		}
	}

	// The owner (subject = externalId) still lands on the account.
	h.idp.User = map[string]any{"sub": "real-subject", "preferred_username": "victimadmin", "groups": []string{}}
	resp, cookies := h.ssoLogin(t)
	if strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatalf("owner: %s", resp.Header.Get("Location"))
	}
	if me := h.meWith(t, sessionFrom(cookies)); me.ID != uid || me.Role != models.RoleSuperAdmin {
		t.Fatalf("owner landed on %+v", me)
	}
}

// A provisioned account without externalId can never be linked by name either.
func TestSSOWithoutExternalIDNeverLinksByUsername(t *testing.T) {
	h := newSCIMHarness(t)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "frank@corp.example", "active": true})
	if st != 201 {
		t.Fatalf("provision: %d %v", st, u)
	}
	h.idp.User = map[string]any{"sub": "whoever", "preferred_username": "Frank@corp.example", "groups": []string{entraInfosecGroup}}
	resp, cookies := h.ssoLogin(t)
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=account_link") || sessionFrom(cookies) != nil {
		t.Fatalf("sign-in by name only: %s", resp.Header.Get("Location"))
	}
	if v := h.user(t, u["id"].(string)); v.ExternalID != "" {
		t.Fatalf("linked by name: %+v", v)
	}
}

// SCIM must not take over a just-in-time SSO account by name: the JIT account's name came from the
// username claim of whoever signed in first.
func TestSCIMDoesNotClaimJITAccountByUsername(t *testing.T) {
	h := newSCIMHarness(t)
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": false}, ui)
	h.idp.User = map[string]any{"sub": "early-bird", "preferred_username": "erin@corp.example", "groups": []string{entraInfosecGroup}}
	resp, cookies := h.ssoLogin(t)
	if strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatal(resp.Header.Get("Location"))
	}
	jit := h.meWith(t, sessionFrom(cookies))
	h.do(t, "POST", "/api/settings/scim", map[string]any{"enabled": true}, ui)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "erin@corp.example", "externalId": "the-real-erin", "active": true})
	if st != 201 || u["id"] == jit.ID {
		t.Fatalf("JIT account claimed by name: %d %v (jit %s)", st, u["id"], jit.ID)
	}
	if h.lastAudit("USER_LINKED_SCIM") != nil {
		t.Error("USER_LINKED_SCIM audited for a name match")
	}
	scimAcct := h.user(t, u["id"].(string))
	if scimAcct.Username == jit.Username || scimAcct.ExternalID != "" {
		t.Fatalf("SCIM account %+v must not share the JIT account's name or identity (%s)", scimAcct, jit.Username)
	}
	if again := h.user(t, jit.ID); again.SCIM != nil || again.Role != jit.Role {
		t.Fatalf("JIT account changed: %+v", again)
	}
}

// Round-4 finding RD4-1: the IdP deletes a user over SCIM and later gives the same userName to a different
// person (new immutable user ID), who is made Super Admin. The deleted record must not be revived for the
// new person, and it must not keep its single sign-on link: the former user would otherwise sign in to the
// new person's account and role, and the new person would be refused.
func TestSCIMReusedUserNameDoesNotReviveDeletedAccount(t *testing.T) {
	h := newSCIMHarness(t)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "alice@corp.example", "externalId": "alice-old-oid", "active": true})
	if st != 201 {
		t.Fatalf("provision former user: %d %v", st, u)
	}
	oldID := u["id"].(string)
	if st, g, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "aegis-auditors", "members": []map[string]string{{"value": oldID}}}); st != 201 {
		t.Fatalf("auditors group: %d %v", st, g)
	}
	h.idp.User = map[string]any{"sub": "alice-old-oid", "preferred_username": "alice@corp.example", "groups": []string{}}
	resp, cookies := h.ssoLogin(t)
	if strings.Contains(resp.Header.Get("Location"), "sso_error") {
		t.Fatalf("former user's first sign-in: %s", resp.Header.Get("Location"))
	}
	oldSession := sessionFrom(cookies)
	former := h.user(t, oldID)
	if former.ExternalID == "" || former.Role != models.RoleAuditorOperator {
		t.Fatalf("former user not linked: %+v", former)
	}

	// Offboarding: the SCIM delete removes the single sign-on link (audited) and ends the session.
	if st, _, _ := h.scim(t, "DELETE", "/Users/"+oldID, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if v := h.user(t, oldID); v.ExternalID != "" || !v.Disabled || v.SCIM == nil || !v.SCIM.Deleted {
		t.Fatalf("deleted record keeps its link or access: %+v", v)
	}
	if ev := h.lastAudit("USER_UNLINKED_SSO"); ev == nil || ev.EntityID != oldID || ev.BeforeState != "sso_link="+former.ExternalID {
		t.Fatalf("unlink not audited: %+v", ev)
	}
	if code := h.meStatus(t, oldSession); code != 401 {
		t.Errorf("session after the SCIM delete: %d", code)
	}

	// A different person gets the userName, with a new immutable ID, and becomes Super Admin: a new account.
	st, u, _ = h.scim(t, "POST", "/Users", map[string]any{"userName": "alice@corp.example", "externalId": "alice-new-oid", "active": true})
	if st != 201 {
		t.Fatalf("provision new owner: %d %v", st, u)
	}
	newID := u["id"].(string)
	if newID == oldID {
		t.Fatal("the deleted account was revived by userName for a different externalId")
	}
	if ev := h.lastAudit("USER_PROVISIONED_SCIM"); ev == nil || ev.EntityID != newID || !strings.Contains(ev.Summary, "was not revived") {
		t.Errorf("provisioning audit: %+v", ev)
	}
	if st, g, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Aegis Platform Owners", "members": []map[string]string{{"value": newID}}}); st != 201 {
		t.Fatalf("owners group: %d %v", st, g)
	}
	owner, kept := h.user(t, newID), h.user(t, oldID)
	if owner.Role != models.RoleSuperAdmin || owner.ExternalID != "" || owner.SCIM.ExternalID != "alice-new-oid" {
		t.Fatalf("new owner's account: %+v", owner)
	}
	// The deleted record keeps the former user's name and audit trail; the new account gets its own name.
	if kept.Username != former.Username || owner.Username == kept.Username || !kept.SCIM.Deleted || kept.SCIM.ExternalID != "alice-old-oid" {
		t.Fatalf("deleted record %+v / new account %+v", kept, owner)
	}

	// The former user's subject is refused, with any username claim, and links nothing.
	for _, name := range []string{"alice.old@corp.example", "alice@corp.example"} {
		h.idp.User = map[string]any{"sub": "alice-old-oid", "preferred_username": name, "groups": []string{entraInfosecGroup}}
		resp, cookies = h.ssoLogin(t)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error=account_disabled") && !strings.Contains(loc, "sso_error=account_link") {
			t.Fatalf("former user (%s) signed in: %s", name, loc)
		}
		if sessionFrom(cookies) != nil {
			t.Fatalf("former user (%s) got a session", name)
		}
		if a, b := h.user(t, newID), h.user(t, oldID); a.ExternalID != "" || b.ExternalID != "" {
			t.Fatalf("former user's sign-in linked an account: new %+v, deleted %+v", a, b)
		}
		if ev := h.lastAudit("LOGIN_SSO_DENIED"); ev == nil {
			t.Fatalf("former user (%s): denial not audited", name)
		}
	}

	// The new owner signs in to the provisioned account.
	h.idp.User = map[string]any{"sub": "alice-new-oid", "preferred_username": "alice@corp.example", "groups": []string{}}
	resp, cookies = h.ssoLogin(t)
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "sso_error") {
		t.Fatalf("new owner refused: %s", loc)
	}
	if me := h.meWith(t, sessionFrom(cookies)); me.ID != newID || me.Role != models.RoleSuperAdmin {
		t.Fatalf("new owner landed on %+v", me)
	}

	// Deleted and provisioned again with the same externalId, each person gets their own record back.
	if st, _, _ := h.scim(t, "DELETE", "/Users/"+newID, nil); st != 204 {
		t.Fatalf("delete new owner: %d", st)
	}
	if st, u, _ = h.scim(t, "POST", "/Users", map[string]any{"userName": "alice@corp.example", "externalId": "alice-new-oid"}); st != 201 || u["id"] != newID {
		t.Fatalf("re-provisioning the new owner: %d %v, want %s", st, u["id"], newID)
	}
	if v := h.user(t, oldID); !v.SCIM.Deleted {
		t.Fatalf("the former user's record was revived: %+v", v)
	}
}

// Without an externalId, deleted users are never revived: every re-provisioning of the same userName is a
// new account with a console name of its own (audit events and approvals name their actor by username).
func TestSCIMRecreatedUserNamesGetDistinctAccounts(t *testing.T) {
	h := newSCIMHarness(t)
	ids, names := map[string]bool{}, map[string]bool{}
	for i := range 5 {
		st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "carol@corp.example", "active": true})
		if st != 201 {
			t.Fatalf("round %d: provision: %d %v", i, st, u)
		}
		id := u["id"].(string)
		name := strings.ToLower(h.user(t, id).Username)
		if ids[id] || names[name] {
			t.Fatalf("round %d: account %s (%s) reused", i, id, name)
		}
		ids[id], names[name] = true, true
		if st, _, _ := h.scim(t, "DELETE", "/Users/"+id, nil); st != 204 {
			t.Fatalf("round %d: delete: %d", i, st)
		}
	}
}

// RD4-1: a new SCIM externalId means a different immutable user: the single sign-on link and the sessions
// of the account end, and only the new subject links it again.
func TestSCIMExternalIDChangeRemovesSSOLink(t *testing.T) {
	h := newSCIMHarness(t)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "bob@corp.example", "externalId": "bob-oid-1", "active": true})
	if st != 201 {
		t.Fatalf("provision: %d %v", st, u)
	}
	uid := u["id"].(string)
	h.scim(t, "POST", "/Groups", map[string]any{"displayName": "aegis-auditors", "members": []map[string]string{{"value": uid}}})
	h.idp.User = map[string]any{"sub": "bob-oid-1", "preferred_username": "bob@corp.example", "groups": []string{}}
	_, cookies := h.ssoLogin(t)
	session := sessionFrom(cookies)
	if me := h.meWith(t, session); me.ID != uid {
		t.Fatalf("first sign-in landed on %+v", me)
	}

	// An attribute update keeps the link; a changed externalId removes it.
	h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"Analyst"}]}`)
	if h.user(t, uid).ExternalID == "" || h.lastAudit("USER_UNLINKED_SSO") != nil {
		t.Fatal("a profile update removed the link")
	}
	// Session revocation has a resolution of one second (iat); the account stays enabled.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	st, _, _ = h.scim(t, "PATCH", "/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"externalId","value":"bob-oid-2"}]}`)
	if st != 200 {
		t.Fatalf("patch externalId: %d", st)
	}
	if v := h.user(t, uid); v.ExternalID != "" || v.SCIM.ExternalID != "bob-oid-2" {
		t.Fatalf("link kept after the externalId changed: %+v", v)
	}
	if ev := h.lastAudit("USER_UNLINKED_SSO"); ev == nil || ev.EntityID != uid || !strings.Contains(ev.Summary, `"bob-oid-1" to "bob-oid-2"`) {
		t.Fatalf("unlink not audited: %+v", ev)
	}
	if code := h.meStatus(t, session); code != 401 {
		t.Errorf("session of the previous subject: %d", code)
	}
	resp, cookies := h.ssoLogin(t)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error=account_link") || sessionFrom(cookies) != nil {
		t.Fatalf("previous subject: %s", loc)
	}
	h.idp.User["sub"] = "bob-oid-2"
	resp, cookies = h.ssoLogin(t)
	if me := h.meWith(t, sessionFrom(cookies)); strings.Contains(resp.Header.Get("Location"), "sso_error") || me.ID != uid {
		t.Fatalf("new subject: %s %+v", resp.Header.Get("Location"), me)
	}
}

// Round-4 finding RD4-2: OIDC subjects are case-sensitive. The first sign-in links only a subject exactly
// equal to the SCIM externalId: neither case folding nor Unicode folding (U+212A KELVIN SIGN folds to "k").
func TestSSOSubjectMustEqualSCIMExternalIDExactly(t *testing.T) {
	for _, tc := range []struct{ externalID, subject string }{
		{"okta-00u1abcd", "OKTA-00U1ABCD"},
		{"kelvin-00u1abcd", "Kelvin-00u1abcd"},
	} {
		h := newSCIMHarness(t)
		st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "victim@corp.example", "externalId": tc.externalID, "active": true})
		if st != 201 {
			t.Fatalf("provision: %d %v", st, u)
		}
		uid := u["id"].(string)
		h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Aegis Platform Owners", "members": []map[string]string{{"value": uid}}})
		if _, l, _ := h.scim(t, "GET", "/Users?filter="+q(`externalId eq "`+tc.subject+`"`), nil); l["totalResults"] != float64(0) {
			t.Errorf("%q: the externalId filter folds: %v", tc.subject, l)
		}

		h.idp.User = map[string]any{"sub": tc.subject, "preferred_username": "someone-else@corp.example", "groups": []string{}}
		resp, cookies := h.ssoLogin(t)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "sso_error") || sessionFrom(cookies) != nil {
			t.Fatalf("subject %q signed in to the account of externalId %q: %s", tc.subject, tc.externalID, loc)
		}
		if v := h.user(t, uid); v.ExternalID != "" || v.Role != models.RoleSuperAdmin {
			t.Fatalf("subject %q linked the account of externalId %q: %+v", tc.subject, tc.externalID, v)
		}

		h.idp.User["sub"] = tc.externalID
		resp, cookies = h.ssoLogin(t)
		if me := h.meWith(t, sessionFrom(cookies)); strings.Contains(resp.Header.Get("Location"), "sso_error") || me.ID != uid {
			t.Fatalf("owner %q: %s %+v", tc.externalID, resp.Header.Get("Location"), me)
		}
	}
}
