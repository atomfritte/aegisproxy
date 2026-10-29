package api

import (
	"strings"
	"testing"

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
