package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// Round-4 finding RD4-1, defense in depth: a SCIM-managed account with an externalId accepts only a
// token subject exactly equal to it. A link to another subject — the state an earlier version left when
// it revived a deleted record by userName for a different person and kept the former user's link — is
// refused and ends the sessions it produced; the owner's first sign-in replaces it.
func TestSSORefusesStaleLinkOfSCIMAccount(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	const issuer = "https://idp.corp.example/realms/aegis"
	cfg := models.EntraIDConfig{Enabled: true, Provider: "oidc", IssuerURL: issuer, ClientID: "aegis-console", ClientSecret: "s3cret-value",
		AllowLocalLogin: true, GroupRoleMap: map[string]models.Role{"name:Aegis Platform Owners": models.RoleSuperAdmin}}
	if err := st.UpdateEntraConfig(cfg, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateSCIMConfig(true, adminClaims); err != nil {
		t.Fatal(err)
	}
	v, err := st.SCIMCreateUser(models.SCIMUser{UserName: "alice@corp.example", ExternalID: "alice-new-oid"}, "scim:test")
	if err != nil {
		t.Fatal(err)
	}
	uid := v.User.ID
	if _, err := st.SCIMCreateGroup(SCIMGroupInput{DisplayName: "Aegis Platform Owners", Members: []models.SCIMMember{{Value: uid}}}, "scim:test"); err != nil {
		t.Fatal(err)
	}
	stale := externalID(issuer, "alice-old-oid")
	st.mu.Lock()
	st.state.Users[st.scimUserIndexLocked(uid)].ExternalID = stale
	st.mu.Unlock()

	former := SSOIdentity{Issuer: issuer, Subject: "alice-old-oid", LoginName: "alice.old@corp.example", Username: "alice.old.corp.example"}
	before := time.Now().Add(-time.Second)
	if _, err := st.ProvisionSSOUser(former); !errors.Is(err, ErrSSOLinkConflict) {
		t.Fatalf("sign-in through a stale link: %v", err)
	}
	if u, _ := st.GetUserByID(uid); u.ExternalID != stale || u.SessionsNotBefore == nil || u.SessionsNotBefore.Before(before) {
		t.Fatalf("after the refused sign-in: %+v", u)
	}
	if ev := newestAudit(st, "LOGIN_SSO_DENIED"); ev == nil || ev.EntityID != uid || !strings.Contains(ev.Summary, "stale link") {
		t.Fatalf("refusal not audited: %+v", ev)
	}

	owner := SSOIdentity{Issuer: issuer, Subject: "alice-new-oid", LoginName: "alice@corp.example", Username: "alice.corp.example"}
	got, err := st.ProvisionSSOUser(owner)
	if err != nil || got.ID != uid || got.Role != models.RoleSuperAdmin {
		t.Fatalf("owner's sign-in: %+v %v", got, err)
	}
	if u, _ := st.GetUserByID(uid); u.ExternalID != externalID(issuer, "alice-new-oid") {
		t.Fatalf("link not replaced: %+v", u)
	}
	if ev := newestAudit(st, "USER_LINKED_SSO"); ev == nil || ev.EntityID != uid || !strings.Contains(ev.Summary, "replaces a link") || ev.BeforeState != "sso_link="+stale {
		t.Fatalf("relink not audited: %+v", ev)
	}
	// The former subject has no account any more: refused like anybody without a mapped group.
	if _, err := st.ProvisionSSOUser(former); !errors.Is(err, ErrSSONotAuthorized) {
		t.Fatalf("former subject after the relink: %v", err)
	}
}

// newestAudit returns the newest event of the in-memory window with the action.
func newestAudit(st *Store, action string) *models.AuditEvent {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for _, ev := range st.state.AuditEvents {
		if ev.Action == action {
			return &ev
		}
	}
	return nil
}
