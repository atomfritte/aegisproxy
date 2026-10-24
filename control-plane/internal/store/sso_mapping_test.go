package store

import (
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func TestGroupMappingKeys(t *testing.T) {
	cfg := models.EntraIDConfig{
		GroupRoleMap: map[string]models.Role{
			"8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159": models.RoleSuperAdmin,
			"name:Okta Leads":                      models.RoleTeamLead,
			"id:aegis-auditors":                    models.RoleAuditorOperator,
		},
		GroupScopeMap: map[string][]string{"name:Okta Leads": {"grp-ci"}},
	}
	renamed := models.SCIMGroup{DisplayName: "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159", ExternalID: "other"}
	for _, tc := range []struct {
		name string
		keys []string
		role models.Role
	}{
		{"display name equal to a mapped object ID", scimGroupKeys(renamed), ""},
		{"externalId", scimGroupKeys(models.SCIMGroup{DisplayName: "Admins", ExternalID: "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159"}), models.RoleSuperAdmin},
		{"name: key and display name", scimGroupKeys(models.SCIMGroup{DisplayName: "Okta Leads"}), models.RoleTeamLead},
		{"name: key and externalId", scimGroupKeys(models.SCIMGroup{DisplayName: "x", ExternalID: "Okta Leads"}), ""},
		{"claim value, unprefixed key", claimGroupKeys([]string{"8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159"}), models.RoleSuperAdmin},
		{"claim value, name: key", claimGroupKeys([]string{"Okta Leads"}), models.RoleTeamLead},
		{"claim value, id: key", claimGroupKeys([]string{"aegis-auditors"}), models.RoleAuditorOperator},
	} {
		if role, _ := mapIdPGroups(cfg, tc.keys); role != tc.role {
			t.Errorf("%s: role %q, want %q", tc.name, role, tc.role)
		}
	}
	if _, groups := mapIdPGroups(cfg, scimGroupKeys(models.SCIMGroup{DisplayName: "Okta Leads"})); len(groups) != 1 || groups[0] != "grp-ci" {
		t.Errorf("scope of a name: mapping: %v", groups)
	}
}

// Pre-2.1 state: unprefixed name mappings of SCIM groups without externalId become "name:" keys once;
// object-ID-shaped keys and keys added later never do.
func TestGroupMappingKeyMigration(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	const guid = "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159"
	st.mu.Lock()
	st.state.GroupMapKeysTyped = false
	st.state.SCIMGroups = []models.SCIMGroup{
		{ID: "scg-1", DisplayName: "Okta Admins"},
		{ID: "scg-2", DisplayName: guid, ExternalID: "renamed-by-owner"},
		{ID: "scg-3", DisplayName: "Entra InfoSec", ExternalID: "Entra InfoSec"},
	}
	st.state.EntraConfig.GroupRoleMap = map[string]models.Role{"Okta Admins": models.RoleSuperAdmin, guid: models.RoleSuperAdmin,
		"Entra InfoSec": models.RoleInfoSecApprover, "not-provisioned": models.RoleAuditorOperator}
	st.state.EntraConfig.GroupScopeMap = map[string][]string{"Okta Admins": {"grp-x"}}
	st.migrateGroupMappingKeysLocked()
	got := st.state.EntraConfig
	st.mu.Unlock()
	want := map[string]models.Role{"name:Okta Admins": models.RoleSuperAdmin, guid: models.RoleSuperAdmin,
		"Entra InfoSec": models.RoleInfoSecApprover, "not-provisioned": models.RoleAuditorOperator}
	if len(got.GroupRoleMap) != len(want) {
		t.Fatalf("migrated role map %v", got.GroupRoleMap)
	}
	for k, r := range want {
		if got.GroupRoleMap[k] != r {
			t.Errorf("migrated role map %v, want %v", got.GroupRoleMap, want)
			break
		}
	}
	if _, ok := got.GroupScopeMap["name:Okta Admins"]; !ok || len(got.GroupScopeMap) != 1 {
		t.Errorf("migrated scope map %v", got.GroupScopeMap)
	}
	if ev := lastAuditAction(st, "SSO_GROUP_MAPPING_MIGRATED"); ev == nil {
		t.Error("migration not audited")
	}
	// Runs once: a later unprefixed key that equals a display name stays an identifier key.
	st.mu.Lock()
	st.state.EntraConfig.GroupRoleMap["Okta Admins"] = models.RoleSuperAdmin
	st.migrateGroupMappingKeysLocked()
	_, still := st.state.EntraConfig.GroupRoleMap["Okta Admins"]
	st.mu.Unlock()
	if !still {
		t.Error("migration ran twice")
	}
}

// The stored client secret never follows a changed issuer or client ID to another token endpoint.
func TestSSOClientSecretBoundToIdP(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	cfg := models.EntraIDConfig{Provider: "oidc", IssuerURL: "https://idp.corp.example/realms/aegis", ClientID: "aegis-console",
		ClientSecret: "s3cret-value", AllowLocalLogin: true, GroupRoleMap: map[string]models.Role{}}
	if err := st.UpdateEntraConfig(cfg, adminClaims); err != nil {
		t.Fatal(err)
	}
	keep := cfg
	keep.ClientSecret = models.MaskedSecretMarker
	keep.DisplayName = "Corporate SSO"
	if err := st.UpdateEntraConfig(keep, adminClaims); err != nil || st.SSOSettings("").ClientSecret != "s3cret-value" {
		t.Fatalf("unchanged destination did not keep the secret: %v", err)
	}
	for _, change := range []func(*models.EntraIDConfig){
		func(c *models.EntraIDConfig) { c.IssuerURL = "https://attacker.example/realms/aegis" },
		func(c *models.EntraIDConfig) { c.ClientID = "other-client" },
	} {
		moved := keep
		change(&moved)
		if err := st.UpdateEntraConfig(moved, adminClaims); err == nil {
			t.Errorf("stored secret kept for %s / %s", moved.IssuerURL, moved.ClientID)
		}
		moved.ClientSecret = "new-secret"
		if err := st.UpdateEntraConfig(moved, adminClaims); err != nil || st.SSOSettings("").ClientSecret != "new-secret" {
			t.Errorf("new secret for a new destination refused: %v", err)
		}
		if err := st.UpdateEntraConfig(cfg, adminClaims); err != nil { // back to the original IdP with its secret
			t.Fatal(err)
		}
	}
	// Entra derives the issuer from the tenant: a new tenant is a new IdP.
	entra := models.EntraIDConfig{Provider: "entra", TenantID: "72f988bf-86f1-41af-91ab-2d7cd011db47", ClientID: "aegis-console",
		ClientSecret: "entra-secret", AllowLocalLogin: true, GroupRoleMap: map[string]models.Role{}}
	if err := st.UpdateEntraConfig(entra, adminClaims); err != nil {
		t.Fatal(err)
	}
	entra.ClientSecret, entra.TenantID = "", "11111111-2222-3333-4444-555555555555"
	if err := st.UpdateEntraConfig(entra, adminClaims); err == nil {
		t.Error("stored secret followed a new tenant")
	}
	// Clearing the client drops the secret instead of failing.
	entra.ClientID = ""
	if err := st.UpdateEntraConfig(entra, adminClaims); err != nil || st.SSOSettings("").ClientSecret != "" {
		t.Errorf("clearing the client: %v", err)
	}
}

func lastAuditAction(st *Store, action string) *models.AuditEvent {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for i := len(st.state.AuditEvents) - 1; i >= 0; i-- {
		if st.state.AuditEvents[i].Action == action {
			ev := st.state.AuditEvents[i]
			return &ev
		}
	}
	return nil
}
