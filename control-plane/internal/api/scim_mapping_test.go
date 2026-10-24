package api

import (
	"testing"

	"aegisproxy/control-plane/internal/models"
)

// A group owner who renames their SCIM group to the object ID that is mapped to a role must not get
// that role: unprefixed mapping keys match the group's externalId only, display names need "name:".
func TestSCIMGroupRenameCannotClaimObjectIDMapping(t *testing.T) {
	h := newSCIMHarness(t)
	st, u, _ := h.scim(t, "POST", "/Users", map[string]any{"userName": "mallory@corp.example", "externalId": "mallory-oid"})
	if st != 201 {
		t.Fatalf("create user: %d", st)
	}
	uid := u["id"].(string)
	st, g, _ := h.scim(t, "POST", "/Groups", map[string]any{"displayName": "Mallory self-service team", "externalId": "0b7d0000-0000-4000-8000-00000000beef",
		"members": []map[string]string{{"value": uid}}})
	if st != 201 {
		t.Fatalf("create group: %d", st)
	}
	if cu := h.user(t, uid); cu.Role != "" || !cu.Disabled {
		t.Fatalf("unmapped group granted access: %+v", cu)
	}
	// The renamed display name equals the object ID mapped to InfoSec.
	st, _, _ = h.scim(t, "PATCH", "/Groups/"+g["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"`+entraInfosecGroup+`"}]}`)
	if st != 200 && st != 204 {
		t.Fatalf("rename group: %d", st)
	}
	if cu := h.user(t, uid); cu.Role != "" || !cu.Disabled {
		t.Fatalf("renaming a group to a mapped object ID granted %q (enabled=%v)", cu.Role, !cu.Disabled)
	}
	// The same rename to a "name:" mapping does match: name mappings are opt-in and renameable.
	st, _, _ = h.scim(t, "PATCH", "/Groups/"+g["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"aegis-auditors"}]}`)
	if st != 200 && st != 204 {
		t.Fatalf("rename group: %d", st)
	}
	if cu := h.user(t, uid); cu.Role != models.RoleAuditorOperator || cu.Disabled {
		t.Fatalf("name: mapping not applied: %+v", cu)
	}
	// An explicit "id:" key matches the externalId.
	cfg := h.st.SSOSettings("")
	cfg.GroupRoleMap = map[string]models.Role{"id:0b7d0000-0000-4000-8000-00000000beef": models.RoleTeamLead}
	cfg.ClientSecret = ""
	if err := h.st.UpdateEntraConfig(cfg, adminClaimsFor(h.harness)); err != nil {
		t.Fatal(err)
	}
	if cu := h.user(t, uid); cu.Role != models.RoleTeamLead || cu.Disabled {
		t.Fatalf("id: mapping not applied: %+v", cu)
	}
	// Empty prefixed keys are rejected.
	for _, k := range []string{"name:", "id:"} {
		cfg.GroupRoleMap = map[string]models.Role{k: models.RoleTeamLead}
		if err := h.st.UpdateEntraConfig(cfg, adminClaimsFor(h.harness)); err == nil {
			t.Errorf("mapping key %q accepted", k)
		}
	}
}
