package scim

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const sampleUser = `{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
  "id": "usr-1", "externalId": "AbC-1", "userName": "Alex.Doe@corp.example", "displayName": "Alex Doe", "active": true,
  "name": {"givenName": "Alex", "familyName": "Doe"},
  "emails": [{"value": "alex@corp.example", "type": "work", "primary": true}, {"value": "alex@home.example", "type": "home", "primary": false}],
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Security"},
  "meta": {"resourceType": "User", "lastModified": "2026-10-01T10:00:00Z"}
}`

func TestFilter(t *testing.T) {
	u := doc(t, sampleUser)
	for expr, want := range map[string]bool{
		`userName eq "alex.doe@CORP.example"`:                           true,  // caseExact false
		`USERNAME Eq "alex.doe@corp.example"`:                           true,  // attribute and operator names are case-insensitive
		`externalId eq "abc-1"`:                                         false, // caseExact true
		`externalId eq "AbC-1"`:                                         true,
		`id eq "usr-1"`:                                                 true,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName sw "alex"`: true,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "security"`: true,
		`emails[type eq "work"].value eq "alex@corp.example"`:                                 true,
		`emails[type eq "work" and value co "home"]`:                                          false,
		`emails[type eq "home" and value co "home"]`:                                          true,
		`emails.value ew "home.example"`:                                                      true,
		`emails eq "alex@home.example"`:                                                       true,
		`active eq true and (name.givenName eq "Bob" or name.familyName eq "doe")`:            true,
		`active eq false or displayName co "lex"`:                                             true,
		`not (displayName pr)`:                                                                false,
		`title pr`:                                                                            false,
		`title eq null`:                                                                       true,
		`userName ne "x"`:                                                                     true,
		`meta.lastModified gt "2026-09-30T00:00:00Z" and meta.lastModified lt "2026-10-02T00:00:00+02:00"`: true,
		`name.givenName eq "Alex" and name.familyName eq "Doe" or userName eq "nobody"`:                    true,
		`userName eq "nobody" or name.givenName eq "Alex" and name.familyName eq "X"`:                      false, // and binds tighter
		`phoneNumbers pr`:               false,
		`userName eq "with \"quotes\""`: false,
	} {
		f, err := ParseFilter(expr, &UserType)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := f.Match(u); got != want {
			t.Errorf("%s = %v, want %v", expr, got, want)
		}
	}
	for _, bad := range []string{``, `userName`, `userName eq`, `userName xx "a"`, `(userName eq "a"`, `emails[type eq "work"`,
		`userName eq alex`, `not userName eq "a"`, `userName eq "a" and`, `userName eq "unterminated`} {
		if _, err := ParseFilter(bad, &UserType); err == nil || err.ScimType != "invalidFilter" {
			t.Errorf("%q accepted (%v)", bad, err)
		}
	}
	g := doc(t, `{"id":"g1","displayName":"CI Leads","members":[{"value":"usr-1"},{"value":"usr-2"}]}`)
	for expr, want := range map[string]bool{`displayName eq "ci leads"`: true, `members[value eq "usr-2"]`: true, `members eq "USR-2"`: false} {
		f, _ := ParseFilter(expr, &GroupType)
		if f.Match(g) != want {
			t.Errorf("group %s != %v", expr, want)
		}
	}
}

func patch(t *testing.T, d map[string]any, rt *ResourceType, ops string) *Error {
	t.Helper()
	var req PatchRequest
	if err := json.Unmarshal([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":`+ops+`}`), &req); err != nil {
		t.Fatal(err)
	}
	return ApplyPatch(d, rt, req)
}

func TestPatchUser(t *testing.T) {
	u := doc(t, sampleUser)
	err := patch(t, u, &UserType, `[
	  {"op":"Replace","value":{"displayName":"A. Doe","name.givenName":"Al","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"SOC","id":"ignored","meta":{"x":1},"password":"ignored"}},
	  {"op":"add","path":"emails[type eq \"other\"].value","value":"alex@other.example"},
	  {"op":"replace","path":"emails[type eq \"work\"].primary","value":false},
	  {"op":"add","path":"emails","value":[{"value":"new@corp.example","type":"work","primary":true}]},
	  {"op":"remove","path":"emails[type eq \"home\"]"},
	  {"op":"Add","path":"phoneNumbers[type eq \"mobile\"].value","value":"+1"},
	  {"op":"replace","path":"active","value":"False"},
	  {"op":"remove","path":"name.familyName"}]`)
	if err != nil {
		t.Fatal(err)
	}
	p, perr := ParseUser(u)
	if perr != nil {
		t.Fatal(perr)
	}
	want := models.SCIMUser{UserName: "Alex.Doe@corp.example", ExternalID: "AbC-1", Active: p.Active, DisplayName: "A. Doe", GivenName: "Al", Department: "SOC",
		Emails: []models.SCIMEmail{{Value: "alex@corp.example", Type: "work"}, {Value: "alex@other.example", Type: "other"}, {Value: "new@corp.example", Type: "work", Primary: true}}}
	if p.Active == nil || *p.Active || !reflect.DeepEqual(p, want) {
		t.Fatalf("patched user\n got %+v\nwant %+v", p, want)
	}
	if u["id"] != "usr-1" || u["phoneNumbers"] != nil || u["password"] != nil {
		t.Errorf("read-only/unknown attributes changed: %v", u)
	}
	// Removing the whole extension, explicit read-only paths and missing targets.
	if err := patch(t, u, &UserType, `[{"op":"remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"}]`); err != nil || u[EnterpriseUserSchema] != nil {
		t.Errorf("remove extension: %v %v", err, u[EnterpriseUserSchema])
	}
	for name, ops := range map[string]string{
		"read-only path":   `[{"op":"replace","path":"id","value":"x"}]`,
		"groups read-only": `[{"op":"add","path":"groups","value":[{"value":"g"}]}]`,
		"remove no path":   `[{"op":"remove"}]`,
		"bad op":           `[{"op":"copy","path":"title","value":"x"}]`,
		"no match":         `[{"op":"replace","path":"emails[type eq \"fax\"]","value":{"value":"x"}}]`,
		"filter on single": `[{"op":"replace","path":"title[value eq \"x\"]","value":"y"}]`,
		"bad path":         `[{"op":"replace","path":"emails[type eq","value":"y"}]`,
		"path-less scalar": `[{"op":"replace","value":"x"}]`,
		"no operations":    `[]`,
	} {
		if err := patch(t, u, &UserType, ops); err == nil || err.Status != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPatchGroupMembers(t *testing.T) {
	g := doc(t, `{"id":"g1","displayName":"CI","members":[{"value":"u1"},{"value":"u2"}]}`)
	steps := []struct {
		ops  string
		want []string
	}{
		{`[{"op":"Add","path":"members","value":[{"value":"u3"},{"value":"u1"}]}]`, []string{"u1", "u2", "u3"}},        // Entra: duplicates ignored
		{`[{"op":"Remove","path":"members","value":[{"value":"u2"}]}]`, []string{"u1", "u3"}},                          // Entra: remove listed members
		{`[{"op":"remove","path":"members[value eq \"u1\"]"}]`, []string{"u3"}},                                        // Okta
		{`[{"op":"replace","path":"members","value":[{"value":"u4"},{"value":"u5"}]}]`, []string{"u4", "u5"}},          // replace all
		{`[{"op":"replace","value":{"id":"g1","displayName":"CI Leads","members":[{"value":"u6"}]}}]`, []string{"u6"}}, // Okta rename (+members)
		{`[{"op":"add","value":{"members":[{"value":"u7","display":"x"}]}}]`, []string{"u6", "u7"}},                    // path-less add
		{`[{"op":"remove","path":"members"}]`, nil},                                                                    // remove all
	}
	for i, s := range steps {
		if err := patch(t, g, &GroupType, s.ops); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		in, err := ParseGroup(g)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		var got []string
		for _, m := range in.Members {
			got = append(got, m.Value)
		}
		if !reflect.DeepEqual(got, s.want) {
			t.Errorf("step %d: members %v, want %v", i, got, s.want)
		}
	}
	if g["displayName"] != "CI Leads" || g["id"] != "g1" {
		t.Errorf("group %v", g)
	}
}

func TestRenderParseRoundTrip(t *testing.T) {
	active := true
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	u := models.User{ID: "usr-1", SCIM: &models.SCIMUser{UserName: "a@x", ExternalID: "e1", Active: &active, DisplayName: "A", GivenName: "G",
		Emails: []models.SCIMEmail{{Value: "a@x", Type: "work", Primary: true}}, Department: "D", Version: 3, Created: now, LastModified: now}}
	d := RenderUser(u, []models.SCIMGroup{{ID: "g1", DisplayName: "CI"}}, "https://aegis/api/scim/v2")
	raw, _ := json.Marshal(d)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	p, err := ParseUser(back)
	if err != nil {
		t.Fatal(err)
	}
	want := *u.SCIM
	want.Version, want.Created, want.LastModified = 0, time.Time{}, time.Time{}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("round trip\n got %+v\nwant %+v", p, want)
	}
	meta := back["meta"].(map[string]any)
	if meta["version"] != `W/"3"` || meta["location"] != "https://aegis/api/scim/v2/Users/usr-1" || ParseETag(`W/"3"`) != 3 {
		t.Errorf("meta %v", meta)
	}
	proj := Project(back, &UserType, []string{"emails.value", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"}, nil)
	if len(proj) != 4 || proj["emails"].([]any)[0].(map[string]any)["value"] != "a@x" || proj[EnterpriseUserSchema].(map[string]any)["department"] != "D" {
		t.Errorf("projection %v", proj)
	}
	ex := Project(back, &UserType, nil, []string{"groups", "name.givenName", "id"})
	if ex["groups"] != nil || ex["id"] != "usr-1" || ex["name"] == nil || ex["name"].(map[string]any)["givenName"] != nil || back["groups"] == nil {
		t.Errorf("exclusion %v (source %v)", ex, back["groups"])
	}
}
