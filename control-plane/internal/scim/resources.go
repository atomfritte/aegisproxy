package scim

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// ETag returns the weak entity tag of a resource version.
func ETag(version int64) string { return fmt.Sprintf(`W/"%d"`, version) }

// ParseETag returns the version of a W/"n" entity tag (0 for "*" or invalid values).
func ParseETag(tag string) int64 {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	n, err := strconv.ParseInt(strings.Trim(tag, `"`), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// RenderUser returns the SCIM representation of a SCIM-managed account.
func RenderUser(u models.User, groups []models.SCIMGroup, base string) map[string]any {
	sc := u.SCIM
	if sc == nil {
		sc = &models.SCIMUser{}
	}
	m := map[string]any{"id": u.ID, "userName": sc.UserName}
	schemas := []any{UserSchema}
	if sc.ExternalID != "" {
		m["externalId"] = sc.ExternalID
	}
	name := map[string]any{}
	for k, v := range map[string]string{"formatted": sc.Formatted, "familyName": sc.FamilyName, "givenName": sc.GivenName} {
		if v != "" {
			name[k] = v
		}
	}
	if len(name) > 0 {
		m["name"] = name
	}
	if sc.DisplayName != "" {
		m["displayName"] = sc.DisplayName
	}
	if sc.Title != "" {
		m["title"] = sc.Title
	}
	if sc.Active != nil {
		m["active"] = *sc.Active
	}
	if len(sc.Emails) > 0 {
		list := make([]any, 0, len(sc.Emails))
		for _, e := range sc.Emails {
			em := map[string]any{"value": e.Value, "primary": e.Primary}
			if e.Type != "" {
				em["type"] = e.Type
			}
			list = append(list, em)
		}
		m["emails"] = list
	}
	if len(groups) > 0 {
		list := make([]any, 0, len(groups))
		for _, g := range groups {
			list = append(list, map[string]any{"value": g.ID, "$ref": base + "/Groups/" + g.ID, "display": g.DisplayName, "type": "direct"})
		}
		m["groups"] = list
	}
	if sc.Department != "" {
		schemas = append(schemas, EnterpriseUserSchema)
		m[EnterpriseUserSchema] = map[string]any{"department": sc.Department}
	}
	m["schemas"] = schemas
	m["meta"] = map[string]any{"resourceType": "User", "created": ts(sc.Created), "lastModified": ts(sc.LastModified),
		"location": base + "/Users/" + u.ID, "version": ETag(sc.Version)}
	return m
}

// RenderGroup returns the SCIM representation of a group.
func RenderGroup(g models.SCIMGroup, base string) map[string]any {
	m := map[string]any{"schemas": []any{GroupSchema}, "id": g.ID, "displayName": g.DisplayName}
	if g.ExternalID != "" {
		m["externalId"] = g.ExternalID
	}
	if len(g.Members) > 0 {
		list := make([]any, 0, len(g.Members))
		for _, mem := range g.Members {
			e := map[string]any{"value": mem.Value, "$ref": base + "/Users/" + mem.Value}
			if mem.Type != "" {
				e["type"] = mem.Type
			}
			list = append(list, e)
		}
		m["members"] = list
	}
	m["meta"] = map[string]any{"resourceType": "Group", "created": ts(g.Created), "lastModified": ts(g.LastModified),
		"location": base + "/Groups/" + g.ID, "version": ETag(g.Version)}
	return m
}

func optString(m map[string]any, key string) (string, *Error) {
	v, k := getFold(m, key)
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(t), nil
	default:
		return "", badValue("%s must be a string", firstKey(k, key))
	}
}

func firstKey(k, fallback string) string {
	if k != "" {
		return k
	}
	return fallback
}

func optBool(m map[string]any, key string) (*bool, *Error) {
	v, k := getFold(m, key)
	switch t := v.(type) {
	case nil:
		return nil, nil
	case bool:
		return &t, nil
	case string: // Entra ID sends "True"/"False" in some PATCH requests
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			b := true
			return &b, nil
		case "false":
			b := false
			return &b, nil
		}
	}
	return nil, badValue("%s must be a boolean", firstKey(k, key))
}

// ParseUser reads the writable User attributes of a POST/PUT body (or a patched representation).
// Read-only and unknown attributes are ignored.
func ParseUser(doc map[string]any) (models.SCIMUser, *Error) {
	var u models.SCIMUser
	var err *Error
	if u.UserName, err = optString(doc, "userName"); err != nil {
		return u, err
	}
	if u.UserName == "" {
		return u, badValue("userName is required")
	}
	if u.ExternalID, err = optString(doc, "externalId"); err != nil {
		return u, err
	}
	if u.Active, err = optBool(doc, "active"); err != nil {
		return u, err
	}
	if u.DisplayName, err = optString(doc, "displayName"); err != nil {
		return u, err
	}
	if u.Title, err = optString(doc, "title"); err != nil {
		return u, err
	}
	if v, _ := getFold(doc, "name"); v != nil {
		name, ok := v.(map[string]any)
		if !ok {
			return u, badValue("name must be an object")
		}
		if u.Formatted, err = optString(name, "formatted"); err != nil {
			return u, err
		}
		if u.GivenName, err = optString(name, "givenName"); err != nil {
			return u, err
		}
		if u.FamilyName, err = optString(name, "familyName"); err != nil {
			return u, err
		}
	}
	if v, _ := getFold(doc, "emails"); v != nil {
		for _, e := range toList(v) {
			em, ok := e.(map[string]any)
			if !ok {
				return u, badValue("emails must be a list of objects")
			}
			var x models.SCIMEmail
			if x.Value, err = optString(em, "value"); err != nil {
				return u, err
			}
			if x.Type, err = optString(em, "type"); err != nil {
				return u, err
			}
			p, err := optBool(em, "primary")
			if err != nil {
				return u, err
			}
			x.Primary = p != nil && *p
			if x.Value == "" { // an element without address carries no information
				continue
			}
			u.Emails = append(u.Emails, x)
		}
	}
	if v, _ := getFold(doc, EnterpriseUserSchema); v != nil {
		ext, ok := v.(map[string]any)
		if !ok {
			return u, badValue("%s must be an object", EnterpriseUserSchema)
		}
		if u.Department, err = optString(ext, "department"); err != nil {
			return u, err
		}
	} else if u.Department, err = optString(doc, EnterpriseUserSchema+":department"); err != nil {
		return u, err
	}
	return u, nil
}

// GroupInput is the writable part of a group.
type GroupInput struct {
	DisplayName string
	ExternalID  string
	Members     []models.SCIMMember
}

// ParseGroup reads the writable Group attributes.
func ParseGroup(doc map[string]any) (GroupInput, *Error) {
	var g GroupInput
	var err *Error
	if g.DisplayName, err = optString(doc, "displayName"); err != nil {
		return g, err
	}
	if g.DisplayName == "" {
		return g, badValue("displayName is required")
	}
	if g.ExternalID, err = optString(doc, "externalId"); err != nil {
		return g, err
	}
	if v, _ := getFold(doc, "members"); v != nil {
		for _, e := range toList(v) {
			mm, ok := e.(map[string]any)
			if !ok {
				return g, badValue("members must be a list of objects")
			}
			var mem models.SCIMMember
			if mem.Value, err = optString(mm, "value"); err != nil {
				return g, err
			}
			if mem.Value == "" {
				return g, badValue("members[].value is required")
			}
			if mem.Type, err = optString(mm, "type"); err != nil {
				return g, err
			}
			g.Members = append(g.Members, mem)
		}
	}
	return g, nil
}

// Project applies the attributes / excludedAttributes query parameters (RFC 7644 section
// 3.4.2.5); id and schemas are always returned.
func Project(doc map[string]any, rt *ResourceType, attributes, excluded []string) map[string]any {
	sc := scope{rt: rt}
	if len(attributes) > 0 {
		out := map[string]any{"schemas": doc["schemas"], "id": doc["id"]}
		for _, a := range attributes {
			r, err := sc.resolve(a)
			if err != nil {
				continue
			}
			src, dst := doc, out
			if r.ext != "" {
				e, _ := getFold(doc, r.ext)
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				src = em
				d, _ := out[r.ext].(map[string]any)
				if d == nil {
					d = map[string]any{}
					out[r.ext] = d
				}
				dst = d
				if r.name == "" {
					for k, v := range em {
						d[k] = v
					}
					continue
				}
			}
			v, _ := getFold(src, r.name)
			if v == nil {
				continue
			}
			if r.sub == "" {
				dst[r.name] = v
				continue
			}
			switch t := v.(type) {
			case map[string]any:
				d, _ := dst[r.name].(map[string]any)
				if d == nil {
					d = map[string]any{}
				}
				if sv, _ := getFold(t, r.sub); sv != nil {
					d[r.sub] = sv
				}
				if len(d) > 0 {
					dst[r.name] = d
				}
			case []any:
				list := []any{}
				for _, x := range t {
					if xm, ok := x.(map[string]any); ok {
						if sv, _ := getFold(xm, r.sub); sv != nil {
							list = append(list, map[string]any{r.sub: sv})
						}
					}
				}
				if len(list) > 0 {
					dst[r.name] = list
				}
			}
		}
		for k, v := range out { // drop empty extension containers
			if m, ok := v.(map[string]any); ok && len(m) == 0 && strings.HasPrefix(k, "urn:") {
				delete(out, k)
			}
		}
		return out
	}
	if len(excluded) == 0 {
		return doc
	}
	out := cloneMap(doc)
	for _, a := range excluded {
		r, err := sc.resolve(a)
		if err != nil || strings.EqualFold(r.name, "id") || (r.ext == "" && strings.EqualFold(r.name, "schemas")) {
			continue
		}
		c := out
		if r.ext != "" {
			e, k := getFold(out, r.ext)
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if r.name == "" {
				delete(out, k)
				continue
			}
			em = cloneMap(em)
			out[k] = em
			c = em
		}
		_, k := getFold(c, r.name)
		if k == "" {
			continue
		}
		if r.sub == "" {
			delete(c, k)
			continue
		}
		if m, ok := c[k].(map[string]any); ok {
			m = cloneMap(m)
			if _, sk := getFold(m, r.sub); sk != "" {
				delete(m, sk)
			}
			c[k] = m
		}
	}
	return out
}

// SplitAttrList splits a comma-separated attributes parameter.
func SplitAttrList(v string) []string {
	var out []string
	for _, a := range strings.Split(v, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}
