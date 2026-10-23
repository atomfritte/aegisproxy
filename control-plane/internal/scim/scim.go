// Package scim implements the protocol side of SCIM 2.0 (RFC 7643 core schema, RFC 7644 protocol)
// for inbound provisioning from Microsoft Entra ID and Okta: schema and resource-type discovery,
// filter expressions, PATCH operations, attribute projection and the mapping between SCIM JSON
// and the console's account and group models. It holds no state; the store persists resources.
package scim

import (
	"fmt"
	"strings"
)

// Schema and message URNs.
const (
	UserSchema           = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	EnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaSchema         = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	ResourceTypeSchema   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SPConfigSchema       = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ListResponseSchema   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpSchema        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SearchRequestSchema  = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	ErrorSchema          = "urn:ietf:params:scim:api:messages:2.0:Error"

	// ContentType is the SCIM media type (RFC 7644 section 3.1).
	ContentType = "application/scim+json"
	// MaxResults bounds a page of a list or search response.
	MaxResults = 200
)

// Error is a SCIM protocol error (RFC 7644 section 3.12).
type Error struct {
	Status   int
	ScimType string // invalidFilter, invalidPath, invalidValue, invalidSyntax, mutability, noTarget, uniqueness, tooMany …
	Detail   string
}

func (e *Error) Error() string { return e.Detail }

// Body is the JSON error document.
func (e *Error) Body() map[string]any {
	m := map[string]any{"schemas": []string{ErrorSchema}, "status": fmt.Sprint(e.Status), "detail": e.Detail}
	if e.ScimType != "" {
		m["scimType"] = e.ScimType
	}
	return m
}

// Errf builds an Error.
func Errf(status int, scimType, format string, a ...any) *Error {
	return &Error{Status: status, ScimType: scimType, Detail: fmt.Sprintf(format, a...)}
}

func badValue(format string, a ...any) *Error { return Errf(400, "invalidValue", format, a...) }

// Attr is an attribute definition of a schema (RFC 7643 section 7).
type Attr struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	MultiValued     bool     `json:"multiValued"`
	Description     string   `json:"description"`
	Required        bool     `json:"required"`
	CaseExact       *bool    `json:"caseExact,omitempty"`
	CanonicalValues []string `json:"canonicalValues,omitempty"`
	ReferenceTypes  []string `json:"referenceTypes,omitempty"`
	Mutability      string   `json:"mutability"`
	Returned        string   `json:"returned"`
	Uniqueness      string   `json:"uniqueness,omitempty"`
	SubAttributes   []Attr   `json:"subAttributes,omitempty"`
}

// Schema is a SCIM schema definition.
type Schema struct {
	ID          string
	Name        string
	Description string
	Attributes  []Attr
}

var (
	yes, no = true, false
)

func str(name, desc string, caseExact bool, mutability string) Attr {
	ce := &no
	if caseExact {
		ce = &yes
	}
	return Attr{Name: name, Type: "string", Description: desc, CaseExact: ce, Mutability: mutability, Returned: "default", Uniqueness: "none"}
}

func boolean(name, desc, mutability string) Attr {
	return Attr{Name: name, Type: "boolean", Description: desc, Mutability: mutability, Returned: "default"}
}

func ref(name, desc, mutability string, types ...string) Attr {
	return Attr{Name: name, Type: "reference", Description: desc, CaseExact: &yes, ReferenceTypes: types, Mutability: mutability, Returned: "default", Uniqueness: "none"}
}

func complexAttr(name, desc string, multi bool, mutability string, sub ...Attr) Attr {
	return Attr{Name: name, Type: "complex", MultiValued: multi, Description: desc, Mutability: mutability, Returned: "default", Uniqueness: "none", SubAttributes: sub}
}

func withCanonical(a Attr, v ...string) Attr {
	a.CanonicalValues = v
	return a
}

// The schemas list exactly the attributes the console stores; other attributes sent by an IdP
// (phone numbers, addresses, manager, password …) are accepted and ignored.
var (
	userName = func() Attr {
		a := str("userName", "Unique identifier of the user, typically the user principal name or login; becomes the console username.", false, "readWrite")
		a.Required, a.Uniqueness = true, "server"
		return a
	}()

	User = Schema{ID: UserSchema, Name: "User", Description: "AegisProxy console account", Attributes: []Attr{
		userName,
		complexAttr("name", "The components of the user's name.", false, "readWrite",
			str("formatted", "The full name.", false, "readWrite"),
			str("familyName", "The family name.", false, "readWrite"),
			str("givenName", "The given name.", false, "readWrite")),
		str("displayName", "The name displayed in the console.", false, "readWrite"),
		str("title", "The user's title, such as \"Security Engineer\".", false, "readWrite"),
		boolean("active", "Whether the console account is enabled. false disables it and revokes its sessions.", "readWrite"),
		complexAttr("emails", "E-mail addresses; the primary (or work) address is shown in the console.", true, "readWrite",
			str("value", "E-mail address.", false, "readWrite"),
			withCanonical(str("type", "work, home or other.", false, "readWrite"), "work", "home", "other"),
			boolean("primary", "The primary address.", "readWrite")),
		func() Attr {
			a := complexAttr("groups", "SCIM groups the user belongs to (read-only; change memberships through the Group resource).", true, "readOnly",
				str("value", "Group id.", true, "readOnly"),
				ref("$ref", "Group URI.", "readOnly", "Group"),
				str("display", "Group display name.", false, "readOnly"),
				withCanonical(str("type", "direct", false, "readOnly"), "direct", "indirect"))
			return a
		}(),
	}}

	EnterpriseUser = Schema{ID: EnterpriseUserSchema, Name: "EnterpriseUser", Description: "Enterprise user extension", Attributes: []Attr{
		str("department", "Department, shown in the console.", false, "readWrite"),
	}}

	Group = Schema{ID: GroupSchema, Name: "Group", Description: "Group whose display name or externalId maps to a console role", Attributes: []Attr{
		func() Attr {
			a := str("displayName", "Group name, unique; matched against the single sign-on group mapping together with externalId.", false, "readWrite")
			a.Required, a.Uniqueness = true, "server"
			return a
		}(),
		complexAttr("members", "Users of the group.", true, "readWrite",
			str("value", "User id.", true, "immutable"),
			ref("$ref", "User URI.", "immutable", "User", "Group"),
			withCanonical(str("type", "User.", false, "immutable"), "User", "Group")),
	}}
)

// ResourceType describes a resource endpoint.
type ResourceType struct {
	ID, Name, Endpoint, Description string
	Schema                          *Schema
	Extensions                      []*Schema
}

var (
	UserType  = ResourceType{ID: "User", Name: "User", Endpoint: "/Users", Description: "Console accounts", Schema: &User, Extensions: []*Schema{&EnterpriseUser}}
	GroupType = ResourceType{ID: "Group", Name: "Group", Endpoint: "/Groups", Description: "Groups mapped to console roles", Schema: &Group}
	// ResourceTypes lists every resource type served.
	ResourceTypes = []*ResourceType{&UserType, &GroupType}
	// Schemas lists every schema served.
	Schemas = []*Schema{&User, &EnterpriseUser, &Group}
)

func meta(resourceType, location string) map[string]any {
	return map[string]any{"resourceType": resourceType, "location": location}
}

// SchemaResource renders a schema for GET /Schemas.
func SchemaResource(s *Schema, base string) map[string]any {
	return map[string]any{"schemas": []string{SchemaSchema}, "id": s.ID, "name": s.Name, "description": s.Description,
		"attributes": s.Attributes, "meta": meta("Schema", base+"/Schemas/"+s.ID)}
}

// ResourceTypeResource renders a resource type for GET /ResourceTypes.
func ResourceTypeResource(rt *ResourceType, base string) map[string]any {
	m := map[string]any{"schemas": []string{ResourceTypeSchema}, "id": rt.ID, "name": rt.Name, "endpoint": rt.Endpoint,
		"description": rt.Description, "schema": rt.Schema.ID, "meta": meta("ResourceType", base+"/ResourceTypes/"+rt.ID)}
	if len(rt.Extensions) > 0 {
		ext := []map[string]any{}
		for _, e := range rt.Extensions {
			ext = append(ext, map[string]any{"schema": e.ID, "required": false})
		}
		m["schemaExtensions"] = ext
	}
	return m
}

// ServiceProviderConfig describes the supported features (RFC 7643 section 5).
func ServiceProviderConfig(base, docs string) map[string]any {
	m := map[string]any{
		"schemas":        []string{SPConfigSchema},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": MaxResults},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": true,
			"description": "Authentication with a SCIM provisioning token issued in the AegisProxy console (Settings → Single sign-on → Provisioning)."}},
		"meta": meta("ServiceProviderConfig", base+"/ServiceProviderConfig"),
	}
	if docs != "" {
		m["documentationUri"] = docs
	}
	return m
}

// ListResponse wraps resources (RFC 7644 section 3.4.2).
func ListResponse(resources []map[string]any, total, startIndex int) map[string]any {
	if resources == nil {
		resources = []map[string]any{}
	}
	return map[string]any{"schemas": []string{ListResponseSchema}, "totalResults": total, "startIndex": startIndex,
		"itemsPerPage": len(resources), "Resources": resources}
}

// FindSchema returns a schema by URN (case-insensitive).
func FindSchema(id string) *Schema {
	for _, s := range Schemas {
		if strings.EqualFold(s.ID, id) {
			return s
		}
	}
	return nil
}

// FindResourceType returns a resource type by id.
func FindResourceType(id string) *ResourceType {
	for _, rt := range ResourceTypes {
		if strings.EqualFold(rt.ID, id) {
			return rt
		}
	}
	return nil
}

func findAttr(attrs []Attr, name string) *Attr {
	for i := range attrs {
		if strings.EqualFold(attrs[i].Name, name) {
			return &attrs[i]
		}
	}
	return nil
}

// common attributes defined outside the schemas (RFC 7643 section 3.1).
var commonAttrs = []Attr{
	{Name: "id", Type: "string", CaseExact: &yes, Mutability: "readOnly", Returned: "always"},
	{Name: "externalId", Type: "string", CaseExact: &yes, Mutability: "readWrite", Returned: "default"},
	complexAttr("meta", "", false, "readOnly",
		str("resourceType", "", true, "readOnly"), Attr{Name: "created", Type: "dateTime", Mutability: "readOnly"},
		Attr{Name: "lastModified", Type: "dateTime", Mutability: "readOnly"}, ref("location", "", "readOnly", "uri"),
		str("version", "", true, "readOnly")),
}

// scope is the attribute namespace a path is resolved in.
type scope struct {
	rt    *ResourceType
	attrs []Attr // nil: resource top level
}

// resolved is an attribute path resolved against a resource type.
type resolved struct {
	ext  string // extension URN (document key) or "" for core/common attributes
	def  *Attr  // nil when the attribute is unknown
	name string // document key (canonical spelling for known attributes)
	sub  string // sub-attribute name, canonical when known
	sdef *Attr
}

// resolve splits "[urn:]attr[.sub]" and finds the definitions.
func (sc scope) resolve(path string) (resolved, *Error) {
	if path == "" {
		return resolved{}, Errf(400, "invalidPath", "empty attribute path")
	}
	var r resolved
	attrs := sc.attrs
	if attrs == nil && sc.rt != nil {
		attrs = append(append([]Attr{}, commonAttrs...), sc.rt.Schema.Attributes...)
		if strings.HasPrefix(strings.ToLower(path), "urn:") {
			rest, ok := cutPrefixFold(path, sc.rt.Schema.ID+":")
			if !ok {
				matched := false
				for _, e := range sc.rt.Extensions {
					if strings.EqualFold(path, e.ID) {
						return resolved{ext: e.ID, name: ""}, nil
					}
					if rest, ok = cutPrefixFold(path, e.ID+":"); ok {
						r.ext, attrs, matched = e.ID, e.Attributes, true
						break
					}
				}
				if !matched {
					return resolved{}, Errf(400, "invalidPath", "unknown schema in attribute path %q", path)
				}
			}
			path = rest
		}
	}
	name, sub, _ := strings.Cut(path, ".")
	if name == "" || strings.ContainsAny(name, " \"[]()") {
		return resolved{}, Errf(400, "invalidPath", "invalid attribute path %q", path)
	}
	r.name, r.sub = name, sub
	if r.def = findAttr(attrs, name); r.def != nil {
		r.name = r.def.Name
		if sub != "" {
			if r.sdef = findAttr(r.def.SubAttributes, sub); r.sdef != nil {
				r.sub = r.sdef.Name
			}
		}
	}
	return r, nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// getFold returns a map value with a case-insensitive key match (SCIM attribute names are
// case-insensitive) and the key actually used.
func getFold(m map[string]any, key string) (any, string) {
	if v, ok := m[key]; ok {
		return v, key
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k
		}
	}
	return nil, ""
}
