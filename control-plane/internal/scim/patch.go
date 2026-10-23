package scim

// PATCH (RFC 7644 section 3.5.2) applied to the JSON representation of a resource. The result is
// parsed again like a PUT body, so validation is identical for both. Interoperability notes:
//   - "op" is case-insensitive (Entra ID sends "Add", "Replace", "Remove").
//   - Path-less add/replace values may use attribute paths as keys ("name.givenName",
//     "urn:…:enterprise:2.0:User:department") and contain read-only attributes such as "id" (Okta
//     sends it when renaming groups): those are ignored.
//   - remove with path "members" and a value list removes only those members (Entra ID).
//   - Attributes the schemas do not define (phoneNumbers, addresses, roles …) are ignored, so that
//     default IdP attribute mappings do not fail provisioning.
//   - Entra ID may send booleans as "True"/"False" strings; the parser accepts them.

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// PatchRequest is the body of a PATCH request.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one operation of a PATCH request.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

const maxPatchOperations = 1000

// ApplyPatch applies the operations to doc (modified in place).
func ApplyPatch(doc map[string]any, rt *ResourceType, req PatchRequest) *Error {
	if len(req.Schemas) > 0 && !slices.ContainsFunc(req.Schemas, func(s string) bool { return strings.EqualFold(s, PatchOpSchema) }) {
		return Errf(400, "invalidSyntax", "schemas must contain %s", PatchOpSchema)
	}
	if len(req.Operations) == 0 {
		return Errf(400, "invalidSyntax", "no operations")
	}
	if len(req.Operations) > maxPatchOperations {
		return Errf(400, "tooMany", "at most %d operations per request", maxPatchOperations)
	}
	for _, o := range req.Operations {
		op := strings.ToLower(strings.TrimSpace(o.Op))
		if op != "add" && op != "replace" && op != "remove" {
			return Errf(400, "invalidSyntax", "unsupported operation %q", o.Op)
		}
		var val any
		if len(o.Value) > 0 {
			if err := json.Unmarshal(o.Value, &val); err != nil {
				return Errf(400, "invalidSyntax", "invalid operation value")
			}
		}
		if strings.TrimSpace(o.Path) == "" {
			if op == "remove" {
				return Errf(400, "noTarget", "remove requires a path")
			}
			m, ok := val.(map[string]any)
			if !ok {
				return badValue("a %s operation without path needs an object value", op)
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if strings.EqualFold(k, "schemas") {
					continue
				}
				if ext := extensionByID(rt, k); ext != nil {
					sub, ok := m[k].(map[string]any)
					if !ok {
						return badValue("%s must be an object", k)
					}
					for k2, v2 := range sub {
						if err := applyPath(doc, rt, op, ext.ID+":"+k2, v2, true); err != nil {
							return err
						}
					}
					continue
				}
				if err := applyPath(doc, rt, op, k, m[k], true); err != nil {
					return err
				}
			}
			continue
		}
		if err := applyPath(doc, rt, op, strings.TrimSpace(o.Path), val, false); err != nil {
			return err
		}
	}
	return nil
}

func extensionByID(rt *ResourceType, id string) *Schema {
	for _, e := range rt.Extensions {
		if strings.EqualFold(e.ID, id) {
			return e
		}
	}
	return nil
}

type patchPath struct {
	res    resolved
	filter *Filter
	sub    string
}

func parsePatchPath(path string, rt *ResourceType) (patchPath, *Error) {
	if len(path) > 1024 {
		return patchPath{}, Errf(400, "invalidPath", "path too long")
	}
	toks, err := tokenize(path)
	if err != nil {
		return patchPath{}, Errf(400, "invalidPath", "invalid path %q", path)
	}
	p := &parser{toks: toks}
	t := p.next()
	if t.kind != 'w' {
		return patchPath{}, Errf(400, "invalidPath", "invalid path %q", path)
	}
	var pp patchPath
	if pp.res, err = (scope{rt: rt}).resolve(t.text); err != nil {
		return patchPath{}, err
	}
	if p.peek().kind == '[' {
		if pp.res.sub != "" {
			return patchPath{}, Errf(400, "invalidPath", "invalid path %q", path)
		}
		p.next()
		n, ferr := p.or(1)
		if ferr != nil {
			return patchPath{}, Errf(400, "invalidPath", "invalid filter in path %q: %s", path, ferr.Detail)
		}
		if p.next().kind != ']' {
			return patchPath{}, Errf(400, "invalidPath", "missing ] in path %q", path)
		}
		pp.filter = &Filter{root: n, rt: rt}
		if nt := p.peek(); nt.kind == 'w' && strings.HasPrefix(nt.text, ".") {
			p.next()
			pp.sub = strings.TrimPrefix(nt.text, ".")
			if pp.res.def != nil {
				if sd := findAttr(pp.res.def.SubAttributes, pp.sub); sd != nil {
					pp.sub = sd.Name
				}
			}
		}
	}
	if p.peek().kind != 0 {
		return patchPath{}, Errf(400, "invalidPath", "invalid path %q", path)
	}
	return pp, nil
}

// container returns the map holding the attribute (the document or an extension object).
func container(doc map[string]any, ext string, create bool) map[string]any {
	if ext == "" {
		return doc
	}
	v, k := getFold(doc, ext)
	if m, ok := v.(map[string]any); ok {
		if k != ext {
			delete(doc, k)
			doc[ext] = m
		}
		return m
	}
	if !create {
		return nil
	}
	m := map[string]any{}
	doc[ext] = m
	return m
}

// canonicalKey removes differently-cased duplicates of key and returns the current value.
func canonicalKey(m map[string]any, key string) any {
	v, k := getFold(m, key)
	if k != "" && k != key {
		delete(m, k)
		m[key] = v
	}
	return v
}

func applyPath(doc map[string]any, rt *ResourceType, op, path string, val any, pathless bool) *Error {
	pp, err := parsePatchPath(path, rt)
	if err != nil {
		if pathless { // unknown keys of a path-less value are ignored like unknown attributes
			return nil
		}
		return err
	}
	r := pp.res
	if r.name == "" { // the whole extension: "urn:…:enterprise:2.0:User"
		switch op {
		case "remove":
			if _, k := getFold(doc, r.ext); k != "" {
				delete(doc, k)
			}
			return nil
		default:
			m, ok := val.(map[string]any)
			if !ok {
				return badValue("%s must be an object", r.ext)
			}
			for k, v := range m {
				if err := applyPath(doc, rt, op, r.ext+":"+k, v, true); err != nil {
					return err
				}
			}
			return nil
		}
	}
	def := r.def
	if def == nil {
		return nil // attribute not stored by AegisProxy: ignored (see package comment)
	}
	if def.Mutability == "readOnly" || (r.sdef != nil && r.sdef.Mutability == "readOnly") {
		if pathless {
			return nil
		}
		return Errf(400, "mutability", "attribute %q is read-only", path)
	}
	c := container(doc, r.ext, op != "remove")
	if c == nil {
		return nil
	}
	cur := canonicalKey(c, def.Name)
	switch {
	case pp.filter != nil:
		if !def.MultiValued || def.Type != "complex" {
			return Errf(400, "invalidPath", "a filter can only select values of a multi-valued complex attribute")
		}
		return applyFiltered(c, def, op, pp, val)
	case r.sub != "":
		return applySub(c, def, op, r.sub, val)
	}
	switch op {
	case "remove":
		if def.MultiValued && val != nil {
			rm := newValueIndex(toList(val))
			list := slices.DeleteFunc(toList(cur), func(x any) bool { return rm.find(x) >= 0 })
			setOrDelete(c, def.Name, list)
			return nil
		}
		delete(c, def.Name)
	case "add":
		if val == nil {
			return nil
		}
		switch {
		case def.MultiValued:
			list := toList(cur)
			idx := newValueIndex(list)
			added := []int{}
			for _, x := range toList(val) {
				if i := idx.find(x); i >= 0 {
					list[i] = mergeElement(list[i], x)
					added = append(added, i)
					continue
				}
				list = append(list, x)
				idx.add(x, len(list)-1)
				added = append(added, len(list)-1)
			}
			fixPrimary(list, added)
			setOrDelete(c, def.Name, list)
		case def.Type == "complex":
			return mergeComplex(c, def, val)
		default:
			c[def.Name] = val
		}
	case "replace":
		switch {
		case val == nil:
			delete(c, def.Name)
		case def.MultiValued:
			list := toList(val)
			fixPrimary(list, nil)
			setOrDelete(c, def.Name, list)
		case def.Type == "complex":
			return mergeComplex(c, def, val)
		default:
			c[def.Name] = val
		}
	}
	return nil
}

// applySub handles "name.givenName" (and "emails.value" for every element).
func applySub(c map[string]any, def *Attr, op, sub string, val any) *Error {
	if sd := findAttr(def.SubAttributes, sub); sd != nil {
		sub = sd.Name
	} else if def.Type == "complex" {
		return nil // unknown sub-attribute: ignored
	}
	if def.MultiValued {
		list := toList(c[def.Name])
		for _, e := range list {
			if m, ok := e.(map[string]any); ok {
				setSub(m, op, sub, val)
			}
		}
		setOrDelete(c, def.Name, list)
		return nil
	}
	m, ok := c[def.Name].(map[string]any)
	if !ok {
		if op == "remove" {
			return nil
		}
		m = map[string]any{}
	}
	setSub(m, op, sub, val)
	if len(m) == 0 {
		delete(c, def.Name)
	} else {
		c[def.Name] = m
	}
	return nil
}

func setSub(m map[string]any, op, sub string, val any) {
	canonicalKey(m, sub)
	if op == "remove" || val == nil {
		delete(m, sub)
		return
	}
	m[sub] = val
}

func applyFiltered(c map[string]any, def *Attr, op string, pp patchPath, val any) *Error {
	list := toList(c[def.Name])
	var hit []int
	for i, e := range list {
		if m, ok := e.(map[string]any); ok && pp.filter.matchElement(m, def.SubAttributes) {
			hit = append(hit, i)
		}
	}
	switch op {
	case "remove":
		if pp.sub != "" {
			for _, i := range hit {
				setSub(list[i].(map[string]any), "remove", pp.sub, nil)
			}
		} else {
			list = slices.DeleteFunc(list, func(e any) bool {
				m, ok := e.(map[string]any)
				return ok && pp.filter.matchElement(m, def.SubAttributes)
			})
		}
	default:
		switch {
		case pp.sub != "" && len(hit) > 0:
			for _, i := range hit {
				setSub(list[i].(map[string]any), "add", pp.sub, val)
			}
		case pp.sub != "":
			// emails[type eq "work"].value on a user without a work address: create it.
			e := equalityConstraints(pp.filter.root)
			if e == nil {
				return Errf(400, "noTarget", "no value matches the filter of %q", def.Name)
			}
			e[pp.sub] = val
			list = append(list, e)
			hit = []int{len(list) - 1}
		case len(hit) > 0:
			m, ok := val.(map[string]any)
			if !ok {
				return badValue("the value for a filtered %s must be an object", def.Name)
			}
			for _, i := range hit {
				if op == "add" {
					list[i] = mergeElement(list[i], m)
				} else {
					list[i] = cloneMap(m)
				}
			}
		case op == "add":
			for _, x := range toList(val) {
				list = append(list, x)
				hit = append(hit, len(list)-1)
			}
		default:
			return Errf(400, "noTarget", "no value matches the filter of %q", def.Name)
		}
		fixPrimary(list, hit)
	}
	setOrDelete(c, def.Name, list)
	return nil
}

// equalityConstraints extracts attr eq "value" (joined with and) from a filter, to create the
// element a filtered path refers to.
func equalityConstraints(n node) map[string]any {
	switch t := n.(type) {
	case compare:
		if t.op == "eq" && t.value != nil && !strings.Contains(t.path, ".") {
			return map[string]any{t.path: t.value}
		}
	case logical:
		if t.and {
			l, r := equalityConstraints(t.l), equalityConstraints(t.r)
			if l != nil && r != nil {
				for k, v := range r {
					l[k] = v
				}
				return l
			}
		}
	}
	return nil
}

func mergeComplex(c map[string]any, def *Attr, val any) *Error {
	m, ok := val.(map[string]any)
	if !ok {
		return badValue("%s must be an object", def.Name)
	}
	cur, _ := c[def.Name].(map[string]any)
	if cur == nil {
		cur = map[string]any{}
	}
	for k, v := range m {
		name := k
		if sd := findAttr(def.SubAttributes, k); sd != nil {
			name = sd.Name
		}
		canonicalKey(cur, name)
		if v == nil {
			delete(cur, name)
		} else {
			cur[name] = v
		}
	}
	if len(cur) == 0 {
		delete(c, def.Name)
	} else {
		c[def.Name] = cur
	}
	return nil
}

func toList(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return slices.Clone(t)
	default:
		return []any{t}
	}
}

func setOrDelete(c map[string]any, key string, list []any) {
	if len(list) == 0 {
		delete(c, key)
		return
	}
	c[key] = list
}

// valueIndex finds elements of a multi-valued attribute by their "value" sub-attribute in constant
// time (group documents can have tens of thousands of members); other elements are compared fully.
type valueIndex struct {
	byValue map[string]int
	rest    []any
	restPos []int
}

func valueKey(x any) (string, bool) {
	if m, ok := x.(map[string]any); ok {
		if v, k := getFold(m, "value"); k != "" {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func newValueIndex(list []any) *valueIndex {
	ix := &valueIndex{byValue: make(map[string]int, len(list))}
	for i, x := range list {
		ix.add(x, i)
	}
	return ix
}

func (ix *valueIndex) add(x any, pos int) {
	if k, ok := valueKey(x); ok {
		if _, dup := ix.byValue[k]; !dup {
			ix.byValue[k] = pos
		}
		return
	}
	ix.rest, ix.restPos = append(ix.rest, x), append(ix.restPos, pos)
}

func (ix *valueIndex) find(x any) int {
	if k, ok := valueKey(x); ok {
		if i, hit := ix.byValue[k]; hit {
			return i
		}
		return -1
	}
	for j, y := range ix.rest {
		if sameValue(x, y) {
			return ix.restPos[j]
		}
	}
	return -1
}

// sameValue compares elements of a multi-valued attribute by their "value" sub-attribute (members,
// emails) or entirely.
func sameValue(a, b any) bool {
	ma, oka := a.(map[string]any)
	mb, okb := b.(map[string]any)
	if oka && okb {
		va, ka := getFold(ma, "value")
		vb, kb := getFold(mb, "value")
		if ka != "" && kb != "" {
			sa, _ := va.(string)
			sb, _ := vb.(string)
			if sa != "" || sb != "" {
				return sa == sb
			}
		}
	}
	return reflect.DeepEqual(a, b)
}

func mergeElement(cur, add any) any {
	mc, ok1 := cur.(map[string]any)
	ma, ok2 := add.(map[string]any)
	if !ok1 || !ok2 {
		return add
	}
	out := cloneMap(mc)
	for k, v := range ma {
		canonicalKey(out, k)
		out[k] = v
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// fixPrimary keeps at most one primary value (RFC 7643 section 2.4): the most recently written one.
func fixPrimary(list []any, changed []int) {
	keep := -1
	for _, i := range changed {
		if m, ok := list[i].(map[string]any); ok && truthy(m["primary"]) {
			keep = i
		}
	}
	if keep < 0 {
		return
	}
	for i, e := range list {
		if m, ok := e.(map[string]any); ok && i != keep && truthy(m["primary"]) {
			m2 := cloneMap(m)
			m2["primary"] = false
			list[i] = m2
		}
	}
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}
