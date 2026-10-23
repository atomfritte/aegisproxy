package scim

// Filter expressions (RFC 7644 section 3.4.2.2): attribute operators eq ne co sw ew gt ge lt le pr,
// logical and/or/not with grouping, value paths (emails[type eq "work"]) and the
// emails[type eq "work"].value eq "…" form some clients send. Attribute names are
// case-insensitive; string comparisons honour caseExact of the schema.

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Filter is a parsed filter expression.
type Filter struct {
	root node
	rt   *ResourceType
	expr string
}

// String returns the filter expression.
func (f *Filter) String() string { return f.expr }

type node interface {
	match(doc map[string]any, sc scope) bool
}

type token struct {
	kind byte // 'w' word, 's' string, '(' ')' '[' ']', 0 EOF
	text string
}

func tokenize(in string) ([]token, *Error) {
	var out []token
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '[' || c == ']':
			out = append(out, token{kind: c, text: string(c)})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(in); j++ {
				if in[j] == '\\' {
					j++
					continue
				}
				if in[j] == '"' {
					break
				}
			}
			if j >= len(in) {
				return nil, Errf(400, "invalidFilter", "unterminated string in filter")
			}
			var s string
			if err := json.Unmarshal([]byte(in[i:j+1]), &s); err != nil {
				return nil, Errf(400, "invalidFilter", "invalid string literal in filter")
			}
			out = append(out, token{kind: 's', text: s})
			i = j + 1
		default:
			j := i
			for j < len(in) && !strings.ContainsRune(" \t\r\n()[]\"", rune(in[j])) {
				j++
			}
			out = append(out, token{kind: 'w', text: in[i:j]})
			i = j
		}
	}
	return append(out, token{}), nil
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) keyword(kw string) bool {
	t := p.peek()
	if t.kind == 'w' && strings.EqualFold(t.text, kw) {
		p.next()
		return true
	}
	return false
}

// ParseFilter parses a filter for a resource type.
func ParseFilter(expr string, rt *ResourceType) (*Filter, *Error) {
	if strings.TrimSpace(expr) == "" {
		return nil, Errf(400, "invalidFilter", "empty filter")
	}
	if len(expr) > 4096 {
		return nil, Errf(400, "invalidFilter", "filter too long")
	}
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != 0 {
		return nil, Errf(400, "invalidFilter", "unexpected %q in filter", p.peek().text)
	}
	return &Filter{root: n, rt: rt, expr: expr}, nil
}

const maxFilterDepth = 32

func (p *parser) or(depth int) (node, *Error) {
	l, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("or") {
		r, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		l = logical{and: false, l: l, r: r}
	}
	return l, nil
}

func (p *parser) and(depth int) (node, *Error) {
	l, err := p.unary(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("and") {
		r, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		l = logical{and: true, l: l, r: r}
	}
	return l, nil
}

func (p *parser) unary(depth int) (node, *Error) {
	if depth > maxFilterDepth {
		return nil, Errf(400, "invalidFilter", "filter nested too deeply")
	}
	if p.keyword("not") {
		if p.next().kind != '(' {
			return nil, Errf(400, "invalidFilter", "expected ( after not")
		}
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next().kind != ')' {
			return nil, Errf(400, "invalidFilter", "missing )")
		}
		return not{n}, nil
	}
	if p.peek().kind == '(' {
		p.next()
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next().kind != ')' {
			return nil, Errf(400, "invalidFilter", "missing )")
		}
		return n, nil
	}
	return p.attrExp(depth)
}

var compareOps = map[string]bool{"eq": true, "ne": true, "co": true, "sw": true, "ew": true, "gt": true, "ge": true, "lt": true, "le": true}

func (p *parser) attrExp(depth int) (node, *Error) {
	t := p.next()
	if t.kind != 'w' || strings.HasPrefix(t.text, ".") {
		return nil, Errf(400, "invalidFilter", "expected an attribute name, got %q", t.text)
	}
	path := t.text
	if p.peek().kind == '[' {
		p.next()
		inner, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next().kind != ']' {
			return nil, Errf(400, "invalidFilter", "missing ]")
		}
		vp := valuePath{attr: path, filter: inner}
		if nt := p.peek(); nt.kind == 'w' && strings.HasPrefix(nt.text, ".") {
			p.next()
			cmp, err := p.comparison(strings.TrimPrefix(nt.text, "."))
			if err != nil {
				return nil, err
			}
			vp.sub = &cmp
		}
		return vp, nil
	}
	cmp, err := p.comparison(path)
	if err != nil {
		return nil, err
	}
	return cmp, nil
}

func (p *parser) comparison(path string) (compare, *Error) {
	opTok := p.next()
	op := strings.ToLower(opTok.text)
	if opTok.kind != 'w' || (op != "pr" && !compareOps[op]) {
		return compare{}, Errf(400, "invalidFilter", "unknown operator %q", opTok.text)
	}
	c := compare{path: path, op: op}
	if op == "pr" {
		return c, nil
	}
	v := p.next()
	switch {
	case v.kind == 's':
		c.value = v.text
	case v.kind == 'w' && strings.EqualFold(v.text, "true"):
		c.value = true
	case v.kind == 'w' && strings.EqualFold(v.text, "false"):
		c.value = false
	case v.kind == 'w' && strings.EqualFold(v.text, "null"):
		c.value = nil
	case v.kind == 'w':
		f, err := strconv.ParseFloat(v.text, 64)
		if err != nil {
			return compare{}, Errf(400, "invalidFilter", "invalid comparison value %q (strings must be quoted)", v.text)
		}
		c.value = f
	default:
		return compare{}, Errf(400, "invalidFilter", "missing comparison value")
	}
	return c, nil
}

// EqualityOn reports whether the filter is a single `attr eq "value"` comparison on a top-level
// attribute; the caller can then preselect candidates without rendering every resource (Entra ID
// and Okta look up each user and group this way during a provisioning cycle). attr is lower-case.
func (f *Filter) EqualityOn() (attr, value string, ok bool) {
	c, isCmp := f.root.(compare)
	v, isStr := c.value.(string)
	if !isCmp || c.op != "eq" || !isStr || strings.ContainsAny(c.path, ".:") {
		return "", "", false
	}
	return strings.ToLower(c.path), v, true
}

// Match reports whether a rendered resource matches the filter.
func (f *Filter) Match(doc map[string]any) bool { return f.root.match(doc, scope{rt: f.rt}) }

type logical struct {
	and  bool
	l, r node
}

func (n logical) match(doc map[string]any, sc scope) bool {
	if n.and {
		return n.l.match(doc, sc) && n.r.match(doc, sc)
	}
	return n.l.match(doc, sc) || n.r.match(doc, sc)
}

type not struct{ n node }

func (n not) match(doc map[string]any, sc scope) bool { return !n.n.match(doc, sc) }

type compare struct {
	path  string
	op    string
	value any
}

// values collects the values an attribute path designates (multi-valued attributes flattened;
// complex values compare by their "value" sub-attribute).
func values(doc map[string]any, sc scope, path string) ([]any, *Attr) {
	r, err := sc.resolve(path)
	if err != nil || r.name == "" {
		return nil, nil
	}
	container := doc
	if r.ext != "" {
		ext, _ := getFold(doc, r.ext)
		m, ok := ext.(map[string]any)
		if !ok {
			return nil, nil
		}
		container = m
	}
	v, _ := getFold(container, r.name)
	def := r.def
	var out []any
	add := func(x any) {
		if m, ok := x.(map[string]any); ok {
			if r.sub != "" {
				sv, _ := getFold(m, r.sub)
				out = append(out, sv)
			} else {
				sv, _ := getFold(m, "value")
				out = append(out, sv)
			}
			return
		}
		if r.sub == "" {
			out = append(out, x)
		}
	}
	switch t := v.(type) {
	case nil:
	case []any:
		for _, x := range t {
			add(x)
		}
	default:
		add(t)
	}
	if r.sdef != nil {
		def = r.sdef
	} else if def != nil && def.Type == "complex" && r.sub == "" {
		def = findAttr(def.SubAttributes, "value")
	}
	return out, def
}

func (c compare) match(doc map[string]any, sc scope) bool {
	vals, def := values(doc, sc, c.path)
	caseExact := def != nil && def.CaseExact != nil && *def.CaseExact
	present := false
	for _, v := range vals {
		if !isEmpty(v) {
			present = true
		}
	}
	switch c.op {
	case "pr":
		return present
	case "ne":
		if c.value == nil {
			return present
		}
		for _, v := range vals {
			if cmpValue("eq", v, c.value, caseExact) {
				return false
			}
		}
		return true
	case "eq":
		if c.value == nil {
			return !present
		}
	}
	for _, v := range vals {
		if cmpValue(c.op, v, c.value, caseExact) {
			return true
		}
	}
	return false
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func cmpValue(op string, v, lit any, caseExact bool) bool {
	switch l := lit.(type) {
	case string:
		s, ok := v.(string)
		if !ok {
			return false
		}
		if !caseExact {
			s, l = strings.ToLower(s), strings.ToLower(l)
		}
		switch op {
		case "eq":
			return s == l
		case "co":
			return strings.Contains(s, l)
		case "sw":
			return strings.HasPrefix(s, l)
		case "ew":
			return strings.HasSuffix(s, l)
		}
		c := strings.Compare(s, l)
		if ts, err1 := time.Parse(time.RFC3339Nano, s); err1 == nil {
			if tl, err2 := time.Parse(time.RFC3339Nano, l); err2 == nil {
				c = ts.Compare(tl)
			}
		}
		return ordered(op, c)
	case bool:
		b, ok := v.(bool)
		if s, isStr := v.(string); isStr { // some IdPs store booleans as "True"/"False"
			b, ok = strings.EqualFold(s, "true"), strings.EqualFold(s, "true") || strings.EqualFold(s, "false")
		}
		return ok && op == "eq" && b == l
	case float64:
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case int:
			f = float64(n)
		case int64:
			f = float64(n)
		default:
			return false
		}
		switch {
		case f < l:
			return ordered(op, -1)
		case f > l:
			return ordered(op, 1)
		}
		return op == "eq" || ordered(op, 0)
	}
	return false
}

func ordered(op string, c int) bool {
	switch op {
	case "gt":
		return c > 0
	case "ge":
		return c >= 0
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	}
	return false
}

type valuePath struct {
	attr   string
	filter node
	sub    *compare // emails[type eq "work"].value eq "x"
}

// elements returns the complex values of a multi-valued attribute and their definition.
func elements(doc map[string]any, sc scope, path string) ([]map[string]any, *Attr) {
	r, err := sc.resolve(path)
	if err != nil || r.name == "" {
		return nil, nil
	}
	container := doc
	if r.ext != "" {
		ext, _ := getFold(doc, r.ext)
		m, ok := ext.(map[string]any)
		if !ok {
			return nil, r.def
		}
		container = m
	}
	v, _ := getFold(container, r.name)
	var out []map[string]any
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case map[string]any:
		out = append(out, t)
	}
	return out, r.def
}

func (n valuePath) match(doc map[string]any, sc scope) bool {
	elems, def := elements(doc, sc, n.attr)
	inner := scope{rt: sc.rt, attrs: []Attr{}}
	if def != nil {
		inner.attrs = def.SubAttributes
	}
	for _, e := range elems {
		if !n.filter.match(e, inner) {
			continue
		}
		if n.sub == nil || n.sub.match(e, inner) {
			return true
		}
	}
	return false
}

// matchElement evaluates a value-path filter against one element of a multi-valued attribute.
func (f *Filter) matchElement(e map[string]any, sub []Attr) bool {
	return f.root.match(e, scope{rt: f.rt, attrs: sub})
}
