package pkgver

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Requirement is a PEP 508 dependency specifier such as `requests[socks] (>=2.8.1,<3) ; python_version < "3.9"`.
type Requirement struct {
	Name      string   // PEP 503 normalized
	Extras    []string // PEP 685 normalized, sorted, unique
	Specifier string   // normalized specifier set ("" = any version)
	URL       string   // direct reference (name @ url)
	Marker    string   // normalized marker ("" = always)

	specifiers SpecifierSet
	marker     *Marker
	parsed     bool
}

// ParseRequirement parses a PEP 508 requirement with packaging's grammar: extras, specifiers with or without
// parentheses, "name @ url" direct references and an environment marker after ";".
func ParseRequirement(s string) (Requirement, error) {
	p := &markerParser{src: s}
	p.ws()
	name := p.identifier()
	if name == "" {
		return Requirement{}, p.errorf("expected package name")
	}
	r := Requirement{Name: NormalizePyPIName(name), parsed: true}
	p.ws()
	if p.peek('[') {
		p.pos++
		p.ws()
		if e := p.identifier(); e != "" {
			r.Extras = append(r.Extras, NormalizePyPIName(e))
			for {
				p.ws()
				if p.identifierAhead() {
					return Requirement{}, p.errorf("expected comma between extra names")
				}
				if !p.peek(',') {
					break
				}
				p.pos++
				p.ws()
				e := p.identifier()
				if e == "" {
					return Requirement{}, p.errorf("expected extra name after comma")
				}
				r.Extras = append(r.Extras, NormalizePyPIName(e))
			}
		}
		p.ws()
		if !p.peek(']') {
			return Requirement{}, p.errorf("expected ] after extras")
		}
		p.pos++
	}
	slices.Sort(r.Extras)
	r.Extras = slices.Compact(r.Extras)
	p.ws()

	var markerText string
	hasMarker := false
	if p.peek('@') {
		p.pos++
		p.ws()
		start := p.pos
		for p.pos < len(s) && s[p.pos] != ' ' && s[p.pos] != '\t' {
			p.pos++
		}
		if p.pos == start {
			return Requirement{}, p.errorf("expected URL after @")
		}
		r.URL = s[start:p.pos]
		if !p.end() {
			if !p.ws() {
				return Requirement{}, p.errorf("expected whitespace after URL")
			}
			if !p.end() {
				hasMarker = true
			}
		}
	} else {
		spec, err := p.specifierList()
		if err != nil {
			return Requirement{}, err
		}
		set, err := ParseSpecifierSet(spec)
		if err != nil {
			return Requirement{}, err
		}
		r.specifiers, r.Specifier = set, set.String()
		p.ws()
		hasMarker = !p.end()
	}
	if hasMarker {
		if !p.peek(';') {
			return Requirement{}, p.errorf("expected semicolon or end")
		}
		p.pos++
		m, err := p.marker()
		if err != nil {
			return Requirement{}, err
		}
		p.ws()
		r.marker = m
		markerText = m.String()
	}
	if !p.end() {
		return Requirement{}, p.errorf("expected end of dependency specifier")
	}
	r.Marker = markerText
	return r, nil
}

// String returns the normalized requirement, e.g. `requests[socks]<3,>=2.8.1; python_version < "3.9"`.
func (r Requirement) String() string {
	var b strings.Builder
	b.WriteString(r.Name)
	if len(r.Extras) > 0 {
		b.WriteString("[" + strings.Join(r.Extras, ",") + "]")
	}
	b.WriteString(r.Specifier)
	if r.URL != "" {
		b.WriteString(" @ " + r.URL)
		if r.Marker != "" {
			b.WriteByte(' ')
		}
	}
	if r.Marker != "" {
		b.WriteString("; " + r.Marker)
	}
	return b.String()
}

// SpecifierSet returns the parsed Specifier.
func (r Requirement) SpecifierSet() SpecifierSet {
	if r.parsed {
		return r.specifiers
	}
	set, _ := ParseSpecifierSet(r.Specifier)
	return set
}

// ParsedMarker returns the parsed Marker (nil = always).
func (r Requirement) ParsedMarker() *Marker {
	if r.parsed || r.Marker == "" {
		return r.marker
	}
	m, _ := ParseMarker(r.Marker)
	return m
}

// Marker is a parsed PEP 508 environment marker. A nil *Marker is the empty marker, which is always true.
type Marker struct {
	// A parenthesized (or the top-level) expression of two or more items joined by ops ("and" / "or"), as
	// packaging keeps it; and binds tighter than or.
	items []*Marker
	ops   []string
	// A comparison (items == nil); op is one of == != < <= > >= ~= === in "not in".
	op  string
	lhs markerOperand
	rhs markerOperand
}

type markerOperand struct {
	variable bool
	s        string // variable name or literal value
}

// ParseMarker parses a marker expression such as `python_version >= "3.8" and (os_name == 'nt' or extra == "x")`.
// Legacy variable spellings (os.name, sys.platform, platform.version, platform.machine,
// platform.python_implementation, python_implementation) are normalized; extra names are normalized (PEP 685).
func ParseMarker(s string) (*Marker, error) {
	p := &markerParser{src: s}
	m, err := p.marker()
	if err != nil {
		return nil, err
	}
	if !p.end() {
		return nil, p.errorf("expected end of marker expression")
	}
	return m, nil
}

// String returns the normalized marker as packaging prints it: single spaces, double-quoted values, the
// expression's parentheses without redundant ones.
func (m *Marker) String() string {
	if m == nil {
		return ""
	}
	var b strings.Builder
	m.format(&b, true)
	return b.String()
}

func (m *Marker) format(b *strings.Builder, top bool) {
	if m.items == nil {
		m.lhs.format(b)
		b.WriteString(" " + m.op + " ")
		m.rhs.format(b)
		return
	}
	if !top {
		b.WriteByte('(')
	}
	for i, it := range m.items {
		if i > 0 {
			b.WriteString(" " + m.ops[i-1] + " ")
		}
		it.format(b, false)
	}
	if !top {
		b.WriteByte(')')
	}
}

func (o markerOperand) format(b *strings.Builder) {
	if o.variable {
		b.WriteString(o.s)
		return
	}
	b.WriteString(quoteMarkerValue(o.s))
}

// quoteMarkerValue quotes a value so that ParseMarker reads it back unchanged.
func quoteMarkerValue(s string) string {
	plain := !strings.ContainsFunc(s, func(r rune) bool { return r == '\\' || r < 0x20 || r == 0x7f })
	if plain && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	if plain && !strings.Contains(s, "'") {
		return "'" + s + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"' || r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Variables whose comparisons use PEP 440 semantics when the value is a valid specifier.
var markerVersionVars = map[string]bool{
	"implementation_version": true, "platform_release": true, "python_full_version": true, "python_version": true,
}

// Set-valued variables of lock files (PEP 751); their environment value is a comma-separated list.
var markerSetVars = map[string]bool{"extras": true, "dependency_groups": true}

// Evaluate evaluates the marker in env (variable name to value) like packaging's Marker.evaluate: PEP 440
// semantics for python_version, python_full_version, implementation_version and platform_release when operator
// and value form a valid specifier, otherwise string equality, substring "in" and false for "<" and ">"; the extra
// value is normalized. The set-valued extras and dependency_groups (PEP 751) are comma-separated lists in env.
// Missing variables are empty strings; comparisons packaging cannot evaluate (UndefinedComparison,
// UndefinedEnvironmentName) are false.
func (m *Marker) Evaluate(env map[string]string) bool {
	if m == nil {
		return true
	}
	return m.eval(env)
}

func (m *Marker) eval(env map[string]string) bool {
	if m.items != nil {
		// any(all(and-group) for and-groups separated by "or")
		group := true
		for i, it := range m.items {
			if i > 0 && m.ops[i-1] == "or" {
				if group {
					return true
				}
				group = true
			}
			group = group && it.eval(env)
		}
		return group
	}
	// As in packaging, the variable on the left is looked up and the right side is taken literally; with a literal
	// on the left, the right side names the environment key.
	var key, lhs, rhs string
	if m.lhs.variable {
		key, lhs, rhs = m.lhs.s, markerEnv(env, m.lhs.s), m.rhs.s
	} else {
		key, lhs = m.rhs.s, m.lhs.s
		if _, ok := env[key]; !ok && !m.rhs.variable {
			return false // undefined environment name
		}
		rhs = markerEnv(env, key)
	}
	if markerSetVars[key] {
		if m.lhs.variable {
			return false // a set cannot be compared
		}
		in := slices.Contains(markerSet(rhs), NormalizePyPIName(lhs))
		switch m.op {
		case "in":
			return in
		case "not in":
			return !in
		case "!=":
			return true
		}
		return false
	}
	if markerVersionVars[key] {
		if sp, err := parsePySpecifier(strings.TrimSpace(m.op + rhs)); err == nil {
			if sp.op == "===" {
				return strings.EqualFold(lhs, sp.text)
			}
			v, err := ParsePEP440(lhs)
			return err == nil && sp.match(v)
		}
	}
	switch m.op {
	case "in":
		return strings.Contains(rhs, lhs)
	case "not in":
		return !strings.Contains(rhs, lhs)
	case "==", "<=", ">=":
		return lhs == rhs
	case "!=":
		return lhs != rhs
	}
	return false // <, > and ~=, === on strings
}

// markerEnv returns an environment value the way packaging prepares the environment: extra normalized and a
// python_full_version ending in "+" (an untagged build) completed to a valid local version.
func markerEnv(env map[string]string, key string) string {
	v := env[key]
	switch key {
	case "extra":
		if v != "" {
			v = NormalizePyPIName(v)
		}
	case "python_full_version":
		if strings.HasSuffix(v, "+") {
			v += "local"
		}
	}
	return v
}

func markerSet(v string) []string {
	var out []string
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, NormalizePyPIName(e))
		}
	}
	return out
}

// MarkerMatchesAny reports whether marker holds in at least one of envs (DefaultPythonEnvironments when envs is
// empty). An empty marker matches; so does an unparsable one (fail-open: the dependency is included and its artifact
// is still pinned). An extra comparison only holds where the environment sets extra.
func MarkerMatchesAny(marker string, envs []map[string]string) bool {
	if strings.TrimSpace(marker) == "" {
		return true
	}
	m, err := ParseMarker(marker)
	if err != nil {
		return true
	}
	if len(envs) == 0 {
		envs = DefaultPythonEnvironments()
	}
	for _, env := range envs {
		if m.Evaluate(env) {
			return true
		}
	}
	return false
}

// DefaultPythonEnvironments returns marker environments of CPython 3.12 on Linux x86_64, Linux aarch64, Windows
// AMD64 and macOS arm64 (fresh maps on every call).
func DefaultPythonEnvironments() []map[string]string {
	base := func(osName, sysPlatform, system, release, version, machine string) map[string]string {
		return map[string]string{
			"implementation_name":            "cpython",
			"implementation_version":         "3.12.10",
			"os_name":                        osName,
			"platform_machine":               machine,
			"platform_python_implementation": "CPython",
			"platform_release":               release,
			"platform_system":                system,
			"platform_version":               version,
			"python_full_version":            "3.12.10",
			"python_version":                 "3.12",
			"sys_platform":                   sysPlatform,
		}
	}
	return []map[string]string{
		base("posix", "linux", "Linux", "6.8.0", "#1 SMP PREEMPT_DYNAMIC", "x86_64"),
		base("posix", "linux", "Linux", "6.8.0", "#1 SMP PREEMPT_DYNAMIC", "aarch64"),
		base("nt", "win32", "Windows", "10", "10.0.19045", "AMD64"),
		base("posix", "darwin", "Darwin", "24.0.0", "Darwin Kernel Version 24.0.0", "arm64"),
	}
}

// markerParser is a recursive-descent parser over packaging's PEP 508 token rules.
type markerParser struct {
	src string
	pos int
}

func (p *markerParser) errorf(format string, args ...any) error {
	return fmt.Errorf("invalid PEP 508 requirement or marker at %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *markerParser) end() bool { return p.pos >= len(p.src) }

func (p *markerParser) peek(c byte) bool { return p.pos < len(p.src) && p.src[p.pos] == c }

// ws skips [ \t]+ and reports whether it skipped anything.
func (p *markerParser) ws() bool {
	start := p.pos
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
	return p.pos > start
}

// isWordBoundary is Python's \b at position i.
func isWordBoundary(s string, i int) bool {
	before, after := false, false
	if i > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:i])
		before = isWordRune(r)
	}
	if i < len(s) {
		r, _ := utf8.DecodeRuneInString(s[i:])
		after = isWordRune(r)
	}
	return before != after
}

func isWordRune(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }

// identifierAt matches \b[a-zA-Z0-9][a-zA-Z0-9._-]*\b at i and returns its end (or -1).
func identifierAt(s string, i int) int {
	if i >= len(s) || !isAlnum(s[i]) || !isWordBoundary(s, i) {
		return -1
	}
	j := i + 1
	for j < len(s) && (isAlnum(s[j]) || isSep(s[j])) {
		j++
	}
	for ; j > i; j-- {
		if isWordBoundary(s, j) {
			return j
		}
	}
	return -1
}

func (p *markerParser) identifier() string {
	e := identifierAt(p.src, p.pos)
	if e < 0 {
		return ""
	}
	s := p.src[p.pos:e]
	p.pos = e
	return s
}

func (p *markerParser) identifierAhead() bool { return identifierAt(p.src, p.pos) >= 0 }

// keyword matches \bword\b.
func (p *markerParser) keyword(word string) bool {
	e := p.pos + len(word)
	if e <= len(p.src) && p.src[p.pos:e] == word && isWordBoundary(p.src, p.pos) && isWordBoundary(p.src, e) {
		p.pos = e
		return true
	}
	return false
}

// specifierList parses `( version_many )` or `version_many` and returns the specifier text.
func (p *markerParser) specifierList() (string, error) {
	paren := p.peek('(')
	if paren {
		p.pos++
	}
	p.ws()
	var b strings.Builder
	for {
		e := specifierTokenAt(p.src, p.pos)
		if e < 0 {
			break
		}
		tok := p.src[p.pos:e]
		b.WriteString(tok)
		p.pos = e
		if strings.HasPrefix(p.src[p.pos:], ".*") {
			return "", p.errorf(".* suffix only allowed after == or != without pre, post, dev or local versions")
		}
		if p.peek('+') && p.pos+1 < len(p.src) && isAlnum(p.src[p.pos+1]) {
			return "", p.errorf("local version label only allowed after == or !=")
		}
		p.ws()
		if !p.peek(',') {
			break
		}
		b.WriteByte(',')
		p.pos++
		p.ws()
	}
	p.ws()
	if paren {
		if !p.peek(')') {
			return "", p.errorf("expected ) after version specifier")
		}
		p.pos++
	}
	return b.String(), nil
}

// specifierTokenAt matches packaging's SPECIFIER token at i and returns its end (or -1).
func specifierTokenAt(s string, i int) int {
	var op string
	switch {
	case strings.HasPrefix(s[i:], "==="):
		op = "==="
	case len(s)-i >= 2 && oneOf(s[i:i+2], "~=", "==", "!=", "<=", ">="):
		op = s[i : i+2]
	case i < len(s) && (s[i] == '<' || s[i] == '>'):
		op = s[i : i+1]
	default:
		return -1
	}
	j := i + len(op)
	for j < len(s) {
		r, n := utf8.DecodeRuneInString(s[j:])
		if !unicode.IsSpace(r) {
			break
		}
		j += n
	}
	if op == "===" {
		for j < len(s) {
			r, n := utf8.DecodeRuneInString(s[j:])
			if unicode.IsSpace(r) || r == ';' || r == ')' {
				break
			}
			j += n
		}
		return j
	}
	if (op == "==" || op == "!=") && wildcardAt(s, j) > 0 {
		return wildcardAt(s, j)
	}
	v, rest, ok := scanPEP440(s[j:], op == "==" || op == "!=")
	if !ok || (op == "~=" && len(v.release) < 2) {
		return -1
	}
	return len(s) - len(rest)
}

// wildcardAt matches v?(N!)?N(.N)*.* at i and returns its end (or -1).
func wildcardAt(s string, i int) int {
	j := i
	if j < len(s) && (s[j] == 'v' || s[j] == 'V') {
		j++
	}
	digits := func() bool {
		k := j
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		return j > k
	}
	if !digits() {
		return -1
	}
	if j < len(s) && s[j] == '!' {
		j++
		if !digits() {
			return -1
		}
	}
	for j+1 < len(s) && s[j] == '.' && isDigit(s[j+1]) {
		j++
		digits()
	}
	if strings.HasPrefix(s[j:], ".*") {
		return j + 2
	}
	return -1
}

// marker parses `marker_atom (BOOLOP marker_atom)*`; a single atom is returned as is.
func (p *markerParser) marker() (*Marker, error) {
	m := &Marker{}
	for {
		a, err := p.atom()
		if err != nil {
			return nil, err
		}
		m.items = append(m.items, a)
		switch {
		case p.keyword("and"):
			m.ops = append(m.ops, "and")
		case p.keyword("or"):
			m.ops = append(m.ops, "or")
		case len(m.items) == 1:
			return a, nil
		default:
			return m, nil
		}
	}
}

func (p *markerParser) atom() (*Marker, error) {
	p.ws()
	var m *Marker
	if p.peek('(') {
		p.pos++
		p.ws()
		inner, err := p.marker()
		if err != nil {
			return nil, err
		}
		p.ws()
		if !p.peek(')') {
			return nil, p.errorf("expected ) after marker expression")
		}
		p.pos++
		m = inner
	} else {
		item, err := p.item()
		if err != nil {
			return nil, err
		}
		m = item
	}
	p.ws()
	return m, nil
}

func (p *markerParser) item() (*Marker, error) {
	p.ws()
	lhs, err := p.operand()
	if err != nil {
		return nil, err
	}
	p.ws()
	var op string
	switch {
	case p.keyword("in"):
		op = "in"
	case p.keyword("not"):
		if !p.ws() || !p.keyword("in") {
			return nil, p.errorf("expected 'in' after 'not'")
		}
		op = "not in"
	default:
		for _, o := range []string{"===", "==", "~=", "!=", "<=", ">=", "<", ">"} {
			if strings.HasPrefix(p.src[p.pos:], o) {
				op = o
				p.pos += len(o)
				break
			}
		}
		if op == "" {
			return nil, p.errorf("expected marker operator")
		}
	}
	p.ws()
	rhs, err := p.operand()
	if err != nil {
		return nil, err
	}
	p.ws()
	// PEP 685: extra names are compared normalized.
	switch {
	case lhs.variable && lhs.s == "extra" && !rhs.variable:
		rhs.s = NormalizePyPIName(rhs.s)
	case rhs.variable && (rhs.s == "extra" || markerSetVars[rhs.s]) && !lhs.variable:
		lhs.s = NormalizePyPIName(lhs.s)
	}
	return &Marker{op: op, lhs: lhs, rhs: rhs}, nil
}

// markerVariables are packaging's VARIABLE alternatives (longest first) and their normalized names.
var markerVariables = []struct{ spelling, name string }{
	{"platform_python_implementation", "platform_python_implementation"},
	{"platform.python_implementation", "platform_python_implementation"},
	{"implementation_version", "implementation_version"},
	{"python_implementation", "platform_python_implementation"},
	{"python_full_version", "python_full_version"},
	{"implementation_name", "implementation_name"},
	{"dependency_groups", "dependency_groups"},
	{"platform_release", "platform_release"},
	{"platform_version", "platform_version"},
	{"platform.version", "platform_version"},
	{"platform_machine", "platform_machine"},
	{"platform.machine", "platform_machine"},
	{"platform_system", "platform_system"},
	{"python_version", "python_version"},
	{"sys_platform", "sys_platform"},
	{"sys.platform", "sys_platform"},
	{"os_name", "os_name"},
	{"os.name", "os_name"},
	{"extras", "extras"},
	{"extra", "extra"},
}

func (p *markerParser) operand() (markerOperand, error) {
	for _, v := range markerVariables {
		if p.keyword(v.spelling) {
			return markerOperand{variable: true, s: v.name}, nil
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == '"' || p.src[p.pos] == '\'') {
		q := p.src[p.pos]
		end := strings.IndexByte(p.src[p.pos+1:], q)
		if end < 0 {
			return markerOperand{}, p.errorf("unterminated quoted string")
		}
		val, err := decodePyString(p.src[p.pos+1 : p.pos+1+end])
		if err != nil {
			return markerOperand{}, p.errorf("invalid quoted string: %v", err)
		}
		p.pos += end + 2
		return markerOperand{s: val}, nil
	}
	return markerOperand{}, p.errorf("expected a marker variable or quoted string")
}

// decodePyString decodes the body of a Python string literal (ast.literal_eval).
func decodePyString(s string) (string, error) {
	if !strings.ContainsAny(s, "\\\n\r\x00") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\n', '\r', 0:
			return "", fmt.Errorf("unterminated or invalid string literal")
		case '\\':
		default:
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("string literal ends with a backslash")
		}
		switch e := s[i]; e {
		case '\n':
		case '\\', '\'', '"':
			b.WriteByte(e)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint(s[i:j], 8, 32)
			b.WriteRune(rune(n))
			i = j - 1
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			if i+1+width > len(s) {
				return "", fmt.Errorf("truncated \\%c escape", e)
			}
			n, err := strconv.ParseUint(s[i+1:i+1+width], 16, 32)
			if err != nil || n > unicode.MaxRune {
				return "", fmt.Errorf("invalid \\%c escape", e)
			}
			b.WriteRune(rune(n))
			i += width
		case 'N':
			return "", fmt.Errorf("\\N escapes are not supported")
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String(), nil
}
