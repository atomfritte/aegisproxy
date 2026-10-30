package pkgver

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// NPMRange is a node-semver range (a union of comparator sets), parsed the way npm parses dependency ranges
// (node-semver's loose mode, semver 7.8). The zero value contains no version.
type NPMRange struct {
	sets    [][]npmComparator // parsed with includePrerelease=false
	setsPre [][]npmComparator // parsed with includePrerelease=true (lower bounds get a -0 prerelease)
}

type npmOp uint8

const (
	npmAny npmOp = iota // "" (matches every version)
	npmEQ
	npmLT
	npmLE
	npmGT
	npmGE
)

type npmComparator struct {
	op  npmOp
	ver NPMVersion
}

var errNPMRange = errors.New("invalid npm range")

// Regular expressions of node-semver (internal/re.js). Range parsing rewrites the range text with them exactly like
// node-semver does; only the parsed comparators are used when matching versions.
const (
	srcNumID        = `0|[1-9]\d*`
	srcNumIDLoose   = `\d+`
	srcNonNumID     = `\d*[a-zA-Z-][a-zA-Z0-9-]*`
	srcPreID        = `(?:` + srcNonNumID + `|` + srcNumID + `)`
	srcPreIDLoose   = `(?:` + srcNonNumID + `|` + srcNumIDLoose + `)`
	srcPre          = `(?:-(` + srcPreID + `(?:\.` + srcPreID + `)*))`
	srcPreLoose     = `(?:-?(` + srcPreIDLoose + `(?:\.` + srcPreIDLoose + `)*))`
	srcBuildID      = `[a-zA-Z0-9-]+`
	srcBuild        = `(?:\+(` + srcBuildID + `(?:\.` + srcBuildID + `)*))`
	srcMainLoose    = `(` + srcNumIDLoose + `)\.(` + srcNumIDLoose + `)\.(` + srcNumIDLoose + `)`
	srcLoosePlain   = `[v=\s]*` + srcMainLoose + srcPreLoose + `?` + srcBuild + `?`
	srcGTLT         = `((?:<|>)?=?)`
	srcXRID         = srcNumID + `|x|X|\*`
	srcXRIDLoose    = srcNumIDLoose + `|x|X|\*`
	srcXRPlain      = `[v=\s]*(` + srcXRID + `)(?:\.(` + srcXRID + `)(?:\.(` + srcXRID + `)(?:` + srcPre + `)?` + srcBuild + `?)?)?`
	srcXRPlainLoose = `[v=\s]*(` + srcXRIDLoose + `)(?:\.(` + srcXRIDLoose + `)(?:\.(` + srcXRIDLoose + `)(?:` + srcPreLoose + `)?` + srcBuild + `?)?)?`
)

var (
	reSemverBuild     = regexp.MustCompile(srcBuild)
	reHyphenLoose     = regexp.MustCompile(`^\s?(` + srcXRPlainLoose + `)\s-\s(` + srcXRPlainLoose + `)\s?$`)
	reComparatorTrim  = regexp.MustCompile(`(\s?)` + srcGTLT + `\s?(` + srcLoosePlain + `|` + srcXRPlain + `)`)
	reTildeTrim       = regexp.MustCompile(`(\s?)(?:~>?)\s`)
	reCaretTrim       = regexp.MustCompile(`(\s?)(?:\^)\s`)
	reTildeLoose      = regexp.MustCompile(`^(?:~>?)` + srcXRPlainLoose + `$`)
	reCaretLoose      = regexp.MustCompile(`^(?:\^)` + srcXRPlainLoose + `$`)
	reXRangeLoose     = regexp.MustCompile(`^` + srcGTLT + `\s?` + srcXRPlainLoose + `$`)
	reStar            = regexp.MustCompile(`(<|>)?=?\s?\*`)
	reGTE0            = regexp.MustCompile(`^\s?>=\s?0\.0\.0\s?$`)
	reGTE0Pre         = regexp.MustCompile(`^\s?>=\s?0\.0\.0-0\s?$`)
	reComparatorLoose = regexp.MustCompile(`^` + srcGTLT + `\s?(` + srcLoosePlain + `)$|^$`)
)

// npmRangeCache memoizes parsed ranges (node-semver does the same): dependency graphs repeat the same few range
// strings many times.
var npmRangeCache struct {
	sync.Mutex
	m map[string]npmRangeEntry
}

type npmRangeEntry struct {
	r   NPMRange
	err error
}

const npmRangeCacheSize = 4096

// ParseNPMRange parses a node-semver range: "*", "", x-ranges and partial versions, "~", "~>", "^", hyphen ranges,
// comparator sets with < <= > >= =, and "||" unions. Like npm it uses node-semver's loose mode, which also accepts
// "v"/"=" prefixes, leading zeros and prereleases without a hyphen, and drops invalid comparators as long as one
// comparator set remains.
func ParseNPMRange(s string) (NPMRange, error) {
	npmRangeCache.Lock()
	e, ok := npmRangeCache.m[s]
	npmRangeCache.Unlock()
	if ok {
		return e.r, e.err
	}
	sets, err := parseNPMSets(s, false)
	var setsPre [][]npmComparator
	if err == nil {
		setsPre, err = parseNPMSets(s, true)
	}
	if err == nil {
		e.r = NPMRange{sets: sets, setsPre: setsPre}
	} else {
		e.err = err
	}
	npmRangeCache.Lock()
	if npmRangeCache.m == nil || len(npmRangeCache.m) >= npmRangeCacheSize {
		npmRangeCache.m = make(map[string]npmRangeEntry, 256)
	}
	npmRangeCache.m[s] = e
	npmRangeCache.Unlock()
	return e.r, e.err
}

// parseNPMSets is node-semver's Range constructor.
func parseNPMSets(s string, incPr bool) ([][]npmComparator, error) {
	raw := collapseJSSpace(jsTrim(s))
	var sets [][]npmComparator
	for _, part := range strings.Split(raw, "||") {
		set, err := parseNPMSet(strings.Trim(part, " "), incPr)
		if err != nil {
			return nil, err
		}
		if len(set) > 0 {
			sets = append(sets, set)
		}
	}
	if len(sets) == 0 {
		return nil, errNPMRange
	}
	if len(sets) > 1 {
		first := sets[0]
		kept := sets[:0:0]
		for _, set := range sets {
			if !set[0].isNullSet() {
				kept = append(kept, set)
			}
		}
		switch {
		case len(kept) == 0:
			kept = [][]npmComparator{first}
		case len(kept) > 1:
			for _, set := range kept {
				if len(set) == 1 && set[0].op == npmAny {
					kept = [][]npmComparator{set}
					break
				}
			}
		}
		sets = kept
	}
	return sets, nil
}

// parseNPMSet is node-semver's Range.parseRange for one comparator set (loose mode).
func parseNPMSet(r string, incPr bool) ([]npmComparator, error) {
	r = reSemverBuild.ReplaceAllString(r, "")
	if m := reHyphenLoose.FindStringSubmatch(r); m != nil {
		r = hyphenReplace(m, incPr)
	}
	r = reComparatorTrim.ReplaceAllString(r, "$1$2$3")
	r = reTildeTrim.ReplaceAllString(r, "$1~")
	r = reCaretTrim.ReplaceAllString(r, "$1^")

	toks := strings.Split(r, " ")
	for i, t := range toks {
		toks[i] = parseComparatorText(t, incPr)
	}
	gte0 := reGTE0
	if incPr {
		gte0 = reGTE0Pre
	}
	var comps []npmComparator
	for _, c := range jsSplitSpace(strings.Join(toks, " ")) {
		c = strings.Trim(c, " ")
		if gte0.MatchString(c) {
			c = ""
		}
		m := reComparatorLoose.FindStringSubmatch(c)
		if m == nil {
			continue // loose mode drops what is not a comparator
		}
		comp := npmComparator{op: npmAny}
		if m[2] != "" {
			if len(m[2]) > semverMaxLength {
				return nil, errNPMRange
			}
			v, err := parseSemver(strings.Trim(m[2], " "), true)
			if err != nil {
				return nil, errNPMRange
			}
			comp.ver = v
			switch m[1] {
			case "", "=":
				comp.op = npmEQ
			case "<":
				comp.op = npmLT
			case "<=":
				comp.op = npmLE
			case ">":
				comp.op = npmGT
			case ">=":
				comp.op = npmGE
			}
		}
		comps = append(comps, comp)
	}
	var out []npmComparator
	for _, c := range comps {
		if c.isNullSet() {
			return []npmComparator{c}, nil
		}
		dup := false
		for _, o := range out {
			if o.op == c.op && o.ver.Compare(c.ver) == 0 {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	if len(out) > 1 {
		kept := out[:0]
		for _, c := range out {
			if c.op != npmAny {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	return out, nil
}

// parseComparatorText desugars carets, tildes, x-ranges and stars of one space-separated token.
func parseComparatorText(comp string, incPr bool) string {
	comp = mapTokens(strings.Trim(comp, " "), func(c string) string { return replaceCaret(c, incPr) })
	comp = mapTokens(strings.Trim(comp, " "), func(c string) string { return replaceTilde(c, incPr) })
	comp = mapTokens(comp, func(c string) string { return replaceXRange(strings.Trim(c, " "), incPr) })
	comp = strings.Trim(comp, " ")
	if loc := reStar.FindStringIndex(comp); loc != nil {
		comp = comp[:loc[0]] + comp[loc[1]:]
	}
	return comp
}

func mapTokens(s string, f func(string) string) string {
	toks := jsSplitSpace(s)
	for i, t := range toks {
		toks[i] = f(t)
	}
	return strings.Join(toks, " ")
}

func replaceCaret(c string, incPr bool) string {
	m := reCaretLoose.FindStringSubmatch(c)
	if m == nil {
		return c
	}
	M, mi, p, pr := m[1], m[2], m[3], m[4]
	z := ""
	if incPr {
		z = "-0"
	}
	switch {
	case isXID(M):
		return ""
	case isXID(mi):
		return ">=" + M + ".0.0" + z + " <" + incNum(M) + ".0.0-0"
	case isXID(p):
		if M == "0" {
			return ">=" + M + "." + mi + ".0" + z + " <" + M + "." + incNum(mi) + ".0-0"
		}
		return ">=" + M + "." + mi + ".0" + z + " <" + incNum(M) + ".0.0-0"
	case pr != "":
		lo := ">=" + M + "." + mi + "." + p + "-" + pr
		if M == "0" {
			if mi == "0" {
				return lo + " <" + M + "." + mi + "." + incNum(p) + "-0"
			}
			return lo + " <" + M + "." + incNum(mi) + ".0-0"
		}
		return lo + " <" + incNum(M) + ".0.0-0"
	default:
		lo := ">=" + M + "." + mi + "." + p
		if M == "0" {
			if mi == "0" {
				return lo + " <" + M + "." + mi + "." + incNum(p) + "-0"
			}
			return lo + " <" + M + "." + incNum(mi) + ".0-0"
		}
		return lo + " <" + incNum(M) + ".0.0-0"
	}
}

func replaceTilde(c string, incPr bool) string {
	m := reTildeLoose.FindStringSubmatch(c)
	if m == nil {
		return c
	}
	M, mi, p, pr := m[1], m[2], m[3], m[4]
	z := ""
	if incPr {
		z = "-0"
	}
	switch {
	case isXID(M):
		return ""
	case isXID(mi):
		return ">=" + M + ".0.0" + z + " <" + incNum(M) + ".0.0-0"
	case isXID(p):
		return ">=" + M + "." + mi + ".0" + z + " <" + M + "." + incNum(mi) + ".0-0"
	case pr != "":
		return ">=" + M + "." + mi + "." + p + "-" + pr + " <" + M + "." + incNum(mi) + ".0-0"
	default:
		return ">=" + M + "." + mi + "." + p + " <" + M + "." + incNum(mi) + ".0-0"
	}
}

func replaceXRange(c string, incPr bool) string {
	m := reXRangeLoose.FindStringSubmatch(c)
	if m == nil {
		return c
	}
	gtlt, M, mi, p := m[1], m[2], m[3], m[4]
	if (isXID(M) && !isXID(mi)) || (isXID(mi) && p != "" && !isXID(p)) {
		return c // invalid x-range order such as "x.1" or "1.x.2"
	}
	xM := isXID(M)
	xm := xM || isXID(mi)
	xp := xm || isXID(p)
	if gtlt == "=" && xp {
		gtlt = ""
	}
	pr := ""
	if incPr {
		pr = "-0"
	}
	switch {
	case xM:
		if gtlt == ">" || gtlt == "<" {
			return "<0.0.0-0" // nothing is allowed
		}
		return "*"
	case gtlt != "" && xp:
		if xm {
			mi = "0"
		}
		p = "0"
		switch gtlt {
		case ">": // >1 => >=2.0.0, >1.2 => >=1.3.0
			gtlt = ">="
			if xm {
				M = incNum(M)
			} else {
				mi = incNum(mi)
			}
		case "<=": // <=1.2 => <1.3.0-0
			gtlt = "<"
			if xm {
				M = incNum(M)
			} else {
				mi = incNum(mi)
			}
		}
		if gtlt == "<" {
			pr = "-0"
		}
		return gtlt + M + "." + mi + "." + p + pr
	case xm:
		return ">=" + M + ".0.0" + pr + " <" + incNum(M) + ".0.0-0"
	case xp:
		return ">=" + M + "." + mi + ".0" + pr + " <" + M + "." + incNum(mi) + ".0-0"
	}
	return c
}

// hyphenReplace rewrites "A - B" (m: submatches of reHyphenLoose) to comparators.
func hyphenReplace(m []string, incPr bool) string {
	from, fM, fm, fp, fpr := m[1], m[2], m[3], m[4], m[5]
	to, tM, tm, tp, tpr := m[7], m[8], m[9], m[10], m[11]
	z := ""
	if incPr {
		z = "-0"
	}
	switch {
	case isXID(fM):
		from = ""
	case isXID(fm):
		from = ">=" + fM + ".0.0" + z
	case isXID(fp):
		from = ">=" + fM + "." + fm + ".0" + z
	case fpr != "":
		from = ">=" + from
	default:
		from = ">=" + from + z
	}
	switch {
	case isXID(tM):
		to = ""
	case isXID(tm):
		to = "<" + incNum(tM) + ".0.0-0"
	case isXID(tp):
		to = "<" + tM + "." + incNum(tm) + ".0-0"
	case tpr != "":
		to = "<=" + tM + "." + tm + "." + tp + "-" + tpr
	case incPr:
		to = "<" + tM + "." + tm + "." + incNum(tp) + "-0"
	default:
		to = "<=" + to
	}
	return strings.Trim(from+" "+to, " ")
}

func isXID(id string) bool { return id == "" || id == "x" || id == "X" || id == "*" }

// incNum is JavaScript's `+n + 1` for a decimal string. Results beyond MAX_SAFE_INTEGER make the comparator invalid.
func incNum(n string) string {
	v, err := strconv.ParseUint(n, 10, 64)
	if err != nil || v >= maxSafeInt {
		return "99999999999999999999"
	}
	return strconv.FormatUint(v+1, 10)
}

// collapseJSSpace replaces every run of JavaScript whitespace with one space.
func collapseJSSpace(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if isJSSpace(r) {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

// jsSplitSpace is JavaScript's s.split(/\s+/) for strings whose only whitespace is " ".
func jsSplitSpace(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		if s[i] != ' ' {
			i++
			continue
		}
		out = append(out, s[start:i])
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start = i
	}
	return append(out, s[start:])
}

func (c npmComparator) isNullSet() bool {
	return c.op == npmLT && c.ver.major == 0 && c.ver.minor == 0 && c.ver.patch == 0 &&
		len(c.ver.pre) == 1 && c.ver.pre[0].num && c.ver.pre[0].s == "0"
}

func (c npmComparator) test(v NPMVersion) bool {
	if c.op == npmAny {
		return true
	}
	d := v.Compare(c.ver)
	switch c.op {
	case npmEQ:
		return d == 0
	case npmLT:
		return d < 0
	case npmLE:
		return d <= 0
	case npmGT:
		return d > 0
	case npmGE:
		return d >= 0
	}
	return false
}

func (c npmComparator) String() string {
	op := ""
	switch c.op {
	case npmAny:
		return ""
	case npmLT:
		op = "<"
	case npmLE:
		op = "<="
	case npmGT:
		op = ">"
	case npmGE:
		op = ">="
	}
	return op + c.ver.String()
}

// Contains reports whether v satisfies the range (semver.satisfies). Unless includePrerelease is set, a prerelease
// version only satisfies a comparator set that has a comparator with a prerelease on the same major.minor.patch.
func (r NPMRange) Contains(v NPMVersion, includePrerelease bool) bool {
	sets := r.sets
	if includePrerelease {
		sets = r.setsPre
	}
	for _, set := range sets {
		if testNPMSet(set, v, includePrerelease) {
			return true
		}
	}
	return false
}

func testNPMSet(set []npmComparator, v NPMVersion, includePrerelease bool) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if len(v.pre) == 0 || includePrerelease {
		return true
	}
	for _, c := range set {
		if c.op != npmAny && len(c.ver.pre) > 0 && c.ver.sameTuple(v) {
			return true
		}
	}
	return false
}

// String returns the desugared range as semver.validRange prints it, e.g. ">=1.2.3 <2.0.0-0" for "^1.2.3".
func (r NPMRange) String() string {
	var b strings.Builder
	for i, set := range r.sets {
		if i > 0 {
			b.WriteString("||")
		}
		for k, c := range set {
			if k > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(c.String())
		}
	}
	if b.Len() == 0 {
		return "*"
	}
	return b.String()
}

// MaxSatisfying returns the index of the highest version that satisfies the range (prereleases per Contains with
// includePrerelease=false; the first of equal versions wins), or -1.
func (r NPMRange) MaxSatisfying(versions []NPMVersion) int {
	best := -1
	for i, v := range versions {
		if r.Contains(v, false) && (best < 0 || versions[best].Compare(v) < 0) {
			best = i
		}
	}
	return best
}

// MaxSatisfyingNPM returns the highest of versions that satisfies rng (semver.maxSatisfying). Versions that do not
// parse are ignored; ok is false when rng is invalid or nothing satisfies it.
func MaxSatisfyingNPM(versions []string, rng string) (string, bool) {
	r, err := ParseNPMRange(rng)
	if err != nil {
		return "", false
	}
	best, bestV := -1, NPMVersion{}
	for i, s := range versions {
		v, err := ParseNPM(s)
		if err != nil || !r.Contains(v, false) {
			continue
		}
		if best < 0 || bestV.Compare(v) < 0 {
			best, bestV = i, v
		}
	}
	if best < 0 {
		return "", false
	}
	return versions[best], true
}
