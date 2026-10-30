package pkgver

import (
	"errors"
	"slices"
	"strings"
	"unicode"
)

// SpecifierSet is a comma-separated set of PEP 440 version specifiers ("" matches every version).
type SpecifierSet struct {
	specs []pySpecifier
}

type pySpecifier struct {
	op       string // ~= == != <= >= < > ===
	text     string // version as written (whitespace stripped)
	ver      PEP440Version
	wildcard bool // ==V.* or !=V.*; ver is V
	hasLocal bool
	lo, hi   PEP440Version // precomputed bounds (wildcards, ~=, < and >)
}

var errSpecifier = errors.New("invalid PEP 440 specifier")

// ParseSpecifierSet parses specifiers such as ">=1.0,!=1.3.*,<2", "~=1.4.5", "==1.0+local" or "===foobar".
// Empty items between commas are ignored.
func ParseSpecifierSet(s string) (SpecifierSet, error) {
	var set SpecifierSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		spec, err := parsePySpecifier(part)
		if err != nil {
			return SpecifierSet{}, err
		}
		set.specs = append(set.specs, spec)
	}
	return set, nil
}

// parsePySpecifier parses one trimmed specifier with packaging's per-operator rules: wildcards and local versions
// only for == and !=, at least two release segments for ~=, any non-blank text for ===.
func parsePySpecifier(s string) (pySpecifier, error) {
	var sp pySpecifier
	switch {
	case strings.HasPrefix(s, "==="):
		sp.op = "==="
	case len(s) >= 2 && oneOf(s[:2], "~=", "==", "!=", "<=", ">="):
		sp.op = s[:2]
	case len(s) >= 1 && (s[0] == '<' || s[0] == '>'):
		sp.op = s[:1]
	default:
		return sp, errSpecifier
	}
	sp.text = strings.TrimSpace(s[len(sp.op):])
	if sp.op == "===" {
		if strings.ContainsAny(sp.text, ";)") || strings.IndexFunc(sp.text, unicode.IsSpace) >= 0 {
			return sp, errSpecifier
		}
		sp.ver, _ = ParsePEP440(sp.text)
		return sp, nil
	}
	text := sp.text
	if base, ok := strings.CutSuffix(text, ".*"); ok && (sp.op == "==" || sp.op == "!=") {
		sp.wildcard, text = true, base
	}
	v, rest, ok := scanPEP440(text, sp.op == "==" || sp.op == "!=")
	if !ok || rest != "" {
		return sp, errSpecifier
	}
	if sp.wildcard && (v.hasPre || v.hasPost || v.hasDev || len(v.local) > 0) {
		return sp, errSpecifier
	}
	if sp.op == "~=" && len(v.release) < 2 {
		return sp, errSpecifier
	}
	sp.ver, sp.hasLocal = v, len(v.local) > 0
	v.raw = ""
	switch {
	case sp.wildcard: // [V.dev0, next prefix .dev0)
		sp.lo = PEP440Version{epoch: v.epoch, release: v.release, hasDev: true}
		sp.hi = nextPrefixDev0(v.epoch, v.release)
	case sp.op == "~=":
		sp.hi = nextPrefixDev0(v.epoch, v.release[:len(v.release)-1])
	case sp.op == "<":
		// <V excludes the pre-releases of V unless V is itself a pre-release.
		sp.hi = v
		if !v.IsPrerelease() {
			sp.hi.hasDev, sp.hi.devN = true, 0
		}
	case sp.op == ">" && v.hasDev: // >V.devN: V.dev(N+1) and above
		sp.lo = v
		sp.lo.devN++
	case sp.op == ">" && v.hasPost: // >V.postN: V.post(N+1).dev0 and above
		sp.lo = v
		sp.lo.postN++
		sp.lo.hasDev, sp.lo.devN = true, 0
	}
	return sp, nil
}

// String returns the specifiers sorted and joined with commas, as packaging prints a SpecifierSet.
func (s SpecifierSet) String() string {
	parts := make([]string, 0, len(s.specs))
	for _, sp := range s.specs {
		parts = append(parts, sp.op+sp.text)
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), ",")
}

// Len returns the number of specifiers.
func (s SpecifierSet) Len() int { return len(s.specs) }

// AllowsPrereleases reports whether the set explicitly names a pre-release (e.g. ">=1.0b1"), which makes pip
// consider pre-releases for it. "!=" and "==V.*" specifiers never do.
func (s SpecifierSet) AllowsPrereleases() bool {
	for _, sp := range s.specs {
		if sp.op != "!=" && !sp.wildcard && sp.ver.IsPrerelease() {
			return true
		}
	}
	return false
}

// Contains reports whether v satisfies every specifier. Pre-releases (and development releases) only match when
// prereleases is set.
func (s SpecifierSet) Contains(v PEP440Version, prereleases bool) bool {
	if !prereleases && v.IsPrerelease() {
		return false
	}
	for _, sp := range s.specs {
		if !sp.match(v) {
			return false
		}
	}
	return true
}

// Filter returns the versions that match set with pip's default pre-release policy: pre-releases only when the set
// names a pre-release or no final release matches. Unparsable versions are skipped; the order is kept.
func Filter(versions []string, set SpecifierSet) []string {
	parsed := make([]PEP440Version, 0, len(versions))
	idx := make([]int, 0, len(versions))
	for i, s := range versions {
		if v, err := ParsePEP440(s); err == nil {
			parsed = append(parsed, v)
			idx = append(idx, i)
		}
	}
	var out []string
	for _, k := range set.Select(parsed) {
		out = append(out, versions[idx[k]])
	}
	return out
}

// Select is Filter for parsed versions; it returns the indexes of the selected versions.
func (s SpecifierSet) Select(versions []PEP440Version) []int {
	allow := s.AllowsPrereleases()
	var finals, pres []int
	for i, v := range versions {
		if !s.Contains(v, true) {
			continue
		}
		if allow || !v.IsPrerelease() {
			finals = append(finals, i)
		} else if len(finals) == 0 {
			pres = append(pres, i)
		}
	}
	if len(finals) == 0 {
		return pres
	}
	return finals
}

func (sp pySpecifier) match(v PEP440Version) bool {
	V := sp.ver
	switch sp.op {
	case "===":
		raw := v.raw
		if raw == "" {
			raw = v.String()
		}
		return strings.EqualFold(raw, sp.text)
	case "==", "!=":
		var eq bool
		switch {
		case sp.wildcard:
			eq = v.Compare(sp.lo) >= 0 && v.Compare(sp.hi) < 0
		case sp.hasLocal:
			eq = v.Compare(V) == 0
		default:
			eq = v.comparePublic(V) == 0
		}
		return eq == (sp.op == "==")
	case ">=":
		return v.Compare(V) >= 0
	case "<=":
		return v.Compare(V) <= 0 || v.comparePublic(V) == 0
	case "<":
		return v.Compare(sp.hi) < 0
	case ">":
		if V.hasDev || V.hasPost {
			return v.Compare(sp.lo) >= 0
		}
		// >V excludes V itself, its local versions and its post releases.
		if v.Compare(V) <= 0 {
			return false
		}
		return v.epoch != V.epoch || v.compareRelease(V) != 0 || v.hasPre != V.hasPre ||
			(v.hasPre && (v.preL != V.preL || v.preN != V.preN))
	case "~=":
		return v.Compare(V) >= 0 && v.Compare(sp.hi) < 0
	}
	return false
}

// nextPrefixDev0 is the first version after the release prefix: 1.2 -> 1.3.dev0.
func nextPrefixDev0(epoch int, release []int) PEP440Version {
	r := append([]int(nil), release...)
	r[len(r)-1]++
	return PEP440Version{epoch: epoch, release: r, hasDev: true}
}
