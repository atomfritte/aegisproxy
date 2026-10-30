package pkgver

import (
	"errors"
	"strings"
	"unicode/utf8"
)

var errUnknownEcosystem = errors.New("unknown package ecosystem")

// Compare orders two versions with the ecosystem's rules ("npm", "pypi", "nuget", "psgallery"). Unparsable
// versions sort before parsable ones and among themselves by string; unknown ecosystems compare strings.
func Compare(ecosystem, a, b string) int {
	switch ecosystem {
	case ecoNPM:
		return compareParsed(a, b, ParseNPM, NPMVersion.Compare)
	case ecoPyPI:
		return compareParsed(a, b, ParsePEP440, PEP440Version.Compare)
	case ecoNuGet, ecoPSGallery:
		return compareParsed(a, b, ParseNuGet, NuGetVersion.Compare)
	}
	return strings.Compare(a, b)
}

func compareParsed[V any](a, b string, parse func(string) (V, error), cmp func(V, V) int) int {
	x, errA := parse(a)
	y, errB := parse(b)
	switch {
	case errA != nil && errB != nil:
		return strings.Compare(a, b)
	case errA != nil:
		return -1
	case errB != nil:
		return 1
	}
	return cmp(x, y)
}

// IsPrerelease reports whether v is a pre-release in the ecosystem (PEP 440: pre or development release); false for
// unparsable versions.
func IsPrerelease(ecosystem, v string) bool {
	switch ecosystem {
	case ecoNPM:
		x, err := ParseNPM(v)
		return err == nil && x.Prerelease()
	case ecoPyPI:
		x, err := ParsePEP440(v)
		return err == nil && x.IsPrerelease()
	case ecoNuGet, ecoPSGallery:
		x, err := ParseNuGet(v)
		return err == nil && x.IsPrerelease()
	}
	return false
}

// NormalizeVersion returns the form versions are stored and compared in: npm canonical (as npm publish writes it,
// without build metadata), PyPI PEP 440 normalized, NuGet / PowerShell Gallery NuGet normalized and lowercase.
func NormalizeVersion(ecosystem, v string) (string, error) {
	switch ecosystem {
	case ecoNPM:
		x, err := ParseNPM(v)
		if err != nil {
			return "", err
		}
		return x.String(), nil
	case ecoPyPI:
		x, err := ParsePEP440(v)
		if err != nil {
			return "", err
		}
		return x.String(), nil
	case ecoNuGet, ecoPSGallery:
		x, err := ParseNuGet(v)
		if err != nil {
			return "", err
		}
		return x.Lower(), nil
	}
	return "", errUnknownEcosystem
}

// NormalizeName returns the canonical package name: npm unchanged, PyPI PEP 503, NuGet / PowerShell Gallery
// lowercase.
func NormalizeName(ecosystem, name string) string {
	switch ecosystem {
	case ecoPyPI:
		return NormalizePyPIName(name)
	case ecoNuGet, ecoPSGallery:
		return strings.ToLower(name)
	}
	return name
}

// Update types returned by UpdateType.
const (
	UpdateMajor      = "major"
	UpdateMinor      = "minor"
	UpdatePatch      = "patch"
	UpdatePrerelease = "prerelease" // same release, different pre-release (npm, NuGet) or pre/dev release (PyPI)
	UpdateDowngrade  = "downgrade"
	UpdateSame       = "same"
)

// UpdateType classifies the step from one version to another: the first differing numeric part (NuGet's revision
// counts as patch; for PEP 440 the epoch and first release segment are major, the second minor, any later one
// patch), "prerelease" when only pre-release parts differ, "downgrade" when to sorts before from, "same" when they
// are equal, and "" when either version does not parse. A PEP 440 change of only the post release or local
// version counts as patch.
func UpdateType(from, to, ecosystem string) string {
	var c int
	var x, y []int64    // numeric parts, same length
	var levels []string // update type of a change in part i (later parts: patch)
	pre := true         // whether equal numeric parts mean a pre-release change
	switch ecosystem {
	case ecoNPM:
		a, errA := ParseNPM(from)
		b, errB := ParseNPM(to)
		if errA != nil || errB != nil {
			return ""
		}
		c = a.Compare(b)
		x, y = []int64{a.major, a.minor, a.patch}, []int64{b.major, b.minor, b.patch}
		levels = []string{UpdateMajor, UpdateMinor, UpdatePatch}
	case ecoNuGet, ecoPSGallery:
		a, errA := ParseNuGet(from)
		b, errB := ParseNuGet(to)
		if errA != nil || errB != nil {
			return ""
		}
		c = a.Compare(b)
		for i := range a.parts {
			x, y = append(x, int64(a.parts[i])), append(y, int64(b.parts[i]))
		}
		levels = []string{UpdateMajor, UpdateMinor, UpdatePatch}
	case ecoPyPI:
		a, errA := ParsePEP440(from)
		b, errB := ParsePEP440(to)
		if errA != nil || errB != nil {
			return ""
		}
		c, pre = a.Compare(b), a.IsPrerelease() || b.IsPrerelease()
		x, y = []int64{int64(a.epoch)}, []int64{int64(b.epoch)}
		for i := range max(len(a.release), len(b.release)) {
			x, y = append(x, int64(a.releaseAt(i))), append(y, int64(b.releaseAt(i)))
		}
		levels = []string{UpdateMajor, UpdateMajor, UpdateMinor} // epoch, first and second release segment
	default:
		return ""
	}
	switch {
	case c == 0:
		return UpdateSame
	case c > 0:
		return UpdateDowngrade
	}
	for i := range x {
		if x[i] != y[i] {
			if i < len(levels) {
				return levels[i]
			}
			return UpdatePatch
		}
	}
	if pre {
		return UpdatePrerelease
	}
	return UpdatePatch
}

// RangeContains reports whether version satisfies rangeExpr with the ecosystem's default pre-release handling:
// npm ranges exclude pre-releases outside their own pre-release tuples, PEP 440 specifiers include them only when
// the set names one, NuGet ranges only for pre-release bounds or floats. Unparsable input never matches.
func RangeContains(ecosystem, rangeExpr, version string) bool {
	switch ecosystem {
	case ecoNPM:
		r, err := ParseNPMRange(rangeExpr)
		if err != nil {
			return false
		}
		v, err := ParseNPM(version)
		return err == nil && r.Contains(v, false)
	case ecoPyPI:
		set, err := ParseSpecifierSet(rangeExpr)
		if err != nil {
			return false
		}
		v, err := ParsePEP440(version)
		return err == nil && set.Contains(v, set.AllowsPrereleases())
	case ecoNuGet, ecoPSGallery:
		r, err := ParseNuGetRange(rangeExpr)
		if err != nil {
			return false
		}
		v, err := ParseNuGet(version)
		return err == nil && r.Contains(v, false)
	}
	return false
}

// MaxSatisfying returns the normalized version (see NormalizeVersion) a client would resolve rangeExpr to from
// versions: npm the highest satisfying version, PyPI the highest version pip's default policy selects, NuGet /
// PowerShell Gallery the version NuGet's resolution picks (the lowest applicable one unless the range floats).
// Unparsable versions are ignored; ok is false when nothing matches or the range does not parse.
func MaxSatisfying(ecosystem string, versions []string, rangeExpr string) (string, bool) {
	switch ecosystem {
	case ecoNPM:
		r, err := ParseNPMRange(rangeExpr)
		if err != nil {
			return "", false
		}
		parsed := parseAll(versions, ParseNPM)
		if k := r.MaxSatisfying(parsed); k >= 0 {
			return parsed[k].String(), true
		}
	case ecoPyPI:
		set, err := ParseSpecifierSet(rangeExpr)
		if err != nil {
			return "", false
		}
		parsed := parseAll(versions, ParsePEP440)
		best := -1
		for _, k := range set.Select(parsed) {
			if best < 0 || parsed[k].Compare(parsed[best]) > 0 {
				best = k
			}
		}
		if best >= 0 {
			return parsed[best].String(), true
		}
	case ecoNuGet, ecoPSGallery:
		r, err := ParseNuGetRange(rangeExpr)
		if err != nil {
			return "", false
		}
		parsed := parseAll(versions, ParseNuGet)
		if k := r.BestMatch(parsed); k >= 0 {
			return parsed[k].Lower(), true
		}
	}
	return "", false
}

func parseAll[V any](versions []string, parse func(string) (V, error)) []V {
	out := make([]V, 0, len(versions))
	for _, s := range versions {
		if v, err := parse(s); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// MatchPackagePattern matches a package name against a rule pattern in which "*" matches any run of characters
// (including "/" and ".") and "?" exactly one. npm compares case-sensitively; PyPI compares PEP 503 normalized
// names (the pattern's literal parts are normalized, wildcards kept); NuGet and the PowerShell Gallery compare
// case-insensitively.
func MatchPackagePattern(pattern, name, ecosystem string) bool {
	switch ecosystem {
	case ecoPyPI:
		pattern, name = normalizePyPIPattern(pattern), NormalizePyPIName(name)
	case ecoNuGet, ecoPSGallery:
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	return globMatch(pattern, name)
}

func normalizePyPIPattern(p string) string {
	var b strings.Builder
	for {
		i := strings.IndexAny(p, "*?")
		if i < 0 {
			b.WriteString(NormalizePyPIName(p))
			return b.String()
		}
		b.WriteString(NormalizePyPIName(p[:i]))
		b.WriteByte(p[i])
		p = p[i+1:]
	}
}

// globMatch matches s against p with "*" and "?" (one rune), backtracking only to the last star, so it runs in
// O(len(p)·len(s)) at worst.
func globMatch(p, s string) bool {
	px, sx := 0, 0
	starP, starS := -1, 0
	for sx < len(s) {
		if px < len(p) {
			switch c := p[px]; {
			case c == '*':
				starP, starS = px, sx
				px++
				continue
			case c == '?':
				_, n := utf8.DecodeRuneInString(s[sx:])
				px, sx = px+1, sx+n
				continue
			case c == s[sx]:
				px, sx = px+1, sx+1
				continue
			}
		}
		if starP < 0 {
			return false
		}
		_, n := utf8.DecodeRuneInString(s[starS:])
		starS += n
		px, sx = starP+1, starS
	}
	for px < len(p) && p[px] == '*' {
		px++
	}
	return px == len(p)
}
