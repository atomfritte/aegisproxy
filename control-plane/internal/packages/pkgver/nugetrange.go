package pkgver

import (
	"errors"
	"strconv"
	"strings"
)

// NuGetRange is a NuGet version range: interval notation, a bare minimum version or a floating version. The zero
// value is the range of all versions.
type NuGetRange struct {
	min, max       NuGetVersion
	hasMin, hasMax bool
	minInc, maxInc bool
	float          nugetFloat // behavior floatNone unless floating
}

type floatBehavior uint8

// The FloatRange behaviors of NuGet.Versioning.
const (
	floatNone               floatBehavior = iota
	floatPrerelease                       // 1.0.0-beta*
	floatRevision                         // 1.0.0.*
	floatPatch                            // 1.0.*
	floatMinor                            // 1.*
	floatMajor                            // *
	floatAbsoluteLatest                   // *-*
	floatPrereleaseRevision               // 1.0.0.*-*
	floatPrereleasePatch                  // 1.0.*-*
	floatPrereleaseMinor                  // 1.*-*
	floatPrereleaseMajor                  // *-beta*
)

type nugetFloat struct {
	behavior floatBehavior
	min      NuGetVersion
	prefix   string // release label prefix of pre-release floats
}

var errNuGetRange = errors.New("invalid NuGet version range")

// ParseNuGetRange parses a range like VersionRange.TryParse with floating versions allowed: "[1.0,2.0)", "(1.0,)",
// "(,2.0]", "[1.0]", "1.0" (at least 1.0), and floating minimums such as "1.*", "1.2.*", "*", "1.0.0-*",
// "1.0.0-beta*" or "1.*-*". An empty string is the range of all versions (an omitted nuspec version).
func ParseNuGetRange(s string) (NuGetRange, error) {
	t := trimSpace(s)
	var r NuGetRange
	switch {
	case t == "":
		return r, nil
	case t == "*":
		r.hasMin, r.minInc, r.float = true, true, nugetFloat{behavior: floatMajor}
		return r, nil
	}
	minS, maxS := t, ""
	r.minInc = true
	if t[0] == '(' || t[0] == '[' {
		r.minInc = t[0] == '['
		switch t[len(t)-1] {
		case ']':
			r.maxInc = true
		case ')':
		default:
			return NuGetRange{}, errNuGetRange
		}
		parts := strings.Split(t[1:len(t)-1], ",")
		switch {
		case len(parts) > 2, len(parts) == 1 && !(r.minInc && r.maxInc):
			return NuGetRange{}, errNuGetRange
		case len(parts) == 2 && parts[0] == "" && parts[1] == "", len(parts) == 1 && parts[0] == "":
			return NuGetRange{}, errNuGetRange
		}
		minS, maxS = parts[0], parts[len(parts)-1]
	}
	if trimSpace(minS) != "" {
		if strings.Contains(minS, "*") {
			f, ok := parseNuGetFloat(minS)
			if !ok {
				return NuGetRange{}, errNuGetRange
			}
			r.min, r.float = f.min, f
		} else {
			v, err := ParseNuGet(minS)
			if err != nil {
				return NuGetRange{}, errNuGetRange
			}
			r.min = v
		}
		r.hasMin = true
	}
	if trimSpace(maxS) != "" {
		v, err := ParseNuGet(maxS)
		if err != nil {
			return NuGetRange{}, errNuGetRange
		}
		r.max, r.hasMax = v, true
	}
	if r.hasMin && r.hasMax {
		if c := r.min.Compare(r.max); c > 0 || (c == 0 && r.minInc != r.maxInc) {
			return NuGetRange{}, errNuGetRange
		}
	}
	r.minInc = r.minInc && r.hasMin
	r.maxInc = r.maxInc && r.hasMax
	return r, nil
}

// parseNuGetFloat is FloatRange.TryParse.
func parseNuGetFloat(s string) (nugetFloat, bool) {
	if trimSpace(s) == "" {
		return nugetFloat{}, false
	}
	first, last := strings.IndexByte(s, '*'), strings.LastIndexByte(s, '*')
	var f nugetFloat
	var actual string
	hasPrefix := false
	switch {
	case s == "*":
		return nugetFloat{behavior: floatMajor}, true
	case s == "*-*":
		return nugetFloat{behavior: floatAbsoluteLatest, min: NuGetVersion{labels: []string{"0"}}}, true
	case first != last && !strings.Contains(s, "+"):
		// Two stars only float a stable part and a label prefix: 1.*-beta*.
		dash := strings.IndexByte(s, '-')
		if dash < 0 || last != len(s)-1 || first != dash-1 {
			return nugetFloat{}, false
		}
		stable := s[:dash-1] + "0"
		f.behavior = [...]floatBehavior{floatPrereleaseMajor, floatPrereleaseMinor, floatPrereleasePatch,
			floatPrereleaseRevision, floatNone}[min(strings.Count(stable, "."), 4)]
		f.prefix, hasPrefix = s[dash+1:len(s)-1], true
		label := f.prefix
		if label == "" || strings.HasSuffix(label, ".") {
			label += "0"
		}
		actual = stable + "-" + label
	case last == len(s)-1 && !strings.Contains(s, "+"):
		actual = s[:len(s)-1]
		if !strings.Contains(s, "-") {
			actual += "0"
			f.behavior = [...]floatBehavior{floatNone, floatMinor, floatPatch, floatRevision, floatNone}[min(strings.Count(actual, "."), 4)]
			break
		}
		f.behavior = floatPrerelease
		if dash := strings.IndexByte(s, '-'); dash == strings.LastIndexByte(s, '-') {
			f.prefix, hasPrefix = actual[dash+1:], true
			if f.prefix == "" || strings.HasSuffix(actual, ".") {
				actual += "0"
			}
		}
	default:
		actual = s
	}
	v, err := ParseNuGet(actual)
	if err != nil {
		return nugetFloat{}, false
	}
	f.min = v
	if !hasPrefix && v.IsPrerelease() {
		f.prefix = v.Release()
	}
	return f, true
}

// satisfies is FloatRange.Satisfies.
func (f nugetFloat) satisfies(v NuGetVersion) bool {
	m := f.min
	labelOK := !v.IsPrerelease() || hasPrefixFold(v.Release(), f.prefix)
	switch f.behavior {
	case floatAbsoluteLatest:
		return true
	case floatMajor:
		return !v.IsPrerelease()
	case floatPrereleaseRevision:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && m.parts[2] == v.parts[2] && labelOK
	case floatPrereleasePatch:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && labelOK
	case floatPrereleaseMinor:
		return m.parts[0] == v.parts[0] && labelOK
	case floatPrereleaseMajor:
		return labelOK
	case floatPrerelease:
		return m.parts == v.parts && labelOK
	case floatRevision:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && m.parts[2] == v.parts[2] && !v.IsPrerelease()
	case floatPatch:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && !v.IsPrerelease()
	case floatMinor:
		return m.parts[0] == v.parts[0] && !v.IsPrerelease()
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// String is FloatRange.ToString.
func (f nugetFloat) String() string {
	m := f.min
	num := func(n int) string {
		var b []byte
		for i := range n {
			b = strconv.AppendInt(b, int64(m.parts[i]), 10)
			b = append(b, '.')
		}
		return string(b)
	}
	switch f.behavior {
	case floatPrerelease:
		return string(m.appendNumbers(nil)) + "-" + f.prefix + "*"
	case floatRevision:
		return num(3) + "*"
	case floatPatch:
		return num(2) + "*"
	case floatMinor:
		return num(1) + "*"
	case floatMajor:
		return "*"
	case floatAbsoluteLatest:
		return "*-*"
	case floatPrereleaseRevision:
		return num(3) + "*-" + f.prefix + "*"
	case floatPrereleasePatch:
		return num(2) + "*-" + f.prefix + "*"
	case floatPrereleaseMinor:
		return num(1) + "*-" + f.prefix + "*"
	case floatPrereleaseMajor:
		return "*-" + f.prefix + "*"
	}
	return m.Normalize()
}

// IsFloating reports a floating range such as "1.*" or "1.0.0-*".
func (r NuGetRange) IsFloating() bool { return r.float.behavior != floatNone }

// String returns NuGet's normalized range form, e.g. "[1.0.0, )", "(, 2.0.0]", "[1.*, 2.0.0)" or "(, )" for all
// versions.
func (r NuGetRange) String() string {
	var b strings.Builder
	switch {
	case r.hasMin && r.minInc:
		b.WriteByte('[')
	default:
		b.WriteByte('(')
	}
	switch {
	case r.IsFloating():
		b.WriteString(r.float.String())
	case r.hasMin:
		b.WriteString(r.min.Normalize())
	}
	b.WriteString(", ")
	if r.hasMax {
		b.WriteString(r.max.Normalize())
	}
	if r.maxInc {
		b.WriteByte(']')
	} else {
		b.WriteByte(')')
	}
	return b.String()
}

// allowsPrerelease reports whether NuGet considers pre-release versions for the range: when a bound is a
// pre-release or the range floats pre-release labels.
func (r NuGetRange) allowsPrerelease() bool {
	switch r.float.behavior {
	case floatPrerelease, floatPrereleaseMajor, floatPrereleaseMinor, floatPrereleasePatch, floatPrereleaseRevision,
		floatAbsoluteLatest:
		return true
	}
	return (r.hasMin && r.min.IsPrerelease()) || (r.hasMax && r.max.IsPrerelease())
}

func (r NuGetRange) inBounds(v NuGetVersion) bool {
	if r.hasMin {
		if c := r.min.Compare(v); c > 0 || (c == 0 && !r.minInc) {
			return false
		}
	}
	if r.hasMax {
		if c := v.Compare(r.max); c > 0 || (c == 0 && !r.maxInc) {
			return false
		}
	}
	return true
}

// Contains reports whether v lies within the bounds and, for a floating range, within the float ("1.*" contains
// 1.x versions only). Pre-releases only match when includePrerelease is set, a bound is a pre-release or the
// range floats pre-release labels, as in NuGet's resolution.
func (r NuGetRange) Contains(v NuGetVersion, includePrerelease bool) bool {
	if !includePrerelease && v.IsPrerelease() && !r.allowsPrerelease() {
		return false
	}
	return r.inBounds(v) && (!r.IsFloating() || r.float.satisfies(v))
}

// BestMatch returns the version NuGet's restore would pick from versions (VersionRange.FindBestMatch): the lowest
// applicable version for a non-floating range; for a floating range the highest version within the float, else
// the lowest above it, else the highest below it. Unparsable versions are ignored; the original string is
// returned.
func BestMatch(versions []string, rng NuGetRange) (string, bool) {
	parsed := make([]NuGetVersion, 0, len(versions))
	idx := make([]int, 0, len(versions))
	for i, s := range versions {
		if v, err := ParseNuGet(s); err == nil {
			parsed = append(parsed, v)
			idx = append(idx, i)
		}
	}
	if k := rng.BestMatch(parsed); k >= 0 {
		return versions[idx[k]], true
	}
	return "", false
}

// BestMatch is the typed form of the package-level BestMatch; it returns the index of the chosen version or -1.
func (r NuGetRange) BestMatch(versions []NuGetVersion) int {
	best := -1
	for i, v := range versions {
		if r.applicable(v) && (best < 0 || r.isBetter(versions[best], v)) {
			best = i
		}
	}
	return best
}

// applicable is the candidate filter of VersionRange.IsBetter.
func (r NuGetRange) applicable(v NuGetVersion) bool {
	return (!v.IsPrerelease() || r.allowsPrerelease()) && r.inBounds(v)
}

// isBetter is VersionRange.IsBetter for two applicable versions.
func (r NuGetRange) isBetter(current, considering NuGetVersion) bool {
	if r.IsFloating() {
		curIn, conIn := r.float.satisfies(current), r.float.satisfies(considering)
		switch {
		case curIn != conIn:
			return conIn
		case curIn:
			return current.Compare(considering) < 0
		}
		curLow, conLow := current.Compare(r.float.min) < 0, considering.Compare(r.float.min) < 0
		switch {
		case curLow != conLow:
			return curLow // favor the version above the float
		case curLow:
			return current.Compare(considering) < 0
		}
	}
	return current.Compare(considering) > 0
}
