package pkgver

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NPMVersion is a SemVer 2.0 version as node-semver parses it. Build metadata is not part of the value: node-semver
// ignores it when comparing and drops it from the canonical form.
type NPMVersion struct {
	major, minor, patch int64
	pre                 []semverID
}

// semverID is a prerelease identifier; numeric identifiers compare numerically and sort before alphanumeric ones.
type semverID struct {
	s   string
	num bool
}

var errNPMVersion = errors.New("invalid npm version")

// semverMaxLength is node-semver's MAX_LENGTH for version strings.
const semverMaxLength = 256

// ParseNPM parses a strict SemVer 2.0 version (semver.valid). Like semver.clean it also accepts surrounding
// whitespace and leading "v" / "=" characters.
func ParseNPM(s string) (NPMVersion, error) {
	t := strings.TrimLeft(jsTrim(s), "=v")
	if len(t) > semverMaxLength {
		return NPMVersion{}, errNPMVersion
	}
	return parseSemver(jsTrim(t), false)
}

// parseSemver implements node-semver's FULL (strict) and LOOSE version grammars. The loose grammar (used for the
// comparators of npm ranges) also accepts leading zeros, any run of "v", "=" and whitespace before the version and a
// prerelease without the hyphen ("1.0.0beta1").
func parseSemver(s string, loose bool) (NPMVersion, error) {
	var v NPMVersion
	i := 0
	if loose {
		for i < len(s) {
			r, n := utf8.DecodeRuneInString(s[i:])
			if r != 'v' && r != '=' && !isJSSpace(r) {
				break
			}
			i += n
		}
	} else if i < len(s) && s[i] == 'v' {
		i++
	}
	var ok bool
	if v.major, i, ok = semverNum(s, i, loose); !ok || i >= len(s) || s[i] != '.' {
		return NPMVersion{}, errNPMVersion
	}
	if v.minor, i, ok = semverNum(s, i+1, loose); !ok || i >= len(s) || s[i] != '.' {
		return NPMVersion{}, errNPMVersion
	}
	if v.patch, i, ok = semverNum(s, i+1, loose); !ok {
		return NPMVersion{}, errNPMVersion
	}
	if i == len(s) {
		return v, nil
	}
	if s[i] == '-' {
		if pre, ok := semverTail(s[i+1:], loose); ok && len(pre) > 0 {
			v.pre = pre
			return v, nil
		}
		if !loose {
			return NPMVersion{}, errNPMVersion
		}
	}
	// Loose prerelease without the hyphen (a leading hyphen then belongs to the first identifier), or build only.
	if s[i] == '+' || loose {
		if pre, ok := semverTail(s[i:], loose); ok {
			v.pre = pre
			return v, nil
		}
	}
	return NPMVersion{}, errNPMVersion
}

// semverNum reads a version component at s[i:]: "0" or digits without a leading zero (strict) or any digits
// (loose), at most MAX_SAFE_INTEGER.
func semverNum(s string, i int, loose bool) (int64, int, bool) {
	j := i
	var n int64
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		if n <= maxSafeInt {
			n = n*10 + int64(s[j]-'0')
		}
		j++
	}
	if j == i || n > maxSafeInt || (!loose && s[i] == '0' && j-i > 1) {
		return 0, j, false
	}
	return n, j, true
}

// semverTail parses "[prerelease][+build]" up to the end of s (the prerelease without its leading hyphen).
func semverTail(s string, loose bool) ([]semverID, bool) {
	var pre []semverID
	i := 0
	if i < len(s) && s[i] != '+' {
		for {
			j := i
			for j < len(s) && isIDChar(s[j]) {
				j++
			}
			id := s[i:j]
			if id == "" {
				return nil, false
			}
			sid, ok := makeSemverID(id, loose)
			if !ok {
				return nil, false
			}
			pre = append(pre, sid)
			i = j
			if i < len(s) && s[i] == '.' {
				i++
				continue
			}
			break
		}
	}
	if i < len(s) && s[i] == '+' {
		i++
		for {
			j := i
			for j < len(s) && isIDChar(s[j]) {
				j++
			}
			if j == i {
				return nil, false
			}
			i = j
			if i < len(s) && s[i] == '.' {
				i++
				continue
			}
			break
		}
	}
	return pre, i == len(s)
}

// makeSemverID validates a prerelease identifier. Numeric identifiers below MAX_SAFE_INTEGER are stored in their
// numeric form, as node-semver converts them to numbers.
func makeSemverID(id string, loose bool) (semverID, bool) {
	for k := 0; k < len(id); k++ {
		if id[k] < '0' || id[k] > '9' {
			return semverID{s: id}, true
		}
	}
	if !loose && len(id) > 1 && id[0] == '0' {
		return semverID{}, false
	}
	if n, err := strconv.ParseInt(id, 10, 64); err == nil && n < maxSafeInt {
		return semverID{s: strconv.FormatInt(n, 10), num: true}, true
	}
	return semverID{s: id, num: true}, true
}

func isIDChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-'
}

// Major returns the major version.
func (v NPMVersion) Major() int64 { return v.major }

// Minor returns the minor version.
func (v NPMVersion) Minor() int64 { return v.minor }

// Patch returns the patch version.
func (v NPMVersion) Patch() int64 { return v.patch }

// Prerelease reports whether the version has prerelease identifiers.
func (v NPMVersion) Prerelease() bool { return len(v.pre) > 0 }

// String returns the canonical form (node-semver's version property): major.minor.patch[-prerelease].
func (v NPMVersion) String() string {
	b := make([]byte, 0, 16)
	b = strconv.AppendInt(b, v.major, 10)
	b = append(b, '.')
	b = strconv.AppendInt(b, v.minor, 10)
	b = append(b, '.')
	b = strconv.AppendInt(b, v.patch, 10)
	for i, id := range v.pre {
		if i == 0 {
			b = append(b, '-')
		} else {
			b = append(b, '.')
		}
		b = append(b, id.s...)
	}
	return string(b)
}

// Compare returns -1, 0 or 1 as v sorts before, equal to or after o (semver.compare).
func (v NPMVersion) Compare(o NPMVersion) int {
	if c := cmpInt64(v.major, o.major); c != 0 {
		return c
	}
	if c := cmpInt64(v.minor, o.minor); c != 0 {
		return c
	}
	if c := cmpInt64(v.patch, o.patch); c != 0 {
		return c
	}
	return comparePre(v.pre, o.pre)
}

func (v NPMVersion) sameTuple(o NPMVersion) bool {
	return v.major == o.major && v.minor == o.minor && v.patch == o.patch
}

func comparePre(a, b []semverID) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; ; i++ {
		switch {
		case i >= len(a) && i >= len(b):
			return 0
		case i >= len(b):
			return 1
		case i >= len(a):
			return -1
		}
		x, y := a[i], b[i]
		var c int
		switch {
		case x.num && y.num:
			c = compareDigits(x.s, y.s)
		case x.num:
			c = -1
		case y.num:
			c = 1
		default:
			c = strings.Compare(x.s, y.s)
		}
		if c != 0 {
			return c
		}
	}
}

// compareDigits compares two non-negative decimal integers of any length.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// isJSSpace reports whether r is whitespace for JavaScript's String.prototype.trim and \s.
func isJSSpace(r rune) bool {
	return r == '\uFEFF' || (r != '\u0085' && unicode.IsSpace(r))
}

func jsTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }
