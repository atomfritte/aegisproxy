package pkgver

import (
	"errors"
	"strconv"
	"strings"
)

// PEP440Version is a PEP 440 version as pypa/packaging parses it. Numeric components must fit into an int.
type PEP440Version struct {
	epoch   int
	release []int
	preL    uint8 // pre-release kind: preA, preB, preRC; valid when hasPre
	preN    int
	postN   int
	devN    int
	hasPre  bool
	hasPost bool
	hasDev  bool
	local   []pepLocal
	raw     string // trimmed input, compared by the === operator
}

// pepLocal is a local version segment; numeric segments sort after alphanumeric ones.
type pepLocal struct {
	s   string
	num bool
}

const (
	preA uint8 = iota
	preB
	preRC
)

var errPEP440 = errors.New("invalid PEP 440 version")

// ParsePEP440 parses a version with every spelling PEP 440 allows: a leading "v", epochs ("1!2.0"), alternative
// pre-release names (alpha, beta, c, pre, preview), implicit numbers ("1.0a"), implicit post releases ("1.0-1"),
// separators "." "-" "_" or none, and local versions ("+ubuntu.1").
func ParsePEP440(s string) (PEP440Version, error) {
	v, rest, ok := scanPEP440(strings.TrimSpace(s), true)
	if !ok || rest != "" {
		return PEP440Version{}, errPEP440
	}
	return v, nil
}

// scanPEP440 parses the longest version prefix of s, the way packaging's possessive VERSION_PATTERN does.
func scanPEP440(s string, allowLocal bool) (PEP440Version, string, bool) {
	v := PEP440Version{raw: s}
	i := 0
	if i < len(s) && (s[i] == 'v' || s[i] == 'V') {
		i++
	}
	n, j, ok := pepNum(s, i)
	if !ok {
		return v, s, false
	}
	if j < len(s) && s[j] == '!' {
		v.epoch = n
		if n, j, ok = pepNum(s, j+1); !ok {
			return v, s, false
		}
	}
	v.release = append(make([]int, 0, 4), n)
	for j+1 < len(s) && s[j] == '.' && isDigit(s[j+1]) {
		if n, j, ok = pepNum(s, j+1); !ok {
			return v, s, false
		}
		v.release = append(v.release, n)
	}
	i = j

	// Pre-release: [._-]? (alpha|a|beta|b|preview|pre|c|rc) [._-]? [0-9]*
	k := skipSep(s, i)
	if l, kind := pepLabel(s[k:], "alpha", "a", "beta", "b", "preview", "pre", "c", "rc"); l > 0 {
		v.hasPre, v.preL = true, [...]uint8{preA, preA, preB, preB, preRC, preRC, preRC, preRC}[kind]
		if v.preN, i, ok = pepOptNum(s, skipSep(s, k+l)); !ok {
			return v, s, false
		}
	}

	// Post release: -N | [._-]? (post|rev|r) [._-]? [0-9]*
	if i+1 < len(s) && s[i] == '-' && isDigit(s[i+1]) {
		v.hasPost = true
		if v.postN, i, ok = pepNum(s, i+1); !ok {
			return v, s, false
		}
	} else {
		k = skipSep(s, i)
		if l, _ := pepLabel(s[k:], "post", "rev", "r"); l > 0 {
			v.hasPost = true
			if v.postN, i, ok = pepOptNum(s, skipSep(s, k+l)); !ok {
				return v, s, false
			}
		}
	}

	// Development release: [._-]? dev [._-]? [0-9]*
	k = skipSep(s, i)
	if l, _ := pepLabel(s[k:], "dev"); l > 0 {
		v.hasDev = true
		if v.devN, i, ok = pepOptNum(s, skipSep(s, k+l)); !ok {
			return v, s, false
		}
	}

	// Local version: + [a-z0-9]+ ([._-][a-z0-9]+)*
	if allowLocal && i+1 < len(s) && s[i] == '+' && isAlnum(s[i+1]) {
		j = i + 1
		for {
			e := j
			for e < len(s) && isAlnum(s[e]) {
				e++
			}
			seg := strings.ToLower(s[j:e])
			v.local = append(v.local, pepLocal{s: seg, num: allDigits(seg)})
			i = e
			if e+1 < len(s) && isSep(s[e]) && isAlnum(s[e+1]) {
				j = e + 1
				continue
			}
			break
		}
	}
	return v, s[i:], true
}

// pepLabel returns the length and index of the first label (case-insensitive) that prefixes s.
func pepLabel(s string, labels ...string) (int, int) {
	for k, l := range labels {
		if len(s) >= len(l) && strings.EqualFold(s[:len(l)], l) {
			return len(l), k
		}
	}
	return 0, 0
}

// pepNum reads a decimal number at s[i:].
func pepNum(s string, i int) (int, int, bool) {
	j := i
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j == i {
		return 0, j, false
	}
	n, err := strconv.Atoi(s[i:j])
	return n, j, err == nil
}

// pepOptNum reads an optional number (implicit 0).
func pepOptNum(s string, i int) (int, int, bool) {
	if i < len(s) && isDigit(s[i]) {
		return pepNum(s, i)
	}
	return 0, i, true
}

func skipSep(s string, i int) int {
	if i < len(s) && isSep(s[i]) {
		return i + 1
	}
	return i
}

func isSep(c byte) bool   { return c == '.' || c == '_' || c == '-' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool { return isDigit(c) || c|0x20 >= 'a' && c|0x20 <= 'z' }

// String returns the normalized form, e.g. "1!2.0rc1.post2.dev3+ubuntu.1" ("v1.0-ALPHA" becomes "1.0a0").
func (v PEP440Version) String() string {
	b := make([]byte, 0, 16)
	if v.epoch != 0 {
		b = strconv.AppendInt(b, int64(v.epoch), 10)
		b = append(b, '!')
	}
	b = v.appendRelease(b)
	if v.hasPre {
		b = append(b, [...]string{"a", "b", "rc"}[v.preL]...)
		b = strconv.AppendInt(b, int64(v.preN), 10)
	}
	if v.hasPost {
		b = append(b, ".post"...)
		b = strconv.AppendInt(b, int64(v.postN), 10)
	}
	if v.hasDev {
		b = append(b, ".dev"...)
		b = strconv.AppendInt(b, int64(v.devN), 10)
	}
	for i, l := range v.local {
		if i == 0 {
			b = append(b, '+')
		} else {
			b = append(b, '.')
		}
		if l.num {
			b = append(b, trimZeros(l.s)...)
		} else {
			b = append(b, l.s...)
		}
	}
	return string(b)
}

func (v PEP440Version) appendRelease(b []byte) []byte {
	for i, n := range v.release {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendInt(b, int64(n), 10)
	}
	return b
}

func trimZeros(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// IsPrerelease reports a pre-release or development release.
func (v PEP440Version) IsPrerelease() bool { return v.hasPre || v.hasDev }

// IsPostrelease reports a post release.
func (v PEP440Version) IsPostrelease() bool { return v.hasPost }

// Epoch returns the epoch (0 when absent).
func (v PEP440Version) Epoch() int { return v.epoch }

// Release returns the release segment, e.g. [1 2 3] for 1.2.3rc1.
func (v PEP440Version) Release() []int { return append([]int(nil), v.release...) }

// Local reports whether the version has a local segment.
func (v PEP440Version) Local() bool { return len(v.local) > 0 }

// Public returns the version without its local segment.
func (v PEP440Version) Public() PEP440Version {
	v.local = nil
	v.raw = ""
	return v
}

func (v PEP440Version) releaseAt(i int) int {
	if i < len(v.release) {
		return v.release[i]
	}
	return 0
}

func (v PEP440Version) compareRelease(o PEP440Version) int {
	for i, n := 0, max(len(v.release), len(o.release)); i < n; i++ {
		if c := cmpInt(v.releaseAt(i), o.releaseAt(i)); c != 0 {
			return c
		}
	}
	return 0
}

// suffix is packaging's pre/post/dev sort key: dev-only releases before a < b < rc < final, then post, then dev.
func (v PEP440Version) suffix() [6]int {
	var k [6]int
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		k[0] = -1
	case !v.hasPre:
		k[0] = 3
	default:
		k[0], k[1] = int(v.preL), v.preN
	}
	if v.hasPost {
		k[2], k[3] = 1, v.postN
	}
	k[4] = 1
	if v.hasDev {
		k[4], k[5] = 0, v.devN
	}
	return k
}

// Compare orders versions per PEP 440: epoch, release (trailing zeros ignored), dev-only < pre < final < post,
// development releases before their release, then local versions (none < alphanumeric < numeric segments).
func (v PEP440Version) Compare(o PEP440Version) int {
	if c := v.comparePublic(o); c != 0 {
		return c
	}
	return compareLocal(v.local, o.local)
}

func (v PEP440Version) comparePublic(o PEP440Version) int {
	if c := cmpInt(v.epoch, o.epoch); c != 0 {
		return c
	}
	if c := v.compareRelease(o); c != 0 {
		return c
	}
	a, b := v.suffix(), o.suffix()
	for i := range a {
		if c := cmpInt(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

func compareLocal(a, b []pepLocal) int {
	if len(a) == 0 || len(b) == 0 {
		return cmpInt(len(a), len(b))
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		var c int
		switch {
		case x.num && y.num:
			c = compareDigits(x.s, y.s)
		case x.num:
			c = 1
		case y.num:
			c = -1
		default:
			c = strings.Compare(x.s, y.s)
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}
