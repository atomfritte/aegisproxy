package pkgver

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
)

// NuGetVersion is a NuGet package version (SemVer 2.0 with an optional fourth "revision" part) as
// NuGet.Versioning parses it.
type NuGetVersion struct {
	parts  [4]int // major, minor, patch, revision
	labels []string
	meta   string
}

var errNuGet = errors.New("invalid NuGet version")

// ParseNuGet parses a version like NuGetVersion.TryParse: surrounding whitespace is ignored, one to four numeric
// parts (leading zeros and whitespace around a part are allowed), dot-separated pre-release labels of
// [0-9A-Za-z-] without leading zeros in numeric labels, and build metadata after "+".
func ParseNuGet(s string) (NuGetVersion, error) {
	s = strings.TrimFunc(s, unicode.IsSpace)
	var v NuGetVersion
	core, labels, meta := s, "", ""
	hasLabels, hasMeta := false, false
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		core = s[:i]
		if s[i] == '-' {
			hasLabels, labels = true, s[i+1:]
			if j := strings.IndexByte(labels, '+'); j >= 0 {
				hasMeta, meta, labels = true, labels[j+1:], labels[:j]
			}
		} else {
			hasMeta, meta = true, s[i+1:]
		}
	}
	if core == "" {
		return v, errNuGet
	}
	n := 0
	for part := range strings.SplitSeq(core, ".") {
		part = strings.TrimFunc(part, unicode.IsSpace)
		if n == 4 || part == "" || strings.Trim(part, "0123456789") != "" {
			return v, errNuGet
		}
		x, err := strconv.ParseInt(part, 10, 32)
		if err != nil {
			return v, errNuGet
		}
		v.parts[n] = int(x)
		n++
	}
	if hasLabels {
		v.labels = strings.Split(labels, ".")
		for _, l := range v.labels {
			if !nugetValidPart(l, false) {
				return NuGetVersion{}, errNuGet
			}
		}
	}
	if hasMeta {
		for m := range strings.SplitSeq(meta, ".") {
			if !nugetValidPart(m, true) {
				return NuGetVersion{}, errNuGet
			}
		}
		v.meta = meta
	}
	return v, nil
}

// nugetValidPart is NuGet's IsValidPart: non-empty [0-9A-Za-z-], and no leading zero in a numeric label.
func nugetValidPart(s string, allowLeadingZeros bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(isAlnum(c) || c == '-') {
			return false
		}
	}
	return allowLeadingZeros || len(s) == 1 || s[0] != '0' || strings.Trim(s, "0123456789") != ""
}

// Major returns the first version part.
func (v NuGetVersion) Major() int { return v.parts[0] }

// Minor returns the second version part.
func (v NuGetVersion) Minor() int { return v.parts[1] }

// Patch returns the third version part.
func (v NuGetVersion) Patch() int { return v.parts[2] }

// Revision returns the fourth (legacy) version part.
func (v NuGetVersion) Revision() int { return v.parts[3] }

// Release returns the pre-release labels joined with "." ("" for a stable version).
func (v NuGetVersion) Release() string { return strings.Join(v.labels, ".") }

// Metadata returns the build metadata ("" when absent).
func (v NuGetVersion) Metadata() string { return v.meta }

// IsPrerelease reports whether the version has pre-release labels.
func (v NuGetVersion) IsPrerelease() bool { return len(v.labels) > 0 }

// Normalize returns NuGet's normalized form: three parts, the revision only when non-zero, the pre-release
// labels, no build metadata ("01.2-Beta+git" becomes "1.2.0-Beta").
func (v NuGetVersion) Normalize() string {
	b := make([]byte, 0, 16)
	b = v.appendNumbers(b)
	if len(v.labels) > 0 {
		b = append(b, '-')
		b = append(b, v.Release()...)
	}
	return string(b)
}

func (v NuGetVersion) appendNumbers(b []byte) []byte {
	n := 3
	if v.parts[3] > 0 {
		n = 4
	}
	for i := range n {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendInt(b, int64(v.parts[i]), 10)
	}
	return b
}

// Lower returns the lowercased normalized form, as the flat-container (v3) API addresses versions.
func (v NuGetVersion) Lower() string { return strings.ToLower(v.Normalize()) }

// String returns the normalized form.
func (v NuGetVersion) String() string { return v.Normalize() }

// Compare orders versions like NuGet's default comparer: the four numeric parts, then a stable version after its
// pre-releases, labels pairwise (numeric before alphanumeric, alphanumeric case-insensitively, fewer labels
// first). Build metadata is ignored.
func (v NuGetVersion) Compare(o NuGetVersion) int {
	for i := range v.parts {
		if c := cmpInt(v.parts[i], o.parts[i]); c != 0 {
			return c
		}
	}
	if len(v.labels) == 0 || len(o.labels) == 0 {
		return cmpInt(len(o.labels), len(v.labels))
	}
	for i := 0; i < len(v.labels) && i < len(o.labels); i++ {
		if c := compareNuGetLabel(v.labels[i], o.labels[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(v.labels), len(o.labels))
}

func compareNuGetLabel(a, b string) int {
	x, aNum := nugetInt32(a)
	y, bNum := nugetInt32(b)
	switch {
	case aNum && bNum:
		return cmpInt(x, y)
	case aNum:
		return -1
	case bNum:
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpInt(int(upperASCII(a[i])), int(upperASCII(b[i]))); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

// nugetInt32 is Int32.TryParse for a label: an optional "-" and digits within the int32 range.
func nugetInt32(s string) (int, bool) {
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 32)
	return int(n), err == nil
}

func upperASCII(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// PSGalleryDependency is one entry of a PowerShell Gallery (NuGet v2 feed) dependency list.
type PSGalleryDependency struct {
	ID              string
	Range           string // NuGet version range ("" = any version)
	TargetFramework string
}

// ParsePSGalleryDependencies parses the v2 feed's Dependencies property, "Id:Range:TargetFramework|...". Entries
// without an ID (framework-only placeholders) are skipped.
func ParsePSGalleryDependencies(s string) []PSGalleryDependency {
	var deps []PSGalleryDependency
	for entry := range strings.SplitSeq(s, "|") {
		f := strings.SplitN(entry, ":", 3)
		d := PSGalleryDependency{ID: strings.TrimSpace(f[0])}
		if d.ID == "" {
			continue
		}
		if len(f) > 1 {
			d.Range = strings.TrimSpace(f[1])
		}
		if len(f) > 2 {
			d.TargetFramework = strings.TrimSpace(f[2])
		}
		deps = append(deps, d)
	}
	return deps
}
