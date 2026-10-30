package pkgver

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizePyPIName normalizes a project or extra name (PEP 503): lowercase, runs of "-", "_" and "." become "-".
func NormalizePyPIName(name string) string {
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			name = strings.ToLower(name)
			break
		}
	}
	b := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case isSep(c):
			if i == 0 || !isSep(name[i-1]) {
				b = append(b, '-')
			}
		case c >= 'A' && c <= 'Z':
			b = append(b, c+'a'-'A')
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// Wheel is a parsed wheel file name (PEP 427): {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl.
type Wheel struct {
	Name         string   // PEP 503 normalized
	Version      string   // PEP 440 normalized
	Build        string   // build tag ("" = none)
	PythonTags   []string // e.g. [py2 py3] for the compressed tag set py2.py3
	ABITags      []string
	PlatformTags []string
}

var errWheel = errors.New("invalid wheel file name")

// ParseWheelFilename parses a wheel file name like packaging.utils.parse_wheel_filename. Tags are lowercased.
func ParseWheelFilename(fn string) (Wheel, error) {
	stem, ok := strings.CutSuffix(fn, ".whl")
	dashes := strings.Count(stem, "-")
	if !ok || (dashes != 4 && dashes != 5) {
		return Wheel{}, errWheel
	}
	parts := strings.SplitN(stem, "-", dashes-1)
	name := parts[0]
	if name == "" || strings.Contains(name, "__") ||
		strings.IndexFunc(name, func(r rune) bool { return r != '.' && !isWordRune(r) }) >= 0 {
		return Wheel{}, errWheel
	}
	v, err := ParsePEP440(parts[1])
	if err != nil {
		return Wheel{}, errWheel
	}
	w := Wheel{Name: NormalizePyPIName(name), Version: v.String()}
	if dashes == 5 {
		if w.Build = parts[2]; w.Build == "" || !isDigit(w.Build[0]) {
			return Wheel{}, errWheel
		}
	}
	tags := strings.Split(strings.ToLower(parts[len(parts)-1]), "-")
	for _, t := range tags {
		for _, c := range strings.Split(t, ".") {
			if c == "" {
				return Wheel{}, errWheel
			}
		}
	}
	w.PythonTags, w.ABITags, w.PlatformTags = strings.Split(tags[0], "."), strings.Split(tags[1], "."), strings.Split(tags[2], ".")
	for _, t := range w.PythonTags {
		if !isPyIdentifier(t) {
			return Wheel{}, errWheel
		}
	}
	return w, nil
}

func isPyIdentifier(s string) bool {
	for i, r := range s {
		if !(r == '_' || unicode.IsLetter(r) || (i > 0 && (unicode.IsDigit(r) || unicode.Is(unicode.Mn, r)))) {
			return false
		}
	}
	return s != ""
}

// sdistExtensions are the source distribution archive types PyPI has accepted (case-insensitive).
var sdistExtensions = []string{".tar.gz", ".zip", ".tar.bz2", ".tgz", ".tar.xz", ".tar"}

// ParseSdistFilename returns the normalized version of a source distribution file name ({name}-{version}.tar.gz,
// .zip and legacy archive types). With the project known, the version is what follows the prefix whose normalized
// form is the project name, so legacy names with dashes ("foo-bar-1.0-2.tar.gz") work; otherwise it is the part
// after the last dash, as packaging.utils.parse_sdist_filename does.
func ParseSdistFilename(fn string, project string) (version string, ok bool) {
	stem := ""
	lower := strings.ToLower(fn)
	for _, ext := range sdistExtensions {
		if strings.HasSuffix(lower, ext) {
			stem = fn[:len(fn)-len(ext)]
			break
		}
	}
	var vpart string
	if project != "" {
		want := NormalizePyPIName(project)
		for i := 0; i < len(stem); i++ {
			if stem[i] == '-' && NormalizePyPIName(stem[:i]) == want {
				vpart, ok = stem[i+1:], true
				break
			}
		}
	} else if i := strings.LastIndexByte(stem, '-'); i > 0 {
		vpart, ok = stem[i+1:], true
	}
	if !ok {
		return "", false
	}
	v, err := ParsePEP440(vpart)
	if err != nil {
		return "", false
	}
	return v.String(), true
}

// PyPIFileVersion returns the normalized version of a wheel or source distribution file of project (any project
// when empty); ok is false for other files and for wheels of another project.
func PyPIFileVersion(filename, project string) (normalizedVersion string, ok bool) {
	if strings.HasSuffix(filename, ".whl") {
		w, err := ParseWheelFilename(filename)
		if err != nil || (project != "" && w.Name != NormalizePyPIName(project)) {
			return "", false
		}
		return w.Version, true
	}
	return ParseSdistFilename(filename, project)
}
