package pkgver

import (
	"strings"
	"testing"
)

// The fuzz targets seed from the differential vectors and check that parsers never panic and that the
// normalized forms parse back to themselves.

func FuzzParseNPMRange(f *testing.F) {
	var vec npmVectors
	loadVectors(f, "npm.json", &vec)
	for _, r := range vec.Ranges {
		f.Add(r.In, "1.2.3-beta.1")
	}
	f.Fuzz(func(t *testing.T, s, version string) {
		r, err := ParseNPMRange(s)
		if err != nil {
			return
		}
		norm := r.String()
		again, err := ParseNPMRange(norm)
		if err != nil {
			t.Fatalf("ParseNPMRange(%q) = %q, which does not parse: %v", s, norm, err)
		}
		// Like semver.validRange, one more pass may still drop a ">=0.0.0" ("00" -> ">=0.0.0 <1.0.0-0" ->
		// "<1.0.0-0"); after that the form is stable.
		fixed := again.String()
		if third, err := ParseNPMRange(fixed); err != nil || third.String() != fixed {
			t.Fatalf("ParseNPMRange(%q) = %q -> %q -> %q, %v", s, norm, fixed, third, err)
		}
		if v, err := ParseNPM(version); err == nil && r.Contains(v, false) != again.Contains(v, false) {
			t.Fatalf("%q and its normal form %q disagree on %s", s, norm, v)
		}
	})
}

func FuzzParsePEP440(f *testing.F) {
	var vec pypiVectors
	loadVectors(f, "pypi.json", &vec)
	for _, v := range vec.Versions {
		f.Add(v.In)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParsePEP440(s)
		if err != nil {
			return
		}
		norm := v.String()
		again, err := ParsePEP440(norm)
		if err != nil {
			t.Fatalf("ParsePEP440(%q) = %q, which does not parse: %v", s, norm, err)
		}
		if again.String() != norm || again.Compare(v) != 0 {
			t.Fatalf("ParsePEP440(%q) = %q, reparsed %q (compare %d)", s, norm, again, again.Compare(v))
		}
	})
}

func FuzzParseRequirement(f *testing.F) {
	var vec pypiVectors
	loadVectors(f, "pypi.json", &vec)
	for _, r := range vec.Requirements {
		f.Add(r.In)
	}
	for _, m := range vec.Markers {
		f.Add("name; " + m.In)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRequirement(s)
		if err != nil {
			return
		}
		norm := r.String()
		again, err := ParseRequirement(norm)
		if err != nil {
			// PEP 503 normalization turns a trailing "_" (which packaging's grammar allows) into "-".
			if strings.HasSuffix(r.Name, "-") || strings.Contains(strings.Join(r.Extras, ",")+",", "-,") {
				return
			}
			t.Fatalf("ParseRequirement(%q) = %q, which does not parse: %v", s, norm, err)
		}
		if again.String() != norm {
			t.Fatalf("ParseRequirement(%q) = %q, reparsed %q", s, norm, again)
		}
		for _, env := range DefaultPythonEnvironments() {
			if r.ParsedMarker().Evaluate(env) != again.ParsedMarker().Evaluate(env) {
				t.Fatalf("%q and its normal form %q evaluate differently in %v", s, norm, env)
			}
		}
	})
}

func FuzzParseNuGetRange(f *testing.F) {
	var vec nugetVectors
	loadVectors(f, "nuget.json", &vec)
	for _, r := range vec.Ranges {
		f.Add(r.In)
	}
	for _, v := range vec.Versions {
		f.Add(v.In)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, err := ParseNuGet(s); err == nil {
			if again, err := ParseNuGet(v.String()); err != nil || again.Compare(v) != 0 {
				t.Fatalf("ParseNuGet(%q) = %q, reparsed %q, %v", s, v, again, err)
			}
		}
		r, err := ParseNuGetRange(s)
		if err != nil {
			return
		}
		norm := r.String()
		again, err := ParseNuGetRange(norm)
		if err != nil || again.String() != norm {
			t.Fatalf("ParseNuGetRange(%q) = %q, reparsed %q, %v", s, norm, again, err)
		}
	})
}

func FuzzMatchPackagePattern(f *testing.F) {
	f.Add("@types/*", "@types/node")
	f.Add("zope.*", "Zope_Interface")
	f.Add("a*b?c", "aXXbYc")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		for _, eco := range []string{ecoNPM, ecoPyPI, ecoNuGet} {
			MatchPackagePattern(pattern, name, eco)
		}
		if !MatchPackagePattern("*", name, ecoNPM) {
			t.Fatalf("* does not match %q", name)
		}
		if !strings.ContainsAny(name, "*?") && !MatchPackagePattern(name, name, ecoNPM) {
			t.Fatalf("%q does not match itself", name)
		}
	})
}
