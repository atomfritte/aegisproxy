package pkgver

import (
	"slices"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func TestEcosystemIdentifiers(t *testing.T) {
	if got := []string{ecoNPM, ecoPyPI, ecoNuGet, ecoPSGallery}; !slices.Equal(got, models.Ecosystems) {
		t.Errorf("ecosystem identifiers %v, models.Ecosystems %v", got, models.Ecosystems)
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		eco, a, b string
		want      int
	}{
		{"npm", "1.0.0", "2.0.0", -1},
		{"npm", "1.0.0", "1.0.0+build", 0},
		{"npm", "bogus", "0.0.0", -1}, // unparsable versions sort first
		{"npm", "1.0.0", "bogus", 1},
		{"npm", "a", "b", -1}, // and among themselves by string
		{"pypi", "1.0", "1.0.0", 0},
		{"pypi", "1.0.post1", "1.0", 1},
		{"pypi", "1.0rc1", "1.0", -1},
		{"nuget", "1.0.0-BETA", "1.0.0-beta", 0},
		{"nuget", "1.0.0.1", "1.0.0", 1},
		{"psgallery", "2.3.5", "2.10.0", -1},
		{"other", "b", "a", 1},
	}
	for _, tt := range tests {
		if got := Compare(tt.eco, tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", tt.eco, tt.a, tt.b, got, tt.want)
		}
	}
	versions := []string{"2.0.0", "zzz", "1.0.0-rc.1", "1.0.0", "aaa", "1.10.0", "1.2.0"}
	slices.SortStableFunc(versions, func(a, b string) int { return Compare("npm", a, b) })
	if want := []string{"aaa", "zzz", "1.0.0-rc.1", "1.0.0", "1.2.0", "1.10.0", "2.0.0"}; !slices.Equal(versions, want) {
		t.Errorf("sorted = %v, want %v", versions, want)
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		eco, v string
		want   bool
	}{
		{"npm", "1.0.0-rc.1", true},
		{"npm", "1.0.0", false},
		{"npm", "bogus", false},
		{"pypi", "1.0.dev1", true},
		{"pypi", "1.0b2", true},
		{"pypi", "1.0.post1", false},
		{"nuget", "1.0.0-beta", true},
		{"psgallery", "1.0.0", false},
		{"other", "1.0.0-beta", false},
	}
	for _, tt := range tests {
		if got := IsPrerelease(tt.eco, tt.v); got != tt.want {
			t.Errorf("IsPrerelease(%s, %q) = %v, want %v", tt.eco, tt.v, got, tt.want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct{ eco, in, want string }{
		{"npm", "v1.2.3", "1.2.3"},
		{"npm", "1.2.3-beta.1+build", "1.2.3-beta.1"},
		{"pypi", "1.0-RC1", "1.0rc1"},
		{"pypi", "v2!1.0.0-post1", "2!1.0.0.post1"},
		{"nuget", "1.0.0.0-Beta+meta", "1.0.0-beta"},
		{"nuget", "01.2", "1.2.0"},
		{"psgallery", "2.3.5.1", "2.3.5.1"},
	}
	for _, tt := range tests {
		if got, err := NormalizeVersion(tt.eco, tt.in); err != nil || got != tt.want {
			t.Errorf("NormalizeVersion(%s, %q) = %q, %v; want %q", tt.eco, tt.in, got, err, tt.want)
		}
	}
	for _, bad := range [][2]string{{"npm", "1.2"}, {"pypi", "foo"}, {"nuget", "1.0.0.0.0"}, {"other", "1.0.0"}} {
		if got, err := NormalizeVersion(bad[0], bad[1]); err == nil {
			t.Errorf("NormalizeVersion(%s, %q) = %q, want error", bad[0], bad[1], got)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct{ eco, in, want string }{
		{"npm", "@Scope/Name", "@Scope/Name"},
		{"pypi", "Foo_Bar.baz", "foo-bar-baz"},
		{"nuget", "Newtonsoft.Json", "newtonsoft.json"},
		{"psgallery", "PSReadLine", "psreadline"},
		{"other", "X", "X"},
	}
	for _, tt := range tests {
		if got := NormalizeName(tt.eco, tt.in); got != tt.want {
			t.Errorf("NormalizeName(%s, %q) = %q, want %q", tt.eco, tt.in, got, tt.want)
		}
	}
}

func TestUpdateType(t *testing.T) {
	tests := []struct{ eco, from, to, want string }{
		{"npm", "1.0.0", "2.0.0", UpdateMajor},
		{"npm", "1.0.0", "1.1.0", UpdateMinor},
		{"npm", "1.0.0", "1.0.1", UpdatePatch},
		{"npm", "1.9.0-rc.1", "2.0.0", UpdateMajor},
		{"npm", "1.0.0-rc.1", "1.0.0", UpdatePrerelease},
		{"npm", "1.0.0-rc.1", "1.0.0-rc.2", UpdatePrerelease},
		{"npm", "1.0.0", "1.0.0-rc.1", UpdateDowngrade},
		{"npm", "2.0.0", "1.0.0", UpdateDowngrade},
		{"npm", "v1.0.0", "1.0.0+build", UpdateSame},
		{"npm", "bogus", "1.0.0", ""},
		{"pypi", "1.0", "2.0", UpdateMajor},
		{"pypi", "1.0", "1!0.1", UpdateMajor},
		{"pypi", "1", "1.1", UpdateMinor},
		{"pypi", "1.0", "1.0.1", UpdatePatch},
		{"pypi", "1.0", "1.0.0.1", UpdatePatch},
		{"pypi", "1.0", "1.0.post1", UpdatePatch},
		{"pypi", "1.0rc1", "1.0", UpdatePrerelease},
		{"pypi", "1.0.dev1", "1.0a1", UpdatePrerelease},
		{"pypi", "1.0", "1.0.0", UpdateSame},
		{"pypi", "2.0", "1.0", UpdateDowngrade},
		{"pypi", "1.0", "foo", ""},
		{"nuget", "1.0", "2.0", UpdateMajor},
		{"nuget", "1.0.0", "1.0.0.1", UpdatePatch},
		{"nuget", "1.0.0-beta", "1.0.0", UpdatePrerelease},
		{"nuget", "1.0.0-BETA", "1.0.0-beta", UpdateSame},
		{"psgallery", "2.3.4", "2.4.0", UpdateMinor},
		{"other", "1.0.0", "2.0.0", ""},
	}
	for _, tt := range tests {
		if got := UpdateType(tt.from, tt.to, tt.eco); got != tt.want {
			t.Errorf("UpdateType(%q, %q, %s) = %q, want %q", tt.from, tt.to, tt.eco, got, tt.want)
		}
	}
}

func TestRangeContains(t *testing.T) {
	tests := []struct {
		eco, rng, v string
		want        bool
	}{
		{"npm", "^1.2.0", "1.5.0", true},
		{"npm", "^1.2.0", "1.5.0-beta", false},
		{"npm", ">=1.5.0-beta <2", "1.5.0-beta.2", true},
		{"npm", "", "1.0.0", true},
		{"npm", "bogus", "1.0.0", false},
		{"npm", "^1", "bogus", false},
		{"pypi", ">=1.0", "1.5", true},
		{"pypi", ">=1.0", "2.0b1", false},
		{"pypi", ">=1.0b1", "2.0b1", true},
		{"pypi", "", "1.0", true},
		{"pypi", "==1.*", "1.0", true},
		{"pypi", "~=", "1.0", false},
		{"nuget", "[1.0,2.0)", "1.5.0", true},
		{"nuget", "[1.0,2.0)", "1.5.0-beta", false},
		{"nuget", "1.*", "2.0.0", false},
		{"nuget", "1.0.0-*", "1.0.0-rc", true},
		{"psgallery", "", "0.1.0", true},
		{"psgallery", "(1.0)", "1.0.0", false},
		{"other", "*", "1.0.0", false},
	}
	for _, tt := range tests {
		if got := RangeContains(tt.eco, tt.rng, tt.v); got != tt.want {
			t.Errorf("RangeContains(%s, %q, %q) = %v, want %v", tt.eco, tt.rng, tt.v, got, tt.want)
		}
	}
}

func TestMaxSatisfying(t *testing.T) {
	tests := []struct {
		eco      string
		versions []string
		rng      string
		want     string // "" = none
	}{
		{"npm", []string{"1.0.0", "1.2.0", "2.0.0", "v1.3.0", "1.4.0-beta", "bogus"}, "^1", "1.3.0"},
		{"npm", []string{"1.0.0"}, "^2", ""},
		{"npm", []string{"1.0.0"}, "bogus", ""},
		{"pypi", []string{"1.0", "1.1", "2.0b1", "bogus"}, ">=1.0", "1.1"},
		{"pypi", []string{"2.0b1", "2.0rc1"}, ">=1.0", "2.0rc1"}, // pre-releases when nothing else matches
		{"pypi", []string{"1.0", "2.0b1"}, ">=1.0b1", "2.0b1"},
		{"pypi", []string{"1.0", "1.0.0"}, "==1.0", "1.0"},
		{"pypi", []string{"1.0"}, ">=2", ""},
		{"nuget", []string{"1.0.0", "1.0.1", "2.0.0"}, "1.0", "1.0.0"},
		{"nuget", []string{"1.0.0", "1.5.0-Beta", "1.4.0"}, "1.*", "1.4.0"},
		{"nuget", []string{"1.0.0-Beta"}, "1.0.0-*", "1.0.0-beta"},
		{"psgallery", []string{"2.3.5", "2.3.4"}, "", "2.3.4"},
		{"other", []string{"1.0.0"}, "*", ""},
	}
	for _, tt := range tests {
		got, ok := MaxSatisfying(tt.eco, tt.versions, tt.rng)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("MaxSatisfying(%s, %v, %q) = %q, %v; want %q", tt.eco, tt.versions, tt.rng, got, ok, tt.want)
		}
	}
}

func TestMatchPackagePattern(t *testing.T) {
	tests := []struct {
		pattern, name, eco string
		want               bool
	}{
		{"lodash", "lodash", "npm", true},
		{"Lodash", "lodash", "npm", false},
		{"@types/*", "@types/node", "npm", true},
		{"*", "@scope/x", "npm", true},
		{"lod?sh", "lodash", "npm", true},
		{"lod?sh", "lodsh", "npm", false},
		{"@scope/*-utils", "@scope/foo-utils", "npm", true},
		{"a*b*c", "aXbYc", "npm", true},
		{"a*b*c", "aXbY", "npm", false},
		{"*.js", "socket.io.js", "npm", true},
		{"", "", "npm", true},
		{"", "x", "npm", false},
		{"?", "é", "npm", true},
		{"??", "é", "npm", false},
		{"Django*", "django-rest-framework", "pypi", true},
		{"zope.*", "zope-interface", "pypi", true},
		{"zope_*", "Zope.Interface", "pypi", true},
		{"requests", "Requests", "pypi", true},
		{"foo-?ar", "foo_bar", "pypi", true},
		{"Microsoft.*", "microsoft.extensions.logging", "nuget", true},
		{"newtonsoft.json", "Newtonsoft.Json", "nuget", true},
		{"Az.*", "az.accounts", "psgallery", true},
		{"System.?", "System.IO", "nuget", false},
		{strings.Repeat("a*", 30) + "b", strings.Repeat("a", 200), "npm", false},
	}
	for _, tt := range tests {
		if got := MatchPackagePattern(tt.pattern, tt.name, tt.eco); got != tt.want {
			t.Errorf("MatchPackagePattern(%q, %q, %s) = %v, want %v", tt.pattern, tt.name, tt.eco, got, tt.want)
		}
	}
}
