package pkgver

import (
	"slices"
	"testing"
)

func TestParseNuGet(t *testing.T) {
	tests := []struct {
		in, norm, lower, meta string
		parts                 [4]int
		pre                   bool
	}{
		{"1.0", "1.0.0", "1.0.0", "", [4]int{1, 0, 0, 0}, false},
		{"1", "1.0.0", "1.0.0", "", [4]int{1, 0, 0, 0}, false},
		{"1.0.0.0", "1.0.0", "1.0.0", "", [4]int{1, 0, 0, 0}, false},
		{"1.0.0.1", "1.0.0.1", "1.0.0.1", "", [4]int{1, 0, 0, 1}, false},
		{"01.002.0003", "1.2.3", "1.2.3", "", [4]int{1, 2, 3, 0}, false},
		{" 1.2.3-Beta.1+Git.Sha ", "1.2.3-Beta.1", "1.2.3-beta.1", "Git.Sha", [4]int{1, 2, 3, 0}, true},
		{"1.2.3+0001", "1.2.3", "1.2.3", "0001", [4]int{1, 2, 3, 0}, false},
		{"4.0.0-beta-12345", "4.0.0-beta-12345", "4.0.0-beta-12345", "", [4]int{4, 0, 0, 0}, true},
		{"1.0.0.1-RC", "1.0.0.1-RC", "1.0.0.1-rc", "", [4]int{1, 0, 0, 1}, true},
	}
	for _, tt := range tests {
		v, err := ParseNuGet(tt.in)
		if err != nil || v.Normalize() != tt.norm || v.Lower() != tt.lower || v.String() != tt.norm ||
			v.Metadata() != tt.meta || [4]int{v.Major(), v.Minor(), v.Patch(), v.Revision()} != tt.parts ||
			v.IsPrerelease() != tt.pre {
			t.Errorf("ParseNuGet(%q) = %s/%s meta=%q parts=%v pre=%v, %v", tt.in, v, v.Lower(), v.Metadata(),
				[4]int{v.Major(), v.Minor(), v.Patch(), v.Revision()}, v.IsPrerelease(), err)
		}
	}
	for _, bad := range []string{"", "v1.0", "1.0.0.0.0", "1..0", "1.0.", "1.0.0-", "1.0.0+", "1.0.0-01",
		"1.0.0-a_b", "1.0.0-a..b", "1.0.0+a+b", "2147483648.0", "-1.0", "+1.0", "1.*", "１.0"} {
		if v, err := ParseNuGet(bad); err == nil {
			t.Errorf("ParseNuGet(%q) = %s, want error", bad, v)
		}
	}
}

func TestNuGetCompare(t *testing.T) {
	ordered := []string{"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0.1-beta", "1.0.0.1", "1.0.1", "1.10.0", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			a, _ := ParseNuGet(ordered[i])
			b, _ := ParseNuGet(ordered[j])
			if got := a.Compare(b); got != cmpInt(i, j) {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, cmpInt(i, j))
			}
		}
	}
	for _, p := range [][2]string{{"1.0.0-BETA", "1.0.0-beta"}, {"1.0", "1.0.0.0"}, {"1.0.0+a", "1.0.0+b"}} {
		a, _ := ParseNuGet(p[0])
		b, _ := ParseNuGet(p[1])
		if a.Compare(b) != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", p[0], p[1], a.Compare(b))
		}
	}
}

func TestNuGetRange(t *testing.T) {
	tests := []struct {
		in, norm string
		floating bool
		in_, out []string // versions inside and outside (without includePrerelease)
	}{
		// NuGet's version range documentation
		{"1.0", "[1.0.0, )", false, []string{"1.0.0", "2.0.0"}, []string{"0.9.0", "1.0.1-beta"}},
		{"(1.0,)", "(1.0.0, )", false, []string{"1.0.1"}, []string{"1.0.0"}},
		{"[1.0]", "[1.0.0, 1.0.0]", false, []string{"1.0.0", "1.0.0.0"}, []string{"1.0.1"}},
		{"(,1.0]", "(, 1.0.0]", false, []string{"0.1.0", "1.0.0"}, []string{"1.0.1"}},
		{"(,1.0)", "(, 1.0.0)", false, []string{"0.9.9"}, []string{"1.0.0", "1.0.0-beta"}},
		{"[1.0,2.0]", "[1.0.0, 2.0.0]", false, []string{"1.0.0", "2.0.0"}, []string{"2.0.1"}},
		{"(1.0,2.0)", "(1.0.0, 2.0.0)", false, []string{"1.5.0"}, []string{"1.0.0", "2.0.0"}},
		{"[1.0,2.0)", "[1.0.0, 2.0.0)", false, []string{"1.9.9"}, []string{"2.0.0", "2.0.0-beta"}},
		{" [ 1.0 , 2.0 ) ", "[1.0.0, 2.0.0)", false, []string{"1.0.0"}, nil},
		{"[1.0.0-beta, 2.0)", "[1.0.0-beta, 2.0.0)", false, []string{"1.0.0-beta", "1.5.0-rc.1"}, []string{"1.0.0-alpha"}},
		{"1*", "[10.0.0, )", false, []string{"10.0.0"}, []string{"1.0.0"}}, // NuGet's FloatRange quirk
		// floating ranges
		{"*", "[*, )", true, []string{"0.0.0", "99.0.0"}, []string{"1.0.0-beta"}},
		{"*-*", "[*-*, )", true, []string{"1.0.0-beta", "1.0.0"}, nil},
		{"1.*", "[1.*, )", true, []string{"1.0.0", "1.99.0"}, []string{"2.0.0", "0.9.0", "1.5.0-beta"}},
		{"1.2.*", "[1.2.*, )", true, []string{"1.2.0", "1.2.9"}, []string{"1.3.0", "1.2.9-beta"}},
		{"1.2.3.*", "[1.2.3.*, )", true, []string{"1.2.3", "1.2.3.9"}, []string{"1.2.4"}},
		{"1.0.0-*", "[1.0.0-*, )", true, []string{"1.0.0-alpha", "1.0.0"}, []string{"1.0.1", "1.0.1-beta"}},
		{"1.0.0-beta*", "[1.0.0-beta*, )", true, []string{"1.0.0-beta", "1.0.0-beta.5", "1.0.0-BETA2", "1.0.0"},
			[]string{"1.0.0-alpha", "1.0.0-rc"}},
		{"1.0.0-beta.*", "[1.0.0-beta.*, )", true, []string{"1.0.0-beta.1"}, []string{"1.0.0-beta"}},
		{"1.*-*", "[1.*-*, )", true, []string{"1.0.0-alpha", "1.5.0"}, []string{"2.0.0-alpha"}},
		{"*-rc*", "[*-rc*, )", true, []string{"1.0.0-rc.1", "3.0.0"}, []string{"1.0.0-beta"}},
		{"[1.*, 2.0)", "[1.*, 2.0.0)", true, []string{"1.5.0"}, []string{"2.0.0"}},
		{"", "(, )", false, []string{"0.0.0", "1.0.0"}, []string{"1.0.0-beta"}}, // all versions
	}
	for _, tt := range tests {
		r, err := ParseNuGetRange(tt.in)
		if err != nil || r.String() != tt.norm || r.IsFloating() != tt.floating {
			t.Errorf("ParseNuGetRange(%q) = %q floating=%v, %v; want %q %v", tt.in, r, r.IsFloating(), err, tt.norm,
				tt.floating)
			continue
		}
		for _, s := range tt.in_ {
			if v, _ := ParseNuGet(s); !r.Contains(v, false) {
				t.Errorf("%q does not contain %s", tt.in, s)
			}
		}
		for _, s := range tt.out {
			if v, _ := ParseNuGet(s); r.Contains(v, false) {
				t.Errorf("%q contains %s", tt.in, s)
			}
		}
	}
	// includePrerelease admits pre-releases within the bounds of stable ranges
	r, _ := ParseNuGetRange("[1.0,2.0)")
	if v, _ := ParseNuGet("1.5.0-beta"); !r.Contains(v, true) {
		t.Error("[1.0,2.0) Contains(1.5.0-beta, true) = false")
	}
	for _, bad := range []string{"(1.0)", "[1.0", "1.0]", "(,)", "[,]", "[1.0,2.0,3.0]", "[2.0,1.0]", "[1.0,1.0)",
		"(1.0,1.0]", "[1.0, 2.*)", "[1.*]", "1.*.3", "1.0.*-beta", "*.*", "1.2.3.4.*", "~1.0", ">=1.0", "1.0 - 2.0"} {
		if r, err := ParseNuGetRange(bad); err == nil {
			t.Errorf("ParseNuGetRange(%q) = %q, want error", bad, r)
		}
	}
}

func TestBestMatch(t *testing.T) {
	tests := []struct {
		rng      string
		versions []string
		want     string // "" = none
	}{
		// lowest applicable version for non-floating ranges
		{"1.0", []string{"2.0.0", "1.0.1", "1.0.0", "0.9.0"}, "1.0.0"},
		{"[1.0, 2.0)", []string{"0.9", "1.5", "1.2", "2.0"}, "1.2"},
		{"(1.0,)", []string{"1.0.0", "1.0.1"}, "1.0.1"},
		{"1.0", []string{"1.0.1-beta", "1.0.2"}, "1.0.2"},
		{"1.0.0-beta", []string{"1.0.0-beta.2", "1.0.0"}, "1.0.0-beta.2"},
		{"1.0", []string{"1.0.0+b", "1.0.0+a"}, "1.0.0+b"}, // equal versions: the first wins
		{"[3.0,)", []string{"1.0", "2.0"}, ""},
		// highest version within the float, else the lowest above it
		{"6.0.*", []string{"6.0.0", "6.0.1", "6.1.0"}, "6.0.1"},
		{"6.0.*", []string{"6.1.0", "7.0.0", "6.2.0"}, "6.1.0"},
		{"1.*", []string{"1.0.0", "1.9.0", "2.0.0", "1.10.0-beta"}, "1.9.0"},
		{"*", []string{"1.0.0", "2.0.0-beta", "1.5.0"}, "1.5.0"},
		{"*-*", []string{"1.0.0", "2.0.0-beta", "1.5.0"}, "2.0.0-beta"},
		{"1.0.0-*", []string{"1.0.0-alpha", "1.0.0-beta", "1.0.0"}, "1.0.0"},
		{"1.0.0-*", []string{"1.0.0-alpha", "1.0.0-beta"}, "1.0.0-beta"},
		{"1.0.0-beta*", []string{"1.0.0-alpha", "1.0.0-beta.2", "1.0.0-rc.1"}, "1.0.0-beta.2"},
		{"1.0.0-beta*", []string{"1.0.0-alpha", "1.0.0-rc.1", "1.0.1"}, "1.0.0-rc.1"},
		{"[1.*, 2.0)", []string{"2.0.0", "1.5.0", "1.2.0"}, "1.5.0"},
		{"1.*", []string{"bogus", "1.2.0"}, "1.2.0"},
	}
	for _, tt := range tests {
		r, err := ParseNuGetRange(tt.rng)
		if err != nil {
			t.Fatalf("ParseNuGetRange(%q): %v", tt.rng, err)
		}
		got, ok := BestMatch(tt.versions, r)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("BestMatch(%v, %q) = %q, %v; want %q", tt.versions, tt.rng, got, ok, tt.want)
		}
	}
}

func TestParsePSGalleryDependencies(t *testing.T) {
	tests := []struct {
		in   string
		want []PSGalleryDependency
	}{
		{"", nil},
		{"PackageManagement:[1.4.4, ):|PowerShellGet:[2.0.0, ):", []PSGalleryDependency{
			{ID: "PackageManagement", Range: "[1.4.4, )"}, {ID: "PowerShellGet", Range: "[2.0.0, )"}}},
		{" Az.Accounts : 2.12.1 : net472 | | Az.Resources:: |:[1.0]:net40", []PSGalleryDependency{
			{ID: "Az.Accounts", Range: "2.12.1", TargetFramework: "net472"}, {ID: "Az.Resources"}}},
		{"Pester", []PSGalleryDependency{{ID: "Pester"}}},
	}
	for _, tt := range tests {
		if got := ParsePSGalleryDependencies(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("ParsePSGalleryDependencies(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}
