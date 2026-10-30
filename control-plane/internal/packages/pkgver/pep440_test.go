package pkgver

import (
	"slices"
	"testing"
)

func TestParsePEP440Normalize(t *testing.T) {
	tests := []struct{ in, want string }{
		// pypa/packaging test_version.py normalization cases
		{"1.0dev", "1.0.dev0"}, {"1.0.dev", "1.0.dev0"}, {"1.0dev1", "1.0.dev1"}, {"1.0-dev", "1.0.dev0"},
		{"1.0-dev1", "1.0.dev1"}, {"1.0DEV", "1.0.dev0"}, {"1.0.DEV1", "1.0.dev1"}, {"1.0a", "1.0a0"},
		{"1.0.a", "1.0a0"}, {"1.0.a1", "1.0a1"}, {"1.0-a", "1.0a0"}, {"1.0alpha", "1.0a0"}, {"1.0.alpha1", "1.0a1"},
		{"1.0beta", "1.0b0"}, {"1.0-beta1", "1.0b1"}, {"1.0c", "1.0rc0"}, {"1.0.c1", "1.0rc1"},
		{"1.0pre", "1.0rc0"}, {"1.0preview1", "1.0rc1"}, {"1.0rc", "1.0rc0"}, {"1.0RC1", "1.0rc1"},
		{"1.0post", "1.0.post0"}, {"1.0.post1", "1.0.post1"}, {"1.0-r", "1.0.post0"}, {"1.0rev4", "1.0.post4"},
		{"1.0-1", "1.0.post1"}, {"1.0+ubuntu-1", "1.0+ubuntu.1"}, {"1.0+ubuntu_1", "1.0+ubuntu.1"},
		{"1.0+UBUNTU.01", "1.0+ubuntu.1"}, {"v1.0", "1.0"}, {" 1.0 ", "1.0"}, {"0!1.0", "1.0"}, {"01!01.02", "1!1.2"},
		{"1.0.0.0", "1.0.0.0"}, {"1.0a1-1", "1.0a1.post1"}, {"1.0-1.dev2", "1.0.post1.dev2"},
		{"1!2.0b3.post4.dev5+local.6", "1!2.0b3.post4.dev5+local.6"},
	}
	for _, tt := range tests {
		v, err := ParsePEP440(tt.in)
		if err != nil || v.String() != tt.want {
			t.Errorf("ParsePEP440(%q) = %q, %v; want %q", tt.in, v, err, tt.want)
		}
	}
	for _, bad := range []string{"", "foo", "1.0+", "1.0+.1", "1.0a1a1", "1.0.post1.post2", "1..0", "1.0.", "1 .0",
		"1!", "!1", "1.0-", "1.0_", "a1.0", "1.0+local version", "1.0.dev1.dev2", "1.0-1-1"} {
		if v, err := ParsePEP440(bad); err == nil {
			t.Errorf("ParsePEP440(%q) = %q, want error", bad, v)
		}
	}
}

// pypa/packaging test_version.py VERSIONS, in ascending order.
var pep440Ordered = []string{
	"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456",
	"1.0b2.post345", "1.0b2-346", "1.0c1.dev456", "1.0c1", "1.0rc2", "1.0c3", "1.0", "1.0.post456.dev34",
	"1.0.post456", "1.1.dev1", "1.2+123abc", "1.2+123abc456", "1.2+abc", "1.2+abc123", "1.2+abc123def",
	"1.2+1234.abc", "1.2+123456", "1.2.r32+123456", "1.2.rev33+123456",
	"1!1.0.dev456", "1!1.0a1", "1!1.0a2.dev456", "1!1.0a12.dev456", "1!1.0a12", "1!1.0b1.dev456", "1!1.0b2",
	"1!1.0b2.post345.dev456", "1!1.0b2.post345", "1!1.0b2-346", "1!1.0c1.dev456", "1!1.0c1", "1!1.0rc2", "1!1.0c3",
	"1!1.0", "1!1.0.post456.dev34", "1!1.0.post456", "1!1.1.dev1", "1!1.2+123abc", "1!1.2+123abc456", "1!1.2+abc",
	"1!1.2+abc123", "1!1.2+abc123def", "1!1.2+1234.abc", "1!1.2+123456", "1!1.2.r32+123456", "1!1.2.rev33+123456",
}

func TestPEP440Compare(t *testing.T) {
	parsed := make([]PEP440Version, len(pep440Ordered))
	for i, s := range pep440Ordered {
		v, err := ParsePEP440(s)
		if err != nil {
			t.Fatalf("ParsePEP440(%q): %v", s, err)
		}
		parsed[i] = v
	}
	for i := range parsed {
		for j := range parsed {
			if got, want := parsed[i].Compare(parsed[j]), cmpInt(i, j); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", pep440Ordered[i], pep440Ordered[j], got, want)
			}
		}
	}
	equal := [][2]string{{"1.0", "1.0.0"}, {"1.0", "1.0.0.0.0"}, {"1.0a1", "1.0.alpha.1"}, {"1.0+abc.1", "1.0+ABC-1"},
		{"1.0+01", "1.0+1"}, {"0!1.0", "1.0"}, {"1.0.post0", "1.0post"}}
	for _, p := range equal {
		a, _ := ParsePEP440(p[0])
		b, _ := ParsePEP440(p[1])
		if a.Compare(b) != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", p[0], p[1], a.Compare(b))
		}
	}
}

func TestPEP440Accessors(t *testing.T) {
	v, err := ParsePEP440("2!1.2.3rc1.post4.dev5+ubuntu.1")
	if err != nil {
		t.Fatal(err)
	}
	if v.Epoch() != 2 || !slices.Equal(v.Release(), []int{1, 2, 3}) || !v.IsPrerelease() || !v.IsPostrelease() ||
		!v.Local() || v.Public().String() != "2!1.2.3rc1.post4.dev5" {
		t.Errorf("accessors of %s: epoch=%d release=%v pre=%v post=%v local=%v public=%s", v, v.Epoch(), v.Release(),
			v.IsPrerelease(), v.IsPostrelease(), v.Local(), v.Public())
	}
	v.Release()[0] = 9 // Release returns a copy
	if v.Release()[0] != 1 {
		t.Error("Release shares the version's storage")
	}
	for s, pre := range map[string]bool{"1.0": false, "1.0.dev1": true, "1.0a1": true, "1.0.post1": false,
		"1.0.post1.dev1": true, "1.0rc1+local": true} {
		if v, _ := ParsePEP440(s); v.IsPrerelease() != pre {
			t.Errorf("ParsePEP440(%q).IsPrerelease() = %v", s, !pre)
		}
	}
}

func TestSpecifierContains(t *testing.T) {
	// pypa/packaging test_specifiers.py (prereleases allowed, as the tests construct the specifiers)
	matching := [][2]string{
		{"2.0", "==2"}, {"2.0", "==2.0"}, {"2.0", "==2.0.0"}, {"2.0+deadbeef", "==2"}, {"2.0+deadbeef", "==2.0"},
		{"2.0+deadbeef", "==2.0.0"}, {"2.0+deadbeef", "==2+deadbeef"}, {"2.0+deadbeef", "==2.0+deadbeef"},
		{"2.0+deadbeef", "==2.0.0+deadbeef"}, {"2.0+deadbeef.0", "==2.0.0+deadbeef.00"},
		{"2.dev1", "==2.*"}, {"2a1", "==2.*"}, {"2a1.post1", "==2.*"}, {"2b1", "==2.*"}, {"2b1.dev1", "==2.*"},
		{"2c1", "==2.*"}, {"2c1.post1.dev1", "==2.*"}, {"2c1.post1.dev1", "==2.0.*"}, {"2rc1", "==2.*"},
		{"2rc1", "==2.0.*"}, {"2", "==2.*"}, {"2", "==2.0.*"}, {"2", "==0!2.*"}, {"0!2", "==2.*"}, {"2.0", "==2.*"},
		{"2.0.0", "==2.*"}, {"2.1+local.version", "==2.1.*"},
		{"2.1", "!=2"}, {"2.1", "!=2.0"}, {"2.0.1", "!=2"}, {"2.0.1", "!=2.0"}, {"2.0.1", "!=2.0.0"},
		{"2.0", "!=2.0+deadbeef"}, {"2.0", "!=3.*"}, {"2.1", "!=2.0.*"},
		{"2.0", ">=2"}, {"2.0", ">=2.0"}, {"2.0", ">=2.0.0"}, {"2.0.post1", ">=2"}, {"2.0.post1.dev1", ">=2"}, {"3", ">=2"},
		{"2.0", "<=2"}, {"2.0", "<=2.0"}, {"2.0", "<=2.0.0"}, {"2.0.dev1", "<=2"}, {"2.0a1", "<=2"}, {"2.0a1.dev1", "<=2"},
		{"2.0b1", "<=2"}, {"2.0b1.post1", "<=2"}, {"2.0c1", "<=2"}, {"2.0c1.post1.dev1", "<=2"}, {"2.0rc1", "<=2"},
		{"1", "<=2"},
		{"3", ">2"}, {"2.1", ">2.0"}, {"2.0.1", ">2"}, {"2.1.post1", ">2"}, {"2.1+local.version", ">2"},
		{"1", "<2"}, {"2.0", "<2.1"}, {"2.0.dev0", "<2.1"},
		{"1", "~=1.0"}, {"1.0.1", "~=1.0"}, {"1.1", "~=1.0"}, {"1.9999999", "~=1.0"}, {"1.1", "~=1.0a1"},
		{"2022.01.01", "~=2022.01.01"},
		{"2!1.0", "~=2!1.0"}, {"2!1.0", "==2!1.*"}, {"2!1.0", "==2!1.0"}, {"2!1.0", "!=1.0"}, {"1.0", "!=2!1.0"},
		{"1.0", "<=2!0.1"}, {"2!1.0", ">=2.0"}, {"1.0", "<2!0.1"}, {"2!1.0", ">2.0"},
		{"2.0.5", ">2.0dev"},
	}
	failing := [][2]string{
		{"2.1", "==2"}, {"2.1", "==2.0"}, {"2.1", "==2.0.0"}, {"2.0", "==2.0+deadbeef"}, {"2.0", "==3.*"},
		{"2.1", "==2.0.*"},
		{"2.0", "!=2"}, {"2.0", "!=2.0"}, {"2.0", "!=2.0.0"}, {"2.0+deadbeef", "!=2"}, {"2.0+deadbeef", "!=2.0"},
		{"2.0+deadbeef", "!=2.0.0"}, {"2.0+deadbeef", "!=2+deadbeef"}, {"2.0+deadbeef", "!=2.0+deadbeef"},
		{"2.0+deadbeef", "!=2.0.0+deadbeef"}, {"2.0+deadbeef.0", "!=2.0.0+deadbeef.00"},
		{"2.dev1", "!=2.*"}, {"2a1", "!=2.*"}, {"2a1.post1", "!=2.*"}, {"2b1", "!=2.*"}, {"2b1.dev1", "!=2.*"},
		{"2c1", "!=2.*"}, {"2c1.post1.dev1", "!=2.*"}, {"2c1.post1.dev1", "!=2.0.*"}, {"2rc1", "!=2.*"},
		{"2rc1", "!=2.0.*"}, {"2", "!=2.*"}, {"2", "!=2.0.*"}, {"2.0", "!=2.*"}, {"2.0.0", "!=2.*"},
		{"2.0.dev1", ">=2"}, {"2.0a1", ">=2"}, {"2.0a1.dev1", ">=2"}, {"2.0b1", ">=2"}, {"2.0b1.post1", ">=2"},
		{"2.0c1", ">=2"}, {"2.0c1.post1.dev1", ">=2"}, {"2.0rc1", ">=2"}, {"1", ">=2"},
		{"2.0.post1", "<=2"}, {"2.0.post1.dev1", "<=2"}, {"3", "<=2"},
		{"1", ">2"}, {"2.0.dev1", ">2"}, {"2.0a1", ">2"}, {"2.0a1.post1", ">2"}, {"2.0b1", ">2"}, {"2.0b1.dev1", ">2"},
		{"2.0c1", ">2"}, {"2.0c1.post1.dev1", ">2"}, {"2.0rc1", ">2"}, {"2.0", ">2"}, {"2.0.post1", ">2"},
		{"2.0.post1.dev1", ">2"}, {"2.0+local.version", ">2"},
		{"2.0.dev1", "<2"}, {"2.0a1", "<2"}, {"2.0a1.post1", "<2"}, {"2.0b1", "<2"}, {"2.0b2.dev1", "<2"},
		{"2.0c1", "<2"}, {"2.0c1.post1.dev1", "<2"}, {"2.0rc1", "<2"}, {"2.0", "<2"}, {"2.post1", "<2"},
		{"2.post1.dev1", "<2"}, {"3", "<2"},
		{"2.0", "~=1.0"}, {"1.1.0", "~=1.0.0"}, {"1.1.post1", "~=1.0.0"},
		{"1.0", "~=2!1.0"}, {"2!1.0", "~=1.0"}, {"2!1.0", "==1.0"}, {"1.0", "==2!1.0"}, {"2!1.0", "==1.*"},
		{"1.0", "==2!1.*"}, {"2!1.0", "!=2!1.0"},
	}
	check := func(pairs [][2]string, want bool) {
		for _, p := range pairs {
			set, err := ParseSpecifierSet(p[1])
			if err != nil {
				t.Errorf("ParseSpecifierSet(%q): %v", p[1], err)
				continue
			}
			v, err := ParsePEP440(p[0])
			if err != nil {
				t.Fatalf("ParsePEP440(%q): %v", p[0], err)
			}
			if got := set.Contains(v, true); got != want {
				t.Errorf("%q Contains(%s) = %v, want %v", p[1], p[0], got, want)
			}
		}
	}
	check(matching, true)
	check(failing, false)

	// Without prereleases, pre and development releases never match.
	set, _ := ParseSpecifierSet(">=1.0")
	if v, _ := ParsePEP440("2.0b1"); set.Contains(v, false) {
		t.Error(">=1.0 contains 2.0b1 without prereleases")
	}
}

func TestParseSpecifierSet(t *testing.T) {
	tests := []struct {
		in, want string
		pre      bool
	}{
		{"", "", false},
		{">=1.0", ">=1.0", false},
		{" >= 1.0 , < 2 ", "<2,>=1.0", false},
		{"==1.0.*,!=1.0.3", "!=1.0.3,==1.0.*", false},
		{">=1.0a1", ">=1.0a1", true},
		{"!=1.0a1", "!=1.0a1", false},
		{"<2.0.dev1", "<2.0.dev1", true},
		{"~=1.4.5a4", "~=1.4.5a4", true},
		{"===foobar", "===foobar", false},
		{"===1.0rc1", "===1.0rc1", true},
		{"=== ", "===", false}, // packaging accepts an empty arbitrary version
		{">=1.0,>=1.0", ">=1.0", false},
		{"==1.0+local", "==1.0+local", false},
	}
	for _, tt := range tests {
		set, err := ParseSpecifierSet(tt.in)
		if err != nil || set.String() != tt.want || set.AllowsPrereleases() != tt.pre {
			t.Errorf("ParseSpecifierSet(%q) = %q pre=%v, %v; want %q %v", tt.in, set, set.AllowsPrereleases(), err,
				tt.want, tt.pre)
		}
	}
	for _, bad := range []string{"foo", "==", ">=1.0 <2", "~=1", "~=1.0.*", "==1.0.*+local", "<1.0+local",
		">=1.*", "==1.0a1.*", "===a b", "==1.0.post1.*", "1.0", "=1.0"} {
		if set, err := ParseSpecifierSet(bad); err == nil {
			t.Errorf("ParseSpecifierSet(%q) = %q, want error", bad, set)
		}
	}
}

func TestFilter(t *testing.T) {
	tests := []struct {
		spec     string
		versions []string
		want     []string
	}{
		// packaging's SpecifierSet.filter examples (PEP 440's pre-release recommendation)
		{">=1.2.3", []string{"1.2", "1.3", "1.5a1"}, []string{"1.3"}},
		{">=1.2.3", []string{"1.2", "1.5a1"}, []string{"1.5a1"}},
		{"", []string{"1.3", "1.5a1"}, []string{"1.3"}},
		{"", []string{"1.5a1"}, []string{"1.5a1"}},
		{">=1.0a1", []string{"1.0", "1.1a1"}, []string{"1.0", "1.1a1"}},
		{">=1.0", []string{"0.9", "bogus", "1.0", "1.1.dev1", "1.1"}, []string{"1.0", "1.1"}},
		{"==2.*", []string{"2.0a1", "2.0", "3.0"}, []string{"2.0"}},
		{"<1", []string{"1.0", "2.0"}, nil},
	}
	for _, tt := range tests {
		set, err := ParseSpecifierSet(tt.spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := Filter(tt.versions, set); !slices.Equal(got, tt.want) {
			t.Errorf("Filter(%v, %q) = %v, want %v", tt.versions, tt.spec, got, tt.want)
		}
	}
}
