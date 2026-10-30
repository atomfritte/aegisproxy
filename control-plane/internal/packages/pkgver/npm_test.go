package pkgver

import (
	"sync"
	"testing"
)

func TestParseNPM(t *testing.T) {
	tests := []struct {
		in        string
		want      string // "" = invalid
		maj, min_ int64
		patch     int64
		pre       bool
	}{
		{"1.2.3", "1.2.3", 1, 2, 3, false},
		{"v1.2.3", "1.2.3", 1, 2, 3, false},
		{" =v1.2.3 ", "1.2.3", 1, 2, 3, false},
		{"1.2.3-beta.1", "1.2.3-beta.1", 1, 2, 3, true},
		{"1.2.3-beta+build.5", "1.2.3-beta", 1, 2, 3, true},
		{"1.2.3+build", "1.2.3", 1, 2, 3, false},
		{"0.0.0-0", "0.0.0-0", 0, 0, 0, true},
		{"9007199254740991.0.0", "9007199254740991.0.0", 9007199254740991, 0, 0, false},
		{"9007199254740992.0.0", "", 0, 0, 0, false},
		{"1.2", "", 0, 0, 0, false},
		{"1.2.3.4", "", 0, 0, 0, false},
		{"01.2.3", "", 0, 0, 0, false},
		{"1.2.3-01", "", 0, 0, 0, false},
		{"1.2.3-", "", 0, 0, 0, false},
		{"1.2.3-a..b", "", 0, 0, 0, false},
		{"1.2.3beta", "", 0, 0, 0, false},
		{"", "", 0, 0, 0, false},
	}
	for _, tt := range tests {
		v, err := ParseNPM(tt.in)
		if tt.want == "" {
			if err == nil {
				t.Errorf("ParseNPM(%q) = %s, want error", tt.in, v)
			}
			continue
		}
		if err != nil || v.String() != tt.want || v.Major() != tt.maj || v.Minor() != tt.min_ || v.Patch() != tt.patch ||
			v.Prerelease() != tt.pre {
			t.Errorf("ParseNPM(%q) = %s (%d.%d.%d pre=%v), %v; want %s", tt.in, v, v.Major(), v.Minor(), v.Patch(),
				v.Prerelease(), err, tt.want)
		}
	}
}

// node-semver test/fixtures/comparisons.js: the first version sorts after the second.
func TestNPMCompare(t *testing.T) {
	greater := [][2]string{
		{"0.0.0", "0.0.0-foo"}, {"0.0.1", "0.0.0"}, {"1.0.0", "0.9.9"}, {"0.10.0", "0.9.0"}, {"0.99.0", "0.10.0"},
		{"2.0.0", "1.2.3"}, {"v0.0.0", "0.0.0-foo"}, {"v0.0.1", "0.0.0"}, {"v1.0.0", "0.9.9"}, {"v0.10.0", "0.9.0"},
		{"v0.99.0", "0.10.0"}, {"v2.0.0", "1.2.3"}, {"0.0.0", "v0.0.0-foo"}, {"0.0.1", "v0.0.0"},
		{"1.0.0", "v0.9.9"}, {"0.10.0", "v0.9.0"}, {"0.99.0", "v0.10.0"}, {"2.0.0", "v1.2.3"},
		{"1.2.3", "1.2.3-asdf"}, {"1.2.3", "1.2.3-4"}, {"1.2.3", "1.2.3-4-foo"}, {"1.2.3-5-foo", "1.2.3-5"},
		{"1.2.3-5", "1.2.3-4"}, {"1.2.3-5-foo", "1.2.3-5-Foo"}, {"3.0.0", "2.7.2+asdf"}, {"1.2.3-a.10", "1.2.3-a.5"},
		{"1.2.3-a.b", "1.2.3-a.5"}, {"1.2.3-a.b", "1.2.3-a"}, {"1.2.3-a.b.c.10.d.5", "1.2.3-a.b.c.5.d.100"},
		{"1.2.3-r2", "1.2.3-r100"}, {"1.2.3-r100", "1.2.3-R2"}, {"1.0.0-alpha.9007199254740992", "1.0.0-alpha.3"},
	}
	for _, p := range greater {
		a, errA := ParseNPM(p[0])
		b, errB := ParseNPM(p[1])
		if errA != nil || errB != nil {
			t.Fatalf("parse %v: %v %v", p, errA, errB)
		}
		if a.Compare(b) != 1 || b.Compare(a) != -1 || a.Compare(a) != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 1", p[0], p[1], a.Compare(b))
		}
	}
	// node-semver test/fixtures/equality.js
	equal := [][2]string{
		{"1.2.3", "v1.2.3"}, {"1.2.3", "=1.2.3"}, {"1.2.3", "v 1.2.3"}, {"1.2.3", "= 1.2.3"}, {"1.2.3", " v1.2.3"},
		{"1.2.3", " =1.2.3"}, {"1.2.3", " v 1.2.3"}, {"1.2.3", " = 1.2.3"}, {"1.2.3-0", "v1.2.3-0"},
		{"1.2.3-0", "= 1.2.3-0"}, {"1.2.3-1", "v1.2.3-1"}, {"1.2.3-beta", "v1.2.3-beta"},
		{"1.2.3-beta+build", " = 1.2.3-beta+otherbuild"}, {"1.2.3+build", " = 1.2.3+otherbuild"},
		{"1.2.3-beta+build", "1.2.3-beta+otherbuild"}, {"1.2.3+build", "1.2.3+otherbuild"},
		{"  v1.2.3+build", "1.2.3+otherbuild"},
	}
	for _, p := range equal {
		a, errA := ParseNPM(p[0])
		b, errB := ParseNPM(p[1])
		if errA != nil || errB != nil || a.Compare(b) != 0 {
			t.Errorf("Compare(%q, %q) = %d (%v %v), want 0", p[0], p[1], a.Compare(b), errA, errB)
		}
	}
}

func TestNPMRange(t *testing.T) {
	tests := []struct {
		rng, version string
		incPre, want bool
	}{
		// node-semver test/fixtures/range-include.js (loose)
		{"1.0.0 - 2.0.0", "1.2.3", false, true},
		{"^1.2.3+build", "1.3.0", false, true},
		{"1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3-pre.2", false, true},
		{"1.2.3pre+asdf - 2.4.3pre+asdf", "1.2.3", false, true},
		{"", "1.0.0", false, true},
		{"*", "1.2.3", false, true},
		{">=0.2.3 || <0.0.1", "0.0.0", false, true},
		{"||", "1.3.4", false, true},
		{"2.x.x", "2.1.3", false, true},
		{"1.2.* || 2.*", "2.1.3", false, true},
		{"~0.0.1", "0.0.2", false, true},
		{"~>3.2.1", "3.2.2", false, true},
		{"~ 1.0.3alpha", "1.0.12", false, true},
		{"~v0.5.4-pre", "0.5.5", false, true},
		{"<=0.7.x", "0.6.2", false, true},
		{"~1.2.1 >=1.2.3 1.2.3", "1.2.3", false, true},
		{"^0.1.2", "0.1.2", false, true},
		{"^1.2 ^1", "1.4.2", false, true},
		{"^1.2.3-alpha", "1.2.3-pre", false, true},
		{"^0.0.1-alpha", "0.0.1-beta", false, true},
		{"x - 1.0.0", "0.9.7", false, true},
		{"1.x - x", "1.9.7", false, true},
		{"2.x", "2.0.0-pre.0", true, true},
		{"*", "1.0.0-rc1", true, true},
		{"^1.0.0-0", "1.0.1-rc1", true, true},
		{"1 - 2", "2.0.0-pre", true, true},
		{">=1.0.0 <=1.1.0", "1.1.0-pre", true, true},
		// node-semver test/fixtures/range-exclude.js (loose)
		{"1.0.0 - 2.0.0", "2.2.3", false, false},
		{"1.2.3+asdf - 2.4.3+asdf", "2.4.3-alpha", false, false},
		{"^1.2.3+build", "2.0.0", false, false},
		{"^1.2.3", "1.2.3-pre", false, false},
		{">1.2", "1.3.0-beta", false, false},
		{"<=1.2.3", "1.2.3-beta", false, false},
		{"=0.7.x", "0.7.0-asdf", false, false},
		{"<1", "1.0.0", false, false},
		{"~0.0.1", "0.1.0-alpha", false, false},
		{"~1.0", "1.1.0", false, false},
		{"<0.7.x", "0.7.2", false, false},
		{"^0.0.1", "0.0.2", false, false},
		{"^1.2.3", "2.0.0-alpha", false, false},
		{"*", "1.2.3-foo", false, false},
		{"^1.0.0", "2.0.0-rc1", true, false},
		{"^1.2.3-rc2", "2.0.0", true, false},
		{"1 - 2", "2.0.0-pre", false, false},
		{"1.1.x", "1.1.0-a", false, false},
		{"1.1.x", "1.0.0-a", true, false},
		{"1.x", "2.0.0-a", true, false},
		{">=1.0.0 <1.1.0", "1.1.0-pre", false, false},
		{">=1.0.0 <1.1.0-pre", "1.1.0-pre", false, false},
		{"== 1.0.0 || foo", "2.0.0", false, false},
		// prerelease rule: only a comparator set with a prerelease of the same tuple admits prereleases
		{">1.2.3-alpha.3", "1.2.3-alpha.7", false, true},
		{">1.2.3-alpha.3", "3.4.5-alpha.9", false, false},
		{">1.2.3-alpha.3 || >=3.4.5-alpha.0", "3.4.5-alpha.9", false, true},
		// tilde with includePrerelease admits the -0 prereleases of the lower bound (node-semver 7.7)
		{"~1.2.3", "1.2.3-0", true, false},
		{"~1.2", "1.2.0-0", true, true},
	}
	for _, tt := range tests {
		r, err := ParseNPMRange(tt.rng)
		if err != nil {
			t.Errorf("ParseNPMRange(%q): %v", tt.rng, err)
			continue
		}
		v, err := ParseNPM(tt.version)
		if err != nil {
			t.Fatalf("ParseNPM(%q): %v", tt.version, err)
		}
		if got := r.Contains(v, tt.incPre); got != tt.want {
			t.Errorf("%q Contains(%s, %v) = %v, want %v", tt.rng, tt.version, tt.incPre, got, tt.want)
		}
	}
}

func TestNPMRangeString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "*"},
		{"*", "*"},
		{"x", "*"},
		{"^1.2.3", ">=1.2.3 <2.0.0-0"},
		{"^0.2.3", ">=0.2.3 <0.3.0-0"},
		{"^0.0.3", ">=0.0.3 <0.0.4-0"},
		{"^0.0", "<0.1.0-0"},
		{"~1.2.3", ">=1.2.3 <1.3.0-0"},
		{"~1", ">=1.0.0 <2.0.0-0"},
		{"1.2.x", ">=1.2.0 <1.3.0-0"},
		{"1.0.0 - 2.0.0", ">=1.0.0 <=2.0.0"},
		{"1.2 - 2.3", ">=1.2.0 <2.4.0-0"},
		{">=1.2.3 || <1.0.0", ">=1.2.3||<1.0.0"},
		{"> 1.2.3   < 2", ">1.2.3 <2.0.0-0"},
		{"<x", "<0.0.0-0"},
		{"1.2.3+build", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{"=1.2.3", "1.2.3"},
		// npm parses ranges loosely: invalid comparators are dropped
		{"1.2.3 || foo", "1.2.3"},
		{">=1.2.3 <=foo", ">=1.2.3"},
		{"1.2.3 - ", "1.2.3"},
	}
	for _, tt := range tests {
		r, err := ParseNPMRange(tt.in)
		if err != nil || r.String() != tt.want {
			t.Errorf("ParseNPMRange(%q) = %q, %v; want %q", tt.in, r, err, tt.want)
		}
	}
	for _, bad := range []string{"blerg", "git+https://user:password0123@github.com/foo", "foo || bar", ">=a.b.c"} {
		if r, err := ParseNPMRange(bad); err == nil {
			t.Errorf("ParseNPMRange(%q) = %q, want error", bad, r)
		}
	}
}

func TestNPMRangeCacheConcurrent(t *testing.T) {
	v, _ := ParseNPM("1.5.0")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 2 * npmRangeCacheSize {
				rng := ">=1.0.0 <2.0.0"
				if (i+j)%3 == 0 {
					rng = "^1." + string(rune('0'+j%10)) + ".0"
				}
				r, err := ParseNPMRange(rng)
				if err != nil || !r.Contains(v, false) && rng == ">=1.0.0 <2.0.0" {
					t.Errorf("ParseNPMRange(%q) = %q, %v", rng, r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestMaxSatisfyingNPM(t *testing.T) {
	versions := []string{"1.2.3", "1.2.4", "1.3.0-beta", "2.0.0", "not-a-version", "v1.2.5"}
	tests := []struct {
		rng  string
		want string
		ok   bool
	}{
		{"^1.2.0", "v1.2.5", true},
		{"~1.2.3", "v1.2.5", true},
		{">=1.3.0-beta <1.4", "1.3.0-beta", true},
		{"*", "2.0.0", true},
		{"^3", "", false},
		{"blerg", "", false},
	}
	for _, tt := range tests {
		got, ok := MaxSatisfyingNPM(versions, tt.rng)
		if got != tt.want || ok != tt.ok {
			t.Errorf("MaxSatisfyingNPM(%q) = %q, %v; want %q, %v", tt.rng, got, ok, tt.want, tt.ok)
		}
	}
}

func TestClassifyNPMSpec(t *testing.T) {
	tests := []struct {
		in   string
		want NPMSpec
	}{
		{"", NPMSpec{Kind: NPMSpecRange, Range: "*"}},
		{"*", NPMSpec{Kind: NPMSpecRange, Range: "*"}},
		{"^1.2.3", NPMSpec{Kind: NPMSpecRange, Range: "^1.2.3"}},
		{" >=1 <2 ", NPMSpec{Kind: NPMSpecRange, Range: ">=1 <2"}},
		{"1.2.3", NPMSpec{Kind: NPMSpecRange, Range: "1.2.3", Version: "1.2.3"}},
		{"v1.2.3", NPMSpec{Kind: NPMSpecRange, Range: "v1.2.3", Version: "1.2.3"}},
		{"latest", NPMSpec{Kind: NPMSpecTag, Tag: "latest"}},
		{"next", NPMSpec{Kind: NPMSpecTag, Tag: "next"}},
		{"npm:lodash@^4", NPMSpec{Kind: NPMSpecAlias, Name: "lodash", Range: "^4"}},
		{"npm:@scope/pkg@1.0.0", NPMSpec{Kind: NPMSpecAlias, Name: "@scope/pkg", Range: "1.0.0", Version: "1.0.0"}},
		{"npm:lodash", NPMSpec{Kind: NPMSpecAlias, Name: "lodash", Range: "*"}},
		{"npm:lodash@beta", NPMSpec{Kind: NPMSpecAlias, Name: "lodash", Tag: "beta"}},
		{"npm:lodash@github:u/r", NPMSpec{Kind: NPMSpecInvalid}},
		{"github:user/repo", NPMSpec{Kind: NPMSpecGit}},
		{"github:user/repo#v1.0", NPMSpec{Kind: NPMSpecGit, Ref: "v1.0"}},
		{"gitlab:user/repo", NPMSpec{Kind: NPMSpecGit}},
		{"bitbucket:user/repo", NPMSpec{Kind: NPMSpecGit}},
		{"user/repo", NPMSpec{Kind: NPMSpecGit}},
		{"user/repo#semver:^1.0", NPMSpec{Kind: NPMSpecGit, Ref: "semver:^1.0"}},
		{"git+ssh://git@github.com/user/repo.git", NPMSpec{Kind: NPMSpecGit}},
		{"git://github.com/user/repo.git#main", NPMSpec{Kind: NPMSpecGit, Ref: "main"}},
		{"git@github.com:user/repo.git", NPMSpec{Kind: NPMSpecGit}},
		{"git@gitea.example.com:team/repo.git", NPMSpec{Kind: NPMSpecGit}},
		{"https://github.com/user/repo", NPMSpec{Kind: NPMSpecGit}},
		{"https://example.com/pkg-1.0.0.tgz", NPMSpec{Kind: NPMSpecURL}},
		{"http://example.com/pkg", NPMSpec{Kind: NPMSpecURL}},
		{"file:../local", NPMSpec{Kind: NPMSpecFile}},
		{"./local", NPMSpec{Kind: NPMSpecFile}},
		{"/abs/path", NPMSpec{Kind: NPMSpecFile}},
		{"~/path", NPMSpec{Kind: NPMSpecFile}},
		{"pkg.tgz", NPMSpec{Kind: NPMSpecFile}},
		{`C:\path\to`, NPMSpec{Kind: NPMSpecFile}},
		{`..\up`, NPMSpec{Kind: NPMSpecFile}},
		{"workspace:*", NPMSpec{Kind: NPMSpecWorkspace}},
		{"workspace:^1.0.0", NPMSpec{Kind: NPMSpecWorkspace}},
		{"link:../foo", NPMSpec{Kind: NPMSpecLink}},
		{"catalog:", NPMSpec{Kind: NPMSpecInvalid}},
		{"jsr:@std/path", NPMSpec{Kind: NPMSpecInvalid}},
		{"not a valid tag!", NPMSpec{Kind: NPMSpecInvalid}},
	}
	for _, tt := range tests {
		if got := ClassifyNPMSpec(tt.in); got != tt.want {
			t.Errorf("ClassifyNPMSpec(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}
