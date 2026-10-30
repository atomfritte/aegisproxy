package pkgver

import (
	"strconv"
	"testing"
)

// benchVersions returns n release versions with some pre-releases, the shape of a large registry packument.
func benchVersions(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		v := strconv.Itoa(i/100) + "." + strconv.Itoa(i/10%10) + "." + strconv.Itoa(i%10)
		if i%7 == 0 {
			v += "-rc." + strconv.Itoa(i%3)
		}
		out = append(out, v)
	}
	return out
}

func BenchmarkParseNPMRangeCached(b *testing.B) {
	for b.Loop() {
		if _, err := ParseNPMRange("^1.2.3 || >=2.0.0-beta <3"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseNPMRangeUncached(b *testing.B) {
	for b.Loop() {
		if _, err := parseNPMSets("^1.2.3 || >=2.0.0-beta <3", false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaxSatisfyingNPM(b *testing.B) {
	versions := benchVersions(500)
	for b.Loop() {
		if _, ok := MaxSatisfyingNPM(versions, "^3.1.0"); !ok {
			b.Fatal("no match")
		}
	}
}

func BenchmarkPyPIMaxSatisfying(b *testing.B) {
	versions := benchVersions(500)
	for b.Loop() {
		if _, ok := MaxSatisfying(ecoPyPI, versions, ">=3.1,<4,!=3.5.*"); !ok {
			b.Fatal("no match")
		}
	}
}

func BenchmarkNuGetBestMatch(b *testing.B) {
	versions := benchVersions(500)
	r, err := ParseNuGetRange("[3.1.0, 4.0.0)")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, ok := BestMatch(versions, r); !ok {
			b.Fatal("no match")
		}
	}
}

func BenchmarkParseRequirement(b *testing.B) {
	for b.Loop() {
		if _, err := ParseRequirement(`requests[socks]>=2.8.1,<3; python_version >= "3.8" and sys_platform != "win32"`); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchPackagePattern(b *testing.B) {
	for b.Loop() {
		MatchPackagePattern("@company/*-internal-?", "@company/some-long-package-name-internal-x", ecoNPM)
	}
}
