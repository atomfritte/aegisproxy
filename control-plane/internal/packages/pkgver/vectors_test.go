package pkgver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The testdata/*.json vectors are generated from the reference implementations by the programs in
// testdata/gen (node-semver and npm-package-arg, pypa/packaging, NuGet.Versioning).

func loadVectors(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func bit(b bool) byte {
	if b {
		return '1'
	}
	return '0'
}

func checkMatrix[V any](t *testing.T, versions []string, matrix []string, parse func(string) (V, error),
	cmp func(V, V) int) {
	t.Helper()
	parsed := make([]V, len(versions))
	for i, s := range versions {
		v, err := parse(s)
		if err != nil {
			t.Fatalf("parse(%q): %v", s, err)
		}
		parsed[i] = v
	}
	for i := range parsed {
		for j := range parsed {
			if got, want := "<=>"[cmp(parsed[i], parsed[j])+1], matrix[i][j]; got != want {
				t.Errorf("compare(%q, %q) = %c, want %c", versions[i], versions[j], got, want)
			}
		}
	}
}

type npmVectors struct {
	Generator string `json:"generator"`
	Versions  []struct {
		In    string  `json:"in"`
		Clean *string `json:"clean"`
	} `json:"versions"`
	CompareVersions []string `json:"compareVersions"`
	CompareMatrix   []string `json:"compareMatrix"`
	Pool            []string `json:"pool"`
	Ranges          []struct {
		In     string  `json:"in"`
		Valid  *string `json:"valid"`
		Sat    string  `json:"sat"`
		SatPre string  `json:"satPre"`
		Max    *string `json:"max"`
	} `json:"ranges"`
	Specs []struct {
		In         string `json:"in"`
		Type       string `json:"type"`
		Name       string `json:"name"`
		Sub        string `json:"sub"`
		SubSpec    string `json:"subSpec"`
		Committish string `json:"committish"`
		Error      string `json:"error"`
	} `json:"specs"`
}

func TestNPMVectors(t *testing.T) {
	var vec npmVectors
	loadVectors(t, "npm.json", &vec)
	t.Log(vec.Generator)

	t.Run("clean", func(t *testing.T) {
		for _, c := range vec.Versions {
			v, err := ParseNPM(c.In)
			switch {
			case c.Clean == nil && err == nil:
				t.Errorf("ParseNPM(%q) = %v, want error", c.In, v)
			case c.Clean != nil && err != nil:
				t.Errorf("ParseNPM(%q): %v, want %s", c.In, err, *c.Clean)
			case c.Clean != nil && v.String() != *c.Clean:
				t.Errorf("ParseNPM(%q) = %s, want %s", c.In, v, *c.Clean)
			}
		}
	})
	t.Run("compare", func(t *testing.T) {
		checkMatrix(t, vec.CompareVersions, vec.CompareMatrix, ParseNPM, NPMVersion.Compare)
	})
	t.Run("ranges", func(t *testing.T) {
		pool := make([]NPMVersion, len(vec.Pool))
		for i, s := range vec.Pool {
			pool[i], _ = ParseNPM(s)
		}
		for _, c := range vec.Ranges {
			r, err := ParseNPMRange(c.In)
			if c.Valid == nil {
				if err == nil {
					t.Errorf("ParseNPMRange(%q) = %q, want error", c.In, r)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseNPMRange(%q): %v, want %q", c.In, err, *c.Valid)
				continue
			}
			if r.String() != *c.Valid {
				t.Errorf("ParseNPMRange(%q) = %q, want %q", c.In, r, *c.Valid)
			}
			var sat, satPre []byte
			for _, v := range pool {
				sat, satPre = append(sat, bit(r.Contains(v, false))), append(satPre, bit(r.Contains(v, true)))
			}
			for i := range pool {
				if sat[i] != c.Sat[i] {
					t.Errorf("%q Contains(%s, false) = %c, want %c", c.In, vec.Pool[i], sat[i], c.Sat[i])
				}
				if satPre[i] != c.SatPre[i] {
					t.Errorf("%q Contains(%s, true) = %c, want %c", c.In, vec.Pool[i], satPre[i], c.SatPre[i])
				}
			}
			got, ok := MaxSatisfyingNPM(vec.Pool, c.In)
			if want := c.Max; (want == nil) == ok || (ok && got != *want) {
				t.Errorf("MaxSatisfyingNPM(%q) = %q, %v, want %v", c.In, got, ok, deref(want))
			}
		}
	})
	t.Run("specs", func(t *testing.T) {
		// Deliberate differences: scp-like git URLs of any host and Windows paths are recognized on every OS.
		deviations := map[string]string{
			"git@example.com:user/repo.git": NPMSpecGit,
			`\\server\share`:                NPMSpecFile,
			"workspace:*":                   NPMSpecWorkspace,
			"workspace:^1.0.0":              NPMSpecWorkspace,
			"link:../foo":                   NPMSpecLink,
		}
		kinds := map[string]string{
			"version": NPMSpecRange, "range": NPMSpecRange, "tag": NPMSpecTag, "alias": NPMSpecAlias,
			"git": NPMSpecGit, "remote": NPMSpecURL, "file": NPMSpecFile, "directory": NPMSpecFile,
		}
		for _, c := range vec.Specs {
			got := ClassifyNPMSpec(c.In)
			want, ok := deviations[c.In]
			if !ok {
				want = kinds[c.Type]
				if c.Error != "" {
					want = NPMSpecInvalid
				}
			}
			if got.Kind != want {
				t.Errorf("ClassifyNPMSpec(%q).Kind = %s, want %s (npa: %s%s)", c.In, got.Kind, want, c.Type, c.Error)
				continue
			}
			switch got.Kind {
			case NPMSpecAlias:
				spec := got.Range
				if got.Tag != "" {
					spec = got.Tag
				}
				if got.Name != c.Name || spec != c.SubSpec || (got.Tag != "") != (c.Sub == "tag") {
					t.Errorf("ClassifyNPMSpec(%q) = %+v, want alias of %s@%s (%s)", c.In, got, c.Name, c.SubSpec, c.Sub)
				}
			case NPMSpecGit:
				if c.Type == "git" && got.Ref != c.Committish {
					t.Errorf("ClassifyNPMSpec(%q).Ref = %q, want %q", c.In, got.Ref, c.Committish)
				}
			case NPMSpecRange:
				if (got.Version != "") != (c.Type == "version") {
					t.Errorf("ClassifyNPMSpec(%q).Version = %q, npa type %s", c.In, got.Version, c.Type)
				}
			}
		}
	})
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return strconv.Quote(*s)
}

type pypiVectors struct {
	Generator string `json:"generator"`
	Versions  []struct {
		In      string        `json:"in"`
		Norm    *string       `json:"norm"`
		Pre     bool          `json:"pre"`
		Post    bool          `json:"post"`
		Epoch   int           `json:"epoch"`
		Release []json.Number `json:"release"`
		Local   *string       `json:"local"`
		Public  string        `json:"public"`
	} `json:"versions"`
	CompareVersions []string `json:"compareVersions"`
	CompareMatrix   []string `json:"compareMatrix"`
	Pool            []string `json:"pool"`
	Specifiers      []struct {
		In          string `json:"in"`
		Valid       bool   `json:"valid"`
		Str         string `json:"str"`
		Prereleases bool   `json:"prereleases"`
		Contains    string `json:"contains"`
		ContainsPre string `json:"containsPre"`
		Filter      []int  `json:"filter"`
	} `json:"specifiers"`
	Envs    []map[string]string `json:"envs"`
	Markers []struct {
		In    string  `json:"in"`
		Valid bool    `json:"valid"`
		Str   string  `json:"str"`
		Eval  []*bool `json:"eval"`
	} `json:"markers"`
	Requirements []struct {
		In        string   `json:"in"`
		Valid     bool     `json:"valid"`
		Name      string   `json:"name"`
		Extras    []string `json:"extras"`
		Specifier string   `json:"specifier"`
		URL       string   `json:"url"`
		Marker    string   `json:"marker"`
	} `json:"requirements"`
	Wheels []struct {
		In      string   `json:"in"`
		Valid   bool     `json:"valid"`
		Name    string   `json:"name"`
		Version string   `json:"version"`
		Build   []any    `json:"build"`
		Tags    []string `json:"tags"`
	} `json:"wheels"`
	Sdists []struct {
		In      string `json:"in"`
		Valid   bool   `json:"valid"`
		Version string `json:"version"`
	} `json:"sdists"`
}

func TestPyPIVectors(t *testing.T) {
	var vec pypiVectors
	loadVectors(t, "pypi.json", &vec)
	t.Log(vec.Generator)

	t.Run("versions", func(t *testing.T) {
		for _, c := range vec.Versions {
			v, err := ParsePEP440(c.In)
			if c.Norm == nil {
				if err == nil {
					t.Errorf("ParsePEP440(%q) = %s, want error", c.In, v)
				}
				continue
			}
			if err != nil {
				// Deliberate difference: numeric components must fit into an int.
				if !slices.ContainsFunc(c.Release, func(n json.Number) bool { _, err := n.Int64(); return err != nil }) {
					t.Errorf("ParsePEP440(%q): %v, want %s", c.In, err, *c.Norm)
				}
				continue
			}
			var release []json.Number
			for _, n := range v.Release() {
				release = append(release, json.Number(strconv.Itoa(n)))
			}
			if v.String() != *c.Norm || v.IsPrerelease() != c.Pre || v.IsPostrelease() != c.Post ||
				v.Epoch() != c.Epoch || !slices.Equal(release, c.Release) || v.Local() != (c.Local != nil) ||
				v.Public().String() != c.Public {
				t.Errorf("ParsePEP440(%q) = %s pre=%v post=%v epoch=%d release=%v local=%v public=%s, want %+v",
					c.In, v, v.IsPrerelease(), v.IsPostrelease(), v.Epoch(), v.Release(), v.Local(), v.Public(), c)
			}
		}
	})
	t.Run("compare", func(t *testing.T) {
		checkMatrix(t, vec.CompareVersions, vec.CompareMatrix, ParsePEP440, PEP440Version.Compare)
	})
	t.Run("specifiers", func(t *testing.T) {
		pool := make([]PEP440Version, len(vec.Pool))
		for i, s := range vec.Pool {
			pool[i], _ = ParsePEP440(s)
		}
		for _, c := range vec.Specifiers {
			set, err := ParseSpecifierSet(c.In)
			if !c.Valid {
				if err == nil {
					t.Errorf("ParseSpecifierSet(%q) = %q, want error", c.In, set)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseSpecifierSet(%q): %v", c.In, err)
				continue
			}
			if set.String() != c.Str || set.AllowsPrereleases() != c.Prereleases {
				t.Errorf("ParseSpecifierSet(%q) = %q prereleases=%v, want %q %v", c.In, set,
					set.AllowsPrereleases(), c.Str, c.Prereleases)
			}
			for i, v := range pool {
				if got := bit(set.Contains(v, false)); got != c.Contains[i] {
					t.Errorf("%q Contains(%s, false) = %c, want %c", c.In, vec.Pool[i], got, c.Contains[i])
				}
				if got := bit(set.Contains(v, true)); got != c.ContainsPre[i] {
					t.Errorf("%q Contains(%s, true) = %c, want %c", c.In, vec.Pool[i], got, c.ContainsPre[i])
				}
			}
			var want []string
			for _, i := range c.Filter {
				want = append(want, vec.Pool[i])
			}
			if got := Filter(vec.Pool, set); !slices.Equal(got, want) {
				t.Errorf("Filter(pool, %q) = %v, want %v", c.In, got, want)
			}
		}
	})
	t.Run("markers", func(t *testing.T) {
		for _, c := range vec.Markers {
			m, err := ParseMarker(c.In)
			if !c.Valid {
				if err == nil {
					t.Errorf("ParseMarker(%q) = %q, want error", c.In, m)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseMarker(%q): %v", c.In, err)
				continue
			}
			// packaging prints values verbatim even when they cannot be read back; pkgver escapes them.
			if !strings.ContainsAny(c.Str, "\\\n") && m.String() != c.Str {
				t.Errorf("ParseMarker(%q) = %q, want %q", c.In, m, c.Str)
			}
			for i, env := range vec.Envs {
				want := c.Eval[i] != nil && *c.Eval[i] // undefined comparisons are false
				if got := m.Evaluate(env); got != want {
					t.Errorf("ParseMarker(%q).Evaluate(env %d) = %v, want %v", c.In, i, got, want)
				}
			}
		}
	})
	t.Run("requirements", func(t *testing.T) {
		for _, c := range vec.Requirements {
			r, err := ParseRequirement(c.In)
			if !c.Valid {
				if err == nil {
					t.Errorf("ParseRequirement(%q) = %q, want error", c.In, r)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseRequirement(%q): %v", c.In, err)
				continue
			}
			if r.Name != c.Name || !slices.Equal(r.Extras, c.Extras) && len(r.Extras)+len(c.Extras) > 0 ||
				r.Specifier != c.Specifier || r.URL != c.URL || r.Marker != c.Marker {
				t.Errorf("ParseRequirement(%q) = %+v, want %+v", c.In, r, c)
			}
		}
	})
	t.Run("wheels", func(t *testing.T) {
		for _, c := range vec.Wheels {
			w, err := ParseWheelFilename(c.In)
			if !c.Valid {
				if err == nil {
					t.Errorf("ParseWheelFilename(%q) = %+v, want error", c.In, w)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseWheelFilename(%q): %v", c.In, err)
				continue
			}
			build := ""
			if len(c.Build) == 2 {
				build = strconv.Itoa(int(c.Build[0].(float64))) + c.Build[1].(string)
			}
			var tags []string
			for _, py := range w.PythonTags {
				for _, abi := range w.ABITags {
					for _, plat := range w.PlatformTags {
						tags = append(tags, py+"-"+abi+"-"+plat)
					}
				}
			}
			slices.Sort(tags)
			gotBuild := w.Build
			if gotBuild != "" {
				n := len(gotBuild) - len(strings.TrimLeft(gotBuild, "0123456789"))
				x, _ := strconv.Atoi(gotBuild[:n])
				gotBuild = strconv.Itoa(x) + gotBuild[n:]
			}
			if w.Name != c.Name || w.Version != c.Version || gotBuild != build || !slices.Equal(tags, c.Tags) {
				t.Errorf("ParseWheelFilename(%q) = %+v, want %+v", c.In, w, c)
			}
		}
	})
	t.Run("sdists", func(t *testing.T) {
		for _, c := range vec.Sdists {
			v, ok := ParseSdistFilename(c.In, "")
			legacy := false // archive types packaging no longer parses
			for _, ext := range sdistExtensions[2:] {
				legacy = legacy || strings.HasSuffix(strings.ToLower(c.In), ext)
			}
			legacy = legacy || strings.HasSuffix(c.In, ".TAR.GZ")
			switch {
			case c.Valid && (!ok || v != c.Version):
				t.Errorf("ParseSdistFilename(%q) = %q, %v, want %q", c.In, v, ok, c.Version)
			case !c.Valid && ok && !legacy:
				t.Errorf("ParseSdistFilename(%q) = %q, want not ok", c.In, v)
			}
		}
	})
}

type nugetVectors struct {
	Generator string `json:"generator"`
	Versions  []struct {
		In   string  `json:"in"`
		Norm *string `json:"norm"`
		Full string  `json:"full"`
		Pre  bool    `json:"pre"`
	} `json:"versions"`
	CompareVersions []string   `json:"compareVersions"`
	CompareMatrix   []string   `json:"compareMatrix"`
	Pool            []string   `json:"pool"`
	MatchPools      [][]string `json:"matchPools"`
	Ranges          []struct {
		In          string    `json:"in"`
		Norm        *string   `json:"norm"`
		Floating    bool      `json:"floating"`
		Contains    string    `json:"contains"`
		ContainsPre string    `json:"containsPre"`
		Best        []*string `json:"best"`
	} `json:"ranges"`
}

func TestNuGetVectors(t *testing.T) {
	var vec nugetVectors
	loadVectors(t, "nuget.json", &vec)
	t.Log(vec.Generator)

	t.Run("versions", func(t *testing.T) {
		for _, c := range vec.Versions {
			v, err := ParseNuGet(c.In)
			if c.Norm == nil {
				if err == nil {
					t.Errorf("ParseNuGet(%q) = %s, want error", c.In, v)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseNuGet(%q): %v, want %s", c.In, err, *c.Norm)
				continue
			}
			full := v.Normalize()
			if v.Metadata() != "" {
				full += "+" + v.Metadata()
			}
			if v.Normalize() != *c.Norm || full != c.Full || v.IsPrerelease() != c.Pre {
				t.Errorf("ParseNuGet(%q) = %s (%s, pre=%v), want %s (%s, pre=%v)", c.In, v, full, v.IsPrerelease(),
					*c.Norm, c.Full, c.Pre)
			}
		}
	})
	t.Run("compare", func(t *testing.T) {
		checkMatrix(t, vec.CompareVersions, vec.CompareMatrix, ParseNuGet, NuGetVersion.Compare)
	})
	t.Run("ranges", func(t *testing.T) {
		pool := make([]NuGetVersion, len(vec.Pool))
		for i, s := range vec.Pool {
			pool[i], _ = ParseNuGet(s)
		}
		for _, c := range vec.Ranges {
			r, err := ParseNuGetRange(c.In)
			if c.Norm == nil {
				// Deliberate difference: an empty range is the range of all versions (an omitted nuspec version).
				if strings.TrimSpace(c.In) == "" {
					if err != nil || r.String() != "(, )" {
						t.Errorf("ParseNuGetRange(%q) = %q, %v, want all versions", c.In, r, err)
					}
				} else if err == nil {
					t.Errorf("ParseNuGetRange(%q) = %q, want error", c.In, r)
				}
				continue
			}
			if err != nil {
				t.Errorf("ParseNuGetRange(%q): %v, want %s", c.In, err, *c.Norm)
				continue
			}
			if r.String() != *c.Norm || r.IsFloating() != c.Floating {
				t.Errorf("ParseNuGetRange(%q) = %q floating=%v, want %q %v", c.In, r, r.IsFloating(), *c.Norm, c.Floating)
			}
			for i, v := range pool {
				if got := bit(r.Contains(v, false)); got != c.Contains[i] {
					t.Errorf("%q Contains(%s, false) = %c, want %c", c.In, vec.Pool[i], got, c.Contains[i])
				}
				if got := bit(r.Contains(v, true)); got != c.ContainsPre[i] {
					t.Errorf("%q Contains(%s, true) = %c, want %c", c.In, vec.Pool[i], got, c.ContainsPre[i])
				}
			}
			for i, versions := range vec.MatchPools {
				got, ok := BestMatch(versions, r)
				if want := c.Best[i]; (want == nil) == ok || (ok && got != *want) {
					t.Errorf("BestMatch(%v, %q) = %q, %v, want %s", versions, c.In, got, ok, deref(want))
				}
			}
		}
	})
}
