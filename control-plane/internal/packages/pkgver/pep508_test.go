package pkgver

import (
	"slices"
	"testing"
)

func TestParseRequirement(t *testing.T) {
	tests := []struct {
		in   string
		want Requirement
		str  string
	}{
		{"requests", Requirement{Name: "requests"}, "requests"},
		{"Requests_OAuthlib>=1.0", Requirement{Name: "requests-oauthlib", Specifier: ">=1.0"}, "requests-oauthlib>=1.0"},
		{"name (>=1.0, <2)", Requirement{Name: "name", Specifier: "<2,>=1.0"}, "name<2,>=1.0"},
		{"name[Bar_Baz, foo,bar-baz]>=3", Requirement{Name: "name", Extras: []string{"bar-baz", "foo"}, Specifier: ">=3"},
			"name[bar-baz,foo]>=3"},
		{`requests[socks] (>=2.8.1,<3) ; python_version < "3.9"`, Requirement{Name: "requests", Extras: []string{"socks"},
			Specifier: "<3,>=2.8.1", Marker: `python_version < "3.9"`}, `requests[socks]<3,>=2.8.1; python_version < "3.9"`},
		{"name @ https://example.com/name-1.0.whl", Requirement{Name: "name", URL: "https://example.com/name-1.0.whl"},
			"name @ https://example.com/name-1.0.whl"},
		{"name@ file:///tmp/x ; os_name == 'nt'", Requirement{Name: "name", URL: "file:///tmp/x", Marker: `os_name == "nt"`},
			`name @ file:///tmp/x ; os_name == "nt"`},
		{`name; extra == "Security_Extra"`, Requirement{Name: "name", Marker: `extra == "security-extra"`},
			`name; extra == "security-extra"`},
		{"name===1.0.local", Requirement{Name: "name", Specifier: "===1.0.local"}, "name===1.0.local"},
		{"  name  ", Requirement{Name: "name"}, "name"},
	}
	for _, tt := range tests {
		r, err := ParseRequirement(tt.in)
		if err != nil {
			t.Errorf("ParseRequirement(%q): %v", tt.in, err)
			continue
		}
		if r.Name != tt.want.Name || !slices.Equal(r.Extras, tt.want.Extras) || r.Specifier != tt.want.Specifier ||
			r.URL != tt.want.URL || r.Marker != tt.want.Marker || r.String() != tt.str {
			t.Errorf("ParseRequirement(%q) = %+v %q, want %+v %q", tt.in, r, r, tt.want, tt.str)
		}
		if r.SpecifierSet().String() != r.Specifier || r.ParsedMarker().String() != r.Marker {
			t.Errorf("ParseRequirement(%q): parsed specifier %q / marker %q", tt.in, r.SpecifierSet(), r.ParsedMarker())
		}
	}
	for _, bad := range []string{"", "-name", "name[", "name[bar", "name>=1.0)", "name (>=1.0", "name ==1.0.*+local",
		"name<=1.0.*", "name 1.0", "name>=1.0 <2", "name @ ", "name @ http://x ;", "name; ", "name; foo == 'x'",
		"name==1.0.org1", "name[a b]", "näme"} {
		if r, err := ParseRequirement(bad); err == nil {
			t.Errorf("ParseRequirement(%q) = %q, want error", bad, r)
		}
	}
}

func TestRequirementWithoutParse(t *testing.T) {
	// A Requirement built by hand (e.g. decoded from JSON) parses its strings on demand.
	r := Requirement{Name: "x", Specifier: ">=1.0", Marker: `os_name == "nt"`}
	v, _ := ParsePEP440("1.5")
	if !r.SpecifierSet().Contains(v, false) {
		t.Error("SpecifierSet of a hand-built Requirement does not match")
	}
	if !r.ParsedMarker().Evaluate(map[string]string{"os_name": "nt"}) {
		t.Error("ParsedMarker of a hand-built Requirement does not match")
	}
	if (Requirement{}).ParsedMarker() != nil {
		t.Error("empty marker is not nil")
	}
}

func TestMarkerEvaluate(t *testing.T) {
	linux := DefaultPythonEnvironments()[0]
	tests := []struct {
		marker string
		env    map[string]string
		want   bool
	}{
		{`python_version >= "3.8"`, linux, true},
		{`python_version < "3.12"`, linux, false},
		{`python_version > "3.12.0"`, linux, false}, // 3.12 == 3.12.0
		{`python_full_version >= "3.12.0rc1"`, linux, true},
		{`"3.8" <= python_version`, linux, true},
		{`os_name == "posix" and sys_platform == "linux"`, linux, true},
		{`os_name == "nt" or (sys_platform == "linux" and platform_machine == "x86_64")`, linux, true},
		{`os_name == "nt" or sys_platform == "linux" and platform_machine == "aarch64"`, linux, false},
		{`platform_system == "Windows"`, linux, false},
		{`"linux" in sys_platform`, linux, true},
		{`"x86" not in platform_machine`, linux, false},
		{`os_name < "posix"`, linux, false}, // ordering on strings is undefined
		{`os_name <= "posix"`, linux, true},
		{`os_name ~= "posix"`, linux, false},
		{`platform_release >= "6"`, linux, true},
		{`platform_release > "5.15.0-generic"`, linux, false},
		{`extra == "security"`, linux, false},
		{`extra == "Security"`, map[string]string{"extra": "SECURITY"}, true},
		{`"tests" == extra`, map[string]string{"extra": "tests"}, true},
		{`extra == "a.b_c"`, map[string]string{"extra": "A-B-C"}, true},
		{`"a" in extras`, map[string]string{"extras": "b, A"}, true},
		{`"a" not in dependency_groups`, map[string]string{"dependency_groups": "test"}, true},
		{`extras == "a"`, map[string]string{"extras": "a"}, false},
		{`python_full_version == "3.13.0+local"`, map[string]string{"python_full_version": "3.13.0+"}, true},
		{`implementation_name == "cpython"`, nil, false},
		{`python_version == python_version`, linux, false}, // packaging takes the right side literally
		{`"3.12" == "python_version"`, linux, true},
		{`"3.12" == "3.12"`, linux, false}, // UndefinedEnvironmentName
	}
	for _, tt := range tests {
		m, err := ParseMarker(tt.marker)
		if err != nil {
			t.Errorf("ParseMarker(%q): %v", tt.marker, err)
			continue
		}
		if got := m.Evaluate(tt.env); got != tt.want {
			t.Errorf("ParseMarker(%q).Evaluate = %v, want %v", tt.marker, got, tt.want)
		}
	}
	var nilMarker *Marker
	if !nilMarker.Evaluate(nil) || nilMarker.String() != "" {
		t.Error("nil marker is not the always-true empty marker")
	}
}

func TestMarkerString(t *testing.T) {
	tests := []struct{ in, want string }{
		{`os_name=='nt'`, `os_name == "nt"`},
		{`os.name == "nt" and sys.platform=="win32"`, `os_name == "nt" and sys_platform == "win32"`},
		{`((os_name == "nt"))`, `os_name == "nt"`},
		{`os_name == "a" and (os_name == "b" or os_name == "c")`, `os_name == "a" and (os_name == "b" or os_name == "c")`},
		{`(os_name == "a" and os_name == "b") or os_name == "c"`, `(os_name == "a" and os_name == "b") or os_name == "c"`},
		{`os_name == "a" and ((os_name == "b" or os_name == "c"))`, `os_name == "a" and (os_name == "b" or os_name == "c")`},
		{`os_name == 'say "hi"'`, `os_name == 'say "hi"'`},
		{`python_version not   in "3.8 3.9"`, `python_version not in "3.8 3.9"`},
		{`extra == "Foo.Bar"`, `extra == "foo-bar"`},
		{`"A_b" in extras`, `"a-b" in extras`},
		{`os_name == "a\\b"`, `os_name == "a\\b"`},
		{`os_name == "\x41\n"`, `os_name == "A\x0a"`},
	}
	for _, tt := range tests {
		m, err := ParseMarker(tt.in)
		if err != nil || m.String() != tt.want {
			t.Errorf("ParseMarker(%q) = %q, %v; want %q", tt.in, m, err, tt.want)
			continue
		}
		if again, err := ParseMarker(m.String()); err != nil || again.String() != m.String() {
			t.Errorf("ParseMarker(%q) does not round-trip: %q, %v", m, again, err)
		}
	}
}

func TestMarkerMatchesAny(t *testing.T) {
	tests := []struct {
		marker string
		envs   []map[string]string
		want   bool
	}{
		{"", nil, true},
		{"   ", nil, true},
		{"not a marker", nil, true}, // fail-open; the artifact is still pinned
		{`sys_platform == "win32"`, nil, true},
		{`platform_machine == "aarch64" and sys_platform == "linux"`, nil, true},
		{`sys_platform == "darwin" and platform_machine == "x86_64"`, nil, false},
		{`python_version < "3"`, nil, false},
		{`extra == "test"`, nil, false},
		{`extra == "test"`, []map[string]string{{"extra": "test"}}, true},
		{`os_name == "java"`, []map[string]string{{"os_name": "posix"}, {"os_name": "java"}}, true},
	}
	for _, tt := range tests {
		if got := MarkerMatchesAny(tt.marker, tt.envs); got != tt.want {
			t.Errorf("MarkerMatchesAny(%q, %v) = %v, want %v", tt.marker, tt.envs, got, tt.want)
		}
	}
}

func TestDefaultPythonEnvironments(t *testing.T) {
	envs := DefaultPythonEnvironments()
	if len(envs) != 4 {
		t.Fatalf("%d environments", len(envs))
	}
	for _, env := range envs {
		for _, k := range []string{"implementation_name", "implementation_version", "os_name", "platform_machine",
			"platform_python_implementation", "platform_release", "platform_system", "platform_version",
			"python_full_version", "python_version", "sys_platform"} {
			if env[k] == "" {
				t.Errorf("environment %v lacks %s", env, k)
			}
		}
	}
	envs[0]["os_name"] = "changed"
	if DefaultPythonEnvironments()[0]["os_name"] != "posix" {
		t.Error("DefaultPythonEnvironments shares its maps")
	}
}

func TestDecodePyString(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{`plain`, "plain", true},
		{`a\\b`, `a\b`, true},
		{`\x41é\U0001F600\101\0`, "Aé😀A\x00", true},
		{`\n\t\r\a\b\f\v`, "\n\t\r\a\b\f\v", true},
		{`\q`, `\q`, true},
		{`\x4`, "", false},
		{`\u12`, "", false},
		{`\U0011ffff`, "", false},
		{`\N{DASH}`, "", false},
		{`trailing\`, "", false},
		{"line\nbreak", "", false},
	}
	for _, tt := range tests {
		got, err := decodePyString(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("decodePyString(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}
