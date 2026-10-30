package pkgver

import (
	"slices"
	"testing"
)

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Django", "django"},
		{"zope.interface", "zope-interface"},
		{"Foo__Bar--baz..qux", "foo-bar-baz-qux"},
		{"a_-_b", "a-b"},
		{"-foo-", "-foo-"},
		{"requests", "requests"},
		{"ÄBC_x", "äbc-x"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizePyPIName(tt.in); got != tt.want {
			t.Errorf("NormalizePyPIName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseWheelFilename(t *testing.T) {
	tests := []struct {
		in   string
		want Wheel
	}{
		{"requests-2.32.3-py3-none-any.whl", Wheel{Name: "requests", Version: "2.32.3", PythonTags: []string{"py3"},
			ABITags: []string{"none"}, PlatformTags: []string{"any"}}},
		{"Foo_Bar-1.0-1abc-py2.py3-none-any.whl", Wheel{Name: "foo-bar", Version: "1.0", Build: "1abc",
			PythonTags: []string{"py2", "py3"}, ABITags: []string{"none"}, PlatformTags: []string{"any"}}},
		{"numpy-2.1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", Wheel{Name: "numpy",
			Version: "2.1.0", PythonTags: []string{"cp312"}, ABITags: []string{"cp312"},
			PlatformTags: []string{"manylinux_2_17_x86_64", "manylinux2014_x86_64"}}},
		{"pkg-V1.0RC1-CP312-ABI3-WIN_AMD64.whl", Wheel{Name: "pkg", Version: "1.0rc1", PythonTags: []string{"cp312"},
			ABITags: []string{"abi3"}, PlatformTags: []string{"win_amd64"}}},
	}
	for _, tt := range tests {
		got, err := ParseWheelFilename(tt.in)
		if err != nil || got.Name != tt.want.Name || got.Version != tt.want.Version || got.Build != tt.want.Build ||
			!slices.Equal(got.PythonTags, tt.want.PythonTags) || !slices.Equal(got.ABITags, tt.want.ABITags) ||
			!slices.Equal(got.PlatformTags, tt.want.PlatformTags) {
			t.Errorf("ParseWheelFilename(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"foo-1.0-py3-none-any", "foo-1.0-py3-none.whl", "foo-bar-1.0-py3-none-any.whl",
		"foo__bar-1.0-py3-none-any.whl", "foo-1.0-abc-py3-none-any.whl", "foo-x.y-py3-none-any.whl",
		"foo-1.0-3py-none-any.whl", "foo-1.0-py3..py2-none-any.whl", "-1.0-py3-none-any.whl", "foo-1.0-py3-none-any.WHL"} {
		if w, err := ParseWheelFilename(bad); err == nil {
			t.Errorf("ParseWheelFilename(%q) = %+v, want error", bad, w)
		}
	}
}

func TestParseSdistFilename(t *testing.T) {
	tests := []struct {
		fn, project, want string
		ok                bool
	}{
		{"foo-1.0.tar.gz", "foo", "1.0", true},
		{"foo-1.0.tar.gz", "", "1.0", true},
		{"foo-bar-1.0-2.tar.gz", "foo-bar", "1.0.post2", true}, // legacy dashes in the version
		{"foo-bar-1.0.tar.gz", "", "1.0", true},
		{"foo_bar-1.0rc1.zip", "Foo.Bar", "1.0rc1", true},
		{"Foo-1.0.ZIP", "foo", "1.0", true},
		{"foo-1.0.tar.bz2", "foo", "1.0", true},
		{"foo-1.0.tgz", "foo", "1.0", true},
		{"foo-bar-1.0.tar.gz", "foo", "", false}, // another project's file
		{"foo-1.0.tar.gz", "bar", "", false},
		{"foo-1.0.exe", "foo", "", false},
		{"foo.tar.gz", "", "", false},
		{"-1.0.tar.gz", "", "", false},
		{"foo-.tar.gz", "foo", "", false},
	}
	for _, tt := range tests {
		got, ok := ParseSdistFilename(tt.fn, tt.project)
		if got != tt.want || ok != tt.ok {
			t.Errorf("ParseSdistFilename(%q, %q) = %q, %v; want %q, %v", tt.fn, tt.project, got, ok, tt.want, tt.ok)
		}
	}
}

func TestPyPIFileVersion(t *testing.T) {
	tests := []struct {
		fn, project, want string
		ok                bool
	}{
		{"requests-2.32.3-py3-none-any.whl", "requests", "2.32.3", true},
		{"requests-2.32.3-py3-none-any.whl", "", "2.32.3", true},
		{"requests-2.32.3-py3-none-any.whl", "other", "", false},
		{"Requests-2.32.3.tar.gz", "requests", "2.32.3", true},
		{"zope.interface-6.0-cp312-cp312-win_amd64.whl", "Zope_Interface", "6.0", true},
		{"requests-2.32.3-py3-none-any.whl.metadata", "requests", "", false},
		{"README.md", "requests", "", false},
	}
	for _, tt := range tests {
		got, ok := PyPIFileVersion(tt.fn, tt.project)
		if got != tt.want || ok != tt.ok {
			t.Errorf("PyPIFileVersion(%q, %q) = %q, %v; want %q, %v", tt.fn, tt.project, got, ok, tt.want, tt.ok)
		}
	}
}
