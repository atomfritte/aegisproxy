package registry

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		eco          string
		host, path   string
		wantKind     string
		wantName     string
		wantVersion  string
	}{
		// npm
		{"npm", "registry.npmjs.org", "/lodash", KindMetadata, "lodash", ""},
		{"npm", "registry.npmjs.org", "/lodash/4.17.21", KindMetadata, "lodash", "4.17.21"},
		{"npm", "registry.npmjs.org", "/@babel%2fcore", KindMetadata, "@babel/core", ""},
		{"npm", "registry.npmjs.org", "/@babel/core", KindMetadata, "@babel/core", ""},
		{"npm", "registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz", KindArtifact, "lodash", "4.17.21"},
		{"npm", "registry.npmjs.org", "/@babel/core/-/core-7.24.0.tgz", KindArtifact, "@babel/core", "7.24.0"},
		{"npm", "registry.npmjs.org", "/-/npm/v1/keys", KindService, "", ""},
		{"npm", "registry.npmjs.org", "/-/npm/v1/attestations/lodash@4.17.21", KindService, "", ""},

		// pypi
		{"pypi", "pypi.org", "/simple/requests/", KindMetadata, "requests", ""},
		{"pypi", "pypi.org", "/simple/Flask-Login/", KindMetadata, "flask-login", ""},
		{"pypi", "pypi.org", "/pypi/requests/json", KindMetadata, "requests", ""},
		{"pypi", "pypi.org", "/pypi/requests/2.32.3/json", KindMetadata, "requests", "2.32.3"},
		{"pypi", "files.pythonhosted.org", "/packages/ab/cd/requests-2.32.3-py3-none-any.whl", KindArtifact, "", ""},
		{"pypi", "files.pythonhosted.org", "/packages/ab/cd/requests-2.32.3.tar.gz.metadata", KindService, "", ""},
		{"pypi", "pypi.org", "/integrity/requests/2.32.3/requests-2.32.3.tar.gz/provenance", KindService, "", ""},

		// nuget
		{"nuget", "api.nuget.org", "/v3-flatcontainer/newtonsoft.json/index.json", KindMetadata, "newtonsoft.json", ""},
		{"nuget", "api.nuget.org", "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", KindArtifact, "newtonsoft.json", "13.0.3"},
		{"nuget", "api.nuget.org", "/v3/registration5-gz-semver2/newtonsoft.json/index.json", KindMetadata, "newtonsoft.json", ""},
		{"nuget", "api.nuget.org", "/v3/index.json", KindService, "", ""},
		{"nuget", "api.nuget.org", "/v3/vulnerabilities/index.json", KindService, "", ""},

		// psgallery
		{"psgallery", "www.powershellgallery.com", "/api/v2/FindPackagesById()?id='PSReadLine'", KindMetadata, "psreadline", ""},
		{"psgallery", "www.powershellgallery.com", "/api/v2/package/PSReadLine/2.3.5", KindArtifact, "psreadline", "2.3.5"},
		{"psgallery", "www.powershellgallery.com", "/api/v2/$metadata", KindService, "", ""},
	}
	for _, c := range cases {
		ad := For(c.eco)
		if ad == nil {
			t.Fatalf("no adapter for %s", c.eco)
		}
		got := ad.Classify(c.host, c.path, "GET")
		if got.Kind != c.wantKind {
			t.Errorf("%s %s: kind = %q, want %q", c.eco, c.path, got.Kind, c.wantKind)
		}
		if c.wantName != "" && got.Name != c.wantName {
			t.Errorf("%s %s: name = %q, want %q", c.eco, c.path, got.Name, c.wantName)
		}
		if c.wantVersion != "" && got.Version != c.wantVersion {
			t.Errorf("%s %s: version = %q, want %q", c.eco, c.path, got.Version, c.wantVersion)
		}
	}
}

func TestClassifyNonGetIsOther(t *testing.T) {
	// Publishing / mutating a registry is never a package read.
	for _, eco := range []string{"npm", "pypi", "nuget", "psgallery"} {
		if got := For(eco).Classify("host", "/lodash", "PUT"); got.Kind != KindOther {
			t.Errorf("%s PUT should be other, got %q", eco, got.Kind)
		}
	}
}

func TestSRIToBase64(t *testing.T) {
	if got := sriToBase64("sha512-oVekP1cKtI+CTDvHWYFUcMtsK=="); got != "oVekP1cKtI+CTDvHWYFUcMtsK==" {
		t.Errorf("sriToBase64 = %q", got)
	}
	if got := sriToBase64("sha1-abc"); got != "" {
		t.Errorf("sriToBase64 of a non-sha512 = %q, want empty", got)
	}
}
