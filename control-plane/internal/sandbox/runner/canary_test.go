package runner

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecoyPlantAndMap(t *testing.T) {
	home := t.TempDir()
	d := GenerateDecoys(home)
	if err := d.Plant(); err != nil {
		t.Fatal(err)
	}
	// Files exist.
	for _, rel := range []string{".ssh/id_rsa", ".aws/credentials", ".npmrc", ".config/gcloud/application_default_credentials.json"} {
		if _, err := os.Stat(filepath.Join(home, rel)); err != nil {
			t.Errorf("decoy %s not planted: %v", rel, err)
		}
	}
	m := d.DecoyFileMap()
	if m[filepath.Join(home, ".npmrc")] != "npm-token" {
		t.Errorf("decoy map npmrc = %q", m[filepath.Join(home, ".npmrc")])
	}
	// CI persona + secret env present.
	if d.Env["CI"] != "true" || d.Env["AWS_SECRET_ACCESS_KEY"] == "" || d.Env["GITHUB_ACTIONS"] != "true" {
		t.Errorf("env persona = %v", d.Env)
	}
}

func TestCanaryEncodingsInCaptures(t *testing.T) {
	home := t.TempDir()
	d := GenerateDecoys(home)
	if err := d.Plant(); err != nil {
		t.Fatal(err)
	}
	npmrc, err := os.ReadFile(filepath.Join(home, ".npmrc"))
	if err != nil {
		t.Fatal(err)
	}
	// //registry.npmjs.org/:_authToken=<marker>
	marker := strings.TrimSpace(strings.SplitN(string(npmrc), "=", 2)[1])
	if len(marker) < 8 {
		t.Fatalf("marker too short: %q", marker)
	}

	caps := []capture{
		{where: "http", text: "GET /collect?t=" + marker + " HTTP/1.1"},                                  // raw
		{where: "dns", text: base64.StdEncoding.EncodeToString([]byte(marker)) + ".c2.test"},             // base64 label
		{where: "tcp", text: hex.EncodeToString([]byte(marker))},                                         // hex
		{where: "http", text: base64.StdEncoding.EncodeToString([]byte("prefix:" + marker + ":suffix"))}, // inside a blob
	}
	hits := d.ScanCaptures(caps)
	where := map[string]bool{}
	for _, h := range hits {
		if h.Canary == "npm-token" {
			where[h.Where] = true
		}
	}
	for _, w := range []string{"http", "dns", "tcp"} {
		if !where[w] {
			t.Errorf("missing npm-token canary hit for where=%s (hits: %+v)", w, hits)
		}
	}
}

func TestCanaryAwsSecretViaEnvMarker(t *testing.T) {
	home := t.TempDir()
	d := GenerateDecoys(home)
	secret := d.Env["AWS_SECRET_ACCESS_KEY"]
	caps := []capture{{where: "http", text: "POST body=" + secret}}
	hits := d.ScanCaptures(caps)
	found := false
	for _, h := range hits {
		if h.Canary == "aws-secret-key" && h.Where == "http" {
			found = true
		}
	}
	if !found {
		t.Errorf("aws secret env marker not detected: %+v", hits)
	}
}
