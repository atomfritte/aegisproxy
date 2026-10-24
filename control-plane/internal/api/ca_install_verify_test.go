package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/ca"
	"aegisproxy/control-plane/internal/config"
)

// The CA download is verified by fingerprint, so a tampered download must not smuggle a second root in
// next to the pinned one: the installer refuses anything but exactly one certificate and installs the
// re-encoded verified certificate, never the downloaded file. The verification block of the generated
// script runs here against crafted downloads (needs bash and openssl).
func TestLinuxInstallScriptInstallsOnlyTheVerifiedCertificate(t *testing.T) {
	for _, tool := range []string{"bash", "openssl", "grep", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := t.TempDir()
	caMgr, err := ca.NewCAManager(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ca.NewCAManager(filepath.Join(dir, "attacker"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: &config.Config{PublicURL: "https://aegis.example"}, caMgr: caMgr}
	script := s.linuxInstallScript()
	start, end := strings.Index(script, "PEM_BLOCKS="), strings.Index(script, "BUNDLE_PATH=")
	if start < 0 || end < start {
		t.Fatalf("verification block not found:\n%s", script)
	}
	if strings.Count(script, `install -m 0644 "$TMP_CA"`) != 3 || strings.Contains(script, `install -m 0644 "$DOWNLOAD"`) {
		t.Fatal("every trust store must receive the re-encoded, verified certificate only")
	}
	check := func(download []byte) (string, string, error) {
		d := t.TempDir()
		dl, out := filepath.Join(d, "download.crt"), filepath.Join(d, "verified.crt")
		if err := os.WriteFile(dl, download, 0o600); err != nil {
			t.Fatal(err)
		}
		block := "set -euo pipefail\nEXPECTED_FP='" + caMgr.Fingerprint + "'\nDOWNLOAD=" + shellQuoteSingle(dl) + "\nTMP_CA=" + shellQuoteSingle(out) + "\n" + script[start:end]
		msg, err := exec.Command("bash", "-c", block).CombinedOutput()
		got, _ := os.ReadFile(out)
		return string(msg), string(got), err
	}
	if msg, got, err := check(caMgr.CertPEM); err != nil || strings.Count(got, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("genuine CA refused: %v %s", err, msg)
	}
	for name, dl := range map[string][]byte{
		"extra root after the pinned one":  append(append([]byte{}, caMgr.CertPEM...), other.CertPEM...),
		"extra root before the pinned one": append(append([]byte{}, other.CertPEM...), caMgr.CertPEM...),
		"other CA":                         other.CertPEM,
		"DER instead of PEM":               caMgr.CertDER,
	} {
		msg, _, err := check(dl)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(msg, "SECURITY ERROR") {
			t.Errorf("%s: refused without a security error: %s", name, msg)
		}
	}
}

// The Windows installer refuses PKCS#7/PFX downloads and anything but one certificate, and adds the
// verified certificate object to the store instead of importing the downloaded file.
func TestWindowsInstallScriptAddsOnlyTheVerifiedCertificate(t *testing.T) {
	caMgr, err := ca.NewCAManager(filepath.Join(t.TempDir(), "certs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://aegis.example", "http://aegis.example:8081"} {
		s := &Server{cfg: &config.Config{PublicURL: url}, caMgr: caMgr}
		script := s.windowsInstallScript()
		if strings.Contains(script, "Import-Certificate") || !strings.Contains(script, "$store.Add($cert)") {
			t.Fatalf("%s: the downloaded file must not be imported as a whole", url)
		}
		steps := []string{"$sha.ComputeHash($bytes)", "if ($download -ne $ExpectedFingerprint)", "GetCertContentType($bytes)",
			`if ("$type" -ne 'Cert')`, "$all.Import($bytes)", "if ($all.Count -ne 1)", "if ($actual -ne $ExpectedFingerprint)", "$store.Add($cert)"}
		last := -1
		for _, step := range steps {
			i := strings.Index(script, step)
			if i <= last {
				t.Fatalf("%s: check missing or out of order: %s", url, step)
			}
			last = i
		}
		warns := strings.Contains(script, "served over plain http")
		if warns != strings.HasPrefix(url, "http://") {
			t.Errorf("%s: plain-http warning present=%v", url, warns)
		}
		if strings.Contains(script, "%!") {
			t.Errorf("%s: fmt verb error in the script template", url)
		}
	}
}

// /api/public/ca/info publishes the SHA-256 of the served CA files (Dockerfile ADD --checksum).
func TestCAInfoPublishesFileHashes(t *testing.T) {
	h := newHarness(t)
	var info map[string]any
	if err := json.NewDecoder(h.do(t, "GET", "/api/public/ca/info", nil, nil).Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	for path, field := range map[string]string{"/api/public/ca/aegis-ca.crt": "pem_sha256", "/api/public/ca/aegis-ca.pem": "pem_sha256", "/api/public/ca/aegis-ca.der": "der_sha256"} {
		b, _ := io.ReadAll(h.do(t, "GET", path, nil, nil).Body)
		sum := sha256.Sum256(b)
		if info[field] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: %s %v does not match the served file", path, field, info[field])
		}
	}
}
