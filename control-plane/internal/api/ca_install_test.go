package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/ca"
	"aegisproxy/control-plane/internal/config"
	"aegisproxy/control-plane/internal/models"
)

// The console hands out install commands that check the installer against its SHA-256 before it runs
// with root/administrator rights. The published hash must match the served bytes exactly, and no
// command pipes a downloaded script into a shell.
func TestCAInstallCommandsVerifyScriptHash(t *testing.T) {
	h := newHarness(t)
	resp := h.do(t, "GET", "/api/public/ca/info", nil, nil)
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	for path, kind := range map[string]string{"/api/public/ca/install-linux.sh": "linux", "/api/public/ca/install-windows.ps1": "windows"} {
		b, _ := io.ReadAll(h.do(t, "GET", path, nil, nil).Body)
		sum := sha256.Sum256(b)
		want := hex.EncodeToString(sum[:])
		if info[kind+"_script_sha256"] != want {
			t.Errorf("%s: published SHA-256 %v, served script hashes to %s", kind, info[kind+"_script_sha256"], want)
		}
		cmd, _ := info[kind+"_command"].(string)
		if !strings.Contains(cmd, want) || !strings.Contains(cmd, path) || strings.Contains(cmd, "| sudo") || strings.Contains(cmd, "iex") {
			t.Errorf("%s command does not verify the script before running it: %s", kind, cmd)
		}
		if strings.Contains(string(b), "WARNING: AEGIS_PUBLIC_URL uses plain http") {
			t.Errorf("%s: http warning in an https deployment", kind)
		}
	}

	ob := h.srvOnboarding(t)
	if !strings.Contains(ob["linux"], "sha256sum -c -") || !strings.Contains(ob["windows"], "Get-FileHash") ||
		strings.Contains(ob["linux"], "| sudo bash") || strings.Contains(ob["windows"], "| iex") {
		t.Errorf("onboarding snippets must verify the installer:\n%s\n%s", ob["linux"], ob["windows"])
	}
}

func TestLinuxInstallScriptWarnsOnPlainHTTP(t *testing.T) {
	caMgr, err := ca.NewCAManager(filepath.Join(t.TempDir(), "certs"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: &config.Config{PublicURL: "http://aegis.example:8081"}, caMgr: caMgr}
	script := s.linuxInstallScript()
	if !strings.Contains(script, "served over plain http") || !strings.Contains(script, "EXPECTED_FP='"+caMgr.Fingerprint+"'") {
		t.Fatalf("plain-http installer must warn and still pin the fingerprint:\n%s", script)
	}
}

func (h *harness) srvOnboarding(t *testing.T) map[string]string {
	t.Helper()
	caMgr, err := ca.NewCAManager(filepath.Join(h.dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: h.cfg, caMgr: caMgr}
	return s.onboarding(models.Server{ProxyAuthUser: "srv-1", IP: "10.1.2.3"}, "tok")
}
