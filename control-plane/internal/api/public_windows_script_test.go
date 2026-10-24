package api

import (
	"io"
	"strings"
	"testing"
)

// The PEM copy referenced by NODE_EXTRA_CA_CERTS is trusted machine-wide: the generated Windows script must write
// it only into an admin-owned directory whose ACL it has reset and verified, never into ProgramData (where users
// may create the directory first).
func TestWindowsInstallScriptHardensPemDirectory(t *testing.T) {
	h := newHarness(t)
	resp := h.do(t, "GET", "/api/public/ca/install-windows.ps1", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	script := string(b)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Contains(script, "ProgramData") {
		t.Error("PEM copy still written below ProgramData")
	}
	write := strings.Index(script, "Set-Content -LiteralPath $pemPath")
	if write < 0 {
		t.Fatal("PEM write not found")
	}
	steps := []string{
		"$dir = Join-Path $env:ProgramFiles 'AegisProxy\\ca-trust'",
		"icacls.exe $dir /setowner '*S-1-5-32-544' /T /C /Q",
		"icacls.exe $dir /reset /T /C /Q",
		"icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q",
		"$acl = Get-Acl -LiteralPath $dir",
		"throw \"SECURITY ERROR: $dir is not restricted to administrators",
	}
	last := -1
	for _, step := range steps {
		i := strings.Index(script, step)
		if i < 0 {
			t.Fatalf("hardening step missing: %s", step)
		}
		if i <= last || i > write {
			t.Errorf("hardening step out of order (must run before the PEM is written): %s", step)
		}
		last = i
	}
	if strings.Contains(script, "%!") {
		t.Error("fmt verb error in the script template")
	}
}
