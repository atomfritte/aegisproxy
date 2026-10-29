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

	// The checked bytes are the ones that run: a fresh private directory (never a fixed name in the
	// current or a shared temp directory), the Windows download hashed in memory and written with
	// CreateNew, and no tee (which would run a file other than the one that was hashed).
	linux, windows := info["linux_command"].(string), info["windows_command"].(string)
	for _, want := range []string{`d=$(mktemp -d)`, `curl -fsSLo "$d/aegis-ca-install.sh" 'https://aegis.example/api/public/ca/install-linux.sh'`,
		`$d/aegis-ca-install.sh" | sha256sum -c -`, `&& sudo bash "$d/aegis-ca-install.sh"`, `rm -rf "$d"`} {
		if !strings.Contains(linux, want) {
			t.Errorf("linux command lacks %q: %s", want, linux)
		}
	}
	for _, want := range []string{`(Invoke-WebRequest -UseBasicParsing 'https://aegis.example/api/public/ca/install-windows.ps1').RawContentStream.ToArray()`,
		`ComputeHash($b)`, `[guid]::NewGuid()`, `[IO.File]::Open($f, 'CreateNew', 'Write', 'None')`, `-File $f`, `$ErrorActionPreference = 'Stop'`} {
		if !strings.Contains(windows, want) {
			t.Errorf("windows command lacks %q: %s", want, windows)
		}
	}
	if strings.Contains(linux, "tee") || strings.Contains(linux, "-o aegis-ca-install.sh") || strings.Contains(linux, "-fsSLo aegis-ca-install.sh") ||
		strings.Contains(windows, "-OutFile") || strings.Contains(windows, "'aegis-ca-install.ps1'; iwr") {
		t.Errorf("install commands must not use a fixed-name download:\n%s\n%s", linux, windows)
	}

	ob := h.srvOnboarding(t)
	if !strings.Contains(ob["linux"], "sha256sum -c -") || !strings.Contains(ob["windows"], "ComputeHash($b)") ||
		strings.Contains(ob["linux"], "| sudo bash") || strings.Contains(ob["windows"], "| iex") {
		t.Errorf("onboarding snippets must verify the installer:\n%s\n%s", ob["linux"], ob["windows"])
	}
}

// caInfoCommands returns the console's install commands pointed at the test server, and the served
// scripts.
func caInfoCommands(t *testing.T, h *harness) (info map[string]any, scripts map[string][]byte) {
	t.Helper()
	if err := json.NewDecoder(h.do(t, "GET", "/api/public/ca/info", nil, nil).Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	scripts = map[string][]byte{}
	for kind, path := range map[string]string{"linux": "/api/public/ca/install-linux.sh", "windows": "/api/public/ca/install-windows.ps1"} {
		scripts[kind], _ = io.ReadAll(h.do(t, "GET", path, nil, nil).Body)
		info[kind+"_command"] = strings.ReplaceAll(info[kind+"_command"].(string), h.cfg.PublicURL, h.srv.URL)
	}
	return info, scripts
}

// fakeElevation puts an executable named name first on PATH that records the file it is asked to
// run (the last argument) and that file's content, instead of running it elevated.
func fakeElevation(t *testing.T, name string) (path, log string) {
	t.Helper()
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	stub := "#!/bin/sh\nfor a in \"$@\"; do f=$a; done\nprintf '%s' \"$f\" > \"$AEGIS_RAN.path\"\ncat \"$f\" > \"$AEGIS_RAN\"\n"
	if err := os.WriteFile(filepath.Join(bin, name), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin + string(os.PathListSeparator) + os.Getenv("PATH"), log
}

// The Linux one-liner, run for real (bash, curl, sha256sum, mktemp; sudo is a stub): it runs exactly
// the downloaded and checked file from a private directory, removes the directory, and runs nothing
// when the SHA-256 does not match.
func TestCAInstallLinuxCommandRunsTheCheckedFile(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "sha256sum", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	h := newHarness(t)
	info, scripts := caInfoCommands(t, h)
	cmd := info["linux_command"].(string)
	for name, c := range map[string]string{"genuine": cmd, "tampered": strings.ReplaceAll(cmd, info["linux_script_sha256"].(string), strings.Repeat("0", 64))} {
		path, ran := fakeElevation(t, "sudo")
		tmp := t.TempDir()
		run := exec.Command("bash", "-c", c)
		run.Dir = t.TempDir()
		run.Env = append(os.Environ(), "PATH="+path, "TMPDIR="+tmp, "AEGIS_RAN="+ran)
		out, err := run.CombinedOutput()
		got, readErr := os.ReadFile(ran)
		if left, _ := os.ReadDir(tmp); len(left) != 0 {
			t.Errorf("%s: download directory not removed: %v", name, left)
		}
		if name == "tampered" {
			if err == nil || readErr == nil {
				t.Errorf("tampered: the installer ran or the command succeeded (%v):\n%s", err, out)
			}
			continue
		}
		ranPath, _ := os.ReadFile(ran + ".path")
		if err != nil || string(got) != string(scripts["linux"]) || !strings.HasPrefix(string(ranPath), tmp+"/tmp.") {
			t.Errorf("genuine: err %v, ran %q (%d bytes, want the checked %d bytes):\n%s", err, ranPath, len(got), len(scripts["linux"]), out)
		}
	}
}

// The Windows one-liner under PowerShell 7 (on Linux, when pwsh is installed; the Windows CI job runs it
// for real): the bytes hashed in memory are the ones written to the new directory and run with -File,
// and nothing runs on a mismatch.
func TestCAInstallWindowsCommandRunsTheCheckedBytes(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("pwsh not available")
	}
	h := newHarness(t)
	info, scripts := caInfoCommands(t, h)
	cmd := info["windows_command"].(string)
	for name, c := range map[string]string{"genuine": cmd, "tampered": strings.ReplaceAll(cmd, info["windows_script_sha256"].(string), strings.Repeat("0", 64))} {
		path, ran := fakeElevation(t, "powershell")
		tmp := t.TempDir()
		run := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", c)
		run.Env = append(os.Environ(), "PATH="+path, "TEMP="+tmp, "AEGIS_RAN="+ran)
		out, err := run.CombinedOutput()
		got, readErr := os.ReadFile(ran)
		if left, _ := os.ReadDir(tmp); len(left) != 0 {
			t.Errorf("%s: download directory not removed: %v", name, left)
		}
		if name == "tampered" {
			if err == nil || readErr == nil || !strings.Contains(string(out), "SHA-256 mismatch") {
				t.Errorf("tampered: the installer ran or the command succeeded (%v):\n%s", err, out)
			}
			continue
		}
		ranPath, _ := os.ReadFile(ran + ".path")
		if err != nil || string(got) != string(scripts["windows"]) || !strings.HasPrefix(string(ranPath), filepath.Join(tmp, "aegis-ca-")) {
			t.Errorf("genuine: err %v, ran %q (%d bytes, want the checked %d bytes):\n%s", err, ranPath, len(got), len(scripts["windows"]), out)
		}
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
