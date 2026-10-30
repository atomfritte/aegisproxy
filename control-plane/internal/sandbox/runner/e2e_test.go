package runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// TestE2E runs each ecosystem's fixture through its real Docker image and asserts the report lists the expected
// DNS name, the web request to the made-up host, the `sh -c id` process, the decoy-file read and syscalls.
//
// It is gated: it runs only with AEGIS_SANDBOX_E2E=1, is skipped under -short, and is skipped when Docker or the
// image is missing. Build the images first:  make sandbox-images   (SANDBOX_TAG defaults to the Makefile VERSION;
// the test uses $SANDBOX_TAG or "dev"). Run:  AEGIS_SANDBOX_E2E=1 go test ./internal/sandbox/runner/ -run TestE2E -v
func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e under -short")
	}
	if os.Getenv("AEGIS_SANDBOX_E2E") == "" {
		t.Skip("set AEGIS_SANDBOX_E2E=1 to run the Docker e2e")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	tag := os.Getenv("SANDBOX_TAG")
	if tag == "" {
		tag = "dev"
	}

	cases := []struct {
		eco       string
		fixture   string // dir under sandbox/testdata/src/<eco>
		filename  string
		scenarios []string
		assertOn  string // phase to assert the observations on
		wantExfil bool
	}{
		{"npm", "npm/observer-demo", "observer-demo-1.0.0.tgz", []string{"install", "load"}, "install", true},
		{"pypi", "pypi", "observerdemo-1.0.tar.gz", []string{"install", "load"}, "install", true},
		{"nuget", "nuget/observerdemo", "ObserverDemo.1.0.0.nupkg", []string{"install"}, "install", true},
		{"psgallery", "psgallery/ObserverDemo", "ObserverDemo.1.0.0.nupkg", []string{"load"}, "load", true},
	}

	for _, c := range cases {
		t.Run(c.eco, func(t *testing.T) {
			image := "aegisproxy-sandbox-" + c.eco + ":" + tag
			if !dockerImageExists(t, image) {
				t.Skipf("image %s not built (run: make sandbox-images)", image)
			}
			artifact := packFixture(t, c.eco, c.fixture)
			rep := runImage(t, image, c.eco, c.filename, c.scenarios, artifact)

			if rep.RunnerVersion == "" {
				t.Error("empty runner version")
			}
			if len(rep.Errors) > 0 {
				t.Logf("report errors: %v", rep.Errors)
			}
			ph := findPhase(rep, c.assertOn)
			if ph == nil {
				t.Fatalf("no %s phase in report; phases: %s", c.assertOn, phaseNames(rep))
			}
			if ph.Skipped != "" {
				t.Fatalf("%s phase skipped: %s", c.assertOn, ph.Skipped)
			}
			t.Logf("%s/%s: exit=%d dns=%d http=%d conns=%d procs=%d syscalls=%d canaries=%d findings=%d",
				c.eco, c.assertOn, ph.ExitCode, len(ph.Network.DNS), len(ph.Network.HTTP),
				len(ph.Network.Connections), len(ph.Processes), ph.Syscalls.Total, len(ph.CanaryHits), len(rep.Findings))

			if !dnsHas(ph.Network.DNS, "telemetry.evil.example") {
				t.Errorf("DNS does not list telemetry.evil.example: %+v", ph.Network.DNS)
			}
			if !httpHas(ph.Network.HTTP, "telemetry.evil.example") {
				t.Errorf("no web request to telemetry.evil.example: %+v", ph.Network.HTTP)
			}
			if !processRanID(ph.Processes) {
				t.Errorf("no `id` process observed: %+v", ph.Processes)
			}
			if !decoyWasRead(ph) {
				t.Errorf("decoy credential read not observed (canary/read_sensitive): canaries=%+v read=%+v",
					ph.CanaryHits, ph.Files.ReadSensitive)
			}
			if ph.Syscalls.Total == 0 {
				t.Error("no syscalls recorded")
			}
			if c.wantExfil && findingWith(rep.Findings, "SBX-CRED-EXFIL") == nil {
				t.Logf("note: no credential-exfil finding (fixture may not have round-tripped the marker)")
			}
			if findingWith(rep.Findings, "SBX-NET-INSTALL") == nil && findingWith(rep.Findings, "SBX-NET-LOAD") == nil {
				t.Errorf("expected a network finding; findings: %s", findingIDs(rep.Findings))
			}
		})
	}
}

func runImage(t *testing.T, image, eco, filename string, scenarios []string, artifact []byte) *sandbox.Report {
	t.Helper()
	sum256 := sha256.Sum256(artifact)
	sum512 := sha512.Sum512(artifact)
	job := sandbox.Job{
		ID: "e2e-" + eco, Ecosystem: eco, Name: filename, Version: "1.0.0", Filename: filename,
		SHA256: hex.EncodeToString(sum256[:]), SHA512: base64.StdEncoding.EncodeToString(sum512[:]),
		Scenarios: scenarios, TimeoutSeconds: 90, Size: int64(len(artifact)),
	}
	line, _ := json.Marshal(sandbox.RunnerInput{Job: job, ArtifactSize: int64(len(artifact))})
	var in bytes.Buffer
	in.Write(line)
	in.WriteByte('\n')
	in.Write(artifact)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--network", "none",
		"--memory", "2g", "--pids-limit", "512", image)
	cmd.Stdin = &in
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Logf("docker run stderr:\n%s", tailStr(stderr.String(), 4000))
		t.Fatalf("docker run %s: %v", image, err)
	}
	raw := extractReport(t, stdout.String())
	var rep sandbox.Report
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatalf("parse report: %v\nreport: %s", err, tailStr(raw, 2000))
	}
	return &rep
}

func extractReport(t *testing.T, stdout string) string {
	t.Helper()
	const begin, end = "AEGIS-REPORT-BEGIN", "AEGIS-REPORT-END"
	bi := strings.Index(stdout, begin)
	ei := strings.Index(stdout, end)
	if bi < 0 || ei < 0 || ei <= bi {
		t.Fatalf("report markers not found in stdout:\n%s", tailStr(stdout, 2000))
	}
	return strings.TrimSpace(stdout[bi+len(begin) : ei])
}

// ---------- fixture packing ----------

func packFixture(t *testing.T, eco, fixture string) []byte {
	t.Helper()
	src := filepath.Join(repoRoot(t), "sandbox", "testdata", "src", fixture)
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("fixture %s missing: %v", src, err)
	}
	switch eco {
	case "npm", "pypi":
		return packTarGz(t, src)
	default: // nuget, psgallery -> zip (.nupkg)
		return packZip(t, src)
	}
}

func packTarGz(t *testing.T, src string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, rel := range sortedFiles(t, src) {
		data, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatal(err)
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func packZip(t *testing.T, src string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, rel := range sortedFiles(t, src) {
		data, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

func sortedFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = <root>/control-plane/internal/sandbox/runner/e2e_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

// ---------- assertions / helpers ----------

func dockerImageExists(t *testing.T, image string) bool {
	t.Helper()
	cmd := exec.Command("docker", "image", "inspect", image)
	return cmd.Run() == nil
}

func findPhase(rep *sandbox.Report, name string) *sandbox.Phase {
	for i := range rep.Phases {
		if rep.Phases[i].Name == name {
			return &rep.Phases[i]
		}
	}
	return nil
}

func phaseNames(rep *sandbox.Report) string {
	var n []string
	for _, p := range rep.Phases {
		n = append(n, p.Name+"("+p.Skipped+")")
	}
	return strings.Join(n, ",")
}

func dnsHas(qs []sandbox.DNSQuery, name string) bool {
	for _, q := range qs {
		if strings.EqualFold(strings.TrimSuffix(q.Name, "."), name) {
			return true
		}
	}
	return false
}

func httpHas(hs []sandbox.HTTPRequest, host string) bool {
	for _, h := range hs {
		if strings.Contains(h.URL, host) || strings.Contains(h.Host, host) {
			return true
		}
	}
	return false
}

func processRanID(ps []sandbox.Process) bool {
	for _, p := range ps {
		if filepath.Base(p.Exe) == "id" {
			return true
		}
		for _, a := range p.Argv {
			if a == "id" {
				return true
			}
		}
	}
	return false
}

func decoyWasRead(ph *sandbox.Phase) bool {
	for _, c := range ph.CanaryHits {
		if c.Where == "file" {
			return true
		}
	}
	for _, r := range ph.Files.ReadSensitive {
		if strings.Contains(r.Path, ".aws/credentials") {
			return true
		}
	}
	return false
}

func findingWith(fs []sandbox.Finding, id string) *sandbox.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func findingIDs(fs []sandbox.Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return strings.Join(ids, ",")
}

func tailStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
