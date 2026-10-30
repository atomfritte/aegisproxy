package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// DockerDriver runs the runner inside a throwaway container. Isolation: no network at all
// (`--network none`), capped memory / CPU / PID count, a tmpfs work area and an auto-removed
// container. A Docker container shares the host kernel, so for a hostile-code threat model the
// Firecracker driver provides stronger isolation; this driver is the portable default.
type DockerDriver struct {
	Docker      string // docker binary (default "docker")
	ImagePrefix string // image = <prefix><ecosystem>:<tag>
	ImageTag    string
	MemoryMB    int
	CPUs        string
	PidsLimit   int
}

func (d DockerDriver) Name() string { return "docker" }

func (d DockerDriver) image(ecosystem string) string {
	prefix := d.ImagePrefix
	if prefix == "" {
		prefix = "aegisproxy-sandbox-"
	}
	tag := d.ImageTag
	if tag == "" {
		tag = "latest"
	}
	return prefix + ecosystem + ":" + tag
}

func (d DockerDriver) Run(ctx context.Context, job sandbox.Job, artifact []byte) (*sandbox.Report, error) {
	timeout := time.Duration(job.TimeoutSeconds)*time.Second + 90*time.Second // scenarios + overhead
	if job.TimeoutSeconds <= 0 {
		timeout = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mem := d.MemoryMB
	if mem <= 0 {
		mem = 2048
	}
	cpus := d.CPUs
	if cpus == "" {
		cpus = "2"
	}
	pids := d.PidsLimit
	if pids <= 0 {
		pids = 512
	}
	args := []string{
		"run", "--rm", "-i",
		"--network", "none",
		"--memory", strconv.Itoa(mem) + "m", "--memory-swap", strconv.Itoa(mem) + "m",
		"--cpus", cpus,
		"--pids-limit", strconv.Itoa(pids),
		"--tmpfs", "/work:rw,size=1g,mode=1777",
		"--security-opt", "no-new-privileges=false", // the runner drops to an unprivileged user itself
		"--label", "org.aegisproxy.sandbox.job=" + job.ID,
		d.image(job.Ecosystem),
	}
	bin := d.Docker
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(runCtx, bin, args...)

	input, err := buildRunnerInput(job, artifact)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Kill the whole container tree when the context expires.
	cmd.Cancel = func() error { return cmd.Process.Kill() }

	runErr := cmd.Run()
	report, perr := parseReport(stdout.Bytes())
	if perr != nil {
		tail := stderr.String()
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		if runErr != nil {
			return nil, fmt.Errorf("docker run failed: %v; no report (%v); stderr: %s", runErr, perr, tail)
		}
		return nil, fmt.Errorf("could not parse the runner report (%v); stderr: %s", perr, tail)
	}
	return report, nil
}

// buildRunnerInput is the runner's stdin: one JSON line (RunnerInput) followed by the artifact bytes.
func buildRunnerInput(job sandbox.Job, artifact []byte) ([]byte, error) {
	line, err := json.Marshal(sandbox.RunnerInput{Job: job, ArtifactSize: int64(len(artifact))})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(line)
	buf.WriteByte('\n')
	buf.Write(artifact)
	return buf.Bytes(), nil
}

// parseReport extracts the report JSON between the runner's markers on stdout.
func parseReport(out []byte) (*sandbox.Report, error) {
	begin := []byte("AEGIS-REPORT-BEGIN")
	end := []byte("AEGIS-REPORT-END")
	i := bytes.Index(out, begin)
	j := bytes.Index(out, end)
	if i < 0 || j < 0 || j < i {
		return nil, fmt.Errorf("report markers not found in %d bytes of output", len(out))
	}
	body := bytes.TrimSpace(out[i+len(begin) : j])
	var rep sandbox.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

var _ = io.Discard
