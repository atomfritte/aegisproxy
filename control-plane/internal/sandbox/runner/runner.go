//go:build linux

package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// Default resource bounds.
const (
	defaultTimeoutSeconds = 120
	workRoot              = "/work"
	aegisDir              = "/aegis"
	sandboxHome           = "/home/sandbox"
)

// Run is the runner entry point. It reads one RunnerInput + artifact (from stdin under Docker, from /dev/vdb as
// PID 1 under Firecracker), performs the analysis and writes the Report between AEGIS-REPORT-BEGIN/END on stdout.
// It returns a process exit code: 0 whenever a report was produced (even if the analyzed package misbehaved or
// its digest did not match), non-zero only on a runner failure.
func Run(stdin io.Reader, stdout, stderr io.Writer) int {
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "[aegis-runner] "+format+"\n", a...) }

	driver := "docker"
	input := stdin
	if isFirecracker() {
		driver = "firecracker"
		defer powerOff(logf)
		r, err := initBoot(logf)
		if err != nil {
			logf("init: %v", err)
			emitReport(stdout, minimalErrReport(driver, "firecracker init failed: "+err.Error()))
			return 1
		}
		input = r
	}

	rep, runnerFailed := buildReport(driver, input, logf)
	emitReport(stdout, rep)
	if runnerFailed {
		return 1
	}
	return 0
}

// isFirecracker decides whether the runner is the init of a Firecracker microVM (read input from /dev/vdb and
// power the VM off when done) versus a Docker container (read stdin). Under Docker the runner is also PID 1, so
// PID 1 alone is not enough: the microVM is identified by the input block device /dev/vdb, or an explicit
// AEGIS_DRIVER override.
func isFirecracker() bool {
	switch os.Getenv("AEGIS_DRIVER") {
	case "firecracker":
		return true
	case "docker":
		return false
	}
	if os.Getpid() != 1 {
		return false
	}
	fi, err := os.Stat("/dev/vdb")
	return err == nil && fi.Mode()&os.ModeDevice != 0
}

func buildReport(driver string, input io.Reader, logf func(string, ...any)) (*sandbox.Report, bool) {
	started := time.Now().UTC()
	rep := &sandbox.Report{
		SchemaVersion: sandbox.SchemaVersion,
		RunnerVersion: Version,
		Driver:        driver,
		Image:         firstNonEmpty(os.Getenv("AEGIS_IMAGE"), os.Getenv("HOSTNAME")),
		WorkerID:      os.Getenv("AEGIS_WORKER_ID"),
		StartedAt:     started,
		Isolation:     isolationDesc(driver),
	}

	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		rep.Errors = append(rep.Errors, "mkdir work: "+err.Error())
		rep.FinishedAt = time.Now().UTC()
		return rep, true
	}
	artifactPath := filepath.Join(workRoot, "artifact.bin")
	in, art, err := ReadInput(input, artifactPath)
	if err != nil {
		rep.Errors = append(rep.Errors, "read input: "+err.Error())
		rep.FinishedAt = time.Now().UTC()
		return rep, true
	}
	rep.Artifact = *art
	job := in.Job

	// Verify the artifact against the job's expected digests before touching its contents.
	if err := VerifyDigests(job, art); err != nil {
		logf("digest verification failed: %v", err)
		rep.Errors = append(rep.Errors, err.Error())
		rep.FinishedAt = time.Now().UTC()
		return rep, false // a report with the error, nothing run; not a runner failure
	}

	// Static analysis is always performed.
	extractRoot := filepath.Join(workRoot, "extract")
	_ = os.RemoveAll(extractRoot)
	if err := os.MkdirAll(extractRoot, 0o755); err != nil {
		rep.Errors = append(rep.Errors, "mkdir extract: "+err.Error())
		rep.FinishedAt = time.Now().UTC()
		return rep, true
	}
	st, _, man, err := StaticAnalysis(job.Ecosystem, artifactPath, art.Format, extractRoot, DefaultExtractLimits())
	if err != nil {
		logf("static analysis: %v", err)
		rep.Errors = append(rep.Errors, "static: "+err.Error())
	}
	rep.Static = st

	// Dynamic scenarios.
	dynamic := wantedDynamic(job.Scenarios)
	if len(dynamic) > 0 {
		if err := runDynamic(rep, job, &man, artifactPath, extractRoot, logf); err != nil {
			logf("dynamic: %v", err)
			rep.Errors = append(rep.Errors, "dynamic: "+err.Error())
		}
	}

	rep.Findings = DeriveFindings(rep)
	rep.FinishedAt = time.Now().UTC()
	return rep, false
}

// runDynamic prepares the sandbox environment, starts the observers and runs every requested install/load phase.
func runDynamic(rep *sandbox.Report, job sandbox.Job, man *ManifestResult, artifactPath, extractRoot string, logf func(string, ...any)) error {
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		return fmt.Errorf("strace not found in image: %w", err)
	}
	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if job.TimeoutSeconds <= 0 {
		timeout = defaultTimeoutSeconds * time.Second
	}

	ctx := &runContext{
		eco:           job.Ecosystem,
		artifactPath:  artifactPath,
		artifactName:  filepath.Base(filepath.Clean("/" + job.Filename)),
		extractRoot:   extractRoot,
		pkgDir:        filepath.Join(extractRoot, filepath.FromSlash(man.PkgDir)),
		siteDir:       filepath.Join(workRoot, "site"),
		home:          sandboxHome,
		aegisDir:      aegisDir,
		traceDir:      filepath.Join(workRoot, "traces"),
		caPEM:         filepath.Join(aegisDir, "ca.pem"),
		caDir:         filepath.Join(aegisDir, "certs"),
		sentinel:      "",
		sentinelToken: randHex(12),
		nodeLoader:    filepath.Join(aegisDir, "node-loader.js"),
		pyLoader:      filepath.Join(aegisDir, "py-loader.py"),
		manifest:      *man,
		stracePath:    stracePath,
		timeout:       timeout,
		tools:         findTools(),
	}
	ctx.sentinel = filepath.Join(aegisDir, "sentinels", ctx.sentinelToken)
	ctx.decoys = GenerateDecoys(ctx.home)

	if err := prepareEnvironment(ctx, logf); err != nil {
		return fmt.Errorf("prepare environment: %w", err)
	}

	obs, err := StartObservers()
	if err != nil {
		return fmt.Errorf("start observers: %w", err)
	}
	defer obs.Close()

	for _, scenario := range wantedDynamic(job.Scenarios) {
		logf("phase %s: start", scenario)
		ph := ctx.runPhase(obs, scenario)
		logf("phase %s: exit=%d timedOut=%v dur=%dms dns=%d http=%d conns=%d procs=%d canaries=%d",
			scenario, ph.ExitCode, ph.TimedOut, ph.DurationMs,
			len(ph.Network.DNS), len(ph.Network.HTTP), len(ph.Network.Connections), len(ph.Processes), len(ph.CanaryHits))
		rep.Phases = append(rep.Phases, ph)
	}

	// Record whether name resolution was actually routed to our resolver in any phase.
	if resolved := anyDNS(rep.Phases); resolved {
		rep.Isolation += "; DNS routed to sandbox resolver"
	} else {
		rep.Isolation += "; no DNS queries observed"
	}
	return nil
}

// prepareEnvironment lays down the CA, sentinel, loader scripts, decoys, resolv.conf and ownership so the
// analyzed code can run (and write) as the unprivileged user while the observers are trusted.
func prepareEnvironment(ctx *runContext, logf func(string, ...any)) error {
	obs := func(path string, mode os.FileMode, data []byte) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, data, mode)
	}
	ca, err := caForEnv()
	if err != nil {
		return err
	}
	if err := obs(ctx.caPEM, 0o644, ca); err != nil {
		return err
	}
	if err := obs(filepath.Join(ctx.caDir, "sandbox-ca.pem"), 0o644, ca); err != nil {
		return err
	}
	if err := obs(ctx.sentinel, 0o644, []byte("aegis-sentinel "+ctx.sentinelToken+"\n")); err != nil {
		return err
	}
	if err := obs(ctx.nodeLoader, 0o644, []byte(nodeLoaderJS)); err != nil {
		return err
	}
	if err := obs(ctx.pyLoader, 0o644, []byte(pyLoaderPy)); err != nil {
		return err
	}

	// The artifact file is written 0600 by root; some installers read it directly as the analyzed user (pip
	// installs the wheel/sdist file). It is already digest-verified, so let uid 1000 read it.
	_ = os.Chmod(ctx.artifactPath, 0o644)

	// Home + decoys.
	if err := os.MkdirAll(ctx.home, 0o755); err != nil {
		return err
	}
	if err := ctx.decoys.Plant(); err != nil {
		return err
	}
	_ = os.MkdirAll(ctx.siteDir, 0o755)
	_ = os.MkdirAll(ctx.traceDir, 0o755)

	// resolv.conf -> our resolver (best effort; some images symlink it).
	resolv := []byte("nameserver 127.0.0.53\noptions timeout:1 attempts:1 single-request\n")
	if err := os.WriteFile("/etc/resolv.conf", resolv, 0o644); err != nil {
		logf("resolv.conf: %v (continuing)", err)
	}

	// Ownership: the analyzed process writes into the package dir, the site dir and /work as uid 1000.
	_ = chownR(ctx.extractRoot, unprivUID, unprivGID)
	_ = chownR(ctx.home, unprivUID, unprivGID)
	_ = os.Chown(workRoot, unprivUID, unprivGID)
	_ = chownR(ctx.siteDir, unprivUID, unprivGID)
	_ = chownR(ctx.traceDir, unprivUID, unprivGID)
	return nil
}

// sharedCA is the single per-run sandbox CA used both by the HTTPS sink (to mint per-SNI leaves) and written into
// the analyzed runtimes' trust store, so the TLS the sink terminates is actually trusted. prepareEnvironment
// writes it before StartObservers brings up the sink; both go through sandboxCA so they are the same instance.
var sharedCA *SandboxCA

func sandboxCA() (*SandboxCA, error) {
	if sharedCA == nil {
		ca, err := NewSandboxCA()
		if err != nil {
			return nil, err
		}
		sharedCA = ca
	}
	return sharedCA, nil
}

func caForEnv() ([]byte, error) {
	ca, err := sandboxCA()
	if err != nil {
		return nil, err
	}
	return ca.CertPEM(), nil
}

func wantedDynamic(scenarios []string) []string {
	var out []string
	for _, s := range scenarios {
		if s == sandbox.ScenarioInstall || s == sandbox.ScenarioLoad {
			out = append(out, s)
		}
	}
	return out
}

func anyDNS(phases []sandbox.Phase) bool {
	for _, p := range phases {
		if len(p.Network.DNS) > 0 {
			return true
		}
	}
	return false
}

func isolationDesc(driver string) string {
	switch driver {
	case "firecracker":
		return "Firecracker microVM, no NIC (loopback only), analyzed code as uid 1000"
	default:
		return "Docker container, --network none (loopback only), analyzed code as uid 1000 no-new-privileges"
	}
}

func minimalErrReport(driver, msg string) *sandbox.Report {
	now := time.Now().UTC()
	return &sandbox.Report{
		SchemaVersion: sandbox.SchemaVersion, RunnerVersion: Version, Driver: driver,
		Isolation: isolationDesc(driver), StartedAt: now, FinishedAt: now, Errors: []string{msg},
	}
}

func emitReport(w io.Writer, rep *sandbox.Report) {
	b, err := BoundReport(rep, MaxReportBytes)
	if err != nil {
		b = []byte(`{"schema_version":1,"errors":["report marshal failed"]}`)
	}
	fmt.Fprintln(w, "AEGIS-REPORT-BEGIN")
	_, _ = w.Write(b)
	fmt.Fprint(w, "\n")
	fmt.Fprintln(w, "AEGIS-REPORT-END")
}
