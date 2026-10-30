package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// FirecrackerDriver runs the runner as the init process of a short-lived Firecracker microVM, which
// isolates hostile code behind a separate kernel and KVM boundary (stronger than a shared-kernel
// container). It needs the firecracker binary, a kernel image and a per-ecosystem root filesystem
// built with scripts/sandbox/build-firecracker-rootfs.sh. Without them Run returns a clear error so
// the operator can fall back to the Docker driver.
type FirecrackerDriver struct {
	Binary     string // firecracker binary (default "firecracker")
	KernelPath string // uncompressed vmlinux
	RootFSDir  string // directory holding <ecosystem>.ext4 images
	VCPUs      int
	MemoryMB   int
	WorkDir    string // scratch for per-run API sockets and the input drive
}

func (FirecrackerDriver) Name() string { return "firecracker" }

func (d FirecrackerDriver) rootfs(ecosystem string) string {
	return filepath.Join(d.RootFSDir, ecosystem+".ext4")
}

func (d FirecrackerDriver) preflight(ecosystem string) error {
	if d.KernelPath == "" || d.RootFSDir == "" {
		return errors.New("firecracker driver not configured: set AEGIS_SANDBOX_FC_KERNEL and AEGIS_SANDBOX_FC_ROOTFS_DIR (or use the docker driver)")
	}
	bin := d.Binary
	if bin == "" {
		bin = "firecracker"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("firecracker binary %q not found: %w", bin, err)
	}
	if _, err := os.Stat(d.KernelPath); err != nil {
		return fmt.Errorf("kernel image %q: %w", d.KernelPath, err)
	}
	if _, err := os.Stat(d.rootfs(ecosystem)); err != nil {
		return fmt.Errorf("root filesystem for %s: %w", ecosystem, err)
	}
	return nil
}

func (d FirecrackerDriver) Run(ctx context.Context, job sandbox.Job, artifact []byte) (*sandbox.Report, error) {
	if err := d.preflight(job.Ecosystem); err != nil {
		return nil, err
	}
	timeout := time.Duration(job.TimeoutSeconds)*time.Second + 120*time.Second
	if job.TimeoutSeconds <= 0 {
		timeout = 6 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	work := d.WorkDir
	if work == "" {
		work = os.TempDir()
	}
	dir, err := os.MkdirTemp(work, "aegis-fc-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	// The input drive holds the RunnerInput JSON line followed by the artifact (read by the runner
	// init from /dev/vdb).
	input, err := buildRunnerInput(job, artifact)
	if err != nil {
		return nil, err
	}
	inputDrive := filepath.Join(dir, "input.img")
	if err := os.WriteFile(inputDrive, input, 0o600); err != nil {
		return nil, err
	}

	cfg := d.vmConfig(job, inputDrive)
	cfgPath := filepath.Join(dir, "vm.json")
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		return nil, err
	}

	bin := d.Binary
	if bin == "" {
		bin = "firecracker"
	}
	// --no-api with a config file boots the VM headless; the serial console (ttyS0) carries the report.
	cmd := exec.CommandContext(runCtx, bin, "--no-api", "--config-file", cfgPath)
	var console bytes.Buffer
	cmd.Stdout = &console
	cmd.Stderr = &console
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	_ = cmd.Run() // the guest powers off itself; the report is on the console regardless of exit status

	report, perr := parseReport(console.Bytes())
	if perr != nil {
		tail := console.String()
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		return nil, fmt.Errorf("no report from the microVM (%v); console tail: %s", perr, tail)
	}
	return report, nil
}

// vmConfig is the Firecracker machine configuration (headless, no network interface).
func (d FirecrackerDriver) vmConfig(job sandbox.Job, inputDrive string) map[string]any {
	vcpus := d.VCPUs
	if vcpus <= 0 {
		vcpus = 2
	}
	mem := d.MemoryMB
	if mem <= 0 {
		mem = 2048
	}
	return map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": d.KernelPath,
			"boot_args":         "console=ttyS0 reboot=k panic=1 pci=off init=/aegis/runner",
		},
		"drives": []map[string]any{
			{"drive_id": "rootfs", "path_on_host": d.rootfs(job.Ecosystem), "is_root_device": true, "is_read_only": true},
			{"drive_id": "input", "path_on_host": inputDrive, "is_root_device": false, "is_read_only": true},
		},
		"machine-config": map[string]any{"vcpu_count": vcpus, "mem_size_mib": mem, "smt": false},
		// No "network-interfaces": the microVM has no route out, like the Docker driver's --network none.
	}
}

var _ = strconv.Itoa
