package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aegisproxy/control-plane/internal/sandboxworker"
)

// runSandboxWorker runs the package-firewall sandbox analysis worker. It claims jobs from the
// control-plane and runs each artifact in the configured isolation driver. Configuration is from
// AEGIS_SANDBOX_* environment variables (see docs/package-firewall.md).
func runSandboxWorker() int {
	cpURL := envOr("AEGIS_CONTROL_PLANE_URL", envOr("CONTROL_PLANE_URL", ""))
	key := strings.TrimSpace(os.Getenv("AEGIS_SANDBOX_KEY"))
	if cpURL == "" || key == "" {
		fmt.Fprintln(os.Stderr, "sandbox-worker: AEGIS_CONTROL_PLANE_URL and AEGIS_SANDBOX_KEY are required")
		return 2
	}
	workerID := envOr("AEGIS_SANDBOX_WORKER", "")
	if workerID == "" {
		if h, err := os.Hostname(); err == nil {
			workerID = "sbx-" + h
		} else {
			workerID = "sbx-worker"
		}
	}
	var ecosystems []string
	if v := strings.TrimSpace(os.Getenv("AEGIS_SANDBOX_ECOSYSTEMS")); v != "" {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				ecosystems = append(ecosystems, e)
			}
		}
	}

	driverName := strings.ToLower(envOr("AEGIS_SANDBOX_DRIVER", "docker"))
	var driver sandboxworker.Driver
	switch driverName {
	case "docker":
		driver = sandboxworker.DockerDriver{
			Docker: envOr("AEGIS_SANDBOX_DOCKER", "docker"), ImagePrefix: envOr("AEGIS_SANDBOX_IMAGE_PREFIX", "aegisproxy-sandbox-"),
			ImageTag: envOr("AEGIS_SANDBOX_IMAGE_TAG", "latest"), MemoryMB: envInt("AEGIS_SANDBOX_MEMORY_MB", 2048),
			CPUs: envOr("AEGIS_SANDBOX_CPUS", "2"), PidsLimit: envInt("AEGIS_SANDBOX_PIDS", 512),
		}
	case "firecracker":
		driver = sandboxworker.FirecrackerDriver{
			Binary: envOr("AEGIS_SANDBOX_FC_BIN", "firecracker"), KernelPath: os.Getenv("AEGIS_SANDBOX_FC_KERNEL"),
			RootFSDir: os.Getenv("AEGIS_SANDBOX_FC_ROOTFS_DIR"), VCPUs: envInt("AEGIS_SANDBOX_CPUS", 2),
			MemoryMB: envInt("AEGIS_SANDBOX_MEMORY_MB", 2048), WorkDir: os.Getenv("AEGIS_SANDBOX_FC_WORKDIR"),
		}
	default:
		fmt.Fprintf(os.Stderr, "sandbox-worker: unknown driver %q (docker|firecracker)\n", driverName)
		return 2
	}

	w := sandboxworker.New(sandboxworker.Config{
		ControlPlaneURL: cpURL, SandboxKey: key, WorkerID: workerID, Ecosystems: ecosystems,
		HTTPProxy:     envOr("AEGIS_PACKAGE_HTTP_PROXY", envOr("AEGIS_FEED_HTTP_PROXY", "")),
		MaxArtifactMB: envInt("AEGIS_SANDBOX_MAX_ARTIFACT_MB", 512), Poll: time.Duration(envInt("AEGIS_SANDBOX_POLL_SECONDS", 5)) * time.Second,
		Driver: driver,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := w.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-worker:", err)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
