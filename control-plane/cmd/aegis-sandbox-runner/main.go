// Command aegis-sandbox-runner is the entrypoint inside the AegisProxy package-firewall sandbox images. It reads
// one RunnerInput line plus the artifact bytes (from stdin under Docker, from /dev/vdb as PID 1 under
// Firecracker), unpacks and statically inspects the artifact, runs its install/load scenarios under strace behind
// a fake resolver and HTTP(S)/TCP sinks, and writes the behavior Report between AEGIS-REPORT-BEGIN/END on stdout.
//
// It is a thin wrapper: all logic lives in internal/sandbox/runner so it can be unit-tested on the host.
package main

import (
	"os"

	"aegisproxy/control-plane/internal/sandbox/runner"
)

// Version is overridden at build time with -ldflags "-X main.Version=...".
var Version = ""

func main() {
	if Version != "" {
		runner.Version = Version
	}
	os.Exit(runner.Run(os.Stdin, os.Stdout, os.Stderr))
}
