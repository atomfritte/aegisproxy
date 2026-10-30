// Package sandboxworker is the control-plane-side sandbox worker: it claims analysis jobs from the
// control-plane, runs each artifact in an isolation driver (Docker container or Firecracker microVM)
// via the aegis-sandbox-runner, and posts the behavior report back. It is started with
// `aegis-control-plane sandbox-worker`.
package sandboxworker

import (
	"context"

	"aegisproxy/control-plane/internal/sandbox"
)

// Driver runs one analysis job in an isolated environment and returns the runner's report. The driver
// receives the artifact bytes (already fetched and verified by the worker) so it never needs network
// access of its own; the sandbox the driver creates has no route to the internet.
type Driver interface {
	// Name is "docker" or "firecracker".
	Name() string
	// Run executes the job's scenarios on the artifact and returns the parsed report.
	Run(ctx context.Context, job sandbox.Job, artifact []byte) (*sandbox.Report, error)
}
