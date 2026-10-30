// Package runner implements the AegisProxy package-firewall behavior-analysis sandbox runner: the program that
// runs as the entrypoint inside a disposable sandbox (Docker container or Firecracker microVM), unpacks and
// statically inspects a third-party registry artifact and then executes its install/load scenarios under strace
// behind a fake DNS resolver and HTTP(S)/TCP sinks, recording every name, URL, connection, process, file access
// and system call into a sandbox.Report.
//
// The analyzed artifact is attacker-controlled. The runner starts as root inside the sandbox only to prepare the
// environment and observers; the analyzed code always runs as the unprivileged uid-1000 user with no capabilities.
// The sandbox itself has no route to the internet. Everything the runner writes into a Report is untrusted data.
//
// The package is split so that all parsing and analysis (archive extraction, manifest/hook parsing, static
// indicators, strace-output parsing, the DNS/HTTP/TCP sinks, canary detection, findings derivation and report
// bounding) is ordinary host-testable Go; only the orchestration, the uid drop and the Firecracker init path are
// Linux- and sandbox-specific.
package runner

// Version is stamped into every Report (RunnerVersion) and into the image labels. The build overrides it via
// -ldflags "-X aegisproxy/control-plane/internal/sandbox/runner.Version=...".
var Version = "3.0.0-dev"
