// Package sandbox holds the contract between the control-plane, the sandbox workers and the runner that executes
// inside the disposable sandbox (Docker container or Firecracker microVM): the analysis job, the runner input and
// the behavior report.
//
// Trust boundaries: the runner processes attacker-controlled archives and executes attacker-controlled code, so
// everything in a Report is untrusted data. The worker and the control-plane bound and validate it (Normalize)
// and never interpret it as instructions.
package sandbox

import "time"

// SchemaVersion of Report.
const SchemaVersion = 1

// Scenarios a job can request.
const (
	ScenarioStatic  = "static"  // unpack and inspect the artifact without running it
	ScenarioInstall = "install" // run the ecosystem's install hooks (npm lifecycle scripts, setup.py / PEP 517 build, MSBuild props/targets)
	ScenarioLoad    = "load"    // load the module (require / import / Import-Module / assembly load with module initializers)
)

// Job is one artifact analysis, handed to a sandbox worker by the control-plane.
type Job struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"` // npm | pypi | nuget | psgallery
	Name      string `json:"name"`      // registry name as published (display form)
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	// URL is where the worker downloads the artifact (the registry, usually through the proxy). Only the worker
	// fetches it, the control-plane never does; the bytes are verified against the expected digests and passed into
	// the sandbox without being stored.
	URL            string    `json:"url"`
	Size           int64     `json:"size,omitempty"`
	SHA256         string    `json:"sha256,omitempty"` // expected, hex
	SHA512         string    `json:"sha512,omitempty"` // expected, base64 (std encoding)
	Scenarios      []string  `json:"scenarios"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	MaxBytes       int64     `json:"max_bytes"`
	CreatedAt      time.Time `json:"created_at"`
}

// RunnerInput is the first line (JSON) the runner reads; ArtifactSize bytes of the artifact follow it.
type RunnerInput struct {
	Job          Job   `json:"job"`
	ArtifactSize int64 `json:"artifact_size"`
}

// Report is the behavior report of one job. Capped lists say so in Truncated / the Dropped counters.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	RunnerVersion string    `json:"runner_version"`
	Driver        string    `json:"driver"`    // docker | firecracker
	Isolation     string    `json:"isolation"` // human-readable description of the isolation that was used
	Image         string    `json:"image"`
	WorkerID      string    `json:"worker_id,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Artifact      Artifact  `json:"artifact"`
	Static        Static    `json:"static"`
	Phases        []Phase   `json:"phases"`
	Findings      []Finding `json:"findings"`
	Errors        []string  `json:"errors,omitempty"`
	Truncated     bool      `json:"truncated,omitempty"`
}

// Artifact describes the analyzed file as the runner received it.
type Artifact struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	SHA512   string `json:"sha512"`
	Format   string `json:"format"` // tgz | zip | wheel | sdist-tar | sdist-zip | nupkg
}

// Static is the result of unpacking and inspecting the artifact.
type Static struct {
	FileCount int   `json:"file_count"`
	TotalSize int64 `json:"total_size"` // unpacked
	// Files lists the archive members (capped); NativeBinaries the ELF / PE / Mach-O / .node / .so / .dll files.
	Files          []File        `json:"files"`
	NativeBinaries []File        `json:"native_binaries,omitempty"`
	InstallHooks   []InstallHook `json:"install_hooks,omitempty"`
	// URLs, Domains and IPs are literals found in the package's text files.
	URLs       []string    `json:"urls,omitempty"`
	Domains    []string    `json:"domains,omitempty"`
	IPs        []string    `json:"ips,omitempty"`
	Indicators []Indicator `json:"indicators,omitempty"`
	// Manifest holds selected fields of package.json / METADATA / .nuspec / .psd1 (name, version, license,
	// dependencies, entry points ...).
	Manifest   map[string]any `json:"manifest,omitempty"`
	Signatures []Signature    `json:"signatures,omitempty"`
	// Entrypoints are the modules the load scenario imports.
	Entrypoints []string `json:"entrypoints,omitempty"`
	Dropped     int      `json:"dropped,omitempty"` // entries beyond the caps
}

// File is an archive member.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Kind   string `json:"kind"` // text | script | native | binary | archive | other
	SHA256 string `json:"sha256,omitempty"`
}

// InstallHook is code the ecosystem runs on install or build.
type InstallHook struct {
	Kind    string `json:"kind"` // npm-script | npm-gyp | setup-py | pep517 | pth | msbuild-props | msbuild-targets | nuget-ps | ps-scripts-to-process | ps-module
	Name    string `json:"name"` // e.g. "postinstall", "build/Foo.targets"
	File    string `json:"file,omitempty"`
	Command string `json:"command,omitempty"`
}

// Indicator is a suspicious pattern found by static inspection.
type Indicator struct {
	Rule        string `json:"rule"`     // e.g. js-child-process, py-exec-base64, ps-invoke-expression
	Severity    string `json:"severity"` // info | low | medium | high | critical
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	Description string `json:"description"`
}

// Signature is a signature embedded in the artifact (NuGet .signature.p7s, Authenticode blocks).
type Signature struct {
	File     string `json:"file"`
	Kind     string `json:"kind"` // nuget-repository | nuget-author | authenticode
	Signer   string `json:"signer"`
	Issuer   string `json:"issuer,omitempty"`
	Verified *bool  `json:"verified,omitempty"` // nil = not verifiable in this sandbox
	Detail   string `json:"detail,omitempty"`
}

// Phase is one executed scenario (install, load).
type Phase struct {
	Name       string       `json:"name"`
	Command    []string     `json:"command"`
	ExitCode   int          `json:"exit_code"`
	TimedOut   bool         `json:"timed_out,omitempty"`
	DurationMs int64        `json:"duration_ms"`
	Skipped    string       `json:"skipped,omitempty"` // reason the phase did not run (no install hooks, unsupported format …)
	Stdout     string       `json:"stdout,omitempty"`  // tail, capped
	Stderr     string       `json:"stderr,omitempty"`  // tail, capped
	Network    Network      `json:"network"`
	Syscalls   Syscalls     `json:"syscalls"`
	Processes  []Process    `json:"processes,omitempty"`
	Files      FileActivity `json:"files"`
	CanaryHits []CanaryHit  `json:"canary_hits,omitempty"`
}

// Network is everything the code tried to reach. The sandbox has no route to the internet: a resolver answers
// every name with a sandbox address and sinks record HTTP(S) and TCP connections (TLS is terminated with a
// sandbox CA the runtimes trust), so the full URL of every web request is visible.
type Network struct {
	DNS         []DNSQuery    `json:"dns,omitempty"`
	HTTP        []HTTPRequest `json:"http,omitempty"`
	Connections []Connection  `json:"connections,omitempty"`
	Dropped     int           `json:"dropped,omitempty"`
}

// DNSQuery is a name lookup.
type DNSQuery struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // A, AAAA, TXT …
	Count   int    `json:"count"`
	FirstMs int64  `json:"first_ms"`
}

// HTTPRequest is a request a sink received.
type HTTPRequest struct {
	TimeMs      int64             `json:"time_ms"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	TLS         bool              `json:"tls"`
	SNI         string            `json:"sni,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodySize    int64             `json:"body_size"`
	BodyPreview string            `json:"body_preview,omitempty"` // printable prefix
}

// Connection is a socket connect / send attempt (from the syscall trace and the TCP sinks).
type Connection struct {
	TimeMs   int64  `json:"time_ms"`
	PID      int    `json:"pid,omitempty"`
	Protocol string `json:"protocol"` // tcp | udp | unix
	Address  string `json:"address"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"` // name the address was handed out for by the sandbox resolver
	Result   string `json:"result,omitempty"`
	Preview  string `json:"preview,omitempty"` // first bytes sent to a non-HTTP sink
}

// Syscalls summarizes the system calls of the analyzed code (strace of the scenario's process tree, noise of the
// runtime's own start-up excluded where a marker allows it).
type Syscalls struct {
	Total   int64            `json:"total"`
	Counts  map[string]int64 `json:"counts,omitempty"`
	Events  []SyscallEvent   `json:"events,omitempty"`
	Dropped int64            `json:"dropped,omitempty"`
}

// SyscallEvent is a notable system call.
type SyscallEvent struct {
	TimeMs   int64  `json:"time_ms"`
	PID      int    `json:"pid"`
	Syscall  string `json:"syscall"`
	Category string `json:"category"` // process | network | file-write | file-sensitive | file-delete | permission | privilege | evasion
	Args     string `json:"args"`
	Result   string `json:"result,omitempty"`
}

// Process is a program the code started.
type Process struct {
	TimeMs int64    `json:"time_ms"`
	PID    int      `json:"pid"`
	PPID   int      `json:"ppid,omitempty"`
	Exe    string   `json:"exe"`
	Argv   []string `json:"argv"`
}

// FileActivity lists file system changes and sensitive reads.
type FileActivity struct {
	Written       []PathEvent `json:"written,omitempty"`        // outside the package's own directory and temp
	ReadSensitive []PathEvent `json:"read_sensitive,omitempty"` // credentials, keys, shell history, bait files
	Deleted       []PathEvent `json:"deleted,omitempty"`
	Permissions   []PathEvent `json:"permissions,omitempty"` // chmod / chown
	Dropped       int         `json:"dropped,omitempty"`
}

// PathEvent is a file access.
type PathEvent struct {
	TimeMs int64  `json:"time_ms"`
	PID    int    `json:"pid"`
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

// CanaryHit is a bait credential that left its place: read, or seen in outgoing traffic.
type CanaryHit struct {
	Canary string `json:"canary"` // e.g. aws-secret-key, npm-token, ssh-private-key
	Where  string `json:"where"`  // file | http | dns | tcp
	Detail string `json:"detail"`
}

// Finding is a conclusion of the runner (or of the control-plane's assessment).
type Finding struct {
	ID       string   `json:"id"`       // stable rule ID, e.g. SBX-NET-INSTALL
	Severity string   `json:"severity"` // info | low | medium | high | critical
	Category string   `json:"category"` // network | process | filesystem | credentials | install-hook | obfuscation | native | signature | runtime
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Phase    string   `json:"phase,omitempty"`
}
