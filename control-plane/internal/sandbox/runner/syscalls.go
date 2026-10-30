package runner

import (
	"regexp"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// AnalyzeConfig drives categorization of a trace.
type AnalyzeConfig struct {
	StartEpoch   float64           // trace start; relative ms are computed from it
	MarkerToken  string            // package code begins after the first event whose Args contains this token
	WorkDir      string            // the package's own directory; writes here are not "outside"
	AllowPrefix  []string          // additional allowed write prefixes (temp, caches, site dir ...)
	DecoyFiles   map[string]string // resolved decoy path -> canary name (a read is a CanaryHit)
	SensitiveRe  *regexp.Regexp    // extra well-known sensitive paths (credentials, history) to flag on read
	ResolveHost  func(ip string) string
	MaxEvents    int // notable-event cap (default 2000)
	MaxProcesses int
	MaxPaths     int // per FileActivity list
}

// AnalyzeResult is the categorized trace.
type AnalyzeResult struct {
	Syscalls    sandbox.Syscalls
	Processes   []sandbox.Process
	Files       sandbox.FileActivity
	Connections []sandbox.Connection
	FileCanary  []sandbox.CanaryHit // decoy files that were read
}

var procCalls = set("execve", "execveat", "clone", "clone3", "fork", "vfork", "kill", "tgkill", "tkill", "ptrace", "prctl", "setns", "unshare")
var netCalls = set("socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "getpeername")
var writeOpenRe = regexp.MustCompile(`O_(WRONLY|RDWR|CREAT|APPEND|TRUNC)`)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Analyze categorizes parsed events (from the marker onward) into the report's per-phase structures.
func Analyze(events []Event, cfg AnalyzeConfig) AnalyzeResult {
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = 2000
	}
	if cfg.MaxProcesses == 0 {
		cfg.MaxProcesses = 1000
	}
	if cfg.MaxPaths == 0 {
		cfg.MaxPaths = 500
	}
	events = filterFromMarker(events, cfg.MarkerToken)

	var res AnalyzeResult
	counts := map[string]int64{}
	res.Syscalls.Counts = counts

	ms := func(e Event) int64 {
		if e.Epoch == 0 || cfg.StartEpoch == 0 {
			return 0
		}
		return int64((e.Epoch - cfg.StartEpoch) * 1000)
	}
	addEvent := func(e sandbox.SyscallEvent) {
		if len(res.Syscalls.Events) < cfg.MaxEvents {
			res.Syscalls.Events = append(res.Syscalls.Events, e)
		} else {
			res.Syscalls.Dropped++
		}
	}

	for _, e := range events {
		if e.Name == "" {
			continue // signal / exit line
		}
		counts[e.Name]++
		res.Syscalls.Total++
		t := ms(e)

		switch {
		case procCalls[e.Name]:
			cat := "process"
			if e.Name == "ptrace" || (e.Name == "prctl" && strings.Contains(e.Args, "PR_SET_PTRACER")) {
				cat = "evasion"
			}
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: cat,
				Args: clampStr(e.Args, 256), Result: result(e)})
			if (e.Name == "execve" || e.Name == "execveat") && e.Ret == "0" {
				if p, ok := execProcess(e, t); ok && len(res.Processes) < cfg.MaxProcesses {
					res.Processes = append(res.Processes, p)
				}
			}
		case netCalls[e.Name]:
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "network",
				Args: clampStr(e.Args, 256), Result: result(e)})
			if conn, ok := connection(e, t, cfg.ResolveHost); ok {
				if len(res.Connections) < cfg.MaxPaths {
					res.Connections = append(res.Connections, conn)
				} else {
					res.Files.Dropped++
				}
			}
		default:
			categorizeFile(e, t, &res, cfg, addEvent)
		}
	}
	return res
}

// categorizeFile handles file/permission/privilege/evasion syscalls.
func categorizeFile(e Event, t int64, res *AnalyzeResult, cfg AnalyzeConfig, addEvent func(sandbox.SyscallEvent)) {
	switch e.Name {
	case "open", "openat", "openat2":
		p := openPath(e)
		if p == "" {
			return
		}
		if canary, ok := cfg.DecoyFiles[p]; ok && isReadish(e) {
			res.FileCanary = append(res.FileCanary, sandbox.CanaryHit{Canary: canary, Where: "file", Detail: "read " + clampStr(p, 200)})
			addSens(res, cfg, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: "decoy read (" + canary + ")"})
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "file-sensitive", Args: clampStr(e.Args, 256), Result: result(e)})
			return
		}
		if isReadish(e) && cfg.SensitiveRe != nil && cfg.SensitiveRe.MatchString(p) {
			addSens(res, cfg, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: "sensitive read"})
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "file-sensitive", Args: clampStr(e.Args, 256), Result: result(e)})
			return
		}
		if writeOpenRe.MatchString(e.Args) && !allowedWrite(p, cfg) {
			addWritten(res, cfg, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: "open for write"})
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "file-write", Args: clampStr(e.Args, 256), Result: result(e)})
		}
	case "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat", "creat", "mkdir", "mkdirat", "truncate":
		p := primaryPath(e)
		if p != "" && !allowedWrite(p, cfg) {
			addWritten(res, cfg, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: e.Name})
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "file-write", Args: clampStr(e.Args, 256), Result: result(e)})
		}
	case "unlink", "unlinkat", "rmdir":
		p := primaryPath(e)
		if p != "" {
			if len(res.Files.Deleted) < cfg.MaxPaths {
				res.Files.Deleted = append(res.Files.Deleted, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: e.Name})
			} else {
				res.Files.Dropped++
			}
			addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "file-delete", Args: clampStr(e.Args, 256), Result: result(e)})
		}
	case "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown":
		p := primaryPath(e)
		if len(res.Files.Permissions) < cfg.MaxPaths {
			res.Files.Permissions = append(res.Files.Permissions, sandbox.PathEvent{TimeMs: t, PID: e.PID, Path: p, Detail: clampStr(e.Args, 120)})
		}
		addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "permission", Args: clampStr(e.Args, 256), Result: result(e)})
	case "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups", "capset", "mount", "umount", "umount2", "pivot_root", "chroot":
		addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "privilege", Args: clampStr(e.Args, 256), Result: result(e)})
	case "process_vm_readv", "process_vm_writev", "personality", "memfd_create", "seccomp", "userfaultfd", "modify_ldt":
		addEvent(sandbox.SyscallEvent{TimeMs: t, PID: e.PID, Syscall: e.Name, Category: "evasion", Args: clampStr(e.Args, 256), Result: result(e)})
	}
}

func addSens(res *AnalyzeResult, cfg AnalyzeConfig, pe sandbox.PathEvent) {
	if len(res.Files.ReadSensitive) < cfg.MaxPaths {
		res.Files.ReadSensitive = append(res.Files.ReadSensitive, pe)
	} else {
		res.Files.Dropped++
	}
}

func addWritten(res *AnalyzeResult, cfg AnalyzeConfig, pe sandbox.PathEvent) {
	if len(res.Files.Written) < cfg.MaxPaths {
		res.Files.Written = append(res.Files.Written, pe)
	} else {
		res.Files.Dropped++
	}
}

// filterFromMarker drops every event up to and including the first whose Args contains token. If no marker is
// found (token empty or absent) the events are returned unchanged.
func filterFromMarker(events []Event, token string) []Event {
	if token == "" {
		return events
	}
	for i, e := range events {
		if strings.Contains(e.Args, token) {
			return events[i+1:]
		}
	}
	return events
}

func result(e Event) string {
	r := e.Ret
	if e.Errno != "" {
		if r != "" {
			return r + " " + e.Errno
		}
		return e.Errno
	}
	return r
}

func isReadish(e Event) bool {
	// A read-only open (no write flags). O_RDONLY is 0, so it's "readish" when no write flag is set.
	return !writeOpenRe.MatchString(e.Args)
}

// openPath returns the resolved path of an open*: prefer the -yy decoded path on the fd result, else the quoted
// path argument.
func openPath(e Event) string {
	if e.RetDecoded != "" && strings.HasPrefix(e.RetDecoded, "/") {
		return e.RetDecoded
	}
	// openat(AT_FDCWD, "path", ...) -> arg[1]; open("path", ...) -> arg[0].
	for _, a := range e.ArgList {
		if s, ok := unquote(a); ok {
			return s
		}
	}
	return ""
}

// primaryPath returns the first quoted-string argument's value (the target path of most path syscalls).
func primaryPath(e Event) string {
	for _, a := range e.ArgList {
		if s, ok := unquote(a); ok {
			return s
		}
	}
	return ""
}

func execProcess(e Event, t int64) (sandbox.Process, bool) {
	p := sandbox.Process{TimeMs: t, PID: e.PID}
	if len(e.ArgList) == 0 {
		return p, false
	}
	if exe, ok := unquote(e.ArgList[0]); ok {
		p.Exe = exe
	}
	// argv is the bracketed second argument: ["sh", "-c", "id"].
	if len(e.ArgList) >= 2 {
		p.Argv = parseStrArray(e.ArgList[1])
	}
	if p.Exe == "" && len(p.Argv) > 0 {
		p.Exe = p.Argv[0]
	}
	return p, true
}

var (
	ipv4ConnRe = regexp.MustCompile(`sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)`)
	ipv6ConnRe = regexp.MustCompile(`sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"`)
	unixConnRe = regexp.MustCompile(`sun_path="([^"]+)"`)
	fdDecoRe   = regexp.MustCompile(`(TCP|UDP|UDPLITE|TCPv6|UDPv6):`)
)

// connection builds a Connection record from a connect/sendto event (the ones that carry a sockaddr).
func connection(e Event, t int64, resolve func(string) string) (sandbox.Connection, bool) {
	if e.Name != "connect" && e.Name != "sendto" && e.Name != "sendmsg" {
		return sandbox.Connection{}, false
	}
	c := sandbox.Connection{TimeMs: t, PID: e.PID, Result: result(e)}
	proto := "tcp"
	if m := fdDecoRe.FindStringSubmatch(e.Args + " " + e.RetDecoded); m != nil {
		if strings.HasPrefix(m[1], "UDP") {
			proto = "udp"
		}
	}
	switch {
	case ipv4ConnRe.MatchString(e.Args):
		m := ipv4ConnRe.FindStringSubmatch(e.Args)
		c.Protocol = proto
		c.Address = m[2]
		c.Port = atoiSafe(m[1])
	case ipv6ConnRe.MatchString(e.Args):
		m := ipv6ConnRe.FindStringSubmatch(e.Args)
		c.Protocol = proto
		c.Address = m[2]
		c.Port = atoiSafe(m[1])
	case unixConnRe.MatchString(e.Args):
		m := unixConnRe.FindStringSubmatch(e.Args)
		c.Protocol = "unix"
		c.Address = m[1]
	default:
		return sandbox.Connection{}, false
	}
	if resolve != nil && c.Address != "" {
		c.Hostname = resolve(c.Address)
	}
	return c, true
}

func allowedWrite(p string, cfg AnalyzeConfig) bool {
	if p == "" {
		return true // unknown path: don't flag
	}
	if cfg.WorkDir != "" && underPrefix(p, cfg.WorkDir) {
		return true
	}
	for _, pre := range cfg.AllowPrefix {
		if underPrefix(p, pre) {
			return true
		}
	}
	return false
}

func underPrefix(p, pre string) bool {
	pre = strings.TrimRight(pre, "/")
	return p == pre || strings.HasPrefix(p, pre+"/")
}

// unquote turns a strace C-string literal ("ab\"c") into its value; ok=false if a is not a quoted string.
func unquote(a string) (string, bool) {
	a = strings.TrimSpace(a)
	if len(a) < 2 || a[0] != '"' {
		return "", false
	}
	// Find the closing quote (honoring \").
	var sb strings.Builder
	for i := 1; i < len(a); i++ {
		c := a[i]
		if c == '\\' && i+1 < len(a) {
			i++
			switch a[i] {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case '"', '\\':
				sb.WriteByte(a[i])
			default:
				sb.WriteByte(a[i])
			}
			continue
		}
		if c == '"' {
			return sb.String(), true
		}
		sb.WriteByte(c)
	}
	return sb.String(), true // unterminated: return what we have
}

// parseStrArray parses a strace string array ["a", "b", ...] into its elements. A trailing "..." (truncation)
// marker is ignored.
func parseStrArray(a string) []string {
	a = strings.TrimSpace(a)
	a = strings.TrimPrefix(a, "[")
	a = strings.TrimSuffix(a, "]")
	var out []string
	for _, part := range splitTopLevel(a) {
		if s, ok := unquote(part); ok {
			out = append(out, s)
		}
	}
	return out
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
