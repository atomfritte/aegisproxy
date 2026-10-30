package runner

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/sandbox"
)

func TestParseLineComplete(t *testing.T) {
	ev, kind, _ := parseLine(`1000 1700000000.110000 execve("/bin/sh", ["sh", "-c", "id"], 0x7ffd /* 20 vars */) = 0 <0.000200>`)
	if kind != lineComplete {
		t.Fatalf("kind = %v", kind)
	}
	if ev.PID != 1000 || ev.Name != "execve" || ev.Ret != "0" {
		t.Fatalf("parsed = %+v", ev)
	}
	argv := parseStrArray(ev.ArgList[1])
	if len(argv) != 3 || argv[0] != "sh" || argv[2] != "id" {
		t.Fatalf("argv = %v", argv)
	}
}

func TestParseRetErrnoAndDecoration(t *testing.T) {
	ev, _, _ := parseLine(`1000 1.0 openat(AT_FDCWD, "/x", O_RDONLY) = 3</resolved/x> <0.1>`)
	if ev.Ret != "3" || ev.RetDecoded != "/resolved/x" {
		t.Fatalf("ret=%q decoded=%q", ev.Ret, ev.RetDecoded)
	}
	ev2, _, _ := parseLine(`1000 1.0 connect(6, {sa_family=AF_INET}, 16) = -1 ECONNREFUSED (Connection refused) <0.1>`)
	if ev2.Ret != "-1" || ev2.Errno != "ECONNREFUSED" {
		t.Fatalf("ret=%q errno=%q", ev2.Ret, ev2.Errno)
	}
}

func TestParseSignalAndExit(t *testing.T) {
	ev, kind, _ := parseLine(`1001 1.0 +++ exited with 0 +++`)
	if kind != lineSignalExit || !ev.Exited {
		t.Fatalf("exit parse: kind=%v ev=%+v", kind, ev)
	}
	ev2, kind2, _ := parseLine(`1001 1.0 --- SIGCHLD {si_signo=SIGCHLD} ---`)
	if kind2 != lineSignalExit || ev2.Signal != "SIGCHLD" {
		t.Fatalf("signal parse: kind=%v ev=%+v", kind2, ev2)
	}
}

func TestAnalyzeFixture(t *testing.T) {
	f, err := os.Open("testdata/strace_install.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := ParseStrace(f)
	if err != nil {
		t.Fatal(err)
	}

	cfg := AnalyzeConfig{
		StartEpoch:  1700000000.1,
		MarkerToken: "MARKER123",
		WorkDir:     "/work/pkg",
		AllowPrefix: []string{"/tmp", "/work"},
		DecoyFiles:  map[string]string{"/home/sandbox/.aws/credentials": "aws-secret-key"},
		SensitiveRe: sensitiveTestRe,
		ResolveHost: func(ip string) string {
			if ip == "127.10.0.5" {
				return "evil.example"
			}
			return ""
		},
	}
	res := Analyze(events, cfg)

	if res.Syscalls.Total != 10 {
		t.Errorf("Total = %d, want 10", res.Syscalls.Total)
	}
	if res.Syscalls.Counts["execve"] != 2 {
		t.Errorf("execve count = %d, want 2", res.Syscalls.Counts["execve"])
	}
	// The sentinel openat before the marker must be excluded.
	if res.Syscalls.Counts["openat"] != 2 { // .aws/credentials + .bashrc, not the sentinel
		t.Errorf("openat count = %d, want 2", res.Syscalls.Counts["openat"])
	}

	// Processes: sh -c id and id.
	if len(res.Processes) != 2 {
		t.Fatalf("processes = %d, want 2: %+v", len(res.Processes), res.Processes)
	}
	if got := strings.Join(res.Processes[0].Argv, " "); got != "sh -c id" {
		t.Errorf("proc0 argv = %q", got)
	}

	// Connections: the sandbox-mapped 127.10.0.5:80 and the raw-IP 203.0.113.9:443 refusal.
	var sawMapped, sawRaw bool
	for _, c := range res.Connections {
		if c.Address == "127.10.0.5" && c.Port == 80 && c.Hostname == "evil.example" {
			sawMapped = true
		}
		if c.Address == "203.0.113.9" && c.Port == 443 && strings.Contains(c.Result, "ECONNREFUSED") {
			sawRaw = true
		}
	}
	if !sawMapped || !sawRaw {
		t.Errorf("connections mapped=%v raw=%v: %+v", sawMapped, sawRaw, res.Connections)
	}

	// Canary: decoy file read.
	if len(res.FileCanary) != 1 || res.FileCanary[0].Canary != "aws-secret-key" || res.FileCanary[0].Where != "file" {
		t.Errorf("file canary = %+v", res.FileCanary)
	}

	// File activity.
	if !hasPath(res.Files.ReadSensitive, "/home/sandbox/.aws/credentials") {
		t.Errorf("read_sensitive missing decoy: %+v", res.Files.ReadSensitive)
	}
	if !hasPath(res.Files.Written, "/home/sandbox/.bashrc") {
		t.Errorf("written missing .bashrc: %+v", res.Files.Written)
	}
	if !hasPath(res.Files.Permissions, "/home/sandbox/.bashrc") {
		t.Errorf("permissions missing chmod: %+v", res.Files.Permissions)
	}

	// Categories present.
	cats := map[string]bool{}
	for _, e := range res.Syscalls.Events {
		cats[e.Category] = true
	}
	for _, want := range []string{"process", "network", "file-sensitive", "file-write", "permission"} {
		if !cats[want] {
			t.Errorf("missing syscall category %q", want)
		}
	}
}

var sensitiveTestRe = regexp.MustCompile(`/\.aws/|/\.ssh/|/etc/passwd`)

func hasPath(events []sandbox.PathEvent, p string) bool {
	for _, e := range events {
		if e.Path == p {
			return true
		}
	}
	return false
}
