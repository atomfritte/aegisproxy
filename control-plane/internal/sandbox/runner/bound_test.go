package runner

import (
	"encoding/json"
	"testing"

	"aegisproxy/control-plane/internal/sandbox"
)

func TestBoundReportFits(t *testing.T) {
	rep := &sandbox.Report{SchemaVersion: 1, RunnerVersion: "t"}
	// Create a phase with far more events than a small limit allows.
	ph := sandbox.Phase{Name: "install"}
	for i := 0; i < 50000; i++ {
		ph.Syscalls.Events = append(ph.Syscalls.Events, sandbox.SyscallEvent{
			PID: i, Syscall: "openat", Category: "file-write", Args: "/some/long/path/that/takes/space/" + itoa(i)})
	}
	for i := 0; i < 20000; i++ {
		ph.Network.HTTP = append(ph.Network.HTTP, sandbox.HTTPRequest{Method: "GET", URL: "http://host.example/" + itoa(i)})
	}
	rep.Phases = []sandbox.Phase{ph}

	limit := 256 << 10 // 256 KiB
	b, err := BoundReport(rep, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > limit {
		t.Fatalf("report %d bytes exceeds limit %d", len(b), limit)
	}
	if !rep.Truncated {
		t.Error("Truncated flag not set")
	}
	// Still valid JSON.
	var out sandbox.Report
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("truncated report is not valid JSON: %v", err)
	}
	if out.Phases[0].Syscalls.Dropped == 0 {
		t.Error("Dropped counter not set after truncation")
	}
}

func TestBoundReportNoTruncationWhenSmall(t *testing.T) {
	rep := &sandbox.Report{SchemaVersion: 1, RunnerVersion: "t"}
	b, err := BoundReport(rep, MaxReportBytes)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Truncated {
		t.Error("small report should not be marked truncated")
	}
	if len(b) == 0 {
		t.Error("empty output")
	}
}
