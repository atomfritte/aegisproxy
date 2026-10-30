package runner

import (
	"testing"

	"aegisproxy/control-plane/internal/sandbox"
)

func findingByID(fs []sandbox.Finding, id string) *sandbox.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestDeriveFindings(t *testing.T) {
	rep := &sandbox.Report{
		Static: sandbox.Static{
			InstallHooks:   []sandbox.InstallHook{{Kind: "npm-script", Name: "postinstall"}},
			NativeBinaries: []sandbox.File{{Path: "x.node", Kind: "native"}},
			Indicators:     []sandbox.Indicator{{Rule: "obf-packed-js", Severity: "medium", File: "a.js"}},
		},
		Phases: []sandbox.Phase{
			{
				Name: sandbox.ScenarioInstall,
				Network: sandbox.Network{
					DNS:         []sandbox.DNSQuery{{Name: "webhook.site", Type: "A"}},
					HTTP:        []sandbox.HTTPRequest{{Method: "POST", URL: "https://webhook.site/abc", Host: "webhook.site"}},
					Connections: []sandbox.Connection{{Protocol: "tcp", Address: "203.0.113.9", Port: 443, Result: "ECONNREFUSED"}},
				},
				Processes:  []sandbox.Process{{Exe: "/bin/sh", Argv: []string{"sh", "-c", "curl http://x"}}},
				Files:      sandbox.FileActivity{Written: []sandbox.PathEvent{{Path: "/home/sandbox/.bashrc"}}},
				CanaryHits: []sandbox.CanaryHit{{Canary: "aws-secret-key", Where: "http", Detail: "leaked"}},
				Syscalls: sandbox.Syscalls{Events: []sandbox.SyscallEvent{
					{Syscall: "unshare", Category: "privilege"},
					{Syscall: "ptrace", Category: "evasion"},
				}},
			},
		},
	}
	fs := DeriveFindings(rep)

	// Credential exfil is critical.
	if f := findingByID(fs, "SBX-CRED-EXFIL"); f == nil || f.Severity != "critical" {
		t.Errorf("SBX-CRED-EXFIL = %+v", f)
	}
	// Network during install is high and escalates to critical on exfil-style host.
	if f := findingByID(fs, "SBX-NET-INSTALL"); f == nil || f.Severity != "critical" {
		t.Errorf("SBX-NET-INSTALL = %+v (want critical from exfil host)", f)
	}
	// Shell spawn during install is high.
	if f := findingByID(fs, "SBX-PROC-SPAWN"); f == nil || f.Severity != "high" {
		t.Errorf("SBX-PROC-SPAWN = %+v", f)
	}
	// .bashrc write is persistence (high).
	if f := findingByID(fs, "SBX-PERSIST"); f == nil || f.Severity != "high" {
		t.Errorf("SBX-PERSIST = %+v", f)
	}
	if findingByID(fs, "SBX-PRIV") == nil || findingByID(fs, "SBX-EVASION") == nil {
		t.Errorf("privilege/evasion findings missing")
	}
	if findingByID(fs, "SBX-NATIVE") == nil || findingByID(fs, "SBX-HOOK") == nil {
		t.Errorf("static findings missing")
	}
	// Findings are sorted most-severe first.
	for i := 1; i < len(fs); i++ {
		if severityRank(fs[i-1].Severity) < severityRank(fs[i].Severity) {
			t.Errorf("findings not sorted by severity: %v", fs)
			break
		}
	}
}

func TestLoadNetworkRawIPIsHigh(t *testing.T) {
	rep := &sandbox.Report{Phases: []sandbox.Phase{{
		Name: sandbox.ScenarioLoad,
		Network: sandbox.Network{
			Connections: []sandbox.Connection{{Protocol: "tcp", Address: "198.51.100.7", Port: 8080, Result: "ENETUNREACH"}},
		},
	}}}
	fs := DeriveFindings(rep)
	if f := findingByID(fs, "SBX-NET-LOAD"); f == nil || f.Severity != "high" {
		t.Errorf("load network to raw IP = %+v (want high)", f)
	}
}
