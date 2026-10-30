package runner

import (
	"encoding/json"

	"aegisproxy/control-plane/internal/sandbox"
)

// MaxReportBytes is the hard cap on the serialized report (one JSON line).
const MaxReportBytes = 8 << 20 // 8 MiB

// BoundReport serializes rep as compact JSON, truncating its lists in least-important-first order until it fits
// within limit. rep.Truncated is set when anything was dropped. The returned bytes are the final document.
func BoundReport(rep *sandbox.Report, limit int) ([]byte, error) {
	b, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	if len(b) <= limit {
		return b, nil
	}
	// Progressive truncation schedule: tighten caps until it fits.
	schedule := []caps{
		{files: 4000, events: 2000, http: 1000, conns: 1000, dns: 2000, paths: 500, indicators: 500, tail: 8192},
		{files: 1000, events: 1000, http: 500, conns: 500, dns: 1000, paths: 300, indicators: 300, tail: 8192},
		{files: 500, events: 500, http: 200, conns: 200, dns: 500, paths: 150, indicators: 150, tail: 4096},
		{files: 200, events: 200, http: 100, conns: 100, dns: 200, paths: 75, indicators: 75, tail: 2048},
		{files: 100, events: 100, http: 50, conns: 50, dns: 100, paths: 40, indicators: 40, tail: 1024},
		{files: 50, events: 40, http: 20, conns: 20, dns: 40, paths: 20, indicators: 20, tail: 512},
		{files: 20, events: 15, http: 10, conns: 10, dns: 20, paths: 10, indicators: 10, tail: 256},
		{files: 5, events: 5, http: 5, conns: 5, dns: 5, paths: 5, indicators: 5, tail: 0},
	}
	for _, c := range schedule {
		applyCaps(rep, c)
		rep.Truncated = true
		b, err = json.Marshal(rep)
		if err != nil {
			return nil, err
		}
		if len(b) <= limit {
			return b, nil
		}
	}
	return b, nil // best effort; still return what we have
}

type caps struct {
	files, events, http, conns, dns, paths, indicators, tail int
}

func applyCaps(rep *sandbox.Report, c caps) {
	// Static.
	if len(rep.Static.Files) > c.files {
		rep.Static.Dropped += len(rep.Static.Files) - c.files
		rep.Static.Files = rep.Static.Files[:c.files]
	}
	if len(rep.Static.Indicators) > c.indicators {
		rep.Static.Dropped += len(rep.Static.Indicators) - c.indicators
		rep.Static.Indicators = rep.Static.Indicators[:c.indicators]
	}
	rep.Static.URLs = truncStr(rep.Static.URLs, c.paths, &rep.Static.Dropped)
	rep.Static.Domains = truncStr(rep.Static.Domains, c.paths, &rep.Static.Dropped)
	rep.Static.IPs = truncStr(rep.Static.IPs, c.paths, &rep.Static.Dropped)

	for i := range rep.Phases {
		p := &rep.Phases[i]
		if len(p.Syscalls.Events) > c.events {
			p.Syscalls.Dropped += int64(len(p.Syscalls.Events) - c.events)
			p.Syscalls.Events = p.Syscalls.Events[:c.events]
		}
		if len(p.Network.HTTP) > c.http {
			p.Network.Dropped += len(p.Network.HTTP) - c.http
			p.Network.HTTP = p.Network.HTTP[:c.http]
		}
		if len(p.Network.Connections) > c.conns {
			p.Network.Dropped += len(p.Network.Connections) - c.conns
			p.Network.Connections = p.Network.Connections[:c.conns]
		}
		if len(p.Network.DNS) > c.dns {
			p.Network.Dropped += len(p.Network.DNS) - c.dns
			p.Network.DNS = p.Network.DNS[:c.dns]
		}
		p.Processes = truncProc(p.Processes, c.paths, &p.Files.Dropped)
		p.Files.Written = truncPath(p.Files.Written, c.paths, &p.Files.Dropped)
		p.Files.ReadSensitive = truncPath(p.Files.ReadSensitive, c.paths, &p.Files.Dropped)
		p.Files.Deleted = truncPath(p.Files.Deleted, c.paths, &p.Files.Dropped)
		p.Files.Permissions = truncPath(p.Files.Permissions, c.paths, &p.Files.Dropped)
		p.Stdout = clampTail(p.Stdout, c.tail)
		p.Stderr = clampTail(p.Stderr, c.tail)
	}
}

func truncStr(xs []string, cap int, dropped *int) []string {
	if len(xs) > cap {
		*dropped += len(xs) - cap
		return xs[:cap]
	}
	return xs
}

func truncPath(xs []sandbox.PathEvent, cap int, dropped *int) []sandbox.PathEvent {
	if len(xs) > cap {
		*dropped += len(xs) - cap
		return xs[:cap]
	}
	return xs
}

func truncProc(xs []sandbox.Process, cap int, dropped *int) []sandbox.Process {
	if len(xs) > cap {
		*dropped += len(xs) - cap
		return xs[:cap]
	}
	return xs
}

func clampTail(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}
