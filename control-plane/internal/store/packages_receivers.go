package store

import (
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// PackageReceiver aggregates one server's observed downloads of a package.
type PackageReceiver struct {
	ServerID   string    `json:"server_id"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	GroupIDs   []string  `json:"group_ids"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int       `json:"count"`
	Files      []string  `json:"files"`
	Versions   []string  `json:"versions"`
	Decisions  []string  `json:"decisions"`
	LastStatus int       `json:"last_status"`
}

// PackageReceiversResult is the incident view "which servers obtained this package".
type PackageReceiversResult struct {
	Ecosystem string            `json:"ecosystem"`
	Name      string            `json:"name"`
	Version   string            `json:"version,omitempty"`
	SHA256    string            `json:"sha256,omitempty"`
	Receivers []PackageReceiver `json:"receivers"`
	// Coverage is the time window the searched telemetry actually spans (the oldest and newest flow
	// carrying a package record), so "no receiver found" can be read correctly.
	WindowFrom *time.Time `json:"window_from,omitempty"`
	WindowTo   *time.Time `json:"window_to,omitempty"`
	Scanned    int        `json:"scanned"`
	Partial    bool       `json:"partial"`
}

// PackageReceivers scans the flow telemetry for artifact deliveries of a package and aggregates them
// per server. It matches on ecosystem+name (required) and, when given, version and/or sha256. The
// search covers the retained flow window held by this node; a note in the result marks that it is not
// the complete history (see docs/package-firewall.md).
func (s *Store) PackageReceivers(ecosystem, name, version, sha256 string) PackageReceiversResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	norm := ""
	if ecosystem != "" {
		norm = normalizePackageName(ecosystem, name)
	}
	res := PackageReceiversResult{Ecosystem: ecosystem, Name: norm, Version: version, SHA256: strings.ToLower(sha256)}
	byServer := map[string]*PackageReceiver{}
	for i := range s.state.Flows {
		f := &s.state.Flows[i]
		p := f.Package
		if p == nil || p.Kind != models.FlowPkgArtifact {
			continue
		}
		res.Scanned++
		if ecosystem != "" && p.Ecosystem != ecosystem {
			continue
		}
		if norm != "" && p.Name != norm {
			continue
		}
		if version != "" && p.Version != version {
			continue
		}
		if res.SHA256 != "" && !strings.EqualFold(p.SHA256, res.SHA256) {
			continue
		}
		key := f.ServerID
		if key == "" {
			key = "ip:" + f.ServerIP
		}
		rcv := byServer[key]
		if rcv == nil {
			rcv = &PackageReceiver{ServerID: f.ServerID, Hostname: f.ServerHostname, IP: f.ServerIP, GroupIDs: f.GroupIDs}
			byServer[key] = rcv
		}
		if rcv.FirstSeen.IsZero() || f.Timestamp.Before(rcv.FirstSeen) {
			rcv.FirstSeen = f.Timestamp
		}
		if f.Timestamp.After(rcv.LastSeen) {
			rcv.LastSeen = f.Timestamp
			rcv.LastStatus = f.StatusCode
		}
		rcv.Count++
		addUnique(&rcv.Files, p.Filename)
		addUnique(&rcv.Versions, p.Version)
		addUnique(&rcv.Decisions, p.Decision)
		if res.WindowFrom == nil || f.Timestamp.Before(*res.WindowFrom) {
			t := f.Timestamp
			res.WindowFrom = &t
		}
		if res.WindowTo == nil || f.Timestamp.After(*res.WindowTo) {
			t := f.Timestamp
			res.WindowTo = &t
		}
	}
	for _, rcv := range byServer {
		res.Receivers = append(res.Receivers, *rcv)
	}
	sort.SliceStable(res.Receivers, func(i, j int) bool { return res.Receivers[i].LastSeen.After(res.Receivers[j].LastSeen) })
	// The in-memory window holds only the most recent flows; the complete history lives in the log
	// export / SIEM. Flag that the answer is bounded by what this node retains.
	res.Partial = len(s.state.Flows) >= maxFlows
	return res
}

func addUnique(list *[]string, v string) {
	if v == "" {
		return
	}
	for _, x := range *list {
		if x == v {
			return
		}
	}
	if len(*list) < 32 {
		*list = append(*list, v)
	}
}
