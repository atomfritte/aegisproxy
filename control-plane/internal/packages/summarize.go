// Package packages is the control-plane core of the package firewall: it resolves dependency graphs,
// assesses versions (advisories, signatures, provenance, sandbox behavior), applies rules and cooldown,
// and drives the sandbox analysis workers. This file turns a raw sandbox report into the compact
// summary and findings stored with an assessment.
package packages

import (
	"fmt"
	"sort"
	"strings"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sandbox"
)

// maxSummaryList bounds each list in the stored summary (the full detail stays in the report store).
const maxSummaryList = 200

// SummarizeReport condenses a sandbox report into the result + findings kept with an assessment. It
// collects every web URL / host / DNS name the package reached and the aggregate system-call
// histogram across all phases — the behavior reviewers and the user asked to see.
func SummarizeReport(rep *sandbox.Report, reportKey string) (*models.PackageSandboxResult, []models.PackageFinding) {
	res := &models.PackageSandboxResult{
		Status: models.AnalysisCompleted, Driver: rep.Driver, StartedAt: rep.StartedAt, FinishedAt: rep.FinishedAt,
		ReportKey: reportKey, SyscallCounts: map[string]int64{},
	}
	urls := newStringSet()
	hosts := newStringSet()
	dns := newStringSet()
	procs := newStringSet()
	writes := newStringSet()
	secrets := newStringSet()

	for _, ph := range rep.Phases {
		for _, q := range ph.Network.DNS {
			dns.add(q.Name)
			hosts.add(q.Name)
		}
		for _, h := range ph.Network.HTTP {
			if h.URL != "" {
				urls.add(h.Method + " " + h.URL)
			}
			hosts.add(h.Host)
		}
		for _, c := range ph.Network.Connections {
			if c.Hostname != "" {
				hosts.add(c.Hostname)
			}
			target := c.Address
			if c.Port != 0 {
				target = fmt.Sprintf("%s:%d", c.Address, c.Port)
			}
			urls.add(strings.TrimSpace(c.Protocol + " " + target))
		}
		for name, n := range ph.Syscalls.Counts {
			res.SyscallCounts[name] += n
		}
		for _, p := range ph.Processes {
			procs.add(strings.Join(p.Argv, " "))
		}
		for _, f := range ph.Files.Written {
			writes.add(f.Path)
		}
		for _, f := range ph.Files.ReadSensitive {
			secrets.add(f.Path)
		}
		res.CanaryHits += len(ph.CanaryHits)
	}
	res.URLs = urls.sorted()
	res.Hosts = hosts.sorted()
	res.DNSNames = dns.sorted()
	res.Processes = procs.sorted()
	res.FilesWritten = writes.sorted()
	res.SecretsRead = secrets.sorted()

	findings := make([]models.PackageFinding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		findings = append(findings, models.PackageFinding{
			ID: f.ID, Severity: f.Severity, Category: f.Category, Title: f.Title,
			Detail: joinEvidence(f.Detail, f.Evidence), Source: "sandbox",
		})
	}
	sortFindings(findings)
	return res, findings
}

// SandboxRisk is the risk level implied by the sandbox findings alone.
func SandboxRisk(findings []models.PackageFinding) string {
	risk := models.RiskNone
	for _, f := range findings {
		if models.RiskRank(f.Severity) > models.RiskRank(risk) {
			risk = f.Severity
		}
	}
	return risk
}

func joinEvidence(detail string, evidence []string) string {
	if len(evidence) == 0 {
		return detail
	}
	ev := evidence
	if len(ev) > 10 {
		ev = ev[:10]
	}
	if detail == "" {
		return strings.Join(ev, "; ")
	}
	return detail + " — " + strings.Join(ev, "; ")
}

func sortFindings(f []models.PackageFinding) {
	sort.SliceStable(f, func(i, j int) bool {
		return models.RiskRank(f[i].Severity) > models.RiskRank(f[j].Severity)
	})
}

// stringSet keeps insertion-bounded, de-duplicated, sorted string lists.
type stringSet struct {
	seen map[string]struct{}
	full bool
}

func newStringSet() *stringSet { return &stringSet{seen: map[string]struct{}{}} }

func (s *stringSet) add(v string) {
	v = strings.TrimSpace(v)
	if v == "" || s.full {
		return
	}
	if _, ok := s.seen[v]; ok {
		return
	}
	if len(s.seen) >= maxSummaryList {
		s.full = true
		return
	}
	s.seen[v] = struct{}{}
}

func (s *stringSet) sorted() []string {
	out := make([]string, 0, len(s.seen))
	for v := range s.seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
