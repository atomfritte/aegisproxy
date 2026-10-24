package api

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metrics is a tiny dependency-free Prometheus text-format registry (counters + histogram sums).
type Metrics struct {
	mu       sync.Mutex
	counters map[string]float64
}

func NewMetrics() *Metrics { return &Metrics{counters: make(map[string]float64)} }

func escapeLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func seriesKey(name string, labels ...string) string {
	if len(labels) == 0 {
		return name
	}
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i := 0; i+1 < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, labels[i], escapeLabel(labels[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

func (m *Metrics) Add(v float64, name string, labels ...string) {
	k := seriesKey(name, labels...)
	m.mu.Lock()
	if _, ok := m.counters[k]; ok || len(m.counters) < 10_000 {
		m.counters[k] += v
	}
	m.mu.Unlock()
}

func (m *Metrics) Inc(name string, labels ...string) { m.Add(1, name, labels...) }

func (m *Metrics) ObserveHTTP(method, route string, status int, d time.Duration) {
	class := fmt.Sprintf("%dxx", status/100)
	m.Inc("aegis_http_requests_total", "method", method, "route", route, "code", class)
	m.Add(d.Seconds(), "aegis_http_request_duration_seconds_sum", "route", route)
	m.Inc("aegis_http_request_duration_seconds_count", "route", route)
}

func (m *Metrics) write(w io.Writer) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.counters))
	for k := range m.counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s %g\n", k, m.counters[k])
	}
	m.mu.Unlock()
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if tok := s.cfg.MetricsToken; tok != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
			writeError(w, http.StatusUnauthorized, "metrics token required")
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.write(w)

	snap := s.store.GetSnapshot()
	gauge := func(name, help string, v float64, labels ...string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, seriesKey(name, labels...), v)
	}
	gauge("aegis_build_info", "Build information.", 1, "version", s.version)
	gauge("aegis_uptime_seconds", "Control-plane uptime.", time.Since(s.started).Seconds())
	gauge("aegis_config_revision", "Current policy configuration revision.", float64(snap.Revision))
	gauge("aegis_policy_rules", "Configured whitelist/guardrail rules.", float64(len(snap.Rules)))
	gauge("aegis_servers", "Registered servers.", float64(len(snap.Servers)))
	pending, open := 0, 0
	for _, rq := range snap.Requests {
		if rq.Status == "pending" {
			pending++
		}
	}
	for _, ev := range snap.SecurityEvents {
		if !ev.Acknowledged {
			open++
		}
	}
	gauge("aegis_access_requests_pending", "Access requests awaiting review.", float64(pending))
	gauge("aegis_security_events_open", "Unacknowledged security events.", float64(open))
	audit := s.store.AuditStatus()
	writable, intact, pendingLegacy := 0.0, 0.0, 0.0
	if audit.Writable {
		writable = 1
	}
	if audit.Integrity == "" {
		intact = 1
	}
	if audit.LegacyPending {
		pendingLegacy = 1
	}
	gauge("aegis_audit_log_writable", "1 while the audit log can be written (file storage refuses changes otherwise).", writable)
	gauge("aegis_audit_trail_intact", "0 after an audit trail integrity violation (missing or invalid anchor or checkpoint, diverged trail).", intact)
	gauge("aegis_audit_legacy_pending", "1 while unkeyed pre-2.1 audit events await acceptance by a Super Admin.", pendingLegacy)
	if ti := s.store.ThreatIntel(); ti != nil {
		st := ti.Snapshot().Status()
		gauge("aegis_threatintel_indicators", "Compiled threat-intel indicators.", float64(st.Domains+st.URLs+st.IPs+st.CIDRs+st.Hashes))
		gauge("aegis_threatintel_active_feeds", "Enabled feeds with content.", float64(st.ActiveFeeds))
		for _, f := range ti.FeedsWithStatus(s.store.ThreatFeedConfigs()) {
			if !f.Enabled {
				continue
			}
			age := -1.0
			if f.LastSuccessAt != nil {
				age = time.Since(*f.LastSuccessAt).Seconds()
			}
			fmt.Fprintf(w, "%s %g\n", seriesKey("aegis_threatintel_feed_age_seconds", "feed", f.ID), age)
			fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_threatintel_feed_entries", "feed", f.ID), f.EntryCount)
		}
	}
	healthy := 0
	for _, dp := range s.DataPlanes() {
		if dp.Healthy {
			healthy++
		}
	}
	gauge("aegis_dataplanes_healthy", "Data-plane workers with a heartbeat in the last 60s.", float64(healthy))
	for _, st := range s.exporter.Status() {
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_records_sent_total", "sink", st.ID), st.Sent)
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_records_failed_total", "sink", st.ID), st.Failed)
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_records_dropped_total", "sink", st.ID), st.Dropped)
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_batches_discarded_total", "sink", st.ID), st.DiscardedBatches)
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_queue_records", "sink", st.ID), st.Queued)
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_spool_bytes", "sink", st.ID), st.SpoolBytes)
		up := 0
		if st.State == "ok" || st.State == "idle" {
			up = 1
		}
		fmt.Fprintf(w, "%s %d\n", seriesKey("aegis_export_sink_healthy", "sink", st.ID), up)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	gauge("aegis_go_heap_bytes", "Go heap in use.", float64(ms.HeapInuse))
	gauge("aegis_go_goroutines", "Goroutines.", float64(runtime.NumGoroutine()))
}
