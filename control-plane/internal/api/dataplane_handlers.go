package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

func (s *Server) verifyDataPlaneKey(r *http.Request) bool {
	provided := strings.TrimSpace(r.Header.Get("X-Aegis-DataPlane-Key"))
	return provided != "" && hmac.Equal([]byte(provided), []byte(s.cfg.DataPlaneKey))
}

func (s *Server) dataPlaneOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.verifyDataPlaneKey(r) {
			s.metrics.Inc("aegis_dataplane_auth_failures_total")
			s.log.Warn("rejected data-plane request with invalid key", "path", r.URL.Path, "client_ip", s.clientIP(r))
			writeError(w, http.StatusUnauthorized, "Unauthorized data-plane worker: valid X-Aegis-DataPlane-Key required")
			return
		}
		h(w, r)
	}
}

func clipHeader(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		v = v[:n]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

func (s *Server) recordHeartbeat(r *http.Request, bundleRev, threatVer string) {
	id := clipHeader(r.Header.Get("X-Aegis-DataPlane-ID"), 64)
	if id == "" {
		id = "dp-" + s.clientIP(r)
	}
	s.dpMu.Lock()
	defer s.dpMu.Unlock()
	st := s.dataPlanes[id]
	if st == nil {
		if len(s.dataPlanes) >= 512 {
			// Worker IDs churn with pod restarts: forget workers that stopped reporting, then the oldest.
			var oldestID string
			var oldest time.Time
			for k, v := range s.dataPlanes {
				if time.Since(v.LastSeenAt) > 15*time.Minute {
					delete(s.dataPlanes, k)
				} else if oldestID == "" || v.LastSeenAt.Before(oldest) {
					oldestID, oldest = k, v.LastSeenAt
				}
			}
			if len(s.dataPlanes) >= 512 {
				delete(s.dataPlanes, oldestID)
			}
		}
		st = &DataPlaneStatus{ID: id}
		s.dataPlanes[id] = st
	}
	st.Version = clipHeader(r.Header.Get("X-Aegis-DataPlane-Version"), 32)
	st.ClamAVAvailable = clipHeader(r.Header.Get("X-Aegis-ClamAV"), 16)
	st.YARAStatus = clipHeader(r.Header.Get("X-Aegis-YARA"), 320)
	st.ICAPStatus = clipHeader(r.Header.Get("X-Aegis-ICAP"), 160)
	st.RemoteIP = s.clientIP(r)
	st.LastSeenAt = time.Now().UTC()
	st.PolicyAgeSeconds = headerSeconds(r, "X-Aegis-Policy-Age")
	st.PolicyMaxAgeSeconds = headerSeconds(r, "X-Aegis-Policy-Max-Age")
	st.FlowBacklog = max(headerSeconds(r, "X-Aegis-Flow-Backlog"), 0)
	st.FlowsDropped, st.FlowsDroppedTotal = parseFlowDrops(r.Header.Get("X-Aegis-Flows-Dropped"))
	if bundleRev != "" {
		st.BundleRevision = bundleRev
	}
	if threatVer != "" {
		st.ThreatVersion = threatVer
	}
}

// headerSeconds parses a non-negative integer heartbeat header (-1 when absent or invalid: older worker).
func headerSeconds(r *http.Request, name string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(r.Header.Get(name)), 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// parseFlowDrops parses the worker's lost-flow counters ("0" or "overflow=12,rejected=1").
func parseFlowDrops(v string) (map[string]int64, int64) {
	var out map[string]int64
	var total int64
	for i, part := range strings.Split(clipHeader(v, 256), ",") {
		reason, num, ok := strings.Cut(part, "=")
		reason = strings.TrimSpace(reason)
		n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
		if !ok || err != nil || n <= 0 || i >= 8 || reason == "" || len(reason) > 32 ||
			strings.Trim(reason, "abcdefghijklmnopqrstuvwxyz_") != "" {
			continue
		}
		if out == nil {
			out = map[string]int64{}
		}
		out[reason] = n
		total += n
	}
	return out, total
}

// DataPlanes returns the known data-plane workers (healthy = heartbeat within 60s).
func (s *Server) DataPlanes() []DataPlaneStatus {
	s.dpMu.Lock()
	defer s.dpMu.Unlock()
	out := make([]DataPlaneStatus, 0, len(s.dataPlanes))
	for _, st := range s.dataPlanes {
		cp := *st
		cp.Healthy = time.Since(st.LastSeenAt) < 60*time.Second
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type dpGroup struct {
	ID                string   `json:"id"`
	CIDRs             []string `json:"cidrs"`
	StrictIsolation   bool     `json:"strict_isolation"`
	RequireProxyToken bool     `json:"require_proxy_token"`
}

type dpServer struct {
	ID                 string   `json:"id"`
	Hostname           string   `json:"hostname"`
	IP                 string   `json:"ip"`
	SubnetCIDR         string   `json:"subnet_cidr"`
	ProxyAuthUser      string   `json:"proxy_auth_user"`
	ProxyAuthTokenHash string   `json:"proxy_auth_token_hash"`
	GroupIDs           []string `json:"group_ids"` // effective memberships (static + label-matched)
	Quarantined        bool     `json:"quarantined,omitempty"`
}

type dpSession struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ServerID  string    `json:"server_id"`
	ServerIP  string    `json:"server_ip"`
	Mode      string    `json:"mode"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// dpBundleCache is the memoized data-plane bundle (see Server.dpBundle). Its payload is treated as
// immutable once stored, so concurrent polls can read it without copying or locking.
type dpBundleCache struct {
	gen        uint64    // store bundle generation this was built from
	threatVer  string    // threat-intel snapshot version this was built from
	validUntil time.Time // earliest expiry of an included rule/session/bypass (zero = none)
	etag       string
	payload    map[string]any
}

func (s *Server) handleDataPlaneBundle(w http.ResponseWriter, r *http.Request) {
	gen := s.store.BundleGeneration()
	rev := s.store.GetRevision()
	threatVer := ""
	if ti := s.store.ThreatIntel(); ti != nil {
		threatVer = ti.Snapshot().Version
	}
	s.recordHeartbeat(r, fmt.Sprint(rev), r.Header.Get("X-Aegis-Threat-Version"))
	now := time.Now()

	// Fast path: nothing data-plane-relevant changed (same bundle generation + threat version) and
	// nothing included has expired since the bundle was built. Serve the cached bundle / a 304 without
	// snapshotting or rebuilding — this is the common case on every worker poll.
	s.dpBundleMu.Lock()
	if c := s.dpBundle; c != nil && c.gen == gen && c.threatVer == threatVer && (c.validUntil.IsZero() || now.Before(c.validUntil)) {
		etag, payload := c.etag, c.payload
		s.dpBundleMu.Unlock()
		s.writeDataPlaneBundle(w, r, etag, payload, rev, now)
		return
	}
	s.dpBundleMu.Unlock()

	// Rebuild (the expensive path, now only on a real change): snapshot the state and assemble the bundle.
	snap := s.store.GetSnapshot()
	policy := snap.SecurityPolicy
	policy.TelemetryQueryRedaction = store.NormalizeRedactionMode(policy.TelemetryQueryRedaction)

	groups := make([]dpGroup, 0, len(snap.Groups))
	for _, g := range snap.Groups {
		groups = append(groups, dpGroup{ID: g.ID, CIDRs: g.CIDRs, StrictIsolation: g.StrictIsolation, RequireProxyToken: g.RequireProxyToken})
	}
	servers := make([]dpServer, 0, len(snap.Servers))
	for _, srv := range snap.Servers {
		servers = append(servers, dpServer{
			ID: srv.ID, Hostname: srv.Hostname, IP: srv.IP, SubnetCIDR: srv.SubnetCIDR,
			ProxyAuthUser: srv.ProxyAuthUser, ProxyAuthTokenHash: srv.ProxyAuthTokenHash, GroupIDs: srv.EffectiveGroupIDs,
			Quarantined: srv.Quarantined,
		})
	}
	// Track the earliest future expiry among the entries we include, so the cache is invalidated exactly
	// when the bundle content would next change due to a rule/session/bypass expiring.
	var validUntil time.Time
	trackExpiry := func(t time.Time) {
		if !t.IsZero() && (validUntil.IsZero() || t.Before(validUntil)) {
			validUntil = t
		}
	}
	sessions := make([]dpSession, 0)
	for _, sess := range snap.Sessions {
		if sess.Status == "active" && now.Before(sess.ExpiresAt) {
			sessions = append(sessions, dpSession{ID: sess.ID, Name: sess.Name, ServerID: sess.ServerID, ServerIP: sess.ServerIP,
				Mode: sess.Mode, Status: sess.Status, ExpiresAt: sess.ExpiresAt})
			trackExpiry(sess.ExpiresAt)
		}
	}
	rules := make([]models.PolicyRule, 0, len(snap.Rules))
	for _, rule := range snap.Rules {
		if rule.Enabled && (rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt)) {
			if rule.ExpiresAt != nil {
				trackExpiry(*rule.ExpiresAt)
			}
			rule.Description = ""
			rules = append(rules, rule)
		}
	}
	tls := make([]models.TLSBypassRule, 0, len(snap.TLSBypass))
	for _, b := range snap.TLSBypass {
		if b.Enabled && (b.ExpiresAt == nil || now.Before(*b.ExpiresAt)) {
			if b.ExpiresAt != nil {
				trackExpiry(*b.ExpiresAt)
			}
			tls = append(tls, b)
		}
	}
	yaraSets := []map[string]string{}
	for _, rs := range s.store.YaraRuleSets() {
		if rs.Enabled {
			yaraSets = append(yaraSets, map[string]string{"id": rs.ID, "name": rs.Name, "source": rs.Source})
		}
	}
	payload := map[string]any{
		"revision":             snap.Revision,
		"yara_rule_sets":       yaraSets,
		"rules":                rules,
		"tls_bypass":           tls,
		"sessions":             sessions,
		"groups":               groups,
		"servers":              servers,
		"security_policy":      policy,
		"threat_intel_version": threatVer,
		"block_pages":          s.blockPageBundle(snap.Revision),
		"internal_domains":     s.cfg.InternalSuffix,
		"public_url":           s.cfg.PublicURL,
		"dashboard_url":        s.cfg.DashboardURL,
		"packages":             s.store.PackageBundle(s.consoleURL("")),
	}
	// The ETag is the hash of the bundle content, not the configuration revision: changes that do not
	// affect the data-plane (for example package requests or analysis jobs advancing) bump the revision
	// for cluster replication but leave this ETag — and the bundle generation — unchanged, so workers
	// keep their bundle (304).
	etag := bundleETag(payload)

	s.dpBundleMu.Lock()
	s.dpBundle = &dpBundleCache{gen: gen, threatVer: threatVer, validUntil: validUntil, etag: etag, payload: payload}
	s.dpBundleMu.Unlock()

	s.writeDataPlaneBundle(w, r, etag, payload, rev, now)
}

// writeDataPlaneBundle answers with a 304 when the worker's ETag matches, otherwise the bundle with a
// fresh synced_at and the current revision. The cached payload is never mutated — these volatile fields
// go onto a shallow copy, and neither is part of the ETag.
func (s *Server) writeDataPlaneBundle(w http.ResponseWriter, r *http.Request, etag string, payload map[string]any, rev uint64, now time.Time) {
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	out := make(map[string]any, len(payload)+2)
	for k, v := range payload {
		out[k] = v
	}
	out["revision"] = rev
	out["synced_at"] = now.UTC()
	writeJSON(w, http.StatusOK, out)
}

// bundleETag is a stable hash of the data-plane-relevant bundle content. The configuration revision is
// excluded, so a revision bump that did not change the bundle (for example a package request or an
// analysis job advancing) does not invalidate the workers' cached bundle. Go's json.Marshal sorts map
// keys, so the encoding is deterministic.
func bundleETag(payload map[string]any) string {
	hashed := make(map[string]any, len(payload))
	for k, v := range payload {
		if k == "revision" || k == "synced_at" {
			continue
		}
		hashed[k] = v
	}
	b, err := json.Marshal(hashed)
	if err != nil {
		return fmt.Sprintf(`"rev-%v"`, payload["revision"])
	}
	sum := sha256.Sum256(b)
	return `"b-` + hex.EncodeToString(sum[:16]) + `"`
}

func (s *Server) handleDataPlaneThreatIntel(w http.ResponseWriter, r *http.Request) {
	ti := s.store.ThreatIntel()
	if ti == nil {
		writeError(w, http.StatusServiceUnavailable, "threat intelligence not initialized")
		return
	}
	snap := ti.Snapshot()
	etag := fmt.Sprintf(`"ti-%s"`, snap.Version)
	s.recordHeartbeat(r, "", r.Header.Get("X-Aegis-Threat-Version"))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	gz, err := snap.ExportGzip()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Vary", "Accept-Encoding")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(gz)))
		_, _ = w.Write(gz)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export failed")
		return
	}
	_, _ = io.Copy(w, zr)
}

func (s *Server) handleDataPlaneEvaluate(w http.ResponseWriter, r *http.Request) {
	var req engine.EvaluationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res := s.store.Evaluate(req)
	s.metrics.Inc("aegis_evaluations_total", "verdict", res.Verdict)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDataPlaneRecordFlow(w http.ResponseWriter, r *http.Request) {
	var flow models.TrafficFlow
	if !decodeJSON(w, r, &flow) {
		return
	}
	recorded, _, ok := s.ingestFlowBatch(w, r, []models.TrafficFlow{flow})
	if !ok {
		return
	}
	id := flow.ID // a resend of a flow that is stored already
	if len(recorded) == 1 {
		id = recorded[0].ID
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

const maxFlowBatch = 1000

// handleDataPlaneRecordFlowBatch acknowledges (201) only once the flows are stored durably: fsync'd to the flow
// journal (file storage) or committed to PostgreSQL (cluster). Otherwise 503 + Retry-After: the worker keeps the batch
// and resends it; flows it delivered before are recognized by their ID (duplicate_count).
func (s *Server) handleDataPlaneRecordFlowBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Flows []models.TrafficFlow `json:"flows"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if len(body.Flows) > maxFlowBatch {
		s.store.CountFlowDrops("batch_too_large", len(body.Flows))
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("at most %d flows per batch", maxFlowBatch))
		return
	}
	recorded, dups, ok := s.ingestFlowBatch(w, r, body.Flows)
	if !ok {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"recorded_count": len(recorded), "duplicate_count": dups})
}

func (s *Server) ingestFlowBatch(w http.ResponseWriter, r *http.Request, flows []models.TrafficFlow) ([]models.TrafficFlow, int, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	recorded, dups, err := s.store.IngestFlowBatch(ctx, flows)
	if err != nil {
		s.metrics.Inc("aegis_flow_batches_refused_total")
		s.log.Warn("flow batch refused: telemetry storage unavailable; the worker retries", "flows", len(flows), "error", err)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "telemetry storage unavailable; retry later")
		return nil, 0, false
	}
	for _, f := range recorded {
		s.metrics.Inc("aegis_flows_total", "verdict", f.Verdict)
	}
	return recorded, dups, true
}
