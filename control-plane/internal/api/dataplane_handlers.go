package api

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
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
	if bundleRev != "" {
		st.BundleRevision = bundleRev
	}
	if threatVer != "" {
		st.ThreatVersion = threatVer
	}
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

func (s *Server) handleDataPlaneBundle(w http.ResponseWriter, r *http.Request) {
	rev := s.store.GetRevision()
	threatVer := ""
	if ti := s.store.ThreatIntel(); ti != nil {
		threatVer = ti.Snapshot().Version
	}
	etag := fmt.Sprintf(`"rev-%d-%s"`, rev, threatVer)
	s.recordHeartbeat(r, fmt.Sprint(rev), r.Header.Get("X-Aegis-Threat-Version"))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	snap := s.store.GetSnapshot()

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
	now := time.Now()
	sessions := make([]dpSession, 0)
	for _, sess := range snap.Sessions {
		if sess.Status == "active" && now.Before(sess.ExpiresAt) {
			sessions = append(sessions, dpSession{ID: sess.ID, Name: sess.Name, ServerID: sess.ServerID, ServerIP: sess.ServerIP,
				Mode: sess.Mode, Status: sess.Status, ExpiresAt: sess.ExpiresAt})
		}
	}
	rules := make([]models.PolicyRule, 0, len(snap.Rules))
	for _, rule := range snap.Rules {
		if rule.Enabled && (rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt)) {
			rule.Description = ""
			rules = append(rules, rule)
		}
	}
	tls := make([]models.TLSBypassRule, 0, len(snap.TLSBypass))
	for _, b := range snap.TLSBypass {
		if b.Enabled && (b.ExpiresAt == nil || now.Before(*b.ExpiresAt)) {
			tls = append(tls, b)
		}
	}
	yaraSets := []map[string]string{}
	for _, rs := range s.store.YaraRuleSets() {
		if rs.Enabled {
			yaraSets = append(yaraSets, map[string]string{"id": rs.ID, "name": rs.Name, "source": rs.Source})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revision":             snap.Revision,
		"yara_rule_sets":       yaraSets,
		"rules":                rules,
		"tls_bypass":           tls,
		"sessions":             sessions,
		"groups":               groups,
		"servers":              servers,
		"security_policy":      snap.SecurityPolicy,
		"threat_intel_version": threatVer,
		"block_pages":          s.blockPageBundle(snap.Revision),
		"internal_domains":     s.cfg.InternalSuffix,
		"public_url":           s.cfg.PublicURL,
		"dashboard_url":        s.cfg.DashboardURL,
		"synced_at":            time.Now().UTC(),
	})
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
	recorded := s.store.RecordFlow(flow)
	s.metrics.Inc("aegis_flows_total", "verdict", recorded.Verdict)
	writeJSON(w, http.StatusCreated, map[string]string{"id": recorded.ID})
}

func (s *Server) handleDataPlaneRecordFlowBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Flows []models.TrafficFlow `json:"flows"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if len(body.Flows) > 1000 {
		writeError(w, http.StatusRequestEntityTooLarge, "at most 1000 flows per batch")
		return
	}
	recorded := s.store.RecordFlowBatch(body.Flows)
	for _, f := range recorded {
		s.metrics.Inc("aegis_flows_total", "verdict", f.Verdict)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"recorded_count": len(recorded)})
}
