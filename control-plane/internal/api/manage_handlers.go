package api

import (
	"net/http"
	"strings"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

// ---------------------------------------------------------------------------
// Identity administration (Super Admin)
// ---------------------------------------------------------------------------

func (s *Server) handleUpsertUser(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in store.UserInput
	if !decodeJSON(w, r, &in) {
		return
	}
	u, generated, err := s.store.UpsertUser(in, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	resp := map[string]any{"user": u}
	if generated != "" {
		resp["temporary_password"] = generated
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteUser(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	pw, err := s.store.ResetUserPassword(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"temporary_password": pw})
}

// ---------------------------------------------------------------------------
// Fleet inventory (InfoSec / Super Admin)
// ---------------------------------------------------------------------------

func (s *Server) handleUpsertGroup(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var g models.ServerGroup
	if !decodeJSON(w, r, &g) {
		return
	}
	saved, err := s.store.UpsertGroup(g, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteGroup(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUpsertServer(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var srv models.Server
	if !decodeJSON(w, r, &srv) {
		return
	}
	saved, err := s.store.UpsertServer(srv, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved.Public())
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteServer(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	srv, token, err := s.store.RotateServerToken(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"server":          srv.Public(),
		"proxy_auth_user": srv.ProxyAuthUser,
		"token":           token,
		"proxy_url_hint":  "http://" + srv.ProxyAuthUser + ":" + token + "@" + s.cfg.ProxyAddress,
		"onboarding":      s.onboarding(srv, token),
		"note":            "This token is shown only once. Store it in the server's secret store / proxy configuration.",
	})
}

// ---------------------------------------------------------------------------
// Threat protection
// ---------------------------------------------------------------------------

func (s *Server) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var p models.SecurityPolicy
	if !decodeJSON(w, r, &p) {
		return
	}
	saved, err := s.store.UpdateSecurityPolicy(p, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleUpsertFeed(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var f models.ThreatFeed
	if !decodeJSON(w, r, &f) {
		return
	}
	saved, err := s.store.UpsertThreatFeed(f, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteFeed(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteThreatFeed(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleRefreshFeeds(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	_ = decodeOptionalJSON(r, &body)
	ti := s.store.ThreatIntel()
	if ti == nil {
		writeError(w, http.StatusServiceUnavailable, "threat intelligence not initialized")
		return
	}
	ti.RefreshNow(strings.TrimSpace(body.ID))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refresh_scheduled"})
}

func (s *Server) handleAddIndicator(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var ind models.Indicator
	if !decodeJSON(w, r, &ind) {
		return
	}
	saved, err := s.store.AddIndicator(ind, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDeleteIndicator(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteIndicator(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAddException(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var ex models.ThreatException
	if !decodeJSON(w, r, &ex) {
		return
	}
	saved, err := s.store.AddThreatException(ex, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDeleteException(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteThreatException(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAckEvent(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.AcknowledgeSecurityEvent(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// handleThreatLookup lets analysts check a URL, domain, IP or file hash against all active
// threat-intelligence sources (read-only, available to every role).
func (s *Server) handleThreatLookup(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Value string `json:"value"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	v := strings.TrimSpace(body.Value)
	if v == "" || len(v) > 4096 {
		writeError(w, http.StatusBadRequest, "value must be a URL, domain, IP address or SHA-256 hash")
		return
	}
	ti := s.store.ThreatIntel()
	if ti == nil {
		writeError(w, http.StatusServiceUnavailable, "threat intelligence not initialized")
		return
	}
	snap := ti.Snapshot()
	matches := snap.Lookup(v)
	writeJSON(w, http.StatusOK, map[string]any{
		"value":     v,
		"malicious": len(matches) > 0,
		"matches":   matches,
		"version":   snap.Version,
	})
}

func decodeOptionalJSON(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	return jsonDecode(r, v)
}

func (s *Server) handleListYara(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	sets := s.store.YaraRuleSets()
	if claims.Role == models.RoleTeamLead {
		// Detection content is need-to-know: Team Leads see which rule sets exist, not their source.
		for i := range sets {
			sets[i].Source = ""
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule_sets": sets, "data_planes": s.DataPlanes()})
}

func (s *Server) handleSaveYara(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var rs models.YaraRuleSet
	if !decodeJSON(w, r, &rs) {
		return
	}
	rs.ID = r.PathValue("id")
	out, err := s.store.UpsertYaraRuleSet(rs, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteYara(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteYaraRuleSet(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
