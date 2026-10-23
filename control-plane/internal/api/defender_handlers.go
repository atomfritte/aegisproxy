package api

import (
	"context"
	"net/http"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

func (s *Server) defenderRoutes() {
	s.mux.HandleFunc("GET /api/integrations/defender", s.authed(s.handleGetDefender))
	s.mux.HandleFunc("PUT /api/integrations/defender", s.authed(s.handleUpdateDefender))
	s.mux.HandleFunc("POST /api/integrations/defender/test", s.authed(s.handleTestDefender))
	s.mux.HandleFunc("POST /api/integrations/defender/sync", s.authed(s.handleSyncDefender))
}

func (s *Server) handleGetDefender(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": s.store.DefenderConfigNormalized().Public(), "can_edit": claims.Role == models.RoleSuperAdmin && !claims.ServiceAccount,
		"permissions": []string{"Ti.ReadWrite.All (indicators; the API has no read-only permission)", "Machine.Read.All (devices)",
			"Machine.ReadWrite.All (only for quarantine on isolation: reads machine actions)"}})
}

func (s *Server) handleUpdateDefender(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var cfg models.DefenderConfig
	if !decodeJSON(w, r, &cfg) {
		return
	}
	out, err := s.store.UpdateDefenderConfig(cfg, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTestDefender(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	var cfg models.DefenderConfig
	if err := decodeOptionalJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	// Only Super Admins (who can change the configuration anyway) may test unsaved settings.
	if cfg.TenantID == "" || claims.Role != models.RoleSuperAdmin {
		cfg = s.store.DefenderConfig()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := s.store.TestDefender(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSyncDefender(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requireSystem(w, claims) {
		return
	}
	cfg := s.store.DefenderConfig()
	if !cfg.Enabled || (!cfg.DeviceSync && !cfg.ImportIndicators) {
		writeError(w, http.StatusConflict, "Nothing to synchronize: enable the integration and device sync or indicator import first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if cfg.DeviceSync {
		if err := s.store.SyncDefenderDevices(ctx, true); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if ti := s.store.ThreatIntel(); ti != nil && cfg.ImportIndicators {
		ti.RefreshNow("microsoft-defender-indicators")
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": s.store.DefenderConfigNormalized().Public(),
		"devices_synced": cfg.DeviceSync, "indicators_refreshing": cfg.ImportIndicators})
}
