package api

import (
	"net/http"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
)

func (s *Server) handleListExports(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only InfoSec Approvers and Super Admins can view log export settings")
		return
	}
	status := s.exporter.Status()
	if status == nil {
		status = []models.ExportSinkStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sinks": s.store.ExportSinks(), "status": status, "types": export.Types,
		"export_dir": s.cfg.ExportDir, "can_edit": claims.Role == models.RoleSuperAdmin,
	})
}

func (s *Server) handleSaveExport(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in models.ExportSink
	if !decodeJSON(w, r, &in) {
		return
	}
	in.ID = r.PathValue("id")
	out, err := s.store.UpsertExportSink(in, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteExport(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteExportSink(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleTestExport sends one synthetic record with the given (possibly unsaved) configuration.
// Omitted secrets are taken from the stored sink with the same id.
func (s *Server) handleTestExport(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only InfoSec Approvers and Super Admins can test log export destinations")
		return
	}
	var in models.ExportSink
	if !decodeJSON(w, r, &in) {
		return
	}
	var sink models.ExportSink
	if claims.Role == models.RoleSuperAdmin {
		var err error
		if sink, err = s.store.MergeExportSecretsForTest(in); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		// Destinations are configured by Super Admins; everybody else tests the saved destination as is.
		stored, ok := s.store.ExportSinkWithSecrets(in.ID)
		if !ok {
			writeError(w, http.StatusForbidden, "RBAC Policy: only Super Admins can test unsaved log export destinations")
			return
		}
		sink = stored
	}
	if err := export.Validate(&sink); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.exporter == nil {
		writeError(w, http.StatusServiceUnavailable, "log export is not initialized")
		return
	}
	if err := s.exporter.Test(r.Context(), sink); err != nil {
		msg := err.Error()
		if claims.Role != models.RoleSuperAdmin {
			msg = export.ShortError(msg) // response bodies of the destination are not shown
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
