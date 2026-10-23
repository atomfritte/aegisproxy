package api

import (
	"net/http"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/store"
)

func (s *Server) serviceAccountRoutes() {
	s.mux.HandleFunc("GET /api/service-accounts", s.authed(s.handleListServiceAccounts))
	s.mux.HandleFunc("POST /api/service-accounts", s.authed(s.handleCreateServiceAccount))
	s.mux.HandleFunc("PUT /api/service-accounts/{id}", s.authed(s.handleUpdateServiceAccount))
	s.mux.HandleFunc("POST /api/service-accounts/{id}/rotate", s.authed(s.handleRotateServiceAccount))
	s.mux.HandleFunc("DELETE /api/service-accounts/{id}", s.authed(s.handleDeleteServiceAccount))
}

func (s *Server) handleListServiceAccounts(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only InfoSec Approvers and Super Admins can view service accounts")
		return
	}
	writeJSON(w, http.StatusOK, s.store.ServiceAccounts())
}

func (s *Server) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in store.ServiceAccountInput
	if !decodeJSON(w, r, &in) {
		return
	}
	sa, key, err := s.store.CreateServiceAccount(in, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"service_account": sa, "api_key": key,
		"note": "The API key is shown only once. Use it as 'Authorization: Bearer <key>'."})
}

func (s *Server) handleUpdateServiceAccount(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in store.ServiceAccountInput
	if !decodeJSON(w, r, &in) {
		return
	}
	sa, err := s.store.UpdateServiceAccount(r.PathValue("id"), in, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sa)
}

func (s *Server) handleRotateServiceAccount(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	sa, key, err := s.store.RotateServiceAccountKey(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_account": sa, "api_key": key})
}

func (s *Server) handleDeleteServiceAccount(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteServiceAccount(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
