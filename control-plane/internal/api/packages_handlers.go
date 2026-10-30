package api

import (
	"context"
	"crypto/hmac"
	"net/http"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sandbox"
)

func (s *Server) packageRoutes() {
	// Console (read: any signed-in role; write: system role — enforced per handler).
	s.mux.HandleFunc("GET /api/packages/overview", s.authed(s.handlePackageOverview))
	s.mux.HandleFunc("POST /api/packages/settings", s.authed(s.handlePackageSettings))

	s.mux.HandleFunc("GET /api/packages/rules", s.authed(s.handlePackageRulesList))
	s.mux.HandleFunc("POST /api/packages/rules", s.authed(s.handlePackageRuleSave))
	s.mux.HandleFunc("PUT /api/packages/rules/{id}", s.authed(s.handlePackageRuleSave))
	s.mux.HandleFunc("DELETE /api/packages/rules/{id}", s.authed(s.handlePackageRuleDelete))
	s.mux.HandleFunc("POST /api/packages/rules/{id}/toggle", s.authed(s.handlePackageRuleToggle))

	s.mux.HandleFunc("GET /api/packages/blocks", s.authed(s.handlePackageBlocksList))
	s.mux.HandleFunc("POST /api/packages/blocks", s.authed(s.handlePackageBlockAdd))
	s.mux.HandleFunc("DELETE /api/packages/blocks/{id}", s.authed(s.handlePackageBlockDelete))

	s.mux.HandleFunc("GET /api/packages/approvals", s.authed(s.handlePackageApprovalsList))
	s.mux.HandleFunc("GET /api/packages/approvals/{id}", s.authed(s.handlePackageApprovalGet))
	s.mux.HandleFunc("POST /api/packages/approvals/{id}/revoke", s.authed(s.handlePackageApprovalRevoke))
	s.mux.HandleFunc("POST /api/packages/approvals/{id}/extend", s.authed(s.handlePackageApprovalExtend))

	s.mux.HandleFunc("GET /api/packages/requests", s.authed(s.handlePackageRequestsList))
	s.mux.HandleFunc("GET /api/packages/requests/{id}", s.authed(s.handlePackageRequestGet))
	s.mux.HandleFunc("POST /api/packages/requests", s.authed(s.handlePackageRequestCreate))
	s.mux.HandleFunc("POST /api/packages/requests/{id}/decision", s.authed(s.handlePackageRequestDecision))
	s.mux.HandleFunc("POST /api/packages/requests/{id}/reanalyze", s.authed(s.handlePackageRequestReanalyze))

	s.mux.HandleFunc("GET /api/packages/lookup", s.authed(s.handlePackageLookup))
	s.mux.HandleFunc("GET /api/packages/analysis/{id}", s.authed(s.handlePackageAnalysisReport))
	s.mux.HandleFunc("GET /api/packages/receivers", s.authed(s.handlePackageReceivers))

	// Sandbox workers (X-Aegis-Sandbox-Key).
	s.mux.HandleFunc("POST /api/sandbox/jobs/claim", s.sandboxOnly(s.handleSandboxClaim))
	s.mux.HandleFunc("POST /api/sandbox/jobs/{id}/heartbeat", s.sandboxOnly(s.handleSandboxHeartbeat))
	s.mux.HandleFunc("POST /api/sandbox/jobs/{id}/result", s.sandboxOnly(s.handleSandboxResult))
}

// requirePackageSystem gates writes to InfoSec Approvers and Super Admins (and never service accounts).
func (s *Server) requirePackageSystem(w http.ResponseWriter, claims *auth.TokenClaims) bool {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "Only InfoSec Approvers and Super Admins can change the package firewall")
		return false
	}
	return true
}

func (s *Server) packagesReady(w http.ResponseWriter) bool {
	if s.pkgs == nil || s.pkgSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "the package firewall is not enabled on this control-plane")
		return false
	}
	return true
}

// --- overview & settings ---

func (s *Server) handlePackageOverview(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	fw := s.store.PackageFirewall()
	requests := s.store.PackageRequests("", "")
	open := 0
	for _, rq := range requests {
		if rq.Status == models.PackageReqReady || rq.Status == models.PackageReqResolving || rq.Status == models.PackageReqAnalyzing {
			open++
		}
	}
	recent := requests
	if len(recent) > 10 {
		recent = recent[:10]
	}
	queued, running := 0, 0
	for _, j := range s.store.AnalysisJobs() {
		switch j.State {
		case models.AnalysisQueued:
			queued++
		case models.AnalysisRunning:
			running++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":        fw.Settings,
		"counts":          map[string]int{"approvals": countActive(fw.Approvals), "blocks": len(fw.Blocks), "rules": len(fw.Rules), "open_requests": open},
		"ecosystems":      s.ecosystemStats(fw),
		"recent_requests": recent,
		"analysis":        map[string]int{"queued": queued, "running": running},
		"can_edit":        auth.CanManageSystem(claims) && !claims.ServiceAccount,
	})
}

func (s *Server) ecosystemStats(fw models.PackageFirewall) []map[string]any {
	approvalsByEco := map[string]int{}
	for _, a := range fw.Approvals {
		if a.Status == "approved" {
			approvalsByEco[a.Ecosystem]++
		}
	}
	out := make([]map[string]any, 0, len(models.Ecosystems))
	for _, e := range models.Ecosystems {
		es := fw.Settings.Ecosystems[e]
		out = append(out, map[string]any{"ecosystem": e, "mode": es.Mode, "approvals": approvalsByEco[e]})
	}
	return out
}

func (s *Server) handlePackageSettings(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var in models.PackageSettings
	if !decodeJSON(w, r, &in) {
		return
	}
	fw, err := s.store.UpdatePackageSettings(in, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fw)
}

// --- rules ---

func (s *Server) handlePackageRulesList(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.store.PackageRules(), "can_edit": auth.CanManageSystem(claims)})
}

func (s *Server) handlePackageRuleSave(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var rule models.PackageRule
	if !decodeJSON(w, r, &rule) {
		return
	}
	if id := r.PathValue("id"); id != "" {
		rule.ID = id
	}
	out, err := s.store.SavePackageRule(rule, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePackageRuleDelete(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	if err := s.store.DeletePackageRule(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handlePackageRuleToggle(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	out, err := s.store.TogglePackageRule(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- blocks ---

func (s *Server) handlePackageBlocksList(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	writeJSON(w, http.StatusOK, map[string]any{"blocks": s.store.PackageBlocks(), "can_edit": auth.CanManageSystem(claims)})
}

func (s *Server) handlePackageBlockAdd(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var b models.PackageBlock
	if !decodeJSON(w, r, &b) {
		return
	}
	out, err := s.store.AddPackageBlock(b, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handlePackageBlockDelete(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	if err := s.store.DeletePackageBlock(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- approvals ---

func (s *Server) handlePackageApprovalsList(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	eco := r.URL.Query().Get("ecosystem")
	status := r.URL.Query().Get("status")
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	all := s.store.PackageApprovals()
	out := all[:0]
	for _, a := range all {
		if eco != "" && a.Ecosystem != eco {
			continue
		}
		if status != "" && a.Status != status {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(a.Name), q) {
			continue
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out, "can_edit": auth.CanManageSystem(claims)})
}

func (s *Server) handlePackageApprovalGet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	a, ok := s.store.PackageApproval(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handlePackageApprovalRevoke(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.store.RevokePackageApproval(r.PathValue("id"), claims.Username, string(claims.Role), body.Reason); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handlePackageApprovalExtend(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var body struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.store.ExtendPackageApproval(r.PathValue("id"), claims.Username, string(claims.Role), body.ExpiresAt); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// --- requests ---

func (s *Server) handlePackageRequestsList(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	reqs := s.store.PackageRequests(r.URL.Query().Get("status"), r.URL.Query().Get("ecosystem"))
	if r.URL.Query().Get("mine") == "1" {
		filtered := reqs[:0]
		for _, rq := range reqs {
			if rq.RequestedBy == claims.Username {
				filtered = append(filtered, rq)
			}
		}
		reqs = filtered
	}
	// The list view does not need the full graph.
	for i := range reqs {
		reqs[i].Graph = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": reqs, "can_review": auth.CanManageSystem(claims)})
}

func (s *Server) handlePackageRequestGet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	req, ok := s.store.PackageRequest(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": req, "can_review": auth.CanManageSystem(claims)})
}

func (s *Server) handlePackageRequestCreate(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.packagesReady(w) {
		return
	}
	var body struct {
		Ecosystem string   `json:"ecosystem"`
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		GroupIDs  []string `json:"group_ids"`
		Reason    string   `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	req := models.PackageRequest{
		Ecosystem: body.Ecosystem, Name: body.Name, DisplayName: body.Name, Requested: strings.TrimSpace(body.Version),
		GroupIDs: body.GroupIDs, Origin: "manual", RequestedBy: claims.Username, Reason: body.Reason,
	}
	// An exact version is kept as the concrete root; a range stays in Requested and is resolved.
	if v := strings.TrimSpace(body.Version); v != "" && !strings.ContainsAny(v, "^~*<>= ") {
		req.Version = v
	}
	created, err := s.pkgs.CreateRequest(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handlePackageRequestDecision(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) {
		return
	}
	var body struct {
		Decision string   `json:"decision"`
		Note     string   `json:"note"`
		GroupIDs []string `json:"group_ids"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	switch body.Decision {
	case "approve":
		n, err := s.store.ApproveRequestGraph(id, claims.Username, string(claims.Role), body.Note, body.GroupIDs)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "approvals_created": n})
	case "reject":
		if err := s.store.FailOrReject(id, "reject", "", body.Note); err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
	default:
		writeError(w, http.StatusBadRequest, "decision must be approve or reject")
	}
}

func (s *Server) handlePackageRequestReanalyze(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.requirePackageSystem(w, claims) || !s.packagesReady(w) {
		return
	}
	if err := s.pkgs.Reanalyze(r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reanalyzing"})
}

func (s *Server) handlePackageLookup(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.packagesReady(w) {
		return
	}
	q := r.URL.Query()
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	node, err := s.pkgs.Lookup(ctx, q.Get("ecosystem"), q.Get("name"), q.Get("version"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handlePackageAnalysisReport(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if s.pkgRepo == nil {
		writeError(w, http.StatusServiceUnavailable, "report store unavailable")
		return
	}
	rep, err := s.pkgRepo.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rep == nil {
		writeError(w, http.StatusNotFound, "no report for this analysis on this node")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handlePackageReceivers(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	q := r.URL.Query()
	res := s.store.PackageReceivers(q.Get("ecosystem"), q.Get("name"), q.Get("version"), q.Get("sha256"))
	writeJSON(w, http.StatusOK, res)
}

// --- sandbox worker API ---

func (s *Server) sandboxOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("X-Aegis-Sandbox-Key"))
		if s.cfg.SandboxKey == "" || key == "" || !hmac.Equal([]byte(key), []byte(s.cfg.SandboxKey)) {
			s.metrics.Inc("aegis_sandbox_auth_failures_total")
			writeError(w, http.StatusUnauthorized, "valid X-Aegis-Sandbox-Key required")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleSandboxClaim(w http.ResponseWriter, r *http.Request) {
	if !s.packagesReady(w) {
		return
	}
	var body struct {
		Ecosystems []string `json:"ecosystems"`
		Drivers    []string `json:"drivers"`
	}
	_ = decodeOptionalJSON(r, &body)
	worker := clipHeader(r.Header.Get("X-Aegis-Sandbox-Worker"), 64)
	job, err := s.store.ClaimAnalysis(worker, body.Ecosystems)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": sandboxJob(*job), "lease_seconds": analysisLease})
}

const analysisLease = 900

func sandboxJob(j models.AnalysisJob) sandbox.Job {
	return sandbox.Job{
		ID: j.ID, Ecosystem: j.Ecosystem, Name: j.Name, Version: j.Version, Filename: j.Filename,
		URL: j.URL, SHA256: j.SHA256, SHA512: j.SHA512, Scenarios: j.Scenarios, CreatedAt: j.CreatedAt,
	}
}

func (s *Server) handleSandboxHeartbeat(w http.ResponseWriter, r *http.Request) {
	worker := clipHeader(r.Header.Get("X-Aegis-Sandbox-Worker"), 64)
	if err := s.store.HeartbeatAnalysis(r.PathValue("id"), worker); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_seconds": analysisLease})
}

func (s *Server) handleSandboxResult(w http.ResponseWriter, r *http.Request) {
	if !s.packagesReady(w) {
		return
	}
	var body struct {
		Report *sandbox.Report `json:"report"`
		Error  string          `json:"error"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	s.pkgs.OnAnalysisResult(id, body.Report, body.Error)
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func countActive(aps []models.PackageApproval) int {
	now := time.Now()
	n := 0
	for _, a := range aps {
		if a.Active(now) {
			n++
		}
	}
	return n
}
