package api

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/blockpage"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

func (s *Server) policyRoutes() {
	// Policy sets & change management
	s.mux.HandleFunc("GET /api/rules", s.authed(s.handleEffectiveRules))
	s.mux.HandleFunc("GET /api/policy-sets", s.authed(s.handleListPolicySets))
	s.mux.HandleFunc("POST /api/policy-sets", s.authed(s.handleCreatePolicySet))
	s.mux.HandleFunc("GET /api/policy-sets/export", s.authed(s.handleExportPolicySets))
	s.mux.HandleFunc("POST /api/policy-sets/import", s.authed(s.handleImportPolicySets))
	s.mux.HandleFunc("GET /api/policy-sets/{id}", s.authed(s.handleGetPolicySet))
	s.mux.HandleFunc("DELETE /api/policy-sets/{id}", s.authed(s.handleDeletePolicySet))
	s.mux.HandleFunc("PUT /api/policy-sets/{id}/draft", s.authed(s.handleSaveDraft))
	s.mux.HandleFunc("DELETE /api/policy-sets/{id}/draft", s.authed(s.handleDiscardDraft))
	s.mux.HandleFunc("POST /api/policy-sets/{id}/publish", s.authed(s.handlePublishDraft))
	s.mux.HandleFunc("POST /api/policy-sets/{id}/submit", s.authed(s.handleSubmitChange))
	s.mux.HandleFunc("POST /api/policy-sets/{id}/simulate", s.authed(s.handleSimulateSet))
	s.mux.HandleFunc("GET /api/policy-sets/{id}/diff", s.authed(s.handleDiffSet))
	s.mux.HandleFunc("GET /api/policy-sets/{id}/versions", s.authed(s.handleListVersions))
	s.mux.HandleFunc("GET /api/policy-sets/{id}/versions/{version}", s.authed(s.handleGetVersion))
	s.mux.HandleFunc("POST /api/policy-sets/{id}/rollback", s.authed(s.handleRollbackSet))
	s.mux.HandleFunc("POST /api/policy-sets/{id}/recertify", s.authed(s.handleRecertifySet))
	s.mux.HandleFunc("GET /api/change-requests", s.authed(s.handleListChangeRequests))
	s.mux.HandleFunc("GET /api/change-requests/{id}", s.authed(s.handleGetChangeRequest))
	s.mux.HandleFunc("POST /api/change-requests/{id}/review", s.authed(s.handleReviewChange))
	s.mux.HandleFunc("POST /api/change-requests/{id}/withdraw", s.authed(s.handleWithdrawChange))
	s.mux.HandleFunc("GET /api/settings/governance", s.authed(s.handleGetGovernance))
	s.mux.HandleFunc("PUT /api/settings/governance", s.authed(s.handleUpdateGovernance))

	// Fleet management
	s.mux.HandleFunc("GET /api/servers", s.authed(s.handleListServers))
	s.mux.HandleFunc("GET /api/servers/discovered", s.authed(s.handleDiscoveredServers))
	s.mux.HandleFunc("POST /api/servers/import", s.authed(s.handleImportServers))
	s.mux.HandleFunc("GET /api/servers/export", s.authed(s.handleExportServers))
	s.mux.HandleFunc("GET /api/servers/{id}/effective-policy", s.authed(s.handleEffectivePolicy))
	s.mux.HandleFunc("POST /api/servers/{id}/quarantine", s.authed(s.handleQuarantine))
	s.mux.HandleFunc("POST /api/servers/quarantine", s.authed(s.handleQuarantineByIdentity))

	// Access request workflow
	s.mux.HandleFunc("GET /api/requests", s.authed(s.handleListRequests))
	s.mux.HandleFunc("GET /api/requests/{id}", s.authed(s.handleGetRequest))
	s.mux.HandleFunc("POST /api/requests/bulk-review", s.authed(s.handleBulkReview))
	s.mux.HandleFunc("POST /api/requests/{id}/comments", s.authed(s.handleCommentRequest))
	s.mux.HandleFunc("POST /api/requests/{id}/assign", s.authed(s.handleAssignRequest))
	s.mux.HandleFunc("POST /api/requests/{id}/revoke", s.authed(s.handleRevokeRequest))
	s.mux.HandleFunc("POST /api/requests/{id}/extend", s.authed(s.handleExtendRequest))

	// Block pages
	s.mux.HandleFunc("GET /api/block-pages", s.authed(s.handleListBlockPages))
	s.mux.HandleFunc("POST /api/block-pages", s.authed(s.handleSaveBlockPage))
	s.mux.HandleFunc("PUT /api/block-pages/{id}", s.authed(s.handleSaveBlockPage))
	s.mux.HandleFunc("DELETE /api/block-pages/{id}", s.authed(s.handleDeleteBlockPage))
	s.mux.HandleFunc("POST /api/block-pages/preview", s.authed(s.handlePreviewBlockPage))
	s.mux.HandleFunc("GET /api/block-pages/{id}/preview", s.authed(s.handleRenderBlockPage))
}

// ---------------------------------------------------------------------------
// Policy sets
// ---------------------------------------------------------------------------

// policyViewFor returns nil for callers that may read every policy object (see policyView).
func (s *Server) policyViewFor(claims *auth.TokenClaims) *policyView {
	scope := scopeFor(claims)
	if scope == nil {
		return nil
	}
	return scope.policyView(s.store.Servers(), s.store.PolicySets())
}

// policySetVisible answers 404 for sets outside a Team Lead's scope.
func (s *Server) policySetVisible(w http.ResponseWriter, claims *auth.TokenClaims, id string) bool {
	if v := s.policyViewFor(claims); v != nil && !v.set(id) {
		writeError(w, http.StatusNotFound, "policy set not found")
		return false
	}
	return true
}

func (s *Server) handleEffectiveRules(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	rules := s.store.GetSnapshot().Rules
	if v := s.policyViewFor(claims); v != nil {
		rules = filterSlice(rules, v.rule)
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleListPolicySets(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	sets := s.store.PolicySets()
	if v := s.policyViewFor(claims); v != nil {
		sets = filterSlice(sets, func(p models.PolicySet) bool { return v.set(p.ID) })
	}
	writeJSON(w, http.StatusOK, sets)
}

func (s *Server) handleCreatePolicySet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Kind string               `json:"kind"`
		Spec models.PolicySetSpec `json:"spec"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	// Rule attribution (created/approved by, request and session links) is set by the store.
	set, err := s.store.CreatePolicySet(body.Kind, body.Spec, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, set)
}

// handleExportPolicySets downloads policy sets as a JSON bundle (?id=…&id=… selects sets).
func (s *Server) handleExportPolicySets(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	b := s.store.ExportPolicySets(r.URL.Query()["id"], claims)
	if v := s.policyViewFor(claims); v != nil {
		b.PolicySets = filterSlice(b.PolicySets, func(d models.PolicySetDocument) bool { return v.set(d.ID) })
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-policy-sets-%s.json"`, time.Now().UTC().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, b)
}

// handleImportPolicySets plans or applies a bundle: {dry_run, bundle}. Changes land in drafts.
func (s *Server) handleImportPolicySets(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		DryRun bool                   `json:"dry_run"`
		Bundle models.PolicySetBundle `json:"bundle"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	results, err := s.store.ImportPolicySets(body.Bundle, body.DryRun, claims)
	if err != nil && results == nil {
		writeStoreError(w, err)
		return
	}
	resp := map[string]any{"dry_run": body.DryRun, "results": results}
	status := http.StatusOK
	if err != nil {
		resp["error"], status = err.Error(), http.StatusUnprocessableEntity
	}
	writeJSON(w, status, resp)
}

func (s *Server) handleGetPolicySet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	id := r.PathValue("id")
	set, ok := s.store.PolicySet(id)
	if !ok {
		writeError(w, http.StatusNotFound, "policy set not found")
		return
	}
	if !s.policySetVisible(w, claims, id) {
		return
	}
	var crs []models.ChangeRequest
	for _, cr := range s.store.ChangeRequests() {
		if cr.PolicySetID == id {
			crs = append(crs, cr)
		}
	}
	crs = scopedChangeRequests(crs, scopeFor(claims))
	var draftDiff *models.PolicyDiff
	if set.Draft != nil {
		d := store.DiffSpecs(set.PolicySetSpec, set.Draft.Spec)
		draftDiff = &d
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_set": set, "versions": versionSummaries(s.store.PolicyVersions(id)), "change_requests": nonNilCRs(crs), "draft_diff": draftDiff,
	})
}

func nonNilCRs(v []models.ChangeRequest) []models.ChangeRequest {
	if v == nil {
		return []models.ChangeRequest{}
	}
	return v
}

type versionSummary struct {
	Version         int       `json:"version"`
	PublishedBy     string    `json:"published_by"`
	PublishedAt     time.Time `json:"published_at"`
	ChangeRequestID string    `json:"change_request_id,omitempty"`
	Summary         string    `json:"summary"`
	Emergency       bool      `json:"emergency,omitempty"`
	Rules           int       `json:"rules"`
}

func versionSummaries(vs []models.PolicySetVersion) []versionSummary {
	out := make([]versionSummary, 0, len(vs))
	for _, v := range vs {
		out = append(out, versionSummary{v.Version, v.PublishedBy, v.PublishedAt, v.ChangeRequestID, v.Summary, v.Emergency, len(v.Spec.Rules)})
	}
	return out
}

func (s *Server) handleDeletePolicySet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	if err := s.store.DeletePolicySet(r.PathValue("id"), r.URL.Query().Get("reason"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleSaveDraft(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Spec models.PolicySetSpec `json:"spec"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !s.policySetVisible(w, claims, id) {
		return
	}
	set, err := s.store.SaveDraft(id, body.Spec, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleDiscardDraft(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	if err := s.store.DiscardDraft(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "discarded"})
}

func (s *Server) handlePublishDraft(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Comment   string `json:"comment"`
		Emergency bool   `json:"emergency"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	set, err := s.store.PublishDraft(r.PathValue("id"), body.Comment, body.Emergency, claims)
	if err != nil {
		if errors.Is(err, store.ErrReviewRequired) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleSubmitChange(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	cr, err := s.store.SubmitChangeRequest(r.PathValue("id"), body.Title, body.Description, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if latest, ok := s.store.ChangeRequest(cr.ID); ok {
		cr = latest
	}
	cr.Impact = scopedImpact(cr.Impact, scopeFor(claims))
	writeJSON(w, http.StatusCreated, cr)
}

func (s *Server) handleSimulateSet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Spec *models.PolicySetSpec `json:"spec"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	id := r.PathValue("id")
	if !s.policySetVisible(w, claims, id) {
		return
	}
	spec := body.Spec
	if spec == nil {
		set, ok := s.store.PolicySet(id)
		if !ok {
			writeError(w, http.StatusNotFound, "policy set not found")
			return
		}
		cp := set.PolicySetSpec
		if set.Draft != nil {
			cp = set.Draft.Spec
		}
		spec = &cp
	}
	impact, err := s.store.SimulateSpec(id, spec, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	impact.Scopes = nil // the per-group breakdown is not served (Team Leads simulate on their own traffic)
	writeJSON(w, http.StatusOK, impact)
}

// handleDiffSet compares two states of a set: from/to are a version number, "published" or "draft".
func (s *Server) handleDiffSet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	id := r.PathValue("id")
	set, ok := s.store.PolicySet(id)
	if !ok {
		writeError(w, http.StatusNotFound, "policy set not found")
		return
	}
	if !s.policySetVisible(w, claims, id) {
		return
	}
	versions := s.store.PolicyVersions(id)
	resolve := func(ref, def string) (models.PolicySetSpec, error) {
		if ref == "" {
			ref = def
		}
		switch ref {
		case "published":
			return set.PolicySetSpec, nil
		case "draft":
			if set.Draft == nil {
				return models.PolicySetSpec{}, errors.New("the set has no draft")
			}
			return set.Draft.Spec, nil
		case "empty":
			return models.PolicySetSpec{}, nil
		}
		n, err := strconv.Atoi(ref)
		if err != nil {
			return models.PolicySetSpec{}, fmt.Errorf("invalid reference %q", ref)
		}
		for _, v := range versions {
			if v.Version == n {
				return v.Spec, nil
			}
		}
		return models.PolicySetSpec{}, fmt.Errorf("version %d not found", n)
	}
	from, err := resolve(r.URL.Query().Get("from"), "published")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	to, err := resolve(r.URL.Query().Get("to"), "draft")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, store.DiffSpecs(from, to))
}

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	writeJSON(w, http.StatusOK, versionSummaries(s.store.PolicyVersions(r.PathValue("id"))))
}

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid version")
		return
	}
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	for _, v := range s.store.PolicyVersions(r.PathValue("id")) {
		if v.Version == n {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	writeError(w, http.StatusNotFound, "version not found")
}

func (s *Server) handleRollbackSet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Version int    `json:"version"`
		Comment string `json:"comment"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	set, published, err := s.store.RollbackPolicySet(r.PathValue("id"), body.Version, body.Comment, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_set": set, "published": published})
}

func (s *Server) handleRecertifySet(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Comment string `json:"comment"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if !s.policySetVisible(w, claims, r.PathValue("id")) {
		return
	}
	set, err := s.store.RecertifyPolicySet(r.PathValue("id"), body.Comment, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleListChangeRequests(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	status := r.URL.Query().Get("status")
	v := s.policyViewFor(claims)
	out := []models.ChangeRequest{}
	for _, cr := range s.store.ChangeRequests() {
		if (status == "" || cr.Status == status) && (v == nil || v.changeRequest(cr)) {
			out = append(out, cr)
		}
	}
	writeJSON(w, http.StatusOK, scopedChangeRequests(out, scopeFor(claims)))
}

func (s *Server) handleGetChangeRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	cr, ok := s.store.ChangeRequest(r.PathValue("id"))
	if v := s.policyViewFor(claims); !ok || (v != nil && !v.changeRequest(cr)) {
		writeError(w, http.StatusNotFound, "change request not found")
		return
	}
	cr.Impact = scopedImpact(cr.Impact, scopeFor(claims))
	writeJSON(w, http.StatusOK, cr)
}

// changeRequestVisible answers 404 for change requests outside a Team Lead's view.
func (s *Server) changeRequestVisible(w http.ResponseWriter, claims *auth.TokenClaims, id string) bool {
	if v := s.policyViewFor(claims); v != nil {
		if cr, ok := s.store.ChangeRequest(id); !ok || !v.changeRequest(cr) {
			writeError(w, http.StatusNotFound, "change request not found")
			return false
		}
	}
	return true
}

func (s *Server) handleReviewChange(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Decision string `json:"decision"`
		Comment  string `json:"comment"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !s.changeRequestVisible(w, claims, r.PathValue("id")) {
		return
	}
	cr, err := s.store.ReviewChangeRequest(r.PathValue("id"), body.Decision, body.Comment, claims)
	cr.Impact = scopedImpact(cr.Impact, scopeFor(claims))
	if err != nil {
		if errors.Is(err, store.ErrSuperseded) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "change_request": cr})
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cr)
}

func (s *Server) handleWithdrawChange(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !s.changeRequestVisible(w, claims, r.PathValue("id")) {
		return
	}
	if err := s.store.WithdrawChangeRequest(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "withdrawn"})
}

func (s *Server) handleGetGovernance(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	writeJSON(w, http.StatusOK, s.store.Governance())
}

func (s *Server) handleUpdateGovernance(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var g models.GovernanceSettings
	if !decodeJSON(w, r, &g) {
		return
	}
	out, err := s.store.UpdateGovernance(g, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Fleet
// ---------------------------------------------------------------------------

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	servers := s.store.Servers()
	if scope := scopeFor(claims); scope != nil {
		servers = filterSlice(servers, func(srv models.Server) bool { return scope.anyOf(srv.EffectiveGroupIDs, srv.GroupIDs) })
	}
	writeJSON(w, http.StatusOK, publicServers(servers))
}

func (s *Server) handleDiscoveredServers(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if scopeFor(claims) != nil {
		writeJSON(w, http.StatusOK, []models.DiscoveredSource{}) // unregistered sources belong to no group
		return
	}
	writeJSON(w, http.StatusOK, s.store.DiscoveredSources())
}

func (s *Server) handleEffectivePolicy(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	ep, err := s.store.EffectivePolicy(r.PathValue("id"))
	if scope := scopeFor(claims); err == nil && scope != nil && !scope.serverVisible(ep.Server) {
		err = errors.New("server not found") // same answer as for unknown servers
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ep.Server = ep.Server.Public()
	writeJSON(w, http.StatusOK, ep)
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Quarantined bool   `json:"quarantined"`
		Reason      string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if scope := scopeFor(claims); scope != nil {
		i := slices.IndexFunc(s.store.Servers(), func(srv models.Server) bool { return srv.ID == r.PathValue("id") && scope.serverVisible(srv) })
		if i < 0 {
			writeError(w, http.StatusNotFound, "server not found") // same answer for foreign servers
			return
		}
	}
	srv, err := s.store.SetQuarantine(r.PathValue("id"), body.Quarantined, body.Reason, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, srv.Public())
}

// handleQuarantineByIdentity serves SOAR playbooks: {hostname | ip, quarantined, reason}.
func (s *Server) handleQuarantineByIdentity(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Hostname    string `json:"hostname"`
		IP          string `json:"ip"`
		Quarantined *bool  `json:"quarantined"`
		Reason      string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	srv, err := s.store.FindServer(body.Hostname, body.IP)
	if scope := scopeFor(claims); err == nil && scope != nil && !scope.serverVisible(srv) {
		err = errors.New("server not found") // same answer for foreign servers
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	q := true
	if body.Quarantined != nil {
		q = *body.Quarantined
	}
	out, err := s.store.SetQuarantine(srv.ID, q, body.Reason, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

var csvColumns = []string{"id", "hostname", "ip", "subnet_cidr", "proxy_auth_user", "group_ids", "labels", "os", "department", "owner_team", "description"}

func parseLabels(v string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(v, ";") {
		if k, val, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	return out
}

func splitIDs(v string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// parseServerCSV reads the export format (header row required, unknown columns ignored).
func parseServerCSV(data string) ([]models.Server, error) {
	rd := csv.NewReader(strings.NewReader(data))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	rd.LazyQuotes = true
	header, err := rd.Read()
	if err != nil {
		return nil, errors.New("CSV needs a header row: " + strings.Join(csvColumns, ","))
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	if _, ok := col["hostname"]; !ok {
		return nil, errors.New("CSV header must contain at least the hostname column")
	}
	var out []models.Server
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CSV line %d: %v", len(out)+2, err)
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		out = append(out, models.Server{ID: get("id"), Hostname: get("hostname"), IP: get("ip"), SubnetCIDR: get("subnet_cidr"),
			ProxyAuthUser: get("proxy_auth_user"), GroupIDs: splitIDs(get("group_ids")), Labels: parseLabels(get("labels")),
			OS: get("os"), Department: get("department"), OwnerTeam: get("owner_team"), Description: get("description")})
	}
	return out, nil
}

func (s *Server) handleImportServers(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		DryRun  bool            `json:"dry_run"`
		CSV     string          `json:"csv"`
		Servers []models.Server `json:"servers"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	rows := body.Servers
	if strings.TrimSpace(body.CSV) != "" {
		var err error
		if rows, err = parseServerCSV(body.CSV); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	results, err := s.store.ImportServers(rows, body.DryRun, claims)
	status := http.StatusOK
	resp := map[string]any{"dry_run": body.DryRun, "results": results}
	if err != nil {
		if strings.HasPrefix(err.Error(), "RBAC") {
			writeStoreError(w, err)
			return
		}
		status = http.StatusUnprocessableEntity
		resp["error"] = err.Error()
	}
	writeJSON(w, status, resp)
}

func (s *Server) handleExportServers(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	servers := s.store.Servers()
	if scope := scopeFor(claims); scope != nil {
		servers = filterSlice(servers, func(srv models.Server) bool { return scope.anyOf(srv.EffectiveGroupIDs, srv.GroupIDs) })
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-servers-%s.json"`, stamp))
		servers = publicServers(servers)
		writeJSON(w, http.StatusOK, servers)
		return
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write(csvColumns)
	for _, srv := range servers {
		keys := make([]string, 0, len(srv.Labels))
		for k := range srv.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var labels []string
		for _, k := range keys {
			labels = append(labels, k+"="+srv.Labels[k])
		}
		row := []string{srv.ID, srv.Hostname, srv.IP, srv.SubnetCIDR, srv.ProxyAuthUser, strings.Join(srv.GroupIDs, ";"),
			strings.Join(labels, ";"), srv.OS, srv.Department, srv.OwnerTeam, srv.Description}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aegis-servers-%s.csv"`, stamp))
	_, _ = w.Write(buf.Bytes())
}

// csvSafe defuses spreadsheet formula injection in free-text columns.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// onboarding returns copy-paste snippets for connecting a server to the proxy.
func (s *Server) onboarding(srv models.Server, token string) map[string]string {
	proxy := fmt.Sprintf("http://%s:%s@%s", srv.ProxyAuthUser, token, s.cfg.ProxyAddress)
	noProxy := []string{"localhost", "127.0.0.1", "::1"}
	noProxy = append(noProxy, s.cfg.InternalSuffix...)
	np := strings.Join(noProxy, ",")
	ca := s.caInstallCommands()
	linux := fmt.Sprintf(`# 1. Trust the AegisProxy root CA (the installer runs only if its SHA-256 matches; it verifies the pinned CA fingerprint)
%[1]s

# 2. Route outbound HTTP(S) through the proxy (root-only file, loaded by login shells and systemd units via EnvironmentFile)
sudo install -m 0600 /dev/null /etc/aegis-proxy.env
sudo tee /etc/aegis-proxy.env >/dev/null <<'EOF'
http_proxy=%[2]s
https_proxy=%[2]s
HTTP_PROXY=%[2]s
HTTPS_PROXY=%[2]s
no_proxy=%[3]s
NO_PROXY=%[3]s
EOF

# 3. Package managers (only the ones present on this host; pacman/zypper read the env from step 2)
[ -d /etc/apt/apt.conf.d ] && echo 'Acquire::http::Proxy "%[2]s"; Acquire::https::Proxy "%[2]s";' | sudo tee /etc/apt/apt.conf.d/95aegis-proxy >/dev/null   # Debian/Ubuntu
[ -f /etc/dnf/dnf.conf ] && printf 'proxy=http://%[4]s\nproxy_username=%[5]s\nproxy_password=%[6]s\n' | sudo tee -a /etc/dnf/dnf.conf >/dev/null   # RHEL/Rocky/Alma
# pacman (Arch/CachyOS) and zypper (SUSE) honour the http_proxy/https_proxy from /etc/aegis-proxy.env; for pacman
# run it so the environment is loaded, e.g.:  sudo env $(grep -v '^#' /etc/aegis-proxy.env | xargs) pacman -Sy

# 4. Verify (expect 403 + block page text for a non-whitelisted host)
set -a; . /etc/aegis-proxy.env; set +a; curl -sS -o /dev/null -w '%%{http_code}\n' https://example.org/
`, ca.Linux, proxy, np, s.cfg.ProxyAddress, srv.ProxyAuthUser, token)
	windows := fmt.Sprintf(`# Run in an elevated PowerShell
# 1. Trust the AegisProxy root CA (the installer runs only if its SHA-256 matches)
%[1]s

# 2. Machine-wide proxy for tools that honour environment variables (curl, git, pip, PowerShell 7)
[Environment]::SetEnvironmentVariable('HTTPS_PROXY', '%[2]s', 'Machine')
[Environment]::SetEnvironmentVariable('HTTP_PROXY',  '%[2]s', 'Machine')
[Environment]::SetEnvironmentVariable('NO_PROXY',    '%[3]s', 'Machine')

# 3. WinHTTP (Windows services, Windows Update). WinHTTP cannot send the token; register the
#    server IP (%[5]s) so the proxy identifies it by address.
netsh winhttp set proxy proxy-server="%[4]s" bypass-list="<local>"

# 4. Verify
curl.exe -sS -o NUL -w "%%{http_code}" https://example.org/
`, ca.Windows, proxy, np, s.cfg.ProxyAddress, firstNonEmptyStr(srv.IP, "<server IP>"))
	return map[string]string{"linux": linux, "windows": windows, "proxy_url": proxy, "no_proxy": np, "proxy_address": s.cfg.ProxyAddress}
}

func firstNonEmptyStr(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Access request workflow
// ---------------------------------------------------------------------------

func (s *Server) handleBulkReview(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		IDs     []string `json:"ids"`
		Approve bool     `json:"approve"`
		Comment string   `json:"comment"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.store.BulkReviewRequests(body.IDs, body.Approve, body.Comment, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": res})
}

func (s *Server) requestAction(w http.ResponseWriter, r *http.Request, fn func(id string, body map[string]string) (models.AccessRequest, error)) {
	body := map[string]string{}
	if !decodeJSON(w, r, &body) {
		return
	}
	req, err := fn(r.PathValue("id"), body)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// handleListRequests lists access requests, newest first, for ITSM/SOAR integrations:
// ?status=pending|approved|rejected|revoked|expired, ?assigned_to=, ?server_id=, ?group_id=,
// ?overdue=true, ?limit= (default 500, max 5000).
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	q := r.URL.Query()
	limit := 500
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = min(v, 5000)
	}
	now := time.Now()
	out := []models.AccessRequest{}
	total := 0
	scope := scopeFor(claims)
	for _, req := range s.store.GetSnapshot().Requests {
		switch {
		case scope != nil && !scope.anyOf(req.TargetGroupIDs, req.GroupIDs):
			continue
		case strings.EqualFold(q.Get("status"), "expired"):
			// Approved temporary access whose expiry has passed (the request keeps status "approved").
			if req.Status != "approved" || req.ExpiresAt == nil || !now.After(*req.ExpiresAt) {
				continue
			}
		case q.Get("status") != "" && !strings.EqualFold(q.Get("status"), "expired") && !strings.EqualFold(req.Status, q.Get("status")),
			q.Get("assigned_to") != "" && !strings.EqualFold(req.AssignedTo, q.Get("assigned_to")),
			q.Get("server_id") != "" && req.ServerID != q.Get("server_id"),
			q.Get("group_id") != "" && !slices.Contains(req.TargetGroupIDs, q.Get("group_id")),
			q.Get("overdue") == "true" && (req.Status != "pending" || req.DueAt == nil || !now.After(*req.DueAt)):
			continue
		}
		total++
		if len(out) < limit {
			out = append(out, req)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out, "total": total})
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	id := r.PathValue("id")
	scope := scopeFor(claims)
	for _, req := range s.store.GetSnapshot().Requests {
		if req.ID == id && (scope == nil || scope.anyOf(req.TargetGroupIDs, req.GroupIDs)) {
			writeJSON(w, http.StatusOK, req)
			return
		}
	}
	writeError(w, http.StatusNotFound, "access request not found")
}

func (s *Server) handleCommentRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	s.requestAction(w, r, func(id string, b map[string]string) (models.AccessRequest, error) {
		return s.store.CommentRequest(id, b["text"], claims)
	})
}

func (s *Server) handleAssignRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	s.requestAction(w, r, func(id string, b map[string]string) (models.AccessRequest, error) {
		return s.store.AssignRequest(id, b["assignee"], claims)
	})
}

func (s *Server) handleRevokeRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	s.requestAction(w, r, func(id string, b map[string]string) (models.AccessRequest, error) {
		return s.store.RevokeAccessRequest(id, b["reason"], claims)
	})
}

func (s *Server) handleExtendRequest(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	s.requestAction(w, r, func(id string, b map[string]string) (models.AccessRequest, error) {
		return s.store.ExtendAccessRequest(id, b["duration"], claims)
	})
}

// ---------------------------------------------------------------------------
// Block pages
// ---------------------------------------------------------------------------

func (s *Server) handleListBlockPages(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	def, groups := s.store.BlockPageAssignments()
	writeJSON(w, http.StatusOK, map[string]any{"templates": s.store.BlockPages(), "default_template_id": def,
		"group_templates": groups, "locales": blockpage.Locales, "variables": []string{"{company}", "{hostname}", "{ip}", "{url}", "{host}", "{method}", "{trace_id}", "{groups}", "{verdict}", "{reason}"}})
}

func (s *Server) handleSaveBlockPage(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var t models.BlockPageTemplate
	if !decodeJSON(w, r, &t) {
		return
	}
	if id := r.PathValue("id"); id != "" {
		t.ID = id
	} else {
		t.ID = ""
	}
	saved, err := s.store.UpsertBlockPage(t, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteBlockPage(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.DeleteBlockPage(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func previewOf(t models.BlockPageTemplate, locale, variant, publicURL, dashboardURL string) (string, string, error) {
	if !slices.Contains(blockpage.Variants, variant) {
		variant = "request"
	}
	shells, err := blockpage.Render(t, locale)
	if err != nil {
		return "", "", err
	}
	vals := blockpage.SampleValues(t, variant, publicURL, dashboardURL)
	htmlShell, cliShell := shells.RequestHTML, shells.RequestCLI
	if variant == "threat" {
		htmlShell, cliShell = shells.ThreatHTML, shells.ThreatCLI
	}
	return blockpage.Fill(htmlShell, vals, true), blockpage.Fill(cliShell, vals, false), nil
}

// handlePreviewBlockPage renders an unsaved template with sample data (console live preview).
func (s *Server) handlePreviewBlockPage(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var body struct {
		Template models.BlockPageTemplate `json:"template"`
		Locale   string                   `json:"locale"`
		Variant  string                   `json:"variant"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := store.ValidateBlockPageTemplate(&body.Template); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	html, cli, err := previewOf(body.Template, body.Locale, body.Variant, s.cfg.PublicURL, s.cfg.DashboardURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": html, "cli": cli})
}

// handleRenderBlockPage serves a saved template as a standalone page (open in new tab).
func (s *Server) handleRenderBlockPage(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	t, ok := s.store.BlockPage(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "block page template not found")
		return
	}
	q := r.URL.Query()
	html, cli, err := previewOf(t, q.Get("locale"), q.Get("variant"), s.cfg.PublicURL, s.cfg.DashboardURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "render failed")
		return
	}
	if q.Get("format") == "cli" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, cli)
		return
	}
	// Scripts are disabled in previews (the form would submit a real request).
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, html)
}

// blockPageBundle renders all templates for the data-plane bundle (cached per revision).
func (s *Server) blockPageBundle(rev uint64) map[string]any {
	s.bpMu.Lock()
	defer s.bpMu.Unlock()
	if s.bpCache != nil && s.bpRev == rev {
		return s.bpCache
	}
	def, groups := s.store.BlockPageAssignments()
	templates := map[string]any{}
	for _, t := range s.store.BlockPages() {
		locales := map[string]blockpage.Shells{}
		for _, l := range blockpage.Locales {
			sh, err := blockpage.Render(t, l)
			if err != nil {
				s.log.Error("block page render failed", "template", t.ID, "error", err)
				continue
			}
			locales[l] = sh
		}
		templates[t.ID] = map[string]any{"name": t.Name, "default_locale": t.DefaultLocale, "logo": t.LogoDataURL,
			"allowed_scopes": t.AllowedScopes, "allowed_durations": t.AllowedDurations, "shells": locales}
	}
	s.bpCache = map[string]any{"default_template_id": def, "group_templates": groups, "templates": templates, "keys": blockpage.Keys, "raw_keys": blockpage.RawKeys}
	s.bpRev = rev
	return s.bpCache
}

// overviewStats summarizes the work queues for the console home page.
// servers carry LastSeenAt refreshed from recent traffic (Store.Servers), like the server list.
func overviewStats(snap store.StateSnapshot, servers []models.Server, claims *auth.TokenClaims) map[string]int {
	now := time.Now()
	out := map[string]int{}
	for _, req := range snap.Requests {
		if req.Status != "pending" {
			continue
		}
		if claims.Role == models.RoleTeamLead && !auth.CanApproveForGroups(claims, req.TargetGroupIDs) {
			continue
		}
		out["pending_requests"]++
		if req.DueAt != nil && now.After(*req.DueAt) {
			out["overdue_requests"]++
		}
		if req.AssignedTo != "" && strings.EqualFold(req.AssignedTo, claims.Username) {
			out["assigned_to_me"]++
		}
	}
	for _, cr := range snap.ChangeRequests {
		if cr.Status == "open" {
			out["open_change_requests"]++
			if !strings.EqualFold(cr.SubmittedBy, claims.Username) {
				out["changes_to_review"]++
			}
		}
	}
	for _, set := range snap.PolicySets {
		switch set.ReviewState {
		case "overdue":
			out["recertification_overdue"]++
		case "due_soon":
			out["recertification_due_soon"]++
		}
		if set.Draft != nil {
			out["drafts"]++
		}
	}
	stale := now.Add(-24 * time.Hour)
	for _, srv := range servers {
		if srv.Quarantined {
			out["quarantined_servers"]++
		}
		if srv.LastSeenAt.Before(stale) {
			out["stale_servers"]++
		}
	}
	return out
}

func publicServers(in []models.Server) []models.Server {
	out := make([]models.Server, len(in))
	for i, srv := range in {
		out[i] = srv.Public()
	}
	return out
}
