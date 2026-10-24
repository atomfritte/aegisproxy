package api

// SCIM 2.0 service provider under /api/scim/v2 (same prefix as every other API route, so reverse
// proxies and ingress rules need no extra path). Only SCIM provisioning tokens are accepted:
// console sessions, cookies and service-account keys are refused.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/scim"
	"aegisproxy/control-plane/internal/store"
)

const scimPrefix = "/api/scim/v2"

type scimHandler func(w http.ResponseWriter, r *http.Request, actor string)

func (s *Server) scimRoutes() {
	s.mux.HandleFunc("GET /api/scim/v2/ServiceProviderConfig", s.scimAuthed(s.handleSCIMServiceProviderConfig))
	s.mux.HandleFunc("GET /api/scim/v2/ResourceTypes", s.scimAuthed(s.handleSCIMResourceTypes))
	s.mux.HandleFunc("GET /api/scim/v2/ResourceTypes/{id}", s.scimAuthed(s.handleSCIMResourceType))
	s.mux.HandleFunc("GET /api/scim/v2/Schemas", s.scimAuthed(s.handleSCIMSchemas))
	s.mux.HandleFunc("GET /api/scim/v2/Schemas/{id}", s.scimAuthed(s.handleSCIMSchema))
	s.mux.HandleFunc("POST /api/scim/v2/.search", s.scimAuthed(s.handleSCIMRootSearch))

	s.mux.HandleFunc("GET /api/scim/v2/Users", s.scimAuthed(s.handleSCIMListUsers))
	s.mux.HandleFunc("POST /api/scim/v2/Users/.search", s.scimAuthed(s.handleSCIMSearchUsers))
	s.mux.HandleFunc("POST /api/scim/v2/Users", s.scimAuthed(s.handleSCIMCreateUser))
	s.mux.HandleFunc("GET /api/scim/v2/Users/{id}", s.scimAuthed(s.handleSCIMGetUser))
	s.mux.HandleFunc("PUT /api/scim/v2/Users/{id}", s.scimAuthed(s.handleSCIMReplaceUser))
	s.mux.HandleFunc("PATCH /api/scim/v2/Users/{id}", s.scimAuthed(s.handleSCIMPatchUser))
	s.mux.HandleFunc("DELETE /api/scim/v2/Users/{id}", s.scimAuthed(s.handleSCIMDeleteUser))

	s.mux.HandleFunc("GET /api/scim/v2/Groups", s.scimAuthed(s.handleSCIMListGroups))
	s.mux.HandleFunc("POST /api/scim/v2/Groups/.search", s.scimAuthed(s.handleSCIMSearchGroups))
	s.mux.HandleFunc("POST /api/scim/v2/Groups", s.scimAuthed(s.handleSCIMCreateGroup))
	s.mux.HandleFunc("GET /api/scim/v2/Groups/{id}", s.scimAuthed(s.handleSCIMGetGroup))
	s.mux.HandleFunc("PUT /api/scim/v2/Groups/{id}", s.scimAuthed(s.handleSCIMReplaceGroup))
	s.mux.HandleFunc("PATCH /api/scim/v2/Groups/{id}", s.scimAuthed(s.handleSCIMPatchGroup))
	s.mux.HandleFunc("DELETE /api/scim/v2/Groups/{id}", s.scimAuthed(s.handleSCIMDeleteGroup))

	// Console administration (Super Admins)
	s.mux.HandleFunc("GET /api/settings/scim", s.authed(s.handleGetSCIMSettings))
	s.mux.HandleFunc("POST /api/settings/scim", s.authed(s.handleUpdateSCIMSettings))
	s.mux.HandleFunc("POST /api/settings/scim/tokens", s.authed(s.handleCreateSCIMToken))
	s.mux.HandleFunc("POST /api/settings/scim/tokens/{id}/rotate", s.authed(s.handleRotateSCIMToken))
	s.mux.HandleFunc("DELETE /api/settings/scim/tokens/{id}", s.authed(s.handleRevokeSCIMToken))
}

func (s *Server) scimBaseURL() string { return strings.TrimRight(s.cfg.PublicURL, "/") + scimPrefix }

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, e *scim.Error) {
	writeSCIM(w, e.Status, e.Body())
}

// writeSCIMStoreError maps provisioning errors of the store onto SCIM errors.
func (s *Server) writeSCIMStoreError(w http.ResponseWriter, err error) {
	var se *store.SCIMError
	var pe *scim.Error
	switch {
	case errors.As(err, &pe):
		writeSCIMError(w, pe)
	case errors.As(err, &se):
		switch se.Kind {
		case store.SCIMUniqueness:
			writeSCIMError(w, scim.Errf(http.StatusConflict, "uniqueness", "%s", se.Detail))
		case store.SCIMNotFound:
			writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "%s", se.Detail))
		case store.SCIMPrecondition:
			writeSCIMError(w, scim.Errf(http.StatusPreconditionFailed, "", "%s", se.Detail))
		case store.SCIMTooMany:
			writeSCIMError(w, scim.Errf(http.StatusBadRequest, "tooMany", "%s", se.Detail))
		case store.SCIMMutability:
			writeSCIMError(w, scim.Errf(http.StatusBadRequest, "mutability", "%s", se.Detail))
		default:
			writeSCIMError(w, scim.Errf(http.StatusBadRequest, "invalidValue", "%s", se.Detail))
		}
	case errors.Is(err, store.ErrClusterUnavailable):
		writeSCIMError(w, scim.Errf(http.StatusServiceUnavailable, "", "storage temporarily unavailable, retry later"))
	default:
		s.log.Error("SCIM request failed", "error", err)
		writeSCIMError(w, scim.Errf(http.StatusInternalServerError, "", "internal error"))
	}
}

// scimAuthed accepts only "Authorization: Bearer aegis_scim_…".
func (s *Server) scimAuthed(h scimHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		raw = strings.TrimSpace(raw)
		ip := s.clientIP(r)
		if !strings.EqualFold(scheme, "Bearer") || raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="AegisProxy SCIM"`)
			writeSCIMError(w, scim.Errf(http.StatusUnauthorized, "", "a SCIM provisioning token is required (Authorization: Bearer aegis_scim_…)"))
			return
		}
		// Guessing tokens is throttled per source address like password sign-ins (the IdP's own
		// requests always succeed, so a legitimate client is never locked out). The attempt is reserved
		// before the token check, so parallel bursts count toward the lockout.
		attempt, wait := s.loginLimiter.Begin(s.throttleSource(r).keys("scim-")...)
		if wait > 0 {
			w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(wait.Seconds()))))
			writeSCIMError(w, scim.Errf(http.StatusTooManyRequests, "", "too many failed SCIM authentications from this address"))
			return
		}
		defer attempt.Release()
		actor, err := s.store.AuthenticateSCIM(raw, ip)
		if err != nil {
			s.metrics.Inc("aegis_scim_auth_failures_total")
			if !errors.Is(err, store.ErrSCIMDisabled) {
				attempt.Fail()
			}
			if errors.Is(err, store.ErrSCIMDisabled) {
				writeSCIMError(w, scim.Errf(http.StatusForbidden, "", "SCIM provisioning is disabled in AegisProxy"))
				return
			}
			s.log.Warn("SCIM authentication failed", "client_ip", ip, "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer realm="AegisProxy SCIM", error="invalid_token"`)
			writeSCIMError(w, scim.Errf(http.StatusUnauthorized, "", "%s", err.Error()))
			return
		}
		attempt.Success() // releases the reservation before the (possibly slow) provisioning request runs
		h(w, r, actor)
	}
}

// decodeSCIM reads a JSON body (application/scim+json or application/json).
func decodeSCIM(r *http.Request, v any) *scim.Error {
	if ct := strings.ToLower(r.Header.Get("Content-Type")); ct != "" && !strings.Contains(ct, "json") {
		return scim.Errf(http.StatusUnsupportedMediaType, "", "Content-Type must be application/scim+json")
	}
	if err := jsonDecode(r, v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			return scim.Errf(http.StatusRequestEntityTooLarge, "", "request body too large")
		case errors.Is(err, io.EOF):
			return scim.Errf(http.StatusBadRequest, "invalidSyntax", "request body is empty")
		default:
			return scim.Errf(http.StatusBadRequest, "invalidSyntax", "request body is not valid JSON for this request")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// scimDocsURL links the SCIM chapter of the documentation when AEGIS_DOCS_URL is configured.
func (s *Server) scimDocsURL() string {
	if s.cfg.DocsURL == "" {
		return ""
	}
	return strings.TrimRight(s.cfg.DocsURL, "/") + "/identity.md#scim-provisioning"
}

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request, _ string) {
	writeSCIM(w, http.StatusOK, scim.ServiceProviderConfig(s.scimBaseURL(), s.scimDocsURL()))
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request, _ string) {
	var out []map[string]any
	for _, rt := range scim.ResourceTypes {
		out = append(out, scim.ResourceTypeResource(rt, s.scimBaseURL()))
	}
	writeSCIM(w, http.StatusOK, scim.ListResponse(out, len(out), 1))
}

func (s *Server) handleSCIMResourceType(w http.ResponseWriter, r *http.Request, _ string) {
	rt := scim.FindResourceType(r.PathValue("id"))
	if rt == nil {
		writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "resource type %q not found", r.PathValue("id")))
		return
	}
	writeSCIM(w, http.StatusOK, scim.ResourceTypeResource(rt, s.scimBaseURL()))
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request, _ string) {
	var out []map[string]any
	for _, sc := range scim.Schemas {
		out = append(out, scim.SchemaResource(sc, s.scimBaseURL()))
	}
	writeSCIM(w, http.StatusOK, scim.ListResponse(out, len(out), 1))
}

func (s *Server) handleSCIMSchema(w http.ResponseWriter, r *http.Request, _ string) {
	sc := scim.FindSchema(r.PathValue("id"))
	if sc == nil {
		writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "schema %q not found", r.PathValue("id")))
		return
	}
	writeSCIM(w, http.StatusOK, scim.SchemaResource(sc, s.scimBaseURL()))
}

// handleSCIMRootSearch searches Users and Groups at once (RFC 7644 section 3.4.3).
func (s *Server) handleSCIMRootSearch(w http.ResponseWriter, r *http.Request, _ string) {
	uq, err := listQueryFromSearch(r, &scim.UserType)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	gq := uq
	if uq.filter != nil {
		gq.filter, _ = scim.ParseFilter(uq.filter.String(), &scim.GroupType)
	}
	var matched []map[string]any
	for _, part := range []struct {
		q    listQuery
		rt   *scim.ResourceType
		docs []map[string]any
	}{{uq, &scim.UserType, s.userDocs(uq.filter)}, {gq, &scim.GroupType, s.groupDocs(gq.filter)}} {
		for _, d := range part.docs {
			if part.q.filter == nil || part.q.filter.Match(d) {
				matched = append(matched, scim.Project(d, part.rt, uq.attributes, uq.excluded))
			}
		}
	}
	total := len(matched)
	from := min(uq.startIndex-1, total)
	to := min(from+uq.count, total)
	writeSCIM(w, http.StatusOK, scim.ListResponse(matched[from:to], total, uq.startIndex))
}

// ---------------------------------------------------------------------------
// Listing, filtering, pagination and projection
// ---------------------------------------------------------------------------

type listQuery struct {
	filter     *scim.Filter
	startIndex int
	count      int
	attributes []string
	excluded   []string
}

func parsePositiveInt(v string, def int) (int, bool) {
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return n, err == nil
}

func newListQuery(rt *scim.ResourceType, filter string, startIndex, count int, attrs, excluded []string) (listQuery, *scim.Error) {
	q := listQuery{startIndex: max(startIndex, 1), count: min(max(count, 0), scim.MaxResults), attributes: attrs, excluded: excluded}
	if strings.TrimSpace(filter) != "" {
		f, err := scim.ParseFilter(filter, rt)
		if err != nil {
			return q, err
		}
		q.filter = f
	}
	return q, nil
}

func listQueryFromURL(r *http.Request, rt *scim.ResourceType) (listQuery, *scim.Error) {
	v := r.URL.Query()
	start, ok1 := parsePositiveInt(v.Get("startIndex"), 1)
	count, ok2 := parsePositiveInt(v.Get("count"), scim.MaxResults)
	if !ok1 || !ok2 {
		return listQuery{}, scim.Errf(http.StatusBadRequest, "invalidValue", "startIndex and count must be integers")
	}
	return newListQuery(rt, v.Get("filter"), start, count, scim.SplitAttrList(v.Get("attributes")), scim.SplitAttrList(v.Get("excludedAttributes")))
}

func listQueryFromSearch(r *http.Request, rt *scim.ResourceType) (listQuery, *scim.Error) {
	var body struct {
		Schemas            []string `json:"schemas"`
		Filter             string   `json:"filter"`
		StartIndex         *int     `json:"startIndex"`
		Count              *int     `json:"count"`
		Attributes         []string `json:"attributes"`
		ExcludedAttributes []string `json:"excludedAttributes"`
	}
	if err := decodeSCIM(r, &body); err != nil {
		return listQuery{}, err
	}
	start, count := 1, scim.MaxResults
	if body.StartIndex != nil {
		start = *body.StartIndex
	}
	if body.Count != nil {
		count = *body.Count
	}
	return newListQuery(rt, body.Filter, start, count, body.Attributes, body.ExcludedAttributes)
}

// list filters rendered resources and returns one page.
func (q listQuery) list(rt *scim.ResourceType, docs []map[string]any) map[string]any {
	var matched []map[string]any
	for _, d := range docs {
		if q.filter == nil || q.filter.Match(d) {
			matched = append(matched, d)
		}
	}
	total := len(matched)
	from := min(q.startIndex-1, total)
	to := min(from+q.count, total)
	page := make([]map[string]any, 0, to-from)
	for _, d := range matched[from:to] {
		page = append(page, scim.Project(d, rt, q.attributes, q.excluded))
	}
	return scim.ListResponse(page, total, q.startIndex)
}

// userDocs renders the users a filter can match. A plain `attr eq "value"` filter on userName,
// externalId or id preselects candidates on the stored values, so that the per-user lookups of a
// provisioning cycle do not render every account; the full filter is still applied afterwards.
func (s *Server) userDocs(f *scim.Filter) []map[string]any {
	base := s.scimBaseURL()
	views := s.store.SCIMUsers()
	pick := func(store.SCIMUserView) bool { return true }
	if f != nil {
		if attr, v, ok := f.EqualityOn(); ok {
			switch attr {
			case "username":
				pick = func(u store.SCIMUserView) bool { return strings.EqualFold(u.User.SCIM.UserName, v) }
			case "externalid":
				pick = func(u store.SCIMUserView) bool { return u.User.SCIM.ExternalID == v }
			case "id":
				pick = func(u store.SCIMUserView) bool { return u.User.ID == v }
			}
		}
	}
	docs := make([]map[string]any, 0, len(views))
	for _, v := range views {
		if pick(v) {
			docs = append(docs, scim.RenderUser(v.User, v.Groups, base))
		}
	}
	return docs
}

func (s *Server) groupDocs(f *scim.Filter) []map[string]any {
	base := s.scimBaseURL()
	groups := s.store.SCIMGroups()
	pick := func(models.SCIMGroup) bool { return true }
	if f != nil {
		if attr, v, ok := f.EqualityOn(); ok {
			switch attr {
			case "displayname":
				pick = func(g models.SCIMGroup) bool { return strings.EqualFold(g.DisplayName, v) }
			case "externalid":
				pick = func(g models.SCIMGroup) bool { return g.ExternalID == v }
			case "id":
				pick = func(g models.SCIMGroup) bool { return g.ID == v }
			}
		}
	}
	docs := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		if pick(g) {
			docs = append(docs, scim.RenderGroup(g, base))
		}
	}
	return docs
}

// writeResource sends one resource with ETag and Location, honouring attributes/excludedAttributes.
func writeResource(w http.ResponseWriter, r *http.Request, rt *scim.ResourceType, status int, doc map[string]any) {
	meta, _ := doc["meta"].(map[string]any)
	if meta != nil {
		if v, ok := meta["version"].(string); ok {
			w.Header().Set("ETag", v)
		}
		if loc, ok := meta["location"].(string); ok && status == http.StatusCreated {
			w.Header().Set("Location", loc)
		}
	}
	q := r.URL.Query()
	writeSCIM(w, status, scim.Project(doc, rt, scim.SplitAttrList(q.Get("attributes")), scim.SplitAttrList(q.Get("excludedAttributes"))))
}

func notModified(w http.ResponseWriter, r *http.Request, version int64) bool {
	inm := r.Header.Get("If-None-Match")
	if inm == "" {
		return false
	}
	for _, t := range strings.Split(inm, ",") {
		if strings.TrimSpace(t) == "*" || scim.ParseETag(t) == version {
			w.Header().Set("ETag", scim.ETag(version))
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	return false
}

func ifMatch(r *http.Request) int64 { return scim.ParseETag(r.Header.Get("If-Match")) }

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request, _ string) {
	q, err := listQueryFromURL(r, &scim.UserType)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, q.list(&scim.UserType, s.userDocs(q.filter)))
}

func (s *Server) handleSCIMSearchUsers(w http.ResponseWriter, r *http.Request, _ string) {
	q, err := listQueryFromSearch(r, &scim.UserType)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, q.list(&scim.UserType, s.userDocs(q.filter)))
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request, actor string) {
	var doc map[string]any
	if err := decodeSCIM(r, &doc); err != nil {
		writeSCIMError(w, err)
		return
	}
	in, perr := scim.ParseUser(doc)
	if perr != nil {
		writeSCIMError(w, perr)
		return
	}
	v, err := s.store.SCIMCreateUser(in, actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.UserType, http.StatusCreated, scim.RenderUser(v.User, v.Groups, s.scimBaseURL()))
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request, _ string) {
	v, ok := s.store.SCIMUser(r.PathValue("id"))
	if !ok {
		writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "user %s not found", r.PathValue("id")))
		return
	}
	if notModified(w, r, v.User.SCIM.Version) {
		return
	}
	writeResource(w, r, &scim.UserType, http.StatusOK, scim.RenderUser(v.User, v.Groups, s.scimBaseURL()))
}

func (s *Server) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request, actor string) {
	var doc map[string]any
	if err := decodeSCIM(r, &doc); err != nil {
		writeSCIMError(w, err)
		return
	}
	in, perr := scim.ParseUser(doc)
	if perr != nil {
		writeSCIMError(w, perr)
		return
	}
	v, err := s.store.SCIMUpdateUser(r.PathValue("id"), ifMatch(r), func(store.SCIMUserView) (models.SCIMUser, error) { return in, nil }, actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.UserType, http.StatusOK, scim.RenderUser(v.User, v.Groups, s.scimBaseURL()))
}

func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request, actor string) {
	var req scim.PatchRequest
	if err := decodeSCIM(r, &req); err != nil {
		writeSCIMError(w, err)
		return
	}
	base := s.scimBaseURL()
	v, err := s.store.SCIMUpdateUser(r.PathValue("id"), ifMatch(r), func(cur store.SCIMUserView) (models.SCIMUser, error) {
		doc := scim.RenderUser(cur.User, cur.Groups, base)
		if err := scim.ApplyPatch(doc, &scim.UserType, req); err != nil {
			return models.SCIMUser{}, err
		}
		in, err := scim.ParseUser(doc)
		if err != nil {
			return models.SCIMUser{}, err
		}
		return in, nil
	}, actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.UserType, http.StatusOK, scim.RenderUser(v.User, v.Groups, base))
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.store.SCIMDeleteUser(r.PathValue("id"), actor); err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func toGroupInput(g scim.GroupInput) store.SCIMGroupInput {
	return store.SCIMGroupInput{DisplayName: g.DisplayName, ExternalID: g.ExternalID, Members: g.Members}
}

func (s *Server) handleSCIMListGroups(w http.ResponseWriter, r *http.Request, _ string) {
	q, err := listQueryFromURL(r, &scim.GroupType)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, q.list(&scim.GroupType, s.groupDocs(q.filter)))
}

func (s *Server) handleSCIMSearchGroups(w http.ResponseWriter, r *http.Request, _ string) {
	q, err := listQueryFromSearch(r, &scim.GroupType)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, q.list(&scim.GroupType, s.groupDocs(q.filter)))
}

func (s *Server) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request, actor string) {
	var doc map[string]any
	if err := decodeSCIM(r, &doc); err != nil {
		writeSCIMError(w, err)
		return
	}
	in, perr := scim.ParseGroup(doc)
	if perr != nil {
		writeSCIMError(w, perr)
		return
	}
	g, err := s.store.SCIMCreateGroup(toGroupInput(in), actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.GroupType, http.StatusCreated, scim.RenderGroup(g, s.scimBaseURL()))
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request, _ string) {
	g, ok := s.store.SCIMGroup(r.PathValue("id"))
	if !ok {
		writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "group %s not found", r.PathValue("id")))
		return
	}
	if notModified(w, r, g.Version) {
		return
	}
	writeResource(w, r, &scim.GroupType, http.StatusOK, scim.RenderGroup(g, s.scimBaseURL()))
}

func (s *Server) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request, actor string) {
	var doc map[string]any
	if err := decodeSCIM(r, &doc); err != nil {
		writeSCIMError(w, err)
		return
	}
	in, perr := scim.ParseGroup(doc)
	if perr != nil {
		writeSCIMError(w, perr)
		return
	}
	g, err := s.store.SCIMUpdateGroup(r.PathValue("id"), ifMatch(r), func(models.SCIMGroup) (store.SCIMGroupInput, error) { return toGroupInput(in), nil }, actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.GroupType, http.StatusOK, scim.RenderGroup(g, s.scimBaseURL()))
}

func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request, actor string) {
	var req scim.PatchRequest
	if err := decodeSCIM(r, &req); err != nil {
		writeSCIMError(w, err)
		return
	}
	base := s.scimBaseURL()
	g, err := s.store.SCIMUpdateGroup(r.PathValue("id"), ifMatch(r), func(cur models.SCIMGroup) (store.SCIMGroupInput, error) {
		doc := scim.RenderGroup(cur, base)
		if err := scim.ApplyPatch(doc, &scim.GroupType, req); err != nil {
			return store.SCIMGroupInput{}, err
		}
		in, err := scim.ParseGroup(doc)
		if err != nil {
			return store.SCIMGroupInput{}, err
		}
		return toGroupInput(in), nil
	}, actor)
	if err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	writeResource(w, r, &scim.GroupType, http.StatusOK, scim.RenderGroup(g, base))
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.store.SCIMDeleteGroup(r.PathValue("id"), actor); err != nil {
		s.writeSCIMStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Console administration
// ---------------------------------------------------------------------------

func (s *Server) scimSettings(claims *auth.TokenClaims) map[string]any {
	out := map[string]any{"status": s.store.SCIMStatus(), "base_url": s.scimBaseURL(),
		"can_edit": claims.Role == models.RoleSuperAdmin && !claims.ServiceAccount}
	if d := s.scimDocsURL(); d != "" {
		out["docs_url"] = d
	}
	return out
}

func (s *Server) handleGetSCIMSettings(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if !auth.CanManageSystem(claims) {
		writeError(w, http.StatusForbidden, "RBAC Policy: only InfoSec Approvers and Super Admins can view SCIM provisioning")
		return
	}
	writeJSON(w, http.StatusOK, s.scimSettings(claims))
}

func (s *Server) handleUpdateSCIMSettings(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	if _, err := s.store.UpdateSCIMConfig(*in.Enabled, claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.scimSettings(claims))
}

func (s *Server) handleCreateSCIMToken(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	var in struct {
		Name      string    `json:"name"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := decodeOptionalJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	t, raw, err := s.store.CreateSCIMToken(in.Name, in.ExpiresAt, claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": raw, "base_url": s.scimBaseURL(),
		"note": "The token is shown only once. Enter it as Secret Token (Entra ID) or as HTTP header 'Authorization: Bearer <token>' (Okta)."})
}

func (s *Server) handleRotateSCIMToken(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	t, raw, err := s.store.RotateSCIMToken(r.PathValue("id"), claims)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": t, "secret": raw, "base_url": s.scimBaseURL()})
}

func (s *Server) handleRevokeSCIMToken(w http.ResponseWriter, r *http.Request, claims *auth.TokenClaims) {
	if err := s.store.RevokeSCIMToken(r.PathValue("id"), claims); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// scimNotFound answers unknown paths below /api/scim/v2 with a SCIM error document.
func scimNotFound(w http.ResponseWriter, r *http.Request, status int) {
	if status == http.StatusMethodNotAllowed {
		writeSCIMError(w, scim.Errf(status, "", "method %s is not allowed for %s", r.Method, r.URL.Path))
		return
	}
	writeSCIMError(w, scim.Errf(http.StatusNotFound, "", "no SCIM endpoint %s", r.URL.Path))
}
