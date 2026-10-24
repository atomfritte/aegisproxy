package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

var (
	ErrTooManyPending = errors.New("too many pending access requests; please wait for InfoSec to review the queue")
	validScopes       = []string{"prefix_with_objects", "exact_path", "domain", "learning_session_15m"}
	validDurations    = []string{"1h", "24h", "7d", "permanent"}
	// Durations a reviewer may grant (also when extending access).
	grantDurations = []string{"1h", "8h", "24h", "7d", "30d", "90d", "permanent"}
)

func durationOf(d string) (time.Duration, bool) {
	switch d {
	case "1h":
		return time.Hour, true
	case "8h":
		return 8 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	case "90d":
		return 90 * 24 * time.Hour, true
	}
	return 0, false
}

// expiryFor converts a grant duration into an expiry and enforces the governance cap for Team Leads.
func (s *Store) expiryForLocked(duration string, reviewer *auth.TokenClaims, now time.Time) (*time.Time, error) {
	if !slices.Contains(grantDurations, duration) {
		return nil, fmt.Errorf("duration must be one of %v", grantDurations)
	}
	maxDays := s.state.Governance.MaxTemporaryAccessDays
	if duration == "permanent" {
		if !auth.CanManageSystem(reviewer) {
			return nil, fmt.Errorf("RBAC Policy: Team Leads can grant temporary access only (at most %d days); permanent access needs InfoSec", maxDays)
		}
		return nil, nil
	}
	d, _ := durationOf(duration)
	if !auth.CanManageSystem(reviewer) && maxDays > 0 && d > time.Duration(maxDays)*24*time.Hour {
		return nil, fmt.Errorf("RBAC Policy: Team Leads can grant at most %d days of access", maxDays)
	}
	t := now.Add(d)
	return &t, nil
}

// CreateAccessRequest files a self-service access request from the public block portal.
// Server identity, group membership and suggested patterns are always computed server-side.
// It returns the existing request when an identical one is still pending (de-duplication).
func (s *Store) CreateAccessRequest(req models.AccessRequest) (models.AccessRequest, bool, error) {
	srvID, srvHost, groups := s.ResolveServer(req.ServerIP, "")

	if err := checkText("reason", req.Reason, 2000, true); err != nil {
		return models.AccessRequest{}, false, err
	}
	if err := checkText("requester", req.Requester, 200, true); err != nil {
		return models.AccessRequest{}, false, err
	}
	if !slices.Contains(validScopes, req.RequestedScope) {
		req.RequestedScope = "prefix_with_objects"
	}
	if !slices.Contains(validDurations, req.Duration) {
		return models.AccessRequest{}, false, fmt.Errorf("duration must be one of %v", validDurations)
	}
	tpl := s.TemplateForGroups(groups)
	if !slices.Contains(tpl.AllowedScopes, req.RequestedScope) {
		return models.AccessRequest{}, false, fmt.Errorf("scope %q is not offered for this server (allowed: %v)", req.RequestedScope, tpl.AllowedScopes)
	}
	if !slices.Contains(tpl.AllowedDurations, req.Duration) {
		return models.AccessRequest{}, false, fmt.Errorf("duration %q is not offered for this server (allowed: %v)", req.Duration, tpl.AllowedDurations)
	}
	if !slices.Contains(allowedMethods, req.Method) || req.Method == "*" {
		req.Method = "GET"
	}
	req.TraceID = clip(req.TraceID, 64)
	req.UserAgent = clip(req.UserAgent, 512)

	var result models.AccessRequest
	isNew := false
	err := s.withWrite(func() error {
		pending, unverified, fromSource, fromServer := 0, 0, 0, 0
		for _, existing := range s.state.Requests {
			if existing.Status != "pending" {
				continue
			}
			pending++
			if !existing.Verified {
				unverified++
				if existing.SourceIP != "" && existing.SourceIP == req.SourceIP {
					fromSource++
				}
			}
			if srvID != "" && existing.ServerID == srvID {
				fromServer++
			}
			if existing.ServerID == srvID && existing.Host == engine.NormalizeHost(req.Host) && existing.Path == req.Path {
				result = existing
				return nil
			}
		}
		// Unverified (self-reported) requests get a small quota of their own, so an anonymous flood
		// can never crowd out requests proven by a data-plane block token.
		switch {
		case pending >= maxPendingRequests,
			!req.Verified && (unverified >= maxPendingUnverified || fromSource >= maxPendingPerSource),
			fromServer >= maxPendingPerServer:
			return ErrTooManyPending
		}

		now := time.Now().UTC()
		req.ID = newRandomID("req")
		req.CreatedAt = now
		req.Status = "pending"
		req.ServerID = srvID
		req.ServerHostname = srvHost
		req.GroupIDs = groups
		req.TargetGroupIDs = append([]string(nil), groups...)
		req.Comments, req.CreatedRuleIDs, req.AssignedTo = []models.RequestComment{}, nil, ""
		if h := s.state.Governance.RequestSLAHours; h > 0 {
			due := now.Add(time.Duration(h) * time.Hour)
			req.DueAt = &due
		}

		cleanPath, okP := engine.CanonicalizePath(req.Path)
		if !okP {
			cleanPath = "/"
		}
		req.Path = cleanPath
		req.Host = engine.NormalizeHost(req.Host)

		h, p, follow := engine.SuggestRulePattern(req.Host, req.Path)
		req.SuggestedHostPattern = h
		req.SuggestedPathPattern = p
		req.FollowRedirects = follow

		switch req.RequestedScope {
		case "domain":
			req.SuggestedPathPattern = "/**"
		case "exact_path":
			req.SuggestedPathPattern = req.Path
		}

		s.state.Requests = append([]models.AccessRequest{req}, s.state.Requests...)
		if len(s.state.Requests) > maxRequests {
			s.state.Requests = s.state.Requests[:maxRequests]
		}
		verified := "UNVERIFIED (self-reported server identity)"
		if req.Verified {
			verified = "verified by data-plane block token"
		}
		// The requester name is self-reported: it never becomes the audit actor.
		actor := "portal"
		if req.SourceIP != "" {
			actor = "portal:" + req.SourceIP
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor:      actor,
			ActorRole:  "SERVER_PORTAL",
			Action:     "REQUEST_SUBMITTED",
			Category:   "APPROVAL",
			EntityType: "access_request",
			EntityID:   req.ID,
			EntityName: req.SuggestedHostPattern + req.SuggestedPathPattern,
			Summary: fmt.Sprintf("Access request by %q from %s (%s, %s) for %s — Reason: %s", oneLine(req.Requester), req.ServerHostname, req.ServerIP,
				verified, oneLine(req.RequestedURL), oneLine(req.Reason)),
			ScopeGroups: req.TargetGroupIDs,
			AfterState:  fmt.Sprintf("{\n  \"requested_url\": %q,\n  \"scope\": %q,\n  \"duration\": %q,\n  \"source_ip\": %q,\n  \"verified\": %v\n}", req.RequestedURL, req.RequestedScope, req.Duration, req.SourceIP, req.Verified),
		})
		s.markDirtyLocked()
		result, isNew = req, true
		return nil
	})
	if err != nil {
		return models.AccessRequest{}, false, err
	}
	if !isNew {
		return result, false, nil
	}

	if s.notifier != nil {
		s.notifier.NotifyAccessRequest(result)
	}
	return result, true, nil
}

// ReviewOptions carries a reviewer's decision and adjustments.
type ReviewOptions struct {
	Approve         bool     `json:"approve"`
	Comment         string   `json:"comment"`
	HostPattern     string   `json:"host_pattern"`
	PathPattern     string   `json:"path_pattern"`
	FollowRedirects bool     `json:"follow_redirects"`
	TargetGroupIDs  []string `json:"target_group_ids"`
	Duration        string   `json:"duration"` // "" = as requested
	Methods         []string `json:"methods"`  // "" = read-only + the requested method
}

// serverForRequestLocked finds the registered server a request came from (by ID, else by IP).
func (s *Store) serverForRequestLocked(req *models.AccessRequest) (models.Server, bool) {
	for _, srv := range s.state.Servers {
		if (req.ServerID != "" && srv.ID == req.ServerID) || (req.ServerID == "" && req.ServerIP != "" && srv.IP == req.ServerIP) {
			return srv, true
		}
	}
	return models.Server{}, false
}

func (s *Store) requestIndexLocked(id string) int {
	return slices.IndexFunc(s.state.Requests, func(r models.AccessRequest) bool { return r.ID == id })
}

// canHandleRequestLocked checks that the actor may act on a request of the given groups.
func canHandleRequest(actor *auth.TokenClaims, groups []string) error {
	if actor.Role == models.RoleAuditorOperator {
		return errors.New("RBAC Policy: read-only role")
	}
	if !auth.CanManageSystem(actor) && !auth.CanApproveForGroups(actor, groups) {
		return fmt.Errorf("RBAC Policy: Role %s is not authorized for server groups %v", actor.Role, groups)
	}
	return nil
}

// ReviewAccessRequest approves or rejects a pending request. Approval adds one rule per target
// group to that group's "approved requests" policy set (published immediately — the approval is the
// review) or starts a learning session.
func (s *Store) ReviewAccessRequest(id string, o ReviewOptions, reviewer *auth.TokenClaims) (*models.AccessRequest, []models.PolicyRule, error) {
	if err := checkText("comment", o.Comment, 2000, false); err != nil {
		return nil, nil, err
	}
	var outReq *models.AccessRequest
	var outRules []models.PolicyRule
	var newCRs []models.ChangeRequest
	err := s.withWrite(func() error {
		idx := s.requestIndexLocked(id)
		if idx == -1 {
			return errors.New("request not found")
		}
		req := &s.state.Requests[idx]
		if !s.requestVisibleLocked(reviewer, req) {
			return errors.New("request not found")
		}
		if req.Status != "pending" {
			return fmt.Errorf("request %s was already %s by %s", req.ID, req.Status, req.ReviewedBy)
		}
		// The reviewer must be responsible for the request itself, not only for the groups chosen.
		if err := canHandleRequest(reviewer, s.requestGroupsLocked(req)); err != nil {
			return err
		}

		groupsToCheck := o.TargetGroupIDs
		if len(groupsToCheck) == 0 {
			groupsToCheck = req.TargetGroupIDs
		}
		if !auth.CanApproveForGroups(reviewer, groupsToCheck) {
			return fmt.Errorf("RBAC Policy: Role %s is not authorized to approve rules for server groups %v", reviewer.Role, groupsToCheck)
		}
		if err := s.validateScopeLocked(groupsToCheck, nil); err != nil {
			return err
		}
		// Audit entries are visible to the teams of the request and of the chosen target groups.
		auditGroups := unionGroups(req.TargetGroupIDs, req.GroupIDs, groupsToCheck)
		openChanges := s.openRequestChangesLocked(req)
		if o.Approve && len(openChanges) > 0 {
			return fmt.Errorf("an approval of this request is awaiting four-eyes review in change request(s) %v; decide those instead", openChanges)
		}

		now := time.Now().UTC()
		if !o.Approve {
			// Rejecting the request also withdraws approvals still waiting for four-eyes review.
			for _, crID := range openChanges {
				if j := slices.IndexFunc(s.state.ChangeRequests, func(c models.ChangeRequest) bool { return c.ID == crID }); j >= 0 {
					cr := &s.state.ChangeRequests[j]
					cr.Status, cr.DecidedBy, cr.DecidedAt = "withdrawn", reviewer.Username, &now
				}
			}
			req.ReviewedBy, req.ReviewerRole, req.ReviewComment, req.ReviewedAt = reviewer.Username, string(reviewer.Role), o.Comment, &now
			req.Status = "rejected"
			s.appendAuditLocked(models.AuditEvent{
				Actor:       reviewer.Username,
				ActorRole:   string(reviewer.Role),
				Action:      "REQUEST_REJECTED",
				Category:    "APPROVAL",
				EntityType:  "access_request",
				EntityID:    req.ID,
				EntityName:  req.SuggestedHostPattern + req.SuggestedPathPattern,
				Summary:     fmt.Sprintf("Rejected access request %s from %s (%s)", req.ID, req.Requester, o.Comment),
				ScopeGroups: auditGroups,
			})
			s.markDirtyLocked()
			reqCopy := *req
			outReq = &reqCopy
			return nil
		}

		if req.RequestedScope == "learning_session_15m" {
			// A session opens egress for the requesting server itself, so it is authorized against the
			// server's current effective groups, never against reviewer-chosen target groups.
			sessGroups := groupsToCheck
			if srv, ok := s.serverForRequestLocked(req); ok {
				sessGroups = srv.EffectiveGroupIDs
				if sessGroups == nil {
					sessGroups = srv.GroupIDs
				}
				if !auth.CanApproveForGroups(reviewer, sessGroups) {
					return fmt.Errorf("RBAC Policy: Role %s is not authorized to start a learning session for %s (groups %v)", reviewer.Role, srv.Hostname, sessGroups)
				}
			} else if !auth.CanManageSystem(reviewer) {
				return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can approve learning sessions for unregistered sources")
			}
			if len(sessGroups) == 0 {
				return errors.New("learning sessions need a registered server with a group membership")
			}
			if s.anyStrictLocked(sessGroups) {
				return errors.New("learning sessions are not permitted for strict-isolation (zero-internet) server groups")
			}
			groupsToCheck = sessGroups
			req.ReviewedBy, req.ReviewerRole, req.ReviewComment, req.ReviewedAt = reviewer.Username, string(reviewer.Role), o.Comment, &now
			req.Status = "approved"
			sess := models.LearningSession{
				ID:             newRandomID("sess"),
				Name:           fmt.Sprintf("Learning Session: %s (%s)", req.ServerHostname, req.Requester),
				Description:    req.Reason,
				ServerID:       req.ServerID,
				ServerIP:       req.ServerIP,
				ServerHostname: req.ServerHostname,
				GroupIDs:       groupsToCheck,
				Mode:           "record_and_allow",
				Status:         "active",
				StartedBy:      reviewer.Username,
				StartedAt:      now,
				ExpiresAt:      now.Add(15 * time.Minute),
			}
			req.ExpiresAt = &sess.ExpiresAt
			s.state.Sessions = append([]models.LearningSession{sess}, s.state.Sessions...)
			s.appendAuditLocked(models.AuditEvent{
				Actor:       reviewer.Username,
				ActorRole:   string(reviewer.Role),
				Action:      "REQUEST_APPROVED",
				Category:    "APPROVAL",
				EntityType:  "learning_session",
				EntityID:    sess.ID,
				EntityName:  sess.Name,
				Summary:     fmt.Sprintf("Approved 15m Learning Session %s for %s (%s)", sess.ID, req.ServerHostname, req.ServerIP),
				ScopeGroups: unionGroups(auditGroups, groupsToCheck),
			})
			s.saveLocked()
			reqCopy := *req
			outReq = &reqCopy
			return nil
		}
		if len(groupsToCheck) == 0 {
			return errors.New("the request has no target group: register the server first or choose target groups")
		}

		hostPat := req.SuggestedHostPattern
		if strings.TrimSpace(o.HostPattern) != "" {
			hostPat = o.HostPattern
		}
		pathPat := req.SuggestedPathPattern
		if strings.TrimSpace(o.PathPattern) != "" {
			pathPat = o.PathPattern
		}
		duration := req.Duration
		if o.Duration != "" {
			duration = o.Duration
		}
		expiresAt, err := s.expiryForLocked(duration, reviewer, now)
		if err != nil {
			return err
		}

		var companions []string
		if strings.EqualFold(hostPat, "github.com") && strings.HasPrefix(pathPat, "/") {
			org := strings.Split(strings.Trim(pathPat, "/"), "/")[0]
			if org != "" && org != "*" && org != "**" {
				companions = []string{
					fmt.Sprintf("codeload.github.com/%s/**", org),
					fmt.Sprintf("api.github.com/repos/%s/**", org),
					fmt.Sprintf("raw.githubusercontent.com/%s/**", org),
				}
			}
		}

		// Least privilege: read-only methods plus the method that was actually requested.
		methods := []string{"GET", "HEAD"}
		if !slices.Contains(methods, req.Method) && req.Method != "CONNECT" {
			methods = append(methods, req.Method)
		}
		if len(o.Methods) > 0 {
			methods = o.Methods
		}
		reviewReasons := s.approvalReviewReasonsLocked(req, reviewer, hostPat, pathPat, duration, methods, o.FollowRedirects, groupsToCheck)

		var created []models.PolicyRule
		var proposed []models.ChangeRequest
		for _, gid := range groupsToCheck {
			if gid == "*" {
				return errors.New("approvals must target concrete server groups")
			}
			i := s.ensureApprovalsSetLocked(gid)
			set := &s.state.PolicySets[i]
			rule := models.PolicyRule{
				ID:              newRandomID("rule"),
				Name:            clip(fmt.Sprintf("Approved: %s%s (%s)", hostPat, pathPat, req.Requester), 200),
				Description:     clip(req.Reason, 2000),
				Action:          "ALLOW",
				HostPattern:     hostPat,
				PathPattern:     pathPat,
				Methods:         append([]string(nil), methods...),
				FollowRedirects: o.FollowRedirects,
				CompanionRules:  companions,
				CreatedBy:       req.Requester,
				ApprovedBy:      reviewer.Username,
				Enabled:         true,
				CreatedAt:       now,
				ExpiresAt:       expiresAt,
				AccessRequestID: req.ID,
			}
			spec := cloneSpec(set.PolicySetSpec)
			spec.Rules = append(spec.Rules, rule)
			if err := s.validateSpecLocked(set.ID, set.Kind, &spec, reviewer); err != nil {
				return err
			}
			rule = spec.Rules[len(spec.Rules)-1]
			if len(reviewReasons) > 0 {
				// Four-eyes: the approval becomes a change request of the approvals set; the set and
				// its draft stay untouched until another reviewer approves it.
				diff := DiffSpecs(set.PolicySetSpec, spec)
				proposed = append(proposed, models.ChangeRequest{
					ID: newRandomID("cr"), PolicySetID: set.ID, PolicySetName: set.Name,
					Title: clip(fmt.Sprintf("Access request %s: %s%s (%s)", req.ID, hostPat, pathPat, duration), 200),
					Description: clip(fmt.Sprintf("Approval of access request %s by %s needs four-eyes review: %s.\nRequester %s on %s (%s): %s\nReviewer comment: %s",
						req.ID, reviewer.Username, strings.Join(reviewReasons, "; "), req.Requester, req.ServerHostname, req.ServerIP, req.Reason, o.Comment), 4000),
					Status: "open", BaseVersion: set.Version, Spec: spec, Diff: &diff, SubmittedBy: reviewer.Username, SubmittedAt: now,
					Reviews: []models.ChangeReview{}, AccessRequestID: req.ID,
				})
				continue
			}
			draft := set.Draft
			s.publishLocked(i, spec, reviewer, publishOpts{comment: "access request " + req.ID, quiet: true})
			if draft != nil && draft.Status == "editing" {
				// Keep a concurrent manual draft and carry the approval into it.
				draft.Spec.Rules = append(draft.Spec.Rules, rule)
				draft.BaseVersion = s.state.PolicySets[i].Version
				s.state.PolicySets[i].Draft = draft
			} else if draft != nil {
				s.state.PolicySets[i].Draft = draft // in review: the change request becomes superseded on approval
			}
			created = append(created, rule)
		}
		if len(proposed) > 0 {
			ids := make([]string, 0, len(proposed))
			for _, cr := range proposed {
				ids = append(ids, cr.ID)
				groups, _ := setScope(&s.state.PolicySets[s.setIndexLocked(cr.PolicySetID)])
				s.appendAuditLocked(models.AuditEvent{
					Actor: reviewer.Username, ActorRole: string(reviewer.Role), Action: "CHANGE_REQUEST_SUBMITTED", Category: "POLICY",
					EntityType: "change_request", EntityID: cr.ID, EntityName: cr.Title, ScopeGroups: unionGroups(auditGroups, groups),
					Summary: fmt.Sprintf("Approval of access request %s submitted for four-eyes review (%s): %s", req.ID, strings.Join(reviewReasons, "; "), diffSummary(*cr.Diff)),
				})
			}
			s.state.ChangeRequests = append(slices.Clone(proposed), s.state.ChangeRequests...)
			if len(s.state.ChangeRequests) > 2000 {
				s.state.ChangeRequests = s.state.ChangeRequests[:2000]
			}
			req.ChangeRequestIDs = ids
			req.Comments = append(slices.Clip(req.Comments), models.RequestComment{Author: reviewer.Username, At: now,
				Text: fmt.Sprintf("Approval submitted for four-eyes review (%s) as change request(s) %s; access is granted when another reviewer approves.",
					strings.Join(reviewReasons, "; "), strings.Join(ids, ", "))})
			s.markDirtyLocked()
			reqCopy := *req
			outReq, newCRs = &reqCopy, proposed
			return nil
		}

		req.ReviewedBy, req.ReviewerRole, req.ReviewComment, req.ReviewedAt = reviewer.Username, string(reviewer.Role), o.Comment, &now
		req.Status = "approved"
		req.TargetGroupIDs = append([]string(nil), groupsToCheck...)
		req.ExpiresAt = expiresAt
		req.CreatedRuleIDs = nil
		for _, r := range created {
			req.CreatedRuleIDs = append(req.CreatedRuleIDs, r.ID)
		}
		req.CreatedRuleID = created[0].ID
		ruleSnap := cloneRule(created[0])
		ruleSnap.GroupIDs = groupsToCheck
		s.appendAuditLocked(models.AuditEvent{
			Actor:       reviewer.Username,
			ActorRole:   string(reviewer.Role),
			Action:      "REQUEST_APPROVED",
			Category:    "APPROVAL",
			EntityType:  "access_request",
			EntityID:    req.ID,
			EntityName:  fmt.Sprintf("%s%s", hostPat, pathPat),
			Summary:     fmt.Sprintf("Approved request %s: %s%s for groups %v (%s), added to approved-requests policy sets", req.ID, hostPat, pathPat, groupsToCheck, duration),
			ScopeGroups: auditGroups,
			AfterState:  formatRuleAuditJSON(ruleSnap),
		})
		s.saveLocked()
		reqCopy := *req
		outReq, outRules = &reqCopy, created
		return nil
	})
	for _, cr := range newCRs {
		s.announceChangeRequest(cr)
	}
	if err == nil && outReq != nil && outReq.Status != "pending" && s.notifier != nil {
		s.notifier.NotifyRequestDecision(*outReq)
	}
	return outReq, outRules, err
}

// approvalReviewReasonsLocked lists why an approval needs four-eyes review: with policy review
// required, a reviewer below InfoSec may grant only what an attested request asked for. Anything the
// reviewer chose themselves (patterns, methods, longer duration, redirects, other groups) or a
// self-reported request goes through a change request.
func (s *Store) approvalReviewReasonsLocked(req *models.AccessRequest, reviewer *auth.TokenClaims, hostPat, pathPat, duration string,
	methods []string, followRedirects bool, groups []string) []string {
	if !s.state.Governance.RequirePolicyReview || auth.CanManageSystem(reviewer) {
		return nil
	}
	var why []string
	if !req.Verified {
		why = append(why, "the request is not attested by a data-plane block token")
	}
	if !strings.EqualFold(hostPat, req.SuggestedHostPattern) || pathPat != req.SuggestedPathPattern {
		why = append(why, "the reviewer changed the host or path pattern")
	}
	if slices.ContainsFunc(methods, func(m string) bool { return m != "GET" && m != "HEAD" && m != req.Method }) {
		why = append(why, "the reviewer added methods")
	}
	if req.Duration != "permanent" {
		want, _ := durationOf(req.Duration)
		if got, ok := durationOf(duration); !ok || got > want {
			why = append(why, "the reviewer granted a longer duration than requested")
		}
	}
	if followRedirects && !req.FollowRedirects {
		why = append(why, "the reviewer enabled redirect following")
	}
	if own := s.requestGroupsLocked(req); slices.ContainsFunc(groups, func(g string) bool { return !slices.Contains(own, g) }) {
		why = append(why, "the reviewer chose other target groups")
	}
	return why
}

// requestGroupsLocked returns the groups responsible for a request: its target groups, else the
// current groups of the registered server it came from.
func (s *Store) requestGroupsLocked(req *models.AccessRequest) []string {
	if len(req.TargetGroupIDs) > 0 {
		return req.TargetGroupIDs
	}
	if srv, ok := s.serverForRequestLocked(req); ok {
		if srv.EffectiveGroupIDs != nil {
			return srv.EffectiveGroupIDs
		}
		return srv.GroupIDs
	}
	return nil
}

// requestVisibleLocked mirrors the API's need-to-know view: Team Leads see the requests of their
// groups only, everything else does not exist for them.
func (s *Store) requestVisibleLocked(actor *auth.TokenClaims, req *models.AccessRequest) bool {
	if !scopedTeamLead(actor) {
		return actor != nil
	}
	mine := func(g string) bool { return slices.Contains(actor.AllowedGroups, g) }
	return slices.ContainsFunc(req.TargetGroupIDs, mine) || slices.ContainsFunc(req.GroupIDs, mine)
}

// openRequestChangesLocked returns the IDs of the request's change requests still awaiting review.
func (s *Store) openRequestChangesLocked(req *models.AccessRequest) []string {
	var open []string
	for _, id := range req.ChangeRequestIDs {
		if cr, ok := s.changeRequestLocked(id); ok && cr.Status == "open" {
			open = append(open, id)
		}
	}
	return open
}

func (s *Store) changeRequestLocked(id string) (*models.ChangeRequest, bool) {
	if j := slices.IndexFunc(s.state.ChangeRequests, func(c models.ChangeRequest) bool { return c.ID == id }); j >= 0 {
		return &s.state.ChangeRequests[j], true
	}
	return nil, false
}

// publishRequestChangeLocked publishes the rules of an approved access-request change request on
// top of the set's current content (approvals sets change with every approval, so these change
// requests are rebased instead of superseded). The granted duration counts from now.
func (s *Store) publishRequestChangeLocked(i int, cr *models.ChangeRequest, actor *auth.TokenClaims, comment string) (models.PolicySetVersion, error) {
	set := &s.state.PolicySets[i]
	spec := cloneSpec(set.PolicySetSpec)
	now := time.Now().UTC()
	added := 0
	for _, r := range cr.Spec.Rules {
		if r.AccessRequestID != cr.AccessRequestID || slices.ContainsFunc(spec.Rules, func(x models.PolicyRule) bool { return x.ID == r.ID }) {
			continue
		}
		r = cloneRule(r)
		if r.ExpiresAt != nil {
			exp := now.Add(r.ExpiresAt.Sub(cr.SubmittedAt))
			r.ExpiresAt = &exp
		}
		spec.Rules = append(spec.Rules, r)
		added++
	}
	if added == 0 {
		return models.PolicySetVersion{}, errors.New("the change request carries no access rules")
	}
	if err := s.validateSpecLocked(set.ID, set.Kind, &spec, actor); err != nil {
		return models.PolicySetVersion{}, err
	}
	draft := set.Draft
	v := s.publishLocked(i, spec, actor, publishOpts{changeRequestID: cr.ID, comment: comment})
	if draft != nil && draft.Status == "editing" {
		// Keep a concurrent manual draft and carry the approval into it.
		for _, r := range spec.Rules {
			if r.AccessRequestID == cr.AccessRequestID && !slices.ContainsFunc(draft.Spec.Rules, func(x models.PolicyRule) bool { return x.ID == r.ID }) {
				draft.Spec.Rules = append(draft.Spec.Rules, r)
			}
		}
		draft.BaseVersion = s.state.PolicySets[i].Version
	}
	s.state.PolicySets[i].Draft = draft
	return v, nil
}

// settleRequestChangesLocked resolves an access request once none of its four-eyes change requests
// is open: granted when at least one was approved (returned for notification), pending again
// otherwise.
func (s *Store) settleRequestChangesLocked(reqID string) *models.AccessRequest {
	idx := s.requestIndexLocked(reqID)
	if idx < 0 {
		return nil
	}
	req := &s.state.Requests[idx]
	if req.Status != "pending" || len(req.ChangeRequestIDs) == 0 {
		return nil
	}
	var approved []*models.ChangeRequest
	for _, id := range req.ChangeRequestIDs {
		cr, ok := s.changeRequestLocked(id)
		if !ok {
			continue
		}
		switch cr.Status {
		case "open":
			return nil
		case "approved":
			approved = append(approved, cr)
		}
	}
	now := time.Now().UTC()
	if len(approved) == 0 {
		req.Comments = append(slices.Clip(req.Comments), models.RequestComment{Author: "system", At: now,
			Text: fmt.Sprintf("Change request(s) %s were not approved; the request is pending again.", strings.Join(req.ChangeRequestIDs, ", "))})
		req.ChangeRequestIDs = nil
		return nil
	}
	var groups, ruleIDs []string
	var expires *time.Time
	for _, cr := range approved {
		i := s.setIndexLocked(cr.PolicySetID)
		if i < 0 {
			continue
		}
		g, _ := setScope(&s.state.PolicySets[i])
		groups = unionGroups(groups, g)
		for _, r := range s.state.PolicySets[i].Rules {
			if r.AccessRequestID == req.ID {
				ruleIDs = append(ruleIDs, r.ID)
				if expires == nil {
					expires = r.ExpiresAt
				}
			}
		}
	}
	last := approved[len(approved)-1]
	role, comment := "", ""
	for _, rv := range last.Reviews {
		if rv.Decision == "approve" {
			role, comment = rv.Role, rv.Comment
		}
	}
	auditGroups := unionGroups(req.TargetGroupIDs, req.GroupIDs, groups)
	req.Status = "approved"
	req.ReviewedBy, req.ReviewerRole, req.ReviewComment, req.ReviewedAt = last.DecidedBy, role, comment, &now
	req.TargetGroupIDs = groups
	req.ExpiresAt = expires
	req.CreatedRuleIDs = ruleIDs
	if len(ruleIDs) > 0 {
		req.CreatedRuleID = ruleIDs[0]
	}
	req.Comments = append(slices.Clip(req.Comments), models.RequestComment{Author: last.DecidedBy, At: now,
		Text: fmt.Sprintf("Access granted after four-eyes review (change request %s, submitted by %s).", last.ID, last.SubmittedBy)})
	s.appendAuditLocked(models.AuditEvent{
		Actor: last.DecidedBy, ActorRole: role, Action: "REQUEST_APPROVED", Category: "APPROVAL",
		EntityType: "access_request", EntityID: req.ID, EntityName: req.SuggestedHostPattern + req.SuggestedPathPattern,
		Summary: fmt.Sprintf("Approved request %s for groups %v after four-eyes review of change request(s) %s submitted by %s",
			req.ID, groups, strings.Join(req.ChangeRequestIDs, ", "), last.SubmittedBy),
		ScopeGroups: auditGroups,
	})
	cp := *req
	return &cp
}

// unionGroups merges group lists without duplicates (order of first appearance).
func unionGroups(lists ...[]string) []string {
	out := []string{}
	for _, l := range lists {
		for _, g := range l {
			if !slices.Contains(out, g) {
				out = append(out, g)
			}
		}
	}
	return out
}

// BulkResult is the outcome of one request in a bulk review.
type BulkResult struct {
	ID     string `json:"id"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// BulkReviewRequests applies the same decision (with the requested scopes) to many requests.
func (s *Store) BulkReviewRequests(ids []string, approve bool, comment string, reviewer *auth.TokenClaims) ([]BulkResult, error) {
	if len(ids) == 0 || len(ids) > 200 {
		return nil, errors.New("select between 1 and 200 requests")
	}
	out := make([]BulkResult, 0, len(ids))
	for _, id := range ids {
		req, _, err := s.ReviewAccessRequest(id, ReviewOptions{Approve: approve, Comment: comment}, reviewer)
		res := BulkResult{ID: id}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Status = req.Status
		}
		out = append(out, res)
	}
	return out, nil
}

// CommentRequest appends a discussion entry.
func (s *Store) CommentRequest(id, text string, actor *auth.TokenClaims) (models.AccessRequest, error) {
	text = strings.TrimSpace(text)
	if err := checkMultiline("comment", text, 2000); err != nil {
		return models.AccessRequest{}, err
	}
	if text == "" {
		return models.AccessRequest{}, errors.New("comment is empty")
	}
	var out models.AccessRequest
	err := s.withWrite(func() error {
		i := s.requestIndexLocked(id)
		if i < 0 {
			return errors.New("request not found")
		}
		req := &s.state.Requests[i]
		if !s.requestVisibleLocked(actor, req) {
			return errors.New("request not found")
		}
		if err := canHandleRequest(actor, req.TargetGroupIDs); err != nil {
			return err
		}
		if len(req.Comments) >= 100 {
			return errors.New("too many comments on this request")
		}
		req.Comments = append(req.Comments, models.RequestComment{Author: actor.Username, Text: text, At: time.Now().UTC()})
		s.markDirtyLocked()
		out = *req
		return nil
	})
	return out, err
}

// AssignRequest sets the responsible reviewer ("" = unassigned).
func (s *Store) AssignRequest(id, assignee string, actor *auth.TokenClaims) (models.AccessRequest, error) {
	assignee = strings.ToLower(strings.TrimSpace(assignee))
	var out models.AccessRequest
	err := s.withWrite(func() error {
		i := s.requestIndexLocked(id)
		if i < 0 {
			return errors.New("request not found")
		}
		req := &s.state.Requests[i]
		if !s.requestVisibleLocked(actor, req) {
			return errors.New("request not found")
		}
		if err := canHandleRequest(actor, req.TargetGroupIDs); err != nil {
			return err
		}
		if assignee != "" {
			j := slices.IndexFunc(s.state.Users, func(u models.User) bool { return strings.EqualFold(u.Username, assignee) })
			if j < 0 || s.state.Users[j].Disabled {
				return fmt.Errorf("unknown or disabled user %q", assignee)
			}
			u := s.state.Users[j]
			claims := &auth.TokenClaims{Username: u.Username, Role: u.Role, AllowedGroups: u.AllowedGroups}
			if u.Role == models.RoleAuditorOperator || (!auth.CanManageSystem(claims) && !auth.CanApproveForGroups(claims, req.TargetGroupIDs)) {
				return fmt.Errorf("%s cannot approve requests for groups %v", u.Username, req.TargetGroupIDs)
			}
		}
		req.AssignedTo = assignee
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "REQUEST_ASSIGNED", Category: "APPROVAL",
			EntityType: "access_request", EntityID: req.ID, EntityName: req.SuggestedHostPattern + req.SuggestedPathPattern,
			Summary: fmt.Sprintf("Assigned request %s to %q", req.ID, assignee), ScopeGroups: req.TargetGroupIDs,
		})
		s.markDirtyLocked()
		out = *req
		return nil
	})
	return out, err
}

// editRequestRulesLocked applies fn to every rule created by the request and publishes the
// affected approvals sets.
func (s *Store) editRequestRulesLocked(req *models.AccessRequest, actor *auth.TokenClaims, note string, fn func(r *models.PolicyRule) (keep bool)) error {
	ids := req.CreatedRuleIDs
	if len(ids) == 0 && req.CreatedRuleID != "" {
		ids = []string{req.CreatedRuleID}
	}
	for i := range s.state.PolicySets {
		set := &s.state.PolicySets[i]
		touched := false
		spec := cloneSpec(set.PolicySetSpec)
		kept := spec.Rules[:0]
		for _, r := range spec.Rules {
			if slices.Contains(ids, r.ID) || (r.AccessRequestID != "" && r.AccessRequestID == req.ID) {
				touched = true
				if !fn(&r) {
					continue
				}
			}
			kept = append(kept, r)
		}
		if !touched {
			continue
		}
		spec.Rules = kept
		if err := s.validateSpecLocked(set.ID, set.Kind, &spec, actor); err != nil {
			return err
		}
		draft := set.Draft
		s.publishLocked(i, spec, actor, publishOpts{comment: note, quiet: true})
		if draft != nil && draft.Status == "editing" {
			draft.Spec.Rules = slices.DeleteFunc(draft.Spec.Rules, func(r models.PolicyRule) bool { return slices.Contains(ids, r.ID) })
			for _, r := range spec.Rules {
				if slices.Contains(ids, r.ID) {
					draft.Spec.Rules = append(draft.Spec.Rules, r)
				}
			}
			draft.BaseVersion = s.state.PolicySets[i].Version
			s.state.PolicySets[i].Draft = draft
		}
	}
	return nil
}

// RevokeAccessRequest withdraws access granted by an approved request.
func (s *Store) RevokeAccessRequest(id, reason string, actor *auth.TokenClaims) (models.AccessRequest, error) {
	if err := checkText("reason", reason, 500, true); err != nil {
		return models.AccessRequest{}, err
	}
	var out models.AccessRequest
	err := s.withWrite(func() error {
		i := s.requestIndexLocked(id)
		if i < 0 {
			return errors.New("request not found")
		}
		req := &s.state.Requests[i]
		if !s.requestVisibleLocked(actor, req) {
			return errors.New("request not found")
		}
		if req.Status != "approved" {
			return fmt.Errorf("only approved requests can be revoked (status: %s)", req.Status)
		}
		if err := canHandleRequest(actor, req.TargetGroupIDs); err != nil {
			return err
		}
		if err := s.editRequestRulesLocked(req, actor, "revoked access request "+req.ID, func(*models.PolicyRule) bool { return false }); err != nil {
			return err
		}
		if req.RequestedScope == "learning_session_15m" {
			for j := range s.state.Sessions {
				if s.state.Sessions[j].ServerID == req.ServerID && s.state.Sessions[j].Status == "active" {
					s.state.Sessions[j].Status = "stopped"
				}
			}
		}
		now := time.Now().UTC()
		req.Status, req.RevokedBy, req.RevokedAt = "revoked", actor.Username, &now
		req.Comments = append(req.Comments, models.RequestComment{Author: actor.Username, Text: "Access revoked: " + reason, At: now})
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "REQUEST_REVOKED", Category: "APPROVAL",
			EntityType: "access_request", EntityID: req.ID, EntityName: req.SuggestedHostPattern + req.SuggestedPathPattern,
			Summary: fmt.Sprintf("Revoked access of request %s (%s): %s", req.ID, req.ServerHostname, reason), ScopeGroups: req.TargetGroupIDs,
		})
		s.saveLocked()
		out = *req
		return nil
	})
	return out, err
}

// ExtendAccessRequest changes the expiry of temporary access granted by an approved request.
func (s *Store) ExtendAccessRequest(id, duration string, actor *auth.TokenClaims) (models.AccessRequest, error) {
	var out models.AccessRequest
	err := s.withWrite(func() error {
		i := s.requestIndexLocked(id)
		if i < 0 {
			return errors.New("request not found")
		}
		req := &s.state.Requests[i]
		if !s.requestVisibleLocked(actor, req) {
			return errors.New("request not found")
		}
		if req.Status != "approved" || req.RequestedScope == "learning_session_15m" {
			return errors.New("only approved rule-based requests can be extended")
		}
		if err := canHandleRequest(actor, req.TargetGroupIDs); err != nil {
			return err
		}
		now := time.Now().UTC()
		exp, err := s.expiryForLocked(duration, actor, now)
		if err != nil {
			return err
		}
		// With four-eyes review required, Team Lead extensions share one budget: the governance
		// maximum counted from the original approval, so repeated extensions cannot add up.
		if maxDays := s.state.Governance.MaxTemporaryAccessDays; s.state.Governance.RequirePolicyReview && !auth.CanManageSystem(actor) && maxDays > 0 && exp != nil {
			start := req.CreatedAt
			if req.ReviewedAt != nil {
				start = *req.ReviewedAt
			}
			if limit := start.Add(time.Duration(maxDays) * 24 * time.Hour); exp.After(limit) {
				return fmt.Errorf("RBAC Policy: with four-eyes review required, Team Leads can extend access to at most %d days after the original approval (until %s); longer access needs InfoSec",
					maxDays, limit.Format(time.RFC3339))
			}
		}
		if err := s.editRequestRulesLocked(req, actor, "extended access request "+req.ID, func(r *models.PolicyRule) bool {
			r.ExpiresAt = exp
			return true
		}); err != nil {
			return err
		}
		req.ExpiresAt = exp
		label := "permanent"
		if exp != nil {
			label = "until " + exp.Format(time.RFC3339)
		}
		req.Comments = append(req.Comments, models.RequestComment{Author: actor.Username, Text: "Access extended " + label, At: now})
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "REQUEST_EXTENDED", Category: "APPROVAL",
			EntityType: "access_request", EntityID: req.ID, EntityName: req.SuggestedHostPattern + req.SuggestedPathPattern,
			Summary: fmt.Sprintf("Extended access of request %s (%s) %s", req.ID, req.ServerHostname, label), ScopeGroups: req.TargetGroupIDs,
		})
		s.saveLocked()
		out = *req
		return nil
	})
	return out, err
}

func (s *Store) anyStrictLocked(groupIDs []string) bool {
	for _, g := range s.state.Groups {
		if g.StrictIsolation && slices.Contains(groupIDs, g.ID) {
			return true
		}
	}
	return false
}

// oneLine replaces control characters (line breaks, escape sequences) in user-supplied text.
func oneLine(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, v)
}
