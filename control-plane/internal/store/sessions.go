package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const maxSessionMinutes = 240

var ErrSessionRecording = errors.New("the learning session is still recording; stop it before publishing its rules")

func (s *Store) StartLearningSession(name, desc, serverID string, durationMinutes int, mode string, actor *auth.TokenClaims) (models.LearningSession, error) {
	if err := checkText("name", name, 200, true); err != nil {
		return models.LearningSession{}, err
	}
	if err := checkText("description", desc, 2000, false); err != nil {
		return models.LearningSession{}, err
	}
	if mode == "" {
		mode = "record_and_allow"
	}
	if mode != "record_and_allow" && mode != "record_only" {
		return models.LearningSession{}, errors.New("mode must be record_and_allow or record_only")
	}
	if durationMinutes <= 0 {
		durationMinutes = 15
	}
	if durationMinutes > maxSessionMinutes {
		return models.LearningSession{}, fmt.Errorf("learning sessions are limited to %d minutes", maxSessionMinutes)
	}

	var sess models.LearningSession
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Servers, func(x models.Server) bool { return x.ID == serverID || x.IP == serverID })
		if i == -1 {
			return fmt.Errorf("reference server %q not found in fleet inventory", serverID)
		}
		srv := s.state.Servers[i]
		// Effective memberships: label-selected groups count like static ones (RBAC and isolation).
		groups := srv.EffectiveGroupIDs
		if groups == nil {
			groups = srv.GroupIDs
		}
		if !auth.CanApproveForGroups(actor, groups) {
			return fmt.Errorf("RBAC Policy: Insufficient permissions to start a learning session for groups %v", groups)
		}
		if mode == "record_and_allow" && s.anyStrictLocked(groups) {
			return errors.New("record_and_allow learning sessions are not permitted for strict-isolation (zero-internet) server groups")
		}

		now := time.Now().UTC()
		sess = models.LearningSession{
			ID:                 newRandomID("sess"),
			Name:               name,
			Description:        desc,
			ServerID:           srv.ID,
			ServerIP:           srv.IP,
			ServerHostname:     srv.Hostname,
			GroupIDs:           append([]string(nil), groups...),
			Mode:               mode,
			Status:             "active",
			StartedBy:          actor.Username,
			StartedAt:          now,
			ExpiresAt:          now.Add(time.Duration(durationMinutes) * time.Minute),
			CompiledCandidates: []models.CompiledRuleCandidate{},
		}
		s.state.Sessions = append([]models.LearningSession{sess}, s.state.Sessions...)
		s.appendAuditLocked(models.AuditEvent{
			Actor:       actor.Username,
			ActorRole:   string(actor.Role),
			Action:      "SESSION_STARTED",
			Category:    "SESSION",
			EntityType:  "learning_session",
			EntityID:    sess.ID,
			EntityName:  sess.Name,
			Summary:     fmt.Sprintf("Started %dm learning session on %s (%s) in mode %s", durationMinutes, srv.Hostname, srv.IP, mode),
			ScopeGroups: groups,
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.LearningSession{}, err
	}
	return sess, nil
}

func (s *Store) StopLearningSession(sessionID string, actor *auth.TokenClaims) (*models.LearningSession, error) {
	var out *models.LearningSession
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Sessions, func(x models.LearningSession) bool { return x.ID == sessionID })
		if i == -1 {
			return fmt.Errorf("session not found")
		}
		sess := &s.state.Sessions[i]
		if !auth.CanApproveForGroups(actor, sess.GroupIDs) {
			return fmt.Errorf("RBAC Policy: Insufficient permissions to stop learning session for groups %v", sess.GroupIDs)
		}
		now := time.Now().UTC()
		if !sess.Recording(now) {
			return errors.New("the learning session has already ended")
		}
		sess.Status = "completed"
		sess.ExpiresAt = now
		s.appendAuditLocked(models.AuditEvent{
			Actor:       actor.Username,
			ActorRole:   string(actor.Role),
			Action:      "SESSION_STOPPED",
			Category:    "SESSION",
			EntityType:  "learning_session",
			EntityID:    sess.ID,
			EntityName:  sess.Name,
			Summary:     fmt.Sprintf("Stopped learning session %s on %s", sess.ID, sess.ServerHostname),
			ScopeGroups: sess.GroupIDs,
		})
		s.saveLocked()
		cp := *sess
		out = &cp
		return nil
	})
	return out, err
}

// SessionPublish describes where compiled learning-session rules go.
type SessionPublish struct {
	Candidates []models.CompiledRuleCandidate `json:"candidates"`
	RulePrefix string                         `json:"rule_prefix"`
	// PolicySetID adds the rules to an existing set; otherwise a new set named NewSetName is created
	// and assigned to TargetGroupIDs / TargetServerIDs.
	PolicySetID     string   `json:"policy_set_id"`
	NewSetName      string   `json:"new_set_name"`
	TargetGroupIDs  []string `json:"target_group_ids"`
	TargetServerIDs []string `json:"target_server_ids"`
	// Publish publishes immediately (when four-eyes review is not required); otherwise the rules
	// are left in the set's draft for review.
	Publish bool `json:"publish"`
}

// PublishSessionRules turns selected learning-session candidates into rules of a policy set.
func (s *Store) PublishSessionRules(sessionID string, p SessionPublish, actor *auth.TokenClaims) (models.PolicySet, []models.PolicyRule, error) {
	if err := checkText("rule_prefix", p.RulePrefix, 80, true); err != nil {
		return models.PolicySet{}, nil, err
	}
	if len(p.Candidates) > 200 {
		return models.PolicySet{}, nil, errors.New("too many candidates in one publish (max 200)")
	}
	var created []models.PolicyRule
	var out models.PolicySet
	err := s.withWrite(func() error {
		sessIdx := slices.IndexFunc(s.state.Sessions, func(x models.LearningSession) bool { return x.ID == sessionID })
		if sessIdx == -1 {
			return fmt.Errorf("learning session %s not found", sessionID)
		}
		if !auth.CanApproveForGroups(actor, s.state.Sessions[sessIdx].GroupIDs) {
			return fmt.Errorf("RBAC Policy: Insufficient permissions for learning session %s", sessionID)
		}
		if s.state.Sessions[sessIdx].Recording(time.Now()) {
			return ErrSessionRecording
		}

		now := time.Now().UTC()
		created = make([]models.PolicyRule, 0)
		for _, c := range p.Candidates {
			if !c.Selected {
				continue
			}
			created = append(created, models.PolicyRule{
				Name:            clip(fmt.Sprintf("%s: %s%s", p.RulePrefix, c.HostPattern, c.PathPattern), 200),
				Description:     fmt.Sprintf("Automatically compiled from Learning Session %s (%d captured requests)", sessionID, c.HitCount),
				Action:          "ALLOW",
				HostPattern:     c.HostPattern,
				PathPattern:     c.PathPattern,
				Methods:         c.Methods,
				FollowRedirects: c.FollowRedirects,
				CompanionRules:  c.CompanionRules,
				CreatedBy:       actor.Username,
				ApprovedBy:      actor.Username,
				SourceSessionID: sessionID,
				Enabled:         true,
				CreatedAt:       now,
			})
		}
		if len(created) == 0 {
			return errors.New("select at least one rule candidate")
		}

		var i int
		var err error
		if p.PolicySetID == "" {
			name := strings.TrimSpace(p.NewSetName)
			if name == "" {
				name = p.RulePrefix
			}
			spec := models.PolicySetSpec{Name: name, Description: "Compiled from learning session " + s.state.Sessions[sessIdx].Name,
				Enabled: true, GroupIDs: p.TargetGroupIDs, ServerIDs: p.TargetServerIDs, Tags: []string{"learning-session"}, Rules: created}
			spec.ReviewIntervalDays = s.state.Governance.DefaultReviewIntervalDays
			if i, err = s.createSetLocked(models.PolicySetKindStandard, spec, actor); err != nil {
				return err
			}
		} else {
			if i = s.setIndexLocked(p.PolicySetID); i < 0 {
				return errors.New("policy set not found")
			}
			set := &s.state.PolicySets[i]
			if set.Kind == models.PolicySetKindApprovals {
				return errors.New("approved-request sets are managed by the request workflow; choose another set")
			}
			if set.Draft != nil && set.Draft.Status == "in_review" {
				return ErrDraftLocked
			}
			spec := cloneSpec(set.PolicySetSpec)
			if set.Draft != nil {
				spec = cloneSpec(set.Draft.Spec)
			}
			spec.Rules = append(spec.Rules, created...)
			if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, spec); err != nil {
				return err
			}
			if err := s.validateSpecLocked(set.ID, set.Kind, &spec, actor); err != nil {
				return err
			}
			set.Draft = &models.PolicySetDraft{Spec: spec, BaseVersion: set.Version, Status: "editing", UpdatedBy: actor.Username, UpdatedAt: now}
		}
		set := &s.state.PolicySets[i]
		if p.Publish && !s.state.Governance.RequirePolicyReview {
			spec := cloneSpec(set.Draft.Spec)
			s.publishLocked(i, spec, actor, publishOpts{comment: "learning session " + sessionID})
		}
		s.state.Sessions[sessIdx].Status = "published"
		published := "drafted in"
		if s.state.PolicySets[i].Draft == nil {
			published = "published to"
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor:       actor.Username,
			ActorRole:   string(actor.Role),
			Action:      "SESSION_PUBLISHED",
			Category:    "SESSION",
			EntityType:  "learning_session",
			EntityID:    sessionID,
			EntityName:  fmt.Sprintf("%s (%d compiled rules)", p.RulePrefix, len(created)),
			Summary:     fmt.Sprintf("Compiled %d whitelist rules from session %s, %s policy set %q", len(created), sessionID, published, s.state.PolicySets[i].Name),
			ScopeGroups: s.state.PolicySets[i].GroupIDs,
		})
		s.saveLocked()
		out = s.decorateSetLocked(s.state.PolicySets[i])
		return nil
	})
	if err != nil {
		return models.PolicySet{}, nil, err
	}
	return out, created, nil
}

// GetSession returns a copy of a learning session.
func (s *Store) GetSession(id string) (models.LearningSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.state.Sessions {
		if sess.ID == id {
			sess.GroupIDs = append([]string(nil), sess.GroupIDs...)
			return sess, true
		}
	}
	return models.LearningSession{}, false
}
