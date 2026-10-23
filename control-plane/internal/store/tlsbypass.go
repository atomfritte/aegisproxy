package store

import (
	"fmt"
	"slices"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

func (s *Store) AddTLSBypass(rule models.TLSBypassRule, actor *auth.TokenClaims) (models.TLSBypassRule, error) {
	if !auth.CanManageSystem(actor) {
		return models.TLSBypassRule{}, fmt.Errorf("RBAC Policy: Only InfoSec and SuperAdmin can modify SSL/TLS Bypass exceptions")
	}
	err := s.withWrite(func() error {
		if err := s.validateTLSBypassLocked(&rule); err != nil {
			return err
		}
		rule.ID = newRandomID("tls")
		rule.CreatedAt = time.Now().UTC()
		rule.AddedBy = actor.Username
		rule.Enabled = true
		s.state.TLSBypass = append([]models.TLSBypassRule{rule}, s.state.TLSBypass...)
		s.appendAuditLocked(models.AuditEvent{
			Actor:       actor.Username,
			ActorRole:   string(actor.Role),
			Action:      "TLS_BYPASS_ADDED",
			Category:    "TLS_BYPASS",
			EntityType:  "tls_bypass",
			EntityID:    rule.ID,
			EntityName:  rule.Pattern,
			Summary:     fmt.Sprintf("Added SSL No-Break passthrough pattern %s (%s): %s", rule.Pattern, rule.Category, rule.Reason),
			ScopeGroups: rule.GroupIDs,
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.TLSBypassRule{}, err
	}
	return rule, nil
}

func (s *Store) ToggleTLSBypass(id string, enabled bool, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return fmt.Errorf("RBAC Policy: Insufficient permissions")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.TLSBypass, func(b models.TLSBypassRule) bool { return b.ID == id })
		if i == -1 {
			return fmt.Errorf("not found")
		}
		s.state.TLSBypass[i].Enabled = enabled
		s.appendAuditLocked(models.AuditEvent{
			Actor:      actor.Username,
			ActorRole:  string(actor.Role),
			Action:     "TLS_BYPASS_TOGGLED",
			Category:   "TLS_BYPASS",
			EntityType: "tls_bypass",
			EntityID:   id,
			EntityName: s.state.TLSBypass[i].Pattern,
			Summary:    fmt.Sprintf("Set SSL No-Break rule %s enabled=%v", s.state.TLSBypass[i].Pattern, enabled),
		})
		s.saveLocked()
		return nil
	})
}

func (s *Store) DeleteTLSBypass(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return fmt.Errorf("RBAC Policy: Insufficient permissions")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.TLSBypass, func(b models.TLSBypassRule) bool { return b.ID == id })
		if i == -1 {
			return fmt.Errorf("not found")
		}
		pat := s.state.TLSBypass[i].Pattern
		s.state.TLSBypass = slices.Delete(s.state.TLSBypass, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor:      actor.Username,
			ActorRole:  string(actor.Role),
			Action:     "TLS_BYPASS_DELETED",
			Category:   "TLS_BYPASS",
			EntityType: "tls_bypass",
			EntityID:   id,
			EntityName: pat,
			Summary:    fmt.Sprintf("Deleted SSL No-Break passthrough rule %s", pat),
		})
		s.saveLocked()
		return nil
	})
}
