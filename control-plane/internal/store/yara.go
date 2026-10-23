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

const (
	maxYaraRuleSets   = 100
	maxYaraSourceSize = 256 << 10
	maxYaraTotalSize  = 2 << 20
)

func (s *Store) YaraRuleSets() []models.YaraRuleSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.YaraRuleSet{}, s.state.YaraRuleSets...)
}

// UpsertYaraRuleSet stores a rule set. Syntax is checked by the data-plane engine (YARA-X); a set
// that fails to compile keeps the previous rules active and is reported per worker.
func (s *Store) UpsertYaraRuleSet(rs models.YaraRuleSet, actor *auth.TokenClaims) (models.YaraRuleSet, error) {
	if !auth.CanManageSystem(actor) {
		return models.YaraRuleSet{}, errNeedSystem
	}
	rs.Name = strings.TrimSpace(rs.Name)
	if err := checkText("name", rs.Name, 120, true); err != nil {
		return models.YaraRuleSet{}, err
	}
	if err := checkMultiline("description", rs.Description, 1000); err != nil {
		return models.YaraRuleSet{}, err
	}
	if len(rs.Source) == 0 || len(rs.Source) > maxYaraSourceSize {
		return models.YaraRuleSet{}, fmt.Errorf("source must contain between 1 byte and %d KiB of YARA rules", maxYaraSourceSize>>10)
	}
	if !strings.Contains(rs.Source, "rule ") || strings.ContainsRune(rs.Source, 0) {
		return models.YaraRuleSet{}, errors.New("source does not look like YARA rules")
	}
	if strings.Contains(rs.Source, "include ") {
		return models.YaraRuleSet{}, errors.New("include statements are not supported (paste the rules instead)")
	}
	if err := lintYara(rs.Source); err != nil {
		return models.YaraRuleSet{}, fmt.Errorf("invalid YARA rules: %w", err)
	}
	err := s.withWrite(func() error {
		now := time.Now().UTC()
		total := len(rs.Source)
		for _, o := range s.state.YaraRuleSets {
			if o.ID != rs.ID {
				total += len(o.Source)
				if strings.EqualFold(o.Name, rs.Name) {
					return fmt.Errorf("a rule set named %q already exists", o.Name)
				}
			}
		}
		if total > maxYaraTotalSize {
			return fmt.Errorf("all rule sets together must stay below %d MiB", maxYaraTotalSize>>20)
		}
		action := "YARA_RULESET_UPDATED"
		i := slices.IndexFunc(s.state.YaraRuleSets, func(x models.YaraRuleSet) bool { return x.ID == rs.ID && rs.ID != "" })
		if i < 0 && rs.ID != "" {
			return errors.New("YARA rule set not found")
		}
		if i < 0 {
			if len(s.state.YaraRuleSets) >= maxYaraRuleSets {
				return fmt.Errorf("at most %d rule sets", maxYaraRuleSets)
			}
			rs.ID, rs.CreatedAt, action = newRandomID("yara"), now, "YARA_RULESET_CREATED"
			rs.UpdatedAt, rs.UpdatedBy = &now, actor.Username
			s.state.YaraRuleSets = append(s.state.YaraRuleSets, rs)
		} else {
			rs.CreatedAt = s.state.YaraRuleSets[i].CreatedAt
			rs.UpdatedAt, rs.UpdatedBy = &now, actor.Username
			s.state.YaraRuleSets[i] = rs
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "SECURITY",
			EntityType: "yara_rule_set", EntityID: rs.ID, EntityName: rs.Name,
			Summary: fmt.Sprintf("Saved YARA rule set %q (%d bytes, %d rules, enabled=%v)", rs.Name, len(rs.Source), strings.Count(rs.Source, "rule "), rs.Enabled),
		})
		s.saveLocked()
		return nil
	})
	return rs, err
}

func (s *Store) DeleteYaraRuleSet(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errNeedSystem
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.YaraRuleSets, func(x models.YaraRuleSet) bool { return x.ID == id })
		if i < 0 {
			return errors.New("rule set not found")
		}
		rs := s.state.YaraRuleSets[i]
		s.state.YaraRuleSets = slices.Delete(s.state.YaraRuleSets, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "YARA_RULESET_DELETED", Category: "SECURITY",
			EntityType: "yara_rule_set", EntityID: rs.ID, EntityName: rs.Name, Summary: fmt.Sprintf("Deleted YARA rule set %q", rs.Name),
		})
		s.saveLocked()
		return nil
	})
}
