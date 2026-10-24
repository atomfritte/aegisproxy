package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// ---------------------------------------------------------------------------
// Migration (schema v4): path pattern semantics of 2.1
// ---------------------------------------------------------------------------
//
// Before 2.1 a trailing "/*" matched the prefix and every deeper path (like "/**") and a trailing "x*" was a
// plain prefix. Since 2.1 '*' never crosses '/' ("/simple/*" = exactly one segment below /simple) and '**'
// spans any depth (see engine.MatchPath). Stored patterns are rewritten to the equivalent new syntax so every
// rule keeps its meaning; a '*' elsewhere in a path (compared literally before, a wildcard now) has no
// equivalent and is reported for review.

// pathRewrite is one migrated (or flagged) pattern, listed in the audit event.
type pathRewrite struct {
	Where  string `json:"where"`
	RuleID string `json:"rule_id,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
	Review bool   `json:"review,omitempty"` // '*' inside the path is a wildcard now
}

// legacyPathMigration collects the rewrites of one migration run.
type legacyPathMigration struct {
	changes []pathRewrite
}

func (m *legacyPathMigration) path(where, ruleID, rule, field string, p *string) {
	out, changed, literal := engine.LegacyPathPattern(*p)
	if !changed && !literal {
		return
	}
	m.changes = append(m.changes, pathRewrite{Where: where, RuleID: ruleID, Rule: rule, Field: field, Before: *p, After: out, Review: literal})
	*p = out
}

// companions migrates the path part of "host/path" companion patterns (a bare host means "/**").
func (m *legacyPathMigration) companions(where, ruleID, rule string, comps []string) {
	for i, c := range comps {
		c = strings.TrimSpace(c)
		slash := strings.IndexByte(c, '/')
		if slash < 0 {
			continue
		}
		host, p := c[:slash], c[slash:]
		n := len(m.changes)
		m.path(where, ruleID, rule, "companion_rules", &p)
		if len(m.changes) > n {
			m.changes[n].Before, m.changes[n].After = c, host+p
			comps[i] = host + p
		}
	}
}

func (m *legacyPathMigration) rule(where string, r *models.PolicyRule) {
	m.path(where, r.ID, r.Name, "path_pattern", &r.PathPattern)
	m.companions(where, r.ID, r.Name, r.CompanionRules)
}

func (m *legacyPathMigration) rules(where string, rules []models.PolicyRule) {
	for i := range rules {
		m.rule(where, &rules[i])
	}
}

func (m *legacyPathMigration) rewritten() int {
	n := 0
	for _, c := range m.changes {
		if c.Before != c.After {
			n++
		}
	}
	return n
}

// migratePathPatternsLocked rewrites every stored path pattern (published sets, drafts, version history so
// rollbacks keep their meaning, change requests, pending access requests and learning session candidates) and
// records one audit event listing the rewritten rules.
func (s *Store) migratePathPatternsLocked() {
	var m legacyPathMigration
	for i := range s.state.PolicySets {
		set := &s.state.PolicySets[i]
		m.rules(fmt.Sprintf("policy set %q", set.Name), set.Rules)
		if set.Draft != nil {
			m.rules(fmt.Sprintf("draft of %q", set.Name), set.Draft.Spec.Rules)
		}
	}
	for i := range s.state.PolicyVersions {
		v := &s.state.PolicyVersions[i]
		m.rules(fmt.Sprintf("version %d of %q", v.Version, v.Spec.Name), v.Spec.Rules)
	}
	for i := range s.state.ChangeRequests {
		cr := &s.state.ChangeRequests[i]
		m.rules(fmt.Sprintf("change request %s", cr.ID), cr.Spec.Rules)
		if cr.Diff != nil {
			var quiet legacyPathMigration // the diff repeats rules of the request's spec
			for _, rc := range cr.Diff.Rules {
				for _, r := range []*models.PolicyRule{rc.Before, rc.After} {
					if r != nil {
						quiet.rule("", r)
					}
				}
			}
		}
	}
	for i := range s.state.Requests {
		req := &s.state.Requests[i]
		m.path(fmt.Sprintf("access request %s", req.ID), "", "", "suggested_path_pattern", &req.SuggestedPathPattern)
	}
	for i := range s.state.Sessions {
		sess := &s.state.Sessions[i]
		for j := range sess.CompiledCandidates {
			c := &sess.CompiledCandidates[j]
			where := fmt.Sprintf("learning session %s", sess.ID)
			m.path(where, c.ID, c.HostPattern, "path_pattern", &c.PathPattern)
			m.companions(where, c.ID, c.HostPattern, c.CompanionRules)
		}
	}
	if len(m.changes) == 0 {
		return
	}
	rewritten, review := m.rewritten(), 0
	var examples []string
	for _, c := range m.changes {
		if c.Review {
			review++
		}
		if c.Before != c.After && len(examples) < 5 {
			examples = append(examples, fmt.Sprintf("%s %q: %s → %s", c.Where, c.Rule, c.Before, c.After))
		}
	}
	summary := fmt.Sprintf("Path wildcard semantics of 2.1 ('*' = one path segment, '**' = any depth): rewrote %d patterns so the rules keep their meaning", rewritten)
	if len(examples) > 0 {
		summary += " (" + strings.Join(examples, "; ")
		if rewritten > len(examples) {
			summary += fmt.Sprintf("; +%d more", rewritten-len(examples))
		}
		summary += ")"
	}
	if review > 0 {
		summary += fmt.Sprintf(". %d patterns contain '*' inside the path, compared literally before and a wildcard now: review them", review)
	}
	list, _ := json.MarshalIndent(m.changes, "", "  ")
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "POLICY_PATH_PATTERNS_MIGRATED", Category: "POLICY",
		EntityType: "policy", EntityID: "path-patterns", EntityName: fmt.Sprintf("%d path patterns", len(m.changes)),
		Summary: summary, AfterState: string(list),
	})
}

// migrateLegacyBundle rewrites the path patterns of an imported bundle exported by a release before 2.1
// (path_syntax < 2) and returns how many were changed.
func migrateLegacyBundle(bundle *models.PolicySetBundle) int {
	var m legacyPathMigration
	for i := range bundle.PolicySets {
		m.rules("import", bundle.PolicySets[i].Rules)
	}
	return m.rewritten()
}
