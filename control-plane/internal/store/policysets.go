package store

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const maxVersionsPerSet = 30

var (
	ErrReviewRequired = errors.New("four-eyes review is required: submit the draft as a change request")
	ErrDraftLocked    = errors.New("the draft is in review; withdraw the change request to edit it")
	ErrSuperseded     = errors.New("the policy set changed since this request was submitted; it is now superseded and the author must resubmit")
)

type publishOpts struct {
	changeRequestID string
	comment         string
	emergency       bool
	quiet           bool // caller writes its own audit event
}

func DefaultGovernance() models.GovernanceSettings {
	return models.GovernanceSettings{
		RequirePolicyReview:       false,
		RequestSLAHours:           24,
		DefaultReviewIntervalDays: 90,
		MaxTemporaryAccessDays:    30,
		DailyDigest:               true,
		PruneExpiredAfterDays:     7,
	}
}

// ---------------------------------------------------------------------------
// Compilation: policy sets -> effective flat rules (what the engine and data-plane enforce)
// ---------------------------------------------------------------------------

func setScope(set *models.PolicySet) ([]string, []string) {
	if set.Kind == models.PolicySetKindBaseline {
		// Every server with a group membership and every registered server — never unknown sources.
		return []string{"*"}, []string{"*"}
	}
	return append([]string(nil), set.GroupIDs...), append([]string(nil), set.ServerIDs...)
}

// compileRulesLocked rebuilds s.state.Rules from the published content of enabled policy sets.
func (s *Store) compileRulesLocked() {
	if s.state.SchemaVersion < 3 && len(s.state.PolicySets) == 0 {
		return // legacy state that has not been migrated yet (cluster join of a 2.x document)
	}
	s.state.Rules = compileSets(s.state.PolicySets, s.state.RuleStats)
}

// ---------------------------------------------------------------------------
// Validation & RBAC
// ---------------------------------------------------------------------------

func normalizeSpec(spec *models.PolicySetSpec) {
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.Tags == nil {
		spec.Tags = []string{}
	}
	if spec.GroupIDs == nil {
		spec.GroupIDs = []string{}
	}
	if spec.ServerIDs == nil {
		spec.ServerIDs = []string{}
	}
	if spec.Rules == nil {
		spec.Rules = []models.PolicyRule{}
	}
}

// validateSpecLocked validates set metadata and every rule against the set's assignment and the
// actor's permissions. Rule IDs are assigned/kept unique across all sets.
func (s *Store) validateSpecLocked(setID, kind string, spec *models.PolicySetSpec, actor *auth.TokenClaims) error {
	normalizeSpec(spec)
	if err := checkText("name", spec.Name, 120, true); err != nil {
		return err
	}
	if err := checkText("description", spec.Description, 2000, false); err != nil {
		return err
	}
	if err := checkText("owner_team", spec.OwnerTeam, 120, false); err != nil {
		return err
	}
	if len(spec.Tags) > 20 {
		return errors.New("at most 20 tags")
	}
	for _, t := range spec.Tags {
		if err := checkText("tag", t, 40, true); err != nil {
			return err
		}
	}
	if spec.ReviewIntervalDays < 0 || spec.ReviewIntervalDays > 730 {
		return errors.New("review_interval_days must be between 0 and 730")
	}
	if len(spec.Rules) > 500 {
		return errors.New("a policy set can hold at most 500 rules")
	}
	if err := s.validateScopeLocked(spec.GroupIDs, spec.ServerIDs); err != nil {
		return err
	}
	if slices.Contains(spec.GroupIDs, "*") || slices.Contains(spec.ServerIDs, "*") {
		return errors.New("use a baseline policy set to target all servers")
	}
	if kind != models.PolicySetKindBaseline && len(spec.GroupIDs) == 0 && len(spec.ServerIDs) == 0 && spec.Enabled && len(spec.Rules) > 0 {
		return errors.New("assign the policy set to at least one server group or server (or make it a baseline set)")
	}
	tmp := models.PolicySet{Kind: kind, PolicySetSpec: *spec}
	groups, servers := setScope(&tmp)

	// IDs used by other sets
	taken := map[string]bool{}
	for _, other := range s.state.PolicySets {
		if other.ID == setID {
			continue
		}
		for _, r := range other.Rules {
			taken[r.ID] = true
		}
		if other.Draft != nil {
			for _, r := range other.Draft.Spec.Rules {
				taken[r.ID] = true
			}
		}
	}
	// Rules unchanged from the published version are not re-validated (they may contain rules
	// created by a more privileged role, or temporary access that has expired since).
	prev := map[string]models.PolicyRule{}
	var prevGroups, prevServers []string
	prevEnabled := false
	if i := s.setIndexLocked(setID); i >= 0 {
		for _, r := range s.state.PolicySets[i].Rules {
			prev[r.ID] = r
		}
		prevGroups, prevServers = setScope(&s.state.PolicySets[i])
		prevEnabled = s.state.PolicySets[i].Enabled
	}
	// Disabling or re-scoping the set withdraws its BLOCK guardrails from the old scope just like
	// deleting them; only roles that may remove those rules may do that.
	guardrailsWithdrawn := len(prev) > 0 && ((prevEnabled && !spec.Enabled) ||
		!slices.Equal(sortedCopy(prevGroups), sortedCopy(groups)) || !slices.Equal(sortedCopy(prevServers), sortedCopy(servers)))
	fleet := s.effectiveServersLocked()
	seen := map[string]bool{}
	now := time.Now().UTC()
	for i := range spec.Rules {
		r := &spec.Rules[i]
		if r.ID == "" || taken[r.ID] || seen[r.ID] {
			r.ID = newRandomID("rule")
		}
		seen[r.ID] = true
		old, existed := prev[r.ID]
		if existed {
			r.CreatedAt, r.CreatedBy = old.CreatedAt, old.CreatedBy
			r.SourceSessionID, r.AccessRequestID = old.SourceSessionID, old.AccessRequestID
		}
		if existed && len(ruleFieldsChanged(old, *r)) == 0 {
			r.Version, r.UpdatedAt, r.ApprovedBy = old.Version, old.UpdatedAt, old.ApprovedBy
			if guardrailsWithdrawn && strings.EqualFold(old.Action, "BLOCK") && old.Enabled && (len(prevGroups) > 0 || len(prevServers) > 0) {
				o := cloneRule(old)
				o.GroupIDs, o.ServerIDs = prevGroups, prevServers
				if err := auth.CanModifyRule(actor, o, fleet); err != nil {
					return fmt.Errorf("disabling or re-scoping the set would withdraw guardrail %q: %w", old.Name, err)
				}
			}
		} else {
			r.GroupIDs, r.ServerIDs = groups, servers
			if err := s.normalizeAndValidateRuleLocked(r, actor.Role); err != nil {
				if len(groups) == 0 && len(servers) == 0 && strings.Contains(err.Error(), "must target") {
					err = nil
				}
				if err != nil {
					return fmt.Errorf("rule %q: %w", r.Name, err)
				}
			}
			if len(groups) > 0 || len(servers) > 0 {
				if err := auth.CanModifyRule(actor, *r, fleet); err != nil {
					return fmt.Errorf("rule %q: %w", r.Name, err)
				}
			}
			if existed {
				r.Version = max(old.Version, 1) + 1
				r.UpdatedAt = &now
				r.ApprovedBy = actor.Username
			} else {
				r.Version = 1
				r.UpdatedAt = nil
				if r.CreatedAt.IsZero() {
					r.CreatedAt, r.CreatedBy = now, actor.Username
				}
				if r.ApprovedBy == "" {
					r.ApprovedBy = actor.Username
				}
			}
		}
		r.GroupIDs, r.ServerIDs = []string{}, []string{}
		r.HitCount, r.TotalBytes = 0, 0
		r.PolicySetID, r.PolicySetName = "", ""
	}
	for id, old := range prev {
		if seen[id] {
			continue
		}
		old = cloneRule(old)
		old.GroupIDs, old.ServerIDs = prevGroups, prevServers
		if len(prevGroups) > 0 || len(prevServers) > 0 {
			if err := auth.CanModifyRule(actor, old, fleet); err != nil {
				return fmt.Errorf("removing rule %q: %w", old.Name, err)
			}
		}
	}
	return nil
}

// canManageSetLocked checks that the actor may change a set with the given (old and new) scopes.
func (s *Store) canManageSetLocked(actor *auth.TokenClaims, kind string, scopes ...models.PolicySetSpec) error {
	if actor == nil {
		return errors.New("unauthenticated")
	}
	if actor.Role == models.RoleAuditorOperator {
		return errors.New("RBAC Policy: read-only role")
	}
	if kind == models.PolicySetKindBaseline && !auth.CanManageSystem(actor) {
		return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage baseline policy sets")
	}
	if auth.CanManageSystem(actor) {
		return nil
	}
	for _, sc := range scopes {
		if len(sc.ServerIDs) > 0 {
			for _, sid := range sc.ServerIDs {
				srv, ok := s.serverByIDLocked(sid)
				if !ok || !auth.CanApproveForGroups(actor, srv.EffectiveGroupIDs) {
					return fmt.Errorf("RBAC Policy: server %s is outside your groups", sid)
				}
			}
		}
		if len(sc.GroupIDs) > 0 && !auth.CanApproveForGroups(actor, sc.GroupIDs) {
			return fmt.Errorf("RBAC Policy: Role %s is not authorized for server groups %v", actor.Role, sc.GroupIDs)
		}
		if len(sc.GroupIDs) == 0 && len(sc.ServerIDs) == 0 && len(sc.Rules) > 0 {
			return errors.New("RBAC Policy: Team Leads must assign policy sets to their server groups")
		}
	}
	return nil
}

func (s *Store) setIndexLocked(id string) int {
	return slices.IndexFunc(s.state.PolicySets, func(p models.PolicySet) bool { return p.ID == id })
}

func cloneSpec(sp models.PolicySetSpec) models.PolicySetSpec {
	out := sp
	out.Tags = append([]string{}, sp.Tags...)
	out.GroupIDs = append([]string{}, sp.GroupIDs...)
	out.ServerIDs = append([]string{}, sp.ServerIDs...)
	out.Rules = make([]models.PolicyRule, len(sp.Rules))
	for i, r := range sp.Rules {
		out.Rules[i] = cloneRule(r)
	}
	return out
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

func ruleFieldsChanged(a, b models.PolicyRule) []string {
	var f []string
	cmp := func(name string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			f = append(f, name)
		}
	}
	cmp("name", a.Name, b.Name)
	cmp("description", a.Description, b.Description)
	cmp("action", a.Action, b.Action)
	cmp("host_pattern", a.HostPattern, b.HostPattern)
	cmp("path_pattern", a.PathPattern, b.PathPattern)
	cmp("methods", nonNil(a.Methods), nonNil(b.Methods))
	cmp("follow_redirects", a.FollowRedirects, b.FollowRedirects)
	cmp("companion_rules", nonNil(a.CompanionRules), nonNil(b.CompanionRules))
	cmp("enabled", a.Enabled, b.Enabled)
	ea, eb := "", ""
	if a.ExpiresAt != nil {
		ea = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if b.ExpiresAt != nil {
		eb = b.ExpiresAt.UTC().Format(time.RFC3339)
	}
	cmp("expires_at", ea, eb)
	return f
}

// DiffSpecs compares two policy set specs (old -> new).
func DiffSpecs(old, cur models.PolicySetSpec) models.PolicyDiff {
	d := models.PolicyDiff{Metadata: []string{}, Rules: []models.RuleChange{}}
	meta := func(name string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			d.Metadata = append(d.Metadata, name)
		}
	}
	meta("name", old.Name, cur.Name)
	meta("description", old.Description, cur.Description)
	meta("owner_team", old.OwnerTeam, cur.OwnerTeam)
	meta("tags", nonNil(old.Tags), nonNil(cur.Tags))
	meta("priority", old.Priority, cur.Priority)
	meta("enabled", old.Enabled, cur.Enabled)
	meta("group_ids", nonNil(old.GroupIDs), nonNil(cur.GroupIDs))
	meta("server_ids", nonNil(old.ServerIDs), nonNil(cur.ServerIDs))
	meta("review_interval_days", old.ReviewIntervalDays, cur.ReviewIntervalDays)

	before := map[string]models.PolicyRule{}
	for _, r := range old.Rules {
		before[r.ID] = r
	}
	after := map[string]bool{}
	for _, r := range cur.Rules {
		after[r.ID] = true
		if b, ok := before[r.ID]; ok {
			if fields := ruleFieldsChanged(b, r); len(fields) > 0 {
				bb, aa := cloneRule(b), cloneRule(r)
				d.Rules = append(d.Rules, models.RuleChange{Op: "modified", RuleID: r.ID, Before: &bb, After: &aa, Fields: fields})
				d.Modified++
			}
			continue
		}
		aa := cloneRule(r)
		d.Rules = append(d.Rules, models.RuleChange{Op: "added", RuleID: r.ID, After: &aa})
		d.Added++
	}
	for _, r := range old.Rules {
		if !after[r.ID] {
			bb := cloneRule(r)
			d.Rules = append(d.Rules, models.RuleChange{Op: "removed", RuleID: r.ID, Before: &bb})
			d.Removed++
		}
	}
	return d
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func diffSummary(d models.PolicyDiff) string {
	parts := []string{}
	if d.Added > 0 {
		parts = append(parts, fmt.Sprintf("+%d rules", d.Added))
	}
	if d.Removed > 0 {
		parts = append(parts, fmt.Sprintf("-%d rules", d.Removed))
	}
	if d.Modified > 0 {
		parts = append(parts, fmt.Sprintf("~%d rules", d.Modified))
	}
	if len(d.Metadata) > 0 {
		parts = append(parts, "settings: "+strings.Join(d.Metadata, ", "))
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// CreatePolicySet creates an unpublished set whose content lives in a draft.
func (s *Store) CreatePolicySet(kind string, spec models.PolicySetSpec, actor *auth.TokenClaims) (models.PolicySet, error) {
	if kind == "" {
		kind = models.PolicySetKindStandard
	}
	if kind != models.PolicySetKindStandard && kind != models.PolicySetKindBaseline {
		return models.PolicySet{}, errors.New("kind must be standard or baseline")
	}
	var out models.PolicySet
	err := s.withWrite(func() error {
		i, err := s.createSetLocked(kind, spec, actor)
		if err != nil {
			return err
		}
		out = s.decorateSetLocked(s.state.PolicySets[i])
		return nil
	})
	return out, err
}

// createSetLocked adds an unpublished set (content in its draft) and returns its index.
func (s *Store) createSetLocked(kind string, spec models.PolicySetSpec, actor *auth.TokenClaims) (int, error) {
	if err := s.canManageSetLocked(actor, kind, spec); err != nil {
		return -1, err
	}
	for _, other := range s.state.PolicySets {
		if strings.EqualFold(other.Name, strings.TrimSpace(spec.Name)) {
			return -1, fmt.Errorf("a policy set named %q already exists", other.Name)
		}
	}
	id := newRandomID("ps")
	if err := s.validateSpecLocked(id, kind, &spec, actor); err != nil {
		return -1, err
	}
	now := time.Now().UTC()
	set := models.PolicySet{
		ID: id, Kind: kind, CreatedAt: now, CreatedBy: actor.Username,
		PolicySetSpec: models.PolicySetSpec{Name: spec.Name, Description: spec.Description, OwnerTeam: spec.OwnerTeam, Enabled: spec.Enabled,
			Tags: spec.Tags, Priority: spec.Priority, GroupIDs: spec.GroupIDs, ServerIDs: spec.ServerIDs,
			ReviewIntervalDays: spec.ReviewIntervalDays, Rules: []models.PolicyRule{}},
		Draft: &models.PolicySetDraft{Spec: spec, Status: "editing", UpdatedBy: actor.Username, UpdatedAt: now},
	}
	s.state.PolicySets = append(s.state.PolicySets, set)
	s.appendAuditLocked(models.AuditEvent{
		Actor: actor.Username, ActorRole: string(actor.Role), Action: "POLICY_SET_CREATED", Category: "POLICY",
		EntityType: "policy_set", EntityID: id, EntityName: spec.Name, ScopeGroups: spec.GroupIDs,
		Summary: fmt.Sprintf("Created %s policy set %q (draft with %d rules)", kind, spec.Name, len(spec.Rules)),
	})
	s.markDirtyLocked()
	return len(s.state.PolicySets) - 1, nil
}

// SaveDraft replaces the working copy of a set.
func (s *Store) SaveDraft(id string, spec models.PolicySetSpec, actor *auth.TokenClaims) (models.PolicySet, error) {
	var out models.PolicySet
	err := s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		if set.Kind == models.PolicySetKindApprovals {
			// approvals sets keep their single-group assignment
			spec.GroupIDs, spec.ServerIDs = set.GroupIDs, set.ServerIDs
		}
		if set.Draft != nil && set.Draft.Status == "in_review" {
			return ErrDraftLocked
		}
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, spec); err != nil {
			return err
		}
		if err := s.validateSpecLocked(id, set.Kind, &spec, actor); err != nil {
			return err
		}
		set.Draft = &models.PolicySetDraft{Spec: spec, BaseVersion: set.Version, Status: "editing", UpdatedBy: actor.Username, UpdatedAt: time.Now().UTC()}
		s.markDirtyLocked()
		out = s.decorateSetLocked(*set)
		return nil
	})
	return out, err
}

func (s *Store) DiscardDraft(id string, actor *auth.TokenClaims) error {
	return s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		if set.Draft == nil {
			return nil
		}
		if set.Draft.Status == "in_review" {
			return ErrDraftLocked
		}
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec); err != nil {
			return err
		}
		set.Draft = nil
		s.markDirtyLocked()
		return nil
	})
}

// publishLocked makes spec the live content of set i and records an immutable version.
func (s *Store) publishLocked(i int, spec models.PolicySetSpec, actor *auth.TokenClaims, o publishOpts) models.PolicySetVersion {
	crID, comment, emergency := o.changeRequestID, o.comment, o.emergency
	set := &s.state.PolicySets[i]
	diff := DiffSpecs(set.PolicySetSpec, spec)
	now := time.Now().UTC()
	prevVersion := set.Version
	set.PolicySetSpec = cloneSpec(spec)
	set.Version++
	set.PublishedAt, set.PublishedBy = &now, actor.Username
	if set.LastReviewedAt == nil {
		set.LastReviewedAt, set.LastReviewedBy = &now, actor.Username
	}
	set.Draft = nil
	summary := diffSummary(diff)
	if comment != "" {
		summary += " — " + clip(comment, 300)
	}
	v := models.PolicySetVersion{PolicySetID: set.ID, Version: set.Version, Spec: cloneSpec(spec), PublishedBy: actor.Username,
		PublishedAt: now, ChangeRequestID: crID, Summary: summary, Emergency: emergency}
	s.state.PolicyVersions = append(s.state.PolicyVersions, v)
	s.pruneVersionsLocked(set.ID)
	action := "POLICY_SET_PUBLISHED"
	if emergency {
		action = "POLICY_SET_EMERGENCY_PUBLISH"
	}
	if !o.quiet {
		groups, _ := setScope(set)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "POLICY",
			EntityType: "policy_set", EntityID: set.ID, EntityName: fmt.Sprintf("%s (v%d → v%d)", set.Name, prevVersion, set.Version),
			Summary:     fmt.Sprintf("Published %q v%d: %s", set.Name, set.Version, summary),
			ScopeGroups: groups,
			AfterState:  fmt.Sprintf("change_request=%s emergency=%v rules=%d", crID, emergency, len(spec.Rules)),
		})
	}
	s.saveLocked()
	return v
}

func (s *Store) pruneVersionsLocked(setID string) {
	n := 0
	for i := len(s.state.PolicyVersions) - 1; i >= 0; i-- {
		if s.state.PolicyVersions[i].PolicySetID == setID {
			n++
			if n > maxVersionsPerSet {
				s.state.PolicyVersions = slices.Delete(s.state.PolicyVersions, i, i+1)
			}
		}
	}
}

// PublishDraft publishes the draft directly (allowed when four-eyes review is not required) or as
// an emergency change by a Super Admin with a justification.
func (s *Store) PublishDraft(id string, comment string, emergency bool, actor *auth.TokenClaims) (models.PolicySet, error) {
	var out models.PolicySet
	err := s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		if set.Draft == nil {
			return errors.New("there is no draft to publish")
		}
		if set.Draft.Status == "in_review" {
			return ErrDraftLocked
		}
		if s.state.Governance.RequirePolicyReview {
			if !emergency {
				return ErrReviewRequired
			}
			if actor.Role != models.RoleSuperAdmin {
				return errors.New("RBAC Policy: only Super Admins can publish emergency changes")
			}
			if len(strings.TrimSpace(comment)) < 10 {
				return errors.New("emergency changes need a justification (at least 10 characters)")
			}
		}
		spec := cloneSpec(set.Draft.Spec)
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, spec); err != nil {
			return err
		}
		if err := s.validateSpecLocked(id, set.Kind, &spec, actor); err != nil {
			return err
		}
		s.publishLocked(i, spec, actor, publishOpts{comment: comment, emergency: emergency})
		out = s.decorateSetLocked(s.state.PolicySets[i])
		return nil
	})
	return out, err
}

// SubmitChangeRequest freezes the draft and opens a change request for review.
func (s *Store) SubmitChangeRequest(id, title, description string, actor *auth.TokenClaims) (models.ChangeRequest, error) {
	if err := checkText("title", title, 200, false); err != nil {
		return models.ChangeRequest{}, err
	}
	if err := checkText("description", description, 4000, false); err != nil {
		return models.ChangeRequest{}, err
	}
	var cr models.ChangeRequest
	err := s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		if set.Draft == nil {
			return errors.New("there is no draft to submit")
		}
		if set.Draft.Status == "in_review" {
			return errors.New("the draft is already in review")
		}
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, set.Draft.Spec); err != nil {
			return err
		}
		spec := cloneSpec(set.Draft.Spec)
		if err := s.validateSpecLocked(id, set.Kind, &spec, actor); err != nil {
			return err
		}
		diff := DiffSpecs(set.PolicySetSpec, spec)
		if strings.TrimSpace(title) == "" {
			title = fmt.Sprintf("%s: %s", set.Name, diffSummary(diff))
		}
		now := time.Now().UTC()
		cr = models.ChangeRequest{
			ID: newRandomID("cr"), PolicySetID: id, PolicySetName: set.Name, Title: clip(title, 200), Description: description,
			Status: "open", BaseVersion: set.Version, Spec: spec, Diff: &diff, SubmittedBy: actor.Username, SubmittedAt: now,
			Reviews: []models.ChangeReview{},
		}
		set.Draft.Status = "in_review"
		set.Draft.ChangeRequestID = cr.ID
		s.state.ChangeRequests = append([]models.ChangeRequest{cr}, s.state.ChangeRequests...)
		if len(s.state.ChangeRequests) > 2000 {
			s.state.ChangeRequests = s.state.ChangeRequests[:2000]
		}
		groups, _ := setScope(set)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "CHANGE_REQUEST_SUBMITTED", Category: "POLICY",
			EntityType: "change_request", EntityID: cr.ID, EntityName: cr.Title, ScopeGroups: groups,
			Summary: fmt.Sprintf("Submitted change request for %q: %s", set.Name, diffSummary(diff)),
		})
		s.markDirtyLocked()
		return nil
	})
	if err == nil {
		// Impact is computed outside the write lock (evaluates recorded traffic) and attached.
		if impact, ierr := s.SimulateSpec(id, &cr.Spec, systemActor); ierr == nil {
			cr.Impact = &impact
			_ = s.withWrite(func() error {
				if j := slices.IndexFunc(s.state.ChangeRequests, func(c models.ChangeRequest) bool { return c.ID == cr.ID }); j >= 0 {
					s.state.ChangeRequests[j].Impact = &impact
					s.markDirtyLocked()
				}
				return nil
			})
		}
		if s.notifier != nil {
			s.notifier.NotifyChangeRequest(cr)
		}
	}
	return cr, err
}

// ReviewChangeRequest records a decision. Approval publishes the change (four-eyes: the reviewer
// must not be the submitter).
func (s *Store) ReviewChangeRequest(crID, decision, comment string, actor *auth.TokenClaims) (models.ChangeRequest, error) {
	if err := checkText("comment", comment, 4000, false); err != nil {
		return models.ChangeRequest{}, err
	}
	if decision != "approve" && decision != "reject" && decision != "comment" {
		return models.ChangeRequest{}, errors.New("decision must be approve, reject or comment")
	}
	var out models.ChangeRequest
	err := s.withWrite(func() error {
		j := slices.IndexFunc(s.state.ChangeRequests, func(c models.ChangeRequest) bool { return c.ID == crID })
		if j < 0 {
			return errors.New("change request not found")
		}
		cr := &s.state.ChangeRequests[j]
		if cr.Status != "open" {
			return fmt.Errorf("change request is already %s", cr.Status)
		}
		i := s.setIndexLocked(cr.PolicySetID)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		now := time.Now().UTC()
		if decision != "comment" {
			if actor.ServiceAccount && decision == "approve" {
				return errors.New("four-eyes principle: change requests must be approved by a person, not a service account")
			}
			if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, cr.Spec); err != nil {
				return err
			}
			if strings.EqualFold(actor.Username, cr.SubmittedBy) {
				return errors.New("four-eyes principle: you cannot review your own change request")
			}
			if decision == "approve" && set.Draft != nil && strings.EqualFold(actor.Username, set.Draft.UpdatedBy) {
				return errors.New("four-eyes principle: you edited this draft, so another reviewer must approve it")
			}
		}
		cr.Reviews = append(cr.Reviews, models.ChangeReview{Reviewer: actor.Username, Role: string(actor.Role), Decision: decision, Comment: comment, At: now})
		switch decision {
		case "approve":
			if set.Version != cr.BaseVersion {
				cr.Status = "superseded"
				if set.Draft != nil && set.Draft.ChangeRequestID == cr.ID {
					set.Draft.Status, set.Draft.ChangeRequestID = "editing", ""
				}
				s.markDirtyLocked()
				out = *cr
				return nil
			}
			spec := cloneSpec(cr.Spec)
			if err := s.validateSpecLocked(set.ID, set.Kind, &spec, actor); err != nil {
				return err
			}
			v := s.publishLocked(i, spec, actor, publishOpts{changeRequestID: cr.ID, comment: comment})
			cr.Status, cr.DecidedBy, cr.DecidedAt, cr.PublishedVer = "approved", actor.Username, &now, v.Version
		case "reject":
			cr.Status, cr.DecidedBy, cr.DecidedAt = "rejected", actor.Username, &now
			if set.Draft != nil && set.Draft.ChangeRequestID == cr.ID {
				set.Draft.Status = "editing"
				set.Draft.ChangeRequestID = ""
			}
			s.appendAuditLocked(models.AuditEvent{
				Actor: actor.Username, ActorRole: string(actor.Role), Action: "CHANGE_REQUEST_REJECTED", Category: "POLICY",
				EntityType: "change_request", EntityID: cr.ID, EntityName: cr.Title,
				Summary: fmt.Sprintf("Rejected change request for %q: %s", cr.PolicySetName, clip(comment, 300)),
			})
		}
		s.markDirtyLocked()
		out = *cr
		return nil
	})
	if err == nil && out.Status == "superseded" {
		err = ErrSuperseded
	}
	return out, err
}

func (s *Store) WithdrawChangeRequest(crID string, actor *auth.TokenClaims) error {
	return s.withWrite(func() error {
		j := slices.IndexFunc(s.state.ChangeRequests, func(c models.ChangeRequest) bool { return c.ID == crID })
		if j < 0 {
			return errors.New("change request not found")
		}
		cr := &s.state.ChangeRequests[j]
		if cr.Status != "open" {
			return fmt.Errorf("change request is already %s", cr.Status)
		}
		if !strings.EqualFold(cr.SubmittedBy, actor.Username) && !auth.CanManageSystem(actor) {
			return errors.New("RBAC Policy: only the author or InfoSec can withdraw a change request")
		}
		now := time.Now().UTC()
		cr.Status, cr.DecidedBy, cr.DecidedAt = "withdrawn", actor.Username, &now
		if i := s.setIndexLocked(cr.PolicySetID); i >= 0 {
			if d := s.state.PolicySets[i].Draft; d != nil && d.ChangeRequestID == cr.ID {
				d.Status, d.ChangeRequestID = "editing", ""
			}
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "CHANGE_REQUEST_WITHDRAWN", Category: "POLICY",
			EntityType: "change_request", EntityID: cr.ID, EntityName: cr.Title, Summary: "Withdrew change request " + cr.ID,
		})
		s.markDirtyLocked()
		return nil
	})
}

// RollbackPolicySet restores a previous version: published directly when review is not required,
// otherwise prepared as a draft for a change request.
func (s *Store) RollbackPolicySet(id string, version int, comment string, actor *auth.TokenClaims) (models.PolicySet, bool, error) {
	var out models.PolicySet
	published := false
	err := s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		k := slices.IndexFunc(s.state.PolicyVersions, func(v models.PolicySetVersion) bool { return v.PolicySetID == id && v.Version == version })
		if k < 0 {
			return fmt.Errorf("version %d not found (only the last %d versions are kept)", version, maxVersionsPerSet)
		}
		if set.Draft != nil && set.Draft.Status == "in_review" {
			return ErrDraftLocked
		}
		spec := cloneSpec(s.state.PolicyVersions[k].Spec)
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, spec); err != nil {
			return err
		}
		if err := s.validateSpecLocked(id, set.Kind, &spec, actor); err != nil {
			return fmt.Errorf("version %d can no longer be restored: %w", version, err)
		}
		if s.state.Governance.RequirePolicyReview {
			set.Draft = &models.PolicySetDraft{Spec: spec, BaseVersion: set.Version, Status: "editing", UpdatedBy: actor.Username, UpdatedAt: time.Now().UTC()}
			s.markDirtyLocked()
		} else {
			s.publishLocked(i, spec, actor, publishOpts{comment: strings.TrimSpace(fmt.Sprintf("rollback to v%d %s", version, comment))})
			published = true
		}
		out = s.decorateSetLocked(s.state.PolicySets[i])
		return nil
	})
	return out, published, err
}

func (s *Store) RecertifyPolicySet(id, comment string, actor *auth.TokenClaims) (models.PolicySet, error) {
	var out models.PolicySet
	err := s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := &s.state.PolicySets[i]
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec); err != nil {
			return err
		}
		now := time.Now().UTC()
		set.LastReviewedAt, set.LastReviewedBy = &now, actor.Username
		groups, _ := setScope(set)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "POLICY_SET_RECERTIFIED", Category: "POLICY",
			EntityType: "policy_set", EntityID: set.ID, EntityName: set.Name, ScopeGroups: groups,
			Summary: fmt.Sprintf("Recertified %q (v%d, %d rules): %s", set.Name, set.Version, len(set.Rules), clip(comment, 300)),
		})
		s.markDirtyLocked()
		out = s.decorateSetLocked(*set)
		return nil
	})
	return out, err
}

func (s *Store) DeletePolicySet(id, reason string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can delete policy sets")
	}
	return s.withWrite(func() error {
		i := s.setIndexLocked(id)
		if i < 0 {
			return errors.New("policy set not found")
		}
		set := s.state.PolicySets[i]
		if set.Kind == models.PolicySetKindApprovals && len(set.Rules) > 0 {
			return errors.New("approval sets are managed by access requests; revoke the requests instead")
		}
		s.state.PolicySets = slices.Delete(s.state.PolicySets, i, i+1)
		for j := range s.state.ChangeRequests {
			if s.state.ChangeRequests[j].PolicySetID == id && s.state.ChangeRequests[j].Status == "open" {
				s.state.ChangeRequests[j].Status = "withdrawn"
			}
		}
		groups, _ := setScope(&set)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "POLICY_SET_DELETED", Category: "POLICY",
			EntityType: "policy_set", EntityID: id, EntityName: set.Name, ScopeGroups: groups,
			Summary:     fmt.Sprintf("Deleted policy set %q (v%d, %d rules): %s — versions kept for restore", set.Name, set.Version, len(set.Rules), clip(reason, 300)),
			BeforeState: fmt.Sprintf("rules=%d groups=%v servers=%v", len(set.Rules), set.GroupIDs, set.ServerIDs),
		})
		s.saveLocked()
		return nil
	})
}

// PolicyVersions lists the kept versions of a set, newest first.
func (s *Store) PolicyVersions(id string) []models.PolicySetVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []models.PolicySetVersion
	for i := len(s.state.PolicyVersions) - 1; i >= 0; i-- {
		if v := s.state.PolicyVersions[i]; v.PolicySetID == id {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

// decorateSetLocked adds computed review state (and rule hit counters) for API responses.
func (s *Store) decorateSetLocked(set models.PolicySet) models.PolicySet {
	set.PolicySetSpec = cloneSpec(set.PolicySetSpec)
	for i := range set.Rules {
		if st, ok := s.state.RuleStats[set.Rules[i].ID]; ok {
			set.Rules[i].HitCount, set.Rules[i].TotalBytes = st.Hits, st.Bytes
		}
	}
	if set.Draft != nil {
		d := *set.Draft
		d.Spec = cloneSpec(d.Spec)
		set.Draft = &d
	}
	if set.Version > 0 && set.ReviewIntervalDays > 0 {
		base := set.LastReviewedAt
		if base == nil {
			base = set.PublishedAt
		}
		if base != nil {
			due := base.Add(time.Duration(set.ReviewIntervalDays) * 24 * time.Hour)
			set.ReviewDueAt = &due
			switch left := time.Until(due); {
			case left < 0:
				set.ReviewState = "overdue"
			case left < 14*24*time.Hour:
				set.ReviewState = "due_soon"
			default:
				set.ReviewState = "ok"
			}
		}
	}
	return set
}

func (s *Store) PolicySets() []models.PolicySet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.PolicySet, 0, len(s.state.PolicySets))
	for _, set := range s.state.PolicySets {
		out = append(out, s.decorateSetLocked(set))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindOrder(out[i].Kind) < kindOrder(out[j].Kind)
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func kindOrder(k string) int {
	switch k {
	case models.PolicySetKindBaseline:
		return 0
	case models.PolicySetKindStandard:
		return 1
	}
	return 2
}

func (s *Store) PolicySet(id string) (models.PolicySet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if i := s.setIndexLocked(id); i >= 0 {
		return s.decorateSetLocked(s.state.PolicySets[i]), true
	}
	return models.PolicySet{}, false
}

func (s *Store) ChangeRequests() []models.ChangeRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]models.ChangeRequest(nil), s.state.ChangeRequests...)
}

func (s *Store) Governance() models.GovernanceSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Governance
}

func (s *Store) UpdateGovernance(g models.GovernanceSettings, actor *auth.TokenClaims) (models.GovernanceSettings, error) {
	if !auth.CanManageSystem(actor) {
		return models.GovernanceSettings{}, errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can change governance settings")
	}
	if g.RequestSLAHours < 1 || g.RequestSLAHours > 24*30 {
		return models.GovernanceSettings{}, errors.New("request_sla_hours must be between 1 and 720")
	}
	if g.DefaultReviewIntervalDays < 0 || g.DefaultReviewIntervalDays > 730 {
		return models.GovernanceSettings{}, errors.New("default_review_interval_days must be between 0 and 730")
	}
	if g.MaxTemporaryAccessDays < 1 || g.MaxTemporaryAccessDays > 365 {
		return models.GovernanceSettings{}, errors.New("max_temporary_access_days must be between 1 and 365")
	}
	if g.PruneExpiredAfterDays < 0 || g.PruneExpiredAfterDays > 3650 {
		return models.GovernanceSettings{}, errors.New("prune_expired_after_days must be between 0 and 3650")
	}
	err := s.withWrite(func() error {
		now := time.Now().UTC()
		g.UpdatedAt, g.UpdatedBy = &now, actor.Username
		g.LastDigestAt = s.state.Governance.LastDigestAt
		before := s.state.Governance
		s.state.Governance = g
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "GOVERNANCE_UPDATED", Category: "SYSTEM",
			EntityType: "governance", EntityID: "global", EntityName: "Governance settings",
			Summary: fmt.Sprintf("Four-eyes review=%v, SLA=%dh, recertification=%dd, max temporary access=%dd, daily digest=%v, prune expired after %dd",
				g.RequirePolicyReview, g.RequestSLAHours, g.DefaultReviewIntervalDays, g.MaxTemporaryAccessDays, g.DailyDigest, g.PruneExpiredAfterDays),
			BeforeState: fmt.Sprintf("%+v", before), AfterState: fmt.Sprintf("%+v", g),
		})
		s.saveLocked()
		return nil
	})
	return g, err
}

func (s *Store) ChangeRequest(id string) (models.ChangeRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, cr := range s.state.ChangeRequests {
		if cr.ID == id {
			return cr, true
		}
	}
	return models.ChangeRequest{}, false
}

func sortedCopy(v []string) []string {
	out := slices.Clone(v)
	slices.Sort(out)
	return out
}
