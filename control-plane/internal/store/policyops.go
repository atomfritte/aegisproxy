package store

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// compileSets flattens the published content of enabled sets into effective rules (highest
// priority first). stats may be nil.
func compileSets(sets []models.PolicySet, stats map[string]RuleStat) []models.PolicyRule {
	sorted := slices.Clone(sets)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority > sorted[j].Priority })
	var out []models.PolicyRule
	for i := range sorted {
		set := &sorted[i]
		if !set.Enabled || set.Version == 0 {
			continue
		}
		groups, servers := setScope(set)
		for _, r := range set.Rules {
			if !r.Enabled {
				continue
			}
			cr := cloneRule(r)
			cr.GroupIDs, cr.ServerIDs = groups, servers
			cr.PolicySetID, cr.PolicySetName = set.ID, set.Name
			if st, ok := stats[r.ID]; ok {
				cr.HitCount, cr.TotalBytes = st.Hits, st.Bytes
			}
			out = append(out, cr)
		}
	}
	if out == nil {
		out = []models.PolicyRule{}
	}
	return out
}

// bumpRuleStatLocked records one hit for a rule (stats map + compiled copy).
func (s *Store) bumpRuleStatLocked(ruleID string, bytes int64) bool {
	i, ok := s.ruleIndex[ruleID]
	if !ok || i >= len(s.state.Rules) || s.state.Rules[i].ID != ruleID {
		return false
	}
	if s.state.RuleStats == nil {
		s.state.RuleStats = map[string]RuleStat{}
	}
	st := s.state.RuleStats[ruleID]
	st.Hits++
	st.Bytes += bytes
	s.state.RuleStats[ruleID] = st
	s.state.Rules[i].HitCount, s.state.Rules[i].TotalBytes = st.Hits, st.Bytes
	return true
}

// applyRuleStatsLocked replaces the hit counters (cluster: values pulled from shared storage).
func (s *Store) applyRuleStatsLocked(stats map[string]RuleStat) {
	if s.state.RuleStats == nil {
		s.state.RuleStats = map[string]RuleStat{}
	}
	for id, st := range stats {
		s.state.RuleStats[id] = st
	}
	for i := range s.state.Rules {
		if st, ok := s.state.RuleStats[s.state.Rules[i].ID]; ok {
			s.state.Rules[i].HitCount, s.state.Rules[i].TotalBytes = st.Hits, st.Bytes
		}
	}
}

// ---------------------------------------------------------------------------
// Migration (schema v3): flat rules -> policy sets
// ---------------------------------------------------------------------------

func (s *Store) groupNameLocked(id string) string {
	for _, g := range s.state.Groups {
		if g.ID == id {
			return g.Name
		}
	}
	return id
}

func (s *Store) migratePolicySetsLocked() {
	if s.state.RuleStats == nil {
		s.state.RuleStats = map[string]RuleStat{}
	}
	if s.state.PolicyVersions == nil {
		s.state.PolicyVersions = []models.PolicySetVersion{}
	}
	if s.state.ChangeRequests == nil {
		s.state.ChangeRequests = []models.ChangeRequest{}
	}
	if len(s.state.PolicySets) > 0 || len(s.state.Rules) == 0 {
		if s.state.PolicySets == nil {
			s.state.PolicySets = []models.PolicySet{}
		}
		return
	}
	if s.state.Governance.RequestSLAHours == 0 {
		s.state.Governance = DefaultGovernance()
	}
	reqByRule := map[string]int{}
	for i, r := range s.state.Requests {
		if r.CreatedRuleID != "" {
			reqByRule[r.CreatedRuleID] = i
		}
	}
	type bucket struct {
		kind            string
		groups, servers []string
		rules           []models.PolicyRule
	}
	var order []string
	buckets := map[string]*bucket{}
	for _, r := range s.state.Rules {
		if r.HitCount > 0 || r.TotalBytes > 0 {
			s.state.RuleStats[r.ID] = RuleStat{Hits: r.HitCount, Bytes: r.TotalBytes}
		}
		groups := slices.Sorted(slices.Values(r.GroupIDs))
		servers := slices.Sorted(slices.Values(r.ServerIDs))
		kind := models.PolicySetKindStandard
		if slices.Contains(groups, "*") || slices.Contains(servers, "*") {
			kind, groups, servers = models.PolicySetKindBaseline, []string{}, []string{}
		} else if ri, ok := reqByRule[r.ID]; ok && len(groups) == 1 && len(servers) == 0 && strings.EqualFold(r.Action, "ALLOW") {
			kind = models.PolicySetKindApprovals
			r.AccessRequestID = s.state.Requests[ri].ID
			s.state.Requests[ri].CreatedRuleIDs = []string{r.ID}
		}
		key := kind + "|" + strings.Join(groups, ",") + "|" + strings.Join(servers, ",")
		b := buckets[key]
		if b == nil {
			b = &bucket{kind: kind, groups: groups, servers: servers}
			buckets[key] = b
			order = append(order, key)
		}
		r = cloneRule(r)
		r.GroupIDs, r.ServerIDs = []string{}, []string{}
		r.HitCount, r.TotalBytes = 0, 0
		if r.Version == 0 {
			r.Version = 1
		}
		b.rules = append(b.rules, r)
	}
	now := time.Now().UTC()
	names := map[string]bool{}
	for _, key := range order {
		b := buckets[key]
		var name, id string
		priority := 0
		switch {
		case b.kind == models.PolicySetKindBaseline:
			name, priority = "Global baseline", 100
		case b.kind == models.PolicySetKindApprovals:
			name, id, priority = "Approved requests · "+s.groupNameLocked(b.groups[0]), "approvals-"+b.groups[0], -10
		default:
			var parts []string
			for _, g := range b.groups {
				parts = append(parts, s.groupNameLocked(g))
			}
			for _, sid := range b.servers {
				if srv, ok := s.serverByIDLocked(sid); ok {
					parts = append(parts, srv.Hostname)
				} else {
					parts = append(parts, sid)
				}
			}
			if len(parts) > 3 {
				parts = append(parts[:3], fmt.Sprintf("+%d", len(parts)-3))
			}
			name = strings.Join(parts, ", ") + " egress"
		}
		base := name
		for n := 2; names[strings.ToLower(name)]; n++ {
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		names[strings.ToLower(name)] = true
		if id == "" {
			id = newRandomID("ps")
		}
		spec := models.PolicySetSpec{
			Name: name, Description: "Migrated automatically from the flat rule list of AegisProxy 2.0.",
			Tags: []string{"migrated"}, Priority: priority, Enabled: true, GroupIDs: b.groups, ServerIDs: b.servers,
			Rules: b.rules, ReviewIntervalDays: s.state.Governance.DefaultReviewIntervalDays,
		}
		set := models.PolicySet{ID: id, Kind: b.kind, PolicySetSpec: spec, Version: 1, PublishedAt: &now, PublishedBy: "system",
			CreatedAt: now, CreatedBy: "system", LastReviewedAt: &now, LastReviewedBy: "system"}
		s.state.PolicySets = append(s.state.PolicySets, set)
		s.state.PolicyVersions = append(s.state.PolicyVersions, models.PolicySetVersion{
			PolicySetID: id, Version: 1, Spec: cloneSpec(spec), PublishedBy: "system", PublishedAt: now,
			Summary: fmt.Sprintf("Migrated %d rules", len(b.rules)),
		})
	}
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "POLICY_MIGRATED", Category: "POLICY",
		EntityType: "policy_set", EntityID: "migration-v3", EntityName: "Policy sets",
		Summary: fmt.Sprintf("Migrated %d flat rules into %d policy sets grouped by scope (schema v3)", len(s.state.Rules), len(order)),
	})
}

// ---------------------------------------------------------------------------
// Approvals sets (approved access requests per group)
// ---------------------------------------------------------------------------

func approvalsSetID(groupID string) string { return "approvals-" + groupID }

// ensureApprovalsSetLocked returns the index of the approvals set of a group, creating it.
func (s *Store) ensureApprovalsSetLocked(groupID string) int {
	id := approvalsSetID(groupID)
	if i := s.setIndexLocked(id); i >= 0 {
		return i
	}
	now := time.Now().UTC()
	s.state.PolicySets = append(s.state.PolicySets, models.PolicySet{
		ID: id, Kind: models.PolicySetKindApprovals, CreatedAt: now, CreatedBy: "system",
		PolicySetSpec: models.PolicySetSpec{
			Name:        "Approved requests · " + s.groupNameLocked(groupID),
			Description: "Managed by the access request workflow: every approved request adds a rule here.",
			Tags:        []string{"approvals"}, Priority: -10, Enabled: true,
			GroupIDs: []string{groupID}, ServerIDs: []string{}, Rules: []models.PolicyRule{},
			ReviewIntervalDays: s.state.Governance.DefaultReviewIntervalDays,
		},
	})
	return len(s.state.PolicySets) - 1
}

// ---------------------------------------------------------------------------
// Impact simulation
// ---------------------------------------------------------------------------

type ruleOutcome struct {
	allowed bool
	rule    string
}

func ruleDecision(idx *engine.CompiledPolicyIndex, host, path, method, srvID string, groups []string, explicitOnly bool) ruleOutcome {
	if r, ok := matchIndexedRules(idx, host, path, method, srvID, groups, true, false); ok {
		return ruleOutcome{false, r.Name}
	}
	if r, ok := matchIndexedRules(idx, host, path, method, srvID, groups, false, explicitOnly); ok {
		return ruleOutcome{true, r.Name}
	}
	return ruleOutcome{false, ""}
}

// SimulateSpec replays the recorded traffic window against the current policy and against the
// policy that would result from publishing spec for set setID ("" = a new set of the given spec).
// Team Leads may only simulate sets they could change and only see their groups' servers and traffic.
func (s *Store) SimulateSpec(setID string, spec *models.PolicySetSpec, actor *auth.TokenClaims) (models.ImpactSummary, error) {
	if actor == nil {
		return models.ImpactSummary{}, errors.New("unauthenticated")
	}
	scoped := actor.Role == models.RoleTeamLead && !slices.Contains(actor.AllowedGroups, "*")
	s.mu.RLock()
	if scoped {
		kind, scopes := models.PolicySetKindStandard, []models.PolicySetSpec{*spec}
		if i := s.setIndexLocked(setID); i >= 0 {
			kind = s.state.PolicySets[i].Kind
			scopes = append(scopes, s.state.PolicySets[i].PolicySetSpec)
		}
		if err := s.canManageSetLocked(actor, kind, scopes...); err != nil {
			s.mu.RUnlock()
			return models.ImpactSummary{}, err
		}
	}
	in := s.simulationInputLocked(setID, spec)
	s.mu.RUnlock()
	if scoped {
		mine := func(groups []string) bool {
			return slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(actor.AllowedGroups, g) })
		}
		in.servers = slices.DeleteFunc(in.servers, func(srv models.Server) bool { return !mine(srv.EffectiveGroupIDs) && !mine(srv.GroupIDs) })
		in.flows = slices.DeleteFunc(in.flows, func(f models.TrafficFlow) bool { return !mine(f.GroupIDs) })
	}
	return simulate(in), nil
}

type simInput struct {
	kind               string
	spec               models.PolicySetSpec
	current, candidate []models.PolicyRule
	servers            []models.Server
	groups             []models.ServerGroup
	flows              []models.TrafficFlow
	policy             models.SecurityPolicy
}

func (s *Store) simulationInputLocked(setID string, spec *models.PolicySetSpec) simInput {
	sets := slices.Clone(s.state.PolicySets)
	kind := models.PolicySetKindStandard
	if i := slices.IndexFunc(sets, func(p models.PolicySet) bool { return p.ID == setID }); i >= 0 {
		kind = sets[i].Kind
		cand := sets[i]
		cand.PolicySetSpec = cloneSpec(*spec)
		cand.Version = max(cand.Version, 1)
		sets[i] = cand
	} else {
		sets = append(sets, models.PolicySet{ID: "simulated", Kind: kind, PolicySetSpec: cloneSpec(*spec), Version: 1})
	}
	return simInput{kind: kind, spec: cloneSpec(*spec), current: slices.Clone(s.state.Rules), candidate: compileSets(sets, nil),
		servers: s.effectiveServersLocked(), groups: slices.Clone(s.state.Groups), flows: slices.Clone(s.state.Flows), policy: s.state.SecurityPolicy}
}

func simulate(in simInput) models.ImpactSummary {
	kind, spec, current, candidate, servers, groups, flows, policy := in.kind, &in.spec, in.current, in.candidate, in.servers, in.groups, in.flows, in.policy
	curIdx := engine.BuildCompiledIndex(0, groups, servers, current)
	candIdx := engine.BuildCompiledIndex(0, groups, servers, candidate)
	srvGroups := make(map[string][]string, len(servers))
	for _, srv := range servers {
		srvGroups[srv.ID] = srv.GroupIDs
	}
	tmp := models.PolicySet{Kind: kind, PolicySetSpec: *spec}
	tGroups, tServers := setScope(&tmp)
	sum := models.ImpactSummary{Samples: []models.ImpactSample{}, ComputedAt: time.Now().UTC()}
	// Per-group breakdown: one scope per distinct server group membership.
	scopeIdx := map[string]int{}
	scopeAffected := map[string]map[string]bool{}
	scopeOf := func(groups []string) *models.ImpactScope {
		key := strings.Join(sortedCopy(groups), ",")
		i, ok := scopeIdx[key]
		if !ok {
			i = len(sum.Scopes)
			scopeIdx[key] = i
			sum.Scopes = append(sum.Scopes, models.ImpactScope{GroupIDs: nonNil(sortedCopy(groups))})
			scopeAffected[key] = map[string]bool{}
		}
		return &sum.Scopes[i]
	}
	for _, srv := range servers {
		if slices.Contains(tGroups, "*") || slices.Contains(tServers, srv.ID) || slices.ContainsFunc(srv.GroupIDs, func(g string) bool { return slices.Contains(tGroups, g) }) {
			sum.TargetServers++
			scopeOf(srv.GroupIDs).TargetServers++
		}
	}
	affected := map[string]bool{}
	seen := map[string]bool{}
	for _, f := range flows {
		ruleBased := f.Verdict == models.VerdictAllowed || f.Verdict == models.VerdictBlocked ||
			(f.Verdict == models.VerdictPolicyBlocked && (f.BlockReason == "ip_literal" || f.BlockReason == "internal_destination"))
		if !ruleBased || f.Host == "" {
			continue
		}
		host := engine.NormalizeHost(f.Host)
		path, ok := engine.CanonicalizePath(f.Path)
		if !ok {
			continue
		}
		method := strings.ToUpper(f.Method)
		if method == "CONNECT" {
			path = "/"
		}
		groupsOf := f.GroupIDs
		if g, ok := srvGroups[f.ServerID]; ok {
			groupsOf = g
		}
		_, ipErr := netip.ParseAddr(host)
		explicitOnly := (ipErr == nil && policy.BlockIPLiterals) || (policy.BlockPrivateDestinations && engine.IsInternalHost(host))
		before := ruleDecision(curIdx, host, path, method, f.ServerID, groupsOf, explicitOnly)
		after := ruleDecision(candIdx, host, path, method, f.ServerID, groupsOf, explicitOnly)
		sum.FlowsEvaluated++
		sc := scopeOf(groupsOf)
		sc.FlowsEvaluated++
		if before.allowed == after.allowed {
			sum.Unchanged++
			sc.Unchanged++
			continue
		}
		if after.allowed {
			sum.NewlyAllowed++
			sc.NewlyAllowed++
		} else {
			sum.NewlyBlocked++
			sc.NewlyBlocked++
		}
		affected[f.ServerID] = true
		if key := strings.Join(sc.GroupIDs, ","); !scopeAffected[key][f.ServerID] {
			scopeAffected[key][f.ServerID] = true
			sc.AffectedServers++
		}
		key := f.ServerID + "|" + method + "|" + f.FullURL
		if len(sum.Samples) < 25 && !seen[key] {
			seen[key] = true
			verdict := func(o ruleOutcome) string {
				if o.allowed {
					return models.VerdictAllowed
				}
				return models.VerdictBlocked
			}
			sum.Samples = append(sum.Samples, models.ImpactSample{ServerHostname: f.ServerHostname, ServerIP: f.ServerIP, Method: method,
				URL: f.FullURL, Before: verdict(before), After: verdict(after), RuleName: cmpOr(after.rule, before.rule),
				ServerID: f.ServerID, GroupIDs: slices.Clone(groupsOf)})
		}
	}
	sum.AffectedServers = len(affected)
	return sum
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
