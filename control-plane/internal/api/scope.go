package api

import (
	"slices"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

// teamScope implements need-to-know for Team Leads: they see requests, traffic, sessions, security
// events, servers, policy objects and audit entries of their own server groups only. Other roles see
// everything.
type teamScope struct {
	groups map[string]bool
	user   string
}

// scopeFor returns nil when the caller is not restricted.
func scopeFor(claims *auth.TokenClaims) *teamScope {
	if claims == nil || claims.Role != models.RoleTeamLead || slices.Contains(claims.AllowedGroups, "*") {
		return nil
	}
	t := &teamScope{groups: map[string]bool{}, user: claims.Username}
	for _, g := range claims.AllowedGroups {
		t.groups[g] = true
	}
	return t
}

func (t *teamScope) anyOf(groups ...[]string) bool {
	for _, gs := range groups {
		for _, g := range gs {
			if t.groups[g] {
				return true
			}
		}
	}
	return false
}

func filterSlice[T any](in []T, keep func(T) bool) []T {
	out := make([]T, 0, len(in))
	for _, v := range in {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

// snapshot restricts a state snapshot and the server list to the Team Lead's groups.
func (t *teamScope) snapshot(snap store.StateSnapshot, servers []models.Server) (store.StateSnapshot, []models.Server) {
	snap = t.policies(snap, servers)
	servers = filterSlice(servers, t.serverVisible)
	snap.Servers = filterSlice(snap.Servers, t.serverVisible)
	snap.Requests = filterSlice(snap.Requests, func(r models.AccessRequest) bool { return t.anyOf(r.TargetGroupIDs, r.GroupIDs) })
	snap.Flows = filterSlice(snap.Flows, func(f models.TrafficFlow) bool { return t.anyOf(f.GroupIDs) })
	snap.Sessions = filterSlice(snap.Sessions, func(s models.LearningSession) bool { return t.anyOf(s.GroupIDs) })
	snap.SecurityEvents = filterSlice(snap.SecurityEvents, func(e models.SecurityEvent) bool { return t.anyOf(e.GroupIDs) })
	snap.AuditEvents = filterSlice(snap.AuditEvents, func(e models.AuditEvent) bool { return e.Actor == t.user || t.anyOf(e.ScopeGroups) })
	// Reviewers they can hand requests to, colleagues of their groups and themselves.
	snap.Users = filterSlice(snap.Users, func(u models.User) bool {
		return u.Username == t.user || u.Role == models.RoleSuperAdmin || u.Role == models.RoleInfoSecApprover ||
			(u.Role == models.RoleTeamLead && t.anyOf(u.AllowedGroups))
	})
	return snap, servers
}

// serverVisible reports whether a server belongs to one of the Team Lead's groups.
func (t *teamScope) serverVisible(srv models.Server) bool {
	return t.anyOf(srv.EffectiveGroupIDs, srv.GroupIDs)
}

// policyView decides which policy objects a Team Lead may read: baseline sets (they apply to every
// server), sets scoped to their groups or servers, sets they created and the rules, change requests
// and TLS bypass entries that belong to them.
type policyView struct {
	t       *teamScope
	servers map[string]bool // in-scope server IDs
	sets    map[string]bool // visible policy set IDs
}

func (t *teamScope) policyView(servers []models.Server, sets []models.PolicySet) *policyView {
	v := &policyView{t: t, servers: map[string]bool{}, sets: map[string]bool{}}
	for _, srv := range servers {
		if t.serverVisible(srv) {
			v.servers[srv.ID] = true
		}
	}
	for _, set := range sets {
		if set.Kind == models.PolicySetKindBaseline || set.CreatedBy == t.user || v.scoped(set.GroupIDs, set.ServerIDs) ||
			(set.Draft != nil && v.scoped(set.Draft.Spec.GroupIDs, set.Draft.Spec.ServerIDs)) {
			v.sets[set.ID] = true
		}
	}
	return v
}

// scoped reports whether a group/server scope reaches one of the Team Lead's servers ("*" reaches all).
func (v *policyView) scoped(groups, servers []string) bool {
	if slices.Contains(groups, "*") || slices.Contains(servers, "*") || v.t.anyOf(groups) {
		return true
	}
	return slices.ContainsFunc(servers, func(id string) bool { return v.servers[id] })
}

func (v *policyView) set(id string) bool { return v.sets[id] }

func (v *policyView) rule(r models.PolicyRule) bool {
	if r.PolicySetID != "" {
		return v.sets[r.PolicySetID]
	}
	return v.scoped(r.GroupIDs, r.ServerIDs)
}

func (v *policyView) changeRequest(cr models.ChangeRequest) bool {
	return v.sets[cr.PolicySetID] || cr.SubmittedBy == v.t.user
}

// tlsBypass: entries without a scope apply to every server.
func (v *policyView) tlsBypass(b models.TLSBypassRule) bool {
	return (len(b.GroupIDs) == 0 && len(b.ServerIDs) == 0) || v.scoped(b.GroupIDs, b.ServerIDs)
}

// policies restricts the policy part of a state snapshot (servers must be the unfiltered list).
func (t *teamScope) policies(snap store.StateSnapshot, servers []models.Server) store.StateSnapshot {
	v := t.policyView(servers, snap.PolicySets)
	snap.PolicySets = filterSlice(snap.PolicySets, func(p models.PolicySet) bool { return v.set(p.ID) })
	snap.Rules = filterSlice(snap.Rules, v.rule)
	snap.ChangeRequests = filterSlice(snap.ChangeRequests, v.changeRequest)
	snap.TLSBypass = filterSlice(snap.TLSBypass, v.tlsBypass)
	return snap
}

// scopedImpact narrows a change request's stored impact to the caller: Team Leads get the counters
// and samples of their groups only (impacts stored without a per-group breakdown show nothing).
// The breakdown itself is never served. The stored value is not modified.
func scopedImpact(imp *models.ImpactSummary, t *teamScope) *models.ImpactSummary {
	if imp == nil {
		return nil
	}
	out := *imp
	out.Scopes = nil
	if t == nil {
		return &out
	}
	out.FlowsEvaluated, out.NewlyAllowed, out.NewlyBlocked, out.Unchanged, out.AffectedServers, out.TargetServers = 0, 0, 0, 0, 0, 0
	for _, sc := range imp.Scopes {
		if t.anyOf(sc.GroupIDs) {
			out.FlowsEvaluated += sc.FlowsEvaluated
			out.NewlyAllowed += sc.NewlyAllowed
			out.NewlyBlocked += sc.NewlyBlocked
			out.Unchanged += sc.Unchanged
			out.AffectedServers += sc.AffectedServers
			out.TargetServers += sc.TargetServers
		}
	}
	out.Samples = filterSlice(imp.Samples, func(s models.ImpactSample) bool { return t.anyOf(s.GroupIDs) })
	return &out
}

// scopedChangeRequests applies scopedImpact to a list of change requests (copies).
func scopedChangeRequests(crs []models.ChangeRequest, t *teamScope) []models.ChangeRequest {
	out := make([]models.ChangeRequest, len(crs))
	for i, cr := range crs {
		cr.Impact = scopedImpact(cr.Impact, t)
		out[i] = cr
	}
	return out
}

func (t *teamScope) bandwidth(b models.BandwidthSummary) models.BandwidthSummary {
	b.TopServers = filterSlice(b.TopServers, func(e models.ServerVolumeEntry) bool { return t.anyOf(e.GroupIDs) })
	b.GroupBreakdown = filterSlice(b.GroupBreakdown, func(e models.GroupVolumeEntry) bool { return t.groups[e.GroupID] })
	b.TopDestinations = nil // not attributable to groups
	return b
}

// nonNil makes empty lists serialize as [] instead of null.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
