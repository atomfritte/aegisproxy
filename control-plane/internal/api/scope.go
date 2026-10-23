package api

import (
	"slices"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

// teamScope implements need-to-know for Team Leads: they see requests, traffic, sessions, security
// events, servers and audit entries of their own server groups only. Other roles see everything.
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
	servers = filterSlice(servers, func(s models.Server) bool { return t.anyOf(s.EffectiveGroupIDs, s.GroupIDs) })
	snap.Servers = filterSlice(snap.Servers, func(s models.Server) bool { return t.anyOf(s.EffectiveGroupIDs, s.GroupIDs) })
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
