package store

import (
	"cmp"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

var (
	idRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
	colorRe      = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	labelKeyRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$`)
	maxLabels    = 32
	maxImportRow = 2000
)

const (
	unregisteredPrefix = "srv-unregistered-"
	autoPrefix         = "srv-auto-"
)

// ---------------------------------------------------------------------------
// Derived membership
// ---------------------------------------------------------------------------

func labelsMatch(labels, selector map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if lv, ok := labels[k]; !ok || (v != "*" && lv != v) {
			return false
		}
	}
	return true
}

// computeEffectiveGroupsLocked sets Server.EffectiveGroupIDs = static groups + label-matched groups.
func (s *Store) computeEffectiveGroupsLocked() {
	for i := range s.state.Servers {
		srv := &s.state.Servers[i]
		eff := append([]string{}, srv.GroupIDs...)
		for _, g := range s.state.Groups {
			if labelsMatch(srv.Labels, g.MatchLabels) && !slices.Contains(eff, g.ID) {
				eff = append(eff, g.ID)
			}
		}
		srv.EffectiveGroupIDs = eff
	}
}

// effectiveServersLocked returns copies whose GroupIDs are the effective memberships (what the
// engine, RBAC checks and the data-plane bundle use).
func (s *Store) effectiveServersLocked() []models.Server {
	out := make([]models.Server, len(s.state.Servers))
	for i, srv := range s.state.Servers {
		srv = cloneServer(srv)
		if srv.EffectiveGroupIDs != nil {
			srv.GroupIDs = append([]string{}, srv.EffectiveGroupIDs...)
		}
		out[i] = srv
	}
	return out
}

func (s *Store) serverByIDLocked(id string) (models.Server, bool) {
	for _, srv := range s.state.Servers {
		if srv.ID == id {
			return srv, true
		}
	}
	return models.Server{}, false
}

func cloneServer(srv models.Server) models.Server {
	srv.GroupIDs = append([]string{}, srv.GroupIDs...)
	srv.EffectiveGroupIDs = append([]string{}, srv.EffectiveGroupIDs...)
	if srv.Labels != nil {
		srv.Labels = maps.Clone(srv.Labels)
	}
	srv.ProxyAuthToken = ""
	return srv
}

func cloneGroup(g models.ServerGroup) models.ServerGroup {
	g.CIDRs = append([]string{}, g.CIDRs...)
	if g.MatchLabels != nil {
		g.MatchLabels = maps.Clone(g.MatchLabels)
	}
	return g
}

func validateLabels(field string, labels map[string]string, allowWildcard bool) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil
	}
	if len(labels) > maxLabels {
		return nil, fmt.Errorf("%s: at most %d labels", field, maxLabels)
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !labelKeyRe.MatchString(k) {
			return nil, fmt.Errorf("%s: invalid label key %q (lowercase letters, digits, '.', '_', '/', '-')", field, k)
		}
		if v == "*" && !allowWildcard {
			return nil, fmt.Errorf("%s: label %q: '*' is only allowed in group selectors", field, k)
		}
		if err := checkText(field+"."+k, v, 128, false); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func (s *Store) UpsertGroup(g models.ServerGroup, actor *auth.TokenClaims) (models.ServerGroup, error) {
	if !auth.CanManageSystem(actor) {
		return models.ServerGroup{}, errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage server groups")
	}
	g.ID = strings.ToLower(strings.TrimSpace(g.ID))
	if !idRe.MatchString(g.ID) {
		return models.ServerGroup{}, errors.New("group id must be 2-64 characters: lowercase letters, digits or '-'")
	}
	if err := checkText("name", g.Name, 120, true); err != nil {
		return models.ServerGroup{}, err
	}
	if err := checkText("description", g.Description, 1000, false); err != nil {
		return models.ServerGroup{}, err
	}
	for _, f := range []struct{ n, v string }{{"environment", g.Environment}, {"owner_team", g.OwnerTeam}} {
		if err := checkText(f.n, f.v, 120, false); err != nil {
			return models.ServerGroup{}, err
		}
	}
	if g.Color == "" {
		g.Color = "#64748B"
	}
	if !colorRe.MatchString(g.Color) {
		return models.ServerGroup{}, errors.New("color must be a hex color like #2563EB")
	}
	cidrs := make([]string, 0, len(g.CIDRs))
	for _, c := range g.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return models.ServerGroup{}, fmt.Errorf("invalid CIDR %q", c)
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	g.CIDRs = cidrs
	if g.ServerCount < 0 {
		g.ServerCount = 0
	}
	var err error
	if g.MatchLabels, err = validateLabels("match_labels", g.MatchLabels, true); err != nil {
		return models.ServerGroup{}, err
	}

	err = s.withWrite(func() error {
		if g.BlockPageTemplateID != "" && !slices.ContainsFunc(s.state.BlockPages, func(t models.BlockPageTemplate) bool { return t.ID == g.BlockPageTemplateID }) {
			return fmt.Errorf("unknown block page template %q", g.BlockPageTemplateID)
		}
		action := "GROUP_CREATED"
		if i := slices.IndexFunc(s.state.Groups, func(x models.ServerGroup) bool { return x.ID == g.ID }); i >= 0 {
			s.state.Groups[i] = g
			action = "GROUP_UPDATED"
		} else {
			s.state.Groups = append(s.state.Groups, g)
		}
		selector := ""
		if len(g.MatchLabels) > 0 {
			selector = fmt.Sprintf(", label selector %s", formatLabels(g.MatchLabels))
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "FLEET",
			EntityType: "server_group", EntityID: g.ID, EntityName: g.Name,
			Summary: fmt.Sprintf("%s server group %s (CIDRs %v, strict isolation=%v%s)", strings.ToLower(strings.TrimPrefix(action, "GROUP_")), g.ID, g.CIDRs, g.StrictIsolation, selector),
		})
		s.saveLocked()
		return nil
	})
	if err != nil {
		return models.ServerGroup{}, err
	}
	return g, nil
}

func formatLabels(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

func (s *Store) DeleteGroup(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage server groups")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Groups, func(x models.ServerGroup) bool { return x.ID == id })
		if i == -1 {
			return errors.New("group not found")
		}
		for _, srv := range s.state.Servers {
			if slices.Contains(srv.GroupIDs, id) {
				return fmt.Errorf("group is still assigned to server %s", srv.ID)
			}
		}
		for _, set := range s.state.PolicySets {
			if set.Kind == models.PolicySetKindApprovals && slices.Contains(set.GroupIDs, id) && len(set.Rules) == 0 {
				continue
			}
			if slices.Contains(set.GroupIDs, id) || (set.Draft != nil && slices.Contains(set.Draft.Spec.GroupIDs, id)) {
				return fmt.Errorf("group is still assigned to policy set %q", set.Name)
			}
		}
		for _, b := range s.state.TLSBypass {
			if slices.Contains(b.GroupIDs, id) {
				return fmt.Errorf("group is still referenced by TLS exception %s", b.Pattern)
			}
		}
		s.state.PolicySets = slices.DeleteFunc(s.state.PolicySets, func(p models.PolicySet) bool {
			return p.Kind == models.PolicySetKindApprovals && slices.Contains(p.GroupIDs, id)
		})
		g := s.state.Groups[i]
		s.state.Groups = slices.Delete(s.state.Groups, i, i+1)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "GROUP_DELETED", Category: "FLEET",
			EntityType: "server_group", EntityID: g.ID, EntityName: g.Name, Summary: "Deleted server group " + g.ID,
		})
		s.saveLocked()
		return nil
	})
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

// normalizeServerInput validates and canonicalizes the client-controllable fields of a server; all problems of the input are reported
// together (one message per field, joined with "; ") so a CSV row can be fixed in one pass.
func normalizeServerInput(srv *models.Server) error {
	var problems []string
	fail := func(err error) {
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	srv.ID = strings.ToLower(strings.TrimSpace(srv.ID))
	if srv.ID == "" {
		srv.ID = newRandomID("srv")
	}
	if !idRe.MatchString(srv.ID) || strings.HasPrefix(srv.ID, unregisteredPrefix) || strings.HasPrefix(srv.ID, autoPrefix) {
		fail(errors.New("server id must be 2-64 characters: lowercase letters, digits or '-' (srv-auto-/srv-unregistered- are reserved)"))
	}
	srv.Hostname = strings.TrimSpace(srv.Hostname)
	fail(checkText("hostname", srv.Hostname, 255, true))
	if srv.IP = strings.TrimSpace(srv.IP); srv.IP != "" {
		if a, err := netip.ParseAddr(srv.IP); err != nil {
			fail(fmt.Errorf("invalid IP address %q", srv.IP))
		} else {
			srv.IP = a.Unmap().String()
		}
	}
	if srv.SubnetCIDR = strings.TrimSpace(srv.SubnetCIDR); srv.SubnetCIDR != "" {
		if p, err := netip.ParsePrefix(srv.SubnetCIDR); err != nil {
			fail(fmt.Errorf("invalid subnet CIDR %q", srv.SubnetCIDR))
		} else {
			srv.SubnetCIDR = p.Masked().String()
		}
	}
	srv.ProxyAuthUser = strings.ToLower(strings.TrimSpace(srv.ProxyAuthUser))
	if srv.ProxyAuthUser != "" && !usernameRe.MatchString(srv.ProxyAuthUser) {
		fail(errors.New("proxy_auth_user must be 2-64 characters: lowercase letters, digits, '.', '_' or '-'"))
	}
	for _, f := range []struct{ n, v string }{{"os", srv.OS}, {"department", srv.Department}, {"owner_team", srv.OwnerTeam}} {
		fail(checkText(f.n, f.v, 120, false))
	}
	fail(checkText("description", srv.Description, 1000, false))
	labels, err := validateLabels("labels", srv.Labels, false)
	if err != nil {
		fail(err)
	} else {
		srv.Labels = labels
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	if srv.GroupIDs == nil {
		srv.GroupIDs = []string{}
	}
	slices.Sort(srv.GroupIDs)
	srv.GroupIDs = slices.Compact(srv.GroupIDs)
	return nil
}

// applyServerLocked validates srv against the inventory inv and returns the updated inventory.
// Server-controlled fields (token digest, quarantine, timestamps) are preserved from the existing entry.
func (s *Store) applyServerLocked(inv []models.Server, srv models.Server) ([]models.Server, string, models.Server, error) {
	if err := s.validateScopeLocked(srv.GroupIDs, nil); err != nil {
		return inv, "", srv, err
	}
	if slices.Contains(srv.GroupIDs, "*") {
		return inv, "", srv, errors.New("servers cannot be members of '*'")
	}
	for _, other := range inv {
		if other.ID == srv.ID {
			continue
		}
		if srv.ProxyAuthUser != "" && strings.EqualFold(other.ProxyAuthUser, srv.ProxyAuthUser) {
			return inv, "", srv, fmt.Errorf("proxy_auth_user %q is already used by %s", srv.ProxyAuthUser, other.ID)
		}
		if srv.IP != "" && other.IP == srv.IP {
			return inv, "", srv, fmt.Errorf("IP %s is already registered to %s", srv.IP, other.ID)
		}
	}
	srv.ProxyAuthToken = ""
	srv.EffectiveGroupIDs = nil
	if i := slices.IndexFunc(inv, func(x models.Server) bool { return x.ID == srv.ID }); i >= 0 {
		prev := inv[i]
		srv.ProxyAuthTokenHash, srv.TokenRotatedAt, srv.LastSeenAt = prev.ProxyAuthTokenHash, prev.TokenRotatedAt, prev.LastSeenAt
		srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = prev.Quarantined, prev.QuarantineReason, prev.QuarantinedBy, prev.QuarantinedAt
		srv.CreatedAt, srv.Defender = prev.CreatedAt, prev.Defender
		inv = slices.Clone(inv)
		inv[i] = srv
		return inv, "update", srv, nil
	}
	now := time.Now().UTC()
	srv.ProxyAuthTokenHash, srv.TokenRotatedAt = "", nil
	srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = false, "", "", nil
	srv.CreatedAt = &now
	return append(slices.Clone(inv), srv), "create", srv, nil
}

func (s *Store) UpsertServer(srv models.Server, actor *auth.TokenClaims) (models.Server, error) {
	if !auth.CanManageSystem(actor) {
		return models.Server{}, errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage servers")
	}
	if err := normalizeServerInput(&srv); err != nil {
		return models.Server{}, err
	}
	var out models.Server
	err := s.withWrite(func() error {
		inv, op, saved, err := s.applyServerLocked(s.state.Servers, srv)
		if err != nil {
			return err
		}
		s.state.Servers = inv
		action := map[string]string{"create": "SERVER_REGISTERED", "update": "SERVER_UPDATED"}[op]
		labels := ""
		if len(saved.Labels) > 0 {
			labels = ", labels " + formatLabels(saved.Labels)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "FLEET",
			EntityType: "server", EntityID: saved.ID, EntityName: saved.Hostname,
			Summary:     fmt.Sprintf("%s %s (%s) in groups %v%s", op+"d", saved.Hostname, saved.IP, saved.GroupIDs, labels),
			ScopeGroups: saved.GroupIDs,
		})
		s.saveLocked()
		out, _ = s.serverByIDLocked(saved.ID)
		out = cloneServer(out)
		return nil
	})
	return out, err
}

// ImportServers creates or updates many servers at once. With dryRun nothing is changed; the
// result shows what would happen. The import is all-or-nothing.
func (s *Store) ImportServers(rows []models.Server, dryRun bool, actor *auth.TokenClaims) ([]models.ServerImportResult, error) {
	if !auth.CanManageSystem(actor) {
		return nil, errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage servers")
	}
	if len(rows) == 0 {
		return nil, errors.New("no rows to import")
	}
	if len(rows) > maxImportRow {
		return nil, fmt.Errorf("at most %d rows per import", maxImportRow)
	}
	results := make([]models.ServerImportResult, len(rows))
	var failed bool
	err := s.withWrite(func() error {
		inv := s.state.Servers
		seen := map[string]int{}
		created, updated := 0, 0
		for i, srv := range rows {
			res := models.ServerImportResult{Row: i + 1, ID: srv.ID, Hostname: srv.Hostname}
			err := normalizeServerInput(&srv)
			if err == nil {
				if prev, dup := seen[srv.ID]; dup {
					err = fmt.Errorf("duplicate id %s (also in row %d)", srv.ID, prev)
				}
			}
			var op string
			if err == nil {
				inv, op, srv, err = s.applyServerLocked(inv, srv)
			}
			res.ID = srv.ID
			if err != nil {
				res.Action, res.Error = "error", err.Error()
				failed = true
			} else {
				seen[srv.ID] = i + 1
				res.Action = op
				if op == "create" {
					created++
				} else {
					updated++
				}
			}
			results[i] = res
		}
		if dryRun || failed {
			return nil
		}
		s.state.Servers = inv
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVERS_IMPORTED", Category: "FLEET",
			EntityType: "server", EntityID: "bulk", EntityName: fmt.Sprintf("%d servers", len(rows)),
			Summary: fmt.Sprintf("Bulk import: %d created, %d updated", created, updated),
		})
		s.saveLocked()
		return nil
	})
	if err == nil && failed && !dryRun {
		err = errors.New("import rejected: fix the rows marked as error (nothing was changed)")
	}
	return results, err
}

func (s *Store) DeleteServer(id string, actor *auth.TokenClaims) error {
	if !auth.CanManageSystem(actor) {
		return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can manage servers")
	}
	return s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Servers, func(x models.Server) bool { return x.ID == id })
		if i == -1 {
			return errors.New("server not found")
		}
		srv := s.state.Servers[i]
		s.state.Servers = slices.Delete(s.state.Servers, i, i+1)
		var touched []string
		drop := func(ids []string) []string { return slices.DeleteFunc(ids, func(x string) bool { return x == id }) }
		for j := range s.state.PolicySets {
			set := &s.state.PolicySets[j]
			if slices.Contains(set.ServerIDs, id) {
				set.ServerIDs = drop(set.ServerIDs)
				touched = append(touched, set.Name)
			}
			if set.Draft != nil {
				set.Draft.Spec.ServerIDs = drop(set.Draft.Spec.ServerIDs)
			}
		}
		for j := range s.state.TLSBypass {
			s.state.TLSBypass[j].ServerIDs = drop(s.state.TLSBypass[j].ServerIDs)
		}
		summary := fmt.Sprintf("Removed server %s (%s); its proxy token is no longer valid", srv.Hostname, srv.IP)
		if len(touched) > 0 {
			summary += fmt.Sprintf("; removed from policy sets %v", touched)
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "SERVER_DECOMMISSIONED", Category: "FLEET",
			EntityType: "server", EntityID: srv.ID, EntityName: srv.Hostname, Summary: summary,
			ScopeGroups: srv.EffectiveGroupIDs,
		})
		s.saveLocked()
		return nil
	})
}

// SetQuarantine isolates a server (every request is blocked) or releases it. Team Leads may
// quarantine servers of their groups (incident response); only InfoSec can release.
func (s *Store) SetQuarantine(id string, quarantine bool, reason string, actor *auth.TokenClaims) (models.Server, error) {
	reason = strings.TrimSpace(reason)
	if err := checkText("reason", reason, 500, quarantine); err != nil {
		return models.Server{}, err
	}
	var out models.Server
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Servers, func(x models.Server) bool { return x.ID == id })
		if i == -1 {
			return errors.New("server not found")
		}
		srv := &s.state.Servers[i]
		switch {
		case actor.Role == models.RoleAuditorOperator:
			return errors.New("RBAC Policy: read-only role")
		case quarantine && !auth.CanManageSystem(actor) && !auth.CanApproveForGroups(actor, srv.EffectiveGroupIDs):
			return errors.New("RBAC Policy: you can only quarantine servers of your own groups")
		case !quarantine && !auth.CanManageSystem(actor):
			return errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can release a quarantine")
		}
		if srv.Quarantined == quarantine {
			out = cloneServer(*srv)
			return nil
		}
		now := time.Now().UTC()
		action := "SERVER_QUARANTINED"
		summary := fmt.Sprintf("Quarantined %s (%s): all egress blocked — %s", srv.Hostname, srv.IP, reason)
		if quarantine {
			srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = true, reason, actor.Username, &now
		} else {
			action = "SERVER_RELEASED"
			summary = fmt.Sprintf("Released %s (%s) from quarantine (was: %s) %s", srv.Hostname, srv.IP, srv.QuarantineReason, reason)
			srv.Quarantined, srv.QuarantineReason, srv.QuarantinedBy, srv.QuarantinedAt = false, "", "", nil
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: action, Category: "SECURITY",
			EntityType: "server", EntityID: srv.ID, EntityName: srv.Hostname, Summary: summary,
			ScopeGroups: srv.EffectiveGroupIDs,
		})
		s.saveLocked()
		out = cloneServer(*srv)
		return nil
	})
	if err == nil && quarantine && s.notifier != nil {
		s.notifier.NotifySecurityEvent(models.SecurityEvent{
			Timestamp: time.Now().UTC(), Type: "QUARANTINE", Severity: "high", Action: "blocked",
			ServerID: out.ID, ServerIP: out.IP, ServerHostname: out.Hostname, GroupIDs: out.EffectiveGroupIDs,
			Detail: fmt.Sprintf("Server quarantined by %s: %s", actor.Username, reason), Count: 1,
		})
	}
	return out, err
}

// RotateServerToken issues a new random proxy token. Only its SHA-256 digest is stored; the
// plaintext is returned exactly once.
func (s *Store) RotateServerToken(id string, actor *auth.TokenClaims) (models.Server, string, error) {
	if !auth.CanManageSystem(actor) {
		return models.Server{}, "", errors.New("RBAC Policy: only InfoSec Approvers and Super Admins can rotate proxy tokens")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return models.Server{}, "", err
	}
	token := "aegis_" + base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now().UTC()
	var out models.Server
	err := s.withWrite(func() error {
		i := slices.IndexFunc(s.state.Servers, func(x models.Server) bool { return x.ID == id })
		if i == -1 {
			return errors.New("server not found")
		}
		srv := &s.state.Servers[i]
		if srv.ProxyAuthUser == "" {
			srv.ProxyAuthUser = strings.TrimPrefix(srv.ID, "srv-")
			if !usernameRe.MatchString(srv.ProxyAuthUser) {
				srv.ProxyAuthUser = "svc-" + srv.ID
			}
			for _, other := range s.state.Servers {
				if other.ID != srv.ID && strings.EqualFold(other.ProxyAuthUser, srv.ProxyAuthUser) {
					srv.ProxyAuthUser = "svc-" + srv.ID
					break
				}
			}
		}
		srv.ProxyAuthTokenHash = engine.HashProxyToken(token)
		srv.ProxyAuthToken = ""
		srv.TokenRotatedAt = &now
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "PROXY_TOKEN_ROTATED", Category: "FLEET",
			EntityType: "server", EntityID: srv.ID, EntityName: srv.Hostname,
			Summary:     fmt.Sprintf("Rotated Proxy-Authorization token for %s (user %s); previous token revoked", srv.Hostname, srv.ProxyAuthUser),
			ScopeGroups: srv.EffectiveGroupIDs,
		})
		s.saveLocked()
		out = cloneServer(*srv)
		return nil
	})
	if err != nil {
		return models.Server{}, "", err
	}
	return out, token, nil
}

// ---------------------------------------------------------------------------
// Read models
// ---------------------------------------------------------------------------

// Servers returns the inventory with LastSeenAt refreshed from recorded traffic.
func (s *Store) Servers() []models.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lastSeen := map[string]time.Time{}
	for _, f := range s.state.Flows {
		if f.Timestamp.After(lastSeen[f.ServerID]) {
			lastSeen[f.ServerID] = f.Timestamp
		}
	}
	out := make([]models.Server, len(s.state.Servers))
	for i, srv := range s.state.Servers {
		srv = cloneServer(srv)
		if t := lastSeen[srv.ID]; t.After(srv.LastSeenAt) {
			srv.LastSeenAt = t
		}
		out[i] = srv
	}
	return out
}

// DiscoveredSources lists clients seen in the traffic window that are not registered servers.
func (s *Store) DiscoveredSources() []models.DiscoveredSource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type agg struct {
		src   models.DiscoveredSource
		hosts map[string]int
		uas   map[string]int
	}
	byIP := map[string]*agg{}
	for _, f := range s.state.Flows {
		if !strings.HasPrefix(f.ServerID, unregisteredPrefix) && !strings.HasPrefix(f.ServerID, autoPrefix) {
			continue
		}
		ip := strings.TrimPrefix(f.ServerIP, "::ffff:")
		if ip == "" {
			continue
		}
		a := byIP[ip]
		if a == nil {
			a = &agg{src: models.DiscoveredSource{IP: ip, FirstSeen: f.Timestamp, LastSeen: f.Timestamp, MatchedGroups: []string{}},
				hosts: map[string]int{}, uas: map[string]int{}}
			byIP[ip] = a
		}
		a.src.Requests++
		if !models.IsAllowedVerdict(f.Verdict) {
			a.src.Blocked++
		}
		if f.Timestamp.Before(a.src.FirstSeen) {
			a.src.FirstSeen = f.Timestamp
		}
		if f.Timestamp.After(a.src.LastSeen) {
			a.src.LastSeen = f.Timestamp
		}
		if f.Host != "" {
			a.hosts[f.Host]++
		}
		if f.UserAgent != "" {
			a.uas[clip(f.UserAgent, 80)]++
		}
		if u := strings.TrimSpace(f.ProxyAuthUser); u != "" && !strings.Contains(u, ":") && a.src.ProxyAuthUser == "" {
			a.src.ProxyAuthUser = clip(u, 64)
		}
		for _, g := range f.GroupIDs {
			if !slices.Contains(a.src.MatchedGroups, g) {
				a.src.MatchedGroups = append(a.src.MatchedGroups, g)
			}
		}
	}
	top := func(m map[string]int, n int) []string {
		keys := slices.Collect(maps.Keys(m))
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] || (m[keys[i]] == m[keys[j]] && keys[i] < keys[j]) })
		if len(keys) > n {
			keys = keys[:n]
		}
		return keys
	}
	out := make([]models.DiscoveredSource, 0, len(byIP))
	for ip, a := range byIP {
		a.src.TopHosts = top(a.hosts, 5)
		a.src.UserAgentHints = top(a.uas, 3)
		a.src.SuggestedID = "srv-" + strings.NewReplacer(".", "-", ":", "-").Replace(ip)
		if len(a.src.SuggestedID) > 64 {
			a.src.SuggestedID = a.src.SuggestedID[:64]
		}
		out = append(out, a.src)
	}
	slices.SortFunc(out, func(a, b models.DiscoveredSource) int { return b.LastSeen.Compare(a.LastSeen) })
	return out
}

// EffectivePolicy explains which policy sets, rules and exceptions apply to one server (API-safe:
// the server is returned without its proxy credential digest).
func (s *Store) EffectivePolicy(serverID string) (models.EffectivePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	srv, ok := s.serverByIDLocked(serverID)
	if !ok {
		return models.EffectivePolicy{}, errors.New("server not found")
	}
	groups := srv.EffectiveGroupIDs
	ep := models.EffectivePolicy{
		Server: cloneServer(srv).Public(), EffectiveGroupIDs: append([]string{}, groups...), DynamicGroupIDs: []string{},
		Quarantined: srv.Quarantined, PolicySets: []models.EffectivePolicySet{}, TLSBypass: []models.TLSBypassRule{},
		BlockPageTemplateID: s.templateForGroupsLocked(groups),
	}
	strict := map[string]bool{}
	for _, g := range s.state.Groups {
		if g.StrictIsolation {
			strict[g.ID] = true
			if slices.Contains(groups, g.ID) {
				ep.StrictIsolation = true
			}
		}
	}
	for _, g := range groups {
		if !slices.Contains(srv.GroupIDs, g) {
			ep.DynamicGroupIDs = append(ep.DynamicGroupIDs, g)
		}
	}
	sets := slices.Clone(s.state.PolicySets)
	slices.SortStableFunc(sets, func(a, b models.PolicySet) int { return cmp.Compare(b.Priority, a.Priority) })
	now := time.Now()
	for _, set := range sets {
		if !set.Enabled || set.Version == 0 {
			continue
		}
		var via []string
		if set.Kind == models.PolicySetKindBaseline {
			via = append(via, "baseline")
		} else {
			for _, g := range set.GroupIDs {
				if slices.Contains(groups, g) {
					via = append(via, "group:"+g)
				}
			}
			if slices.Contains(set.ServerIDs, srv.ID) {
				via = append(via, "server")
			}
		}
		if len(via) == 0 {
			continue
		}
		eps := models.EffectivePolicySet{ID: set.ID, Name: set.Name, Kind: set.Kind, Version: set.Version, Priority: set.Priority, Via: via, Rules: []models.PolicyRule{}}
		for _, r := range set.Rules {
			if !r.Enabled || (r.ExpiresAt != nil && now.After(*r.ExpiresAt)) {
				continue
			}
			r = cloneRule(r)
			if st, ok := s.state.RuleStats[r.ID]; ok {
				r.HitCount, r.TotalBytes = st.Hits, st.Bytes
			}
			eps.Rules = append(eps.Rules, r)
			if strings.EqualFold(r.Action, "BLOCK") {
				ep.BlockRules++
			} else {
				ep.AllowRules++
			}
		}
		ep.PolicySets = append(ep.PolicySets, eps)
	}
	for _, b := range s.state.TLSBypass {
		if b.Enabled && (b.ExpiresAt == nil || now.Before(*b.ExpiresAt)) && matchesTLSBypassScope(b, srv.ID, groups, strict) {
			ep.TLSBypass = append(ep.TLSBypass, b)
		}
	}
	ep.BlockedFileTypes = append([]string{}, s.state.SecurityPolicy.BlockedFileTypes...)
	for _, g := range groups {
		for _, ft := range s.state.SecurityPolicy.GroupBlockedFileTypes[g] {
			if !slices.Contains(ep.BlockedFileTypes, ft) {
				ep.BlockedFileTypes = append(ep.BlockedFileTypes, ft)
			}
		}
	}
	return ep, nil
}

// FindServer resolves a server by hostname (full or short name, case-insensitive) or IP address,
// as SIEM/SOAR incidents reference hosts rather than AegisProxy IDs.
func (s *Store) FindServer(hostname, ip string) (models.Server, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := strings.ToLower(strings.TrimSpace(hostname))
	short, _, _ := strings.Cut(h, ".")
	var byShort []models.Server
	for _, srv := range s.state.Servers {
		sh := strings.ToLower(srv.Hostname)
		if h != "" && sh == h {
			return cloneServer(srv), nil
		}
		if s2, _, _ := strings.Cut(sh, "."); short != "" && s2 == short {
			byShort = append(byShort, srv)
		}
	}
	if len(byShort) == 1 {
		return cloneServer(byShort[0]), nil
	}
	if len(byShort) > 1 {
		return models.Server{}, fmt.Errorf("hostname %q is ambiguous; use the FQDN or the IP address", hostname)
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		for _, srv := range s.state.Servers {
			if srv.IP == a.Unmap().String() {
				return cloneServer(srv), nil
			}
		}
	}
	return models.Server{}, errors.New("server not found")
}
