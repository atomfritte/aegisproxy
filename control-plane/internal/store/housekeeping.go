package store

import (
	"fmt"
	"slices"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

// systemActor performs scheduled maintenance (audited as "system").
var systemActor = &auth.TokenClaims{UserID: "system", Username: "system", Role: models.RoleSuperAdmin, AllowedGroups: []string{"*"}}

const housekeepingInterval = 15 * time.Minute

// Digest is the daily summary of open work.
type Digest struct {
	PendingRequests        int
	OverdueRequests        int
	OpenChangeRequests     int
	RecertificationOverdue int
	QuarantinedServers     int
	ExpiringAccess         int // approved requests expiring within 24 h
}

func (d Digest) empty() bool {
	return d.PendingRequests+d.OpenChangeRequests+d.RecertificationOverdue+d.QuarantinedServers+d.ExpiringAccess == 0
}

func (s *Store) housekeepingLoop() {
	defer s.persistWG.Done()
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.Housekeeping(time.Now())
			t.Reset(housekeepingInterval)
		}
	}
}

// Housekeeping prunes long-expired temporary access and sends the daily digest. Both steps are
// serialized through withWrite, so in a cluster only one replica performs them.
func (s *Store) Housekeeping(now time.Time) {
	if n, err := s.pruneExpiredApprovals(now); err != nil {
		s.log.Warn("pruning expired approvals failed", "error", err)
	} else if n > 0 {
		s.log.Info("pruned expired temporary access", "rules", n)
	}
	if d, send := s.claimDigest(now); send && s.notifier != nil {
		s.notifier.NotifyDigest(d.PendingRequests, d.OverdueRequests, d.OpenChangeRequests, d.RecertificationOverdue, d.QuarantinedServers, d.ExpiringAccess)
	}
}

func (s *Store) pruneExpiredApprovals(now time.Time) (int, error) {
	s.mu.RLock()
	days := s.state.Governance.PruneExpiredAfterDays
	s.mu.RUnlock()
	if days <= 0 {
		return 0, nil
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	expired := func(r models.PolicyRule) bool { return r.ExpiresAt != nil && r.ExpiresAt.Before(cutoff) }
	pruned := 0
	err := s.withWrite(func() error {
		for i := range s.state.PolicySets {
			set := &s.state.PolicySets[i]
			if set.Kind != models.PolicySetKindApprovals || !slices.ContainsFunc(set.Rules, expired) {
				continue
			}
			spec := cloneSpec(set.PolicySetSpec)
			before := len(spec.Rules)
			spec.Rules = slices.DeleteFunc(spec.Rules, expired)
			if err := s.validateSpecLocked(set.ID, set.Kind, &spec, systemActor); err != nil {
				return err
			}
			draft := set.Draft
			s.publishLocked(i, spec, systemActor, publishOpts{comment: "pruned expired temporary access", quiet: true})
			if draft != nil {
				draft.Spec.Rules = slices.DeleteFunc(draft.Spec.Rules, expired)
				draft.BaseVersion = s.state.PolicySets[i].Version
				s.state.PolicySets[i].Draft = draft
			}
			n := before - len(spec.Rules)
			pruned += n
			s.appendAuditLocked(models.AuditEvent{
				Actor: "system", ActorRole: "SYSTEM", Action: "APPROVALS_PRUNED", Category: "POLICY",
				EntityType: "policy_set", EntityID: set.ID, EntityName: set.Name, ScopeGroups: set.GroupIDs,
				Summary: fmt.Sprintf("Removed %d temporary access rules that expired more than %d days ago from %q (v%d)", n, days, set.Name, s.state.PolicySets[i].Version),
			})
		}
		return nil
	})
	return pruned, err
}

// claimDigest decides (cluster-wide, once per day after 08:00 server time) whether a digest is due.
func (s *Store) claimDigest(now time.Time) (Digest, bool) {
	var d Digest
	send := false
	_ = s.withWrite(func() error {
		g := &s.state.Governance
		if !g.DailyDigest || now.Hour() < 8 {
			return nil
		}
		if g.LastDigestAt != nil && now.Sub(*g.LastDigestAt) < 23*time.Hour {
			return nil
		}
		d = s.digestLocked(now)
		t := now.UTC()
		g.LastDigestAt = &t
		s.markDirtyLocked()
		send = !d.empty()
		return nil
	})
	return d, send
}

func (s *Store) digestLocked(now time.Time) Digest {
	var d Digest
	for _, r := range s.state.Requests {
		switch {
		case r.Status == "pending":
			d.PendingRequests++
			if r.DueAt != nil && now.After(*r.DueAt) {
				d.OverdueRequests++
			}
		case r.Status == "approved" && r.ExpiresAt != nil && r.ExpiresAt.After(now) && r.ExpiresAt.Before(now.Add(24*time.Hour)):
			d.ExpiringAccess++
		}
	}
	for _, cr := range s.state.ChangeRequests {
		if cr.Status == "open" {
			d.OpenChangeRequests++
		}
	}
	for _, set := range s.state.PolicySets {
		if s.decorateSetLocked(set).ReviewState == "overdue" {
			d.RecertificationOverdue++
		}
	}
	for _, srv := range s.state.Servers {
		if srv.Quarantined {
			d.QuarantinedServers++
		}
	}
	return d
}
