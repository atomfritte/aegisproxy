package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

const PolicyBundleFormat = "aegisproxy.policy-sets/v1"

// ExportPolicySets returns the published content of the selected sets (all when ids is empty),
// without hit counters. Approvals sets are included for reference but skipped on import.
func (s *Store) ExportPolicySets(ids []string, actor *auth.TokenClaims) models.PolicySetBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	b := models.PolicySetBundle{Format: PolicyBundleFormat, ExportedAt: time.Now().UTC(), ExportedBy: actor.Username, PolicySets: []models.PolicySetDocument{}}
	for _, set := range s.state.PolicySets {
		if len(want) > 0 && !want[set.ID] {
			continue
		}
		spec := cloneSpec(set.PolicySetSpec)
		for i := range spec.Rules {
			spec.Rules[i].HitCount, spec.Rules[i].TotalBytes = 0, 0
		}
		b.PolicySets = append(b.PolicySets, models.PolicySetDocument{ID: set.ID, Kind: set.Kind, PolicySetSpec: spec})
	}
	return b
}

// planImportLocked validates one document against the current state without changing anything.
func (s *Store) planImportLocked(doc models.PolicySetDocument, actor *auth.TokenClaims) (models.PolicySetImportResult, int, models.PolicySetSpec) {
	res := models.PolicySetImportResult{ID: doc.ID, Name: doc.Name}
	if doc.Kind == "" {
		doc.Kind = models.PolicySetKindStandard
	}
	if doc.Kind == models.PolicySetKindApprovals {
		res.Action, res.Error = "skip", "approvals sets are managed by the access request workflow"
		return res, -1, doc.PolicySetSpec
	}
	if doc.Kind != models.PolicySetKindStandard && doc.Kind != models.PolicySetKindBaseline {
		res.Action, res.Error = "error", "kind must be standard or baseline"
		return res, -1, doc.PolicySetSpec
	}
	idx := -1
	if doc.ID != "" {
		idx = s.setIndexLocked(doc.ID)
	}
	if idx < 0 { // match by name (sets created on another installation)
		for i, set := range s.state.PolicySets {
			if strings.EqualFold(set.Name, strings.TrimSpace(doc.Name)) {
				idx = i
				break
			}
		}
	}
	spec := cloneSpec(doc.PolicySetSpec)
	if idx >= 0 {
		set := s.state.PolicySets[idx]
		res.ID = set.ID
		if set.Kind != doc.Kind {
			res.Action, res.Error = "error", fmt.Sprintf("existing set %q is %s, document says %s", set.Name, set.Kind, doc.Kind)
			return res, idx, spec
		}
		if set.Draft != nil && set.Draft.Status == "in_review" {
			res.Action, res.Error = "error", "the set has a draft in review"
			return res, idx, spec
		}
		if err := s.canManageSetLocked(actor, set.Kind, set.PolicySetSpec, spec); err != nil {
			res.Action, res.Error = "error", err.Error()
			return res, idx, spec
		}
		if err := s.validateSpecLocked(set.ID, set.Kind, &spec, actor); err != nil {
			res.Action, res.Error = "error", err.Error()
			return res, idx, spec
		}
		d := DiffSpecs(set.PolicySetSpec, spec)
		res.Diff = &d
		res.Action = "update"
		if d.Added+d.Removed+d.Modified == 0 && len(d.Metadata) == 0 {
			res.Action = "unchanged"
		}
		return res, idx, spec
	}
	if err := s.canManageSetLocked(actor, doc.Kind, spec); err != nil {
		res.Action, res.Error = "error", err.Error()
		return res, -1, spec
	}
	if err := s.validateSpecLocked("", doc.Kind, &spec, actor); err != nil {
		res.Action, res.Error = "error", err.Error()
		return res, -1, spec
	}
	d := DiffSpecs(models.PolicySetSpec{}, spec)
	res.Diff, res.Action = &d, "create"
	return res, -1, spec
}

// ImportPolicySets plans (dryRun) or applies a bundle. Changes always land in drafts — publishing
// follows the normal workflow (direct publish or change request). The import is all-or-nothing.
func (s *Store) ImportPolicySets(bundle models.PolicySetBundle, dryRun bool, actor *auth.TokenClaims) ([]models.PolicySetImportResult, error) {
	if bundle.Format != "" && bundle.Format != PolicyBundleFormat {
		return nil, fmt.Errorf("unsupported format %q (expected %s)", bundle.Format, PolicyBundleFormat)
	}
	if len(bundle.PolicySets) == 0 || len(bundle.PolicySets) > 200 {
		return nil, errors.New("the bundle must contain between 1 and 200 policy sets")
	}
	if actor.Role == models.RoleAuditorOperator {
		return nil, errors.New("RBAC Policy: read-only role")
	}
	results := make([]models.PolicySetImportResult, len(bundle.PolicySets))
	err := s.withWrite(func() error {
		failed := false
		type step struct {
			idx, result int
			doc         models.PolicySetDocument
			spec        models.PolicySetSpec
		}
		var steps []step
		for i, doc := range bundle.PolicySets {
			res, idx, spec := s.planImportLocked(doc, actor)
			results[i] = res
			if res.Action == "error" {
				failed = true
			}
			if res.Action == "create" || res.Action == "update" {
				steps = append(steps, step{idx: idx, result: i, doc: doc, spec: spec})
			}
		}
		if dryRun || failed || len(steps) == 0 {
			return nil // nothing changed: no audit entry, no revision
		}
		now := time.Now().UTC()
		for _, st := range steps {
			if st.idx < 0 {
				kind := st.doc.Kind
				if kind == "" {
					kind = models.PolicySetKindStandard
				}
				i, err := s.createSetLocked(kind, st.doc.PolicySetSpec, actor)
				if err != nil {
					return err
				}
				results[st.result].ID = s.state.PolicySets[i].ID
				continue
			}
			set := &s.state.PolicySets[st.idx]
			set.Draft = &models.PolicySetDraft{Spec: st.spec, BaseVersion: set.Version, Status: "editing", UpdatedBy: actor.Username, UpdatedAt: now}
		}
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "POLICY_SETS_IMPORTED", Category: "POLICY",
			EntityType: "policy_set", EntityID: "import", EntityName: fmt.Sprintf("%d sets", len(steps)),
			Summary: fmt.Sprintf("Imported %d policy sets as drafts (%s)", len(steps), bundle.Format),
		})
		s.markDirtyLocked()
		return nil
	})
	if err == nil && !dryRun {
		for _, r := range results {
			if r.Action == "error" {
				return results, errors.New("import rejected: fix the sets marked as error (nothing was changed)")
			}
		}
	}
	return results, err
}
