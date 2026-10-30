package store

import (
	"errors"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
)

const (
	maxPackageRequests = 2000
	maxAssessments     = 20000
	maxAnalysisJobs    = 5000
)

func assessmentKey(ecosystem, name, version string) string {
	return ecosystem + ":" + name + "@" + version
}

// --- assessment cache ---

// Assessment returns the cached assessment of a version (nil when none).
func (s *Store) Assessment(ecosystem, name, version string) *models.PackageAssessment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.PackageWork.Assessments == nil {
		return nil
	}
	a, ok := s.state.PackageWork.Assessments[assessmentKey(ecosystem, name, version)]
	if !ok {
		return nil
	}
	cp := a
	return &cp
}

// PutAssessment stores or replaces an assessment. Returns without a revision bump via bumpPackageWorkLocked.
func (s *Store) PutAssessment(a models.PackageAssessment) {
	_ = s.withWrite(func() error {
		if s.state.PackageWork.Assessments == nil {
			s.state.PackageWork.Assessments = map[string]models.PackageAssessment{}
		}
		key := assessmentKey(a.Ecosystem, a.Name, a.Version)
		if _, existed := s.state.PackageWork.Assessments[key]; !existed && len(s.state.PackageWork.Assessments) >= maxAssessments {
			s.pruneAssessmentsLocked()
		}
		s.state.PackageWork.Assessments[key] = a
		s.bumpPackageWorkLocked()
		return nil
	})
}

// pruneAssessmentsLocked drops the oldest assessments that no active request or approval references.
func (s *Store) pruneAssessmentsLocked() {
	referenced := map[string]bool{}
	for _, r := range s.state.PackageWork.Requests {
		for _, n := range r.Graph {
			referenced[assessmentKey(n.Ecosystem, n.Name, n.Version)] = true
		}
	}
	// Keep the assessment of every still-approved version too: the re-audit loop diffs against it to
	// tell new advisories from pre-existing ones, so dropping it would make re-audit re-alert as if
	// every known finding were new.
	for _, a := range s.state.Packages.Approvals {
		if a.Status == "approved" {
			referenced[assessmentKey(a.Ecosystem, a.Name, a.Version)] = true
		}
	}
	type kv struct {
		key string
		at  time.Time
	}
	var all []kv
	for k, a := range s.state.PackageWork.Assessments {
		if referenced[k] {
			continue
		}
		all = append(all, kv{k, a.UpdatedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < len(all) && len(s.state.PackageWork.Assessments) >= maxAssessments; i++ {
		delete(s.state.PackageWork.Assessments, all[i].key)
	}
}

// --- requests ---

// PackageRequest returns one request by ID.
func (s *Store) PackageRequest(id string) (models.PackageRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.state.PackageWork.Requests {
		if r.ID == id {
			return r, true
		}
	}
	return models.PackageRequest{}, false
}

// PackageRequests returns requests filtered by status and ecosystem (both optional), newest first.
func (s *Store) PackageRequests(status, ecosystem string) []models.PackageRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.PackageRequest, 0, len(s.state.PackageWork.Requests))
	for _, r := range s.state.PackageWork.Requests {
		if status != "" && r.Status != status {
			continue
		}
		if ecosystem != "" && r.Ecosystem != ecosystem {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// CreatePackageRequest inserts a new request (status resolving) and returns it. The caller then drives
// resolution and analysis and calls SavePackageRequest with the result.
func (s *Store) CreatePackageRequest(r models.PackageRequest) (models.PackageRequest, error) {
	err := s.withWrite(func() error {
		if !models.ValidEcosystem(r.Ecosystem) {
			return errors.New("unknown ecosystem")
		}
		r.Name = normalizePackageName(r.Ecosystem, strings.TrimSpace(r.Name))
		if r.Name == "" {
			return errors.New("a package name is required")
		}
		r.ID = newRandomID("preq")
		now := time.Now().UTC()
		r.CreatedAt, r.UpdatedAt = now, now
		if r.Status == "" {
			r.Status = models.PackageReqResolving
		}
		if len(s.state.PackageWork.Requests) >= maxPackageRequests {
			s.pruneRequestsLocked()
		}
		s.state.PackageWork.Requests = append(s.state.PackageWork.Requests, r)
		s.bumpPackageWorkLocked()
		return nil
	})
	return r, err
}

// SavePackageRequest replaces a request in place (resolution/analysis progress, decisions).
func (s *Store) SavePackageRequest(r models.PackageRequest) error {
	return s.withWrite(func() error {
		for i := range s.state.PackageWork.Requests {
			if s.state.PackageWork.Requests[i].ID == r.ID {
				r.UpdatedAt = time.Now().UTC()
				s.state.PackageWork.Requests[i] = r
				s.bumpPackageWorkLocked()
				return nil
			}
		}
		return errors.New("request not found")
	})
}

// pruneRequestsLocked drops the oldest decided requests.
func (s *Store) pruneRequestsLocked() {
	reqs := s.state.PackageWork.Requests
	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].CreatedAt.Before(reqs[j].CreatedAt) })
	kept := reqs[:0]
	dropped := 0
	target := len(reqs) - maxPackageRequests + 1
	for _, r := range reqs {
		if dropped < target && decidedRequest(r.Status) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	s.state.PackageWork.Requests = kept
}

// FailOrReject sets a terminal request status with an audit entry (used by the coordinator for an
// automatic rejection or a resolution failure). kind is "reject" or "fail".
func (s *Store) FailOrReject(id, kind, ruleName, reason string) error {
	return s.withWrite(func() error {
		for i := range s.state.PackageWork.Requests {
			r := &s.state.PackageWork.Requests[i]
			if r.ID != id {
				continue
			}
			now := time.Now().UTC()
			if kind == "reject" {
				r.Status, r.Decision, r.DecidedBy, r.DecidedAt = models.PackageReqRejected, "reject", "system", &now
				r.AutoRuleName, r.DecisionNote = ruleName, reason
				s.appendAuditLocked(models.AuditEvent{
					Actor: "system", ActorRole: "SYSTEM", Action: "PACKAGE_REQUEST_REJECTED", Category: "SECURITY",
					EntityType: "package_request", EntityID: id, EntityName: r.Ecosystem + ":" + r.Name,
					Summary: "Auto-rejected: " + reason,
				})
			} else {
				r.Status, r.Error = models.PackageReqFailed, reason
			}
			s.bumpPackageWorkLocked()
			return nil
		}
		return errors.New("request not found")
	})
}

// --- node-state helpers for the coordinator ---

// NodeState classifies a version relative to the current approvals/blocks for a set of groups.
func (s *Store) NodeState(ecosystem, name, version string, groups []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.isBlockedIndexedLocked(ecosystem, name, version) {
		return "blocked"
	}
	if s.activeApprovalIndexedLocked(ecosystem, name, version, groups) != nil {
		return "approved"
	}
	if s.hasApprovedVersionIndexedLocked(ecosystem, name) {
		return "update"
	}
	return "new"
}

// ActiveApprovalID returns the ID of an active approval covering a version for the groups ("" = none).
func (s *Store) ActiveApprovalID(ecosystem, name, version string, groups []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a := s.activeApprovalIndexedLocked(ecosystem, name, version, groups); a != nil {
		return a.ID
	}
	return ""
}

// IsBlocked reports whether a version is on the block list.
func (s *Store) IsBlocked(ecosystem, name, version string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isBlockedIndexedLocked(ecosystem, name, version)
}

// HasApprovedVersion reports whether any version of a package is approved (any groups) — the "updates"
// rule trigger.
func (s *Store) HasApprovedVersion(ecosystem, name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasApprovedVersionIndexedLocked(ecosystem, name)
}

// The *IndexedLocked helpers use the approval/block lookup indexes (rebuilt in buildIndexLocked) instead
// of scanning every approval/block. They run only on the read path (NodeState and friends, under the
// read lock); the index is consistent with committed state because every approval/block mutation ends in
// saveLocked -> buildIndexLocked. The linear activeApprovalLocked/isBlockedLocked stay for the
// intra-mutation path (ApproveRequestGraph), which must see additions made within the same operation.
func (s *Store) activeApprovalIndexedLocked(ecosystem, name, version string, groups []string) *models.PackageApproval {
	now := time.Now().UTC()
	for _, i := range s.pkgApprovalIdx[ecosystem+"\x00"+name] {
		a := &s.state.Packages.Approvals[i]
		if a.Version != version || !a.Active(now) {
			continue
		}
		if groupsCovered(a.GroupIDs, groups) {
			return a
		}
	}
	return nil
}

func (s *Store) hasApprovedVersionIndexedLocked(ecosystem, name string) bool {
	now := time.Now().UTC()
	for _, i := range s.pkgApprovalIdx[ecosystem+"\x00"+name] {
		if s.state.Packages.Approvals[i].Active(now) {
			return true
		}
	}
	return false
}

func (s *Store) isBlockedIndexedLocked(ecosystem, name, version string) bool {
	for _, i := range s.pkgBlockIdx[ecosystem+"\x00"+normalizePackageName(ecosystem, name)] {
		if versionInBlock(ecosystem, version, s.state.Packages.Blocks[i].Versions) {
			return true
		}
	}
	return false
}

func decidedRequest(status string) bool {
	switch status {
	case models.PackageReqApproved, models.PackageReqRejected, models.PackageReqFailed:
		return true
	}
	return false
}
