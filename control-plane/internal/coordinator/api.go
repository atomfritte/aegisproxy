package coordinator

import (
	"context"
	"errors"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// CreateRequest opens a request and schedules its resolution and analysis. It returns immediately; the
// request progresses in the background (status resolving → analyzing → ready/approved).
func (c *Coordinator) CreateRequest(req models.PackageRequest) (models.PackageRequest, error) {
	created, err := c.store.CreatePackageRequest(req)
	if err != nil {
		return models.PackageRequest{}, err
	}
	c.Kick(created.ID)
	return created, nil
}

// Reanalyze re-runs resolution and analysis for a request (new advisories / rules / versions).
func (c *Coordinator) Reanalyze(id string) error {
	req, ok := c.store.PackageRequest(id)
	if !ok {
		return errors.New("request not found")
	}
	req.Status = models.PackageReqResolving
	req.Error = ""
	if err := c.store.SavePackageRequest(req); err != nil {
		return err
	}
	c.Kick(id)
	return nil
}

// Lookup returns a quick assessment preview for one version (the request wizard), without creating a
// request. It resolves the root version, assesses it and returns the direct dependency count.
func (c *Coordinator) Lookup(ctx context.Context, ecosystem, name, spec string) (*models.PackageNode, error) {
	version, err := c.svc.SelectVersion(ctx, ecosystem, name, spec)
	if err != nil || version == "" {
		return nil, errors.New("no matching version found for " + spec)
	}
	normName := registryNormalize(ecosystem, name)
	a := c.store.Assessment(ecosystem, normName, version)
	if a == nil {
		a, err = c.svc.Assess(ctx, ecosystem, normName, version)
		if err != nil {
			return nil, err
		}
		c.store.PutAssessment(*a)
	}
	node := &models.PackageNode{
		Key: ecosystem + ":" + normName + "@" + version, Ecosystem: ecosystem, Name: normName,
		Version: version, Root: true, Assessment: a, PublishedAt: a.PublishedAt,
		State: c.store.NodeState(ecosystem, normName, version, nil),
	}
	return node, nil
}

// maintenance runs the re-audit and watch loops at the configured intervals.
func (c *Coordinator) maintenance() {
	defer c.wg.Done()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	c.runMaintenance()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			c.runMaintenance()
		}
	}
}

func (c *Coordinator) runMaintenance() {
	settings := c.svc.Settings()
	now := time.Now().UTC()
	if settings.ReauditHours > 0 && now.Sub(c.lastReaudit) >= time.Duration(settings.ReauditHours)*time.Hour {
		c.lastReaudit = now
		c.reaudit(settings)
	}
	if settings.WatchHours > 0 && now.Sub(c.lastWatch) >= time.Duration(settings.WatchHours)*time.Hour {
		c.lastWatch = now
		c.watch(settings)
	}
}

// reaudit re-checks active approvals against the advisory sources and revokes those that a new
// advisory at or above revoke_on_severity (or any malware verdict) now affects.
func (c *Coordinator) reaudit(settings models.PackageSettings) {
	threshold := settings.RevokeOnSeverity
	if threshold == "" {
		return
	}
	ctx, cancel := c.ctx(10 * time.Minute)
	defer cancel()
	for _, ap := range c.store.PackageApprovals() {
		select {
		case <-c.closed:
			return
		default:
		}
		if ap.Status != "approved" {
			continue
		}
		a, err := c.svc.Assess(ctx, ap.Ecosystem, ap.Name, ap.Version)
		if err != nil {
			continue
		}
		c.store.PutAssessment(*a)
		if shouldRevoke(a, threshold) {
			reason := "re-audit: " + a.Summary
			if err := c.store.RevokePackageApproval(ap.ID, "system", "SYSTEM", reason); err == nil {
				c.log.Warn("revoked package approval after re-audit", "approval", ap.ID,
					"package", ap.Ecosystem+":"+ap.Name+"@"+ap.Version, "risk", a.Risk)
			}
		}
	}
}

func shouldRevoke(a *models.PackageAssessment, threshold string) bool {
	for _, adv := range a.Advisories {
		if adv.Withdrawn {
			continue
		}
		if adv.Malware {
			return true
		}
		if threshold != "malware" && models.RiskRank(adv.Severity) >= models.RiskRank(threshold) {
			return true
		}
	}
	return false
}

// watch looks for new upstream versions of packages that already have an approved version and opens an
// automatic request for each, so an "updates" rule can approve a release once it clears its cooldown.
func (c *Coordinator) watch(settings models.PackageSettings) {
	ctx, cancel := c.ctx(15 * time.Minute)
	defer cancel()
	seen := map[string]bool{}
	for _, ap := range c.store.PackageApprovals() {
		select {
		case <-c.closed:
			return
		default:
		}
		if ap.Status != "approved" {
			continue
		}
		key := ap.Ecosystem + ":" + ap.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		latest, err := c.svc.SelectVersion(ctx, ap.Ecosystem, ap.Name, "*")
		if err != nil || latest == "" {
			continue
		}
		if c.store.NodeState(ap.Ecosystem, ap.Name, latest, ap.GroupIDs) != "update" {
			continue // already approved/blocked, or not newer
		}
		req := models.PackageRequest{
			Ecosystem: ap.Ecosystem, Name: ap.Name, DisplayName: ap.DisplayName, Requested: latest, Version: latest,
			GroupIDs: ap.GroupIDs, Origin: "watch", RequestedBy: "system",
			Reason: "watch: new version of an approved package",
		}
		if created, err := c.store.CreatePackageRequest(req); err == nil {
			c.Kick(created.ID)
		}
	}
}
