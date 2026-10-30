package coordinator

import (
	"context"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages"
)

// process resolves, assesses and decides one request. It is idempotent and re-entrant: it is called
// again whenever a dependency's analysis completes, and it only advances the request.
func (c *Coordinator) process(reqID string) {
	req, ok := c.store.PackageRequest(reqID)
	if !ok || req.Status == models.PackageReqApproved || req.Status == models.PackageReqRejected {
		return
	}
	ctx, cancel := c.ctx(5 * time.Minute)
	defer cancel()

	// 1. Pick the concrete root version if a range was requested.
	if req.Version == "" {
		v, err := c.svc.SelectVersion(ctx, req.Ecosystem, req.Name, req.Requested)
		if err != nil || v == "" {
			c.fail(&req, "could not resolve a version for "+req.Requested)
			return
		}
		req.Version = v
	}

	// 2. Resolve the dependency graph.
	resolution, err := c.svc.Resolve(ctx, req.Ecosystem, req.Name, req.Version, c.svc.ResolveConfig())
	if err != nil {
		c.fail(&req, "resolution failed: "+err.Error())
		return
	}
	req.RootKey = resolution.RootKey

	// 3. Assess every node (reuse the cache) and queue sandbox analysis where needed.
	settings := c.svc.Settings()
	analysisPending := false
	for i := range resolution.Nodes {
		n := &resolution.Nodes[i]
		a := c.assessmentFor(ctx, n.Ecosystem, n.Name, n.Version)
		n.Assessment = a
		n.State = c.store.NodeState(n.Ecosystem, n.Name, n.Version, req.GroupIDs)
		if n.State == "approved" {
			if ap := c.store.ActiveApprovalID(n.Ecosystem, n.Name, n.Version, req.GroupIDs); ap != "" {
				n.AlreadyApprovedID = ap
			}
		}
		if c.needsSandbox(settings, a, n) {
			if c.enqueue(n) {
				analysisPending = true
			}
		}
	}
	req.Graph = resolution.Nodes
	req.Counts = countStates(resolution.Nodes)
	req.Risk = graphRisk(resolution.Nodes)

	// 4. If sandbox analysis is still running and policy requires it, wait for the results.
	if analysisPending && settings.Sandbox.Required {
		req.Status = models.PackageReqAnalyzing
		_ = c.store.SavePackageRequest(req)
		return
	}

	// 5. Apply the rules to decide automatically or hold for review.
	c.decide(&req, settings)
	_ = c.store.SavePackageRequest(req)
}

// decide applies the rules to the graph and either auto-approves, auto-rejects (block rule on the
// root) or marks the request ready for human review.
func (c *Coordinator) decide(req *models.PackageRequest, settings models.PackageSettings) {
	rules := c.store.PackageRules()
	now := time.Now().UTC()
	allAuto := true
	var rootRule packages.RuleDecision
	blockedNode := ""
	for i := range req.Graph {
		n := &req.Graph[i]
		if n.State == "blocked" || c.store.IsBlocked(n.Ecosystem, n.Name, n.Version) {
			blockedNode = n.Key
			allAuto = false
			continue
		}
		if n.State == "approved" {
			continue // already permitted for these groups
		}
		in := ruleInput(n, c.store.HasApprovedVersion(n.Ecosystem, n.Name))
		dec := packages.EvaluateRules(rules, settings, in, now)
		if n.Root {
			rootRule = dec
		}
		if dec.Action != models.PackageRuleAutoApprove {
			allAuto = false
		}
		if dec.Action == models.PackageRuleBlock {
			blockedNode = n.Key
		}
	}

	switch {
	case blockedNode != "" && rootRule.Action == models.PackageRuleBlock:
		// A block rule on the root auto-rejects.
		req.Status = models.PackageReqRejected
		req.Decision = "reject"
		req.AutoRuleID, req.AutoRuleName = rootRule.RuleID, rootRule.RuleName
		req.DecisionNote = rootRule.Reason
		req.DecidedBy, req.DecidedAt = "system", &now
		_ = c.store.FailOrReject(req.ID, "reject", rootRule.RuleName, rootRule.Reason)
	case allAuto && len(req.Graph) > 0:
		// Every node clears an auto-approve rule: approve the whole graph.
		req.AutoRuleID, req.AutoRuleName = rootRule.RuleID, rootRule.RuleName
		if _, err := c.store.ApproveRequestGraph(req.ID, "system", "SYSTEM", "auto-approved by rule "+rootRule.RuleName, nil); err != nil {
			c.log.Warn("auto-approval failed", "request", req.ID, "error", err)
			req.Status = models.PackageReqReady
		} else {
			req.Status = models.PackageReqApproved
			req.Decision = "approve"
			req.DecidedBy, req.DecidedAt = "system", &now
		}
	default:
		req.Status = models.PackageReqReady
	}
}

// assessmentFor returns a cached assessment or computes and caches a fresh one.
func (c *Coordinator) assessmentFor(ctx context.Context, eco, name, version string) *models.PackageAssessment {
	if a := c.store.Assessment(eco, name, version); a != nil {
		return a
	}
	a, err := c.svc.Assess(ctx, eco, name, version)
	if err != nil {
		c.log.Warn("assessment failed", "ecosystem", eco, "name", name, "version", version, "error", err)
		return &models.PackageAssessment{Ecosystem: eco, Name: name, Version: version, Risk: models.RiskUnknown,
			Summary: "assessment could not complete: " + err.Error(), Partial: true, UpdatedAt: time.Now().UTC()}
	}
	c.store.PutAssessment(*a)
	return a
}

// needsSandbox reports whether a node still needs a behavior analysis.
func (c *Coordinator) needsSandbox(settings models.PackageSettings, a *models.PackageAssessment, n *models.PackageNode) bool {
	if !settings.Sandbox.Enabled || len(n.Files) == 0 {
		return false
	}
	if a != nil && a.Sandbox != nil {
		return false // already analyzed
	}
	return true
}

// enqueue queues a sandbox job for a node's primary analyzable artifact. Returns true when a job is
// now queued or running for it.
func (c *Coordinator) enqueue(n *models.PackageNode) bool {
	f := primaryArtifact(n)
	if f.Filename == "" {
		return false
	}
	settings := c.svc.Settings()
	job := models.AnalysisJob{
		Ecosystem: n.Ecosystem, Name: n.DisplayName, Version: n.Version, Filename: f.Filename, URL: f.URL,
		SHA256: f.SHA256, SHA512: f.SHA512, Scenarios: settings.Sandbox.Scenarios,
	}
	if job.Name == "" {
		job.Name = n.Name
	}
	_, _, err := c.store.EnqueueAnalysis(job)
	if err != nil {
		c.log.Warn("could not queue analysis", "node", n.Key, "error", err)
		return false
	}
	return true
}

func (c *Coordinator) fail(req *models.PackageRequest, reason string) {
	req.Status = models.PackageReqFailed
	req.Error = reason
	_ = c.store.FailOrReject(req.ID, "fail", "", reason)
}
