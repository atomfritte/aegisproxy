package store

import (
	"time"

	"aegisproxy/control-plane/internal/models"
)

// seedDemoPackagesLocked populates the package firewall (3.0) for the demo fleet: npm / PyPI / NuGet
// enforced, PowerShell Gallery in monitor, a handful of rules with a cooldown (Karenz), realistic
// approvals and blocks, and a couple of requests — one still in review with a resolved dependency graph
// and a sandbox report (the URLs, system calls and decoy-credential access a package made while
// installing and loading). It is showcase data only; no network or sandbox worker is involved.
func (s *Store) seedDemoPackagesLocked(now time.Time) {
	h := time.Hour
	day := 24 * h
	at := func(d time.Duration) time.Time { return now.Add(-d) }
	atp := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	pin := func(name, sha256, sha512 string, size int64) models.PackageFilePin {
		return models.PackageFilePin{Filename: name, SHA256: sha256, SHA512: sha512, Size: size}
	}

	fw := DefaultPackageFirewall()
	setMode := func(eco, mode string) {
		es := fw.Settings.Ecosystems[eco]
		es.Mode = mode
		fw.Settings.Ecosystems[eco] = es
	}
	setMode(models.EcosystemNPM, models.PackageModeEnforce)
	setMode(models.EcosystemPyPI, models.PackageModeEnforce)
	setMode(models.EcosystemNuGet, models.PackageModeEnforce)
	setMode(models.EcosystemPSGallery, models.PackageModeMonitor)
	fw.Settings.Sandbox.Required = true

	fw.Rules = []models.PackageRule{
		{
			ID: "pkr-internal", Name: "Auto-approve internal scopes", Enabled: true, Priority: 10,
			Description: "Packages published to our own npm scope are trusted and approved without review.",
			Ecosystems:  []string{models.EcosystemNPM}, Packages: []string{"@acme/*"}, GroupIDs: []string{"*"},
			Action: models.PackageRuleAutoApprove, Trigger: models.PackageTriggerAny,
			RequireSignature: true, MaxSeverity: models.RiskHigh, CreatedBy: "sophia.laurent", CreatedAt: at(40 * day), UpdatedAt: at(9 * day),
		},
		{
			ID: "pkr-updates", Name: "Patch & minor updates after a 72h cooldown", Enabled: true, Priority: 50,
			Description: "Updates to already-approved packages auto-approve once public for 72h and clear advisory, signature and sandbox checks.",
			Packages:    []string{"*"}, GroupIDs: []string{"*"}, Action: models.PackageRuleAutoApprove, Trigger: models.PackageTriggerUpdates,
			UpdateTypes: []string{"patch", "minor"}, MinAgeHours: 72, MaxSeverity: models.RiskMedium, MaxRisk: models.RiskMedium,
			RequireSignature: true, RequireSandbox: true, ExcludePrerelease: true, CreatedBy: "sophia.laurent", CreatedAt: at(40 * day), UpdatedAt: at(5 * day),
		},
		{
			ID: "pkr-major", Name: "Hold major updates for review", Enabled: true, Priority: 40,
			Description: "Major version bumps always go to a human, even for approved packages.",
			Packages:    []string{"*"}, GroupIDs: []string{"*"}, Action: models.PackageRuleReview, Trigger: models.PackageTriggerUpdates,
			UpdateTypes: []string{"major"}, CreatedBy: "marcus.webb", CreatedAt: at(30 * day), UpdatedAt: at(30 * day),
		},
	}

	fw.Approvals = []models.PackageApproval{
		{
			ID: "pka-lodash", Ecosystem: models.EcosystemNPM, Name: "lodash", DisplayName: "lodash", Version: "4.17.21",
			Files:    []models.PackageFilePin{pin("lodash-4.17.21.tgz", "679d0d35a7b0a3c9c76e2f3d3a0c0e2a1b6f2c8d4e5a6b7c8d9e0f1a2b3c4d5e", "mZ8o1b2c3d4e5f6A7B8C9D0e1F2g3H4i5J6k7L8m9N0o1P2q3R4s5T6u7V8w9X0y==", 1412336)},
			GroupIDs: []string{"*"}, Status: "approved", Via: "manual", ApprovedBy: "priya.nair", ApprovedAt: at(21 * day),
			Risk: models.RiskLow, PublishedAt: atp(900 * day), Reason: "Core utility, widely used; no open advisories.",
		},
		{
			ID: "pka-react", Ecosystem: models.EcosystemNPM, Name: "react", DisplayName: "react", Version: "18.3.1",
			Files:    []models.PackageFilePin{pin("react-18.3.1.tgz", "a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f7081", "Qw3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9z0X1c2V3b4N5m6Q7w8E9r0T1y2U3i==", 345210)},
			GroupIDs: []string{"*"}, Status: "approved", Via: "rule", RuleID: "pkr-updates", ApprovedBy: "system", ApprovedAt: at(4 * day),
			Risk: models.RiskNone, PublishedAt: atp(120 * day), Reason: "Auto-approved by rule after cooldown.",
		},
		{
			ID: "pka-acme-ui", Ecosystem: models.EcosystemNPM, Name: "@acme/ui", DisplayName: "@acme/ui", Version: "2.4.0",
			Files:    []models.PackageFilePin{pin("acme-ui-2.4.0.tgz", "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", "Zx1c2V3b4N5m6A7s8D9f0G1h2J3k4L5q6W7e8R9t0Y1u2I3o4P5a6S7d8F9g0H1==", 88214)},
			GroupIDs: []string{"grp-build", "grp-apps"}, Status: "approved", Via: "rule", RuleID: "pkr-internal", ApprovedBy: "system", ApprovedAt: at(6 * h),
			Risk: models.RiskNone, PublishedAt: atp(2 * day), RequiredBy: "@acme/portal@7.2.0",
		},
		{
			ID: "pka-requests", Ecosystem: models.EcosystemPyPI, Name: "requests", DisplayName: "requests", Version: "2.32.3",
			Files:    []models.PackageFilePin{pin("requests-2.32.3-py3-none-any.whl", "88c1a3f6e2b4d5078a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f7", "Pl0o9I8u7Y6t5R4e3W2q1A0s9D8f7G6h5J4k3L2z1X0c9V8b7N6m5Q4w3E2r1T0==", 64321)},
			GroupIDs: []string{"*"}, Status: "approved", Via: "manual", ApprovedBy: "priya.nair", ApprovedAt: at(14 * day),
			Risk: models.RiskMedium, PublishedAt: atp(200 * day), Reason: "Accepted a historical, patched advisory; monitored by re-audit.",
		},
		{
			ID: "pka-urllib3", Ecosystem: models.EcosystemPyPI, Name: "urllib3", DisplayName: "urllib3", Version: "2.2.3",
			Files:    []models.PackageFilePin{pin("urllib3-2.2.3-py3-none-any.whl", "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9", "Mn4b5V6c7X8z9L0k1J2h3G4f5D6s7A8q9W0e1R2t3Y4u5I6o7P8a9S0d1F2g3H4==", 126770)},
			GroupIDs: []string{"*"}, Status: "approved", Via: "dependency", RequiredBy: "requests@2.32.3", ApprovedBy: "priya.nair", ApprovedAt: at(14 * day),
			Risk: models.RiskLow, PublishedAt: atp(160 * day),
		},
		{
			ID: "pka-newtonsoft", Ecosystem: models.EcosystemNuGet, Name: "newtonsoft.json", DisplayName: "Newtonsoft.Json", Version: "13.0.3",
			Files:    []models.PackageFilePin{pin("newtonsoft.json.13.0.3.nupkg", "e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", "Bv5c6X7z8L9k0J1h2G3f4D5s6A7q8W9e0R1t2Y3u4I5o6P7a8S9d0F1g2H3j4K5==", 711123)},
			GroupIDs: []string{"*"}, Status: "approved", Via: "manual", ApprovedBy: "marcus.webb", ApprovedAt: at(33 * day),
			Risk: models.RiskNone, PublishedAt: atp(420 * day),
		},
		{
			ID: "pka-colors-revoked", Ecosystem: models.EcosystemNPM, Name: "colors", DisplayName: "colors", Version: "1.4.1",
			Files:    []models.PackageFilePin{pin("colors-1.4.1.tgz", "d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2", "Cx6v7B8n9M0q1W2e3R4t5Y6u7I8o9P0a1S2d3F4g5H6j7K8l9Z0x1C2v3B4n5M6==", 18233)},
			GroupIDs: []string{"*"}, Status: "revoked", Via: "manual", ApprovedBy: "priya.nair", ApprovedAt: at(60 * day),
			RevokedBy: "system", RevokedAt: atp(2 * day), RevokeReason: "re-audit: author published a sabotaged release; advisory GHSA-colors-2022.",
			Risk: models.RiskCritical, PublishedAt: atp(70 * day),
		},
	}

	fw.Blocks = []models.PackageBlock{
		{
			ID: "pkb-event-stream", Ecosystem: models.EcosystemNPM, Name: "event-stream", Versions: "3.3.6",
			Reason: "Known malicious release (flatmap-stream backdoor targeting crypto wallets).", Source: "advisory",
			CreatedBy: "marcus.webb", CreatedAt: at(28 * day),
		},
		{
			ID: "pkb-ctx", Ecosystem: models.EcosystemPyPI, Name: "ctx", Versions: "*",
			Reason: "Typosquat; sandbox observed environment-variable exfiltration to an external host.", Source: "sandbox",
			CreatedBy: "priya.nair", CreatedAt: at(9 * day),
		},
	}

	s.state.Packages = fw

	// A request still in review: fastify, with a resolved graph and a sandbox report that flagged
	// outbound telemetry and a decoy-credential read during install.
	fastifySandbox := &models.PackageSandboxResult{
		JobID: "job-demo-fastify", Status: "completed", Driver: "docker", StartedAt: at(2 * h), FinishedAt: at(2*h - 95*time.Second),
		URLs:     []string{"https://registry.npmjs.org/fastify/-/fastify-5.1.0.tgz", "https://telemetry.pkg-insights.net/collect?pkg=fastify&v=5.1.0"},
		Hosts:    []string{"registry.npmjs.org", "telemetry.pkg-insights.net"},
		DNSNames: []string{"registry.npmjs.org", "telemetry.pkg-insights.net"},
		SyscallCounts: map[string]int64{"openat": 1842, "read": 3310, "stat": 904, "connect": 4, "socket": 3, "execve": 2, "clone": 5, "write": 271},
		Processes:     []string{"/usr/local/bin/node /tmp/pkg/install.js", "sh -c node-gyp rebuild"},
		FilesWritten:  []string{"/tmp/pkg/node_modules/.package-lock.json", "/tmp/pkg/build/Release/fastify.node"},
		SecretsRead:   []string{"/root/.npmrc (decoy canary)"},
		CanaryHits:    1, ReportKey: "demo/fastify-5.1.0",
	}
	fastifyAssessment := &models.PackageAssessment{
		Ecosystem: models.EcosystemNPM, Name: "fastify", Version: "5.1.0", Risk: models.RiskHigh,
		Summary:           "Install script contacts an undeclared telemetry host and reads a decoy credential file.",
		Signature:         models.PackageVerification{Status: "verified", Kind: "npm-registry", KeyID: "SHA256:jl3nKQ…npm", Detail: "npm registry signature valid"},
		Provenance:        models.PackageVerification{Status: "verified", Kind: "sigstore", Identity: "https://github.com/fastify/fastify/.github/workflows/release.yml@refs/tags/v5.1.0", SourceRepo: "github.com/fastify/fastify", Workflow: "release.yml"},
		Sandbox:           fastifySandbox,
		HasInstallScripts: true, PublishedAt: atp(30 * h), Sources: []string{"osv", "npm", "depsdev"}, UpdatedAt: at(2 * h),
		Findings: []models.PackageFinding{
			{ID: "SBX-NET-EGRESS", Severity: models.RiskHigh, Category: "network", Title: "Outbound connection to an undeclared host during install", Detail: "Contacted telemetry.pkg-insights.net (not a declared registry/CDN host) while running the install script.", Source: "sandbox"},
			{ID: "SBX-CRED-ACCESS", Severity: models.RiskMedium, Category: "credential", Title: "Read a decoy credential file", Detail: "Opened the planted /root/.npmrc canary during the load phase.", Source: "sandbox"},
		},
	}
	node := func(name, ver string, root, direct bool, parent, rng, state string, a *models.PackageAssessment) models.PackageNode {
		n := models.PackageNode{
			Key: "npm:" + name + "@" + ver, Ecosystem: models.EcosystemNPM, Name: name, DisplayName: name, Version: ver,
			Root: root, Direct: direct, Kinds: []string{"runtime"}, State: state, Assessment: a,
		}
		if parent != "" || rng != "" {
			n.RequiredBy = []models.PackageEdge{{Parent: parent, Range: rng, Kind: "runtime"}}
		}
		return n
	}
	rootKey := "npm:fastify@5.1.0"
	fastify := models.PackageRequest{
		ID: "pkq-fastify", Ecosystem: models.EcosystemNPM, Name: "fastify", DisplayName: "fastify",
		Requested: "^5.1.0", Version: "5.1.0", GroupIDs: []string{"grp-apps"}, Status: models.PackageReqReady,
		Origin: "manual", RequestedBy: "daniel.osei", Reason: "New web framework for the payments API.",
		CreatedAt: at(3 * h), UpdatedAt: at(90 * time.Minute), RootKey: rootKey, Risk: models.RiskHigh,
		Counts: map[string]int{"new": 6}, Graph: []models.PackageNode{
			node("fastify", "5.1.0", true, false, "", "^5.1.0", "new", fastifyAssessment),
			node("@fastify/ajv-compiler", "4.0.1", false, true, rootKey, "^4.0.0", "new", nil),
			node("avvio", "9.1.0", false, true, rootKey, "^9.0.0", "new", nil),
			node("fast-json-stringify", "6.0.0", false, true, rootKey, "^6.0.0", "new", nil),
			node("find-my-way", "9.1.0", false, true, rootKey, "^9.0.0", "new", nil),
			node("pino", "9.5.0", false, true, rootKey, "^9.0.0", "new", nil),
		},
	}

	httpx := models.PackageRequest{
		ID: "pkq-httpx", Ecosystem: models.EcosystemPyPI, Name: "httpx", DisplayName: "httpx",
		Requested: "0.27.2", Version: "0.27.2", GroupIDs: []string{"*"}, Status: models.PackageReqApproved,
		Origin: "manual", RequestedBy: "daniel.osei", Reason: "Async HTTP client for the data pipeline.",
		CreatedAt: at(5 * day), UpdatedAt: at(5*day - 20*time.Minute), DecidedBy: "priya.nair", DecidedAt: atp(5*day - 25*time.Minute),
		Decision: "approve", RootKey: "pypi:httpx@0.27.2", Risk: models.RiskLow, Counts: map[string]int{"approved": 4},
	}

	leftpad := models.PackageRequest{
		ID: "pkq-leftpad", Ecosystem: models.EcosystemNPM, Name: "left-pad", DisplayName: "left-pad",
		Requested: "1.3.0", Version: "1.3.0", GroupIDs: []string{"grp-build"}, Status: models.PackageReqReady,
		Origin: "discovered", RequestedBy: "system", Reason: "A build server tried to download this unapproved package.",
		CreatedAt: at(50 * time.Minute), UpdatedAt: at(48 * time.Minute), RootKey: "npm:left-pad@1.3.0", Risk: models.RiskLow,
		Counts: map[string]int{"new": 1},
	}

	s.state.PackageWork = PackageWorkState{
		Requests: []models.PackageRequest{fastify, leftpad, httpx},
		Assessments: map[string]models.PackageAssessment{
			"npm:fastify@5.1.0": *fastifyAssessment,
		},
		Jobs: []models.AnalysisJob{
			{ID: "job-demo-fastify", Ecosystem: models.EcosystemNPM, Name: "fastify", Version: "5.1.0", Filename: "fastify-5.1.0.tgz",
				Scenarios: []string{"static", "install", "load"}, State: models.AnalysisCompleted, CreatedAt: at(2 * h), FinishedAt: atp(2*h - 95*time.Second), ReportKey: "demo/fastify-5.1.0"},
			{ID: "job-demo-leftpad", Ecosystem: models.EcosystemNPM, Name: "left-pad", Version: "1.3.0", Filename: "left-pad-1.3.0.tgz",
				Scenarios: []string{"static", "install", "load"}, State: models.AnalysisRunning, Worker: "sbx-worker-1", CreatedAt: at(45 * time.Minute), LeasedAt: atp(2 * time.Minute)},
		},
	}
}
