package coordinator

import (
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// registryNormalize applies an ecosystem's canonical name form.
func registryNormalize(ecosystem, name string) string {
	return pkgver.NormalizeName(ecosystem, name)
}

// primaryArtifact chooses the artifact to analyze for a node: the one with a digest, preferring a
// platform-neutral file (npm tarball, nupkg, module, pure-python wheel or sdist).
func primaryArtifact(n *models.PackageNode) models.PackageFilePin {
	var best models.PackageFilePin
	bestScore := -1
	for _, f := range n.Files {
		score := 0
		if f.SHA256 != "" || f.SHA512 != "" {
			score += 2
		}
		switch {
		case n.Ecosystem == models.EcosystemPyPI && hasSuffix(f.Filename, ".tar.gz"):
			score += 3 // sdist carries the build step we most want to observe
		case n.Ecosystem == models.EcosystemPyPI && hasSuffix(f.Filename, "-none-any.whl"):
			score += 2
		default:
			score++
		}
		if score > bestScore {
			best, bestScore = f, score
		}
	}
	return best
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// ruleInput builds the rule-engine input for a node.
func ruleInput(n *models.PackageNode, isUpdate bool) packages.RuleInput {
	in := packages.RuleInput{
		Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version, PublishedAt: n.PublishedAt,
		Deprecated: n.Deprecated, License: n.License, Assessment: n.Assessment, IsUpdate: isUpdate,
	}
	if n.Assessment != nil {
		in.HasInstall = n.Assessment.HasInstallScripts
		in.SignatureOK = n.Assessment.Signature.Status == "verified"
		in.ProvenanceOK = n.Assessment.Provenance.Status == "verified"
		in.SandboxDone = n.Assessment.Sandbox != nil && n.Assessment.Sandbox.Status == models.AnalysisCompleted
		in.Prerelease = n.Assessment.Risk != "" && false // prerelease is tracked on the version, set below
	}
	return in
}

// countStates summarizes node states for the request list view.
func countStates(nodes []models.PackageNode) map[string]int {
	m := map[string]int{}
	for _, n := range nodes {
		m[n.State]++
	}
	m["total"] = len(nodes)
	return m
}

// graphRisk is the highest node risk in the graph.
func graphRisk(nodes []models.PackageNode) string {
	risk := models.RiskNone
	for _, n := range nodes {
		if n.Assessment != nil && models.RiskRank(n.Assessment.Risk) > models.RiskRank(risk) {
			risk = n.Assessment.Risk
		}
	}
	return risk
}
