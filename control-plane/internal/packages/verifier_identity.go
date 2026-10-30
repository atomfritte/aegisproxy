package packages

import (
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/provenance"
)

// applyNPMIdentity and applyPyPIIdentity copy the verified build identity (source repository, commit,
// workflow) out of a provenance result into the assessment's verification record.

func applyNPMIdentity(out *models.PackageVerification, res *provenance.NPMAttestations) {
	if res == nil || res.Provenance == nil || res.Provenance.Identity == nil {
		return
	}
	src := res.Provenance.Identity.Source()
	out.Identity = res.Provenance.Identity.SAN
	out.SourceRepo = src.Repository
	out.Commit = src.Commit
	out.Workflow = src.Workflow
}

func applyPyPIIdentity(out *models.PackageVerification, res *provenance.PyPIResult) {
	if res == nil || len(res.Attestations) == 0 {
		return
	}
	r := res.Attestations[0].Result
	if r == nil || r.Identity == nil {
		return
	}
	src := r.Identity.Source()
	out.Identity = r.Identity.SAN
	out.SourceRepo = src.Repository
	out.Commit = src.Commit
	out.Workflow = src.Workflow
}
