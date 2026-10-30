package provenance

// PyPIPublisher is the Trusted Publisher of a PEP 740 attestation bundle as PyPI reports it.
type PyPIPublisher struct {
	Kind                 string `json:"kind"`                             // GitHub, GitLab, Google, CircleCI
	Repository           string `json:"repository,omitempty"`             // GitHub, GitLab: owner/repo
	Workflow             string `json:"workflow,omitempty"`               // GitHub: workflow file name
	WorkflowFilepath     string `json:"workflow_filepath,omitempty"`      // GitLab: CI configuration path
	Environment          string `json:"environment,omitempty"`            // GitHub, GitLab (not in the certificate)
	Email                string `json:"email,omitempty"`                  // Google: service account
	ProjectID            string `json:"project_id,omitempty"`             // CircleCI
	PipelineDefinitionID string `json:"pipeline_definition_id,omitempty"` // CircleCI
	VCSOrigin            string `json:"vcs_origin,omitempty"`             // CircleCI
	VCSRef               string `json:"vcs_ref,omitempty"`                // CircleCI
}

// PyPIAttestation is one verified PEP 740 attestation and the publisher it was checked against.
type PyPIAttestation struct {
	Publisher PyPIPublisher `json:"publisher"`
	Result    *Result       `json:"result"`
}

// PyPIResult is the verified provenance of one distribution file.
type PyPIResult struct {
	Filename     string            `json:"filename"`
	SHA256       string            `json:"sha256"`
	Attestations []PyPIAttestation `json:"attestations"`
}

type pypiProvenance struct {
	Version            int `json:"version"`
	AttestationBundles []struct {
		Publisher    *PyPIPublisher `json:"publisher"`
		Attestations []struct {
			Version              int `json:"version"`
			VerificationMaterial struct {
				Certificate         b64         `json:"certificate"`
				TransparencyEntries []tlogEntry `json:"transparency_entries"`
			} `json:"verification_material"`
			Envelope struct {
				Statement b64 `json:"statement"`
				Signature b64 `json:"signature"`
			} `json:"envelope"`
		} `json:"attestations"`
	} `json:"attestation_bundles"`
}

// VerifyPyPIProvenance verifies a PEP 740 provenance document (GET https://pypi.org/integrity/<project>/<version>/
// <filename>/provenance) for one distribution file: every attestation must verify against the Sigstore trusted
// root, carry exactly one subject named filename with the sha256 digest, have a known predicate type and be signed
// by the identity of its bundle's Trusted Publisher (the policy of pypi-attestations, which PyPI applies on
// upload). Publisher mismatches wrap ErrIdentityMismatch.
func VerifyPyPIProvenance(provenance []byte, root *TrustedRoot, filename, sha256hex string) (*PyPIResult, error) {
	return Options{}.VerifyPyPIProvenance(provenance, root, filename, sha256hex)
}

// VerifyPyPIProvenance is VerifyPyPIProvenance with options.
func (o Options) VerifyPyPIProvenance(provenance []byte, root *TrustedRoot, filename, sha256hex string) (*PyPIResult, error) {
	var doc pypiProvenance
	if err := decodeJSON(provenance, &doc, "PyPI provenance"); err != nil {
		return nil, err
	}
	if doc.Version != 1 {
		return nil, failf(ErrUnsupported, "provenance version %d", doc.Version)
	}
	digest, err := Digest{Algorithm: "sha256", Value: sha256hex}.normalized()
	if err != nil {
		return nil, err
	}
	if filename == "" {
		return nil, failf(ErrMalformed, "filename is required")
	}
	n := 0
	for _, b := range doc.AttestationBundles {
		n += len(b.Attestations)
	}
	if n == 0 {
		return nil, failf(ErrNoAttestations, "%s", filename)
	}
	if n > MaxAttestations {
		return nil, failf(ErrLimit, "%d attestations", n)
	}
	res := &PyPIResult{Filename: filename, SHA256: digest.Value}
	for _, b := range doc.AttestationBundles {
		if b.Publisher == nil {
			return nil, failf(ErrMalformed, "attestation bundle without publisher")
		}
		for _, a := range b.Attestations {
			if a.Version != 1 {
				return nil, failf(ErrUnsupported, "attestation version %d", a.Version)
			}
			vm := a.VerificationMaterial
			if len(vm.Certificate) == 0 {
				return nil, failf(ErrMalformed, "attestation without certificate")
			}
			// A PEP 740 attestation is a v0.3 bundle in another shape: the statement is the DSSE payload.
			m := &material{
				minor: 3, leaf: vm.Certificate, entries: vm.TransparencyEntries,
				env: envelope{payloadType: InTotoPayloadType, payload: a.Envelope.Statement, sig: a.Envelope.Signature},
			}
			r, err := o.verify(m, root, expectation{subjectName: filename, digest: digest, oneSubject: true})
			if err != nil {
				return nil, err
			}
			if r.PredicateType != PredicatePyPIPublish && r.PredicateType != PredicateSLSAv1 {
				return nil, failf(ErrUnsupported, "attestation predicate type %.100q", r.PredicateType)
			}
			if err := checkPublisher(b.Publisher, r.Identity); err != nil {
				return nil, err
			}
			res.Attestations = append(res.Attestations, PyPIAttestation{Publisher: *b.Publisher, Result: r})
		}
	}
	return res, nil
}

// checkPublisher applies the Trusted Publisher policies of pypi-attestations to the certified identity.
func checkPublisher(p *PyPIPublisher, id *Identity) error {
	mismatch := func(what, got, want string) error {
		return failf(ErrIdentityMismatch, "%s publisher: certificate %s is %.200q, expected %.200q", p.Kind, what, got, want)
	}
	switch p.Kind {
	case "GitHub", "GitLab":
		host, issuer, sep, file := "https://github.com/", "https://token.actions.githubusercontent.com", "/.github/workflows/", p.Workflow
		if p.Kind == "GitLab" {
			host, issuer, sep, file = "https://gitlab.com/", "https://gitlab.com", "//", p.WorkflowFilepath
		}
		if p.Repository == "" || file == "" {
			return failf(ErrMalformed, "%s publisher without repository or workflow", p.Kind)
		}
		if id.issuerV2 != issuer {
			return mismatch("issuer", id.issuerV2, issuer)
		}
		if id.SourceRepositoryURI != host+p.Repository {
			return mismatch("source repository", id.SourceRepositoryURI, host+p.Repository)
		}
		// The Build Config URI is the top-level workflow (also when it calls a reusable workflow, which the SAN
		// would name): <host><repository><sep><workflow>@<commit or ref of the source repository>.
		want := host + p.Repository + sep + file + "@"
		for _, suffix := range []string{id.SourceRepositoryDigest, id.SourceRepositoryRef} {
			if suffix != "" && id.BuildConfigURI == want+suffix {
				return nil
			}
		}
		return mismatch("build config", id.BuildConfigURI, want+"<commit or ref>")
	case "Google":
		if p.Email == "" {
			return failf(ErrMalformed, "Google publisher without email")
		}
		if id.Issuer != "https://accounts.google.com" {
			return mismatch("issuer", id.Issuer, "https://accounts.google.com")
		}
		if id.SAN != p.Email {
			return mismatch("email", id.SAN, p.Email)
		}
		return nil
	case "CircleCI":
		if p.ProjectID == "" || p.PipelineDefinitionID == "" {
			return failf(ErrMalformed, "CircleCI publisher without project or pipeline definition")
		}
		if id.issuerV2 != "https://oidc.circleci.com" {
			return mismatch("issuer", id.issuerV2, "https://oidc.circleci.com")
		}
		if p.VCSOrigin != "" && id.SourceRepositoryURI != p.VCSOrigin {
			return mismatch("source repository", id.SourceRepositoryURI, p.VCSOrigin)
		}
		if p.VCSRef != "" && id.SourceRepositoryRef != p.VCSRef {
			return mismatch("source ref", id.SourceRepositoryRef, p.VCSRef)
		}
		want := "https://circleci.com/api/v2/projects/" + p.ProjectID + "/pipeline-definitions/" + p.PipelineDefinitionID
		if id.BuildSignerURI != want {
			return mismatch("build signer", id.BuildSignerURI, want)
		}
		return nil
	}
	return failf(ErrUnsupported, "publisher kind %.100q", p.Kind)
}
