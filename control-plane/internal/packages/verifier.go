package packages

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/provenance"
	"aegisproxy/control-plane/internal/packages/registry"
)

// RegistryVerifier implements Verifier using internal/packages/provenance. It fetches the npm signing
// keys, npm attestations and PyPI provenance documents through the SSRF-guarded registry client and
// verifies them against the embedded Sigstore public-good trusted root.
type RegistryVerifier struct {
	http *http.Client
	root *provenance.TrustedRoot
	log  *slog.Logger
}

const maxProvenanceBytes = 8 << 20

// NewRegistryVerifier builds the verifier. A failure to load the embedded trusted root disables
// provenance verification (reported as "unchecked" rather than failing closed).
func NewRegistryVerifier(proxy string, logger *slog.Logger) *RegistryVerifier {
	if logger == nil {
		logger = slog.Default()
	}
	root, err := provenance.PublicGoodTrustedRoot()
	if err != nil {
		logger.Error("package firewall: could not load the Sigstore trusted root; provenance stays unchecked", "error", err)
	}
	return &RegistryVerifier{http: registry.NewClient(proxy).HTTPClient(), root: root, log: logger.With("component", "packages-verifier")}
}

// VerifySignature verifies a registry/publisher signature (npm registry signatures today; the other
// ecosystems carry their signature inside the artifact and are checked by the sandbox).
func (v *RegistryVerifier) VerifySignature(ctx context.Context, ecosystem string, vm *registry.VersionMeta) models.PackageVerification {
	if ecosystem != models.EcosystemNPM {
		return models.PackageVerification{Status: "unchecked", Detail: "registry signature not applicable for this ecosystem"}
	}
	var sigs []provenance.NPMSignature
	for _, s := range vm.Signatures {
		if s.Kind == "npm-registry" {
			sigs = append(sigs, provenance.NPMSignature{KeyID: s.KeyID, Sig: s.Sig})
		}
	}
	if len(sigs) == 0 {
		return models.PackageVerification{Status: "unsigned"}
	}
	keys, err := v.npmKeys(ctx)
	if err != nil {
		return models.PackageVerification{Status: "unchecked", Detail: "could not fetch registry keys: " + err.Error()}
	}
	keyID, err := provenance.VerifyNPMRegistrySignature(keys, vm.DisplayName, vm.RawVersion, artifactIntegrity(vm), sigs, publishedTime(vm))
	if err != nil {
		return models.PackageVerification{Status: "failed", Kind: "npm-registry", Detail: err.Error()}
	}
	return models.PackageVerification{Status: "verified", Kind: "npm-registry", KeyID: keyID}
}

// VerifyProvenance verifies Sigstore attestations (npm) or PEP 740 provenance (PyPI).
func (v *RegistryVerifier) VerifyProvenance(ctx context.Context, ecosystem string, vm *registry.VersionMeta) models.PackageVerification {
	if v.root == nil {
		return models.PackageVerification{Status: "unchecked", Detail: "trusted root unavailable"}
	}
	switch ecosystem {
	case models.EcosystemNPM:
		if vm.Provenance == "" {
			return models.PackageVerification{Status: "unsigned"}
		}
		doc, err := v.get(ctx, vm.Provenance)
		if err != nil {
			return models.PackageVerification{Status: "unchecked", Detail: err.Error()}
		}
		keys, err := v.npmKeys(ctx)
		if err != nil {
			return models.PackageVerification{Status: "unchecked", Detail: err.Error()}
		}
		res, err := provenance.VerifyNPMAttestations(doc, keys, v.root, vm.DisplayName, vm.RawVersion, artifactIntegrity(vm))
		if err != nil {
			return models.PackageVerification{Status: "failed", Kind: "npm-attestation", Detail: err.Error()}
		}
		out := models.PackageVerification{Status: "verified", Kind: "npm-attestation"}
		applyNPMIdentity(&out, res)
		return out
	case models.EcosystemPyPI:
		file := primaryPyPIFile(vm)
		if file.Provenance == "" || file.SHA256 == "" {
			return models.PackageVerification{Status: "unsigned"}
		}
		doc, err := v.get(ctx, file.Provenance)
		if err != nil {
			return models.PackageVerification{Status: "unchecked", Detail: err.Error()}
		}
		res, err := provenance.VerifyPyPIProvenance(doc, v.root, file.Filename, file.SHA256)
		if err != nil {
			return models.PackageVerification{Status: "failed", Kind: "pypi-provenance", Detail: err.Error()}
		}
		out := models.PackageVerification{Status: "verified", Kind: "pypi-provenance"}
		applyPyPIIdentity(&out, res)
		return out
	default:
		return models.PackageVerification{Status: "unchecked"}
	}
}

func (v *RegistryVerifier) npmKeys(ctx context.Context) ([]provenance.NPMKey, error) {
	body, err := v.get(ctx, "https://registry.npmjs.org/-/npm/v1/keys")
	if err != nil {
		return nil, err
	}
	return provenance.ParseNPMKeys(body)
}

func (v *RegistryVerifier) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AegisProxy-Packages/3.0 (+provenance)")
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxProvenanceBytes))
}

func artifactIntegrity(vm *registry.VersionMeta) string {
	for _, f := range vm.Files {
		if f.Integrity != "" {
			return f.Integrity
		}
		if f.SHA512 != "" {
			return "sha512-" + f.SHA512
		}
	}
	return ""
}

func primaryPyPIFile(vm *registry.VersionMeta) registry.ArtifactRef {
	for _, f := range vm.Files {
		if f.Provenance != "" {
			return f
		}
	}
	if len(vm.Files) > 0 {
		return vm.Files[0]
	}
	return registry.ArtifactRef{}
}

func publishedTime(vm *registry.VersionMeta) time.Time {
	if vm.PublishedAt != nil {
		return *vm.PublishedAt
	}
	return time.Time{}
}
