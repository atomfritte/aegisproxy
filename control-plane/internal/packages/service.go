package packages

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/advisory"
	"aegisproxy/control-plane/internal/packages/registry"
)

// Verifier verifies registry signatures and Sigstore/PEP 740 provenance. It is implemented by an
// adapter over internal/packages/provenance; the Service depends on this narrow interface so the
// verification backend can evolve independently.
type Verifier interface {
	// VerifySignature checks a version's registry/publisher signature against the version metadata.
	VerifySignature(ctx context.Context, ecosystem string, vm *registry.VersionMeta) models.PackageVerification
	// VerifyProvenance verifies attestations / provenance for a version's primary artifact.
	VerifyProvenance(ctx context.Context, ecosystem string, vm *registry.VersionMeta) models.PackageVerification
}

// SettingsProvider exposes the live package-firewall settings to the Service (backed by the store).
type SettingsProvider func() models.PackageSettings

// Service is the control-plane core of the package firewall: registry access, resolution, assessment
// and the advisory/verification backends. It holds no state beyond its clients; configuration is read
// live through SettingsProvider so a settings change takes effect without a restart.
type Service struct {
	client   *registry.Client
	settings SettingsProvider
	verifier Verifier
	log      *slog.Logger

	mu      sync.RWMutex
	sources []advisory.Source
	// adapters overrides the registry adapters (tests inject in-memory ones); nil uses registry.All().
	adapters map[string]registry.Adapter
}

// adapter returns the registry adapter for an ecosystem (test override or the built-in).
func (s *Service) adapter(ecosystem string) registry.Adapter {
	if s.adapters != nil {
		if a, ok := s.adapters[ecosystem]; ok {
			return a
		}
	}
	return registry.For(ecosystem)
}

// SetAdapters overrides the registry adapters (test seam).
func (s *Service) SetAdapters(m map[string]registry.Adapter) { s.adapters = m }

// Options configures NewService.
type Options struct {
	HTTPProxy string
	Settings  SettingsProvider
	Verifier  Verifier
	Logger    *slog.Logger
	// Sources overrides the advisory sources (tests); nil uses the default set from the settings.
	Sources []advisory.Source
}

// NewService builds the package-firewall service.
func NewService(opts Options) *Service {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	c := registry.NewClient(opts.HTTPProxy)
	s := &Service{
		client:   c,
		settings: opts.Settings,
		verifier: opts.Verifier,
		log:      opts.Logger.With("component", "packages"),
		sources:  opts.Sources,
	}
	if s.sources == nil {
		s.sources = []advisory.Source{advisory.NewOSV(c.HTTPClient())}
	}
	return s
}

// Client exposes the registry client (sandbox worker job URLs, tests).
func (s *Service) Client() *registry.Client { return s.client }

// cfg returns the current settings (empty when no provider is set).
func (s *Service) cfg() models.PackageSettings {
	if s.settings == nil {
		return models.PackageSettings{}
	}
	return s.settings()
}

// upstream returns the configured upstream registry base URL for an ecosystem.
func (s *Service) upstream(ecosystem string) string {
	if es, ok := s.cfg().Ecosystems[ecosystem]; ok && es.Upstream != "" {
		return strings.TrimRight(es.Upstream, "/")
	}
	return registryDefaults[ecosystem]
}

var registryDefaults = map[string]string{
	models.EcosystemNPM:       "https://registry.npmjs.org",
	models.EcosystemPyPI:      "https://pypi.org",
	models.EcosystemNuGet:     "https://api.nuget.org",
	models.EcosystemPSGallery: "https://www.powershellgallery.com",
}

// enabledSources returns the advisory sources enabled in the settings that cover the ecosystem.
func (s *Service) enabledSources(ecosystem string) []advisory.Source {
	cfg := s.cfg()
	enabled := map[string]bool{}
	for _, a := range cfg.Audit {
		enabled[a.ID] = a.Enabled
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []advisory.Source
	for _, src := range s.sources {
		if enabled[src.ID()] && src.Supports(ecosystem) {
			out = append(out, src)
		}
	}
	return out
}

// Settings returns the current package-firewall settings.
func (s *Service) Settings() models.PackageSettings { return s.cfg() }

// SelectVersion picks the version a client resolver would choose for a spec (exact version or range),
// among the non-yanked published versions.
func (s *Service) SelectVersion(ctx context.Context, ecosystem, name, spec string) (string, error) {
	ad := s.adapter(ecosystem)
	if ad == nil {
		return "", fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	cache := map[string]*registry.PackageMeta{}
	return s.pickVersion(ctx, ad, s.upstream(ecosystem), ad.NormalizeName(name), spec, cache)
}

// ResolveConfig builds the resolver configuration from the current settings.
func (s *Service) ResolveConfig() ResolveConfig { return s.resolveConfig() }

// resolveConfig builds the resolver configuration from the settings.
func (s *Service) resolveConfig() ResolveConfig {
	cfg := s.cfg()
	rc := ResolveConfig{MaxGraph: cfg.MaxGraphSize, PythonEnvs: cfg.PythonEnvironments, NuGetFrameworks: cfg.NuGetFrameworks}
	if len(rc.PythonEnvs) == 0 {
		rc.PythonEnvs = nil
	}
	return rc
}
