// Package registry holds the ecosystem adapters of the package firewall. An adapter speaks one
// registry's metadata protocol: it lists the versions of a package, returns the metadata of a
// version (dependencies, artifact files with their integrity data, publication time, license,
// deprecation and yank markers, publisher signatures), and classifies a URL as a metadata request,
// an artifact request or a harmless service endpoint.
//
// Adapters never store or re-host packages: Fetch pulls metadata only, and the digests of artifacts
// are carried through from the registry's own metadata so the data-plane and the sandbox can verify
// the bytes they see without the control-plane downloading them.
package registry

import (
	"context"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// Adapter is the per-ecosystem registry protocol.
type Adapter interface {
	// Ecosystem is the models.Ecosystem* identifier.
	Ecosystem() string
	// NormalizeName and NormalizeVersion apply the ecosystem's canonical forms.
	NormalizeName(name string) string
	NormalizeVersion(version string) (string, error)
	// Package returns every published version of a package (versions sorted newest first).
	Package(ctx context.Context, c *Client, upstream, name string) (*PackageMeta, error)
	// Version returns the metadata of one version (nil, ErrVersionNotFound when it does not exist).
	Version(ctx context.Context, c *Client, upstream, name, version string) (*VersionMeta, error)
	// Classify decides what a request to a registry host is about (metadata, artifact, service, other).
	Classify(host, path, method string) Classification
}

// PackageMeta is the registry's view of a package across all versions.
type PackageMeta struct {
	Ecosystem   string               `json:"ecosystem"`
	Name        string               `json:"name"` // normalized
	DisplayName string               `json:"display_name"`
	DistTags    map[string]string    `json:"dist_tags,omitempty"` // npm; e.g. latest, next
	Versions    []VersionMeta        `json:"versions"`            // newest first
	TimeByVer   map[string]time.Time `json:"-"`                   // publication time per version
	Deprecated  map[string]string    `json:"-"`                   // version -> reason ("" = deprecated, no reason)
	Yanked      map[string]string    `json:"-"`                   // PyPI / NuGet unlisted
}

// VersionMeta is the registry metadata of one version.
type VersionMeta struct {
	Ecosystem   string        `json:"ecosystem"`
	Name        string        `json:"name"`         // normalized
	DisplayName string        `json:"display_name"` // as published
	Version     string        `json:"version"`      // normalized
	RawVersion  string        `json:"raw_version"`  // as published
	PublishedAt *time.Time    `json:"published_at,omitempty"`
	License     string        `json:"license,omitempty"`
	Deprecated  bool          `json:"deprecated,omitempty"`
	Yanked      bool          `json:"yanked,omitempty"`
	YankReason  string        `json:"yank_reason,omitempty"`
	Prerelease  bool          `json:"prerelease,omitempty"`
	Files       []ArtifactRef `json:"files"`
	// Dependencies are the direct dependencies that matter for the configured resolution scenario.
	Dependencies []Dependency `json:"dependencies,omitempty"`
	// HasInstallScripts flags npm lifecycle scripts / build backends / MSBuild logic declared in the
	// metadata (a stronger signal comes from the sandbox).
	HasInstallScripts bool `json:"has_install_scripts,omitempty"`
	// Signatures are registry/publisher signatures named in the metadata (verified separately).
	Signatures []SignatureRef `json:"signatures,omitempty"`
	// Provenance points at an attestation/provenance document, when the registry advertises one.
	Provenance string `json:"provenance,omitempty"`
	// Raw keeps selected registry fields for the console (bin, engines, repository, authors …).
	Raw map[string]any `json:"raw,omitempty"`
}

// ArtifactRef is one downloadable file of a version with its integrity data.
type ArtifactRef struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Kind     string `json:"kind"` // npm-tarball | wheel | sdist | nupkg | module
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"` // hex
	SHA512   string `json:"sha512,omitempty"` // base64 (std)
	MD5      string `json:"md5,omitempty"`    // hex (PyPI legacy, weak: never trusted alone)
	// Integrity is the ecosystem's own integrity string (npm SRI "sha512-…", kept verbatim).
	Integrity string `json:"integrity,omitempty"`
	// Platform describes a wheel's / native tarball's target (python tags, abi, platform; TFM for NuGet).
	Platform string `json:"platform,omitempty"`
	// Provenance points at a PEP 740 provenance document for this file, when the registry advertises one.
	Provenance string `json:"provenance,omitempty"`
}

// Dependency is a direct dependency declared by a version.
type Dependency struct {
	Name  string `json:"name"` // normalized
	Range string `json:"range"`
	// Kind: runtime | dev | optional | peer | build | framework. The resolver includes the kinds
	// that the configured install/build scenario uses.
	Kind string `json:"kind"`
	// Target is the dependency group / target framework (NuGet) or marker environment (PyPI) the
	// dependency belongs to; "" = unconditional.
	Target string `json:"target,omitempty"`
	// Marker is the PEP 508 environment marker (PyPI), kept for display and re-evaluation.
	Marker string `json:"marker,omitempty"`
	// Optional dependencies may be absent without failing the resolution.
	Optional bool `json:"optional,omitempty"`
}

// SignatureRef names a signature carried in the metadata.
type SignatureRef struct {
	Kind  string `json:"kind"` // npm-registry | npm-attestation | nuget-repository | nuget-author | psgallery
	KeyID string `json:"key_id,omitempty"`
	Sig   string `json:"sig,omitempty"`
}

// Classification is the result of Adapter.Classify.
type Classification struct {
	Kind    string // metadata | artifact | service | other
	Name    string // normalized package name (metadata, artifact)
	Version string // normalized version (artifact)
	File    string // artifact filename
}

const (
	KindMetadata = "metadata"
	KindArtifact = "artifact"
	KindService  = "service"
	KindOther    = "other"
)

// All returns the adapters for every supported ecosystem.
func All() map[string]Adapter {
	return map[string]Adapter{
		models.EcosystemNPM:       NPM{},
		models.EcosystemPyPI:      PyPI{},
		models.EcosystemNuGet:     NuGet{},
		models.EcosystemPSGallery: PSGallery{},
	}
}

// For returns the adapter for an ecosystem (nil when unsupported).
func For(ecosystem string) Adapter { return All()[ecosystem] }
