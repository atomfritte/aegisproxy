package registry

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// NPM speaks the npm registry protocol (registry.npmjs.org and compatible mirrors).
type NPM struct{}

func (NPM) Ecosystem() string { return models.EcosystemNPM }

// NormalizeName keeps the published form; npm names are case-sensitive and already canonical.
func (NPM) NormalizeName(name string) string { return pkgver.NormalizeName(models.EcosystemNPM, name) }

func (NPM) NormalizeVersion(v string) (string, error) {
	return pkgver.NormalizeVersion(models.EcosystemNPM, v)
}

// npmPackument is the registry document for GET /<name> (full or abbreviated install form).
type npmPackument struct {
	Name     string                   `json:"name"`
	DistTags map[string]string        `json:"dist-tags"`
	Versions map[string]npmVersionDoc `json:"versions"`
	Time     map[string]string        `json:"time"`
}

type npmVersionDoc struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              any               `json:"license"`
	Deprecated           any               `json:"deprecated"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
	GypFile              bool              `json:"gypfile"`
	Bin                  any               `json:"bin"`
	Engines              any               `json:"engines"`
	Repository           any               `json:"repository"`
	Dist                 npmDist           `json:"dist"`
}

type npmDist struct {
	Tarball      string         `json:"tarball"`
	Integrity    string         `json:"integrity"`
	Shasum       string         `json:"shasum"`
	UnpackedSize int64          `json:"unpackedSize"`
	FileCount    int            `json:"fileCount"`
	Signatures   []npmSignature `json:"signatures"`
	Attestations *npmAttest     `json:"attestations"`
}

type npmSignature struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid"`
}

type npmAttest struct {
	URL string `json:"url"`
}

func (n NPM) Package(ctx context.Context, c *Client, upstream, name string) (*PackageMeta, error) {
	var doc npmPackument
	// The abbreviated metadata document carries exactly the fields the firewall needs and is far
	// smaller than the full packument.
	if err := c.getJSON(ctx, upstream+"/"+escapeNPMName(name), "application/vnd.npm.install-v1+json", &doc); err != nil {
		return nil, err
	}
	meta := &PackageMeta{
		Ecosystem:   models.EcosystemNPM,
		Name:        n.NormalizeName(name),
		DisplayName: doc.Name,
		DistTags:    doc.DistTags,
		TimeByVer:   map[string]time.Time{},
		Deprecated:  map[string]string{},
	}
	for ver, vdoc := range doc.Versions {
		nv, err := n.NormalizeVersion(ver)
		if err != nil {
			continue
		}
		vm := n.versionMeta(name, nv, ver, vdoc)
		if t, ok := parseNPMTime(doc.Time, ver); ok {
			vm.PublishedAt = &t
			meta.TimeByVer[nv] = t
		}
		if dep, ok := deprecatedReason(vdoc.Deprecated); ok {
			vm.Deprecated = true
			meta.Deprecated[nv] = dep
		}
		meta.Versions = append(meta.Versions, vm)
	}
	sortVersionsDesc(models.EcosystemNPM, meta.Versions)
	return meta, nil
}

func (n NPM) Version(ctx context.Context, c *Client, upstream, name, version string) (*VersionMeta, error) {
	// npm has a per-version document, but it is not available on every mirror; the packument always is.
	meta, err := n.Package(ctx, c, upstream, name)
	if err != nil {
		return nil, err
	}
	want, err := n.NormalizeVersion(version)
	if err != nil {
		return nil, ErrVersionNotFound
	}
	for i := range meta.Versions {
		if meta.Versions[i].Version == want {
			return &meta.Versions[i], nil
		}
	}
	return nil, ErrVersionNotFound
}

func (n NPM) versionMeta(name, normVer, rawVer string, vdoc npmVersionDoc) VersionMeta {
	vm := VersionMeta{
		Ecosystem:   models.EcosystemNPM,
		Name:        n.NormalizeName(name),
		DisplayName: firstNonEmpty(vdoc.Name, name),
		Version:     normVer,
		RawVersion:  rawVer,
		License:     npmLicense(vdoc.License),
		Prerelease:  pkgver.IsPrerelease(models.EcosystemNPM, normVer),
	}
	if vdoc.Dist.Tarball != "" {
		vm.Files = []ArtifactRef{{
			Filename:  tarballName(vdoc.Dist.Tarball, vdoc.Name, rawVer),
			URL:       vdoc.Dist.Tarball,
			Kind:      "npm-tarball",
			Size:      vdoc.Dist.UnpackedSize,
			Integrity: vdoc.Dist.Integrity,
			SHA512:    sriToBase64(vdoc.Dist.Integrity),
		}}
		if vm.Files[0].SHA512 == "" && vdoc.Dist.Shasum != "" {
			vm.Files[0].SHA256 = "" // shasum is sha1, not recorded as a strong digest
		}
		for _, s := range vdoc.Dist.Signatures {
			vm.Signatures = append(vm.Signatures, SignatureRef{Kind: "npm-registry", KeyID: s.KeyID, Sig: s.Sig})
		}
		if vdoc.Dist.Attestations != nil {
			vm.Provenance = vdoc.Dist.Attestations.URL
		}
	}
	vm.Dependencies = append(vm.Dependencies, npmDeps(vdoc.Dependencies, "runtime")...)
	vm.Dependencies = append(vm.Dependencies, npmDeps(vdoc.OptionalDependencies, "optional")...)
	vm.Dependencies = append(vm.Dependencies, npmDeps(vdoc.PeerDependencies, "peer")...)
	vm.Dependencies = append(vm.Dependencies, npmDeps(vdoc.DevDependencies, "dev")...)
	vm.HasInstallScripts = hasLifecycleScript(vdoc.Scripts) || vdoc.GypFile
	vm.Raw = map[string]any{}
	if vdoc.Bin != nil {
		vm.Raw["bin"] = vdoc.Bin
	}
	if vdoc.Engines != nil {
		vm.Raw["engines"] = vdoc.Engines
	}
	if vdoc.Repository != nil {
		vm.Raw["repository"] = vdoc.Repository
	}
	if len(vdoc.Scripts) > 0 {
		vm.Raw["scripts"] = vdoc.Scripts
	}
	return vm
}

func npmDeps(m map[string]string, kind string) []Dependency {
	if len(m) == 0 {
		return nil
	}
	out := make([]Dependency, 0, len(m))
	for name, rng := range m {
		out = append(out, Dependency{Name: name, Range: rng, Kind: kind, Optional: kind == "optional" || kind == "peer"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var npmLifecycle = map[string]bool{
	"preinstall": true, "install": true, "postinstall": true,
	"preuninstall": true, "uninstall": true, "postuninstall": true,
	"prepare": true, "prepublish": true, "prepublishOnly": true, "prepack": true, "postpack": true,
}

func hasLifecycleScript(scripts map[string]string) bool {
	for name := range scripts {
		if npmLifecycle[name] {
			return true
		}
	}
	return false
}

// Classify recognizes npm registry metadata, tarball downloads and harmless service endpoints.
func (NPM) Classify(host, path, method string) Classification {
	if method != "" && method != "GET" && method != "HEAD" {
		return Classification{Kind: KindOther}
	}
	p := strings.TrimPrefix(path, "/")
	// Service endpoints: signing keys, attestations, audit, ping, login/whoami, search.
	switch {
	case p == "-/ping" || p == "-/whoami" || p == "-/v1/search" || strings.HasPrefix(p, "-/v1/search?"):
		return Classification{Kind: KindService}
	case strings.HasPrefix(p, "-/npm/v1/keys"), strings.HasPrefix(p, "-/npm/v1/attestations/"),
		strings.HasPrefix(p, "-/npm/v1/security/"), strings.HasPrefix(p, "-/user/"), p == "-/v1/login":
		return Classification{Kind: KindService}
	}
	// Tarball: /<name>/-/<file>.tgz (also scoped: /@scope/name/-/@scope/file.tgz).
	if i := strings.Index(p, "/-/"); i > 0 && strings.HasSuffix(p, ".tgz") {
		name := npmNameFromPath(p[:i])
		file := p[i+3:]
		if ver := tarballVersion(file, name); ver != "" {
			return Classification{Kind: KindArtifact, Name: name, Version: ver, File: pathBase(file)}
		}
		return Classification{Kind: KindArtifact, Name: name, File: pathBase(file)}
	}
	// Metadata: /<name> or /@scope%2fname or /@scope/name (optionally /<version> or /<dist-tag>).
	if name, ver := npmMetadataPath(p); name != "" {
		return Classification{Kind: KindMetadata, Name: name, Version: ver}
	}
	return Classification{Kind: KindOther}
}

func npmMetadataPath(p string) (name, version string) {
	if p == "" {
		return "", ""
	}
	dec, err := url.PathUnescape(p)
	if err == nil {
		p = dec
	}
	if strings.HasPrefix(p, "@") {
		// @scope/name or @scope/name/version
		parts := strings.SplitN(p, "/", 3)
		if len(parts) < 2 {
			return "", ""
		}
		name = parts[0] + "/" + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			version = normalizeOrEmpty(parts[2])
		}
		return name, version
	}
	parts := strings.SplitN(p, "/", 2)
	name = parts[0]
	if len(parts) == 2 && parts[1] != "" {
		version = normalizeOrEmpty(parts[1])
	}
	return name, version
}

func npmNameFromPath(p string) string {
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	return strings.TrimPrefix(p, "/")
}

func escapeNPMName(name string) string {
	// Scoped names are requested as @scope%2fname.
	if strings.HasPrefix(name, "@") {
		return strings.Replace(name, "/", "%2f", 1)
	}
	return name
}

// --- small helpers ---

func normalizeOrEmpty(v string) string {
	nv, err := pkgver.NormalizeVersion(models.EcosystemNPM, v)
	if err != nil {
		return ""
	}
	return nv
}

func tarballName(tarball, name, version string) string {
	if b := pathBase(tarball); b != "" {
		return b
	}
	short := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		short = name[i+1:]
	}
	return fmt.Sprintf("%s-%s.tgz", short, version)
}

func tarballVersion(file, name string) string {
	base := strings.TrimSuffix(pathBase(file), ".tgz")
	short := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		short = name[i+1:]
	}
	if rest, ok := strings.CutPrefix(base, short+"-"); ok {
		return normalizeOrEmpty(rest)
	}
	return ""
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func parseNPMTime(times map[string]string, ver string) (time.Time, bool) {
	if times == nil {
		return time.Time{}, false
	}
	if s, ok := times[ver]; ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func deprecatedReason(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		if t {
			return "", true
		}
	}
	return "", false
}

func npmLicense(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["type"].(string); ok {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sortVersionsDesc(ecosystem string, vs []VersionMeta) {
	sort.SliceStable(vs, func(i, j int) bool {
		return pkgver.Compare(ecosystem, vs[i].Version, vs[j].Version) > 0
	})
}
