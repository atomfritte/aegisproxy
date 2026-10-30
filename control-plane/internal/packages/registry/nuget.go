package registry

import (
	"context"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// NuGet speaks the NuGet V3 protocol (api.nuget.org and compatible feeds).
type NuGet struct{}

func (NuGet) Ecosystem() string { return models.EcosystemNuGet }

func (NuGet) NormalizeName(name string) string {
	return pkgver.NormalizeName(models.EcosystemNuGet, name)
}

func (NuGet) NormalizeVersion(v string) (string, error) {
	return pkgver.NormalizeVersion(models.EcosystemNuGet, v)
}

// nugetRegistration is the registration index (registration5-gz-semver2/<id>/index.json).
type nugetRegistration struct {
	Count int                     `json:"count"`
	Items []nugetRegistrationPage `json:"items"`
}

type nugetRegistrationPage struct {
	ID    string                  `json:"@id"`
	Count int                     `json:"count"`
	Lower string                  `json:"lower"`
	Upper string                  `json:"upper"`
	Items []nugetRegistrationLeaf `json:"items"` // inline on small packages; else fetched per page
}

type nugetRegistrationLeaf struct {
	CatalogEntry   nugetCatalogEntry `json:"catalogEntry"`
	PackageContent string            `json:"packageContent"`
}

type nugetCatalogEntry struct {
	ID                string                 `json:"id"`
	Version           string                 `json:"version"`
	Listed            *bool                  `json:"listed"`
	Published         string                 `json:"published"`
	LicenseExpression string                 `json:"licenseExpression"`
	LicenseURL        string                 `json:"licenseUrl"`
	Deprecation       *nugetDeprecation      `json:"deprecation"`
	Vulnerabilities   []any                  `json:"vulnerabilities"`
	DependencyGroups  []nugetDependencyGroup `json:"dependencyGroups"`
	PackageContent    string                 `json:"packageContent"`
}

type nugetDeprecation struct {
	Reasons []string `json:"reasons"`
	Message string   `json:"message"`
}

type nugetDependencyGroup struct {
	TargetFramework string            `json:"targetFramework"`
	Dependencies    []nugetDependency `json:"dependencies"`
}

type nugetDependency struct {
	ID    string `json:"id"`
	Range string `json:"range"`
}

func (n NuGet) Package(ctx context.Context, c *Client, upstream, name string) (*PackageMeta, error) {
	id := n.NormalizeName(name)
	var reg nugetRegistration
	if err := c.getJSON(ctx, upstream+"/v3/registration5-gz-semver2/"+id+"/index.json", "application/json", &reg); err != nil {
		return nil, err
	}
	meta := &PackageMeta{
		Ecosystem: models.EcosystemNuGet, Name: id, DisplayName: name,
		TimeByVer: map[string]time.Time{}, Deprecated: map[string]string{}, Yanked: map[string]string{},
	}
	for _, page := range reg.Items {
		leaves := page.Items
		if len(leaves) == 0 && page.ID != "" {
			// A paged registration: the leaves live behind the page @id.
			var pg nugetRegistrationPage
			if err := c.getJSON(ctx, page.ID, "application/json", &pg); err != nil {
				return nil, err
			}
			leaves = pg.Items
		}
		for _, leaf := range leaves {
			vm, ok := n.versionMeta(upstream, leaf)
			if !ok {
				continue
			}
			if vm.PublishedAt != nil {
				meta.TimeByVer[vm.Version] = *vm.PublishedAt
			}
			if vm.Deprecated {
				meta.Deprecated[vm.Version] = vm.YankReason
			}
			if vm.Yanked {
				meta.Yanked[vm.Version] = ""
			}
			meta.Versions = append(meta.Versions, vm)
		}
	}
	sortVersionsDesc(models.EcosystemNuGet, meta.Versions)
	return meta, nil
}

func (n NuGet) versionMeta(upstream string, leaf nugetRegistrationLeaf) (VersionMeta, bool) {
	e := leaf.CatalogEntry
	nv, err := n.NormalizeVersion(e.Version)
	if err != nil {
		return VersionMeta{}, false
	}
	id := n.NormalizeName(e.ID)
	content := firstNonEmpty(leaf.PackageContent, e.PackageContent)
	if content == "" {
		content = upstream + "/v3-flatcontainer/" + id + "/" + nv + "/" + id + "." + nv + ".nupkg"
	}
	vm := VersionMeta{
		Ecosystem: models.EcosystemNuGet, Name: id, DisplayName: e.ID,
		Version: nv, RawVersion: e.Version, License: firstNonEmpty(e.LicenseExpression, e.LicenseURL),
		Prerelease: pkgver.IsPrerelease(models.EcosystemNuGet, nv),
		Files: []ArtifactRef{{
			Filename: id + "." + nv + ".nupkg", URL: content, Kind: "nupkg",
		}},
	}
	if e.Listed != nil && !*e.Listed {
		vm.Yanked = true // unlisted
	}
	if e.Deprecation != nil {
		vm.Deprecated = true
		vm.YankReason = firstNonEmpty(e.Deprecation.Message, strings.Join(e.Deprecation.Reasons, ", "))
	}
	if t, err := time.Parse(time.RFC3339, e.Published); err == nil {
		// NuGet publishes unlisted packages with the sentinel year 1900.
		if t.Year() > 1901 {
			tt := t.UTC()
			vm.PublishedAt = &tt
		} else {
			vm.Yanked = true
		}
	}
	for _, g := range e.DependencyGroups {
		tfm := g.TargetFramework
		for _, d := range g.Dependencies {
			vm.Dependencies = append(vm.Dependencies, Dependency{
				Name: n.NormalizeName(d.ID), Range: d.Range, Kind: "framework", Target: tfm,
			})
		}
	}
	// NuGet packages can carry MSBuild logic; the sandbox confirms it. The metadata does not flag it,
	// so HasInstallScripts stays false here and is set from the sandbox report.
	return vm, true
}

func (n NuGet) Version(ctx context.Context, c *Client, upstream, name, version string) (*VersionMeta, error) {
	nv, err := n.NormalizeVersion(version)
	if err != nil {
		return nil, ErrVersionNotFound
	}
	meta, err := n.Package(ctx, c, upstream, name)
	if err != nil {
		return nil, err
	}
	for i := range meta.Versions {
		if meta.Versions[i].Version == nv {
			return &meta.Versions[i], nil
		}
	}
	return nil, ErrVersionNotFound
}

// Classify recognizes the flat container (metadata index + nupkg), the registration API and the
// service index / search / vulnerability endpoints.
func (NuGet) Classify(host, path, method string) Classification {
	if method != "" && method != "GET" && method != "HEAD" {
		return Classification{Kind: KindOther}
	}
	p := strings.TrimPrefix(path, "/")
	switch {
	case p == "v3/index.json", strings.HasPrefix(p, "v3/vulnerabilities/"),
		strings.HasPrefix(p, "v3-index/"), strings.HasPrefix(p, "query"), strings.Contains(p, "autocomplete"),
		strings.HasPrefix(p, "v3/catalog0/"):
		return Classification{Kind: KindService}
	case strings.HasPrefix(p, "v3-flatcontainer/"):
		rest := strings.TrimPrefix(p, "v3-flatcontainer/")
		seg := strings.Split(rest, "/")
		id := NuGet{}.NormalizeName(seg[0])
		if len(seg) == 2 && seg[1] == "index.json" {
			return Classification{Kind: KindMetadata, Name: id}
		}
		if len(seg) == 3 && strings.HasSuffix(seg[2], ".nupkg") {
			return Classification{Kind: KindArtifact, Name: id, Version: normalizeNuGetOrEmpty(seg[1]), File: seg[2]}
		}
		if len(seg) == 3 && (seg[2] == "readme" || strings.HasSuffix(seg[2], ".nuspec") || seg[2] == "icon") {
			return Classification{Kind: KindService}
		}
		return Classification{Kind: KindMetadata, Name: id}
	case strings.Contains(p, "registration"):
		// registration5-*/<id>/index.json or /<id>/<version>.json
		i := strings.Index(p, "/")
		rest := p
		if i >= 0 {
			rest = p[i+1:]
		}
		seg := strings.Split(rest, "/")
		if len(seg) >= 2 {
			id := NuGet{}.NormalizeName(seg[len(seg)-2])
			last := seg[len(seg)-1]
			if last == "index.json" {
				return Classification{Kind: KindMetadata, Name: id}
			}
			if strings.HasSuffix(last, ".json") {
				return Classification{Kind: KindMetadata, Name: id, Version: normalizeNuGetOrEmpty(strings.TrimSuffix(last, ".json"))}
			}
		}
		return Classification{Kind: KindService}
	}
	return Classification{Kind: KindOther}
}

func normalizeNuGetOrEmpty(v string) string {
	nv, err := pkgver.NormalizeVersion(models.EcosystemNuGet, v)
	if err != nil {
		return ""
	}
	return nv
}
