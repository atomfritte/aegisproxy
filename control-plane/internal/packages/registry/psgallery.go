package registry

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// PSGallery speaks the PowerShell Gallery OData v2 protocol (NuGet versions, module semantics).
type PSGallery struct{}

func (PSGallery) Ecosystem() string { return models.EcosystemPSGallery }

func (PSGallery) NormalizeName(name string) string {
	return pkgver.NormalizeName(models.EcosystemPSGallery, name)
}

func (PSGallery) NormalizeVersion(v string) (string, error) {
	return pkgver.NormalizeVersion(models.EcosystemPSGallery, v)
}

// odataFeed is the Atom feed returned by FindPackagesById() and Packages().
type odataFeed struct {
	Entries []odataEntry `xml:"entry"`
	// A paged feed carries a <link rel="next" href="…">.
	Links []odataLink `xml:"link"`
}

type odataLink struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
}

type odataEntry struct {
	Title   string       `xml:"title"`
	Content odataContent `xml:"content"`
	Props   odataProps   `xml:"properties"`
}

type odataContent struct {
	Src  string `xml:"src,attr"`
	Type string `xml:"type,attr"`
}

type odataProps struct {
	ID                string `xml:"Id"`
	Version           string `xml:"Version"`
	NormalizedVersion string `xml:"NormalizedVersion"`
	Authors           string `xml:"Authors"`
	Description       string `xml:"Description"`
	Published         string `xml:"Published"`
	Created           string `xml:"Created"`
	Dependencies      string `xml:"Dependencies"`
	PackageHash       string `xml:"PackageHash"`
	PackageHashAlgo   string `xml:"PackageHashAlgorithm"`
	PackageSize       int64  `xml:"PackageSize"`
	IsPrerelease      string `xml:"IsPrerelease"`
	Listed            string `xml:"Listed"`
	LicenseURL        string `xml:"LicenseUrl"`
	ProjectURL        string `xml:"ProjectUrl"`
	ItemType          string `xml:"ItemType"`
	CompanyName       string `xml:"CompanyName"`
}

func (p PSGallery) Package(ctx context.Context, c *Client, upstream, name string) (*PackageMeta, error) {
	meta := &PackageMeta{
		Ecosystem: models.EcosystemPSGallery, Name: p.NormalizeName(name), DisplayName: name,
		TimeByVer: map[string]time.Time{}, Yanked: map[string]string{},
	}
	seen := map[string]bool{}
	url := upstream + "/api/v2/FindPackagesById()?id='" + odataQuote(name) + "'"
	for hops := 0; url != "" && hops < 40; hops++ {
		body, _, err := c.get(ctx, url, "application/atom+xml")
		if err != nil {
			return nil, err
		}
		var feed odataFeed
		if err := xml.Unmarshal(body, &feed); err != nil {
			return nil, err
		}
		for _, e := range feed.Entries {
			vm, ok := p.versionMeta(upstream, name, e)
			if !ok || seen[vm.Version] {
				continue
			}
			seen[vm.Version] = true
			if vm.PublishedAt != nil {
				meta.TimeByVer[vm.Version] = *vm.PublishedAt
			}
			if meta.DisplayName == name && e.Props.ID != "" {
				meta.DisplayName = e.Props.ID
			}
			meta.Versions = append(meta.Versions, vm)
		}
		url = nextLink(feed.Links)
	}
	if len(meta.Versions) == 0 {
		return nil, ErrPackageNotFound
	}
	sortVersionsDesc(models.EcosystemPSGallery, meta.Versions)
	return meta, nil
}

func (p PSGallery) versionMeta(upstream, name string, e odataEntry) (VersionMeta, bool) {
	raw := firstNonEmpty(e.Props.NormalizedVersion, e.Props.Version)
	nv, err := p.NormalizeVersion(raw)
	if err != nil {
		return VersionMeta{}, false
	}
	id := p.NormalizeName(firstNonEmpty(e.Props.ID, name))
	content := e.Content.Src
	if content == "" {
		content = upstream + "/api/v2/package/" + e.Props.ID + "/" + raw
	}
	vm := VersionMeta{
		Ecosystem: models.EcosystemPSGallery, Name: id, DisplayName: firstNonEmpty(e.Props.ID, name),
		Version: nv, RawVersion: raw, License: e.Props.LicenseURL,
		Prerelease: strings.EqualFold(e.Props.IsPrerelease, "true") || pkgver.IsPrerelease(models.EcosystemPSGallery, nv),
		Yanked:     e.Props.Listed != "" && !strings.EqualFold(e.Props.Listed, "true"),
		Files: []ArtifactRef{{
			Filename: id + "." + nv + ".nupkg", URL: content, Kind: "module", Size: e.Props.PackageSize,
			SHA512: psHash(e.Props.PackageHash, e.Props.PackageHashAlgo),
		}},
		Raw: map[string]any{"item_type": e.Props.ItemType, "authors": e.Props.Authors, "company": e.Props.CompanyName},
	}
	if t, ok := parseODataTime(firstNonEmpty(e.Props.Published, e.Props.Created)); ok {
		if t.Year() > 1901 {
			vm.PublishedAt = &t
		} else {
			vm.Yanked = true
		}
	}
	for _, d := range pkgver.ParsePSGalleryDependencies(e.Props.Dependencies) {
		vm.Dependencies = append(vm.Dependencies, Dependency{
			Name: p.NormalizeName(d.ID), Range: d.Range, Kind: "runtime", Target: d.TargetFramework,
		})
	}
	return vm, true
}

func (p PSGallery) Version(ctx context.Context, c *Client, upstream, name, version string) (*VersionMeta, error) {
	nv, err := p.NormalizeVersion(version)
	if err != nil {
		return nil, ErrVersionNotFound
	}
	meta, err := p.Package(ctx, c, upstream, name)
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

// Classify recognizes the OData metadata queries and the package download endpoint.
func (PSGallery) Classify(host, path, method string) Classification {
	if method != "" && method != "GET" && method != "HEAD" {
		return Classification{Kind: KindOther}
	}
	p := strings.TrimPrefix(path, "/")
	switch {
	case strings.HasPrefix(p, "api/v2/package/"):
		rest := strings.TrimPrefix(p, "api/v2/package/")
		seg := strings.Split(rest, "/")
		if len(seg) >= 2 {
			return Classification{Kind: KindArtifact, Name: PSGallery{}.NormalizeName(seg[0]), Version: normalizePSOrEmpty(seg[1])}
		}
		return Classification{Kind: KindArtifact, Name: PSGallery{}.NormalizeName(seg[0])}
	case strings.Contains(p, ".nupkg"):
		// CDN object (…/packages/<id>.<ver>.nupkg).
		return Classification{Kind: KindArtifact, File: pathBase(p)}
	case strings.HasPrefix(p, "api/v2/FindPackagesById"), strings.HasPrefix(p, "api/v2/Packages"),
		strings.HasPrefix(p, "api/v2/Search"), strings.HasPrefix(p, "api/v2/GetUpdates"):
		return Classification{Kind: KindMetadata, Name: psNameFromQuery(path)}
	case p == "api/v2", p == "api/v2/", strings.HasPrefix(p, "api/v2/$metadata"):
		return Classification{Kind: KindService}
	}
	return Classification{Kind: KindOther}
}

// --- helpers ---

func psHash(hash, algo string) string {
	if hash == "" {
		return ""
	}
	// PSGallery PackageHash is base64. Keep SHA512 base64; map SHA256 to the hex field.
	if strings.EqualFold(algo, "SHA512") || algo == "" {
		return hash
	}
	return ""
}

func psNameFromQuery(path string) string {
	// FindPackagesById()?id='Name'
	if i := strings.Index(path, "id='"); i >= 0 {
		rest := path[i+4:]
		if j := strings.IndexByte(rest, '\''); j >= 0 {
			return PSGallery{}.NormalizeName(rest[:j])
		}
	}
	return ""
}

func odataQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func nextLink(links []odataLink) string {
	for _, l := range links {
		if l.Rel == "next" {
			return l.Href
		}
	}
	return ""
}

func parseODataTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func normalizePSOrEmpty(v string) string {
	nv, err := pkgver.NormalizeVersion(models.EcosystemPSGallery, v)
	if err != nil {
		return ""
	}
	return nv
}

// decodeHashAlgo is a tiny guard so a hex PackageHash is not mistaken for base64 (unused today but
// keeps the hash helpers together).
func decodeHashAlgo(hash string) string {
	if _, err := base64.StdEncoding.DecodeString(hash); err == nil {
		return "base64"
	}
	if _, err := hex.DecodeString(hash); err == nil {
		return "hex"
	}
	return ""
}

var _ = decodeHashAlgo
