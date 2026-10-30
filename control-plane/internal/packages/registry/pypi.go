package registry

import (
	"context"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// PyPI speaks the PyPI JSON and Simple Repository APIs (PEP 503 / 691 / 658 / 740).
type PyPI struct{}

func (PyPI) Ecosystem() string { return models.EcosystemPyPI }

func (PyPI) NormalizeName(name string) string {
	return pkgver.NormalizeName(models.EcosystemPyPI, name)
}

func (PyPI) NormalizeVersion(v string) (string, error) {
	return pkgver.NormalizeVersion(models.EcosystemPyPI, v)
}

// pypiSimple is the PEP 691 JSON Simple API response.
type pypiSimple struct {
	Name     string           `json:"name"`
	Versions []string         `json:"versions"`
	Files    []pypiSimpleFile `json:"files"`
	Meta     map[string]any   `json:"meta"`
}

type pypiSimpleFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython string            `json:"requires-python"`
	Yanked         any               `json:"yanked"`
	Size           int64             `json:"size"`
	UploadTime     string            `json:"upload-time"`
	CoreMetadata   any               `json:"core-metadata"`
	Provenance     string            `json:"provenance"`
	DataDistInfo   any               `json:"data-dist-info-metadata"`
}

// Package lists every version via the JSON Simple API. Dependencies come from the per-version JSON
// API (Simple does not carry them), fetched lazily by Version.
func (p PyPI) Package(ctx context.Context, c *Client, upstream, name string) (*PackageMeta, error) {
	var simple pypiSimple
	norm := p.NormalizeName(name)
	if err := c.getJSON(ctx, upstream+"/simple/"+norm+"/", "application/vnd.pypi.simple.v1+json", &simple); err != nil {
		return nil, err
	}
	meta := &PackageMeta{
		Ecosystem:   models.EcosystemPyPI,
		Name:        norm,
		DisplayName: firstNonEmpty(simple.Name, name),
		TimeByVer:   map[string]time.Time{},
		Yanked:      map[string]string{},
	}
	byVer := map[string]*VersionMeta{}
	for _, f := range simple.Files {
		ver, ok := pkgver.PyPIFileVersion(f.Filename, norm)
		if !ok {
			continue
		}
		vm := byVer[ver]
		if vm == nil {
			vm = &VersionMeta{
				Ecosystem: models.EcosystemPyPI, Name: norm, DisplayName: simple.Name,
				Version: ver, RawVersion: ver, Prerelease: pkgver.IsPrerelease(models.EcosystemPyPI, ver),
			}
			byVer[ver] = vm
		}
		ref := ArtifactRef{
			Filename:   f.Filename,
			URL:        f.URL,
			Kind:       pypiFileKind(f.Filename),
			Size:       f.Size,
			SHA256:     f.Hashes["sha256"],
			MD5:        f.Hashes["md5"],
			Platform:   pypiPlatform(f.Filename),
			Provenance: f.Provenance,
		}
		if yanked, reason := pypiYanked(f.Yanked); yanked {
			vm.Yanked = true
			vm.YankReason = reason
			meta.Yanked[ver] = reason
		}
		if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil {
			if vm.PublishedAt == nil || t.Before(*vm.PublishedAt) {
				tt := t.UTC()
				vm.PublishedAt = &tt
				meta.TimeByVer[ver] = tt
			}
		}
		vm.Files = append(vm.Files, ref)
	}
	for _, vm := range byVer {
		// A version is prerelease-only when every file says so; yanked when every file is yanked.
		meta.Versions = append(meta.Versions, *vm)
	}
	sortVersionsDesc(models.EcosystemPyPI, meta.Versions)
	return meta, nil
}

// pypiJSON is the per-version JSON API response.
type pypiJSON struct {
	Info struct {
		Name           string   `json:"name"`
		Version        string   `json:"version"`
		RequiresDist   []string `json:"requires_dist"`
		RequiresPython string   `json:"requires_python"`
		License        string   `json:"license"`
		Yanked         bool     `json:"yanked"`
		YankedReason   string   `json:"yanked_reason"`
	} `json:"info"`
	URLs            []pypiURL `json:"urls"`
	Vulnerabilities []any     `json:"vulnerabilities"`
}

type pypiURL struct {
	Filename    string            `json:"filename"`
	URL         string            `json:"url"`
	PackageType string            `json:"packagetype"`
	Digests     map[string]string `json:"digests"`
	Size        int64             `json:"size"`
	UploadTime  string            `json:"upload_time_iso_8601"`
	Yanked      bool              `json:"yanked"`
	RequiresPy  string            `json:"requires_python"`
}

func (p PyPI) Version(ctx context.Context, c *Client, upstream, name, version string) (*VersionMeta, error) {
	norm := p.NormalizeName(name)
	nv, err := p.NormalizeVersion(version)
	if err != nil {
		return nil, ErrVersionNotFound
	}
	var doc pypiJSON
	if err := c.getJSON(ctx, upstream+"/pypi/"+norm+"/"+version+"/json", "application/json", &doc); err != nil {
		if err == ErrPackageNotFound {
			return nil, ErrVersionNotFound
		}
		return nil, err
	}
	vm := &VersionMeta{
		Ecosystem: models.EcosystemPyPI, Name: norm, DisplayName: doc.Info.Name,
		Version: nv, RawVersion: doc.Info.Version, License: doc.Info.License,
		Yanked: doc.Info.Yanked, YankReason: doc.Info.YankedReason,
		Prerelease: pkgver.IsPrerelease(models.EcosystemPyPI, nv),
	}
	for _, u := range doc.URLs {
		vm.Files = append(vm.Files, ArtifactRef{
			Filename: u.Filename, URL: u.URL, Kind: pypiFileKind(u.Filename), Size: u.Size,
			SHA256: u.Digests["sha256"], MD5: u.Digests["md5"], Platform: pypiPlatform(u.Filename),
		})
		if t, err := time.Parse(time.RFC3339, u.UploadTime); err == nil && vm.PublishedAt == nil {
			tt := t.UTC()
			vm.PublishedAt = &tt
		}
	}
	for _, raw := range doc.Info.RequiresDist {
		req, err := pkgver.ParseRequirement(raw)
		if err != nil {
			continue
		}
		dep := Dependency{Name: req.Name, Range: req.Specifier, Kind: "runtime", Marker: req.Marker, Optional: req.Marker != ""}
		if req.URL != "" {
			dep.Range = "@ " + req.URL
		}
		vm.Dependencies = append(vm.Dependencies, dep)
	}
	vm.HasInstallScripts = vm.hasSdist()
	return vm, nil
}

func (vm VersionMeta) hasSdist() bool {
	for _, f := range vm.Files {
		if f.Kind == "sdist" {
			return true
		}
	}
	return false
}

// Classify recognizes the Simple API, the JSON API, the Integrity (provenance) API and file downloads.
func (p PyPI) Classify(host, path, method string) Classification {
	if method != "" && method != "GET" && method != "HEAD" {
		return Classification{Kind: KindOther}
	}
	pl := strings.TrimPrefix(path, "/")
	// files.pythonhosted.org and CDNs serve the artifacts: /packages/<..>/<file>.
	if strings.HasPrefix(pl, "packages/") {
		file := pathBase(pl)
		if strings.HasSuffix(file, ".metadata") {
			return Classification{Kind: KindService} // PEP 658 metadata sidecar
		}
		return Classification{Kind: KindArtifact, File: file}
	}
	switch {
	case strings.HasPrefix(pl, "simple/"):
		name := strings.Trim(strings.TrimPrefix(pl, "simple/"), "/")
		if name == "" || strings.Contains(name, "/") && !strings.HasSuffix(pl, "/") {
			return Classification{Kind: KindService} // the index root
		}
		return Classification{Kind: KindMetadata, Name: p.NormalizeName(strings.TrimSuffix(name, "/"))}
	case strings.HasPrefix(pl, "pypi/"):
		rest := strings.TrimPrefix(pl, "pypi/")
		seg := strings.Split(rest, "/")
		if len(seg) >= 2 && seg[len(seg)-1] == "json" {
			name := p.NormalizeName(seg[0])
			ver := ""
			if len(seg) == 3 {
				ver = normalizePyPIOrEmpty(seg[1])
			}
			return Classification{Kind: KindMetadata, Name: name, Version: ver}
		}
	case strings.HasPrefix(pl, "integrity/"):
		return Classification{Kind: KindService}
	}
	return Classification{Kind: KindOther}
}

func pypiFileKind(filename string) string {
	if strings.HasSuffix(filename, ".whl") {
		return "wheel"
	}
	return "sdist"
}

func pypiPlatform(filename string) string {
	if !strings.HasSuffix(filename, ".whl") {
		return ""
	}
	w, err := pkgver.ParseWheelFilename(filename)
	if err != nil {
		return ""
	}
	return strings.Join([]string{strings.Join(w.PythonTags, "."), strings.Join(w.ABITags, "."), strings.Join(w.PlatformTags, ".")}, "-")
}

func pypiYanked(v any) (bool, string) {
	switch t := v.(type) {
	case bool:
		return t, ""
	case string:
		return true, t
	}
	return false, ""
}

func normalizePyPIOrEmpty(v string) string {
	nv, err := pkgver.NormalizeVersion(models.EcosystemPyPI, v)
	if err != nil {
		return ""
	}
	return nv
}
