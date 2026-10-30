package packages

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/pkgver"
	"aegisproxy/control-plane/internal/packages/registry"
)

// ResolveConfig controls dependency resolution.
type ResolveConfig struct {
	MaxGraph int
	// Kinds included when expanding a node's dependencies. The root's own dev dependencies are added
	// only when IncludeRootDev is set (build tooling of the requested package).
	Kinds          []string
	IncludeRootDev bool
	// PythonEnvs are the PEP 508 marker environments PyPI dependencies are resolved for (union); a
	// dependency whose marker matches any environment is included.
	PythonEnvs []map[string]string
	// NuGetFrameworks limits the NuGet dependency groups considered (empty = every group).
	NuGetFrameworks []string
}

// defaultKinds resolves the dependencies a normal install/build pulls in.
func (c ResolveConfig) kinds() map[string]bool {
	k := c.Kinds
	if len(k) == 0 {
		k = []string{"runtime", "optional", "peer", "build", "framework"}
	}
	m := map[string]bool{}
	for _, x := range k {
		m[x] = true
	}
	return m
}

// Resolution is the output of Resolve.
type Resolution struct {
	Nodes   []models.PackageNode
	RootKey string
	// Partial is set when the graph hit MaxGraph or a dependency could not be resolved (recorded per
	// node in Unresolved). Enforcement stays safe regardless: a missing node is simply not approved.
	Partial    bool
	Unresolved []string
}

// Resolve builds the dependency graph of one package version using registry metadata. It is an
// approximation of the client's resolver (one chosen version per package name), good enough to review
// and to seed approvals; the data-plane still pins exact artifacts, so a dependency the approximation
// misses is blocked and surfaces as a new request rather than slipping through.
func (s *Service) Resolve(ctx context.Context, ecosystem, name, version string, cfg ResolveConfig) (*Resolution, error) {
	ad := s.adapter(ecosystem)
	if ad == nil {
		return nil, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	up := s.upstream(ecosystem)
	if cfg.MaxGraph <= 0 {
		cfg.MaxGraph = 4000
	}
	kinds := cfg.kinds()

	rootVer, err := pkgver.NormalizeVersion(ecosystem, version)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", version, err)
	}
	rootName := ad.NormalizeName(name)
	rootKey := nodeKey(ecosystem, rootName, rootVer)

	res := &Resolution{RootKey: rootKey}
	nodes := map[string]*models.PackageNode{}
	order := []string{}
	// chosen records the single version picked per package name (first win, like a flat resolution).
	chosen := map[string]string{}
	pkgCache := map[string]*registry.PackageMeta{}

	type item struct {
		name, version string
		parent        string
		rng, kind     string
		root, direct  bool
	}
	queue := []item{{name: rootName, version: rootVer, root: true}}

	for len(queue) > 0 {
		if len(nodes) >= cfg.MaxGraph {
			res.Partial = true
			break
		}
		it := queue[0]
		queue = queue[1:]
		key := nodeKey(ecosystem, it.name, it.version)
		if n, ok := nodes[key]; ok {
			if it.parent != "" {
				n.RequiredBy = append(n.RequiredBy, models.PackageEdge{Parent: it.parent, Range: it.rng, Kind: it.kind})
			}
			continue
		}
		vm, err := s.versionMeta(ctx, ad, up, it.name, it.version, pkgCache)
		if err != nil {
			res.Unresolved = append(res.Unresolved, key)
			res.Partial = true
			// Still record the node so the reviewer sees the gap.
			nodes[key] = &models.PackageNode{Key: key, Ecosystem: ecosystem, Name: it.name, Version: it.version,
				Root: it.root, Direct: it.direct, State: "new"}
			order = append(order, key)
			if it.parent != "" {
				nodes[key].RequiredBy = []models.PackageEdge{{Parent: it.parent, Range: it.rng, Kind: it.kind}}
			}
			continue
		}
		node := &models.PackageNode{
			Key: key, Ecosystem: ecosystem, Name: it.name, DisplayName: vm.DisplayName, Version: it.version,
			Root: it.root, Direct: it.direct, PublishedAt: vm.PublishedAt, License: vm.License,
			Deprecated: vm.Deprecated, Yanked: vm.Yanked, State: "new",
		}
		for _, f := range vm.Files {
			node.Files = append(node.Files, models.PackageFilePin{
				Filename: f.Filename, SHA256: f.SHA256, SHA512: f.SHA512, Size: f.Size, URL: f.URL,
			})
		}
		if it.parent != "" {
			node.RequiredBy = []models.PackageEdge{{Parent: it.parent, Range: it.rng, Kind: it.kind}}
		}
		nodes[key] = node
		order = append(order, key)
		chosen[it.name] = it.version

		// Expand dependencies.
		deps := vm.Dependencies
		for _, d := range deps {
			if !s.wantDep(ecosystem, d, kinds, it.root, cfg) {
				continue
			}
			addKind(node, d.Kind)
			depName := ad.NormalizeName(d.Name)
			// If we already picked a version for this name, just add the edge (flat resolution).
			if cur, ok := chosen[depName]; ok {
				queue = append(queue, item{name: depName, version: cur, parent: key, rng: d.Range, kind: d.Kind})
				continue
			}
			pick, err := s.pickVersion(ctx, ad, up, depName, d.Range, pkgCache)
			if err != nil || pick == "" {
				res.Unresolved = append(res.Unresolved, ecosystem+":"+depName+"@"+d.Range)
				res.Partial = true
				continue
			}
			queue = append(queue, item{name: depName, version: pick, parent: key, rng: d.Range, kind: d.Kind,
				direct: it.root})
		}
	}

	res.Nodes = make([]models.PackageNode, 0, len(order))
	for _, k := range order {
		n := nodes[k]
		dedupeEdges(n)
		sort.Strings(n.Kinds)
		res.Nodes = append(res.Nodes, *n)
	}
	return res, nil
}

// wantDep decides whether a dependency is part of the resolved scenario.
func (s *Service) wantDep(ecosystem string, d registry.Dependency, kinds map[string]bool, parentIsRoot bool, cfg ResolveConfig) bool {
	if d.Kind == "dev" && !(parentIsRoot && cfg.IncludeRootDev) {
		return false
	}
	if !kinds[d.Kind] && d.Kind != "runtime" {
		return false
	}
	switch ecosystem {
	case models.EcosystemPyPI:
		if d.Marker == "" {
			return true
		}
		return pkgver.MarkerMatchesAny(d.Marker, cfg.PythonEnvs)
	case models.EcosystemNuGet:
		if len(cfg.NuGetFrameworks) == 0 || d.Target == "" {
			return true
		}
		for _, fw := range cfg.NuGetFrameworks {
			if strings.EqualFold(fw, d.Target) {
				return true
			}
		}
		return true // when in doubt, include (the artifact pin still gates delivery)
	}
	return true
}

// pickVersion chooses the version a client resolver would select for a range.
func (s *Service) pickVersion(ctx context.Context, ad registry.Adapter, up, name, rng string, cache map[string]*registry.PackageMeta) (string, error) {
	pm, err := s.packageMeta(ctx, ad, up, name, cache)
	if err != nil {
		return "", err
	}
	versions := make([]string, 0, len(pm.Versions))
	for _, v := range pm.Versions {
		if v.Yanked {
			continue
		}
		versions = append(versions, v.Version)
	}
	pick, ok := pkgver.MaxSatisfying(ad.Ecosystem(), versions, rng)
	if !ok {
		return "", nil
	}
	return pick, nil
}

// versionMeta returns a version's metadata, using the cached package document when it already carries
// the dependencies (npm, NuGet, PSGallery) and fetching the per-version document otherwise (PyPI).
func (s *Service) versionMeta(ctx context.Context, ad registry.Adapter, up, name, version string, cache map[string]*registry.PackageMeta) (*registry.VersionMeta, error) {
	pm, err := s.packageMeta(ctx, ad, up, name, cache)
	if err != nil {
		return nil, err
	}
	for i := range pm.Versions {
		if pm.Versions[i].Version == version {
			vm := pm.Versions[i]
			if len(vm.Dependencies) == 0 && ad.Ecosystem() == models.EcosystemPyPI {
				full, err := ad.Version(ctx, s.client, up, name, version)
				if err == nil && full != nil {
					return full, nil
				}
			}
			return &vm, nil
		}
	}
	// Not in the list (newer than the cached document or a yanked version): fetch directly.
	return ad.Version(ctx, s.client, up, name, version)
}

func (s *Service) packageMeta(ctx context.Context, ad registry.Adapter, up, name string, cache map[string]*registry.PackageMeta) (*registry.PackageMeta, error) {
	if pm, ok := cache[name]; ok {
		return pm, nil
	}
	pm, err := ad.Package(ctx, s.client, up, name)
	if err != nil {
		return nil, err
	}
	cache[name] = pm
	return pm, nil
}

func nodeKey(ecosystem, name, version string) string {
	return ecosystem + ":" + name + "@" + version
}

func addKind(n *models.PackageNode, kind string) {
	if kind == "" {
		return
	}
	for _, k := range n.Kinds {
		if k == kind {
			return
		}
	}
	n.Kinds = append(n.Kinds, kind)
}

func dedupeEdges(n *models.PackageNode) {
	if len(n.RequiredBy) < 2 {
		return
	}
	seen := map[string]bool{}
	out := n.RequiredBy[:0]
	for _, e := range n.RequiredBy {
		k := e.Parent + "|" + e.Range + "|" + e.Kind
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	n.RequiredBy = out
}
