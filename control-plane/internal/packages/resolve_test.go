package packages

import (
	"context"
	"testing"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages/advisory"
	"aegisproxy/control-plane/internal/packages/registry"
)

// fakeAdapter serves an in-memory dependency graph so the resolver's BFS, de-duplication and edge
// recording can be tested independently of the pkgver version math.
type fakeAdapter struct {
	pkgs map[string]*registry.PackageMeta // name -> metadata
}

func (fakeAdapter) Ecosystem() string                   { return models.EcosystemNPM }
func (fakeAdapter) NormalizeName(n string) string        { return n }
func (fakeAdapter) NormalizeVersion(v string) (string, error) { return v, nil }
func (f fakeAdapter) Package(_ context.Context, _ *registry.Client, _, name string) (*registry.PackageMeta, error) {
	pm, ok := f.pkgs[name]
	if !ok {
		return nil, registry.ErrPackageNotFound
	}
	return pm, nil
}
func (f fakeAdapter) Version(ctx context.Context, c *registry.Client, up, name, version string) (*registry.VersionMeta, error) {
	pm, err := f.Package(ctx, c, up, name)
	if err != nil {
		return nil, err
	}
	for i := range pm.Versions {
		if pm.Versions[i].Version == version {
			return &pm.Versions[i], nil
		}
	}
	return nil, registry.ErrVersionNotFound
}
func (fakeAdapter) Classify(string, string, string) registry.Classification {
	return registry.Classification{Kind: registry.KindOther}
}

func ver(name, v string, deps ...registry.Dependency) registry.VersionMeta {
	return registry.VersionMeta{
		Ecosystem: models.EcosystemNPM, Name: name, DisplayName: name, Version: v, RawVersion: v,
		Files:        []registry.ArtifactRef{{Filename: name + "-" + v + ".tgz", SHA512: "x"}},
		Dependencies: deps,
	}
}

func TestResolveGraphDedupAndEdges(t *testing.T) {
	// A@1 -> B@1, C@1 ; B@1 -> C@1  (C is shared: one node, two edges)
	fake := fakeAdapter{pkgs: map[string]*registry.PackageMeta{
		"a": {Ecosystem: "npm", Name: "a", Versions: []registry.VersionMeta{ver("a", "1.0.0",
			registry.Dependency{Name: "b", Range: "^1", Kind: "runtime"},
			registry.Dependency{Name: "c", Range: "^1", Kind: "runtime"})}},
		"b": {Ecosystem: "npm", Name: "b", Versions: []registry.VersionMeta{ver("b", "1.0.0",
			registry.Dependency{Name: "c", Range: "^1", Kind: "runtime"})}},
		"c": {Ecosystem: "npm", Name: "c", Versions: []registry.VersionMeta{ver("c", "1.0.0")}},
	}}
	svc := NewService(Options{Sources: []advisory.Source{advisorySourceNone{}}})
	svc.SetAdapters(map[string]registry.Adapter{models.EcosystemNPM: fake})

	res, err := svc.Resolve(context.Background(), models.EcosystemNPM, "a", "1.0.0", ResolveConfig{MaxGraph: 100})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d: %+v", len(res.Nodes), nodeKeys(res.Nodes))
	}
	byKey := map[string]models.PackageNode{}
	for _, n := range res.Nodes {
		byKey[n.Key] = n
	}
	root := byKey["npm:a@1.0.0"]
	if !root.Root {
		t.Error("a@1.0.0 should be the root")
	}
	c := byKey["npm:c@1.0.0"]
	if len(c.RequiredBy) != 2 {
		t.Errorf("c should have 2 edges (from a and b), got %d: %+v", len(c.RequiredBy), c.RequiredBy)
	}
	b := byKey["npm:b@1.0.0"]
	if !b.Direct {
		t.Error("b should be a direct dependency of the root")
	}
}

func TestResolveCycleTerminates(t *testing.T) {
	// A@1 -> B@1 -> A@1 (cycle): resolution must terminate with two nodes.
	fake := fakeAdapter{pkgs: map[string]*registry.PackageMeta{
		"a": {Ecosystem: "npm", Name: "a", Versions: []registry.VersionMeta{ver("a", "1.0.0",
			registry.Dependency{Name: "b", Range: "^1", Kind: "runtime"})}},
		"b": {Ecosystem: "npm", Name: "b", Versions: []registry.VersionMeta{ver("b", "1.0.0",
			registry.Dependency{Name: "a", Range: "^1", Kind: "runtime"})}},
	}}
	svc := NewService(Options{Sources: []advisory.Source{advisorySourceNone{}}})
	svc.SetAdapters(map[string]registry.Adapter{models.EcosystemNPM: fake})
	res, err := svc.Resolve(context.Background(), models.EcosystemNPM, "a", "1.0.0", ResolveConfig{MaxGraph: 100})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("cycle should yield 2 nodes, got %d", len(res.Nodes))
	}
}

func TestResolveUnresolvedDependency(t *testing.T) {
	fake := fakeAdapter{pkgs: map[string]*registry.PackageMeta{
		"a": {Ecosystem: "npm", Name: "a", Versions: []registry.VersionMeta{ver("a", "1.0.0",
			registry.Dependency{Name: "missing", Range: "^1", Kind: "runtime"})}},
	}}
	svc := NewService(Options{Sources: []advisory.Source{advisorySourceNone{}}})
	svc.SetAdapters(map[string]registry.Adapter{models.EcosystemNPM: fake})
	res, err := svc.Resolve(context.Background(), models.EcosystemNPM, "a", "1.0.0", ResolveConfig{MaxGraph: 100})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.Partial || len(res.Unresolved) == 0 {
		t.Errorf("expected a partial resolution with an unresolved dependency, got %+v", res)
	}
}

func nodeKeys(nodes []models.PackageNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Key
	}
	return out
}

// advisorySourceNone is a no-op advisory source used to disable OSV in resolver tests.
type advisorySourceNone struct{}

func (advisorySourceNone) ID() string                 { return "none" }
func (advisorySourceNone) Supports(string) bool       { return false }
func (advisorySourceNone) Lookup(context.Context, []advisory.Query) ([][]models.PackageAdvisory, error) {
	return nil, nil
}
