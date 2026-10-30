package store

import (
	"context"
	"testing"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

// Two Store instances over one in-memory cluster backend simulate active-active in-process. It validates
// the 3.0 work-store split: the package work-store (requests / assessments / jobs) replicates as its own
// document, work-store churn does NOT advance the configuration revision or reload config on peers, and a
// config refresh does not clobber a peer's replicated work-store.
//
// In-process only: it exercises the store's replication LOGIC via the memCluster double. Real multi-node
// PostgreSQL behaviour (LISTEN/NOTIFY, SELECT ... FOR UPDATE contention, two-node job-lease races) must be
// signed off against an actual two-node cluster before production.
func TestClusterWorkStoreSplit(t *testing.T) {
	mc := &memCluster{}
	newNode := func(name string) *Store {
		st, err := NewStore(Options{DataDir: t.TempDir(), Engine: engine.NewPolicyEngine(), Cluster: mc, BootstrapAdminPassword: "Cluster-Split-Pass-1"})
		if err != nil {
			t.Fatalf("NewStore %s: %v", name, err)
		}
		t.Cleanup(st.Close)
		return st
	}
	a := newNode("a") // seeds the cluster
	b := newNode("b") // joins the cluster
	ctx := context.Background()

	// --- Baseline: a configuration change on A replicates to B and advances the config revision on both.
	cfgRevA0, cfgRevB0 := a.GetRevision(), b.GetRevision()
	s := a.PackageFirewall().Settings
	es := s.Ecosystems[models.EcosystemNPM]
	es.Mode = models.PackageModeEnforce
	s.Ecosystems[models.EcosystemNPM] = es
	if _, err := a.UpdatePackageSettings(s, superAdmin()); err != nil {
		t.Fatalf("UpdatePackageSettings: %v", err)
	}
	if a.GetRevision() <= cfgRevA0 {
		t.Fatalf("config change did not advance A's config revision")
	}
	b.refreshFromCluster(ctx)
	if b.GetRevision() <= cfgRevB0 {
		t.Fatalf("config change did not replicate to B (config revision)")
	}
	if b.PackageFirewall().Settings.Ecosystems[models.EcosystemNPM].Mode != models.PackageModeEnforce {
		t.Fatalf("config change (npm enforce) did not replicate to B")
	}

	// --- The split: a work-store change on A must NOT advance the config revision, must advance the
	// composite state revision (console refresh), and must replicate to B without touching B's config.
	cfgRevA1, cfgRevB1 := a.GetRevision(), b.GetRevision()
	stateRevA1 := a.GetStateRevision()
	req, err := a.CreatePackageRequest(models.PackageRequest{
		Ecosystem: models.EcosystemNPM, Name: "left-pad", Version: "1.3.0", GroupIDs: []string{"*"}, Status: models.PackageReqReady,
	})
	if err != nil {
		t.Fatalf("CreatePackageRequest: %v", err)
	}
	if a.GetRevision() != cfgRevA1 {
		t.Fatalf("work-store change bumped A's config revision (%d -> %d)", cfgRevA1, a.GetRevision())
	}
	if a.GetStateRevision() <= stateRevA1 {
		t.Fatalf("work-store change did not advance A's composite state revision (console would not refresh)")
	}
	b.refreshPackageWorkFromCluster(ctx)
	if b.GetRevision() != cfgRevB1 {
		t.Fatalf("work-store replication bumped B's config revision (%d -> %d)", cfgRevB1, b.GetRevision())
	}
	if _, ok := b.PackageRequest(req.ID); !ok {
		t.Fatalf("package request did not replicate to B's work-store")
	}

	// --- A later configuration change + config refresh on B must not clobber B's replicated work-store.
	if _, err := a.AddPackageBlock(models.PackageBlock{Ecosystem: "pypi", Name: "ctx", Versions: "*", Reason: "typosquat"}, superAdmin()); err != nil {
		t.Fatalf("AddPackageBlock: %v", err)
	}
	b.refreshFromCluster(ctx)
	if !b.IsBlocked("pypi", "ctx", "1.0.0") {
		t.Fatalf("second config change did not replicate to B")
	}
	if _, ok := b.PackageRequest(req.ID); !ok {
		t.Fatalf("a config refresh clobbered B's replicated work-store")
	}
}
