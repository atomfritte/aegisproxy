package store

import (
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

func superAdmin() *auth.TokenClaims {
	return &auth.TokenClaims{Username: "admin", Role: models.RoleSuperAdmin}
}

func newPackageTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestDefaultPackageFirewallSeeded(t *testing.T) {
	st := newPackageTestStore(t)
	fw := st.PackageFirewall()
	if len(fw.Settings.Ecosystems) != len(models.Ecosystems) {
		t.Fatalf("expected %d ecosystems, got %d", len(models.Ecosystems), len(fw.Settings.Ecosystems))
	}
	for _, e := range models.Ecosystems {
		if fw.Settings.Ecosystems[e].Mode != models.PackageModeOff {
			t.Errorf("ecosystem %s should default to off", e)
		}
	}
	// The bundle is nil while every ecosystem is off.
	if b := st.PackageBundle(""); b != nil {
		t.Errorf("bundle should be nil when the firewall is off, got %v", b)
	}
}

func TestPackageApprovalViaRequestAndBundle(t *testing.T) {
	st := newPackageTestStore(t)
	// Enable npm enforce.
	s := st.PackageFirewall().Settings
	es := s.Ecosystems[models.EcosystemNPM]
	es.Mode = models.PackageModeEnforce
	s.Ecosystems[models.EcosystemNPM] = es
	if _, err := st.UpdatePackageSettings(s, superAdmin()); err != nil {
		t.Fatalf("UpdatePackageSettings: %v", err)
	}

	// A request with a two-node graph (root + one dependency).
	req, err := st.CreatePackageRequest(models.PackageRequest{
		Ecosystem: models.EcosystemNPM, Name: "left-pad", Version: "1.3.0", GroupIDs: []string{"*"},
		Status: models.PackageReqReady,
		Graph: []models.PackageNode{
			{Key: "npm:left-pad@1.3.0", Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Root: true, State: "new",
				Files: []models.PackageFilePin{{Filename: "left-pad-1.3.0.tgz", SHA512: "abc"}}},
			{Key: "npm:dep@1.0.0", Ecosystem: "npm", Name: "dep", Version: "1.0.0", State: "new",
				Files: []models.PackageFilePin{{Filename: "dep-1.0.0.tgz", SHA512: "def"}}},
		},
	})
	if err != nil {
		t.Fatalf("CreatePackageRequest: %v", err)
	}

	n, err := st.ApproveRequestGraph(req.ID, "admin", "SUPER_ADMIN", "ok", nil)
	if err != nil {
		t.Fatalf("ApproveRequestGraph: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 approvals created, got %d", n)
	}
	if got, _ := st.PackageRequest(req.ID); got.Status != models.PackageReqApproved {
		t.Errorf("request status = %q, want approved", got.Status)
	}

	// The bundle now carries the approvals.
	b := st.PackageBundle("https://console.example")
	if b == nil {
		t.Fatal("bundle should not be nil once an ecosystem is enforced")
	}
	approved, _ := b["approved"].(map[string]map[string]map[string]any)
	if approved["npm"]["left-pad"]["1.3.0"] == nil {
		t.Errorf("approved map missing left-pad@1.3.0: %+v", approved)
	}

	// Blocking the dependency revokes its approval for cause.
	if _, err := st.AddPackageBlock(models.PackageBlock{Ecosystem: "npm", Name: "dep", Versions: "*", Reason: "malware"}, superAdmin()); err != nil {
		t.Fatalf("AddPackageBlock: %v", err)
	}
	active := 0
	for _, a := range st.PackageApprovals() {
		if a.Active(time.Now()) {
			active++
		}
	}
	if active != 1 {
		t.Errorf("expected 1 active approval after blocking the dependency, got %d", active)
	}
}

func TestPackageRuleValidation(t *testing.T) {
	st := newPackageTestStore(t)
	_, err := st.SavePackageRule(models.PackageRule{Name: "", Action: "auto_approve"}, superAdmin())
	if err == nil {
		t.Error("expected an error for an empty rule name")
	}
	_, err = st.SavePackageRule(models.PackageRule{Name: "bad", Action: "nonsense"}, superAdmin())
	if err == nil {
		t.Error("expected an error for an invalid action")
	}
	r, err := st.SavePackageRule(models.PackageRule{Name: "auto patches", Action: "auto_approve", Trigger: "updates", MinAgeHours: 72}, superAdmin())
	if err != nil {
		t.Fatalf("SavePackageRule: %v", err)
	}
	if r.ID == "" || r.Trigger != "updates" {
		t.Errorf("unexpected saved rule: %+v", r)
	}
}

func TestPackageAnalysisQueue(t *testing.T) {
	st := newPackageTestStore(t)
	id, created, err := st.EnqueueAnalysis(models.AnalysisJob{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Filename: "left-pad-1.3.0.tgz"})
	if err != nil || !created || id == "" {
		t.Fatalf("EnqueueAnalysis: id=%q created=%v err=%v", id, created, err)
	}
	// A duplicate does not create a second job.
	id2, created2, _ := st.EnqueueAnalysis(models.AnalysisJob{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Filename: "left-pad-1.3.0.tgz"})
	if created2 || id2 != id {
		t.Errorf("duplicate job should reuse %q, got %q created=%v", id, id2, created2)
	}
	job, err := st.ClaimAnalysis("worker-1", []string{"npm"})
	if err != nil || job == nil || job.ID != id {
		t.Fatalf("ClaimAnalysis: job=%v err=%v", job, err)
	}
	if job.State != models.AnalysisRunning {
		t.Errorf("claimed job state = %q, want running", job.State)
	}
	if _, err := st.CompleteAnalysis(id, "worker-1", "report-key", ""); err != nil {
		t.Fatalf("CompleteAnalysis: %v", err)
	}
	got, _ := st.AnalysisJob(id)
	if got.State != models.AnalysisCompleted || got.ReportKey != "report-key" {
		t.Errorf("completed job = %+v", got)
	}
	// Nothing left to claim.
	if job, _ := st.ClaimAnalysis("worker-1", nil); job != nil {
		t.Errorf("expected empty queue, got %v", job)
	}
}
