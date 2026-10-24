package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/threatintel"
)

// Integration tests for active-active clustering. They run only when AEGIS_TEST_DATABASE_URL points
// to a disposable PostgreSQL database, e.g.:
//
//	docker run -d --rm --name aegis-pg -e POSTGRES_PASSWORD=x -e POSTGRES_USER=aegis -p 55432:5432 postgres:17-alpine
//	AEGIS_TEST_DATABASE_URL=postgres://aegis:x@127.0.0.1:55432/aegis?sslmode=disable go test ./internal/store/
func testDSN(t *testing.T) string {
	dsn := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	return dsn
}

func resetDB(t *testing.T, dsn string) {
	t.Helper()
	b, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.pool.Exec(context.Background(), "TRUNCATE aegis_config, aegis_audit, aegis_flows, aegis_security_events, aegis_rule_stats"); err != nil {
		t.Fatal(err)
	}
}

func newClusterNode(t *testing.T, dsn, dir string) *Store {
	t.Helper()
	be, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	ti, err := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, Cluster: be,
		BootstrapAdminPassword: "Cluster-Root-Pass-9"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		be.Close()
	})
	return st
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	eventuallyWithin(t, 8*time.Second, what, cond)
}

func eventuallyWithin(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestClusterReplication(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	b := newClusterNode(t, dsn, t.TempDir())

	if a.GetRevision() == 0 || len(b.GetSnapshot().Users) != 1 {
		t.Fatalf("second node did not join the cluster state: rev=%d users=%d", a.GetRevision(), len(b.GetSnapshot().Users))
	}
	if _, err := b.AuthenticateLocal("admin", "Cluster-Root-Pass-9"); err != nil {
		t.Fatalf("bootstrap admin not usable on node B: %v", err)
	}

	// Config written on A becomes visible on B (LISTEN/NOTIFY or polling).
	setupFleet(t, a)
	eventually(t, "groups replicated to B", func() bool { return len(b.GetSnapshot().Groups) == 2 })
	if id, _, _ := b.ResolveServer("10.1.0.5", ""); id != "srv-ci-1" {
		t.Errorf("node B resolved %q", id)
	}

	// Concurrent writes on both nodes are serialized; none are lost.
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		node := a
		if i%2 == 1 {
			node = b
		}
		wg.Add(1)
		go func(i int, node *Store) {
			defer wg.Done()
			_, err := node.AddIndicator(models.Indicator{Type: "domain", Value: fmt.Sprintf("bad%d.example", i), Category: "malware", Reason: "test"}, adminClaims)
			errs <- err
		}(i, node)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}
	eventually(t, "all 20 IOCs on both nodes", func() bool {
		return len(a.GetSnapshot().Indicators) == 20 && len(b.GetSnapshot().Indicators) == 20 && a.GetRevision() == b.GetRevision()
	})
	for _, n := range []*Store{a, b} {
		if cnt, err := n.VerifyAuditChain(); err != nil {
			t.Fatalf("audit chain broken after concurrent cluster writes (%d events): %v", cnt, err)
		}
	}

	// Duplicate on the other node is detected against the shared state.
	if _, err := b.AddIndicator(models.Indicator{Type: "domain", Value: "bad0.example", Category: "malware", Reason: "dup"}, adminClaims); err == nil {
		t.Error("duplicate IOC accepted across nodes")
	}

	// Telemetry recorded on A shows up on B; security events from B show up on A.
	a.RecordFlow(models.TrafficFlow{ID: "flw-cluster-1", ServerIP: "10.1.0.5", Method: "GET", Host: "x.example", Verdict: models.VerdictBlocked})
	eventually(t, "flow replicated to B", func() bool {
		for _, f := range b.GetSnapshot().Flows {
			if f.ID == "flw-cluster-1" {
				return true
			}
		}
		return false
	})
	b.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "c2.example", Verdict: models.VerdictThreatBlocked, ThreatCategory: "botnet_c2"})
	eventually(t, "security event replicated to A", func() bool { return len(a.GetSnapshot().SecurityEvents) == 1 })

	// Session revocation is cluster-wide.
	if err := a.RevokeToken("jti-cluster-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revocation replicated to B", func() bool { return b.IsTokenRevoked("jti-cluster-test") })
}

func TestClusterImportsLegacyFileState(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	dir := t.TempDir()
	legacy := StateSnapshot{
		Revision: 40,
		Users:    []models.User{{ID: "usr-admin", Username: "admin", Role: models.RoleSuperAdmin, AllowedGroups: []string{"*"}}},
		Groups:   []models.ServerGroup{{ID: "grp-x", Name: "X", CIDRs: []string{"10.5.0.0/16"}}},
		Flows:    []models.TrafficFlow{{ID: "flw-legacy", Timestamp: time.Now(), ServerIP: "10.5.0.1", Host: "a.example", Verdict: models.VerdictAllowed}},
	}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st := newClusterNode(t, dsn, dir)
	snap := st.GetSnapshot()
	if len(snap.Groups) != 1 || snap.Revision <= 40 {
		t.Fatalf("legacy state not imported: groups=%d rev=%d", len(snap.Groups), snap.Revision)
	}
	other := newClusterNode(t, dsn, t.TempDir())
	eventually(t, "imported flow visible on second node", func() bool {
		for _, f := range other.GetSnapshot().Flows {
			if f.ID == "flw-legacy" {
				return true
			}
		}
		return false
	})
}

func TestClusterPolicySets(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	b := newClusterNode(t, dsn, t.TempDir())
	setupFleet(t, a)
	gov := a.Governance()
	gov.RequirePolicyReview = true
	if _, err := a.UpdateGovernance(gov, adminClaims); err != nil {
		t.Fatal(err)
	}
	set, err := a.CreatePolicySet("", models.PolicySetSpec{Name: "CI", Enabled: true, GroupIDs: []string{"grp-ci"},
		Rules: []models.PolicyRule{{Name: "gh", Action: "ALLOW", HostPattern: "github.com", PathPattern: "/**", Enabled: true}}}, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := a.SubmitChangeRequest(set.ID, "", "", adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	// Reviewed on the other replica by a second person.
	eventually(t, "change request replicated", func() bool { _, ok := b.ChangeRequest(cr.ID); return ok })
	if _, err := b.ReviewChangeRequest(cr.ID, "approve", "ok", infosecClaims); err != nil {
		t.Fatal(err)
	}
	eventually(t, "published set enforced on A", func() bool {
		return a.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Path: "/x"}).Allowed
	})
	ruleID := a.GetSnapshot().Rules[0].ID
	for i := 0; i < 3; i++ {
		a.RecordFlow(models.TrafficFlow{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Verdict: models.VerdictAllowed, MatchedRuleID: ruleID})
	}
	// Hit counters are aggregated in shared storage and pulled every 10 seconds.
	eventuallyWithin(t, 25*time.Second, "rule hit counters replicated to B", func() bool {
		for _, r := range b.GetSnapshot().Rules {
			if r.ID == ruleID && r.HitCount == 3 {
				return true
			}
		}
		return false
	})
	if _, err := b.SetQuarantine("srv-ci-1", true, "cluster quarantine test", adminClaims); err != nil {
		t.Fatal(err)
	}
	eventually(t, "quarantine enforced on A", func() bool {
		return a.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Path: "/x"}).Verdict == models.VerdictQuarantined
	})
}

// A 2.x replica wrote the shared document (flat rules, schema 2); a 2.1 replica joining migrates it.
func TestClusterMigratesV2Document(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	setupFleet(t, a)
	a.Close()
	be, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := be.pool.QueryRow(context.Background(), "SELECT doc FROM aegis_config WHERE id = 1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["schema_version"] = 2
	delete(doc, "policy_sets")
	delete(doc, "policy_versions")
	doc["rules"] = []map[string]any{{"id": "r-legacy", "name": "legacy gh", "action": "ALLOW", "host_pattern": "github.com", "path_pattern": "/**",
		"group_ids": []string{"grp-ci"}, "enabled": true}}
	raw, _ = json.Marshal(doc)
	// Same revision: the audit checkpoint sealed with it stays valid (a changed revision without a
	// new checkpoint is reported as a replaced configuration).
	if _, err := be.pool.Exec(context.Background(), "UPDATE aegis_config SET doc = $1 WHERE id = 1", raw); err != nil {
		t.Fatal(err)
	}
	be.Close()
	b := newClusterNode(t, dsn, t.TempDir())
	if sets := b.PolicySets(); len(sets) != 1 || sets[0].Rules[0].ID != "r-legacy" {
		t.Fatalf("v2 document not migrated: %+v", sets)
	}
	if !b.Evaluate(engine.EvaluationRequest{ServerIP: "10.1.0.5", Method: "GET", Host: "github.com", Path: "/x"}).Allowed {
		t.Fatal("migrated legacy rule not enforced")
	}
	c := newClusterNode(t, dsn, t.TempDir())
	if len(c.PolicySets()) != 1 {
		t.Fatal("migration was not committed to shared storage")
	}
}

func TestClusterAuditExportIsComplete(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	b := newClusterNode(t, dsn, t.TempDir())
	for i := 0; i < 30; i++ {
		node := a
		if i%2 == 1 {
			node = b
		}
		id := fmt.Sprintf("grp-exp-%02d", i)
		if _, err := node.UpsertGroup(models.ServerGroup{ID: id, Name: id, CIDRs: []string{"10.0.0.0/8"}}, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := a.ExportAudit(context.Background(), &buf, filepath.Join(t.TempDir(), "absent.jsonl")); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	groups := 0
	prev := ""
	for _, l := range lines {
		var ev models.AuditEvent
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(ev.EntityID, "grp-exp-") {
			groups++
		}
		if prev != "" && ev.PrevHash != prev {
			t.Fatalf("export breaks the hash chain at %s", ev.ID)
		}
		prev = ev.EventHash
	}
	if groups != 30 {
		t.Fatalf("exported %d group events from both nodes, want 30", groups)
	}
	for _, node := range []*Store{a, b} {
		if res := node.VerifyCompleteAudit(context.Background(), filepath.Join(t.TempDir(), "absent.jsonl")); !res.OK || res.Events != len(lines) {
			t.Fatalf("complete verification on a cluster node: %+v", res)
		}
	}
}

func TestClusterKeyRotationReencrypts(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	oldKey, _ := sealed.DeriveKey(strings.Repeat("o", 48))
	newKey, _ := sealed.DeriveKey(strings.Repeat("n", 48))
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	_ = sealed.Configure(oldKey)
	oldID := sealed.KeyID()
	a := newClusterNode(t, dsn, t.TempDir())
	if _, err := a.UpsertExportSink(models.ExportSink{Name: "hook", Type: "webhook", Streams: []string{"audit"},
		Endpoint: "https://hooks.example/x", Secret: "rotate-me"}, adminClaims); err != nil {
		t.Fatal(err)
	}
	rev := a.GetSnapshot().Revision
	// An unchanged restart must not commit a new revision (sealing uses fresh nonces).
	b := newClusterNode(t, dsn, t.TempDir())
	if got := b.GetSnapshot().Revision; got != rev {
		t.Fatalf("restart without changes bumped the revision %d -> %d", rev, got)
	}
	_ = sealed.Configure(newKey, oldKey)
	c := newClusterNode(t, dsn, t.TempDir())
	if c.GetSnapshot().Revision <= rev {
		t.Fatal("rotation restart did not re-encrypt")
	}
	be, _ := NewPostgresBackend(context.Background(), dsn, nil)
	defer be.Close()
	var doc string
	if err := be.pool.QueryRow(context.Background(), "SELECT doc::text FROM aegis_config LIMIT 1").Scan(&doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "enc:v1:"+oldID+":") || !strings.Contains(doc, "enc:v1:"+sealed.KeyID()+":") {
		t.Fatal("cluster config still contains secrets sealed with the old key")
	}
}

func newClusterNodeWithSink(t *testing.T, dsn, dir, path string) (*Store, *AuditSink) {
	t.Helper()
	be, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, Cluster: be, AuditSink: sink,
		BootstrapAdminPassword: "Cluster-Root-Pass-9"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		sink.Close()
		be.Close()
	})
	return st, sink
}

func clusterAuditIDs(t *testing.T, st *Store) []string {
	t.Helper()
	var ids []string
	if err := st.cluster.StreamAudit(context.Background(), func(raw []byte) error {
		var ev models.AuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return err
		}
		ids = append(ids, ev.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

// Finding 12: migrating from file storage imports the complete trail (all generations), not only the
// in-memory window, and a repeated migration neither fails nor duplicates events. Finding 1 for the
// database: a trail re-hashed with the unkeyed algorithm fails the verification.
func TestClusterImportsCompleteFileAuditTrail(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 4)
	rotateByCopy(t, path, path+"-20260101")
	mkAuditGroups(t, st, 4)
	st.mu.Lock()
	st.state.AuditEvents = st.state.AuditEvents[:3] // a long-running installation: the window is only the tail
	st.markDirtyLocked()
	st.mu.Unlock()
	closeAuditStore(st, sink)
	fileSink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := fileSink.snapshot()
	var want []string
	scanTrail(files, func(ev models.AuditEvent) error { want = append(want, ev.ID); return nil })
	closeTrail(files)
	fileSink.Close()

	node, nodeSink := newClusterNodeWithSink(t, dsn, dir, path)
	got := clusterAuditIDs(t, node)
	if !strings.HasPrefix(strings.Join(got, ","), strings.Join(want, ",")) {
		t.Fatalf("imported %d events, want the %d of the file trail first:\n%v\n%v", len(got), len(want), got, want)
	}
	if res := node.VerifyCompleteAudit(context.Background(), path); !res.OK || !res.StartsAtGenesis {
		t.Fatalf("verification after the migration: %+v", res)
	}
	mkAuditGroups(t, node, 1)
	if res := node.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("verification after a change on the cluster: %+v", res)
	}
	stored := clusterAuditIDs(t, node)

	// The configuration is lost and the file state is imported once more: nothing is duplicated.
	closeAuditStore(node, nodeSink)
	be, _ := NewPostgresBackend(context.Background(), dsn, nil)
	defer be.Close()
	if _, err := be.pool.Exec(context.Background(), "UPDATE aegis_config SET revision = 0"); err != nil {
		t.Fatal(err)
	}
	again, _ := newClusterNodeWithSink(t, dsn, dir, path)
	if ids := clusterAuditIDs(t, again); len(ids) < len(stored) || strings.Join(ids[:len(stored)], ",") != strings.Join(stored, ",") {
		t.Fatalf("repeated migration changed the stored trail: %d -> %d events", len(stored), len(ids))
	}
	if res := again.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("verification after a repeated migration: %+v", res)
	}

	// Somebody with database access re-hashes the trail with the unkeyed algorithm.
	rows, err := be.pool.Query(context.Background(), "SELECT seq, doc FROM aegis_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		seq int64
		ev  models.AuditEvent
	}
	var all []row
	for rows.Next() {
		var r row
		var raw []byte
		if err := rows.Scan(&r.seq, &raw); err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(raw, &r.ev)
		all = append(all, r)
	}
	rows.Close()
	prev := zeroHash
	for i := range all {
		ev := &all[i].ev
		ev.HashVersion = 0
		ev.PrevHash = prev
		ev.EventHash = auditHashV1(prev, *ev)
		prev = ev.EventHash
		raw, _ := json.Marshal(ev)
		if _, err := be.pool.Exec(context.Background(), "UPDATE aegis_audit SET doc = $1, event_hash = $2, prev_hash = $3 WHERE seq = $4",
			raw, ev.EventHash, ev.PrevHash, all[i].seq); err != nil {
			t.Fatal(err)
		}
	}
	if res := again.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "downgrade") {
		t.Fatalf("re-hashed database trail accepted: %+v", res)
	}
}
