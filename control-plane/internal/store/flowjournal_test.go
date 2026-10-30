package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
)

func ingestTestFlows(prefix string, n int) []models.TrafficFlow {
	out := make([]models.TrafficFlow, n)
	for i := range out {
		out[i] = models.TrafficFlow{
			ID: fmt.Sprintf("%s-%d", prefix, i), Timestamp: time.Now().UTC(), ServerIP: "10.1.0.5",
			Method: "GET", Scheme: "https", Host: "pkg.example", Path: "/", FullURL: "https://pkg.example/?token=s3cret",
			Verdict: models.VerdictAllowed, StatusCode: 200,
		}
	}
	return out
}

func storedFlowIDs(st *Store) map[string]int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := map[string]int{}
	for _, f := range st.state.Flows {
		out[f.ID]++
	}
	return out
}

// holdPersist saves the state now and keeps the flow window from being saved again for telemetryPersistInterval.
func holdPersist(st *Store) {
	st.persist(true)
	st.mu.Lock()
	st.lastPersist = time.Now()
	st.mu.Unlock()
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An acknowledged batch survives a crash before the next state save: the copy of the data directory taken right
// after the acknowledgement is what a killed control-plane leaves behind.
func TestFlowJournalReplaysAcknowledgedFlowsAfterCrash(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	holdPersist(st)
	recorded, dups, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("crash", 5))
	if err != nil || len(recorded) != 5 || dups != 0 {
		t.Fatalf("ingest: %d recorded, %d dups, %v", len(recorded), dups, err)
	}
	if recorded[0].FullURL != "https://pkg.example/?token=REDACTED" {
		t.Fatalf("query not redacted by default: %s", recorded[0].FullURL)
	}
	crashed := t.TempDir()
	copyTree(t, dir, crashed)
	if raw, _ := os.ReadFile(filepath.Join(crashed, "aegis_state.json")); strings.Contains(string(raw), "crash-0") {
		t.Fatal("state file already holds the flows; the test does not exercise the journal")
	}

	again := newTestStore(t, crashed, false)
	ids := storedFlowIDs(again)
	for i := range 5 {
		if ids[fmt.Sprintf("crash-%d", i)] != 1 {
			t.Fatalf("flow crash-%d not replayed exactly once: %v", i, ids)
		}
	}
	// The worker did not see the acknowledgement and resends: recorded once.
	recorded, dups, err = again.IngestFlowBatch(context.Background(), ingestTestFlows("crash", 5))
	if err != nil || len(recorded) != 0 || dups != 5 || again.FlowDuplicates() != 5 {
		t.Fatalf("resend: %d recorded, %d dups (%d total), %v", len(recorded), dups, again.FlowDuplicates(), err)
	}
	// After the next save the replayed segment is folded into the state and deleted.
	again.persist(true)
	segs, _ := listFlowSegments(filepath.Join(crashed, flowJournalDir))
	if len(segs) != 0 {
		t.Fatalf("segments left after save: %v", segs)
	}
	third := newTestStore(t, crashed, false)
	if n := len(storedFlowIDs(third)); n != 5 {
		t.Fatalf("after save and restart: %d flows", n)
	}
}

func TestFlowJournalRotationKeepsUnsavedSegments(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	holdPersist(st)
	if _, _, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("a", 3)); err != nil {
		t.Fatal(err)
	}
	cut := st.rotateFlowJournal()
	if cut == 0 {
		t.Fatal("rotation did not close the written segment")
	}
	if _, _, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("b", 3)); err != nil {
		t.Fatal(err)
	}
	st.releaseFlowJournal(cut)
	segs, _ := listFlowSegments(filepath.Join(dir, flowJournalDir))
	if len(segs) != 1 || segs[0] != cut+1 {
		t.Fatalf("segments after release of %d: %v", cut, segs)
	}
}

func TestFlowJournalFailureRefusesBatch(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t, dir, false)
	holdPersist(st)
	j := st.journal
	j.mu.Lock()
	good := j.dir
	j.dir = filepath.Join(dir, "missing", "journal")
	j.mu.Unlock()

	recorded, _, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("fail", 2))
	if !errors.Is(err, ErrTelemetryUnavailable) || len(recorded) != 0 {
		t.Fatalf("journal failure: %d recorded, err %v", len(recorded), err)
	}
	if len(storedFlowIDs(st)) != 0 {
		t.Fatal("refused flows were recorded")
	}
	j.mu.Lock()
	j.dir = good
	j.mu.Unlock()
	recorded, dups, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("fail", 2))
	if err != nil || len(recorded) != 2 || dups != 0 {
		t.Fatalf("retry after the journal works again: %d recorded, %d dups, %v", len(recorded), dups, err)
	}
}

func TestIngestFlowBatchDeduplicatesWithinBatch(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	holdPersist(st)
	flows := ingestTestFlows("dup", 2)
	flows = append(flows, flows[0])
	recorded, dups, err := st.IngestFlowBatch(context.Background(), flows)
	if err != nil || len(recorded) != 2 || dups != 1 {
		t.Fatalf("%d recorded, %d dups, %v", len(recorded), dups, err)
	}
}

// memCluster is an in-memory ClusterBackend whose telemetry push can be made to fail.
type memCluster struct {
	mu      sync.Mutex
	doc     []byte
	rev     uint64
	pkgDoc  []byte
	pkgRev  uint64
	audits  []models.AuditEvent
	flows   []models.TrafficFlow
	pushErr error
}

type memTx struct {
	c      *memCluster
	doc    []byte // stored config document at BeginWrite (nil when unchanged)
	rev    uint64
	pkgDoc []byte // stored work-store document at BeginWrite (nil when unchanged)
	pkgRev uint64
	done   bool
}

func (c *memCluster) Name() string   { return "memory" }
func (c *memCluster) NodeID() string { return "node-test" }
func (c *memCluster) LoadConfig(context.Context) ([]byte, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.doc, c.rev, nil
}
func (c *memCluster) StoredRevision(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rev, nil
}
func (c *memCluster) LoadPackageWork(context.Context) ([]byte, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pkgRev == 0 {
		return nil, 0, nil
	}
	return c.pkgDoc, c.pkgRev, nil
}
func (c *memCluster) StoredPackageWorkRevision(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pkgRev, nil
}
func (c *memCluster) BeginWrite(_ context.Context, known, knownPkg uint64) (ClusterTx, error) {
	c.mu.Lock() // released by Commit or Rollback
	tx := &memTx{c: c, rev: c.rev, pkgRev: c.pkgRev}
	if c.rev != known {
		tx.doc = c.doc
	}
	if c.pkgRev != knownPkg && c.pkgRev != 0 {
		tx.pkgDoc = c.pkgDoc
	}
	return tx, nil
}
func (c *memCluster) RecentAudit(_ context.Context, limit int) ([]models.AuditEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return recentAuditDesc(c.audits, limit), nil
}

// recentAuditDesc returns the newest `limit` events, newest first — matching the Postgres backend
// (ORDER BY seq DESC LIMIT n), so the two-node harness exercises the real audit-checkpoint handshake.
func recentAuditDesc(audits []models.AuditEvent, limit int) []models.AuditEvent {
	out := make([]models.AuditEvent, 0, len(audits))
	for i := len(audits) - 1; i >= 0; i-- {
		if limit > 0 && len(out) >= limit {
			break
		}
		out = append(out, audits[i])
	}
	return out
}
func (c *memCluster) StreamAudit(context.Context, func([]byte) error) error { return nil }
func (c *memCluster) RecentFlows(context.Context, int) ([]models.TrafficFlow, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]models.TrafficFlow(nil), c.flows...), int64(len(c.flows)), nil
}
func (c *memCluster) RecentSecurityEvents(context.Context, int) ([]models.SecurityEvent, error) {
	return nil, nil
}
func (c *memCluster) PushTelemetry(_ context.Context, b TelemetryBatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pushErr != nil {
		return c.pushErr
	}
	c.flows = append(c.flows, b.Flows...)
	return nil
}
func (c *memCluster) PullFlows(_ context.Context, after int64, _ int) ([]models.TrafficFlow, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if after >= int64(len(c.flows)) {
		return nil, int64(len(c.flows)), nil
	}
	return append([]models.TrafficFlow(nil), c.flows[after:]...), int64(len(c.flows)), nil
}
func (c *memCluster) PullSecurityEvents(context.Context, time.Time) ([]models.SecurityEvent, error) {
	return nil, nil
}
func (c *memCluster) RuleStats(context.Context) (map[string]RuleStat, error) { return nil, nil }
func (c *memCluster) Prune(context.Context, time.Duration, time.Duration) error {
	return nil
}
func (c *memCluster) Listen(ctx context.Context, _ func(uint64)) { <-ctx.Done() }
func (c *memCluster) Close()                                     {}

func (tx *memTx) StoredDoc() []byte                 { return tx.doc }
func (tx *memTx) StoredRevision() uint64            { return tx.rev }
func (tx *memTx) StoredPackageWorkDoc() []byte      { return tx.pkgDoc }
func (tx *memTx) StoredPackageWorkRevision() uint64 { return tx.pkgRev }
func (tx *memTx) RecentAudit(_ context.Context, limit int) ([]models.AuditEvent, error) {
	return recentAuditDesc(tx.c.audits, limit), nil
}
func (tx *memTx) ImportAudit(_ context.Context, audits []models.AuditEvent) error {
	tx.c.audits = append(tx.c.audits, audits...)
	return nil
}
func (tx *memTx) Commit(_ context.Context, doc []byte, rev uint64, audits []models.AuditEvent, pkgDoc []byte, pkgRev uint64) error {
	if tx.done {
		return errors.New("transaction finished")
	}
	if doc != nil {
		tx.c.doc, tx.c.rev = doc, rev
	}
	if pkgDoc != nil {
		tx.c.pkgDoc, tx.c.pkgRev = pkgDoc, pkgRev
	}
	tx.c.audits = append(tx.c.audits, audits...)
	tx.done = true
	tx.c.mu.Unlock()
	return nil
}
func (tx *memTx) Rollback(context.Context) {
	if !tx.done {
		tx.done = true
		tx.c.mu.Unlock()
	}
}

// Cluster storage: a batch is acknowledged only once shared storage holds it; a resend after a failed commit is
// stored exactly once.
func TestIngestFlowBatchWaitsForClusterCommit(t *testing.T) {
	mc := &memCluster{}
	st, err := NewStore(Options{DataDir: t.TempDir(), Engine: engine.NewPolicyEngine(), Cluster: mc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	mc.mu.Lock()
	mc.pushErr = errors.New("database down")
	mc.mu.Unlock()
	if _, _, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("cl", 3)); !errors.Is(err, ErrTelemetryUnavailable) {
		t.Fatalf("failed commit acknowledged: %v", err)
	}

	mc.mu.Lock()
	mc.pushErr = nil
	mc.mu.Unlock()
	_, dups, err := st.IngestFlowBatch(context.Background(), ingestTestFlows("cl", 3))
	if err != nil {
		t.Fatalf("resend after recovery: %v", err)
	}
	if dups != 3 {
		t.Fatalf("resend: %d duplicates, want 3 (recorded locally by the first attempt)", dups)
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	seen := map[string]int{}
	for _, f := range mc.flows {
		seen[f.ID]++
	}
	for i := range 3 {
		if seen[fmt.Sprintf("cl-%d", i)] != 1 {
			t.Fatalf("shared storage: %v", seen)
		}
	}
}

// A worker that did not see the acknowledgement may resend a batch to another replica: stored once.
func TestClusterFlowResendStoredOnce(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	b := newClusterNode(t, dsn, t.TempDir())
	flows := ingestTestFlows("resend", 4)
	if _, _, err := a.IngestFlowBatch(context.Background(), flows); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.IngestFlowBatch(context.Background(), flows); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := a.cluster.(*PostgresBackend).pool.QueryRow(context.Background(),
		"SELECT count(*) FROM aegis_flows WHERE flow_id LIKE 'resend-%'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("%d rows for 4 flows", n)
	}
}
