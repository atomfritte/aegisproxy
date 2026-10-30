package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

var ErrClusterUnavailable = errors.New("cluster storage unavailable")

const (
	clusterWriteTimeout = 15 * time.Second
	flowPullWindow      = 1000 // trailing re-scan window for out-of-order BIGSERIAL commits
	telemetryQueueMax   = 20_000
)

// withWrite runs fn as one atomic configuration mutation.
//
// Single node (file backend): fn runs under the store mutex and the state is persisted
// asynchronously; while the audit log cannot be written nothing is changed (ErrAuditUnavailable).
// Cluster (PostgreSQL): the cluster-wide write lock is taken first, the local
// configuration is refreshed if another replica committed a newer revision, fn runs, and the
// result is committed synchronously. If the commit fails the local state is restored from
// storage and the error is returned to the caller — no acknowledged write is ever lost.
func (s *Store) withWrite(fn func() error) error {
	if s.cluster == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.auditWritableLocked(); err != nil {
			return err
		}
		return fn()
	}
	ctx, cancel := context.WithTimeout(context.Background(), clusterWriteTimeout)
	defer cancel()

	s.writeMu.Lock() // one storage transaction per node at a time
	defer s.writeMu.Unlock()

	s.mu.RLock()
	known := s.state.Revision
	knownPkg := s.pkgWorkRev
	s.mu.RUnlock()
	tx, err := s.cluster.BeginWrite(ctx, known, knownPkg)
	if err != nil {
		s.log.Error("cluster write lock failed", "error", err)
		return fmt.Errorf("%w: %v", ErrClusterUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback(ctx)
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	if doc := tx.StoredDoc(); doc != nil {
		audits, err := tx.RecentAudit(ctx, maxAuditEvents)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrClusterUnavailable, err)
		}
		if err := s.applyConfigDocLocked(doc, tx.StoredRevision()); err != nil {
			return err
		}
		s.state.AuditEvents = audits
		s.checkClusterAuditLocked() // anchor and checkpoint against the trail read in this transaction
	}
	// Refresh the work-store to the latest committed under this same lock, so a mutation that claims a
	// sandbox job or decides a request sees the newest work-store (cross-node coordination).
	if pkgDoc := tx.StoredPackageWorkDoc(); pkgDoc != nil {
		if err := s.applyPackageWorkDocLocked(pkgDoc, tx.StoredPackageWorkRevision()); err != nil {
			return err
		}
	}
	before, err := s.configDocLocked()
	if err != nil {
		return err
	}
	beforePkg, err := s.packageWorkDocLocked()
	if err != nil {
		return err
	}
	startRev := s.state.Revision
	startPkgRev := s.pkgWorkRev
	s.pendingAudit = nil
	s.dirty = false
	s.pkgWorkDirty = false
	s.reportAuditViolationsLocked() // committed with this write

	fnErr := fn()
	configChanged := s.state.Revision != startRev || len(s.pendingAudit) > 0
	pkgChanged := s.pkgWorkRev != startPkgRev || s.pkgWorkDirty
	if !configChanged && !pkgChanged {
		s.pendingAudit = nil
		return fnErr
	}
	restore := func() {
		_ = s.applyConfigDocLocked(before, startRev)
		_ = s.applyPackageWorkDocLocked(beforePkg, startPkgRev)
		s.dropPendingAuditLocked()
	}
	if fnErr != nil {
		// Partial mutation before an error: restore the pre-mutation config and work-store.
		restore()
		return fnErr
	}
	// Only the documents that actually changed are committed (and rewritten); the other row is untouched.
	var cfgDoc, pkgCommitDoc []byte
	cfgRev, pkgCommitRev := s.state.Revision, s.pkgWorkRev
	if configChanged {
		if s.state.Revision == startRev {
			s.rebuildIndexLocked()
			cfgRev = s.state.Revision
		}
		if cfgDoc, err = s.configDocLocked(); err != nil {
			restore()
			return err
		}
	}
	if pkgChanged {
		if s.pkgWorkRev == startPkgRev {
			s.pkgWorkRev++ // a dirty flag without an explicit bump: advance so peers observe the change
			pkgCommitRev = s.pkgWorkRev
		}
		if pkgCommitDoc, err = s.packageWorkDocLocked(); err != nil {
			restore()
			return err
		}
	}
	if err = tx.Commit(ctx, cfgDoc, cfgRev, s.pendingAudit, pkgCommitDoc, pkgCommitRev); err != nil {
		s.log.Error("cluster commit failed; restoring last committed state", "error", err)
		restore()
		return fmt.Errorf("%w: commit failed: %v", ErrClusterUnavailable, err)
	}
	committed = true
	for _, ev := range s.pendingAudit {
		s.emitAudit(ev)
	}
	s.pendingAudit = nil
	return nil
}

func (s *Store) dropPendingAuditLocked() {
	if n := len(s.pendingAudit); n > 0 && n <= len(s.state.AuditEvents) {
		s.state.AuditEvents = s.state.AuditEvents[n:]
	}
	s.pendingAudit = nil
}

// configDocLocked serializes the configuration part of the state (telemetry lives in its own tables, the
// package work-store in its own document).
func (s *Store) configDocLocked() ([]byte, error) {
	cfg := s.state
	cfg.Flows, cfg.AuditEvents, cfg.SecurityEvents, cfg.RuleStats = nil, nil, nil, nil
	cfg.PackageWork = PackageWorkState{} // travels in the work-store document (packageWorkDocLocked)
	// Committed in the same transaction as the audit rows it seals.
	cfg.AuditCheckpoint = s.sealedCheckpointLocked()
	sessions := make([]models.LearningSession, len(cfg.Sessions))
	for i, sess := range cfg.Sessions {
		sess.CompiledCandidates = nil // recomputed from replicated flows on every node
		sessions[i] = sess
	}
	cfg.Sessions = sessions
	return json.Marshal(cfg)
}

// applyConfigDocLocked replaces the configuration while keeping local telemetry windows.
func (s *Store) applyConfigDocLocked(doc []byte, rev uint64) error {
	if err := requireSealedAuditSecrets(doc); err != nil {
		return fmt.Errorf("cluster configuration: %w", err)
	}
	var cfg StateSnapshot
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return fmt.Errorf("decode cluster configuration: %w", err)
	}
	flows, audits, events, stats := s.state.Flows, s.state.AuditEvents, s.state.SecurityEvents, s.state.RuleStats
	pkgWork := s.state.PackageWork // kept local; replicated as its own document
	s.state = cfg
	s.state.Flows, s.state.AuditEvents, s.state.SecurityEvents, s.state.RuleStats = flows, audits, events, stats
	s.state.PackageWork = pkgWork
	s.recompileSessionsLocked(nil)
	s.buildIndexLocked(rev)
	s.state.Revision = rev
	s.revoked = make(map[string]time.Time, len(s.state.RevokedTokens))
	for _, rt := range s.state.RevokedTokens {
		s.revoked[rt.JTI] = rt.ExpiresAt
	}
	if s.notifier != nil {
		s.notifier.UpdateConfig(s.state.NotifyConfig)
	}
	s.syncThreatIntelLocked()
	s.syncExportLocked()
	return nil
}

// packageWorkDocLocked serializes the package firewall work-store (requests, assessments, analysis jobs).
func (s *Store) packageWorkDocLocked() ([]byte, error) {
	return json.Marshal(s.state.PackageWork)
}

// applyPackageWorkDocLocked replaces the work-store from a replicated document.
func (s *Store) applyPackageWorkDocLocked(doc []byte, rev uint64) error {
	var pw PackageWorkState
	if err := json.Unmarshal(doc, &pw); err != nil {
		return fmt.Errorf("decode cluster package work: %w", err)
	}
	s.state.PackageWork = pw
	s.pkgWorkRev = rev
	s.pkgWorkDirty = false
	return nil
}

// recompileSessionsLocked rebuilds learning-session rule candidates from the flow window
// (only the given session IDs, or all sessions when ids is nil).
func (s *Store) recompileSessionsLocked(ids map[string]bool) {
	for i := range s.state.Sessions {
		sess := &s.state.Sessions[i]
		if ids != nil && !ids[sess.ID] {
			continue
		}
		var sessFlows []models.TrafficFlow
		for _, f := range s.state.Flows {
			if f.SessionID == sess.ID {
				sessFlows = append(sessFlows, f)
			}
		}
		if len(sessFlows) > 0 || ids != nil {
			sess.CapturedFlowCount = len(sessFlows)
			sess.CompiledCandidates = engine.CompileSessionRules(sessFlows)
		}
	}
}

// importFileAuditTrailLocked copies the audit trail of a single-node installation into the cluster
// (migration): every event of the audit log and its rotated generations, oldest first, then window
// events the log missed. Events stored already (same ID) are skipped, so a repeated migration never
// duplicates them.
func (s *Store) importFileAuditTrailLocked(ctx context.Context, tx ClusterTx) (anchorScan, error) {
	var sc anchorScan
	batch := make([]models.AuditEvent, 0, 500)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := tx.ImportAudit(ctx, batch)
		batch = batch[:0]
		return err
	}
	missing := make(map[string]bool, len(s.state.AuditEvents))
	for _, ev := range s.state.AuditEvents {
		missing[ev.ID] = true
	}
	add := func(ev models.AuditEvent) error {
		_ = sc.add(ev)
		delete(missing, ev.ID)
		if batch = append(batch, ev); len(batch) == cap(batch) {
			return flush()
		}
		return nil
	}
	if sink := s.opts.AuditSink; sink != nil {
		files, err := sink.snapshot()
		if err != nil {
			return sc, err
		}
		err = scanTrail(files, add)
		closeTrail(files)
		if err != nil {
			return sc, err
		}
	}
	for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
		if ev := s.state.AuditEvents[i]; missing[ev.ID] {
			if err := add(ev); err != nil {
				return sc, err
			}
		}
	}
	if err := flush(); err != nil {
		return sc, err
	}
	s.log.Info("imported the audit trail of the file storage", "events", sc.events)
	return sc, nil
}

// initCluster loads (or atomically initializes) the shared configuration at start-up.
func (s *Store) initCluster(seed func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, err := s.cluster.BeginWrite(ctx, 0, 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrClusterUnavailable, err)
	}
	defer tx.Rollback(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	staleBefore := sealed.StaleCount()
	if doc := tx.StoredDoc(); doc != nil {
		if err := s.applyConfigDocLocked(doc, tx.StoredRevision()); err != nil {
			return err
		}
		s.log.Info("joined cluster", "backend", s.cluster.Name(), "node", s.cluster.NodeID(), "revision", s.state.Revision)
	} else {
		if err := seed(); err != nil {
			return err
		}
		s.log.Info("initialized empty cluster storage", "backend", s.cluster.Name(), "node", s.cluster.NodeID())
	}
	if pkgDoc := tx.StoredPackageWorkDoc(); pkgDoc != nil {
		if err := s.applyPackageWorkDocLocked(pkgDoc, tx.StoredPackageWorkRevision()); err != nil {
			return err
		}
	}
	fresh := tx.StoredDoc() == nil
	s.pendingAudit = nil
	switch {
	case !fresh:
		audits, err := tx.RecentAudit(ctx, maxAuditEvents)
		if err != nil {
			return err
		}
		s.state.AuditEvents = audits
		s.noteAuditLoadedLocked()
		// A missing anchor is left to ensureClusterAuditAnchor (it scans the trail outside the lock).
		s.checkClusterAuditLocked()
	case s.importedFileState:
		// Migration from file storage: the complete audit trail, not only the in-memory window. The
		// checkpoint of the file state is checked against the window saved with it first.
		s.noteAuditLoadedLocked()
		s.checkAuditCheckpointLocked()
		sc, err := s.importFileAuditTrailLocked(ctx, tx)
		if err != nil {
			return fmt.Errorf("import the audit trail of the file storage: %w", err)
		}
		audits, err := tx.RecentAudit(ctx, maxAuditEvents)
		if err != nil {
			return err
		}
		s.state.AuditEvents = audits
		n, _ := countThrough(audits, sc.last, sc.events)
		if c, ok := tx.(auditCounter); ok {
			if total, err := c.CountAudit(ctx); err == nil {
				n = total
			}
		}
		if s.state.AuditAnchor == "" {
			s.establishAuditAnchorLocked(sc, true, n)
		} else {
			if _, err := s.auditAnchorLocked(); err != nil {
				s.auditViolationLocked(err.Error())
			}
			s.auditCheckpointLocked().Events = n
		}
	default:
		var sc anchorScan
		for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
			_ = sc.add(s.state.AuditEvents[i])
		}
		s.establishAuditAnchorLocked(sc, false, sc.events)
	}
	before, _ := s.configDocLocked()
	s.reportAuditViolationsLocked()
	s.migrateLocked()
	if err := s.ensureBootstrapAdminLocked(); err != nil {
		return err
	}
	after, err := s.configDocLocked()
	if err != nil {
		return err
	}
	// Secrets sealed with a previous key (or still in plain text) are re-encrypted with the current key.
	reseal := sealed.StaleCount() - staleBefore
	if !fresh && bytes.Equal(sealed.Normalize(before), sealed.Normalize(after)) && len(s.pendingAudit) == 0 && reseal == 0 {
		return nil
	}
	if reseal > 0 {
		s.log.Info("re-encrypting secrets with the current key", "secrets", reseal, "key_id", sealed.KeyID())
	}
	pending := s.pendingAudit
	if fresh && !s.importedFileState {
		// Persist the complete seeded audit history, oldest first (keeps seq order = chain order).
		pending = append([]models.AuditEvent(nil), s.state.AuditEvents...)
		slices.Reverse(pending)
	}
	s.rebuildIndexLocked()
	if s.state.Revision <= tx.StoredRevision() {
		s.state.Revision = tx.StoredRevision() + 1
	}
	if after, err = s.configDocLocked(); err != nil {
		return err
	}
	// On a brand-new cluster, seed the work-store document alongside the configuration; when joining an
	// existing cluster the work-store was loaded above and is left untouched here.
	var pkgDoc []byte
	pkgRev := s.pkgWorkRev
	if fresh {
		s.pkgWorkRev = tx.StoredPackageWorkRevision() + 1
		pkgRev = s.pkgWorkRev
		if pkgDoc, err = s.packageWorkDocLocked(); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx, after, s.state.Revision, pending, pkgDoc, pkgRev); err != nil {
		return fmt.Errorf("%w: initial commit: %v", ErrClusterUnavailable, err)
	}
	for _, ev := range s.pendingAudit {
		s.emitAudit(ev)
	}
	s.pendingAudit = nil
	if s.importedTelemetry && tx.StoredDoc() == nil {
		stats := make(map[string]RuleStat, len(s.state.RuleStats))
		for id, st := range s.state.RuleStats {
			if st.Hits > 0 || st.Bytes > 0 {
				stats[id] = st
			}
		}
		flows := append([]models.TrafficFlow(nil), s.state.Flows...)
		slices.Reverse(flows)
		if err := s.cluster.PushTelemetry(ctx, TelemetryBatch{Flows: flows, Events: s.state.SecurityEvents, Stats: stats}); err != nil {
			s.log.Warn("could not import telemetry history", "error", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Telemetry replication
// ---------------------------------------------------------------------------

// telemetryQueue holds telemetry not yet committed to shared storage. Data-plane batches are acknowledged only once
// their flows left it (IngestFlowBatch → commitTelemetry); pending tracks those flow IDs until the commit.
type telemetryQueue struct {
	mu      sync.Mutex
	flows   []models.TrafficFlow
	events  map[string]models.SecurityEvent
	stats   map[string]RuleStat
	pending map[string]struct{}
}

func newTelemetryQueue() *telemetryQueue {
	return &telemetryQueue{events: map[string]models.SecurityEvent{}, stats: map[string]RuleStat{}, pending: map[string]struct{}{}}
}

// trimLocked bounds the queue (oldest flows first) and returns the IDs of the flows it dropped.
func (q *telemetryQueue) trimLocked() []string {
	over := len(q.flows) - telemetryQueueMax
	if over <= 0 {
		return nil
	}
	lost := make([]string, 0, over)
	for _, f := range q.flows[:over] {
		delete(q.pending, f.ID)
		lost = append(lost, f.ID)
	}
	q.flows = q.flows[over:]
	return lost
}

// add queues telemetry; returns the IDs of flows dropped because the queue was full.
func (q *telemetryQueue) add(flows []models.TrafficFlow, events []models.SecurityEvent, stats map[string]RuleStat) []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.flows = append(q.flows, flows...)
	for _, f := range flows {
		q.pending[f.ID] = struct{}{}
	}
	lost := q.trimLocked()
	for _, ev := range events {
		q.events[ev.ID] = ev
	}
	for id, st := range stats {
		cur := q.stats[id]
		q.stats[id] = RuleStat{Hits: cur.Hits + st.Hits, Bytes: cur.Bytes + st.Bytes}
	}
	return lost
}

// committed marks the flows of a pushed batch as stored.
func (q *telemetryQueue) committed(b TelemetryBatch) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, f := range b.Flows {
		delete(q.pending, f.ID)
	}
}

func (q *telemetryQueue) anyPending(ids []string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range ids {
		if _, ok := q.pending[id]; ok {
			return true
		}
	}
	return false
}

func (q *telemetryQueue) take() TelemetryBatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := TelemetryBatch{Flows: q.flows, Stats: q.stats}
	for _, ev := range q.events {
		b.Events = append(b.Events, ev)
	}
	q.flows, q.events, q.stats = nil, map[string]models.SecurityEvent{}, map[string]RuleStat{}
	return b
}

// requeue puts a failed batch back (newer data that arrived meanwhile wins); returns the IDs of flows dropped
// because the queue was full.
func (q *telemetryQueue) requeue(b TelemetryBatch) []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.flows = append(b.Flows, q.flows...)
	lost := q.trimLocked()
	for _, ev := range b.Events {
		if _, newer := q.events[ev.ID]; !newer {
			q.events[ev.ID] = ev
		}
	}
	for id, st := range b.Stats {
		cur := q.stats[id]
		q.stats[id] = RuleStat{Hits: cur.Hits + st.Hits, Bytes: cur.Bytes + st.Bytes}
	}
	return lost
}

func (q *telemetryQueue) pendingStats() map[string]RuleStat {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make(map[string]RuleStat, len(q.stats))
	for k, v := range q.stats {
		out[k] = v
	}
	return out
}

// seenSet is a bounded set of recently recorded or merged flow IDs: de-duplicates flows pulled from other replicas
// and batches a data-plane worker resends (its spool delivers at least once).
type seenSet struct {
	mu    sync.Mutex
	ids   map[string]struct{}
	order []string
}

func (s *seenSet) add(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = make(map[string]struct{})
	}
	if _, ok := s.ids[id]; ok {
		return false
	}
	s.ids[id] = struct{}{}
	s.order = append(s.order, id)
	if len(s.order) > 50_000 {
		for _, old := range s.order[:10_000] {
			delete(s.ids, old)
		}
		s.order = s.order[10_000:]
	}
	return true
}

func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

// forget removes an ID whose flow was never stored (its order slot is reclaimed with the oldest entries).
func (s *seenSet) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, id)
}

// clusterLoops runs replication until the store is closed.
func (s *Store) clusterLoops() {
	defer s.persistWG.Done()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-s.closed
		cancel()
	}()

	go s.cluster.Listen(ctx, func(rev uint64) {
		s.mu.RLock()
		cur := s.state.Revision
		s.mu.RUnlock()
		if rev > cur {
			s.refreshFromCluster(ctx)
		}
	})

	fast := time.NewTicker(time.Second)
	defer fast.Stop()
	slow := time.NewTicker(10 * time.Second)
	defer slow.Stop()
	prune := time.NewTicker(15 * time.Minute)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
			s.flushTelemetry(flushCtx)
			c()
			return
		case <-fast.C:
			s.flushTelemetry(ctx)
			s.pullTelemetry(ctx)
			if rev, err := s.cluster.StoredPackageWorkRevision(ctx); err == nil {
				s.mu.RLock()
				cur := s.pkgWorkRev
				s.mu.RUnlock()
				if rev > cur {
					s.refreshPackageWorkFromCluster(ctx)
				}
			}
		case <-slow.C:
			if rev, err := s.cluster.StoredRevision(ctx); err == nil {
				s.mu.RLock()
				cur := s.state.Revision
				s.mu.RUnlock()
				if rev > cur {
					s.refreshFromCluster(ctx)
				}
			}
			s.pullRuleStats(ctx)
			s.exportAuditCheckpointIfDue()
		case <-prune.C:
			if err := s.cluster.Prune(ctx, s.opts.FlowRetention, s.opts.EventRetention); err != nil {
				s.log.Warn("telemetry retention pruning failed", "error", err)
			}
		}
	}
}

func (s *Store) refreshFromCluster(ctx context.Context) {
	doc, rev, err := s.cluster.LoadConfig(ctx)
	if err != nil || doc == nil {
		if err != nil {
			s.log.Warn("cluster refresh failed", "error", err)
		}
		return
	}
	audits, err := s.cluster.RecentAudit(ctx, maxAuditEvents)
	if err != nil {
		s.log.Warn("cluster audit refresh failed", "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rev <= s.state.Revision {
		return
	}
	if err := s.applyConfigDocLocked(doc, rev); err != nil {
		s.log.Error("cluster refresh rejected", "error", err)
		return
	}
	s.state.AuditEvents = audits
	s.log.Debug("configuration refreshed from cluster", "revision", rev)
}

// refreshPackageWorkFromCluster reloads the work-store document when a peer advanced it. Writes refresh
// the work-store under the write lock (withWrite); this keeps read-only replicas current for the console.
func (s *Store) refreshPackageWorkFromCluster(ctx context.Context) {
	doc, rev, err := s.cluster.LoadPackageWork(ctx)
	if err != nil {
		s.log.Warn("cluster work-store refresh failed", "error", err)
		return
	}
	if doc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rev <= s.pkgWorkRev {
		return
	}
	if err := s.applyPackageWorkDocLocked(doc, rev); err != nil {
		s.log.Error("cluster work-store refresh rejected", "error", err)
	}
}

// flushTelemetry commits queued telemetry in one transaction (serialized: a data-plane ingest that finds its flows
// in a push of the background loop waits for that push).
func (s *Store) flushTelemetry(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	b := s.telemetry.take()
	if b.empty() {
		return nil
	}
	if err := s.cluster.PushTelemetry(ctx, b); err != nil {
		s.log.Warn("telemetry push failed; will retry", "error", err, "flows", len(b.Flows))
		if lost := s.telemetry.requeue(b); len(lost) > 0 {
			for _, id := range lost {
				s.seenFlows.forget(id)
			}
			s.CountFlowDrops("queue_overflow", len(lost))
			s.log.Error("cluster telemetry queue full: oldest unsaved flows dropped", "flows", len(lost))
		}
		return err
	}
	s.telemetry.committed(b)
	return nil
}

// commitTelemetry returns once none of the given flows waits for shared storage any more.
func (s *Store) commitTelemetry(ctx context.Context, ids []string) error {
	if !s.telemetry.anyPending(ids) {
		return nil
	}
	if err := s.flushTelemetry(ctx); err != nil {
		return err
	}
	if s.telemetry.anyPending(ids) {
		// Taken by a concurrent push that failed meanwhile and requeued them.
		return errors.New("flows not committed yet")
	}
	return nil
}

func (s *Store) pullTelemetry(ctx context.Context) {
	from := max(s.flowCursor-flowPullWindow, 0)
	flows, maxSeq, err := s.cluster.PullFlows(ctx, from, 5000)
	if err != nil {
		s.log.Warn("telemetry pull failed", "error", err)
		return
	}
	s.flowCursor = max(s.flowCursor, maxSeq)
	var fresh []models.TrafficFlow
	for _, f := range flows {
		if s.seenFlows.add(f.ID) {
			fresh = append(fresh, f)
		}
	}
	events, err := s.cluster.PullSecurityEvents(ctx, s.eventCursor.Add(-5*time.Second))
	if err == nil && len(events) > 0 {
		s.eventCursor = time.Now()
	}
	if len(fresh) == 0 && len(events) == 0 {
		if err == nil {
			s.eventCursor = time.Now()
		}
		return
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Timestamp.After(fresh[j].Timestamp) })
	touched := map[string]bool{}
	s.mu.Lock()
	if len(fresh) > 0 {
		s.state.Flows = append(fresh, s.state.Flows...)
		sort.SliceStable(s.state.Flows, func(i, j int) bool { return s.state.Flows[i].Timestamp.After(s.state.Flows[j].Timestamp) })
		if len(s.state.Flows) > maxFlows {
			s.state.Flows = s.state.Flows[:maxFlows]
		}
		for _, f := range fresh {
			if f.SessionID != "" {
				touched[f.SessionID] = true
			}
		}
		if len(touched) > 0 {
			s.recompileSessionsLocked(touched)
		}
	}
	for _, ev := range events {
		if i := slices.IndexFunc(s.state.SecurityEvents, func(x models.SecurityEvent) bool { return x.ID == ev.ID }); i >= 0 {
			s.state.SecurityEvents[i] = ev
		} else {
			s.state.SecurityEvents = append(s.state.SecurityEvents, ev)
		}
	}
	if len(events) > 0 {
		sort.SliceStable(s.state.SecurityEvents, func(i, j int) bool {
			return s.state.SecurityEvents[i].Timestamp.After(s.state.SecurityEvents[j].Timestamp)
		})
		if len(s.state.SecurityEvents) > maxSecurityEvents {
			s.state.SecurityEvents = s.state.SecurityEvents[:maxSecurityEvents]
		}
	}
	s.mu.Unlock()
	for i := len(fresh) - 1; i >= 0; i-- {
		s.traffic.add(fresh[i])
		s.broadcastFlow(fresh[i])
	}
}

func (s *Store) pullRuleStats(ctx context.Context) {
	stats, err := s.cluster.RuleStats(ctx)
	if err != nil {
		return
	}
	pending := s.telemetry.pendingStats()
	merged := make(map[string]RuleStat, len(stats))
	for id, st := range stats {
		p := pending[id]
		merged[id] = RuleStat{Hits: st.Hits + p.Hits, Bytes: st.Bytes + p.Bytes}
	}
	s.mu.Lock()
	s.applyRuleStatsLocked(merged)
	s.mu.Unlock()
}

// loadClusterTelemetry seeds the local telemetry windows from shared storage at start-up.
func (s *Store) loadClusterTelemetry() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	flows, maxSeq, err := s.cluster.RecentFlows(ctx, maxFlows)
	if err != nil {
		return err
	}
	events, err := s.cluster.RecentSecurityEvents(ctx, maxSecurityEvents)
	if err != nil {
		return err
	}
	stats, err := s.cluster.RuleStats(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flowCursor = maxSeq
	s.eventCursor = time.Now()
	for _, f := range flows {
		s.seenFlows.add(f.ID)
	}
	s.state.Flows = flows
	s.state.SecurityEvents = events
	s.applyRuleStatsLocked(stats)
	s.recompileSessionsLocked(nil)
	return nil
}
