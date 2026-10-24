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
	s.mu.RUnlock()
	tx, err := s.cluster.BeginWrite(ctx, known)
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
	}
	before, err := s.configDocLocked()
	if err != nil {
		return err
	}
	startRev := s.state.Revision
	s.pendingAudit = nil
	s.dirty = false

	fnErr := fn()
	changed := s.state.Revision != startRev || len(s.pendingAudit) > 0 || s.dirty
	if !changed {
		s.pendingAudit = nil
		return fnErr
	}
	if fnErr != nil {
		// Partial mutation before an error: restore the pre-mutation configuration.
		_ = s.applyConfigDocLocked(before, startRev)
		s.dropPendingAuditLocked()
		return fnErr
	}
	if s.state.Revision == startRev {
		s.rebuildIndexLocked()
	}
	doc, err := s.configDocLocked()
	if err == nil {
		err = tx.Commit(ctx, doc, s.state.Revision, s.pendingAudit)
	}
	if err != nil {
		s.log.Error("cluster commit failed; restoring last committed configuration", "error", err)
		_ = s.applyConfigDocLocked(before, startRev)
		s.dropPendingAuditLocked()
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

// configDocLocked serializes the configuration part of the state (telemetry lives in its own tables).
func (s *Store) configDocLocked() ([]byte, error) {
	cfg := s.state
	cfg.Flows, cfg.AuditEvents, cfg.SecurityEvents, cfg.RuleStats = nil, nil, nil, nil
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
	s.state = cfg
	s.state.Flows, s.state.AuditEvents, s.state.SecurityEvents, s.state.RuleStats = flows, audits, events, stats
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
	tx, err := s.cluster.BeginWrite(ctx, 0)
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
	fresh := tx.StoredDoc() == nil
	switch {
	case !fresh:
		audits, err := tx.RecentAudit(ctx, maxAuditEvents)
		if err != nil {
			return err
		}
		s.state.AuditEvents = audits
	case s.importedFileState:
		// Migration from file storage: the complete audit trail, not only the in-memory window.
		sc, err := s.importFileAuditTrailLocked(ctx, tx)
		if err != nil {
			return fmt.Errorf("import the audit trail of the file storage: %w", err)
		}
		audits, err := tx.RecentAudit(ctx, maxAuditEvents)
		if err != nil {
			return err
		}
		s.state.AuditEvents = audits
		if s.state.AuditAnchor == "" {
			s.establishAuditAnchorLocked(sc, false)
		}
	default:
		var sc anchorScan
		for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
			_ = sc.add(s.state.AuditEvents[i])
		}
		s.establishAuditAnchorLocked(sc, false)
	}
	before, _ := s.configDocLocked()
	s.pendingAudit = nil
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
	if err := tx.Commit(ctx, after, s.state.Revision, pending); err != nil {
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

type telemetryQueue struct {
	mu     sync.Mutex
	flows  []models.TrafficFlow
	events map[string]models.SecurityEvent
	stats  map[string]RuleStat
}

func newTelemetryQueue() *telemetryQueue {
	return &telemetryQueue{events: map[string]models.SecurityEvent{}, stats: map[string]RuleStat{}}
}

func (q *telemetryQueue) add(flows []models.TrafficFlow, events []models.SecurityEvent, stats map[string]RuleStat) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.flows = append(q.flows, flows...)
	if over := len(q.flows) - telemetryQueueMax; over > 0 {
		q.flows = q.flows[over:]
	}
	for _, ev := range events {
		q.events[ev.ID] = ev
	}
	for id, st := range stats {
		cur := q.stats[id]
		q.stats[id] = RuleStat{Hits: cur.Hits + st.Hits, Bytes: cur.Bytes + st.Bytes}
	}
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

// requeue puts a failed batch back (newer data that arrived meanwhile wins).
func (q *telemetryQueue) requeue(b TelemetryBatch) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.flows = append(b.Flows, q.flows...)
	if over := len(q.flows) - telemetryQueueMax; over > 0 {
		q.flows = q.flows[over:]
	}
	for _, ev := range b.Events {
		if _, newer := q.events[ev.ID]; !newer {
			q.events[ev.ID] = ev
		}
	}
	for id, st := range b.Stats {
		cur := q.stats[id]
		q.stats[id] = RuleStat{Hits: cur.Hits + st.Hits, Bytes: cur.Bytes + st.Bytes}
	}
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

// seenSet is a bounded set of recently merged flow IDs.
type seenSet struct {
	ids   map[string]struct{}
	order []string
}

func (s *seenSet) add(id string) bool {
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

func (s *Store) flushTelemetry(ctx context.Context) {
	b := s.telemetry.take()
	if b.empty() {
		return
	}
	if err := s.cluster.PushTelemetry(ctx, b); err != nil {
		s.log.Warn("telemetry push failed; will retry", "error", err, "flows", len(b.Flows))
		s.telemetry.requeue(b)
	}
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
