// Package export forwards audit, traffic and security records to external systems (SIEM, log
// platforms, OpenTelemetry). Every sink has a bounded in-memory queue, batches records, and keeps
// undeliverable batches in a durable on-disk spool that is replayed in order once the destination
// is reachable again (at-least-once delivery).
package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/models"
)

const queueSize = 20_000

type Options struct {
	SpoolDir  string // per-sink spools: <SpoolDir>/<sink id>
	ExportDir string // base directory of "file" sinks
	Node      string // cluster node / instance id
	Host      string // host name (syslog HOSTNAME, resource attributes)
	Version   string
	Logger    *slog.Logger
}

type Manager struct {
	opts       Options
	meta       Meta
	log        *slog.Logger
	mu         sync.RWMutex
	sinks      map[string]*runtime
	known      map[string]bool // ids present in the last configuration (deleted sinks lose their spool)
	configured bool

	pending atomic.Pointer[[]models.ExportSink]
	signal  chan struct{}
	quit    chan struct{}
	applied chan struct{}
}

func New(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	m := &Manager{opts: opts, meta: Meta{Node: opts.Node, Host: opts.Host, Version: opts.Version},
		log: opts.Logger.With("component", "export"), sinks: map[string]*runtime{}, known: map[string]bool{},
		signal: make(chan struct{}, 1), quit: make(chan struct{}), applied: make(chan struct{})}
	go m.applyLoop()
	return m
}

// Apply schedules a configuration asynchronously (never blocks the caller); the newest wins.
func (m *Manager) Apply(sinks []models.ExportSink) {
	if m == nil {
		return
	}
	cp := append([]models.ExportSink(nil), sinks...)
	m.pending.Store(&cp)
	select {
	case m.signal <- struct{}{}:
	default:
	}
}

func (m *Manager) applyLoop() {
	defer close(m.applied)
	for {
		select {
		case <-m.signal:
			if p := m.pending.Swap(nil); p != nil {
				m.Configure(*p)
			}
		case <-m.quit:
			return
		}
	}
}

// ExportDir is where "file" sinks write.
func (m *Manager) ExportDir() string { return m.opts.ExportDir }

func signature(s models.ExportSink) string {
	s.UpdatedAt, s.UpdatedBy, s.Name = nil, "", ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// encodingSignature identifies the record encoding stored in a spool.
func encodingSignature(s models.ExportSink) string {
	return fmt.Sprintf("v1|%s|%s|%s|%s|%s|%s|%s", s.Type, s.Format, s.SyslogProtocol, s.SyslogFacility, s.Index, s.SourceType, s.Endpoint)
}

// Configure applies the sink list (called whenever the replicated configuration changes).
func (m *Manager) Configure(sinks []models.ExportSink) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]models.ExportSink{}
	ids := map[string]bool{}
	for _, s := range sinks {
		ids[s.ID] = true
		if s.Enabled {
			want[s.ID] = s
		}
	}
	for id, rt := range m.sinks {
		if s, ok := want[id]; ok && rt.sig == signature(s) {
			continue
		}
		rt.shutdown()
		delete(m.sinks, id)
	}
	stale := maps.Keys(m.known)
	if !m.configured && m.opts.SpoolDir != "" {
		// First configuration after start: also clean up spools of sinks deleted while offline.
		var dirs []string
		if entries, err := os.ReadDir(m.opts.SpoolDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					dirs = append(dirs, e.Name())
				}
			}
		}
		stale = slices.Values(dirs)
	}
	for id := range stale {
		if !ids[id] {
			if err := removeSpool(filepath.Join(m.opts.SpoolDir, id)); err == nil {
				m.log.Info("removed spool of deleted sink", "sink", id)
			}
		}
	}
	m.known, m.configured = ids, true
	for id, s := range want {
		if _, running := m.sinks[id]; running {
			continue
		}
		rt, err := m.start(s)
		if err != nil {
			m.log.Error("export sink not started", "sink", s.Name, "type", s.Type, "error", err)
			m.sinks[id] = &runtime{cfg: s, sig: signature(s), failedStart: err.Error(), done: closedChan()}
			continue
		}
		m.sinks[id] = rt
		m.log.Info("export sink started", "sink", s.Name, "type", s.Type, "streams", s.Streams)
	}
}

func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func (m *Manager) start(s models.ExportSink) (*runtime, error) {
	drv, err := newDriver(s, m.meta, m.opts.ExportDir)
	if err != nil {
		return nil, err
	}
	rt := &runtime{cfg: s, sig: signature(s), drv: drv, meta: m.meta, log: m.log.With("sink", s.Name),
		q: make(chan Event, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	if s.SpoolMB > 0 && m.opts.SpoolDir != "" {
		sp, discarded, err := openSpool(filepath.Join(m.opts.SpoolDir, s.ID), int64(s.SpoolMB)<<20, encodingSignature(s))
		if err != nil {
			return nil, fmt.Errorf("spool: %w", err)
		}
		if discarded > 0 {
			rt.log.Warn("discarded spooled records written with a different encoding", "bytes", discarded)
		}
		rt.spool = sp
	}
	go rt.run()
	return rt, nil
}

// Publish hands an event to every matching sink without blocking.
func (m *Manager) Publish(ev Event) {
	if m == nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rt := range m.sinks {
		if rt.q == nil || !rt.accepts(ev) {
			continue
		}
		select {
		case rt.q <- ev:
		default:
			rt.dropped.Add(1)
		}
	}
}

// Status reports delivery statistics of the running sinks on this node.
func (m *Manager) Status() []models.ExportSinkStatus {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]models.ExportSinkStatus, 0, len(m.sinks))
	for _, rt := range m.sinks {
		out = append(out, rt.status(m.meta.Node))
	}
	slices.SortFunc(out, func(a, b models.ExportSinkStatus) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	return out
}

// Test sends one synthetic record synchronously and returns the destination's verdict.
func (m *Manager) Test(ctx context.Context, s models.ExportSink) error {
	drv, err := newDriver(s, m.meta, m.opts.ExportDir)
	if err != nil {
		return err
	}
	defer drv.close()
	ev := AuditEvent(models.AuditEvent{ID: "aud-export-test", Timestamp: time.Now().UTC(), Actor: "aegisproxy", ActorRole: "SYSTEM",
		Action: "EXPORT_TEST", Category: "SYSTEM", EntityType: "export_sink", EntityID: s.ID, EntityName: s.Name,
		Summary: "Test record from the AegisProxy log export (safe to ignore)"})
	rec, err := drv.encode(ev)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return drv.send(ctx, [][]byte{rec})
}

// Close flushes queues (to the destination or the spool) and stops all sinks.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	select {
	case <-m.quit:
	default:
		close(m.quit)
	}
	<-m.applied
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, rt := range m.sinks {
		rt.shutdown()
		delete(m.sinks, id)
	}
}

// ---------------------------------------------------------------------------
// Sink runtime
// ---------------------------------------------------------------------------

type runtime struct {
	cfg         models.ExportSink
	sig         string
	drv         driver
	meta        Meta
	log         *slog.Logger
	spool       *spool
	q           chan Event
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	failedStart string

	sent, failed, dropped atomic.Uint64

	mu        sync.Mutex
	lastOK    *time.Time
	lastErr   string
	lastErrAt *time.Time
	nextRetry time.Time
	backoff   time.Duration
}

func (rt *runtime) accepts(ev Event) bool {
	if !slices.Contains(rt.cfg.Streams, ev.Stream) {
		return false
	}
	switch ev.Stream {
	case models.StreamTraffic:
		v := ev.Flow.Verdict
		switch rt.cfg.TrafficFilter {
		case "blocked":
			return !models.IsAllowedVerdict(v) && v != models.VerdictSimulatedDryRun
		case "allowed":
			return models.IsAllowedVerdict(v)
		case "security":
			return models.IsSecurityVerdict(v) || len(ev.Flow.SecurityFlags) > 0
		}
		return v != models.VerdictSimulatedDryRun
	case models.StreamSecurity:
		return severityRank[ev.Severity] >= severityRank[rt.cfg.MinSeverity]
	}
	return true
}

func (rt *runtime) batchSize() int {
	if rt.cfg.BatchSize > 0 {
		return rt.cfg.BatchSize
	}
	return 500
}

func (rt *runtime) run() {
	defer close(rt.done)
	flush := time.Duration(max(rt.cfg.FlushSeconds, 1)) * time.Second
	ticker := time.NewTicker(flush)
	defer ticker.Stop()
	batch := make([][]byte, 0, rt.batchSize())
	add := func(ev Event) {
		rec, err := rt.drv.encode(redacted(ev, &rt.cfg))
		if err != nil {
			rt.dropped.Add(1)
			return
		}
		batch = append(batch, rec)
	}
	for {
		select {
		case ev := <-rt.q:
			add(ev)
			if len(batch) >= rt.batchSize() {
				rt.deliver(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				rt.deliver(batch)
				batch = batch[:0]
			}
			rt.drainSpool()
		case <-rt.stop:
			for {
				select {
				case ev := <-rt.q:
					add(ev)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				rt.deliverFinal(batch)
			}
			rt.drv.close()
			if rt.spool != nil {
				_ = rt.spool.Close()
			}
			return
		}
	}
}

func (rt *runtime) spooling() bool {
	if rt.spool == nil {
		return false
	}
	rt.mu.Lock()
	waiting := time.Now().Before(rt.nextRetry)
	rt.mu.Unlock()
	return waiting || !rt.spool.empty()
}

func (rt *runtime) toSpool(batch [][]byte) {
	if rt.spool == nil {
		rt.dropped.Add(uint64(len(batch)))
		return
	}
	if err := rt.spool.Append(batch); err != nil {
		rt.dropped.Add(uint64(len(batch)))
		rt.recordErr("spool write failed: " + err.Error())
	}
	rt.dropped.Add(rt.spool.takeDropped())
}

func (rt *runtime) deliver(batch [][]byte) {
	if rt.spooling() {
		rt.toSpool(batch)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if rt.handle(len(batch), rt.drv.send(ctx, batch)) {
		rt.toSpool(batch)
	}
}

// deliverFinal is used on shutdown: one quick attempt, then the spool.
func (rt *runtime) deliverFinal(batch [][]byte) {
	if rt.spooling() {
		rt.toSpool(batch)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if rt.handle(len(batch), rt.drv.send(ctx, batch)) {
		rt.toSpool(batch)
	}
}

// handle accounts a send result and reports whether the batch must be retried later.
func (rt *runtime) handle(n int, err error) (retry bool) {
	now := time.Now().UTC()
	var pe *permanentError
	var part *partialError
	switch {
	case err == nil:
		rt.sent.Add(uint64(n))
		rt.mu.Lock()
		rt.lastOK, rt.backoff, rt.nextRetry = &now, 0, time.Time{}
		rt.mu.Unlock()
		return false
	case errors.As(err, &part):
		rt.sent.Add(uint64(n - part.rejected))
		rt.failed.Add(uint64(part.rejected))
		rt.mu.Lock()
		rt.lastOK = &now
		rt.mu.Unlock()
		rt.recordErr(part.msg)
		return false
	case errors.As(err, &pe):
		rt.failed.Add(uint64(n))
		rt.recordErr(pe.msg)
		rt.log.Warn("export batch rejected", "records", n, "error", pe.msg)
		return false
	default:
		rt.recordErr(err.Error())
		rt.mu.Lock()
		rt.backoff = min(max(rt.backoff*2, time.Second), 5*time.Minute)
		jitter := time.Duration(rand.Int64N(int64(rt.backoff / 4)))
		rt.nextRetry = time.Now().Add(rt.backoff + jitter)
		rt.mu.Unlock()
		rt.log.Warn("export destination unavailable; spooling", "records", n, "retry_in", rt.backoff.String(), "error", err)
		return true
	}
}

func (rt *runtime) recordErr(msg string) {
	now := time.Now().UTC()
	rt.mu.Lock()
	rt.lastErr, rt.lastErrAt = msg, &now
	rt.mu.Unlock()
}

// drainSpool replays spooled batches in order while the destination accepts them.
func (rt *runtime) drainSpool() {
	if rt.spool == nil {
		return
	}
	rt.mu.Lock()
	wait := time.Now().Before(rt.nextRetry)
	rt.mu.Unlock()
	if wait {
		return
	}
	for i := 0; i < 50; i++ {
		recs, pos, err := rt.spool.Peek(rt.batchSize())
		if err != nil {
			rt.recordErr("spool read failed: " + err.Error())
			return
		}
		if len(recs) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		retry := rt.handle(len(recs), rt.drv.send(ctx, recs))
		cancel()
		if retry {
			return
		}
		rt.spool.Commit(pos)
		select {
		case <-rt.stop:
			return
		default:
		}
	}
}

func (rt *runtime) shutdown() {
	rt.stopOnce.Do(func() {
		if rt.stop != nil {
			close(rt.stop)
		}
	})
	<-rt.done
}

func (rt *runtime) status(node string) models.ExportSinkStatus {
	st := models.ExportSinkStatus{ID: rt.cfg.ID, Node: node, Sent: rt.sent.Load(), Failed: rt.failed.Load(), Dropped: rt.dropped.Load()}
	if rt.failedStart != "" {
		st.State, st.LastError = "error", rt.failedStart
		return st
	}
	st.Queued = len(rt.q)
	if rt.spool != nil {
		st.SpoolRecords, st.SpoolBytes = rt.spool.records()
	}
	rt.mu.Lock()
	st.LastSuccessAt, st.LastError, st.LastErrorAt = rt.lastOK, rt.lastErr, rt.lastErrAt
	retrying := time.Now().Before(rt.nextRetry) || st.SpoolRecords > 0
	rt.mu.Unlock()
	switch {
	case retrying:
		st.State = "retrying"
	case st.LastErrorAt != nil && (st.LastSuccessAt == nil || st.LastErrorAt.After(*st.LastSuccessAt)):
		st.State = "error"
	case st.LastSuccessAt == nil:
		st.State = "idle"
	default:
		st.State = "ok"
	}
	return st
}
