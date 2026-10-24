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
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// queueSize bounds the in-memory queue per sink (a variable for tests).
var queueSize = 20_000

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
			m.log.Error("export sink not started", "sink", s.Name, "type", s.Type, "error", scrubError(s, err.Error()))
			m.sinks[id] = &runtime{cfg: s, sig: signature(s), failedStart: scrubError(s, err.Error()), done: closedChan()}
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
	if m.opts.SpoolDir != "" {
		rt.deadLetterPath = filepath.Join(m.opts.SpoolDir, s.ID, "dead-letter.jsonl")
	}
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
			rt.overflow(ev)
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
	// deadLetterPath keeps permanently rejected batches of audit/security sinks ("" = none).
	deadLetterPath string

	sent, failed, dropped, discarded atomic.Uint64
	lastDropAlert                    atomic.Int64 // unix nanos

	mu        sync.Mutex
	lastOK    *time.Time
	lastErr   string
	lastErrAt *time.Time
	nextRetry time.Time
	backoff   time.Duration
}

// critical streams must not be lost silently: when the in-memory queue is full their records go to
// the spool, and batches the destination rejects are kept in a dead-letter file.
func critical(stream string) bool {
	return stream == models.StreamAudit || stream == models.StreamSecurity
}

// overflow takes an event the full queue cannot hold: audit and security records are spooled to disk
// (behind the records already spooled), traffic records are dropped. Drops are counted and reported
// in the status (at most once a minute).
func (rt *runtime) overflow(ev Event) {
	if critical(ev.Stream) && rt.spool != nil {
		if rec, err := rt.drv.encode(redacted(ev, &rt.cfg)); err == nil && rt.spool.Append([][]byte{rec}) == nil {
			rt.dropped.Add(rt.spool.takeDropped())
			return
		}
	}
	rt.dropped.Add(1)
	now := time.Now().UnixNano()
	if last := rt.lastDropAlert.Load(); now-last >= int64(time.Minute) && rt.lastDropAlert.CompareAndSwap(last, now) {
		msg := fmt.Sprintf("export queue full (%d events): records are being dropped (%d so far); the destination is too slow or unreachable",
			queueSize, rt.dropped.Load())
		rt.recordErr(msg)
		rt.log.Warn(msg, "stream", ev.Stream)
	}
}

// deadLetterMax bounds the dead-letter file; one older generation (.1) is kept.
const deadLetterMax = 32 << 20

// deadLetter appends a batch the destination rejected permanently to <spool dir>/dead-letter.jsonl
// when the sink carries audit or security records (one JSON object per batch, records as text), so
// they can be inspected and replayed. It reports whether the batch was kept.
func (rt *runtime) deadLetter(batch [][]byte, reason string) bool {
	if rt.deadLetterPath == "" || !slices.ContainsFunc(rt.cfg.Streams, critical) {
		return false
	}
	recs := make([]string, len(batch))
	for i, r := range batch {
		recs[i] = strings.TrimRight(string(r), "\n")
	}
	line, err := json.Marshal(map[string]any{"discarded_at": time.Now().UTC(), "sink_id": rt.cfg.ID, "sink": rt.cfg.Name,
		"error": scrubError(rt.cfg, reason), "records": recs})
	if err != nil {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(rt.deadLetterPath), 0o700); err != nil {
		rt.log.Error("dead-letter file not writable", "error", err)
		return false
	}
	if fi, err := os.Stat(rt.deadLetterPath); err == nil && fi.Size()+int64(len(line)) > deadLetterMax {
		_ = os.Rename(rt.deadLetterPath, rt.deadLetterPath+".1")
	}
	f, err := os.OpenFile(rt.deadLetterPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		rt.log.Error("dead-letter file not writable", "error", err)
		return false
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		rt.log.Error("dead-letter write failed", "error", err)
		return false
	}
	return true
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

// deliveryTimeout bounds one delivery attempt (a variable for tests).
var deliveryTimeout = 30 * time.Second

func (rt *runtime) deliver(batch [][]byte) {
	if rt.spooling() {
		rt.toSpool(batch)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
	defer cancel()
	if rt.handle(batch, rt.drv.send(ctx, batch)) {
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
	if rt.handle(batch, rt.drv.send(ctx, batch)) {
		rt.toSpool(batch)
	}
}

// handle accounts a send result and reports whether the batch must be retried later.
func (rt *runtime) handle(batch [][]byte, err error) (retry bool) {
	n := len(batch)
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
		rt.discarded.Add(1)
		rt.recordErr(pe.msg)
		kept := rt.deadLetter(batch, pe.msg)
		rt.log.Warn("export batch rejected", "records", n, "dead_letter", kept, "error", scrubError(rt.cfg, pe.msg))
		return false
	default:
		rt.recordErr(err.Error())
		rt.mu.Lock()
		rt.backoff = min(max(rt.backoff*2, time.Second), 5*time.Minute)
		jitter := time.Duration(rand.Int64N(int64(rt.backoff / 4)))
		rt.nextRetry = time.Now().Add(rt.backoff + jitter)
		rt.mu.Unlock()
		rt.log.Warn("export destination unavailable; spooling", "records", n, "retry_in", rt.backoff.String(), "error", scrubError(rt.cfg, err.Error()))
		return true
	}
}

func (rt *runtime) recordErr(msg string) {
	now := time.Now().UTC()
	msg = scrubError(rt.cfg, msg)
	rt.mu.Lock()
	rt.lastErr, rt.lastErrAt = msg, &now
	rt.mu.Unlock()
}

var urlWithQuery = regexp.MustCompile(`(https?://[^\s?#"'<>]+)\?[^\s"'<>]*`)

// scrubError removes credentials from a delivery error before it is stored, shown or logged
// (defense in depth; drivers already name destinations without them): the configured endpoint is
// replaced by its masked form and query strings of any URL are hidden.
func scrubError(s models.ExportSink, msg string) string {
	if s.Endpoint != "" && s.Type != "syslog" && s.Type != "file" {
		if masked := models.MaskSinkEndpoint(s.Type, s.Endpoint); masked != s.Endpoint {
			msg = strings.ReplaceAll(msg, s.Endpoint, masked)
		}
	}
	return urlWithQuery.ReplaceAllString(msg, "$1?"+models.MaskedSecretMarker)
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
		ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
		retry := rt.handle(recs, rt.drv.send(ctx, recs))
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
	st := models.ExportSinkStatus{ID: rt.cfg.ID, Node: node, Sent: rt.sent.Load(), Failed: rt.failed.Load(), Dropped: rt.dropped.Load(),
		DiscardedBatches: rt.discarded.Load()}
	if rt.failedStart != "" {
		st.State, st.LastError = "error", rt.failedStart // scrubbed when recorded
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
