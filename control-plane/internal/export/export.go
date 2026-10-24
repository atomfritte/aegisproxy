// Package export forwards audit, traffic and security records to external systems (SIEM, log
// platforms, OpenTelemetry). Every sink has a bounded in-memory queue, batches records, and keeps
// undeliverable records in a durable on-disk spool that is replayed in order once the destination
// is reachable again (at-least-once delivery). Sinks carrying audit records also keep a cursor into
// the local audit trail and replay what follows it at start, so a crash loses no audit record.
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// Variables for tests.
var (
	queueSize       = 20_000           // in-memory queue per sink
	deliveryTimeout = 30 * time.Second // one delivery attempt
	closeTimeout    = 5 * time.Second  // final delivery attempts on shutdown; the rest is spooled
	pendingRetry    = time.Second      // next attempt while a confirmation (Splunk ackId) is outstanding
)

type Options struct {
	SpoolDir  string // per-sink spools: <SpoolDir>/<sink id>
	ExportDir string // base directory of "file" sinks
	Node      string // cluster node / instance id
	Host      string // host name (syslog HOSTNAME, resource attributes)
	Version   string
	Logger    *slog.Logger
	// AuditReplay keeps an audit cursor per sink carrying audit records (in its spool directory) and
	// replays the audit trail attached with SetAuditSource after it at start.
	AuditReplay bool
	// HECAckAttempts is the number of indexer acknowledgement timeouts after which Splunk HEC records
	// are set aside in the dead-letter file (0 = 5).
	HECAckAttempts int
}

type Manager struct {
	opts       Options
	meta       Meta
	log        *slog.Logger
	cfgMu      sync.Mutex // serializes Configure and Close; never taken by Publish
	mu         sync.RWMutex
	sinks      map[string]*runtime
	known      map[string]bool // ids present in the last configuration (deleted sinks lose their spool)
	configured bool
	closed     bool

	pending   atomic.Pointer[[]models.ExportSink]
	signal    chan struct{}
	quit      chan struct{}
	applied   chan struct{}
	closeOnce sync.Once

	source      atomic.Pointer[AuditSource]
	sourceReady chan struct{}
	sourceOnce  sync.Once

	alertFn   atomic.Pointer[func(Alert)]
	alerts    chan Alert
	alertQuit chan struct{}
	alertDone chan struct{}
}

func New(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	m := &Manager{opts: opts, meta: Meta{Node: opts.Node, Host: opts.Host, Version: opts.Version},
		log: opts.Logger.With("component", "export"), sinks: map[string]*runtime{}, known: map[string]bool{},
		signal: make(chan struct{}, 1), quit: make(chan struct{}), applied: make(chan struct{}), sourceReady: make(chan struct{}),
		alerts: make(chan Alert, 64), alertQuit: make(chan struct{}), alertDone: make(chan struct{})}
	go m.applyLoop()
	go m.alertLoop()
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

// legacyKey identifies the record encoding of spools written by release 2.0 and earlier (see
// legacyEncoding): their records are resent unchanged only while it still matches.
func legacyKey(s models.ExportSink) string {
	return fmt.Sprintf("v1|%s|%s|%s|%s|%s|%s", s.Type, s.Format, s.SyslogProtocol, s.SyslogFacility, s.Index, s.SourceType)
}

type stopMode int

const (
	stopClose       stopMode = iota // shutdown: quick final attempts, the rest is spooled
	stopReconfigure                 // replaced by a new configuration: records go to the spool for it
	stopDisable                     // disabled: like stopClose, and the audit cursor is dropped
	stopDelete                      // deleted: records, spool and cursor are discarded
)

// Configure applies the sink list (called whenever the replicated configuration changes). The sink
// table is swapped under the lock; replaced runtimes are stopped outside of it, so Publish never
// waits for a destination. A new runtime of a sink takes over only after its predecessor handed
// over its records.
func (m *Manager) Configure(sinks []models.ExportSink) {
	if m == nil {
		return
	}
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	want := map[string]models.ExportSink{}
	ids := map[string]bool{}
	for _, s := range sinks {
		ids[s.ID] = true
		if s.Enabled {
			want[s.ID] = s
		}
	}
	type stopping struct {
		rt   *runtime
		mode stopMode
	}
	var stops []stopping
	var started []*runtime
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	prev := map[string]*runtime{}
	for id, rt := range m.sinks {
		s, ok := want[id]
		if ok && rt.sig == signature(s) {
			continue
		}
		mode := stopReconfigure
		switch {
		case !ids[id]:
			mode = stopDelete
		case !ok:
			mode = stopDisable
		case s.SpoolMB == 0:
			mode = stopClose // no spool to hand the records over in
		}
		stops = append(stops, stopping{rt, mode})
		prev[id] = rt
		delete(m.sinks, id)
	}
	for id, s := range want {
		if _, running := m.sinks[id]; running {
			continue
		}
		rt, err := m.newRuntime(s, prev[id])
		if err != nil {
			msg := scrubError(s, err.Error())
			m.log.Error("export sink not started", "sink", s.Name, "type", s.Type, "error", msg)
			m.sinks[id] = &runtime{cfg: s, sig: signature(s), failedStart: msg, done: closedChan()}
			continue
		}
		m.sinks[id] = rt
		started = append(started, rt)
	}
	stale := slices.Collect(maps.Keys(m.known))
	if !m.configured && m.opts.SpoolDir != "" {
		// First configuration after start: also clean up spools of sinks deleted while offline.
		stale = nil
		if entries, err := os.ReadDir(m.opts.SpoolDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					stale = append(stale, e.Name())
				}
			}
		}
	}
	m.known, m.configured = ids, true
	m.mu.Unlock()

	for _, st := range stops {
		st.rt.requestStop(st.mode)
	}
	for _, rt := range started {
		go rt.run()
		m.log.Info("export sink started", "sink", rt.cfg.Name, "type", rt.cfg.Type, "streams", rt.cfg.Streams)
	}
	for _, st := range stops {
		<-st.rt.done
	}
	if m.opts.SpoolDir == "" {
		return
	}
	for _, id := range stale {
		if !ids[id] {
			if err := removeSpool(filepath.Join(m.opts.SpoolDir, id)); err == nil {
				m.log.Info("removed spool of deleted sink", "sink", id)
			}
		}
	}
	for id := range ids {
		if _, on := want[id]; !on {
			// Disabled (possibly while this node was down): a later re-enable starts at the newest
			// audit event instead of replaying the paused period.
			_ = os.Remove(filepath.Join(m.opts.SpoolDir, id, cursorFile))
		}
	}
}

func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func (m *Manager) newRuntime(s models.ExportSink, prev *runtime) (*runtime, error) {
	drv, err := newDriver(s, m.meta, m.opts.ExportDir)
	if err != nil {
		return nil, err
	}
	if hec, ok := drv.(*splunkDriver); ok {
		hec.ackAttempts = m.opts.HECAckAttempts
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt := &runtime{m: m, cfg: s, sig: signature(s), drv: drv, meta: m.meta, log: m.log.With("sink", s.Name),
		q: make(chan Event, queueSize), stop: make(chan struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel,
		prev: prev, created: time.Now()}
	if m.opts.SpoolDir != "" {
		rt.dir = filepath.Join(m.opts.SpoolDir, s.ID)
		rt.deadLetterPath = filepath.Join(rt.dir, "dead-letter.jsonl")
	}
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
			if !rt.overflow(ev) && ev.Stream == models.StreamAudit {
				rt.markGap("queue full")
			}
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

// Close stops all sinks: queued records get quick final delivery attempts (batch by batch, within
// closeTimeout), the rest goes to the spool.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.quit)
		<-m.applied
		m.cfgMu.Lock()
		m.mu.Lock()
		m.closed = true
		rts := slices.Collect(maps.Values(m.sinks))
		m.sinks = map[string]*runtime{}
		m.mu.Unlock()
		for _, rt := range rts {
			rt.requestStop(stopClose)
		}
		for _, rt := range rts {
			<-rt.done
		}
		m.cfgMu.Unlock()
		close(m.alertQuit)
		<-m.alertDone
	})
}

// ---------------------------------------------------------------------------
// Sink runtime
// ---------------------------------------------------------------------------

type runtime struct {
	m           *Manager
	cfg         models.ExportSink
	sig         string
	drv         driver
	meta        Meta
	log         *slog.Logger
	sp          atomic.Pointer[spool] // opened by the run goroutine
	q           chan Event
	stop        chan struct{}
	done        chan struct{}
	ctx         context.Context // canceled on stop: aborts the delivery attempt in flight
	cancel      context.CancelFunc
	stopOnce    sync.Once
	mode        stopMode
	prev        *runtime // previous runtime of this sink; must finish before this one starts
	created     time.Time
	failedStart string
	dir         string // <SpoolDir>/<id> ("" = nothing persisted)
	// deadLetterPath keeps records of audit/security sinks that cannot be delivered ("" = none).
	deadLetterPath string

	// Owned by the run goroutine.
	batch        []record
	cursorOn     bool      // the audit cursor is maintained in this run
	mark, saved  auditMark // last settled audit record, last saved cursor
	replayed     map[string]struct{}
	alerted      map[string]time.Time
	lastEvictLog time.Time

	auditGap atomic.Bool // an audit record was lost: the cursor stays until the next start

	sent, failed, dropped, discarded, replayedN, deadLettered atomic.Uint64
	lastDropAlert                                             atomic.Int64 // unix nanos

	mu        sync.Mutex
	lastOK    *time.Time
	lastErr   string
	lastErrAt *time.Time
	nextRetry time.Time
	backoff   time.Duration
}

// record is an event on its way to the destination.
type record struct {
	ev    Event
	data  []byte // encoded for the destination
	raw   bool   // legacy spool record: only data is known
	track bool   // audit record that moves the audit cursor once settled
}

// critical streams must not be lost silently: when the in-memory queue is full their records go to
// the spool, and records the destination rejects are kept in a dead-letter file.
func critical(stream string) bool {
	return stream == models.StreamAudit || stream == models.StreamSecurity
}

func isCritical(r record) bool { return r.raw || critical(r.ev.Stream) }

func datas(recs []record) [][]byte {
	out := make([][]byte, len(recs))
	for i, r := range recs {
		out[i] = r.data
	}
	return out
}

// spoolData is the spool form of a record: the event itself, so that it is encoded for the
// destination configured when it is sent.
func spoolData(r record) []byte {
	if r.raw {
		return r.data
	}
	b, _ := json.Marshal(r.ev)
	return append([]byte{eventMarker}, b...)
}

var errLegacyEncoding = errors.New("spooled by an earlier release in an encoding this destination no longer uses (format, index or source type changed); not resent")

// fromSpool turns a spooled record into a record for the current destination. On error the record
// still carries what is known, for the dead-letter file.
func (rt *runtime) fromSpool(sp *spool, data []byte) (record, error) {
	if len(data) == 0 || data[0] != eventMarker {
		r := record{data: data, raw: true}
		if sp.legacyKey != legacyKey(rt.cfg) {
			return r, errLegacyEncoding
		}
		return r, nil
	}
	var ev Event
	if err := json.Unmarshal(data[1:], &ev); err != nil {
		return record{data: data[1:], raw: true}, fmt.Errorf("unreadable spool record: %v", err)
	}
	ev = redacted(ev, &rt.cfg)
	r := record{ev: ev}
	enc, err := rt.drv.encode(ev)
	if err != nil {
		return r, fmt.Errorf("encoding failed: %v", err)
	}
	r.data = enc
	return r, nil
}

// overflow takes an event the full queue cannot hold: audit and security records are spooled to disk
// (behind the records already spooled), traffic records are dropped. Drops are counted and reported
// in the status (at most once a minute). It reports whether the event was kept.
func (rt *runtime) overflow(ev Event) bool {
	if critical(ev.Stream) {
		if sp := rt.sp.Load(); sp != nil {
			if b, err := json.Marshal(redacted(ev, &rt.cfg)); err == nil {
				if big, err := sp.Append([][]byte{append([]byte{eventMarker}, b...)}, true); err == nil && len(big) == 0 {
					return true
				}
			}
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
	return false
}

// deadLetter appends records that cannot be delivered to <spool dir>/dead-letter.jsonl when the sink
// carries audit or security records (one JSON object per batch, records as text, per-record errors
// when known), so they can be inspected and replayed. It reports whether the records were kept.
func (rt *runtime) deadLetter(recs []record, reasons []string, reason string) bool {
	if rt.deadLetterPath == "" || len(recs) == 0 || !slices.ContainsFunc(rt.cfg.Streams, critical) {
		return false
	}
	texts := make([]string, len(recs))
	for i, r := range recs {
		texts[i] = rt.recordText(r)
	}
	entry := map[string]any{"discarded_at": time.Now().UTC(), "sink_id": rt.cfg.ID, "sink": rt.cfg.Name,
		"error": scrubError(rt.cfg, reason), "records": texts}
	if reasons != nil {
		scrubbed := make([]string, len(reasons))
		for i, r := range reasons {
			scrubbed[i] = scrubError(rt.cfg, r)
		}
		entry["record_errors"] = scrubbed
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return false
	}
	if err := appendDeadLetter(rt.deadLetterPath, append(line, '\n')); err != nil {
		rt.log.Error("dead-letter file not writable; records lost", "records", len(recs), "error", err)
		return false
	}
	rt.deadLettered.Add(uint64(len(recs)))
	return true
}

// recordText is a record as sent to the destination (as the event when it could not be encoded).
func (rt *runtime) recordText(r record) string {
	if r.data != nil {
		return strings.TrimRight(string(r.data), "\n")
	}
	b, _ := json.Marshal(r.ev)
	return string(b)
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
	if rt.prev != nil {
		<-rt.prev.done // the previous runtime of this sink hands over its records and spool first
		rt.prev = nil
	}
	rt.open()
	ticker := time.NewTicker(time.Duration(max(rt.cfg.FlushSeconds, 1)) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case ev := <-rt.q:
			rt.add(ev, true)
			if len(rt.batch) >= rt.batchSize() {
				rt.flush()
			}
		case <-ticker.C:
			rt.flush()
			rt.processEvicted()
			rt.drainSpool()
			rt.saveCursor()
			if rt.replayed != nil && time.Since(rt.created) > replayDedupWindow {
				rt.replayed = nil
			}
		case <-rt.stop:
			rt.finish()
			return
		}
	}
}

// open prepares the spool and the audit cursor (replaying the audit trail after it).
func (rt *runtime) open() {
	if rt.dir != "" && rt.cfg.SpoolMB > 0 {
		sp, err := openSpool(rt.dir, int64(rt.cfg.SpoolMB)<<20)
		if err != nil {
			rt.recordErr("spool: " + err.Error())
			rt.log.Error("export spool not available; undeliverable records are dropped", "error", err)
		} else {
			rt.sp.Store(sp)
			if n, _ := sp.records(); n > 0 {
				rt.log.Info("spooled records pending", "records", n)
			}
		}
	}
	rt.processEvicted()
	rt.startAuditCursor()
}

// add encodes an event into the batch.
func (rt *runtime) add(ev Event, live bool) {
	ev = redacted(ev, &rt.cfg)
	r := record{ev: ev, track: rt.cursorOn && ev.Stream == models.StreamAudit}
	if live && rt.replayed != nil && ev.Stream == models.StreamAudit {
		if _, dup := rt.replayed[ev.ID]; dup { // already replayed from the audit trail
			delete(rt.replayed, ev.ID)
			rt.settle([]record{r}, false)
			return
		}
	}
	data, err := rt.drv.encode(ev)
	if err != nil {
		rt.unsendable([]record{r}, []string{"encoding failed: " + err.Error()}, alertRejected)
		return
	}
	r.data = data
	rt.batch = append(rt.batch, r)
}

// settle accounts records whose fate is decided (delivered, spooled durably, dead-lettered or lost)
// for the audit cursor; records are settled in order.
func (rt *runtime) settle(recs []record, lost bool) {
	for _, r := range recs {
		if !r.track {
			continue
		}
		if lost {
			rt.markGap("audit record not delivered, spooled or dead-lettered")
			continue
		}
		rt.mark = auditMark{ID: r.ev.ID, Time: r.ev.Time}
	}
}

// unsendable sets aside records that cannot be sent at all (encoding failed, unreadable, spooled in
// an encoding the destination no longer uses).
func (rt *runtime) unsendable(recs []record, reasons []string, kind string) {
	kept := rt.deadLetter(recs, reasons, reasons[0])
	if !kept {
		rt.dropped.Add(uint64(len(recs)))
	}
	rt.recordErr(reasons[0])
	rt.log.Warn("export records cannot be sent", "records", len(recs), "dead_letter", kept, "error", scrubError(rt.cfg, reasons[0]))
	if slices.ContainsFunc(recs, isCritical) {
		rt.alert(kind, kept)
	}
	rt.settle(recs, !kept)
}

func (rt *runtime) waiting() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return time.Now().Before(rt.nextRetry)
}

func (rt *runtime) spooling() bool {
	sp := rt.sp.Load()
	return sp != nil && (rt.waiting() || !sp.empty())
}

// toSpool keeps records for a later attempt (durably when they include audit or security records).
func (rt *runtime) toSpool(recs []record) {
	if len(recs) == 0 {
		return
	}
	sp := rt.sp.Load()
	if sp == nil {
		rt.dropped.Add(uint64(len(recs)))
		rt.settle(recs, true)
		return
	}
	data := make([][]byte, len(recs))
	for i, r := range recs {
		data[i] = spoolData(r)
	}
	oversize, err := sp.Append(data, slices.ContainsFunc(recs, isCritical))
	if err != nil {
		rt.dropped.Add(uint64(len(recs)))
		rt.recordErr("spool write failed: " + err.Error())
		rt.log.Error("spool write failed; records dropped", "records", len(recs), "error", err)
		rt.settle(recs, true)
		return
	}
	keptBig := false
	if len(oversize) > 0 {
		big := make([]record, len(oversize))
		for i, j := range oversize {
			big[i] = recs[j]
		}
		reason := fmt.Sprintf("record larger than the spool record limit (%d bytes)", maxRecordSize)
		keptBig = rt.deadLetter(big, nil, reason)
		if !keptBig {
			rt.dropped.Add(uint64(len(big)))
		}
		rt.recordErr(reason)
		rt.log.Error("export record too large for the spool", "records", len(big), "dead_letter", keptBig)
		if slices.ContainsFunc(big, isCritical) {
			rt.alert(alertOversize, keptBig)
		}
	}
	for i := range recs {
		rt.settle(recs[i:i+1], slices.Contains(oversize, i) && !keptBig)
	}
}

// flush delivers the batch, or spools it while the destination is unavailable.
func (rt *runtime) flush() {
	if len(rt.batch) == 0 {
		return
	}
	b := rt.batch
	if rt.spooling() {
		rt.batch = nil
		rt.toSpool(b)
		return
	}
	ctx, cancel := context.WithTimeout(rt.ctx, deliveryTimeout)
	err := rt.drv.send(ctx, datas(b))
	cancel()
	if err != nil && rt.ctx.Err() != nil {
		return // stopping: finish() decides about the batch
	}
	rt.batch = nil
	from := rt.handle(b, err)
	rt.toSpool(b[from:])
}

// deliverWithin is used on shutdown: quick attempts batch by batch until the deadline, then the spool.
func (rt *runtime) deliverWithin(d time.Duration) {
	deadline := time.Now().Add(d)
	b := rt.batch
	for len(b) > 0 && !rt.spooling() && time.Now().Before(deadline) {
		chunk := b[:min(len(b), rt.batchSize())]
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		err := rt.drv.send(ctx, datas(chunk))
		cancel()
		from := rt.handle(chunk, err)
		b = b[from:]
		if from < len(chunk) {
			break
		}
	}
	rt.toSpool(b)
}

// handle accounts a send result and returns the index from which the batch must be retried later
// (len(batch) when every record was delivered or set aside).
func (rt *runtime) handle(batch []record, err error) int {
	n := len(batch)
	now := time.Now().UTC()
	var pe *permanentError
	var part *partialError
	var pend *pendingError
	switch {
	case err == nil:
		rt.sent.Add(uint64(n))
		rt.mu.Lock()
		rt.lastOK, rt.backoff, rt.nextRetry = &now, 0, time.Time{}
		rt.mu.Unlock()
		rt.settle(batch, false)
		return n
	case errors.As(err, &part):
		from := min(max(part.retryFrom, 0), n)
		idx := slices.Sorted(maps.Keys(part.rejected))
		var rej []record
		var reasons []string
		for _, i := range idx {
			if i >= 0 && i < from {
				rej = append(rej, batch[i])
				reasons = append(reasons, part.rejected[i])
			}
		}
		if delivered := from - len(rej); delivered > 0 {
			rt.sent.Add(uint64(delivered))
			rt.mu.Lock()
			rt.lastOK = &now
			rt.mu.Unlock()
		}
		rt.failed.Add(uint64(len(rej)))
		rt.recordErr(part.msg)
		kept := rt.deadLetter(rej, reasons, part.msg)
		rt.log.Warn("export records rejected", "records", len(rej), "dead_letter", kept, "error", scrubError(rt.cfg, part.msg))
		if slices.ContainsFunc(rej, isCritical) {
			rt.alert(part.kind, kept)
		}
		for i := 0; i < from; i++ {
			_, rejected := part.rejected[i]
			rt.settle(batch[i:i+1], rejected && !kept)
		}
		return from
	case errors.As(err, &pe):
		rt.failed.Add(uint64(n))
		rt.discarded.Add(1)
		rt.recordErr(pe.msg)
		kept := rt.deadLetter(batch, nil, pe.msg)
		rt.log.Warn("export batch rejected", "records", n, "dead_letter", kept, "error", scrubError(rt.cfg, pe.msg))
		if slices.ContainsFunc(batch, isCritical) {
			rt.alert(alertRejected, kept)
		}
		rt.settle(batch, !kept)
		return n
	case errors.As(err, &pend):
		rt.recordErr(pend.msg)
		rt.mu.Lock()
		rt.nextRetry = time.Now().Add(pendingRetry)
		rt.mu.Unlock()
		rt.log.Info("waiting for the destination to confirm records", "records", n, "detail", scrubError(rt.cfg, pend.msg))
		return 0
	default:
		rt.recordErr(err.Error())
		rt.mu.Lock()
		rt.backoff = min(max(rt.backoff*2, time.Second), 5*time.Minute)
		jitter := time.Duration(rand.Int64N(int64(rt.backoff / 4)))
		rt.nextRetry = time.Now().Add(rt.backoff + jitter)
		rt.mu.Unlock()
		rt.log.Warn("export destination unavailable; spooling", "records", n, "retry_in", rt.backoff.String(), "error", scrubError(rt.cfg, err.Error()))
		return 0
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

// drainSpool replays spooled records in order while the destination accepts them.
func (rt *runtime) drainSpool() {
	sp := rt.sp.Load()
	if sp == nil || rt.waiting() {
		return
	}
	for i := 0; i < 50 && rt.ctx.Err() == nil; i++ {
		peek, err := sp.Peek(rt.batchSize())
		if err != nil {
			rt.recordErr("spool read failed: " + err.Error())
			return
		}
		if len(peek) == 0 {
			return
		}
		var batch, bad []record
		var at, badAt []int
		var badReasons []string
		for j, p := range peek {
			r, err := rt.fromSpool(sp, p.data)
			if err != nil {
				bad, badAt, badReasons = append(bad, r), append(badAt, j), append(badReasons, err.Error())
				continue
			}
			batch, at = append(batch, r), append(at, j)
		}
		cut := len(peek)
		if len(batch) > 0 {
			ctx, cancel := context.WithTimeout(rt.ctx, deliveryTimeout)
			err := rt.drv.send(ctx, datas(batch))
			cancel()
			if err != nil && rt.ctx.Err() != nil {
				return // stopping: the records stay spooled
			}
			if from := rt.handle(batch, err); from < len(batch) {
				cut = at[from]
			}
		}
		// Unsendable records before the cut are set aside now; the others when the cut passes them.
		if k := sort.SearchInts(badAt, cut); k > 0 {
			kind := alertRejected
			if slices.Contains(badReasons[:k], errLegacyEncoding.Error()) {
				kind = alertEncoding
			}
			rt.unsendable(bad[:k], badReasons[:k], kind)
		}
		sp.Commit(peek[:cut])
		if cut < len(peek) && rt.waiting() {
			return
		}
	}
}

// processEvicted dead-letters the audit and security records of spool segments evicted by the size
// limit; every evicted record counts as dropped.
func (rt *runtime) processEvicted() {
	sp := rt.sp.Load()
	if sp == nil {
		return
	}
	for _, e := range sp.takeEvicted() {
		var keep []record
		total := 0
		err := readSegment(e.path, e.from, func(data []byte) {
			total++
			if r, _ := rt.fromSpool(sp, data); isCritical(r) {
				keep = append(keep, r)
			}
		})
		if err != nil {
			rt.log.Error("evicted spool segment unreadable", "error", err)
		}
		kept := rt.deadLetter(keep, nil, "spool limit reached: the oldest spooled records were evicted")
		rt.dropped.Add(uint64(total))
		if !kept && slices.ContainsFunc(keep, func(r record) bool { return r.raw || r.ev.Stream == models.StreamAudit }) {
			rt.markGap("evicted audit records could not be dead-lettered")
		}
		moved := 0
		if kept {
			moved = len(keep)
		}
		msg := fmt.Sprintf("spool limit (%d MiB) reached: %d records evicted (%d audit/security records moved to the dead-letter file)",
			rt.cfg.SpoolMB, total, moved)
		rt.recordErr(msg)
		if time.Since(rt.lastEvictLog) >= time.Minute {
			rt.lastEvictLog = time.Now()
			rt.log.Error("export "+msg, "dead_letter", kept)
		}
		if len(keep) > 0 {
			rt.alert(alertEvicted, kept)
		}
		_ = os.Remove(e.path)
	}
}

func (rt *runtime) requestStop(mode stopMode) {
	rt.stopOnce.Do(func() {
		rt.mode = mode
		if rt.cancel != nil {
			rt.cancel()
		}
		if rt.stop != nil {
			close(rt.stop)
		}
	})
}

// finish runs when the runtime stops: the queue is taken over and the records are handed on
// according to the stop mode.
func (rt *runtime) finish() {
	for {
		select {
		case ev := <-rt.q:
			rt.add(ev, true)
			continue
		default:
		}
		break
	}
	switch rt.mode {
	case stopDelete:
		// Deleted: the records go with the sink.
	case stopReconfigure:
		if rt.sp.Load() != nil {
			rt.toSpool(rt.batch) // the new runtime delivers them first
			break
		}
		rt.deliverWithin(closeTimeout)
	default:
		rt.deliverWithin(closeTimeout)
	}
	rt.batch = nil
	if rt.mode != stopDelete {
		rt.processEvicted()
	}
	switch rt.mode {
	case stopDelete, stopDisable:
		if rt.dir != "" {
			_ = os.Remove(filepath.Join(rt.dir, cursorFile))
		}
	default:
		rt.saveCursor()
	}
	rt.drv.close()
	if sp := rt.sp.Load(); sp != nil {
		_ = sp.Close()
	}
}

func (rt *runtime) status(node string) models.ExportSinkStatus {
	st := models.ExportSinkStatus{ID: rt.cfg.ID, Node: node, Sent: rt.sent.Load(), Failed: rt.failed.Load(), Dropped: rt.dropped.Load(),
		DiscardedBatches: rt.discarded.Load(), Replayed: rt.replayedN.Load(), DeadLettered: rt.deadLettered.Load()}
	if rt.failedStart != "" {
		st.State, st.LastError = "error", rt.failedStart // scrubbed when recorded
		return st
	}
	st.Queued = len(rt.q)
	if sp := rt.sp.Load(); sp != nil {
		st.SpoolRecords, st.SpoolBytes = sp.records()
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
