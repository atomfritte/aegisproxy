package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// AuditSource is this node's audit trail, from which sinks replay audit records a crash may have
// lost (the store implements it).
type AuditSource interface {
	// LatestAudit returns the newest audit event of this node.
	LatestAudit() (models.AuditEvent, bool)
	// ReplayAuditAfter streams the events following afterID, oldest first; when afterID is no longer
	// in the trail, the events newer than afterTime.
	ReplayAuditAfter(ctx context.Context, afterID string, afterTime time.Time, fn func(models.AuditEvent) error) (found bool, err error)
}

// Variables for tests.
var (
	auditSourceWait   = time.Minute      // how long a starting sink waits for the audit trail
	replayDedupWindow = 10 * time.Minute // live audit records already replayed are skipped this long
)

// replayDedupMargin: replayed events this much older than the runtime may still arrive live (events
// are published after their store transaction committed).
const replayDedupMargin = time.Minute

// cursorFile holds the audit cursor of a sink in its spool directory: the newest audit record up to
// which every record was delivered, spooled durably or dead-lettered.
const cursorFile = "audit-cursor.json"

type auditMark struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
}

func (a auditMark) equal(b auditMark) bool { return a.ID == b.ID && a.Time.Equal(b.Time) }

func readCursor(path string) (auditMark, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return auditMark{}, err
	}
	var m auditMark
	if err := json.Unmarshal(b, &m); err != nil || (m.ID == "" && m.Time.IsZero()) {
		return auditMark{}, fmt.Errorf("%s: invalid content", filepath.Base(path))
	}
	return m, nil
}

func writeCursor(path string, m auditMark) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileSync(path, b)
}

// SetAuditSource attaches the audit trail (nil detaches it). Starting sinks wait for it up to
// auditSourceWait when Options.AuditReplay is set.
func (m *Manager) SetAuditSource(src AuditSource) {
	if m == nil {
		return
	}
	if src == nil {
		m.source.Store(nil)
		return
	}
	m.source.Store(&src)
	m.sourceOnce.Do(func() { close(m.sourceReady) })
}

func (rt *runtime) waitSource() AuditSource {
	t := time.NewTimer(auditSourceWait)
	defer t.Stop()
	select {
	case <-rt.m.sourceReady:
	case <-rt.ctx.Done():
		return nil
	case <-t.C:
		rt.log.Warn("audit trail not attached: audit records lost in a crash are not replayed in this run")
		return nil
	}
	if p := rt.m.source.Load(); p != nil {
		return *p
	}
	return nil
}

func (rt *runtime) auditCursor() bool {
	return rt.dir != "" && rt.m.opts.AuditReplay && slices.Contains(rt.cfg.Streams, models.StreamAudit)
}

// startAuditCursor loads the audit cursor and replays the audit trail after it. A sink without a
// cursor (new, re-enabled or upgraded) starts at the newest audit event.
func (rt *runtime) startAuditCursor() {
	if rt.dir == "" {
		return
	}
	path := filepath.Join(rt.dir, cursorFile)
	if !rt.auditCursor() {
		_ = os.Remove(path) // a later replay must not start from a stale position
		return
	}
	src := rt.waitSource()
	if src == nil {
		return // the cursor stays: the next start replays from it
	}
	cur, err := readCursor(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rt.log.Error("audit export cursor unreadable; exporting from the newest audit event on", "error", err)
		}
		cur = auditMark{Time: rt.created.UTC()}
		if ev, ok := src.LatestAudit(); ok {
			cur = auditMark{ID: ev.ID, Time: ev.Timestamp}
		}
		if err := writeCursor(path, cur); err != nil {
			rt.log.Error("audit export cursor not writable; audit records lost in a crash are not replayed", "error", err)
			return
		}
		rt.cursorOn, rt.mark, rt.saved = true, cur, cur
		return
	}
	rt.cursorOn, rt.mark, rt.saved = true, cur, cur
	rt.replayAudit(src, cur)
}

// replayAudit sends the audit events after the cursor (delivered or spooled like live records). The
// IDs of recent ones are remembered: their live copies, queued meanwhile, are skipped.
func (rt *runtime) replayAudit(src AuditSource, cur auditMark) {
	since := rt.created.Add(-replayDedupMargin)
	n := 0
	found, err := src.ReplayAuditAfter(rt.ctx, cur.ID, cur.Time, func(a models.AuditEvent) error {
		ev := AuditEvent(a)
		if !ev.Time.Before(since) {
			if rt.replayed == nil {
				rt.replayed = map[string]struct{}{}
			}
			rt.replayed[ev.ID] = struct{}{}
		}
		rt.add(ev, false)
		n++
		if len(rt.batch) >= rt.batchSize() {
			rt.flush()
		}
		return rt.ctx.Err()
	})
	rt.flush()
	rt.replayedN.Add(uint64(n))
	switch {
	case err != nil && rt.ctx.Err() != nil:
		rt.auditGap.Store(true) // stopped during the replay: the next runtime replays from the cursor
	case err != nil:
		rt.markGap("audit replay failed: " + err.Error())
	case !found && cur.ID != "":
		rt.log.Warn("audit export cursor not found in the audit trail (rotated away); replayed the events after its time", "cursor", cur.ID)
	}
	if n > 0 {
		rt.log.Info("replayed audit records from the audit trail", "records", n, "after", cur.ID)
	}
}

// saveCursor persists the audit cursor once every record up to it is settled.
func (rt *runtime) saveCursor() {
	if !rt.cursorOn || len(rt.batch) > 0 || rt.auditGap.Load() || rt.mark.equal(rt.saved) {
		return
	}
	if err := writeCursor(filepath.Join(rt.dir, cursorFile), rt.mark); err != nil {
		rt.log.Warn("audit export cursor not saved", "error", err)
		return
	}
	rt.saved = rt.mark
}

// markGap freezes the audit cursor after an audit record was lost: the next start replays it from the
// audit trail.
func (rt *runtime) markGap(reason string) {
	if rt.auditGap.CompareAndSwap(false, true) && rt.auditCursor() {
		rt.log.Warn("audit records were not exported; the audit cursor keeps its position so that the next start replays them from the audit trail",
			"reason", reason)
	}
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

// AlertEventType is the security event type of export alerts.
const AlertEventType = "EXPORT_DELIVERY"

// Alert reports audit or security records that a sink set aside in its dead-letter file or lost;
// the store raises it as a security event (dashboard, notifications, the export itself).
type Alert struct {
	SinkID   string
	SinkName string
	Severity string // high (dead-lettered) | critical (lost)
	Detail   string // stable per sink and cause (security events are de-duplicated on it)
}

const (
	alertRejected       = "rejected"
	alertUnacknowledged = "unacknowledged"
	alertEvicted        = "evicted"
	alertEncoding       = "encoding"
	alertOversize       = "oversize"
	alertIntegrity      = "integrity"
)

var alertText = map[string]string{
	alertRejected:       "the destination rejected audit/security records permanently",
	alertUnacknowledged: "Splunk did not acknowledge indexing of audit/security records after repeated resends",
	alertEvicted:        "the spool limit was reached and the oldest spooled audit/security records were evicted",
	alertEncoding:       "spooled audit/security records were written in an encoding the destination no longer uses (format, index or source type changed)",
	alertOversize:       "audit/security records exceed the spool record limit",
	alertIntegrity:      "spooled records failed the integrity check (no MAC or a wrong one: modified or added in the spool directory, or spooled by an earlier release) and were not resent",
}

// alertInterval rate-limits alerts per sink and cause.
const alertInterval = time.Minute

// SetAlertHandler sets the receiver of alerts (called on a separate goroutine; nil drops them).
func (m *Manager) SetAlertHandler(fn func(Alert)) {
	if m == nil {
		return
	}
	if fn == nil {
		m.alertFn.Store(nil)
		return
	}
	m.alertFn.Store(&fn)
}

// alertLoop hands alerts to the handler outside of every exporter (and store) lock.
func (m *Manager) alertLoop() {
	defer close(m.alertDone)
	deliver := func(a Alert) {
		if fn := m.alertFn.Load(); fn != nil {
			(*fn)(a)
		}
	}
	for {
		select {
		case a := <-m.alerts:
			deliver(a)
		case <-m.alertQuit:
			for {
				select {
				case a := <-m.alerts:
					deliver(a)
				default:
					return
				}
			}
		}
	}
}

func (rt *runtime) alert(kind string, kept bool) {
	key := fmt.Sprint(kind, kept)
	if last, ok := rt.alerted[key]; ok && time.Since(last) < alertInterval {
		return
	}
	if rt.alerted == nil {
		rt.alerted = map[string]time.Time{}
	}
	rt.alerted[key] = time.Now()
	a := Alert{SinkID: rt.cfg.ID, SinkName: rt.cfg.Name, Severity: "high",
		Detail: fmt.Sprintf("Log export %q: %s; they were moved to its dead-letter file (dead-letter.jsonl in the spool directory)", rt.cfg.Name, alertText[kind])}
	if !kept {
		a.Severity = "critical"
		a.Detail = fmt.Sprintf("Log export %q: %s; they were lost (the dead-letter file is not writable)", rt.cfg.Name, alertText[kind])
	}
	select {
	case rt.m.alerts <- a:
	default:
		rt.log.Warn("export alert dropped (alert queue full)", "detail", a.Detail)
	}
}
