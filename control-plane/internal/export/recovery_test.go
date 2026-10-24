package export

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// fakeTrail is an audit trail for replay tests (oldest first).
type fakeTrail struct {
	mu     sync.Mutex
	events []models.AuditEvent
}

func (f *fakeTrail) add(ev models.AuditEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeTrail) LatestAudit() (models.AuditEvent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return models.AuditEvent{}, false
	}
	return f.events[len(f.events)-1], true
}

func (f *fakeTrail) ReplayAuditAfter(ctx context.Context, afterID string, afterTime time.Time, fn func(models.AuditEvent) error) (bool, error) {
	f.mu.Lock()
	events := slices.Clone(f.events)
	f.mu.Unlock()
	found := false
	for _, ev := range events {
		switch {
		case found:
		case ev.ID == afterID:
			found = true
			continue
		case !ev.Timestamp.After(afterTime):
			continue
		}
		if err := fn(ev); err != nil {
			return found, err
		}
	}
	return found, ctx.Err()
}

// alertLog collects the alerts of a manager.
type alertLog struct {
	mu     sync.Mutex
	alerts []Alert
}

func (a *alertLog) add(al Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, al)
}

func (a *alertLog) find(substr string) *Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.alerts {
		if strings.Contains(a.alerts[i].Detail, substr) {
			al := a.alerts[i]
			return &al
		}
	}
	return nil
}

type deadLetterEntry struct {
	SinkID       string   `json:"sink_id"`
	Error        string   `json:"error"`
	Records      []string `json:"records"`
	RecordErrors []string `json:"record_errors"`
}

func readDeadLetters(t *testing.T, path string) []deadLetterEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	defer f.Close()
	var out []deadLetterEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		var e deadLetterEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func statusOf(m *Manager, id string) models.ExportSinkStatus {
	for _, st := range m.Status() {
		if st.ID == id {
			return st
		}
	}
	return models.ExportSinkStatus{}
}

func cursorID(dir string) string {
	c, _ := readCursor(filepath.Join(dir, cursorFile))
	return c.ID
}

// #4: audit records still in memory when the process dies are replayed from the audit trail by the
// next start (the cursor only covers records that were delivered, spooled durably or dead-lettered).
func TestAuditReplayAfterCrash(t *testing.T) {
	var got webhookEvents
	var hang atomic.Bool
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hang.Load() {
			<-block
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got.add(r)
	}))
	defer srv.Close()
	defer close(block)
	spoolDir := filepath.Join(t.TempDir(), "export-spool")
	sink := models.ExportSink{ID: "exp-crash", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL, BatchSize: 10, FlushSeconds: 1}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	sink.SpoolMB = 0 // nothing on disk: only the cursor and the trail recover the records
	sinkDir := filepath.Join(spoolDir, sink.ID)
	trail := &fakeTrail{}
	emit := func(m *Manager, id string) {
		ev := models.AuditEvent{ID: id, Timestamp: time.Now().UTC(), Actor: "admin", Action: "X"}
		trail.add(ev)
		m.Publish(AuditEvent(ev))
	}
	trail.add(models.AuditEvent{ID: "before-sink", Timestamp: time.Now().UTC().Add(-time.Hour)})
	opts := Options{SpoolDir: spoolDir, Node: "n1", Version: "t", AuditReplay: true}

	m1 := New(opts)
	m1.SetAuditSource(trail)
	m1.Configure([]models.ExportSink{sink})
	waitFor(t, "cursor initialized at the newest audit event", func() bool { return cursorID(sinkDir) == "before-sink" })
	for i := 0; i < 3; i++ {
		emit(m1, fmt.Sprintf("a%d", i))
	}
	waitFor(t, "first records delivered", func() bool { return len(got.list()) == 3 })
	waitFor(t, "cursor advanced", func() bool { return cursorID(sinkDir) == "a2" })

	// The destination stalls: a3..a5 sit in memory when the process dies (m1 is abandoned).
	hang.Store(true)
	for i := 3; i < 6; i++ {
		emit(m1, fmt.Sprintf("a%d", i))
	}
	waitFor(t, "records taken from the queue", func() bool { return statusOf(m1, sink.ID).Queued == 0 })
	time.Sleep(1500 * time.Millisecond) // a flush interval: the cursor must not move past undelivered records
	if c := cursorID(sinkDir); c != "a2" {
		t.Fatalf("cursor moved to %s before the records were delivered", c)
	}

	hang.Store(false)
	m2 := New(opts)
	defer m2.Close()
	m2.SetAuditSource(trail)
	m2.Configure([]models.ExportSink{sink})
	emit(m2, "a6")
	waitFor(t, "lost records replayed", func() bool { return len(got.list()) >= 7 })
	time.Sleep(1200 * time.Millisecond)
	want := []string{"audit:a0", "audit:a1", "audit:a2", "audit:a3", "audit:a4", "audit:a5", "audit:a6"}
	if list := got.list(); !slices.Equal(list, want) {
		t.Fatalf("delivered %v, want %v (each once, history before the sink excluded)", list, want)
	}
	if st := statusOf(m2, sink.ID); st.Replayed != 3 && st.Replayed != 4 { // a6 may be replayed (then its live copy is skipped)
		t.Fatalf("replayed counter: %+v", st)
	}
	waitFor(t, "cursor at the newest delivered record", func() bool { return cursorID(sinkDir) == "a6" })
	hang.Store(true) // the stuck runtime of m1 must not deliver anything after the test
	m1.mu.RLock()
	stuck := m1.sinks[sink.ID]
	m1.mu.RUnlock()
	stuck.requestStop(stopDelete)
	m1.Close()
}

// #4: an audit record lost while running (no spool, destination down) freezes the cursor; the next
// start delivers it from the trail.
func TestAuditCursorFrozenAfterLoss(t *testing.T) {
	var got webhookEvents
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got.add(r)
	}))
	defer srv.Close()
	spoolDir := filepath.Join(t.TempDir(), "export-spool")
	sink := models.ExportSink{ID: "exp-gap", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL, BatchSize: 10, FlushSeconds: 1}
	trail := &fakeTrail{}
	trail.add(models.AuditEvent{ID: "start", Timestamp: time.Now().UTC().Add(-time.Minute)})
	opts := Options{SpoolDir: spoolDir, Node: "n1", Version: "t", AuditReplay: true}
	m1 := New(opts)
	m1.SetAuditSource(trail)
	m1.Configure([]models.ExportSink{sink})
	waitFor(t, "cursor initialized", func() bool { return cursorID(filepath.Join(spoolDir, sink.ID)) == "start" })
	for _, id := range []string{"g1", "g2"} {
		ev := models.AuditEvent{ID: id, Timestamp: time.Now().UTC(), Actor: "admin", Action: "X"}
		trail.add(ev)
		m1.Publish(AuditEvent(ev))
	}
	waitFor(t, "records dropped without spool", func() bool { return statusOf(m1, sink.ID).Dropped == 2 })
	m1.Close()
	if c := cursorID(filepath.Join(spoolDir, sink.ID)); c != "start" {
		t.Fatalf("cursor moved past lost records: %s", c)
	}
	up.Store(true)
	m2 := New(opts)
	defer m2.Close()
	m2.SetAuditSource(trail)
	m2.Configure([]models.ExportSink{sink})
	waitFor(t, "lost records delivered after restart", func() bool { return len(got.list()) == 2 })
	waitFor(t, "cursor advanced", func() bool { return cursorID(filepath.Join(spoolDir, sink.ID)) == "g2" })
}

// bodyCollector keeps raw request bodies.
type bodyCollector struct {
	mu     sync.Mutex
	bodies []string
}

func (c *bodyCollector) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, string(b))
}

func (c *bodyCollector) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies, "\n")
}

// #5: spooled records do not depend on the destination: a new endpoint and format keep them.
func TestSpoolSurvivesDestinationChange(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer down.Close()
	var got bodyCollector
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.add(r) }))
	defer up.Close()
	sink := models.ExportSink{ID: "exp-move", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit", "traffic"},
		Endpoint: down.URL, BatchSize: 2, FlushSeconds: 1}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	m := New(Options{SpoolDir: filepath.Join(t.TempDir(), "export-spool"), Node: "n1", Version: "t"})
	defer m.Close()
	m.Configure([]models.ExportSink{sink})
	for i := 0; i < 3; i++ {
		m.Publish(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("moved-%d", i), Timestamp: time.Now(), Actor: "admin", Action: "X"}))
	}
	m.Publish(FlowEvent(flow(models.VerdictBlocked)))
	waitFor(t, "records spooled", func() bool { return statusOf(m, sink.ID).SpoolRecords == 4 })
	moved := sink
	moved.Endpoint, moved.Format = up.URL, "ecs"
	m.Configure([]models.ExportSink{moved})
	waitFor(t, "spooled records delivered to the new destination", func() bool {
		return strings.Count(got.all(), `"event.action"`) == 4
	})
	all := got.all()
	for i := 0; i < 3; i++ {
		if !strings.Contains(all, fmt.Sprintf("moved-%d", i)) {
			t.Errorf("record moved-%d lost: %s", i, all)
		}
	}
	if !strings.Contains(all, `"@timestamp"`) {
		t.Errorf("records not re-encoded in the new format: %s", all)
	}
	if st := statusOf(m, sink.ID); st.SpoolRecords != 0 || st.Sent != 4 || st.DeadLettered != 0 {
		t.Fatalf("status: %+v", st)
	}
}

// writeLegacySpool writes a spool as release 2.0 did: encoded records behind a v1 signature.
func writeLegacySpool(t *testing.T, dir string, s models.ExportSink, recs [][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sig := fmt.Sprintf("v1|%s|%s|%s|%s|%s|%s|%s", s.Type, s.Format, s.SyslogProtocol, s.SyslogFacility, s.Index, s.SourceType, s.Endpoint)
	if err := os.WriteFile(filepath.Join(dir, "signature"), []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf []byte
	for _, r := range recs {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(r)))
		buf = append(buf, r...)
	}
	if err := os.WriteFile(filepath.Join(dir, segName(1)), buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

// #5: spools of the previous release are kept when only the endpoint changed and dead-lettered (with
// an alert) when the encoding changed.
func TestLegacySpoolMigration(t *testing.T) {
	var got bodyCollector
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.add(r) }))
	defer srv.Close()
	spoolDir := filepath.Join(t.TempDir(), "export-spool")
	old := models.ExportSink{ID: "exp-legacy", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"},
		Endpoint: "https://old-collector.example/hook", BatchSize: 10, FlushSeconds: 1}
	if err := Validate(&old); err != nil {
		t.Fatal(err)
	}
	drv, err := newDriver(old, Meta{Node: "n1", Version: "t"}, "")
	if err != nil {
		t.Fatal(err)
	}
	var recs [][]byte
	for i := 0; i < 2; i++ {
		rec, err := drv.encode(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("legacy-%d", i), Timestamp: time.Now(), Actor: "admin", Action: "X"}))
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}

	// Same encoding, new endpoint: resent unchanged.
	writeLegacySpool(t, filepath.Join(spoolDir, old.ID), old, recs)
	sameEnc := old
	sameEnc.Endpoint = srv.URL
	var alerts alertLog
	m := New(Options{SpoolDir: spoolDir, Node: "n1", Version: "t"})
	m.SetAlertHandler(alerts.add)
	m.Configure([]models.ExportSink{sameEnc})
	waitFor(t, "legacy records delivered", func() bool { return statusOf(m, old.ID).Sent == 2 })
	if all := got.all(); !strings.Contains(all, "legacy-0") || !strings.Contains(all, "legacy-1") {
		t.Fatalf("legacy records: %s", all)
	}
	m.Close()

	// Different format: the records cannot be resent; they go to the dead-letter file with an alert.
	writeLegacySpool(t, filepath.Join(spoolDir, old.ID), old, recs)
	_ = os.Remove(filepath.Join(spoolDir, old.ID, "cursor"))
	_ = os.Remove(filepath.Join(spoolDir, old.ID, legacyFile))
	otherEnc := sameEnc
	otherEnc.Format = "ecs"
	m2 := New(Options{SpoolDir: spoolDir, Node: "n1", Version: "t"})
	defer m2.Close()
	m2.SetAlertHandler(alerts.add)
	m2.Configure([]models.ExportSink{otherEnc})
	waitFor(t, "legacy records dead-lettered", func() bool { return statusOf(m2, old.ID).DeadLettered == 2 })
	entries := readDeadLetters(t, filepath.Join(spoolDir, old.ID, "dead-letter.jsonl"))
	if len(entries) != 1 || len(entries[0].Records) != 2 || !strings.Contains(entries[0].Records[1], "legacy-1") ||
		!strings.Contains(entries[0].Error, "encoding") {
		t.Fatalf("dead-letter entries: %+v", entries)
	}
	if st := statusOf(m2, old.ID); st.SpoolRecords != 0 {
		t.Fatalf("legacy records still spooled: %+v", st)
	}
	waitFor(t, "alert raised", func() bool { return alerts.find("encoding the destination no longer uses") != nil })
}

// #6: a reconfiguration never waits for a stuck destination, and Publish/Status never wait for it.
func TestReconfigureDoesNotWaitForDestination(t *testing.T) {
	entered := make(chan struct{}, 16)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-block
	}))
	defer srv.Close()
	defer close(block)
	sink := models.ExportSink{ID: "exp-stuck", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL, BatchSize: 1, FlushSeconds: 1}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	m := New(Options{SpoolDir: filepath.Join(t.TempDir(), "export-spool"), Node: "n1", Version: "t"})
	defer m.Close()
	m.Configure([]models.ExportSink{sink})
	m.Publish(AuditEvent(models.AuditEvent{ID: "in-flight", Timestamp: time.Now(), Actor: "admin", Action: "X"}))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no delivery attempt")
	}
	changed := sink
	changed.BatchSize = 2
	done := make(chan struct{})
	go func() {
		m.Configure([]models.ExportSink{changed})
		close(done)
	}()
	start := time.Now()
	for i := 0; i < 200; i++ {
		m.Publish(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("p%d", i), Timestamp: time.Now(), Actor: "admin", Action: "X"}))
		_ = m.Status()
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Publish/Status blocked for %s during a reconfiguration", d)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Configure waits for the stuck delivery")
	}
	// The record of the aborted attempt is handed over to the new runtime through the spool.
	waitFor(t, "records kept for the new configuration", func() bool {
		st := statusOf(m, sink.ID)
		return st.SpoolRecords+int64(st.Queued) >= 1
	})
}

// #7: Elasticsearch rejects documents one by one: only the rejected ones count as failed and are
// dead-lettered with their own error.
func TestElasticRejectedDocumentsDeadLettered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [user.name]"}}},{"create":{"status":409}}]}`))
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "export-spool")
	sink := models.ExportSink{ID: "exp-es", Name: "es", Type: "elasticsearch", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL, BatchSize: 3, FlushSeconds: 1, SpoolMB: 16}
	var alerts alertLog
	m := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
	defer m.Close()
	m.SetAlertHandler(alerts.add)
	m.Configure([]models.ExportSink{sink})
	for i := 0; i < 3; i++ {
		m.Publish(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("doc-%d", i), Timestamp: time.Now(), Actor: "admin", Action: "X"}))
	}
	waitFor(t, "partial result accounted", func() bool {
		st := statusOf(m, sink.ID)
		return st.Sent == 2 && st.Failed == 1 && st.DeadLettered == 1
	})
	entries := readDeadLetters(t, filepath.Join(dir, sink.ID, "dead-letter.jsonl"))
	if len(entries) != 1 || len(entries[0].Records) != 1 || !strings.Contains(entries[0].Records[0], `"_id":"doc-1"`) ||
		len(entries[0].RecordErrors) != 1 || !strings.Contains(entries[0].RecordErrors[0], "mapper_parsing_exception: failed to parse field [user.name]") {
		t.Fatalf("dead-letter entries: %+v", entries)
	}
	waitFor(t, "alert raised", func() bool { return alerts.find("rejected audit/security records") != nil })
	if st := statusOf(m, sink.ID); st.SpoolRecords != 0 {
		t.Fatalf("rejected document retried: %+v", st)
	}
}

// #10: shutdown sends the queue in batch_size requests within closeTimeout and spools the rest.
func TestShutdownDeliversQueueInBatches(t *testing.T) {
	oldClose := closeTimeout
	defer func() { closeTimeout = oldClose }()
	for _, slow := range []bool{false, true} {
		t.Run(fmt.Sprintf("slow=%v", slow), func(t *testing.T) {
			closeTimeout = 5 * time.Second
			if slow {
				closeTimeout = time.Second
			}
			var mu sync.Mutex
			var sizes []int
			var got webhookEvents
			entered, block := make(chan struct{}, 1), make(chan struct{})
			var first sync.Once
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				isFirst := false
				first.Do(func() { isFirst = true })
				if isFirst { // the first attempt hangs while the queue fills
					entered <- struct{}{}
					<-block
					return
				}
				if slow {
					time.Sleep(400 * time.Millisecond)
				}
				body, _ := io.ReadAll(r.Body)
				var b struct {
					Events []json.RawMessage `json:"events"`
				}
				_ = json.Unmarshal(body, &b)
				mu.Lock()
				sizes = append(sizes, len(b.Events))
				mu.Unlock()
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				got.add(r)
			}))
			defer srv.Close()
			defer close(block)
			dir := filepath.Join(t.TempDir(), "export-spool")
			sink := models.ExportSink{ID: "exp-close", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"},
				Endpoint: srv.URL, BatchSize: 2, FlushSeconds: 60}
			if err := Validate(&sink); err != nil {
				t.Fatal(err)
			}
			m := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
			m.Configure([]models.ExportSink{sink})
			for i := 0; i < 9; i++ {
				m.Publish(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("q%d", i), Timestamp: time.Now(), Actor: "admin", Action: "X"}))
			}
			<-entered
			start := time.Now()
			m.Close()
			if d := time.Since(start); d > closeTimeout+2*time.Second {
				t.Fatalf("Close took %s", d)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, n := range sizes {
				if n > 2 {
					t.Fatalf("shutdown sent %d records in one request (batch_size 2): %v", n, sizes)
				}
			}
			sp, err := openSpool(filepath.Join(dir, sink.ID), 16<<20)
			if err != nil {
				t.Fatal(err)
			}
			spooled, _ := sp.records()
			_ = sp.Close()
			delivered := len(got.list())
			if !slow && (delivered != 9 || spooled != 0) {
				t.Fatalf("delivered %d (requests %v), spooled %d; want all 9 delivered", delivered, sizes, spooled)
			}
			// A request cut off by the deadline may still reach the destination (and is spooled too).
			if slow && (delivered < 2 || spooled == 0 || int64(delivered)+spooled < 9) {
				t.Fatalf("slow destination: delivered %d, spooled %d; want the rest spooled after the deadline", delivered, spooled)
			}
		})
	}
}

// #11: when the spool limit evicts segments, their audit/security records are dead-lettered (with
// an alert); records too large for the spool are dead-lettered too.
func TestSpoolEvictionDeadLettersCriticalRecords(t *testing.T) {
	oldSeg, oldMax := segMaxBytes, maxRecordSize
	segMaxBytes, maxRecordSize = 200<<10, 400<<10
	defer func() { segMaxBytes, maxRecordSize = oldSeg, oldMax }()
	var up atomic.Bool
	var got webhookEvents
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got.add(r)
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "export-spool")
	sink := models.ExportSink{ID: "exp-full", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit", "traffic"},
		Endpoint: srv.URL, BatchSize: 1, FlushSeconds: 1}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	sink.SpoolMB = 1
	var alerts alertLog
	m := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
	defer m.Close()
	m.SetAlertHandler(alerts.add)
	m.Configure([]models.ExportSink{sink})
	big := strings.Repeat("x", 100<<10)
	ids := map[string]bool{}
	for i := 0; i < 16; i++ {
		id := fmt.Sprintf("big-%02d", i)
		ids[id] = true
		m.Publish(AuditEvent(models.AuditEvent{ID: id, Timestamp: time.Now(), Actor: "admin", Action: "X", Summary: big}))
		m.Publish(FlowEvent(flow(models.VerdictBlocked)))
	}
	m.Publish(AuditEvent(models.AuditEvent{ID: "huge", Timestamp: time.Now(), Actor: "admin", Action: "X", Summary: strings.Repeat("y", 500<<10)}))
	waitFor(t, "evicted and oversize records dead-lettered", func() bool {
		st := statusOf(m, sink.ID)
		return st.DeadLettered > 0 && st.Dropped > 0 && alerts.find("spool limit was reached") != nil && alerts.find("exceed the spool record limit") != nil
	})
	up.Store(true)
	waitFor(t, "spool drained", func() bool { st := statusOf(m, sink.ID); return st.SpoolRecords == 0 && st.Sent > 0 })
	seen := map[string]bool{}
	for _, e := range got.list() {
		seen[strings.TrimPrefix(e, "audit:")] = true
	}
	huge := false
	for _, e := range readDeadLetters(t, filepath.Join(dir, sink.ID, "dead-letter.jsonl")) {
		for _, r := range e.Records {
			var rec struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if json.Unmarshal([]byte(r), &rec) == nil {
				seen[rec.Data.ID] = true
				huge = huge || rec.Data.ID == "huge"
			}
		}
	}
	for id := range ids {
		if !seen[id] {
			t.Errorf("audit record %s neither delivered nor dead-lettered", id)
		}
	}
	if !huge {
		t.Error("oversize audit record not dead-lettered")
	}
}

// #12: records Splunk never acknowledges are dead-lettered after the configured number of timeouts
// (with an alert) instead of blocking the destination forever.
func TestSplunkUnacknowledgedRecordsSetAside(t *testing.T) {
	oldAck, oldDeliver := splunkAckTimeout, deliveryTimeout
	splunkAckTimeout, deliveryTimeout = 300*time.Millisecond, 2*time.Second
	defer func() { splunkAckTimeout, deliveryTimeout = oldAck, oldDeliver }()
	hec := &fakeHEC{pending: map[string]map[int64]int{}, never: true}
	srv := httptest.NewServer(hec)
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "export-spool")
	s := models.ExportSink{ID: "exp-hec-stuck", Name: "splunk", Type: "splunk_hec", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL, Secret: "hec-token", BatchSize: 1, FlushSeconds: 1}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	var alerts alertLog
	m := New(Options{SpoolDir: dir, Node: "n1", Version: "t", HECAckAttempts: 2})
	defer m.Close()
	m.SetAlertHandler(alerts.add)
	m.Configure([]models.ExportSink{s})
	m.Publish(AuditEvent(models.AuditEvent{ID: "never-acked", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"}))
	waitFor(t, "unacknowledged record set aside", func() bool { return statusOf(m, s.ID).DeadLettered == 1 })
	hec.mu.Lock()
	posts := hec.events
	hec.never = false
	hec.mu.Unlock()
	if posts != 2 {
		t.Fatalf("record posted %d times, want 2 (HECAckAttempts)", posts)
	}
	entries := readDeadLetters(t, filepath.Join(dir, s.ID, "dead-letter.jsonl"))
	if len(entries) != 1 || !strings.Contains(entries[0].Records[0], "never-acked") || !strings.Contains(entries[0].RecordErrors[0], "no indexer acknowledgement after 2 attempts") {
		t.Fatalf("dead-letter entries: %+v", entries)
	}
	waitFor(t, "alert raised", func() bool { return alerts.find("did not acknowledge") != nil })
	m.Publish(AuditEvent(models.AuditEvent{ID: "acked", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"}))
	waitFor(t, "destination not blocked afterwards", func() bool { st := statusOf(m, s.ID); return st.Sent == 1 && st.SpoolRecords == 0 })
}

// #12: once a token answered with an ackId, a success without ackId (or with an error code) is a
// failed attempt, not a delivery.
func TestSplunkAckRequiredOnceEnabled(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/ack" {
			_, _ = w.Write([]byte(`{"acks":{"0":true}}`))
			return
		}
		switch n.Add(1) {
		case 1:
			_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":0}`))
		case 2:
			_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
		default:
			_, _ = w.Write([]byte(`{"text":"Server is busy","code":9,"ackId":1}`))
		}
	}))
	defer srv.Close()
	s := models.ExportSink{ID: "exp-hec-ack", Name: "splunk", Type: "splunk_hec", Streams: []string{"audit"}, Endpoint: srv.URL, Secret: "t"}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	drv, err := newDriver(s, meta, "")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := drv.encode(AuditEvent(models.AuditEvent{ID: "a1", Timestamp: time.Now(), Actor: "admin", Action: "LOGIN"}))
	if err := drv.send(context.Background(), [][]byte{rec}); err != nil {
		t.Fatalf("acknowledged batch: %v", err)
	}
	for i, want := range []string{"code 0", "code 9"} {
		err := drv.send(context.Background(), [][]byte{rec})
		var perm *permanentError
		if err == nil || !strings.Contains(err.Error(), want) || errors.As(err, &perm) {
			t.Fatalf("response %d must be a retryable failure (%s): %v", i+2, want, err)
		}
	}
}

// #14: the dead-letter file keeps five older generations and is never written through a symlink.
func TestDeadLetterRotationAndSymlink(t *testing.T) {
	old := deadLetterMax
	deadLetterMax = 300
	defer func() { deadLetterMax = old }()
	dir := t.TempDir()
	path := filepath.Join(dir, "dead-letter.jsonl")
	for i := 0; i < 12; i++ {
		if err := appendDeadLetter(path, []byte(fmt.Sprintf(`{"n":%d,"pad":"%s"}`+"\n", i, strings.Repeat("p", 200)))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= deadLetterKeep; i++ {
		b, err := os.ReadFile(fmt.Sprintf("%s.%d", path, i))
		if err != nil || !strings.Contains(string(b), fmt.Sprintf(`{"n":%d,`, 11-i)) {
			t.Fatalf("generation %d: %q %v", i, b, err)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", path, deadLetterKeep+1)); !os.IsNotExist(err) {
		t.Fatalf("more than %d generations kept", deadLetterKeep)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), `{"n":11,`) {
		t.Fatalf("live file: %q", b)
	}

	target := filepath.Join(dir, "elsewhere")
	link := filepath.Join(dir, "linked", "dead-letter.jsonl")
	_ = os.MkdirAll(filepath.Dir(link), 0o700)
	if err := os.Symlink(target, link); err != nil {
		if goruntime.GOOS == "windows" {
			t.Skip("symbolic links need a privilege on Windows:", err)
		}
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Skip("the platform does not report the symbolic link (Wine follows host symlinks transparently)")
	}
	if err := appendDeadLetter(link, []byte("{}\n")); err == nil {
		t.Fatal("dead-letter written through a symbolic link")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target created: %v", err)
	}
}
