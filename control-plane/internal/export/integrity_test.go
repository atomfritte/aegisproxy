package export

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// An Elasticsearch response proves delivery only when it is a complete bulk result that answers
// every document: a proxy or another service answering 200, a truncated body or missing items are
// retried instead of counted as delivered.
func TestElasticBulkResultMustAnswerEveryDocument(t *testing.T) {
	var answer atomic.Value
	var query atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query.Store(r.URL.RawQuery)
		_, _ = w.Write([]byte(answer.Load().(string)))
	}))
	defer srv.Close()
	s := models.ExportSink{Name: "es", Type: "elasticsearch", Streams: []string{"audit"}, Endpoint: srv.URL}
	if err := Validate(&s); err != nil {
		t.Fatal(err)
	}
	drv, err := newDriver(s, meta, "")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := drv.encode(AuditEvent(models.AuditEvent{ID: "a1", Timestamp: time.Now()}))
	recs := [][]byte{rec, rec, rec}
	send := func(body string) error {
		answer.Store(body)
		return drv.send(context.Background(), recs)
	}
	ok3 := `{"items":[{"create":{"status":201}},{"create":{"status":409}},{"create":{"status":201}}]}`
	if err := send(ok3); err != nil {
		t.Fatalf("complete result: %v", err)
	}
	if q, _ := query.Load().(string); !strings.Contains(q, "filter_path=items.%2A.status") && !strings.Contains(q, "filter_path=items.*.status") {
		t.Errorf("bulk request without filter_path: %q", q)
	}
	big := strings.Repeat(" ", maxBulkResponse) + ok3
	for name, body := range map[string]string{
		"html from a proxy":  "<html>ok</html>",
		"empty":              "",
		"truncated":          ok3[:40],
		"fewer items":        `{"items":[{"create":{"status":201}},{"create":{"status":201}}]}`,
		"no items":           `{"took":1}`,
		"item without state": `{"items":[{"create":{"status":201}},{"create":{}},{"create":{"status":201}}]}`,
		"larger than limit":  big,
	} {
		err := send(body)
		if err == nil {
			t.Errorf("%s: counted as delivered", name)
			continue
		}
		if pe, ok := err.(*permanentError); ok {
			t.Errorf("%s: permanent instead of retried: %v", name, pe)
		}
	}
	// A large result (beyond the 1 MiB other drivers read) with rejected documents is still judged
	// document by document.
	pad := strings.Repeat("x", 1<<20)
	rejected := `{"items":[{"create":{"status":201}},{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"` + pad + `"}}},{"create":{"status":201}}]}`
	err = send(rejected)
	if pe, ok := err.(*partialError); !ok || len(pe.rejected) != 1 || !strings.Contains(pe.rejected[1], "mapper_parsing_exception") {
		t.Fatalf("large partial result: %T %v", err, err)
	}
}

// A sink that could not be started counts the records it misses as dropped and raises one critical
// alert as soon as audit or security records are affected.
func TestFailedSinkCountsDropsAndAlerts(t *testing.T) {
	var alerts alertLog
	m := New(Options{Node: "n1", Version: "t"})
	defer m.Close()
	m.SetAlertHandler(alerts.add)
	// A client certificate that does not parse makes the driver fail at start.
	bad := models.ExportSink{ID: "exp-bad", Name: "broken", Type: "webhook", Enabled: true, Streams: []string{"audit", "security", "traffic"},
		Endpoint: "https://siem.example/hook", ClientCertPEM: "not a certificate", ClientKeyPEM: "not a key"}
	m.Configure([]models.ExportSink{bad})
	if st := statusOf(m, bad.ID); st.State != "error" || st.LastError == "" {
		t.Fatalf("failed sink status: %+v", st)
	}
	m.Publish(FlowEvent(flow(models.VerdictBlocked)))
	if alerts.find("could not be started") != nil {
		t.Fatal("traffic records alone must not alert")
	}
	m.Publish(AuditEvent(models.AuditEvent{ID: "a1", Timestamp: time.Now()}))
	m.Publish(SecurityEvent(models.SecurityEvent{ID: "s1", Type: "X", Severity: "critical", Timestamp: time.Now()}))
	waitFor(t, "critical alert for the failed sink", func() bool {
		a := alerts.find("could not be started")
		return a != nil && a.Severity == "critical" && a.SinkID == bad.ID
	})
	if st := statusOf(m, bad.ID); st.Dropped != 3 {
		t.Fatalf("dropped records not counted: %+v", st)
	}
	time.Sleep(100 * time.Millisecond)
	alerts.mu.Lock()
	n := len(alerts.alerts)
	alerts.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected exactly one alert, got %d", n)
	}
}

// Sync applies the configuration scheduled with Apply before it returns.
func TestSyncAppliesScheduledConfiguration(t *testing.T) {
	m := New(Options{ExportDir: t.TempDir(), Node: "n1", Version: "t"})
	defer m.Close()
	sink := models.ExportSink{ID: "exp-file", Name: "file", Type: "file", Enabled: true, Streams: []string{"security"}, Endpoint: "sec.jsonl"}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		m.Apply([]models.ExportSink{sink})
		m.Sync()
		if len(m.Status()) != 1 {
			t.Fatalf("round %d: sink not running after Sync", i)
		}
		m.Apply(nil)
		m.Sync()
		if len(m.Status()) != 0 {
			t.Fatalf("round %d: sink still running after Sync", i)
		}
	}
}

// With a spool key, spooled records carry a MAC: records changed or added in the spool directory are
// set aside in the dead-letter file with an alert instead of being sent as genuine.
func TestSpoolRecordsAuthenticated(t *testing.T) {
	var up atomic.Bool
	var mu sync.Mutex
	var ids []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(503)
			return
		}
		var body struct {
			Events []struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, e := range body.Events {
			ids = append(ids, e.Data.ID)
		}
		mu.Unlock()
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "export-spool")
	sink := models.ExportSink{ID: "exp-1", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit"}, Endpoint: srv.URL,
		BatchSize: 10, FlushSeconds: 1, SpoolMB: 16}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	m := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
	m.SetSpoolKey(key)
	m.Configure([]models.ExportSink{sink})
	for i := 0; i < 3; i++ {
		m.Publish(AuditEvent(models.AuditEvent{ID: fmt.Sprintf("aud-%d", i), Timestamp: time.Now(), Summary: "original"}))
	}
	waitFor(t, "records spooled", func() bool { return statusOf(m, sink.ID).SpoolRecords == 3 })
	m.Close()

	// Somebody with write access to the spool edits the second record and appends one without MAC.
	segs, _ := filepath.Glob(filepath.Join(dir, sink.ID, "seg-*.dat"))
	if len(segs) != 1 {
		t.Fatalf("segments: %v", segs)
	}
	raw, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	var recs [][]byte
	for off := 0; off+4 <= len(raw); {
		n := int(binary.BigEndian.Uint32(raw[off:]))
		recs = append(recs, slices.Clone(raw[off+4:off+4+n]))
		off += 4 + n
	}
	if len(recs) != 3 || recs[0][0] != macMarker {
		t.Fatalf("spool records: %d, marker %x", len(recs), recs[0][0])
	}
	recs[1] = []byte(strings.Replace(string(recs[1]), "original", "forged!!", 1))
	injected, _ := json.Marshal(AuditEvent(models.AuditEvent{ID: "aud-injected", Timestamp: time.Now()}))
	recs = append(recs, append([]byte{eventMarker}, injected...))
	var out []byte
	for _, r := range recs {
		out = binary.BigEndian.AppendUint32(out, uint32(len(r)))
		out = append(out, r...)
	}
	if err := os.WriteFile(segs[0], out, 0o600); err != nil {
		t.Fatal(err)
	}

	up.Store(true)
	var alerts alertLog
	m2 := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
	defer m2.Close()
	m2.SetAlertHandler(alerts.add)
	m2.SetSpoolKey(key)
	m2.Configure([]models.ExportSink{sink})
	waitFor(t, "authentic records delivered, the others set aside", func() bool {
		st := statusOf(m2, sink.ID)
		return st.SpoolRecords == 0 && st.DeadLettered == 2
	})
	mu.Lock()
	got := slices.Clone(ids)
	mu.Unlock()
	if !slices.Equal(got, []string{"aud-0", "aud-2"}) {
		t.Fatalf("delivered %v, want only the authentic records", got)
	}
	entries := readDeadLetters(t, filepath.Join(dir, sink.ID, "dead-letter.jsonl"))
	all := ""
	for _, e := range entries {
		b, _ := json.Marshal(e)
		all += string(b)
	}
	if !strings.Contains(all, "forged!!") || !strings.Contains(all, "aud-injected") || !strings.Contains(all, "does not match its MAC") || !strings.Contains(all, "has no MAC") {
		t.Fatalf("dead-letter entries: %s", all)
	}
	waitFor(t, "integrity alert", func() bool { return alerts.find("integrity check") != nil })
}
