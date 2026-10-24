package export

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// webhookEvents collects the stream/id pairs a webhook destination received.
type webhookEvents struct {
	mu  sync.Mutex
	got []string
}

func (c *webhookEvents) add(r *http.Request) {
	var body struct {
		Events []struct {
			Stream string `json:"stream"`
			Data   struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"events"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range body.Events {
		c.got = append(c.got, e.Stream+":"+e.Data.ID)
	}
}

func (c *webhookEvents) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
}

// A full queue spools audit and security records instead of dropping them; traffic records are
// dropped, counted and reported.
func TestQueueOverflowSpoolsCriticalStreams(t *testing.T) {
	oldQ, oldD := queueSize, deliveryTimeout
	queueSize, deliveryTimeout = 4, 10*time.Second
	defer func() { queueSize, deliveryTimeout = oldQ, oldD }()
	var got webhookEvents
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { entered <- struct{}{}; <-release }) // the first delivery hangs: the queue fills up
		got.add(r)
	}))
	defer srv.Close()
	sink := models.ExportSink{ID: "exp-q", Name: "hook", Type: "webhook", Enabled: true, Streams: []string{"audit", "traffic", "security"},
		Endpoint: srv.URL, BatchSize: 1, FlushSeconds: 1, SpoolMB: 16}
	if err := Validate(&sink); err != nil {
		t.Fatal(err)
	}
	m := New(Options{SpoolDir: filepath.Join(t.TempDir(), "export-spool"), Node: "n1", Version: "t"})
	defer m.Close()
	m.Configure([]models.ExportSink{sink})
	audit := func(id string) Event {
		return AuditEvent(models.AuditEvent{ID: id, Timestamp: time.Now(), Actor: "admin", Action: "X"})
	}
	traffic := func(id string) Event {
		f := flow(models.VerdictBlocked)
		f.ID = id
		return FlowEvent(f)
	}
	m.Publish(audit("first"))
	<-entered
	for i := 0; i < 4; i++ {
		m.Publish(traffic(fmt.Sprintf("queued-%d", i)))
	}
	waitFor(t, "queue full", func() bool { return m.Status()[0].Queued == 4 })
	for i := 0; i < 3; i++ {
		m.Publish(audit(fmt.Sprintf("overflow-audit-%d", i)))
		m.Publish(traffic(fmt.Sprintf("overflow-traffic-%d", i)))
	}
	st := m.Status()[0]
	if st.Dropped != 3 || st.SpoolRecords != 3 || !strings.Contains(st.LastError, "export queue full") {
		t.Fatalf("overflow accounting: %+v", st)
	}
	close(release)
	waitFor(t, "queued and spooled records delivered", func() bool { return len(got.list()) == 8 })
	all := strings.Join(got.list(), " ")
	for i := 0; i < 3; i++ {
		if !strings.Contains(all, fmt.Sprintf("audit:overflow-audit-%d", i)) {
			t.Errorf("overflowing audit record %d lost: %s", i, all)
		}
		if strings.Contains(all, fmt.Sprintf("overflow-traffic-%d", i)) {
			t.Errorf("overflowing traffic record %d delivered although counted as dropped: %s", i, all)
		}
	}
}

// Batches the destination rejects permanently are counted; audit/security sinks keep them in a
// dead-letter file in the spool directory.
func TestRejectedBatchesCountedAndDeadLettered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"schema mismatch"}`))
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "export-spool")
	auditSink := models.ExportSink{ID: "exp-audit", Name: "audit", Type: "webhook", Enabled: true, Streams: []string{"audit"},
		Endpoint: srv.URL + "/hook?token=SECRET", BatchSize: 2, FlushSeconds: 1}
	trafficSink := models.ExportSink{ID: "exp-traffic", Name: "traffic", Type: "webhook", Enabled: true, Streams: []string{"traffic"},
		Endpoint: srv.URL, BatchSize: 1, FlushSeconds: 1}
	for _, s := range []*models.ExportSink{&auditSink, &trafficSink} {
		if err := Validate(s); err != nil {
			t.Fatal(err)
		}
	}
	m := New(Options{SpoolDir: dir, Node: "n1", Version: "t"})
	defer m.Close()
	m.Configure([]models.ExportSink{auditSink, trafficSink})
	m.Publish(AuditEvent(models.AuditEvent{ID: "aud-rejected-1", Timestamp: time.Now(), Actor: "admin", Action: "X"}))
	m.Publish(AuditEvent(models.AuditEvent{ID: "aud-rejected-2", Timestamp: time.Now(), Actor: "admin", Action: "X"}))
	m.Publish(FlowEvent(flow(models.VerdictBlocked)))
	status := func(id string) models.ExportSinkStatus {
		for _, st := range m.Status() {
			if st.ID == id {
				return st
			}
		}
		return models.ExportSinkStatus{}
	}
	waitFor(t, "rejections recorded", func() bool {
		return status("exp-audit").DiscardedBatches == 1 && status("exp-traffic").DiscardedBatches == 1
	})
	if st := status("exp-audit"); st.Failed != 2 || st.Sent != 0 {
		t.Errorf("audit sink status: %+v", st)
	}
	f, err := os.Open(filepath.Join(dir, "exp-audit", "dead-letter.jsonl"))
	if err != nil {
		t.Fatalf("dead-letter file: %v", err)
	}
	defer f.Close()
	type deadLetterEntry struct {
		SinkID  string   `json:"sink_id"`
		Error   string   `json:"error"`
		Records []string `json:"records"`
	}
	var entries []deadLetterEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e deadLetterEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 1 || entries[0].SinkID != "exp-audit" || len(entries[0].Records) != 2 ||
		!strings.Contains(entries[0].Records[0]+entries[0].Records[1], "aud-rejected-2") || !strings.Contains(entries[0].Error, "HTTP 400") {
		t.Fatalf("dead-letter entries: %+v", entries)
	}
	if strings.Contains(entries[0].Error, "SECRET") {
		t.Errorf("dead-letter reason leaks the endpoint query: %s", entries[0].Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "exp-traffic", "dead-letter.jsonl")); !os.IsNotExist(err) {
		t.Errorf("traffic-only sink wrote a dead-letter file: %v", err)
	}
}
