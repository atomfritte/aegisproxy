package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

// The log export replays audit events after its cursor from the in-memory window or, when the
// cursor is older, from the audit log; an unknown cursor falls back to its time.
func TestReplayAuditAfter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, BootstrapAdminPassword: "Replay-Test-Pass-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, id := range []string{"grp-a", "grp-b", "grp-c", "grp-d"} {
		if _, err := st.UpsertGroup(models.ServerGroup{ID: id, Name: id, CIDRs: []string{"10.0.0.0/8"}}, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	ids := exportedAuditIDs(t, st, path) // oldest first
	if len(ids) < 5 {
		t.Fatalf("audit trail: %v", ids)
	}
	latest, ok := st.LatestAudit()
	if !ok || latest.ID != ids[len(ids)-1] {
		t.Fatalf("latest: %v %v", latest.ID, ok)
	}
	at := map[string]time.Time{}
	for _, ev := range st.GetSnapshot().AuditEvents {
		at[ev.ID] = ev.Timestamp
	}
	replay := func(afterID string, afterTime time.Time) ([]string, bool) {
		t.Helper()
		var got []string
		found, err := st.ReplayAuditAfter(context.Background(), afterID, afterTime, func(ev models.AuditEvent) error {
			got = append(got, ev.ID)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got, found
	}
	if got, found := replay(ids[len(ids)-3], at[ids[len(ids)-3]]); !found || !slices.Equal(got, ids[len(ids)-2:]) {
		t.Fatalf("from the window: %v %v, want %v", got, found, ids[len(ids)-2:])
	}
	if got, found := replay(latest.ID, latest.Timestamp); !found || len(got) != 0 {
		t.Fatalf("after the newest event: %v %v", got, found)
	}

	// A cursor older than the window is found in the audit log.
	st.mu.Lock()
	window := st.state.AuditEvents
	st.state.AuditEvents = window[:2]
	st.mu.Unlock()
	got, found := replay(ids[1], at[ids[1]])
	st.mu.Lock()
	st.state.AuditEvents = window
	st.mu.Unlock()
	if !found || !slices.Equal(got, ids[2:]) {
		t.Fatalf("from the audit log: %v %v, want %v", got, found, ids[2:])
	}

	// A cursor rotated away entirely: the events after its time.
	got, found = replay("aud-rotated-away", at[ids[len(ids)-2]].Add(-time.Nanosecond))
	if found || !slices.Contains(got, ids[len(ids)-1]) || slices.Contains(got, ids[0]) {
		t.Fatalf("by time: %v %v", got, found)
	}
}

// Export alerts become (de-duplicated) security events.
func TestRecordExportAlert(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	a := export.Alert{SinkID: "exp-1", SinkName: "Splunk", Severity: "high", Detail: `Log export "Splunk": records were moved to its dead-letter file`}
	st.RecordExportAlert(a)
	st.RecordExportAlert(a)
	st.mu.RLock()
	defer st.mu.RUnlock()
	var found []models.SecurityEvent
	for _, ev := range st.state.SecurityEvents {
		if ev.Type == export.AlertEventType {
			found = append(found, ev)
		}
	}
	if len(found) != 1 || found[0].Count != 2 || found[0].Severity != "high" || found[0].Detail != a.Detail {
		t.Fatalf("security events: %+v", found)
	}
}
