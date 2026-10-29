package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/notify"
	"aegisproxy/control-plane/internal/threatintel"
)

func init() { auditVerifyConfirmDelay = 20 * time.Millisecond }

// verifyingStore opens a file store with an audit log, an exporter and a notifier, verifying the
// complete trail in the background.
type verifyingStore struct {
	st       *Store
	sink     *AuditSink
	exp      *export.Manager
	notifier *notify.Dispatcher
}

func openVerifyingStore(t *testing.T, dir, path string) *verifyingStore {
	t.Helper()
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := export.New(export.Options{SpoolDir: filepath.Join(dir, "spool"), ExportDir: filepath.Join(dir, "export")})
	notifier := notify.NewDispatcher(models.NotificationConfig{}, nil)
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, Exporter: exp,
		Notifier: notifier, BootstrapAdminPassword: "Audit-Test-Pass-1", AuditVerifyInterval: time.Hour})
	if err != nil {
		exp.Close()
		sink.Close()
		t.Fatal(err)
	}
	v := &verifyingStore{st: st, sink: sink, exp: exp, notifier: notifier}
	t.Cleanup(v.close)
	return v
}

func (v *verifyingStore) close() {
	v.st.Close()
	v.exp.Close()
	v.sink.Close()
}

func waitFullCheck(t *testing.T, st *Store) AuditFullCheck {
	t.Helper()
	var c AuditFullCheck
	eventually(t, "complete verification finished", func() bool {
		c = st.AuditFullCheck()
		return c.At != nil && !c.Running
	})
	return c
}

// Round-3 F1: a trail changed in the middle (one event deleted, one edited) while the anchor and the
// checkpoint still match is found by the complete verification at start-up and recorded as an
// integrity violation: sealed, audited, alerted, and kept across restarts.
func TestStartupVerificationRecordsMidTrailTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	v := openVerifyingStore(t, dir, path)
	if c := waitFullCheck(t, v.st); !c.OK || c.Trigger != "start-up" || c.Events == 0 {
		t.Fatalf("intact trail: %+v", c)
	}
	mkAuditGroups(t, v.st, 6)
	v.close()

	events := readAuditLines(t, path)
	events[2].Summary = "(edited by insider)"
	events = slices.Delete(events, 4, 5)
	writeAuditLines(t, path, events)

	v = openVerifyingStore(t, dir, path)
	c := waitFullCheck(t, v.st)
	if c.OK || !strings.Contains(c.Error, "hash mismatch") {
		t.Fatalf("tampering not found: %+v", c)
	}
	if a := v.st.AuditStatus(); !strings.Contains(a.Integrity, "complete verification (start-up)") {
		t.Fatalf("violation not recorded: %+v", a)
	}
	if !hasAuditAlert(v.st, SecurityEventAuditViolation) || !windowHas(v.st, "AUDIT_INTEGRITY_VIOLATION") {
		t.Fatal("violation not alerted or audited")
	}
	v.close()

	// The violation is sealed into the checkpoint: it stays after a restart, and the restart reminds of it.
	v = openVerifyingStore(t, dir, path)
	if a := v.st.AuditStatus(); !strings.Contains(a.Integrity, "hash mismatch") {
		t.Fatalf("violation not kept across the restart: %+v", a)
	}
	if !slices.ContainsFunc(v.st.GetSnapshot().SecurityEvents, func(e models.SecurityEvent) bool {
		return e.Type == SecurityEventAuditViolation && strings.Contains(e.Detail, "still in effect")
	}) {
		t.Fatal("no reminder at the restart")
	}
}

// A trail that no longer starts at its sealed origin is alerted but not recorded as a violation: it
// is also the state between removing old generations and applying the retention point.
func TestVerificationOfCutStartAlertsUntilRetentionApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	v := openVerifyingStore(t, dir, path)
	mkAuditGroups(t, v.st, 3)
	rotateByCopy(t, path, path+"-20260101")
	mkAuditGroups(t, v.st, 2)
	if err := os.Remove(path + "-20260101"); err != nil {
		t.Fatal(err)
	}
	res := v.st.VerifyCompleteAudit(context.Background(), path)
	if res.OK || !strings.Contains(res.Error, "sealed origin") {
		t.Fatalf("missing start not reported: %+v", res)
	}
	if c := v.st.AuditFullCheck(); c.OK || c.Trigger != "api" {
		t.Fatalf("full check after the failed verification: %+v", c)
	}
	if a := v.st.AuditStatus(); a.Integrity != "" {
		t.Fatalf("missing start recorded as a violation: %+v", a)
	}
	if !hasAuditAlert(v.st, SecurityEventAuditVerification) {
		t.Fatal("missing start not alerted")
	}
	if _, err := v.st.ApplyAuditRetention(context.Background(), path, adminClaims); err != nil {
		t.Fatal(err)
	}
	if res := v.st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("after the retention point: %+v", res)
	}
	if c := v.st.AuditFullCheck(); !c.OK {
		t.Fatalf("full check after the retention point: %+v", c)
	}
}

// A rotation of the audit log triggers a complete verification.
func TestRotationTriggersCompleteVerification(t *testing.T) {
	defer func(d time.Duration) { auditVerifyMinGap = d }(auditVerifyMinGap)
	auditVerifyMinGap = 0
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	v := openVerifyingStore(t, dir, path)
	waitFullCheck(t, v.st)
	v.sink.RotateAtSize(1)
	mkAuditGroups(t, v.st, 1)
	eventually(t, "verification after the rotation", func() bool {
		c := v.st.AuditFullCheck()
		return c.Trigger == "rotation" && c.At != nil && c.OK
	})
}

// Round-3 F2: the alert for a violation found at start-up reaches the security-stream sinks and the
// notification channels, although it is raised before the exporter has its sinks and the notifier
// its configuration.
func TestStartupAlertsReachSinksAndChannels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	v := openVerifyingStore(t, dir, path)
	if _, err := v.st.UpsertExportSink(models.ExportSink{Name: "secops", Type: "file", Enabled: true, Format: "json", MinSeverity: "low",
		Endpoint: "security.jsonl", Streams: []string{models.StreamSecurity}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if err := v.st.UpdateNotificationConfig(models.NotificationConfig{TeamsEnabled: true, TeamsWebhookURL: "https://hooks.example.com/aegis",
		NotifySecurityEvents: true}, adminClaims); err != nil {
		t.Fatal(err)
	}
	waitFullCheck(t, v.st)
	v.close()
	// Insider: the sealed checkpoint is removed from the state file.
	editStateFile(t, dir, func(state map[string]json.RawMessage) { delete(state, "audit_checkpoint") })

	v = openVerifyingStore(t, dir, path)
	out := filepath.Join(dir, "export", "security.jsonl")
	eventually(t, "violation exported to the security stream", func() bool {
		raw, _ := os.ReadFile(out)
		return strings.Contains(string(raw), SecurityEventAuditViolation)
	})
	sent := func(substr string) bool {
		return slices.ContainsFunc(v.notifier.GetLogs(), func(l models.NotificationLog) bool {
			return l.Channel == "teams" && strings.Contains(l.Title+l.Summary, substr) && !strings.Contains(l.StatusNote, "disabled")
		})
	}
	eventually(t, "violation sent to the notification channel", func() bool { return sent(SecurityEventAuditViolation) })
	v.close()

	// The next start reminds of the recorded violation, on both paths.
	v = openVerifyingStore(t, dir, path)
	eventually(t, "reminder exported", func() bool {
		raw, _ := os.ReadFile(out)
		return strings.Contains(string(raw), "still in effect")
	})
	eventually(t, "reminder sent", func() bool { return sent("still in effect") })
}

// Round-3 F1, cluster: a database user deletes an audit row from the middle of aegis_audit. A node
// starting with background verification finds it and records the violation in the shared
// configuration, so every node reports it.
func TestClusterVerificationRecordsDeletedRow(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	a := newClusterNode(t, dsn, t.TempDir())
	mkAuditGroups(t, a, 4)
	be, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	if _, err := be.pool.Exec(context.Background(), "DELETE FROM aegis_audit WHERE seq = (SELECT seq FROM aegis_audit ORDER BY seq OFFSET 2 LIMIT 1)"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	b, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, Cluster: be,
		BootstrapAdminPassword: "Cluster-Root-Pass-9", AuditVerifyInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if c := waitFullCheck(t, b); c.OK || !strings.Contains(c.Error, "chain broken") {
		t.Fatalf("deleted row not found: %+v", c)
	}
	if s := b.AuditStatus(); !strings.Contains(s.Integrity, "complete verification (start-up)") {
		t.Fatalf("violation not recorded: %+v", s)
	}
	eventually(t, "violation recorded for the other node", func() bool { return a.AuditStatus().Integrity != "" })
	if res := a.VerifyCompleteAudit(context.Background(), ""); res.OK || !strings.Contains(res.Error, "chain broken") {
		t.Fatalf("other node: %+v", res)
	}
}
