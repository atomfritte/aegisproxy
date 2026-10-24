package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
	"aegisproxy/control-plane/internal/threatintel"
)

// openAuditStore opens a file-storage store that writes its audit log to path.
func openAuditStore(t *testing.T, dir, path string) (*Store, *AuditSink) {
	t.Helper()
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, BootstrapAdminPassword: "Audit-Test-Pass-1"})
	if err != nil {
		sink.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		sink.Close()
	})
	return st, sink
}

func closeAuditStore(st *Store, sink *AuditSink) {
	st.Close()
	sink.Close()
}

var groupSeq int

func mkAuditGroups(t *testing.T, st *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		groupSeq++
		id := fmt.Sprintf("grp-%04d", groupSeq)
		if _, err := st.UpsertGroup(models.ServerGroup{ID: id, Name: id, CIDRs: []string{"10.0.0.0/8"}}, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
}

func readAuditLines(t *testing.T, path string) []models.AuditEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []models.AuditEvent
	for _, l := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		var ev models.AuditEvent
		if err := json.Unmarshal(l, &ev); err != nil {
			t.Fatalf("invalid line %q", l)
		}
		out = append(out, ev)
	}
	return out
}

func writeAuditLines(t *testing.T, path string, events []models.AuditEvent) {
	t.Helper()
	var buf bytes.Buffer
	for _, ev := range events {
		line, _ := json.Marshal(ev)
		buf.Write(append(line, '\n'))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rotateByCopy moves the content of the live audit log into a generation file (works while the sink
// holds the log open, also on Windows); the sink notices the truncation and continues at the start.
func rotateByCopy(t *testing.T, path, gen string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gen, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
}

func editStateFile(t *testing.T, dir string, edit func(state map[string]json.RawMessage)) {
	t.Helper()
	p := filepath.Join(dir, "aegis_state.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	edit(state)
	out, _ := json.Marshal(state)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeLegacyInstallation leaves the data directory of a pre-2.1 installation behind: one unkeyed
// event in the state window and in the audit log, no audit chain key and no anchor.
func writeLegacyInstallation(t *testing.T, dir, path string) models.AuditEvent {
	t.Helper()
	newTestStore(t, dir, false).Close()
	legacy := models.AuditEvent{ID: "aud-legacy", Revision: 1, Timestamp: time.Now().Add(-time.Hour).UTC(), Actor: "system", Action: "LEGACY"}
	legacy.PrevHash = zeroHash
	legacy.EventHash = auditHashV1(zeroHash, legacy)
	editStateFile(t, dir, func(state map[string]json.RawMessage) {
		delete(state, "audit_chain_key")
		delete(state, "audit_anchor")
		state["audit_events"], _ = json.Marshal([]models.AuditEvent{legacy})
	})
	writeAuditLines(t, path, []models.AuditEvent{legacy})
	return legacy
}

// Finding 1: the unkeyed (version 1) hash is accepted only in the sealed prefix before the cutover.
func TestAuditVerificationRejectsHashVersionDowngrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 3)
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || res.Legacy != 0 || !res.StartsAtGenesis || !res.HeadMatches {
		t.Fatalf("intact trail: %+v", res)
	}
	// An attacker with write access to the files (no key) re-hashes the complete trail with the
	// unkeyed algorithm after changing an event, in the audit log and in the state window.
	events := readAuditLines(t, path)
	prev := zeroHash
	for i := range events {
		events[i].HashVersion = 0
		if i == 1 {
			events[i].Summary = "nothing happened"
		}
		events[i].PrevHash = prev
		events[i].EventHash = auditHashV1(prev, events[i])
		prev = events[i].EventHash
	}
	writeAuditLines(t, path, events)
	st.mu.Lock()
	st.state.AuditEvents = nil
	for i := len(events) - 1; i >= 0; i-- {
		st.state.AuditEvents = append(st.state.AuditEvents, events[i])
	}
	st.markDirtyLocked()
	st.mu.Unlock()
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "downgrade") {
		t.Fatalf("re-hashed trail accepted: %+v", res)
	}
	if _, err := st.VerifyAuditChain(); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("posture check accepted the re-hashed window: %v", err)
	}
	// A restart does not launder it: the sealed anchor says the trail has no unkeyed prefix.
	closeAuditStore(st, sink)
	st, _ = openAuditStore(t, dir, path)
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "downgrade") {
		t.Fatalf("re-hashed trail accepted after a restart: %+v", res)
	}
	if _, err := st.VerifyAuditChain(); err == nil {
		t.Fatal("posture check accepted the re-hashed window after a restart")
	}
}

func TestAuditLegacyPrefixIsSealedAtUpgrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	legacy := writeLegacyInstallation(t, dir, path)
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 2)
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK || res.Legacy != 1 || res.FirstID != legacy.ID {
		t.Fatalf("upgraded trail: %+v", res)
	}
	if st.AuditStatus().LegacyEvents != 1 {
		t.Fatalf("legacy events not reported: %+v", st.AuditStatus())
	}
	if got := st.GetSnapshot().AuditEvents; got[len(got)-2].Action != "AUDIT_ANCHOR_SEALED" {
		t.Fatalf("sealing the anchor is not audited: %+v", got[len(got)-2])
	}
	// An unkeyed event appended after the cutover is refused although its own hash is correct.
	events := readAuditLines(t, path)
	last := events[len(events)-1]
	extra := models.AuditEvent{ID: "aud-late", Revision: last.Revision + 1, Timestamp: time.Now().UTC(), Actor: "attacker", Action: "LEGACY", PrevHash: last.EventHash}
	extra.EventHash = auditHashV1(extra.PrevHash, extra)
	writeAuditLines(t, path, append(events, extra))
	closeAuditStore(st, sink)
	st, _ = openAuditStore(t, dir, path)
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "downgrade") && !strings.Contains(res.Error, "diverged") {
		t.Fatalf("unkeyed event after the cutover accepted: %+v", res)
	}
}

func TestAuditSecretsMustStaySealed(t *testing.T) {
	key, _ := sealed.DeriveKey(strings.Repeat("a", 48))
	if err := sealed.Configure(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sealed.Configure(nil) })
	dir, other := t.TempDir(), t.TempDir()
	newTestStore(t, dir, false).Close()
	newTestStore(t, other, false).Close()
	raw, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
	if !bytes.Contains(raw, []byte(`"audit_anchor":"enc:v1:`)) || !bytes.Contains(raw, []byte(`"audit_chain_key":"enc:v1:`)) {
		t.Fatal("audit chain key or anchor not sealed at rest")
	}
	// Replacing the sealed key by a plain one (to re-key and recompute the chain) is refused.
	editStateFile(t, dir, func(state map[string]json.RawMessage) {
		state["audit_chain_key"], _ = json.Marshal(strings.Repeat("ab", 32))
	})
	if _, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine()}); err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("plain audit chain key accepted: %v", err)
	}
	// An anchor sealed by another installation (same encryption key) does not match the chain key.
	newDir := t.TempDir()
	newTestStore(t, newDir, false).Close()
	var foreign json.RawMessage
	editStateFile(t, other, func(state map[string]json.RawMessage) { foreign = state["audit_anchor"] })
	editStateFile(t, newDir, func(state map[string]json.RawMessage) { state["audit_anchor"] = foreign })
	st := newTestStore(t, newDir, false)
	if res := st.VerifyCompleteAudit(context.Background(), ""); res.OK || !strings.Contains(res.Error, "anchor") {
		t.Fatalf("foreign anchor accepted: %+v", res)
	}
	if _, err := st.VerifyAuditChain(); err == nil {
		t.Fatal("posture check accepted a foreign anchor")
	}
}

// Finding 2: the trail must start at its sealed origin and reach the newest event of the store.
func TestAuditVerificationAnchorsStartAndHead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, _ := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 3)
	rotateByCopy(t, path, path+"-20260101")
	mkAuditGroups(t, st, 3)
	rotateByCopy(t, path, path+"-20260201")
	mkAuditGroups(t, st, 3)
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || !res.StartsAtGenesis || !res.HeadMatches {
		t.Fatalf("intact trail: %+v", res)
	}
	// Removing the oldest generation is detected.
	if err := os.Rename(path+"-20260101", filepath.Join(dir, "archived-20260101")); err != nil {
		t.Fatal(err)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "sealed origin") {
		t.Fatalf("missing oldest generation not detected: %+v", res)
	}
	// Applying a retention point needs a Super Admin, re-seals the start and is audited.
	auditor := &auth.TokenClaims{UserID: "usr-aud", Username: "auditor", Role: models.RoleAuditorOperator, AllowedGroups: []string{"*"}}
	if _, err := st.ApplyAuditRetention(context.Background(), path, auditor); err == nil {
		t.Fatal("auditor applied a retention point")
	}
	if res, err := st.ApplyAuditRetention(context.Background(), path, adminClaims); err != nil || !res.OK {
		t.Fatalf("retention point: %+v %v", res, err)
	}
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK || res.StartsAtGenesis {
		t.Fatalf("trail after the retention point: %+v", res)
	}
	if got := st.GetSnapshot().AuditEvents[0]; got.Action != "AUDIT_RETENTION_APPLIED" {
		t.Fatalf("retention point not audited: %+v", got)
	}
	// Cutting the newest events off the end is detected.
	events := readAuditLines(t, path)
	writeAuditLines(t, path, events[:len(events)-1])
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || res.HeadMatches || !strings.Contains(res.Error, "newest events are missing") {
		t.Fatalf("missing newest event not detected: %+v", res)
	}
	// So is a missing newest generation.
	writeAuditLines(t, path, events)
	if err := os.Rename(path+"-20260201", filepath.Join(dir, "archived-20260201")); err != nil {
		t.Fatal(err)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK {
		t.Fatalf("missing generation not detected: %+v", res)
	}
}

// Finding 4: a renamed-away live file (logrotate dateext + nocreate) must not shrink the export to
// the in-memory window.
func TestAuditExportWithoutLiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, _ := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 4)
	want := exportedAuditIDs(t, st, path)
	rotateByCopy(t, path, path+"-20260901")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.state.AuditEvents = st.state.AuditEvents[:1] // the window holds far fewer events than the trail
	st.mu.Unlock()
	if got := exportedAuditIDs(t, st, path); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("export without live file: %d events, want %d", len(got), len(want))
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || res.Events != len(want) {
		t.Fatalf("verification without live file: %+v", res)
	}
	// The next event recreates the live file and continues the chain.
	mkAuditGroups(t, st, 1)
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || res.Events != len(want)+1 {
		t.Fatalf("verification after the live file was recreated: %+v", res)
	}
}

// Finding 5: generations are ordered by content, not by names (local-date logrotate names, UTC sink
// names, clock steps).
func TestAuditGenerationsOrderedByChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, _ := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 2)
	rotateByCopy(t, path, path+"-20261001") // logrotate, local date (sorts last by name)
	mkAuditGroups(t, st, 2)
	rotateByCopy(t, path, path+"-20260930235959") // sink, UTC (newer, sorts first by name)
	mkAuditGroups(t, st, 2)
	rotateByCopy(t, path, path+"-20260930120000") // clock stepped back
	mkAuditGroups(t, st, 2)
	var order []string
	for _, p := range rotatedAuditFiles(path) {
		order = append(order, strings.TrimPrefix(filepath.Base(p), "audit.jsonl"))
	}
	if strings.Join(order, ",") != "-20261001,-20260930235959,-20260930120000" {
		t.Fatalf("generation order %v", order)
	}
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK {
		t.Fatalf("verification across misnamed generations: %+v", res)
	}
	ids := exportedAuditIDs(t, st, path)
	win := st.GetSnapshot().AuditEvents
	for i, id := range ids {
		if win[len(win)-1-i].ID != id {
			t.Fatalf("export position %d: %s, want %s", i, id, win[len(win)-1-i].ID)
		}
	}
}

// Finding 6: a crash between the synchronous audit write and the asynchronous state save must not
// fork the chain.
func TestAuditCrashRecoveryAdoptsOrphanedEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	statePath := filepath.Join(dir, "aegis_state.json")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 2)
	closeAuditStore(st, sink)
	saved, _ := os.ReadFile(statePath)

	st, sink = openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 3)
	lost := st.GetSnapshot().AuditEvents[:3]
	closeAuditStore(st, sink)
	os.WriteFile(statePath, saved, 0o600) // the state save of these changes never happened

	st, sink = openAuditStore(t, dir, path)
	win := st.GetSnapshot().AuditEvents
	if win[0].Action != "AUDIT_TRAIL_RECOVERED" || !strings.Contains(win[0].Summary, lost[0].ID) {
		t.Fatalf("recovery not audited: %+v", win[0])
	}
	for i, ev := range lost {
		if win[1+i].ID != ev.ID {
			t.Fatalf("orphaned event %s not adopted (window %d: %s)", ev.ID, 1+i, win[1+i].ID)
		}
		if win[0].Revision <= ev.Revision {
			t.Fatalf("revision went backwards: %d after %d", win[0].Revision, ev.Revision)
		}
	}
	mkAuditGroups(t, st, 1)
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || !res.HeadMatches {
		t.Fatalf("chain forked after the crash: %+v", res)
	}

	// The other direction: the audit log lost its newest lines (restored from an older backup);
	// they are appended again from the window.
	closeAuditStore(st, sink)
	events := readAuditLines(t, path)
	writeAuditLines(t, path, events[:len(events)-2])
	st, _ = openAuditStore(t, dir, path)
	if got := readAuditLines(t, path); len(got) != len(events) || got[len(got)-1].ID != events[len(events)-1].ID {
		t.Fatalf("missing events not appended again: %d lines, want %d", len(got), len(events))
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("verification after completing the audit log: %+v", res)
	}
}

// Finding 7: a failed or short write (disk full) leaves no torn line, is reported and suspends
// changes until the audit log can be written again; nothing acknowledged is lost.
func TestAuditSinkShortWriteSuspendsChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 1)
	before, _ := os.ReadFile(path)
	sink.mu.Lock()
	sink.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
		n, _ := f.WriteAt(b[:len(b)/2], off)
		return n, errors.New("no space left on device (simulated)")
	}
	sink.mu.Unlock()
	mkAuditGroups(t, st, 1) // applied; its event stays in the window until the log is writable
	pending := st.GetSnapshot().AuditEvents[0]
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatalf("torn line left in the audit log:\n%q", after[len(before):])
	}
	if s := st.AuditStatus(); s.Writable || !strings.Contains(s.Error, "no space") {
		t.Fatalf("failure not reported: %+v", s)
	}
	_, err := st.UpsertGroup(models.ServerGroup{ID: "grp-refused", Name: "x"}, adminClaims)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("change accepted while the audit log is not writable: %v", err)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || res.HeadMatches {
		t.Fatalf("verification passed with an event missing from the audit log: %+v", res)
	}
	// Space is available again: the next change first completes the log.
	sink.mu.Lock()
	sink.writeAt = (*os.File).WriteAt
	sink.mu.Unlock()
	mkAuditGroups(t, st, 1)
	got := readAuditLines(t, path)
	if len(got) < 2 || got[len(got)-2].ID != pending.ID {
		t.Fatalf("pending event %s not appended after recovery", pending.ID)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || !st.AuditStatus().Writable {
		t.Fatalf("after recovery: %+v %+v", res, st.AuditStatus())
	}
}

func TestAuditSinkRemovesTornTailAtOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 2)
	closeAuditStore(st, sink)
	good, _ := os.ReadFile(path)
	// Crash in the middle of a write (the state save of that change never happened either).
	os.WriteFile(path, append(append([]byte(nil), good...), `{"id":"aud-torn","summa`...), 0o600)
	st, _ = openAuditStore(t, dir, path)
	if got, _ := os.ReadFile(path); !bytes.HasPrefix(got, good) || bytes.Contains(got, []byte("aud-torn")) {
		t.Fatalf("torn tail not removed:\n%s", got)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("after removing the torn tail: %+v", res)
	}
}

// Finding 9: compression never replaces an existing .gz and keeps the original then.
func TestAuditCompressionNeverReplacesGeneration(t *testing.T) {
	dir := t.TempDir()
	var mu sync.RWMutex
	p := filepath.Join(dir, "audit.jsonl-20260101000000")
	os.WriteFile(p, []byte("one\n"), 0o600)
	if err := compressAuditGeneration(p, &mu); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p + ".gz")
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != "one\n" {
		t.Fatalf("compressed content %q", b)
	}
	f.Close()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("original not removed after compression")
	}
	p2 := filepath.Join(dir, "audit.jsonl-20260102000000")
	os.WriteFile(p2, []byte("two\n"), 0o600)
	os.WriteFile(p2+".gz", []byte("an older generation"), 0o600)
	if err := compressAuditGeneration(p2, &mu); err == nil {
		t.Fatal("existing compressed generation replaced")
	}
	if b, _ := os.ReadFile(p2 + ".gz"); string(b) != "an older generation" {
		t.Fatal("existing compressed generation modified")
	}
	if b, _ := os.ReadFile(p2); string(b) != "two\n" {
		t.Fatal("original removed although it was not compressed")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp*")); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

// Finding 10: a slow export neither blocks rotation and compression nor shutdown, and still returns
// the consistent snapshot taken when it started.
func TestSlowAuditExportDoesNotBlockRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	sink.RotateAtSize(2 << 10)
	mkAuditGroups(t, st, 12)
	time.Sleep(1100 * time.Millisecond)
	mkAuditGroups(t, st, 12)
	sink.compress.Wait()
	want := exportedAuditIDs(t, st, path)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := st.ExportAudit(context.Background(), pw, path)
		pw.CloseWithError(err)
		done <- err
	}()
	head := make([]byte, 64)
	if _, err := io.ReadFull(pr, head); err != nil {
		t.Fatal(err)
	}
	// The export stalls (slow client) while rotation and compression continue.
	before := len(auditGenerationNames(path))
	for round := 0; round < 2; round++ {
		time.Sleep(1100 * time.Millisecond)
		mkAuditGroups(t, st, 12)
	}
	waited := make(chan struct{})
	go func() { sink.compress.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("compression blocked by a stalled export")
	}
	if after := len(auditGenerationNames(path)); after <= before {
		t.Fatalf("no rotation during a stalled export: %d -> %d generations", before, after)
	}
	rest, err := io.ReadAll(pr)
	if err != nil || <-done != nil {
		t.Fatalf("stalled export failed: %v", err)
	}
	var got []string
	if err := scanAuditLines(bytes.NewReader(append(head, rest...)), func(_ int, ev models.AuditEvent) error {
		got = append(got, ev.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stalled export returned %d events, want the %d of its snapshot", len(got), len(want))
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("verification after rotation during an export: %+v", res)
	}
}

// Finding 11: rotation never creates a plain twin of an existing .gz generation, and generations
// with colliding names but different content are both read.
func TestAuditRotationNeverShadowsCompressedGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	now := time.Now().UTC()
	var taken []string
	for i := 0; i < 3; i++ {
		p := path + "-" + now.Add(time.Duration(i)*time.Second).Format("20060102150405") + ".gz"
		os.WriteFile(p, []byte("not ours"), 0o600)
		taken = append(taken, p)
	}
	sink.RotateAtSize(1) // rotate after every event
	mkAuditGroups(t, st, 1)
	for _, p := range taken {
		if _, err := os.Stat(strings.TrimSuffix(p, ".gz")); err == nil {
			t.Fatalf("rotation created %s next to an existing compressed generation", filepath.Base(p))
		}
		if b, _ := os.ReadFile(p); string(b) != "not ours" {
			t.Fatalf("%s modified", filepath.Base(p))
		}
	}

	// Listing: a plain and a compressed generation with the same name but different content.
	dir2 := t.TempDir()
	path2 := filepath.Join(dir2, "audit.jsonl")
	a := models.AuditEvent{ID: "aud-a", Revision: 1, PrevHash: zeroHash, EventHash: "a"}
	b := models.AuditEvent{ID: "aud-b", Revision: 2, PrevHash: "a", EventHash: "b"}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	line, _ := json.Marshal(a)
	zw.Write(append(line, '\n'))
	zw.Close()
	os.WriteFile(path2+"-20260101000000.gz", gz.Bytes(), 0o600)
	writeAuditLines(t, path2+"-20260101000000", []models.AuditEvent{b})
	var got []string
	for _, p := range rotatedAuditFiles(path2) {
		got = append(got, filepath.Base(p))
	}
	if strings.Join(got, ",") != "audit.jsonl-20260101000000.gz,audit.jsonl-20260101000000" {
		t.Fatalf("colliding generations: %v", got)
	}
	// The same generation twice (compression interrupted before the original was removed) is read once.
	gz.Reset()
	zw = gzip.NewWriter(&gz)
	line, _ = json.Marshal(b)
	zw.Write(append(line, '\n'))
	zw.Close()
	os.WriteFile(path2+"-20260101000000.gz", gz.Bytes(), 0o600)
	if got := rotatedAuditFiles(path2); len(got) != 1 || strings.HasSuffix(got[0], ".gz") {
		t.Fatalf("duplicate generation: %v", got)
	}
}
