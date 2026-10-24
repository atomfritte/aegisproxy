package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

// Round-2 review: removing the audit chain key, the anchor or the checkpoint must never make a
// re-written or truncated trail verify again.

func hasAuditAlert(st *Store, typ string) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return slices.ContainsFunc(st.state.SecurityEvents, func(ev models.SecurityEvent) bool {
		return ev.Type == typ && ev.Severity == "high"
	})
}

func windowHas(st *Store, action string) bool {
	return slices.ContainsFunc(st.GetSnapshot().AuditEvents, func(ev models.AuditEvent) bool { return ev.Action == action })
}

// rehashUnkeyed re-links events read oldest first with the unkeyed pre-2.1 hash, as an insider
// without the audit chain key can.
func rehashUnkeyed(events []models.AuditEvent) []models.AuditEvent {
	out := slices.Clone(events)
	prev := zeroHash
	for i := range out {
		out[i].HashVersion, out[i].PrevHash = 0, prev
		out[i].EventHash = auditHashV1(prev, out[i])
		prev = out[i].EventHash
	}
	return out
}

// setTrail writes events (oldest first) to the audit log and the state window.
func setTrail(t *testing.T, dir, path string, events []models.AuditEvent, edit func(state map[string]json.RawMessage)) {
	t.Helper()
	writeAuditLines(t, path, events)
	window := slices.Clone(events)
	slices.Reverse(window)
	editStateFile(t, dir, func(state map[string]json.RawMessage) {
		state["audit_events"], _ = json.Marshal(window)
		if edit != nil {
			edit(state)
		}
	})
}

func deleteKeys(keys ...string) func(map[string]json.RawMessage) {
	return func(state map[string]json.RawMessage) {
		for _, k := range keys {
			delete(state, k)
		}
	}
}

func mustFailVerify(t *testing.T, st *Store, path, want string) AuditVerification {
	t.Helper()
	res := st.VerifyCompleteAudit(context.Background(), path)
	if res.OK || !strings.Contains(res.Error, want) {
		t.Fatalf("verification must fail with %q: %+v", want, res)
	}
	return res
}

// Finding 1: an insider removes audit_chain_key and audit_anchor (and the checkpoint) and re-hashes
// the trail with the unkeyed algorithm. That looks like an upgrade from before 2.1, so the prefix is
// sealed as pending: verification fails, an alert is raised, and only a Super Admin can accept it.
func TestAuditKeyAndAnchorRemovalIsNeverAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 4)
	closeAuditStore(st, sink)
	events := readAuditLines(t, path)
	victim := events[2]
	forged := rehashUnkeyed(append(slices.Clone(events[:2]), events[3:]...))
	setTrail(t, dir, path, forged, deleteKeys("audit_chain_key", "audit_anchor", "audit_checkpoint"))

	st, sink = openAuditStore(t, dir, path)
	res := mustFailVerify(t, st, path, "legacy_pending")
	if !res.LegacyPending || res.Legacy != len(forged) || res.LegacyHead != forged[len(forged)-1].EventHash {
		t.Fatalf("pending prefix not reported: %+v", res)
	}
	if s := st.AuditStatus(); !s.LegacyPending || s.LegacyEvents != len(forged) {
		t.Fatalf("status: %+v", s)
	}
	if !hasAuditAlert(st, SecurityEventAuditLegacyPending) || !windowHas(st, "AUDIT_ANCHOR_SEALED") {
		t.Fatal("the pending seal raised no alert or was not audited")
	}
	mkAuditGroups(t, st, 1) // the control-plane keeps working; new events are keyed
	mustFailVerify(t, st, path, "legacy_pending")
	closeAuditStore(st, sink)
	st, _ = openAuditStore(t, dir, path)
	mustFailVerify(t, st, path, "legacy_pending")
	for _, ev := range readAuditLines(t, path) {
		if ev.ID == victim.ID {
			t.Fatal("test setup: the victim event is still in the trail")
		}
	}
}

func TestAuditAnchorRemovalFromKeyedInstallationIsViolation(t *testing.T) {
	cases := []struct {
		name   string
		rehash bool
		remove []string
	}{
		// The checkpoint gives the 2.1 installation away although key and anchor are gone.
		{"re-hashed, checkpoint left", true, []string{"audit_chain_key", "audit_anchor"}},
		// Keyed events give it away.
		{"keyed trail", false, []string{"audit_chain_key", "audit_anchor", "audit_checkpoint"}},
		// The key gives it away (finding 2: anchor removed, chain key kept).
		{"anchor only", false, []string{"audit_anchor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			st, sink := openAuditStore(t, dir, path)
			mkAuditGroups(t, st, 3)
			closeAuditStore(st, sink)
			events := readAuditLines(t, path)
			if tc.rehash {
				events = rehashUnkeyed(events)
			}
			setTrail(t, dir, path, events, deleteKeys(tc.remove...))

			st, sink = openAuditStore(t, dir, path)
			mustFailVerify(t, st, path, "anchor is missing")
			if s := st.AuditStatus(); s.Integrity == "" || s.LegacyPending {
				t.Fatalf("status: %+v", s)
			}
			if !hasAuditAlert(st, SecurityEventAuditViolation) || !windowHas(st, "AUDIT_INTEGRITY_VIOLATION") {
				t.Fatal("violation not alerted or not audited")
			}
			mkAuditGroups(t, st, 1)
			closeAuditStore(st, sink)
			// Never re-sealed silently: the next start reports it again.
			st, _ = openAuditStore(t, dir, path)
			mustFailVerify(t, st, path, "anchor is missing")
		})
	}
}

// Finding 2: the oldest events are cut off and only the anchor is removed.
func TestAuditStartCutWithoutAnchorIsViolation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 4)
	closeAuditStore(st, sink)
	events := readAuditLines(t, path)
	setTrail(t, dir, path, events[3:], deleteKeys("audit_anchor"))

	st, sink = openAuditStore(t, dir, path)
	mustFailVerify(t, st, path, "anchor is missing")
	if !hasAuditAlert(st, SecurityEventAuditViolation) {
		t.Fatal("no alert")
	}
	closeAuditStore(st, sink)
	st, _ = openAuditStore(t, dir, path)
	mustFailVerify(t, st, path, "anchor is missing")
}

// Finding 3: the newest events are cut off the log and the state window; the configuration stays.
func TestAuditTailTruncationIsDetected(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, dir string, state map[string]json.RawMessage)
		want string
	}{
		{"checkpoint kept", nil, "newest events were removed"},
		{"checkpoint removed", func(t *testing.T, dir string, state map[string]json.RawMessage) {
			delete(state, "audit_checkpoint")
		}, "checkpoint is missing"},
		{"checkpoint rewritten", func(t *testing.T, dir string, state map[string]json.RawMessage) {
			var cp AuditCheckpoint
			json.Unmarshal(state["audit_checkpoint"], &cp)
			var win []models.AuditEvent
			json.Unmarshal(state["audit_events"], &win)
			cp.Head, cp.HeadRevision, cp.Events = win[0].EventHash, win[0].Revision, cp.Events-1
			state["audit_checkpoint"], _ = json.Marshal(cp)
		}, "does not match the audit chain key"},
		// The checkpoint of the previous save (e.g. from aegis_state.json.bak) matches the cut window
		// but not the configuration it is pasted into.
		{"older checkpoint transplanted", func(t *testing.T, dir string, state map[string]json.RawMessage) {
			raw, err := os.ReadFile(filepath.Join(dir, "state-before-victim.json"))
			if err != nil {
				t.Fatal(err)
			}
			var old map[string]json.RawMessage
			json.Unmarshal(raw, &old)
			state["audit_checkpoint"] = old["audit_checkpoint"]
		}, "configuration is at revision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			st, sink := openAuditStore(t, dir, path)
			mkAuditGroups(t, st, 3)
			st.persist(true)
			before, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
			os.WriteFile(filepath.Join(dir, "state-before-victim.json"), before, 0o600)
			mkAuditGroups(t, st, 1) // the victim change
			closeAuditStore(st, sink)
			events := readAuditLines(t, path)
			setTrail(t, dir, path, events[:len(events)-1], func(state map[string]json.RawMessage) {
				if tc.edit != nil {
					tc.edit(t, dir, state)
				}
			})

			st, sink = openAuditStore(t, dir, path)
			mustFailVerify(t, st, path, tc.want)
			if s := st.AuditStatus(); s.Integrity == "" {
				t.Fatalf("status: %+v", s)
			}
			if !hasAuditAlert(st, SecurityEventAuditViolation) || !windowHas(st, "AUDIT_INTEGRITY_VIOLATION") {
				t.Fatal("violation not alerted or not audited")
			}
			mkAuditGroups(t, st, 1)
			closeAuditStore(st, sink)
			// The violation is sealed into the checkpoint: it is reported after every restart.
			st, _ = openAuditStore(t, dir, path)
			mustFailVerify(t, st, path, "integrity violation recorded")
		})
	}
}

// The checkpoint must not raise false alarms: restarts, a crash between the log write and the state
// save, and a restored older state file (the log keeps the newer events).
func TestAuditCheckpointWithoutFalsePositives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 3)
	for range 2 {
		closeAuditStore(st, sink)
		st, sink = openAuditStore(t, dir, path)
		res := st.VerifyCompleteAudit(context.Background(), path)
		if !res.OK || !res.CheckpointMatches || res.CheckpointEvents != res.Events || res.LegacyPending {
			t.Fatalf("after a restart: %+v", res)
		}
	}
	st.persist(true)
	saved, _ := os.ReadFile(filepath.Join(dir, "aegis_state.json"))
	mkAuditGroups(t, st, 2)
	closeAuditStore(st, sink)
	if err := os.WriteFile(filepath.Join(dir, "aegis_state.json"), saved, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ = openAuditStore(t, dir, path)
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK || !res.CheckpointMatches || st.AuditStatus().Integrity != "" || hasAuditAlert(st, SecurityEventAuditViolation) {
		t.Fatalf("after recovering newer events: %+v %+v", res, st.AuditStatus())
	}
	if !windowHas(st, "AUDIT_TRAIL_RECOVERED") {
		t.Fatal("recovery not audited")
	}
}

// A fresh installation seals its genesis anchor without anybody's help.
func TestAuditFreshInstallationNeedsNoAcceptance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, _ := openAuditStore(t, dir, path)
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK || res.LegacyPending || !res.StartsAtGenesis || !res.CheckpointMatches {
		t.Fatalf("fresh installation: %+v", res)
	}
	if hasAuditAlert(st, SecurityEventAuditLegacyPending) || hasAuditAlert(st, SecurityEventAuditViolation) {
		t.Fatal("alert on a fresh installation")
	}
}

// The documented way to start a new trail (encryption key lost): archive the log, remove the trail
// and its seals from the state. It is pending like a legacy trail until a Super Admin accepts it.
func TestAuditNewTrailNeedsAcceptance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 2)
	closeAuditStore(st, sink)
	if err := os.Rename(path, filepath.Join(t.TempDir(), "archived.jsonl")); err != nil {
		t.Fatal(err)
	}
	editStateFile(t, dir, deleteKeys("audit_chain_key", "audit_anchor", "audit_checkpoint", "audit_events"))

	st, _ = openAuditStore(t, dir, path)
	if res := mustFailVerify(t, st, path, "legacy_pending"); res.Legacy != 0 || res.LegacyHead != zeroHash {
		t.Fatalf("new trail: %+v", res)
	}
	if !hasAuditAlert(st, SecurityEventAuditLegacyPending) {
		t.Fatal("no alert for the new trail")
	}
	if _, err := st.AcceptLegacyAudit(context.Background(), path, 0, zeroHash, adminClaims); err != nil {
		t.Fatal(err)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || !res.CheckpointMatches {
		t.Fatalf("after acceptance: %+v", res)
	}
}

// Finding 13: a retention point raises an alert.
func TestAuditRetentionRaisesAlert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, _ := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 3)
	rotateByCopy(t, path, path+"-20260101")
	mkAuditGroups(t, st, 2)
	if err := os.Remove(path + "-20260101"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyAuditRetention(context.Background(), path, adminClaims); err != nil {
		t.Fatal(err)
	}
	if !hasAuditAlert(st, SecurityEventAuditRetention) {
		t.Fatal("no alert for the retention point")
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || !res.CheckpointMatches || res.CheckpointEvents != res.Events {
		t.Fatalf("after the retention point: %+v", res)
	}
}

// AUDIT_CHECKPOINT records go to the exported audit stream (outside the hash chain).
func TestAuditCheckpointsAreExported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := export.New(export.Options{SpoolDir: filepath.Join(dir, "spool"), ExportDir: filepath.Join(dir, "export")})
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, Exporter: exp,
		BootstrapAdminPassword: "Audit-Test-Pass-1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		exp.Close()
		sink.Close()
	})
	if _, err := st.UpsertExportSink(models.ExportSink{Name: "siem", Type: "file", Enabled: true, Format: "json",
		Endpoint: "audit-export.jsonl", Streams: []string{models.StreamAudit}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "export", "audit-export.jsonl")
	eventually(t, "export sink running", func() bool {
		mkAuditGroups(t, st, 1)
		raw, _ := os.ReadFile(out)
		return strings.Contains(string(raw), "GROUP_CREATED")
	})
	mkAuditGroups(t, st, auditCheckpointEvery)
	eventually(t, "checkpoint record exported", func() bool {
		raw, _ := os.ReadFile(out)
		return strings.Contains(string(raw), "AUDIT_CHECKPOINT")
	})
	raw, _ := os.ReadFile(out)
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "AUDIT_CHECKPOINT") {
			continue
		}
		if !strings.Contains(line, `\"mac\"`) || !strings.Contains(line, `\"head\"`) || strings.Contains(line, `"event_hash"`) {
			t.Fatalf("checkpoint record: %s", line)
		}
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("checkpoint records must stay out of the trail: %+v", res)
	}
}

// Finding 9: an emergency login is refused when it cannot be recorded in the audit log.
func TestBreakGlassLoginRefusedWhenAuditLogUnwritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	st, sink := openAuditStore(t, dir, path)
	st.mu.Lock()
	st.state.EntraConfig.Enabled, st.state.EntraConfig.AllowLocalLogin = true, false
	for i := range st.state.Users {
		if st.state.Users[i].Username == "admin" {
			st.state.Users[i].BreakGlass = true
		}
	}
	st.mu.Unlock()
	sink.mu.Lock()
	sink.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
		return 0, errors.New("no space left on device (simulated)")
	}
	sink.mu.Unlock()
	if u, err := st.AuthenticateLocal("admin", "Audit-Test-Pass-1"); err == nil || !errors.Is(err, ErrAuditUnavailable) || u != nil {
		t.Fatalf("unaudited break-glass login: %v %v", u, err)
	}
	sink.mu.Lock()
	sink.writeAt = (*os.File).WriteAt
	sink.mu.Unlock()
	if _, err := st.AuthenticateLocal("admin", "Audit-Test-Pass-1"); err != nil {
		t.Fatalf("break-glass login once the log is writable: %v", err)
	}
	n := 0
	for _, ev := range readAuditLines(t, path) {
		if ev.Action == "BREAK_GLASS_LOGIN" {
			n++
		}
	}
	if n == 0 {
		t.Fatal("break-glass login not in the audit log")
	}
}
