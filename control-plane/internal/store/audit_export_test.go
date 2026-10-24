package store

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/engine"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/threatintel"
)

func exportedAuditIDs(t *testing.T, st *Store, path string) []string {
	t.Helper()
	var buf bytes.Buffer
	if err := st.ExportAudit(context.Background(), &buf, path); err != nil {
		t.Fatal(err)
	}
	var ids []string
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var ev models.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("invalid line %q: %v", sc.Text(), err)
		}
		ids = append(ids, ev.ID)
	}
	return ids
}

func TestAuditExportIncludesRotatedGenerations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename the open audit log (sharing violation); the sink rotates itself: TestAuditSinkRotatesBySize")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, BootstrapAdminPassword: "Export-Test-Pass-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mkGroup := func(id string) {
		if _, err := st.UpsertGroup(models.ServerGroup{ID: id, Name: id, CIDRs: []string{"10.0.0.0/8"}}, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	mkGroup("grp-a")
	before := exportedAuditIDs(t, st, path)
	if len(before) == 0 {
		t.Fatal("no audit events exported")
	}

	// logrotate: rename + compress an older generation; the sink must reopen a fresh file.
	if err := os.Rename(path, path+"-20260901"); err != nil {
		t.Fatal(err)
	}
	mkGroup("grp-b")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sink did not recreate the audit log after rotation: %v", err)
	}
	raw, _ := os.ReadFile(path + "-20260901")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw)
	zw.Close()
	os.WriteFile(path+"-20260801.gz", gz.Bytes(), 0o600)
	os.Remove(path + "-20260901")
	mkGroup("grp-c")
	os.Rename(path, path+"-20261001")
	mkGroup("grp-d")

	ids := exportedAuditIDs(t, st, path)
	if len(ids) != len(before)+3 {
		t.Fatalf("exported %d events, want %d", len(ids), len(before)+3)
	}
	for i, id := range before {
		if ids[i] != id {
			t.Fatalf("event %d: %s, want %s (oldest generation first)", i, ids[i], id)
		}
	}
	// The export is in append order and matches the complete hash chain of the store.
	snap := st.GetSnapshot()
	if snap.AuditEvents[0].ID != ids[len(ids)-1] {
		t.Fatalf("newest exported event %s, newest stored %s", ids[len(ids)-1], snap.AuditEvents[0].ID)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate event %s", id)
		}
		seen[id] = true
	}
}

func TestRotatedAuditFileOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for _, n := range []string{"audit.jsonl", "audit.jsonl-20260201.gz", "audit.jsonl-20260101.gz", "audit.jsonl-20260301", "audit.jsonl.bak", "audit.jsonl.2.gz", "audit.jsonl.1", "other.jsonl-20260101"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	got := rotatedAuditFiles(path)
	want := []string{"audit.jsonl.2.gz", "audit.jsonl.1", "audit.jsonl-20260101.gz", "audit.jsonl-20260201.gz", "audit.jsonl-20260301"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if filepath.Base(got[i]) != want[i] {
			t.Fatalf("position %d: %s, want %s (all: %v)", i, filepath.Base(got[i]), want[i], got)
		}
	}
}

func TestCompleteAuditVerificationDetectsForgery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// A pre-2.1 (unkeyed) event at the start of the trail stays verifiable after the upgrade.
	legacy := writeLegacyInstallation(t, dir, path)
	st, _ := openAuditStore(t, dir, path)
	for _, g := range []string{"grp-1", "grp-2", "grp-3"} {
		if _, err := st.UpsertGroup(models.ServerGroup{ID: g, Name: g}, adminClaims); err != nil {
			t.Fatal(err)
		}
	}
	// legacy + AUDIT_ANCHOR_SEALED + 3 changes
	res := st.VerifyCompleteAudit(context.Background(), path)
	if !res.OK || res.Events != 5 || res.Legacy != 1 || res.FirstID != legacy.ID || !res.StartsAtGenesis || !res.HeadMatches {
		t.Fatalf("verification of an intact trail: %+v", res)
	}
	raw, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	var ev models.AuditEvent
	json.Unmarshal(lines[2], &ev)
	if ev.HashVersion != 2 {
		t.Fatalf("new events must use hash version 2: %+v", ev)
	}
	// An attacker with file/database access rewrites a summary and recomputes an unkeyed hash.
	ev.Summary = "nothing happened"
	ev.EventHash = auditHashV1(ev.PrevHash, ev)
	ev.HashVersion = 0
	forged, _ := json.Marshal(ev)
	orig := lines[2]
	lines[2] = forged
	os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600)
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "downgrade") {
		t.Fatalf("forgery not detected: %+v", res)
	}
	// Dropping an event breaks the chain.
	lines[2] = orig
	os.WriteFile(path, append(bytes.Join([][]byte{lines[0], lines[1], lines[3], lines[4]}, []byte("\n")), '\n'), 0o600)
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "chain broken") {
		t.Fatalf("missing event not detected: %+v", res)
	}
	st.mu.RLock()
	key := st.state.AuditChainKey
	st.mu.RUnlock()
	if len(key) != 64 || st.GetSnapshot().AuditChainKey != "" || st.GetSnapshot().AuditAnchor != "" {
		t.Fatalf("audit chain key missing or key/anchor exposed in snapshots (len %d)", len(key))
	}
}

func TestAuditSinkRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(path+"-20990101000000.gz.tmp", []byte("partial"), 0o600) // left behind by a crash
	sink, err := NewAuditSink(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if _, err := os.Stat(path + "-20990101000000.gz.tmp"); !os.IsNotExist(err) {
		t.Fatal("stale compression file not removed")
	}
	sink.RotateAtSize(2 << 10)
	ti, _ := threatintel.NewManager(threatintel.Options{CacheDir: filepath.Join(dir, "ti")})
	st, err := NewStore(Options{DataDir: dir, Engine: engine.NewPolicyEngine(), ThreatIntel: ti, AuditSink: sink, BootstrapAdminPassword: "Rotate-Test-Pass-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	gens := func() (plain, gz []string) {
		for _, p := range rotatedAuditFiles(path) {
			if strings.HasSuffix(p, ".gz") {
				gz = append(gz, p)
			} else {
				plain = append(plain, p)
			}
		}
		return
	}
	n := 0
	mkGroups := func(count int) {
		for i := 0; i < count; i++ {
			n++
			id := fmt.Sprintf("grp-%03d", n)
			if _, err := st.UpsertGroup(models.ServerGroup{ID: id, Name: id, CIDRs: []string{"10.0.0.0/8"}}, adminClaims); err != nil {
				t.Fatal(err)
			}
		}
	}
	// One rotation per second at most (the generation name has second precision).
	for round := 0; round < 3; round++ {
		mkGroups(8)
		time.Sleep(1100 * time.Millisecond)
	}
	mkGroups(8)
	sink.compress.Wait()
	plain, gz := gens()
	if len(plain)+len(gz) < 3 || len(gz) == 0 {
		t.Fatalf("expected several generations with older ones compressed: plain %v gz %v", plain, gz)
	}
	if len(plain) != 1 {
		t.Fatalf("only the newest generation stays uncompressed (delaycompress): %v", plain)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() >= 2<<10+4096 {
		t.Fatalf("current file not rotated: %v", err)
	}

	// The export streams every generation once, oldest first, and the complete chain verifies.
	ids := exportedAuditIDs(t, st, path)
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate event %s", id)
		}
		seen[id] = true
	}
	if snap := st.GetSnapshot(); snap.AuditEvents[0].ID != ids[len(ids)-1] {
		t.Fatalf("newest exported %s, newest stored %s", ids[len(ids)-1], snap.AuditEvents[0].ID)
	}
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK || res.Events != len(ids) {
		t.Fatalf("verification across rotated generations: %+v (exported %d)", res, len(ids))
	}

	if m, _ := filepath.Glob(path + "-*.tmp"); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

func TestRotatedAuditFileOrderMixedSchemes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for _, n := range []string{"audit.jsonl-20260101.gz", "audit.jsonl-20260115093000.gz", "audit.jsonl-20260201", "audit.jsonl-20260201120000", "audit.jsonl-20260201120000.gz", "audit.jsonl-20260301000000.gz.tmp"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	var got []string
	for _, p := range rotatedAuditFiles(path) {
		got = append(got, filepath.Base(p))
	}
	// A generation that is being compressed exists twice for a moment: the uncompressed file is listed.
	want := []string{"audit.jsonl-20260101.gz", "audit.jsonl-20260115093000.gz", "audit.jsonl-20260201", "audit.jsonl-20260201120000"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
