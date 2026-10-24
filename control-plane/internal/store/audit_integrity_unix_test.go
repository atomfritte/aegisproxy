//go:build !windows

package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s blocked (FIFO?)", what)
	}
}

// Finding 3: symbolic links and FIFOs are refused for the audit log and its generations, without
// ever blocking the store.
func TestAuditLogRefusesSymlinksAndFIFOs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditSink(path, nil); err == nil {
		t.Fatal("audit log opened through a symbolic link")
	}
	os.Remove(path)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, 5*time.Second, "opening a FIFO as audit log", func() {
		if _, err := NewAuditSink(path, nil); err == nil {
			t.Error("FIFO accepted as audit log")
		}
	})
	os.Remove(path)

	st, _ := openAuditStore(t, dir, path)
	mkAuditGroups(t, st, 1)
	// The live file is replaced by a FIFO nobody reads: writes fail at once instead of hanging with
	// the store lock held, and further changes are refused.
	os.Rename(path, path+"-20260101")
	syscall.Mkfifo(path, 0o600)
	within(t, 5*time.Second, "a change with a FIFO as audit log", func() { mkAuditGroups(t, st, 1) })
	within(t, 5*time.Second, "a refused change", func() {
		if _, err := st.UpsertGroup(models.ServerGroup{ID: "grp-refused", Name: "x"}, adminClaims); !errors.Is(err, ErrAuditUnavailable) {
			t.Errorf("change accepted although the audit log is a FIFO: %v", err)
		}
	})
	if st.AuditStatus().Writable {
		t.Fatal("FIFO audit log reported as writable")
	}
	os.Remove(path) // removed by the operator: the next change recreates the log and completes it
	mkAuditGroups(t, st, 1)
	if res := st.VerifyCompleteAudit(context.Background(), path); !res.OK {
		t.Fatalf("after recovery: %+v", res)
	}

	// A FIFO or symbolic link posing as a generation makes export and verification fail, not hang.
	syscall.Mkfifo(path+"-20250101", 0o600)
	within(t, 5*time.Second, "an export with a FIFO generation", func() {
		if err := st.ExportAudit(context.Background(), io.Discard, path); err == nil || !strings.Contains(err.Error(), "20250101") {
			t.Errorf("FIFO generation exported: %v", err)
		}
	})
	os.Remove(path + "-20250101")
	os.Symlink(victim, path+"-20250102")
	if res := st.VerifyCompleteAudit(context.Background(), path); res.OK || !strings.Contains(res.Error, "20250102") {
		t.Fatalf("symbolic link generation accepted: %+v", res)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("link target modified")
	}
}

// Finding 9: compression never writes through a planted symbolic link.
func TestAuditCompressionIgnoresPlantedLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	var mu sync.RWMutex
	p := filepath.Join(dir, "audit.jsonl-20260101000000")
	os.WriteFile(p, []byte("one\n"), 0o600)
	os.Symlink(victim, p+".gz.tmp") // the fixed temporary name of earlier releases
	if err := compressAuditGeneration(p, &mu); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(p + ".gz"); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("compressed generation: %v", err)
	}
	p2 := filepath.Join(dir, "audit.jsonl-20260102000000")
	os.WriteFile(p2, []byte("two\n"), 0o600)
	os.Symlink(victim, p2+".gz")
	if err := compressAuditGeneration(p2, &mu); err == nil {
		t.Fatal("compressed into a planted link")
	}
	if b, _ := os.ReadFile(p2); !bytes.Equal(b, []byte("two\n")) {
		t.Fatal("original removed")
	}
	// A symbolic link posing as the generation itself is not compressed (nor removed).
	p3 := filepath.Join(dir, "audit.jsonl-20260103000000")
	os.Symlink(victim, p3)
	if err := compressAuditGeneration(p3, &mu); err == nil {
		t.Fatal("compressed through a symbolic link")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("link target modified")
	}
	if _, err := os.Lstat(p3); err != nil {
		t.Fatal("link removed")
	}
}
