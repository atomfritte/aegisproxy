package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// openAuditFile refuses a symbolic link at the final path component and a directory, without
// following the link, for reading and writing.
func TestOpenAuditFileRefusesReparsePoints(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.jsonl")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openAuditFile(target, false)
	if err != nil {
		t.Fatalf("regular file: %v", err)
	}
	f.Close()
	// CreateFile refuses a directory without FILE_FLAG_BACKUP_SEMANTICS (access denied).
	if f, err := openAuditFile(dir, false); err == nil {
		f.Close()
		t.Fatal("directory opened")
	}
	link := filepath.Join(dir, "audit.jsonl")
	// Creating links needs SeCreateSymbolicLinkPrivilege or developer mode; Wine reports success
	// without creating one.
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Skipf("no symbolic link was created: %v", err)
	}
	for _, write := range []bool{false, true} {
		if f, err := openAuditFile(link, write); !errors.Is(err, errNotRegularFile) {
			if f != nil {
				f.Close()
			}
			t.Fatalf("symbolic link opened (write=%v): %v", write, err)
		}
	}
	if data, _ := os.ReadFile(target); string(data) != "{}\n" {
		t.Fatalf("link target changed: %q", data)
	}
}
