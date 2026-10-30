package runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTgz builds a .tar.gz from a list of entries into a temp file and returns its path.
type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
	mode     int64
}

func writeTgz(t *testing.T, entries []tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: tf, Linkname: e.linkname, Mode: e.mode}
		if tf == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			tw.Write(e.body)
		}
	}
	tw.Close()
	gz.Close()
	path := filepath.Join(t.TempDir(), "a.tgz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractRejectsTraversalAndAbsolute(t *testing.T) {
	src := writeTgz(t, []tarEntry{
		{name: "package/index.js", body: []byte("console.log(1)\n")},
		{name: "../escape.txt", body: []byte("nope")},
		{name: "/etc/evil", body: []byte("nope")},
		{name: "package/../../deep.txt", body: []byte("nope")},
	})
	dst := t.TempDir()
	res, err := Extract(dst, src, "tgz", DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if res.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1", res.FileCount)
	}
	if len(res.Rejected) != 3 {
		t.Errorf("Rejected = %v, want 3", res.Rejected)
	}
	// Nothing must exist outside dst.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escape.txt")); err == nil {
		t.Error("traversal file escaped the root")
	}
	if _, err := os.Stat("/etc/evil"); err == nil {
		t.Error("absolute path escaped")
	}
}

func TestExtractDoesNotMaterializeSymlinks(t *testing.T) {
	src := writeTgz(t, []tarEntry{
		{name: "package/ok.txt", body: []byte("x")},
		{name: "package/link", typeflag: tar.TypeSymlink, linkname: "../../../../etc/passwd"},
		{name: "package/inner", typeflag: tar.TypeSymlink, linkname: "ok.txt"},
	})
	dst := t.TempDir()
	res, err := Extract(dst, src, "tgz", DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "package", "link")); err == nil {
		t.Error("symlink was materialized")
	}
	// The escaping link is a rejection; the in-root link is a non-fatal warning.
	if len(res.Rejected) != 1 {
		t.Errorf("Rejected = %v, want 1 (escaping symlink)", res.Rejected)
	}
}

func TestExtractRejectsDeviceNodes(t *testing.T) {
	src := writeTgz(t, []tarEntry{
		{name: "package/ok.txt", body: []byte("x")},
		{name: "package/dev", typeflag: tar.TypeChar},
	})
	dst := t.TempDir()
	res, _ := Extract(dst, src, "tgz", DefaultExtractLimits())
	if res.FileCount != 1 || len(res.Rejected) != 1 {
		t.Errorf("FileCount=%d Rejected=%v", res.FileCount, res.Rejected)
	}
}

func TestExtractTotalCap(t *testing.T) {
	// Two 1 MiB files, total cap 1.5 MiB: the second write hits the cap.
	big := bytes.Repeat([]byte("A"), 1<<20)
	src := writeTgz(t, []tarEntry{
		{name: "package/a.bin", body: big},
		{name: "package/b.bin", body: big},
	})
	dst := t.TempDir()
	lim := DefaultExtractLimits()
	lim.MaxTotalBytes = 1536 << 10
	res, _ := Extract(dst, src, "tgz", lim)
	if !res.LimitHit {
		t.Error("LimitHit should be set")
	}
	if res.TotalBytes > lim.MaxTotalBytes {
		t.Errorf("TotalBytes %d exceeds cap %d", res.TotalBytes, lim.MaxTotalBytes)
	}
}

func TestExtractPerFileCapTruncates(t *testing.T) {
	src := writeTgz(t, []tarEntry{
		{name: "package/a.bin", body: bytes.Repeat([]byte("A"), 4096)},
	})
	dst := t.TempDir()
	lim := DefaultExtractLimits()
	lim.MaxFileBytes = 1024
	res, _ := Extract(dst, src, "tgz", lim)
	if res.Files[0].Size != 1024 {
		t.Errorf("file size = %d, want 1024 (truncated)", res.Files[0].Size)
	}
}

func TestExtractFileCountCap(t *testing.T) {
	var entries []tarEntry
	for i := 0; i < 50; i++ {
		entries = append(entries, tarEntry{name: "package/f" + itoa(i) + ".txt", body: []byte("x")})
	}
	dst := t.TempDir()
	lim := DefaultExtractLimits()
	lim.MaxFiles = 10
	res, _ := Extract(dst, writeTgz(t, entries), "tgz", lim)
	if res.FileCount != 10 || !res.LimitHit {
		t.Errorf("FileCount=%d LimitHit=%v", res.FileCount, res.LimitHit)
	}
}

func TestExtractZipBombRatio(t *testing.T) {
	// A highly compressible 4 MiB member; the central-directory ratio check rejects it.
	path := filepath.Join(t.TempDir(), "b.zip")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("package/zeros.bin")
	w.Write(bytes.Repeat([]byte{0}, 4<<20))
	zw.Close()
	f.Close()

	dst := t.TempDir()
	res, err := Extract(dst, path, "zip", DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.BombSuspected {
		t.Error("BombSuspected should be set for a high-ratio member")
	}
}

func TestExtractKinds(t *testing.T) {
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	src := writeTgz(t, []tarEntry{
		{name: "package/index.js", body: []byte("module.exports = 1\n")},
		{name: "package/native.node", body: elf},
		{name: "package/readme.txt", body: []byte("hello world\n")},
		{name: "package/blob.bin", body: []byte{0, 1, 2, 3, 0, 0xff}},
	})
	dst := t.TempDir()
	res, _ := Extract(dst, src, "tgz", DefaultExtractLimits())
	kinds := map[string]string{}
	for _, fl := range res.Files {
		kinds[filepath.Base(fl.Path)] = fl.Kind
	}
	if kinds["index.js"] != "script" || kinds["native.node"] != "native" ||
		kinds["readme.txt"] != "text" || kinds["blob.bin"] != "binary" {
		t.Errorf("kinds = %v", kinds)
	}
	if len(res.NativeBinaries) != 1 {
		t.Errorf("NativeBinaries = %d, want 1", len(res.NativeBinaries))
	}
}

func TestSafeRel(t *testing.T) {
	cases := map[string]bool{ // input -> ok
		"package/a.js":   true,
		"a/b/c":          true,
		"/abs":           false,
		"../up":          false,
		"a/../../up":     false,
		"C:\\windows\\x": false,
		"a/./b":          true,
		"":               false,
	}
	for in, wantOK := range cases {
		if _, ok := safeRel(in); ok != wantOK {
			t.Errorf("safeRel(%q) ok=%v, want %v", in, ok, wantOK)
		}
	}
	_ = strings.TrimSpace
}
