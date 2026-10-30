package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzExtract throws arbitrary bytes at the archive extractor (as both tar.gz and zip) and requires that it never
// panics and never writes outside the destination directory.
func FuzzExtract(f *testing.F) {
	// Seed with a valid tiny tgz.
	f.Add(buildSeedTgz())
	f.Add([]byte("PK\x03\x04 not really a zip"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		src := filepath.Join(dir, "in.bin")
		if err := os.WriteFile(src, data, 0o644); err != nil {
			t.Skip()
		}
		for _, format := range []string{"tgz", "sdist-tar", "zip"} {
			dst := filepath.Join(t.TempDir(), "out")
			_ = os.MkdirAll(dst, 0o755)
			res, _ := Extract(dst, src, format, DefaultExtractLimits())
			if res == nil {
				continue
			}
			// Nothing must have been written above dst.
			for _, fe := range res.Files {
				abs := filepath.Join(dst, filepath.FromSlash(fe.Path))
				rel, err := filepath.Rel(dst, abs)
				if err != nil || rel == ".." || filepath.IsAbs(fe.Path) ||
					(len(rel) >= 3 && rel[:3] == "..") {
					t.Fatalf("member escaped root: %q", fe.Path)
				}
			}
		}
	})
}

// FuzzParseStrace throws arbitrary bytes at the strace line parser; it must never panic.
func FuzzParseStrace(f *testing.F) {
	seed, _ := os.ReadFile("testdata/strace_install.log")
	f.Add(seed)
	f.Add([]byte("1000 1.0 openat(AT_FDCWD, \"/x\", O_RDONLY <unfinished ...>\n"))
	f.Add([]byte("garbage ( ) = = = < < > >\n9 9 9\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		events, _ := ParseStrace(bytes.NewReader(data))
		cfg := AnalyzeConfig{MarkerToken: "MARKER123", WorkDir: "/work"}
		_ = Analyze(events, cfg) // must not panic either
	})
}

func buildSeedTgz() []byte {
	var buf bytes.Buffer
	// Minimal gzip header + empty content; Extract tolerates a short/corrupt stream.
	buf.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff})
	return buf.Bytes()
}
