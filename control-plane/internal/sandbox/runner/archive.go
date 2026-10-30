package runner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// ExtractLimits bound a safe extraction so a hostile archive cannot exhaust the sandbox.
type ExtractLimits struct {
	MaxTotalBytes int64 // total unpacked bytes across all members
	MaxFiles      int   // number of members written
	MaxFileBytes  int64 // per-file unpacked size
	MinRatioBytes int64 // ignore the ratio check below this uncompressed size
	MaxRatio      int64 // uncompressed/compressed above this (and above MinRatioBytes) is a decompression bomb
}

// DefaultExtractLimits are the caps used in production.
func DefaultExtractLimits() ExtractLimits {
	return ExtractLimits{
		MaxTotalBytes: 512 << 20, // 512 MiB
		MaxFiles:      20000,
		MaxFileBytes:  128 << 20, // 128 MiB
		MinRatioBytes: 1 << 20,   // 1 MiB
		MaxRatio:      120,
	}
}

// ExtractResult is the inventory of a safe extraction. It is always returned, even when a limit was hit or an
// entry was rejected, so the caller can still report what it saw.
type ExtractResult struct {
	Root           string
	Files          []sandbox.File
	NativeBinaries []sandbox.File
	TotalBytes     int64
	FileCount      int
	Dropped        int      // entries skipped for any safety reason (traversal, device node, cap ...)
	Warnings       []string // one line per rejected / clamped entry (capped)
	LimitHit       bool     // a size / count cap stopped extraction early
	BombSuspected  bool     // a member with a decompression ratio above MaxRatio was seen
	Rejected       []string // the exact archive paths rejected for traversal / absolute / escape (capped)
}

const maxArchiveWarnings = 256

func (r *ExtractResult) warn(format string, a ...any) {
	if len(r.Warnings) < maxArchiveWarnings {
		r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
	}
	r.Dropped++
}

func (r *ExtractResult) reject(p, reason string) {
	if len(r.Rejected) < maxArchiveWarnings {
		r.Rejected = append(r.Rejected, p)
	}
	r.warn("rejected %q: %s", clampPath(p), reason)
}

// DetectFormat maps a filename (and, where ambiguous, the first bytes) to one of the sandbox.Artifact formats.
func DetectFormat(filename string, head []byte) string {
	low := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(low, ".whl"):
		return "wheel"
	case strings.HasSuffix(low, ".nupkg"):
		return "nupkg"
	case strings.HasSuffix(low, ".tgz"), strings.HasSuffix(low, ".tar.gz"):
		return "tgz"
	case strings.HasSuffix(low, ".tar.bz2"), strings.HasSuffix(low, ".tar"):
		return "sdist-tar"
	case strings.HasSuffix(low, ".zip"):
		return "sdist-zip"
	}
	// Fall back to magic bytes.
	if len(head) >= 2 {
		if head[0] == 0x1f && head[1] == 0x8b {
			return "tgz"
		}
		if head[0] == 'P' && head[1] == 'K' {
			return "sdist-zip"
		}
	}
	return "tgz"
}

// isZip reports whether a format is a zip container (zip/wheel/nupkg/sdist-zip).
func isZip(format string) bool {
	switch format {
	case "zip", "wheel", "nupkg", "sdist-zip":
		return true
	}
	return false
}

// Extract safely unpacks the artifact at srcPath (of the given format) into dst. dst must already exist and be
// empty. A returned error means extraction could not even be started (unreadable file, unknown container); a
// hostile member never produces an error, it is skipped and recorded in the result.
func Extract(dst, srcPath, format string, lim ExtractLimits) (*ExtractResult, error) {
	res := &ExtractResult{Root: dst}
	if isZip(format) {
		return res, extractZip(dst, srcPath, lim, res)
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	var tr io.Reader = f
	if format == "tgz" {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return res, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		tr = gz
	}
	compressed := fileSize(srcPath)
	return res, extractTar(dst, tr, compressed, lim, res)
}

func extractTar(dst string, r io.Reader, compressed int64, lim ExtractLimits, res *ExtractResult) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A truncated / corrupt stream: stop, keep what we have.
			res.warn("tar stream error: %v", err)
			break
		}
		if res.FileCount >= lim.MaxFiles {
			res.LimitHit = true
			break
		}
		rel, ok := safeRel(hdr.Name)
		if !ok {
			res.reject(hdr.Name, "path traversal or absolute path")
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(filepath.Join(dst, rel), 0o755)
			continue
		case tar.TypeSymlink, tar.TypeLink:
			// Never materialize links: a link is enough to turn a later regular-file entry into a write
			// outside the root. Record it (and whether its target escapes) but create nothing.
			kind := "symlink"
			if hdr.Typeflag == tar.TypeLink {
				kind = "hardlink"
			}
			if linkEscapes(rel, hdr.Linkname) {
				res.reject(hdr.Name, kind+" target escapes the root: "+clampPath(hdr.Linkname))
			} else {
				res.warn("%s not materialized: %s -> %s", kind, clampPath(hdr.Name), clampPath(hdr.Linkname))
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
			// handled below
		default:
			res.reject(hdr.Name, fmt.Sprintf("unsupported entry type %q (device node / fifo?)", hdr.Typeflag))
			continue
		}
		if err := writeMember(dst, rel, tr, hdr.Size, compressed, lim, res); err != nil {
			if errors.Is(err, errTotalCap) {
				res.LimitHit = true
				return nil
			}
			res.warn("write %q: %v", clampPath(rel), err)
		}
	}
	return nil
}

func extractZip(dst, srcPath string, lim ExtractLimits, res *ExtractResult) error {
	zr, err := zip.OpenReader(srcPath)
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if res.FileCount >= lim.MaxFiles {
			res.LimitHit = true
			break
		}
		name := zf.Name
		if strings.HasSuffix(name, "/") {
			if rel, ok := safeRel(name); ok {
				_ = os.MkdirAll(filepath.Join(dst, rel), 0o755)
			}
			continue
		}
		rel, ok := safeRel(name)
		if !ok {
			res.reject(name, "path traversal or absolute path")
			continue
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			res.reject(name, "symlink in zip not materialized")
			continue
		}
		// Decompression-ratio check from the central directory before we read a single byte.
		if zf.CompressedSize64 > 0 && zf.UncompressedSize64 > u64(lim.MinRatioBytes) &&
			zf.UncompressedSize64/zf.CompressedSize64 > u64(lim.MaxRatio) {
			res.BombSuspected = true
			res.warn("decompression ratio bomb %q: %d -> %d", clampPath(name), zf.CompressedSize64, zf.UncompressedSize64)
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			res.warn("open %q: %v", clampPath(name), err)
			continue
		}
		err = writeMember(dst, rel, rc, int64(zf.UncompressedSize64), int64(zf.CompressedSize64), lim, res)
		rc.Close()
		if err != nil {
			if errors.Is(err, errTotalCap) {
				res.LimitHit = true
				return nil
			}
			res.warn("write %q: %v", clampPath(rel), err)
		}
	}
	return nil
}

func u64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

var errTotalCap = errors.New("total unpacked cap reached")

// writeMember writes one regular file, enforcing the per-file and total caps and the ratio check, and appends it
// to the inventory with its detected kind and sha256. declared is the member's advertised uncompressed size (for
// logging) and compressed is the backing compressed size for the ratio heuristic.
func writeMember(dst, rel string, src io.Reader, declared, compressed int64, lim ExtractLimits, res *ExtractResult) error {
	_ = declared
	abs := filepath.Join(dst, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	// Never honor exotic modes from the archive; the file is for inspection only.
	out, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			// Duplicate entry (classic overwrite trick): keep the first, drop the rest.
			res.warn("duplicate entry %q ignored", clampPath(rel))
			return nil
		}
		return err
	}
	defer out.Close()

	remainingFile := lim.MaxFileBytes
	remainingTotal := lim.MaxTotalBytes - res.TotalBytes
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var n int64
	truncated := false
	for {
		if remainingTotal <= 0 {
			out.Close()
			return errTotalCap
		}
		chunk := int64(len(buf))
		if remainingFile+1 < chunk {
			chunk = remainingFile + 1 // read one extra byte to notice an over-size file
		}
		if remainingTotal+1 < chunk {
			chunk = remainingTotal + 1
		}
		if chunk <= 0 {
			truncated = true
			break
		}
		m, rerr := src.Read(buf[:chunk])
		if m > 0 {
			if n+int64(m) > lim.MaxFileBytes {
				m = int(lim.MaxFileBytes - n)
				truncated = true
			}
			if _, werr := out.Write(buf[:m]); werr != nil {
				return werr
			}
			h.Write(buf[:m])
			n += int64(m)
			remainingFile -= int64(m)
			remainingTotal -= int64(m)
			if truncated {
				break
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if truncated {
		res.warn("file %q truncated at per-file cap (%d bytes)", clampPath(rel), lim.MaxFileBytes)
	}
	// Ratio bomb for tar: the tar reader hands us uncompressed bytes, so compare the bytes actually written
	// against the whole-archive compressed size — a single member far larger than the entire input is a bomb.
	if compressed > 0 && n > lim.MinRatioBytes && n/compressed > lim.MaxRatio {
		res.BombSuspected = true
	}
	res.TotalBytes += n
	res.FileCount++

	kind := classifyKind(rel, abs, n)
	fe := sandbox.File{Path: filepath.ToSlash(rel), Size: n, Kind: kind, SHA256: hex.EncodeToString(h.Sum(nil))}
	res.Files = append(res.Files, fe)
	if kind == "native" {
		res.NativeBinaries = append(res.NativeBinaries, fe)
	}
	return nil
}

// safeRel cleans an archive path and returns a relative, root-contained slash path, or ok=false if the entry
// is absolute, empty, or escapes the root with "..".
func safeRel(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	// Windows-style absolute/backslash paths in a cross-platform archive.
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return "", false
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return filepath.FromSlash(clean), true
}

// linkEscapes reports whether a symlink/hardlink at rel pointing at target would resolve outside the root.
func linkEscapes(rel, target string) bool {
	target = strings.ReplaceAll(target, "\\", "/")
	if strings.HasPrefix(target, "/") {
		return true
	}
	joined := path.Join(path.Dir(filepath.ToSlash(rel)), target)
	clean := path.Clean(joined)
	return clean == ".." || strings.HasPrefix(clean, "../")
}

func clampPath(p string) string {
	const n = 200
	if len(p) > n {
		return p[:n] + "…"
	}
	return p
}

func fileSize(p string) int64 {
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return 0
}
