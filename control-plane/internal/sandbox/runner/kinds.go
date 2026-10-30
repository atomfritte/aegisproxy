package runner

import (
	"bytes"
	"os"
	"strings"
	"unicode/utf8"
)

// classifyKind returns the sandbox.File Kind for a member: text | script | native | binary | archive | other.
func classifyKind(rel, abs string, size int64) string {
	ext := strings.ToLower(extOf(rel))
	switch ext {
	case ".node", ".so", ".dll", ".exe", ".dylib", ".pyd", ".a", ".lib":
		return "native"
	case ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".whl", ".nupkg", ".jar", ".7z":
		return "archive"
	case ".js", ".mjs", ".cjs", ".ts", ".py", ".ps1", ".psm1", ".psd1", ".sh", ".bash",
		".rb", ".pl", ".php", ".bat", ".cmd", ".ps1xml":
		return "script"
	}
	head := readHead(abs, 512)
	switch magicKind(head) {
	case "native":
		return "native"
	case "archive":
		return "archive"
	}
	if size == 0 {
		return "other"
	}
	if looksText(head) {
		if hasShebang(head) {
			return "script"
		}
		return "text"
	}
	return "binary"
}

// magicKind identifies executable/container formats from leading bytes.
func magicKind(b []byte) string {
	if len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return "native" // ELF
	}
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return "native" // DOS/PE (.exe/.dll)
	}
	if len(b) >= 4 {
		switch {
		case b[0] == 0xFE && b[1] == 0xED && b[2] == 0xFA && (b[3] == 0xCE || b[3] == 0xCF):
			return "native" // Mach-O big-endian
		case (b[0] == 0xCE || b[0] == 0xCF) && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE:
			return "native" // Mach-O little-endian
		case b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE:
			return "native" // Mach-O universal / fat
		}
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		return "archive" // gzip
	}
	if len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 || b[2] == 5 || b[2] == 7) {
		return "archive" // zip
	}
	return ""
}

func hasShebang(b []byte) bool {
	return len(b) >= 2 && b[0] == '#' && b[1] == '!'
}

// looksText reports whether a head of a file is printable UTF-8 text (no NUL, mostly printable).
func looksText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	if !utf8.Valid(b) {
		// Allow a partial rune at the very end of the head window.
		if !utf8.Valid(bytes.TrimRightFunc(b, func(r rune) bool { return r == utf8.RuneError })) {
			return false
		}
	}
	var ctrl int
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			ctrl++
		}
	}
	return ctrl*20 < len(b) // fewer than 5% odd control bytes
}

func extOf(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		return p[i:]
	}
	return ""
}

func readHead(abs string, n int) []byte {
	f, err := os.Open(abs)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	m, _ := f.Read(buf)
	return buf[:m]
}
