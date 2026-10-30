package runner

import (
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// printable renders an arbitrary byte slice as a single-line, printable, length-capped preview suitable for a
// JSON report: control bytes become ".", invalid UTF-8 is dropped, and the result is clamped to max runes.
func printable(b []byte, max int) string {
	var sb strings.Builder
	runes := 0
	for i := 0; i < len(b) && runes < max; {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			sb.WriteByte('.')
			i++
			runes++
			continue
		}
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			sb.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
		i += size
		runes++
	}
	out := sb.String()
	if len(b) > 0 && runes >= max {
		out += "…"
	}
	return out
}

// clampStr clamps a string to max runes with an ellipsis.
func clampStr(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "…"
}

// readTextCapped reads up to max bytes of a file as a string. Returns ok=false on error.
func readTextCapped(abs string, max int64) (string, bool) {
	f, err := os.Open(abs)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n]), true
}

// dedupeCap deduplicates a slice preserving first-seen order and caps it, returning the capped slice and the
// number of distinct values dropped beyond the cap.
func dedupeCap(in []string, cap int) ([]string, int) {
	seen := make(map[string]struct{}, len(in))
	var out []string
	dropped := 0
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		if len(out) < cap {
			out = append(out, v)
		} else {
			dropped++
		}
	}
	return out, dropped
}

// sortedKeys returns the sorted keys of a string-keyed map (deterministic output).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
