package store

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aegisproxy/control-plane/internal/models"
)

// The file trail is audit.jsonl plus its rotated generations in the same directory. Readers work on
// open handles taken while the sink is locked (a consistent snapshot) and stream them afterwards, so
// a slow export never blocks rotation, compression or shutdown.

var errNotRegularFile = errors.New("not a regular file (symbolic link, FIFO or device)")

func requireRegularFile(f *os.File) (*os.File, error) {
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: f.Name(), Err: errNotRegularFile}
	}
	return f, nil
}

// maxAuditLine bounds a single JSON line (before/after states of large policies included).
const maxAuditLine = 16 << 20

// auditTrailFile is one open file of a trail snapshot.
type auditTrailFile struct {
	path  string
	f     *os.File
	limit int64              // bytes to read (the live file up to the last complete line), -1 = all
	first *models.AuditEvent // first event, nil when empty or unreadable
}

func (t *auditTrailFile) gz() bool { return strings.HasSuffix(t.path, ".gz") }

// reader returns the decompressed content from the start of the file.
func (t *auditTrailFile) reader() (io.Reader, error) {
	if _, err := t.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var r io.Reader = t.f
	if t.limit >= 0 {
		r = io.LimitReader(t.f, t.limit)
	}
	if t.gz() {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(t.path), err)
		}
		r = zr
	}
	return r, nil
}

// copyTo writes the file's lines, terminating a last line that lacks its newline so that two
// generations never merge into one line.
func (t *auditTrailFile) copyTo(w io.Writer) error {
	r, err := t.reader()
	if err != nil {
		return err
	}
	lw := &lastByteWriter{w: w}
	if _, err := io.Copy(lw, r); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(t.path), err)
	}
	if lw.n > 0 && lw.last != '\n' {
		_, err = w.Write([]byte{'\n'})
	}
	return err
}

type lastByteWriter struct {
	w    io.Writer
	n    int64
	last byte
}

func (l *lastByteWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if n > 0 {
		l.n += int64(n)
		l.last = p[n-1]
	}
	return n, err
}

// peekFirst reads the first event of the file (cheap for compressed generations too).
func (t *auditTrailFile) peekFirst() {
	r, err := t.reader()
	if err != nil {
		return
	}
	br := bufio.NewReaderSize(io.LimitReader(r, maxAuditLine), 64<<10)
	line, err := br.ReadBytes('\n')
	if err != nil && (err != io.EOF || len(line) == 0) {
		return
	}
	var ev models.AuditEvent
	if json.Unmarshal(bytes.TrimSpace(line), &ev) == nil && ev.EventHash != "" {
		t.first = &ev
	}
}

func closeTrail(files []*auditTrailFile) {
	for _, t := range files {
		t.f.Close()
	}
}

// scanAuditLines decodes JSON Lines and calls fn for every event (line numbers start at 1).
func scanAuditLines(r io.Reader, fn func(line int, ev models.AuditEvent) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxAuditLine)
	n := 0
	for sc.Scan() {
		n++
		var ev models.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return &auditLineError{line: n}
		}
		if err := fn(n, ev); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the audit trail failed: %w", err)
	}
	return nil
}

type auditLineError struct{ line int }

func (e *auditLineError) Error() string {
	return fmt.Sprintf("line %d is not a valid audit event", e.line)
}

// scanTrail streams the events of a snapshot, oldest first.
func scanTrail(files []*auditTrailFile, fn func(ev models.AuditEvent) error) error {
	pr, pw := io.Pipe()
	go func() {
		var err error
		for _, t := range files {
			if err = t.copyTo(pw); err != nil {
				break
			}
		}
		pw.CloseWithError(err)
	}()
	defer pr.Close()
	return scanAuditLines(pr, func(_ int, ev models.AuditEvent) error { return fn(ev) })
}

// lastEvent returns the newest event of the file ("" hash when it holds none). Plain files are read
// backwards from the end; compressed generations have to be decompressed completely.
func (t *auditTrailFile) lastEvent() (models.AuditEvent, error) {
	var last []byte
	if !t.gz() {
		size := t.limit
		if size < 0 {
			fi, err := t.f.Stat()
			if err != nil {
				return models.AuditEvent{}, err
			}
			size = fi.Size()
		}
		line, err := lastLine(t.f, size)
		if err != nil {
			return models.AuditEvent{}, err
		}
		last = line
	} else {
		r, err := t.reader()
		if err != nil {
			return models.AuditEvent{}, err
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), maxAuditLine)
		for sc.Scan() {
			if len(bytes.TrimSpace(sc.Bytes())) > 0 {
				last = append(last[:0], sc.Bytes()...)
			}
		}
		if err := sc.Err(); err != nil {
			return models.AuditEvent{}, fmt.Errorf("%s: %w", filepath.Base(t.path), err)
		}
	}
	var ev models.AuditEvent
	if len(bytes.TrimSpace(last)) == 0 {
		return ev, nil
	}
	if err := json.Unmarshal(last, &ev); err != nil {
		return ev, fmt.Errorf("%s: the last line is not a valid audit event", filepath.Base(t.path))
	}
	return ev, nil
}

// lastLine returns the last non-empty line of the first size bytes of f.
func lastLine(f *os.File, size int64) ([]byte, error) {
	const chunk = 64 << 10
	var buf []byte
	end := size
	for end > 0 {
		start := max(end-chunk, 0)
		b := make([]byte, end-start)
		if _, err := f.ReadAt(b, start); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(b, buf...)
		trimmed := bytes.TrimRight(buf, "\r\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if int64(len(buf)) > maxAuditLine {
			return nil, errors.New("audit log line too long")
		}
		end = start
	}
	return bytes.TrimRight(buf, "\r\n"), nil
}

// completeLinesEnd returns the offset after the last newline in the first size bytes of f.
func completeLinesEnd(f *os.File, size int64) (int64, error) {
	const chunk = 64 << 10
	end := size
	for end > 0 {
		start := max(end-chunk, 0)
		b := make([]byte, end-start)
		if _, err := f.ReadAt(b, start); err != nil && err != io.EOF {
			return 0, err
		}
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

// auditGenerationNames lists rotated generations of the audit log by name: logrotate "dateext"
// (audit.jsonl-20260101[.gz]), the sink's own rotation (audit.jsonl-20260101083000[.gz]) and
// numbered (audit.jsonl.1[.gz]) names. Only directories are skipped: a symbolic link or FIFO with a
// generation name makes reading fail instead of silently missing from the trail.
func auditGenerationNames(path string) []string {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil
	}
	base := filepath.Base(path)
	type gen struct {
		path string
		key  string
	}
	var gens []gen
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == base || !strings.HasPrefix(name, base) {
			continue
		}
		suffix := strings.TrimSuffix(name[len(base):], ".gz")
		switch {
		case (len(suffix) == 9 || len(suffix) == 15) && suffix[0] == '-' && allDigits(suffix[1:]):
			gens = append(gens, gen{filepath.Join(filepath.Dir(path), name), "1" + (suffix[1:] + "000000")[:14] + name})
		case len(suffix) > 1 && suffix[0] == '.' && allDigits(suffix[1:]) && len(suffix) <= 6:
			n, _ := strconv.Atoi(suffix[1:])
			gens = append(gens, gen{filepath.Join(filepath.Dir(path), name), fmt.Sprintf("0%08d", 99999999-n) + name})
		}
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i].key < gens[j].key })
	out := make([]string, len(gens))
	for i, g := range gens {
		out[i] = g.path
	}
	return out
}

// openAuditGenerations opens every rotated generation. A generation that disappears between listing
// and opening was compressed meanwhile (the caller holds the sink's readers lock to prevent that).
func openAuditGenerations(path string) ([]*auditTrailFile, error) {
	var out []*auditTrailFile
	for _, p := range auditGenerationNames(path) {
		f, err := openAuditFile(p, false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			closeTrail(out)
			return nil, fmt.Errorf("audit log generation %s: %w", filepath.Base(p), err)
		}
		out = append(out, &auditTrailFile{path: p, f: f, limit: -1})
	}
	return out, nil
}

// orderAuditGenerations drops duplicate generations and sorts them oldest first by their content,
// not their names: logrotate names carry the local date, the sink's names UTC time, and clocks can
// step backwards. The first event's revision never decreases along the chain; a direct chain link
// and the timestamp break ties. Files without a readable first event (empty) keep their name order
// in front.
func orderAuditGenerations(gens []*auditTrailFile) []*auditTrailFile {
	for _, g := range gens {
		g.peekFirst()
	}
	// A generation can exist twice for a moment (compressed copy complete, original not yet
	// removed, or a crash in between): files starting with the same event are one generation and
	// the uncompressed file is complete for sure. Generations with colliding names but different
	// content are both kept.
	byName := map[string]*auditTrailFile{}
	for _, g := range gens {
		byName[g.path] = g
	}
	drop := map[*auditTrailFile]bool{}
	for _, g := range gens {
		if !g.gz() {
			continue
		}
		plain, ok := byName[strings.TrimSuffix(g.path, ".gz")]
		if ok && (g.first == nil || plain.first != nil && plain.first.EventHash == g.first.EventHash) {
			drop[g] = true
		}
	}
	seen := map[string]*auditTrailFile{}
	for _, g := range gens {
		if g.first == nil || drop[g] {
			continue
		}
		if prev, dup := seen[g.first.EventHash]; dup {
			if prev.gz() && !g.gz() {
				drop[prev], seen[g.first.EventHash] = true, g
			} else {
				drop[g] = true
			}
			continue
		}
		seen[g.first.EventHash] = g
	}
	kept := gens[:0]
	for _, g := range gens {
		if drop[g] {
			g.f.Close()
		} else {
			kept = append(kept, g)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i].first, kept[j].first
		switch {
		case a == nil || b == nil:
			return a == nil && b != nil
		case a.Revision != b.Revision:
			return a.Revision < b.Revision
		case b.PrevHash == a.EventHash:
			return true
		case a.PrevHash == b.EventHash:
			return false
		}
		return a.Timestamp.Before(b.Timestamp)
	})
	return kept
}

// rotatedAuditFiles lists the rotated generations of the audit log, oldest first (see
// orderAuditGenerations).
func rotatedAuditFiles(path string) []string {
	gens, err := openAuditGenerations(path)
	if err != nil {
		return auditGenerationNames(path)
	}
	gens = orderAuditGenerations(gens)
	defer closeTrail(gens)
	out := make([]string, len(gens))
	for i, g := range gens {
		out[i] = g.path
	}
	return out
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
