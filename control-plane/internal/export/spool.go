package export

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// spool is a durable FIFO of encoded records (append-only segment files + a read cursor). Records
// are kept until the destination accepted them; the oldest segments are discarded when the size
// limit is exceeded.
type spool struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	segs     []*segment
	readSeq  uint64
	readOff  int64
	wf       *os.File
	nextSeq  uint64
	dropped  uint64
}

type segment struct {
	seq     uint64
	bytes   int64 // file size
	records int64 // records not yet consumed
}

const (
	segMaxBytes   = 8 << 20
	maxRecordSize = 4 << 20
)

type spoolCursor struct {
	Seq uint64 `json:"seq"`
	Off int64  `json:"off"`
}

func segName(seq uint64) string { return fmt.Sprintf("seg-%016d.dat", seq) }

// openSpool opens (or creates) the spool in dir. A changed signature (record encoding) discards
// the existing content.
func openSpool(dir string, maxBytes int64, signature string) (*spool, int64, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, 0, err
	}
	s := &spool{dir: dir, maxBytes: maxBytes}
	var discarded int64
	metaPath := filepath.Join(dir, "signature")
	if old, err := os.ReadFile(metaPath); err == nil && string(old) != signature {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "seg-") {
				if fi, err := e.Info(); err == nil {
					discarded += fi.Size()
				}
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
		_ = os.Remove(filepath.Join(dir, "cursor"))
	}
	if err := os.WriteFile(metaPath, []byte(signature), 0o600); err != nil {
		return nil, 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "seg-") || !strings.HasSuffix(name, ".dat") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".dat"), 10, 64)
		if err != nil {
			continue
		}
		s.segs = append(s.segs, &segment{seq: seq})
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].seq < s.segs[j].seq })
	var cur spoolCursor
	if b, err := os.ReadFile(filepath.Join(dir, "cursor")); err == nil {
		_ = json.Unmarshal(b, &cur)
	}
	kept := s.segs[:0]
	for _, seg := range s.segs {
		if seg.seq < cur.Seq {
			_ = os.Remove(filepath.Join(dir, segName(seg.seq)))
			continue
		}
		start := int64(0)
		if seg.seq == cur.Seq {
			start = cur.Off
		}
		n, size, err := countRecords(filepath.Join(dir, segName(seg.seq)), start)
		if err != nil {
			_ = os.Remove(filepath.Join(dir, segName(seg.seq)))
			continue
		}
		seg.records, seg.bytes = n, size
		kept = append(kept, seg)
	}
	s.segs = kept
	s.nextSeq = cur.Seq + 1
	if n := len(s.segs); n > 0 && s.segs[n-1].seq >= s.nextSeq {
		s.nextSeq = s.segs[n-1].seq + 1
	}
	if len(s.segs) == 0 {
		s.readSeq, s.readOff = s.nextSeq, 0
	} else if s.segs[0].seq == cur.Seq {
		s.readSeq, s.readOff = cur.Seq, cur.Off
	} else if len(s.segs) > 0 {
		s.readSeq, s.readOff = s.segs[0].seq, 0
	}
	return s, discarded, nil
}

// countRecords counts complete records after offset start and truncates a torn tail.
func countRecords(path string, start int64) (int64, int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	var n, off int64
	r := bufio.NewReaderSize(f, 1<<16)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			break
		}
		l := int64(binary.BigEndian.Uint32(hdr[:]))
		if l > maxRecordSize || off+4+l > fi.Size() {
			break
		}
		if _, err := r.Discard(int(l)); err != nil {
			break
		}
		if off >= start {
			n++
		}
		off += 4 + l
	}
	if off < fi.Size() {
		_ = f.Truncate(off) // torn write from a crash
	}
	return n, off, nil
}

func (s *spool) records() (int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n, b int64
	for _, seg := range s.segs {
		n += seg.records
		b += seg.bytes
	}
	return n, b
}

func (s *spool) empty() bool {
	n, _ := s.records()
	return n == 0
}

// Append stores records at the tail.
func (s *spool) Append(recs [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range recs {
		if len(rec) > maxRecordSize {
			s.dropped++
			continue
		}
		var tail *segment
		if len(s.segs) > 0 {
			tail = s.segs[len(s.segs)-1]
		}
		if tail == nil || tail.bytes >= segMaxBytes {
			if s.wf != nil {
				_ = s.wf.Close()
				s.wf = nil
			}
			tail = &segment{seq: s.nextSeq}
			s.nextSeq++
			s.segs = append(s.segs, tail)
			if len(s.segs) == 1 {
				s.readSeq, s.readOff = tail.seq, 0
			}
		}
		if s.wf == nil {
			f, err := os.OpenFile(filepath.Join(s.dir, segName(tail.seq)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return err
			}
			s.wf = f
		}
		buf := make([]byte, 4+len(rec))
		binary.BigEndian.PutUint32(buf, uint32(len(rec)))
		copy(buf[4:], rec)
		if _, err := s.wf.Write(buf); err != nil {
			return err
		}
		tail.bytes += int64(len(buf))
		tail.records++
	}
	s.enforceLimitLocked()
	return nil
}

func (s *spool) enforceLimitLocked() {
	var total int64
	for _, seg := range s.segs {
		total += seg.bytes
	}
	for total > s.maxBytes && len(s.segs) > 1 {
		old := s.segs[0]
		total -= old.bytes
		s.dropped += uint64(old.records)
		_ = os.Remove(filepath.Join(s.dir, segName(old.seq)))
		s.segs = s.segs[1:]
		s.readSeq, s.readOff = s.segs[0].seq, 0
		s.saveCursorLocked()
	}
}

type position struct {
	seq      uint64
	off      int64
	consumed map[uint64]int64 // records consumed per segment
}

// Peek reads up to n records from the head without consuming them.
func (s *spool) Peek(n int) ([][]byte, position, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pos := position{seq: s.readSeq, off: s.readOff, consumed: map[uint64]int64{}}
	var out [][]byte
	for _, seg := range s.segs {
		if seg.seq < pos.seq || len(out) >= n {
			continue
		}
		start := int64(0)
		if seg.seq == pos.seq {
			start = pos.off
		}
		f, err := os.Open(filepath.Join(s.dir, segName(seg.seq)))
		if err != nil {
			return nil, pos, err
		}
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			f.Close()
			return nil, pos, err
		}
		r := bufio.NewReaderSize(f, 1<<16)
		off := start
		var hdr [4]byte
		for len(out) < n && off < seg.bytes {
			if _, err := io.ReadFull(r, hdr[:]); err != nil {
				break
			}
			l := int(binary.BigEndian.Uint32(hdr[:]))
			rec := make([]byte, l)
			if _, err := io.ReadFull(r, rec); err != nil {
				break
			}
			out = append(out, rec)
			off += 4 + int64(l)
			pos.consumed[seg.seq]++
		}
		f.Close()
		pos.seq, pos.off = seg.seq, off
	}
	return out, pos, nil
}

// Commit consumes everything up to pos (returned by Peek).
func (s *spool) Commit(pos position) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.segs[:0]
	for i, seg := range s.segs {
		seg.records -= pos.consumed[seg.seq]
		if seg.seq < pos.seq || (seg.seq == pos.seq && pos.off >= seg.bytes) {
			if i == len(s.segs)-1 && s.wf != nil {
				_ = s.wf.Close()
				s.wf = nil
			}
			_ = os.Remove(filepath.Join(s.dir, segName(seg.seq)))
			continue
		}
		kept = append(kept, seg)
	}
	s.segs = kept
	switch {
	case len(s.segs) == 0:
		s.readSeq, s.readOff = s.nextSeq, 0
	case s.segs[0].seq == pos.seq:
		s.readSeq, s.readOff = pos.seq, pos.off
	default:
		s.readSeq, s.readOff = s.segs[0].seq, 0
	}
	s.saveCursorLocked()
}

func (s *spool) saveCursorLocked() {
	b, _ := json.Marshal(spoolCursor{Seq: s.readSeq, Off: s.readOff})
	tmp := filepath.Join(s.dir, "cursor.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, filepath.Join(s.dir, "cursor"))
	}
}

func (s *spool) takeDropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dropped
	s.dropped = 0
	return d
}

func (s *spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wf != nil {
		err := s.wf.Sync()
		_ = s.wf.Close()
		s.wf = nil
		return err
	}
	return nil
}

// remove deletes the spool directory (sink deleted).
func removeSpool(dir string) error {
	if dir == "" || !strings.Contains(dir, "export-spool") {
		return errors.New("refusing to remove unexpected directory")
	}
	return os.RemoveAll(dir)
}
