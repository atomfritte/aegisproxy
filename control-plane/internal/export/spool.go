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

// spool is a durable FIFO of records (append-only segment files + a read cursor). Records are kept
// until the destination accepted them. When the size limit is exceeded the oldest segments are set
// aside (evicted) for the runtime, which dead-letters their audit and security records.
//
// Records are destination independent: the event as JSON behind a marker byte, encoded for the
// destination when it is sent, so a changed endpoint, format, index or source type keeps them. With a
// spool key (Manager.SetSpoolKey) the marker is followed by an HMAC-SHA256 of the sink id and the
// event, so records changed or added by somebody with write access to the spool are not sent.
// Spools of earlier releases (signature "v1|…") hold records already encoded for the destination;
// they stay as legacy records together with the encoding they were written in (legacyKey).
type spool struct {
	mu        sync.Mutex
	dir       string
	maxBytes  int64
	segs      []*segment
	readSeq   uint64
	readOff   int64
	wf        *os.File
	nextSeq   uint64
	unsynced  bool
	legacyKey string    // encoding of records without marker byte ("" = unknown)
	evicted   []evicted // segments set aside by the size limit, not yet processed
}

type segment struct {
	seq     uint64
	bytes   int64 // file size
	records int64 // records not yet consumed
}

// evicted is a segment file removed from the spool by the size limit; records before from had
// already been delivered.
type evicted struct {
	path string
	from int64
}

// Variables for tests.
var (
	segMaxBytes   int64 = 8 << 20
	maxRecordSize       = 32 << 20 // audit lines are up to 16 MiB
)

const (
	spoolVersion = "v2"
	eventMarker  = 0x00 // first byte of a destination independent record without MAC
	macMarker    = 0x01 // first byte of a destination independent record with MAC
	legacyFile   = "legacy-encoding"
)

type spoolCursor struct {
	Seq uint64 `json:"seq"`
	Off int64  `json:"off"`
}

func segName(seq uint64) string { return fmt.Sprintf("seg-%016d.dat", seq) }

// legacyEncoding is the encoding of records spooled by release 2.0 and earlier (signature "v1|…"
// without the endpoint, which does not change the records).
func legacyEncoding(signature string) string {
	parts := strings.SplitN(signature, "|", 8)
	if len(parts) != 8 || parts[0] != "v1" {
		return ""
	}
	return strings.Join(parts[:7], "|")
}

// openSpool opens (or creates) the spool in dir. A spool of an earlier release is kept: its records
// are marked as legacy records with the encoding they were written in.
func openSpool(dir string, maxBytes int64) (*spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &spool{dir: dir, maxBytes: maxBytes}
	metaPath := filepath.Join(dir, "signature")
	if old, err := os.ReadFile(metaPath); err == nil && string(old) != spoolVersion {
		if err := writeFileSync(filepath.Join(dir, legacyFile), []byte(legacyEncoding(string(old)))); err != nil {
			return nil, err
		}
	}
	if err := writeFileSync(metaPath, []byte(spoolVersion)); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(dir, legacyFile)); err == nil {
		s.legacyKey = string(b)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "evict-") && strings.HasSuffix(name, ".dat") {
			// Evicted before a crash, not yet dead-lettered.
			parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "evict-"), ".dat"), "-")
			var from int64
			if len(parts) == 2 {
				from, _ = strconv.ParseInt(parts[1], 10, 64)
			}
			s.evicted = append(s.evicted, evicted{path: filepath.Join(dir, name), from: from})
			continue
		}
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
	} else {
		s.readSeq, s.readOff = s.segs[0].seq, 0
	}
	return s, nil
}

// writeFileSync replaces a small file atomically and durably.
func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir makes created and renamed directory entries durable (not supported on Windows, where
// NTFS journals them).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
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
		if l > int64(maxRecordSize) || off+4+l > fi.Size() {
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

// readSegment calls fn for every complete record of a segment file from offset from on.
func readSegment(path string, from int64, fn func(rec []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 1<<16)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil
		}
		l := int(binary.BigEndian.Uint32(hdr[:]))
		if l > maxRecordSize {
			return nil
		}
		rec := make([]byte, l)
		if _, err := io.ReadFull(r, rec); err != nil {
			return nil
		}
		fn(rec)
	}
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

// Append stores records at the tail; with sync they are on stable storage when it returns. It
// returns the indexes of records larger than maxRecordSize, which are not stored.
func (s *spool) Append(recs [][]byte, sync bool) (oversize []int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	created := false
	for i, rec := range recs {
		if len(rec) > maxRecordSize {
			oversize = append(oversize, i)
			continue
		}
		var tail *segment
		if len(s.segs) > 0 {
			tail = s.segs[len(s.segs)-1]
		}
		if tail == nil || tail.bytes >= segMaxBytes {
			if s.wf != nil {
				if s.unsynced {
					_ = s.wf.Sync()
				}
				_ = s.wf.Close()
				s.wf = nil
			}
			tail = &segment{seq: s.nextSeq}
			s.nextSeq++
			s.segs = append(s.segs, tail)
			if len(s.segs) == 1 {
				s.readSeq, s.readOff = tail.seq, 0
			}
			created = true
		}
		if s.wf == nil {
			f, err := os.OpenFile(filepath.Join(s.dir, segName(tail.seq)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return oversize, err
			}
			s.wf = f
		}
		buf := make([]byte, 4+len(rec))
		binary.BigEndian.PutUint32(buf, uint32(len(rec)))
		copy(buf[4:], rec)
		if _, err := s.wf.Write(buf); err != nil {
			return oversize, err
		}
		s.unsynced = true
		tail.bytes += int64(len(buf))
		tail.records++
	}
	if sync && s.wf != nil && s.unsynced {
		if err := s.wf.Sync(); err != nil {
			return oversize, err
		}
		s.unsynced = false
		if created {
			syncDir(s.dir)
		}
	}
	s.enforceLimitLocked()
	return oversize, nil
}

// enforceLimitLocked sets the oldest segments aside while the spool exceeds its limit.
func (s *spool) enforceLimitLocked() {
	var total int64
	for _, seg := range s.segs {
		total += seg.bytes
	}
	for total > s.maxBytes && len(s.segs) > 1 {
		old := s.segs[0]
		total -= old.bytes
		from := int64(0)
		if old.seq == s.readSeq {
			from = s.readOff
		}
		src := filepath.Join(s.dir, segName(old.seq))
		dst := filepath.Join(s.dir, fmt.Sprintf("evict-%016d-%d.dat", old.seq, from))
		if err := os.Rename(src, dst); err == nil {
			s.evicted = append(s.evicted, evicted{path: dst, from: from})
		} else {
			_ = os.Remove(src)
		}
		s.segs = s.segs[1:]
		s.readSeq, s.readOff = s.segs[0].seq, 0
		s.saveCursorLocked()
	}
}

// takeEvicted returns the segments set aside since the last call.
func (s *spool) takeEvicted() []evicted {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := s.evicted
	s.evicted = nil
	return ev
}

// peeked is a record read from the head of the spool, with its position.
type peeked struct {
	data []byte
	seq  uint64
	end  int64 // offset after the record in its segment
}

// Peek reads up to n records from the head without consuming them.
func (s *spool) Peek(n int) ([]peeked, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []peeked
	for _, seg := range s.segs {
		if seg.seq < s.readSeq || len(out) >= n {
			continue
		}
		start := int64(0)
		if seg.seq == s.readSeq {
			start = s.readOff
		}
		f, err := os.Open(filepath.Join(s.dir, segName(seg.seq)))
		if err != nil {
			return nil, err
		}
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			f.Close()
			return nil, err
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
			off += 4 + int64(l)
			out = append(out, peeked{data: rec, seq: seg.seq, end: off})
		}
		f.Close()
	}
	return out, nil
}

// Commit consumes recs, a prefix of what Peek returned.
func (s *spool) Commit(recs []peeked) {
	if len(recs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	consumed := map[uint64]int64{}
	for _, r := range recs {
		consumed[r.seq]++
	}
	last := recs[len(recs)-1]
	kept := s.segs[:0]
	for i, seg := range s.segs {
		seg.records -= consumed[seg.seq]
		if seg.seq < last.seq || (seg.seq == last.seq && last.end >= seg.bytes) {
			if i == len(s.segs)-1 && s.wf != nil {
				_ = s.wf.Close()
				s.wf = nil
				s.unsynced = false
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
	case s.segs[0].seq == last.seq:
		s.readSeq, s.readOff = last.seq, last.end
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
