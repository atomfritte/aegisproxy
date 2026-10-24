package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"

	"aegisproxy/control-plane/internal/models"
)

// Flow journal (file storage). The state file holds the flow window but is rewritten at most every
// telemetryPersistInterval; a data-plane batch is acknowledged only after it was appended to the journal and fsync'd.
// Every state save starts a new journal segment first and deletes the older segments once the state file (which then
// includes their flows, see FlowJournalSeq) is on disk. At start-up, segments newer than the state are replayed, so an
// acknowledged batch survives a crash or kill of the control-plane.
const flowJournalDir = "flow-journal"

var flowSegmentName = regexp.MustCompile(`^flows-(\d{12})\.jsonl$`)

type flowJournal struct {
	// gate is held shared by an ingest from its append until the flows are in the state, and exclusively by a
	// rotation: after rotate returns, every journaled flow is part of the state that is about to be saved.
	gate sync.RWMutex
	mu   sync.Mutex
	dir  string
	seq  uint64   // segment receiving appends
	f    *os.File // nil until the segment's first append
}

func flowSegmentPath(dir string, seq uint64) string {
	return filepath.Join(dir, fmt.Sprintf("flows-%012d.jsonl", seq))
}

func listFlowSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range entries {
		if m := flowSegmentName.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			if seq, err := strconv.ParseUint(m[1], 10, 64); err == nil {
				out = append(out, seq)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// append writes flows to the current segment and fsyncs it.
func (j *flowJournal) append(flows []models.TrafficFlow) error {
	var buf bytes.Buffer
	for _, f := range flows {
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		f, err := os.OpenFile(flowSegmentPath(j.dir, j.seq), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		syncDir(j.dir)
		j.f = f
	}
	st, err := j.f.Stat()
	if err == nil {
		if _, err = j.f.Write(buf.Bytes()); err == nil {
			err = j.f.Sync()
		}
	}
	if err != nil {
		// The batch is not acknowledged. Continue in a new segment: a torn line must not swallow the next batch, and
		// after a failed fsync the old file's state is unknown. Replay skips unreadable lines.
		if st != nil {
			_ = j.f.Truncate(st.Size())
		}
		_ = j.f.Close()
		j.f = nil
		j.seq++
		return err
	}
	return nil
}

// rotate closes the current segment and returns the newest segment number that is complete.
func (j *flowJournal) rotate() uint64 {
	j.gate.Lock()
	defer j.gate.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return j.seq - 1
	}
	_ = j.f.Close()
	j.f = nil
	j.seq++
	return j.seq - 1
}

// release deletes the segments up to cut (their flows are in the saved state file).
func (j *flowJournal) release(cut uint64) {
	segs, err := listFlowSegments(j.dir)
	if err != nil {
		return
	}
	for _, seq := range segs {
		if seq <= cut {
			_ = os.Remove(flowSegmentPath(j.dir, seq))
		}
	}
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// openFlowJournal opens the journal of a file-storage data directory and replays the flows that were acknowledged
// but are not in the loaded state yet.
func (s *Store) openFlowJournal() error {
	dir := filepath.Join(s.opts.DataDir, flowJournalDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("flow journal: %w", err)
	}
	segs, err := listFlowSegments(dir)
	if err != nil {
		return fmt.Errorf("flow journal: %w", err)
	}
	s.mu.RLock()
	watermark := s.state.FlowJournalSeq
	for _, f := range s.state.Flows {
		s.seenFlows.add(f.ID)
	}
	s.mu.RUnlock()
	next := watermark + 1
	var replay []models.TrafficFlow
	torn := 0
	for _, seq := range segs {
		path := flowSegmentPath(dir, seq)
		if seq <= watermark {
			_ = os.Remove(path) // included in the state file (the deletion after that save did not happen)
			continue
		}
		next = max(next, seq+1)
		fh, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("flow journal: %w", err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var f models.TrafficFlow
			if json.Unmarshal(sc.Bytes(), &f) != nil || f.ID == "" {
				torn++ // a write cut short by the crash: never acknowledged
				continue
			}
			if s.seenFlows.add(f.ID) {
				replay = append(replay, f)
			}
		}
		if err := sc.Err(); err != nil {
			s.log.Error("flow journal segment unreadable after this point", "path", path, "error", err)
		}
		fh.Close()
	}
	s.journal = &flowJournal{dir: dir, seq: next}
	for start := 0; start < len(replay); start += maxFlowBatch {
		s.applyFlows(replay[start:min(start+maxFlowBatch, len(replay))])
	}
	if len(replay) > 0 || torn > 0 {
		s.log.Warn("flow journal replayed: acknowledged flows that were not in the state file are recorded again",
			"flows", len(replay), "unreadable_lines", torn)
	}
	return nil
}

func (s *Store) rotateFlowJournal() uint64 {
	if s.journal == nil {
		return 0
	}
	cut := s.journal.rotate()
	s.mu.Lock()
	if cut > s.state.FlowJournalSeq {
		s.state.FlowJournalSeq = cut
	}
	s.mu.Unlock()
	return cut
}

func (s *Store) releaseFlowJournal(cut uint64) {
	if s.journal != nil && cut > 0 {
		s.journal.release(cut)
	}
}
