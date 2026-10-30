package packages

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"aegisproxy/control-plane/internal/sandbox"
)

// ReportStore keeps raw sandbox reports on local disk, keyed by job ID. Reports are large and are not
// part of the replicated configuration document; the compact summary (URLs, hosts, syscalls, findings)
// lives in the assessment and is available cluster-wide, while the full report is served from the node
// that received the worker's result. A bounded number of reports is retained.
type ReportStore struct {
	dir     string
	maxKeep int
}

var reportKeyRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// NewReportStore creates the store under dir (created if missing).
func NewReportStore(dir string) (*ReportStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &ReportStore{dir: dir, maxKeep: 2000}, nil
}

// Put stores a report and returns its key (the job ID).
func (r *ReportStore) Put(key string, rep *sandbox.Report) error {
	if !reportKeyRe.MatchString(key) {
		return errors.New("invalid report key")
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	tmp := filepath.Join(r.dir, "."+key+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(r.dir, key+".json")); err != nil {
		return err
	}
	r.prune()
	return nil
}

// Get returns a stored report (nil, nil when absent).
func (r *ReportStore) Get(key string) (*sandbox.Report, error) {
	if !reportKeyRe.MatchString(key) {
		return nil, errors.New("invalid report key")
	}
	b, err := os.ReadFile(filepath.Join(r.dir, key+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rep sandbox.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// prune keeps at most maxKeep reports, dropping the oldest by modification time.
func (r *ReportStore) prune() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		mod  int64
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(r.dir, e.Name()), info.ModTime().UnixNano()})
	}
	if len(files) <= r.maxKeep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for i := 0; i < len(files)-r.maxKeep; i++ {
		_ = os.Remove(files[i].path)
	}
}
