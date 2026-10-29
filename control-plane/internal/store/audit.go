package store

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

func formatRuleAuditJSON(r models.PolicyRule) string {
	var expStr string
	if r.ExpiresAt != nil {
		expStr = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	view := map[string]any{
		"id":               r.ID,
		"version":          r.Version,
		"name":             r.Name,
		"action":           r.Action,
		"host_pattern":     r.HostPattern,
		"path_pattern":     r.PathPattern,
		"methods":          r.Methods,
		"follow_redirects": r.FollowRedirects,
		"companion_rules":  r.CompanionRules,
		"group_ids":        r.GroupIDs,
		"server_ids":       r.ServerIDs,
		"expires_at":       expStr,
		"enabled":          r.Enabled,
	}
	if len(r.RedirectHosts) > 0 {
		view["redirect_hosts"] = r.RedirectHosts
	}
	b, _ := json.MarshalIndent(view, "", "  ")
	return string(b)
}

// computeAuditEventHash returns the chain hash of ev in its HashVersion.
func computeAuditEventHash(prevHash string, ev models.AuditEvent, key []byte) string {
	if ev.HashVersion >= 2 {
		return auditHashV2(prevHash, ev, key)
	}
	return auditHashV1(prevHash, ev)
}

func auditHashV2(prevHash string, ev models.AuditEvent, key []byte) string {
	rollbackStr := ""
	if ev.RollbackRule != nil {
		rollbackStr = formatRuleAuditJSON(*ev.RollbackRule)
	}
	mac := hmac.New(sha256.New, key)
	var lenBuf [binary.MaxVarintLen64]byte
	field := func(v string) {
		n := binary.PutUvarint(lenBuf[:], uint64(len(v)))
		mac.Write(lenBuf[:n])
		mac.Write([]byte(v))
	}
	field("aegis-audit-v2")
	field(prevHash)
	field(ev.ID)
	field(strconv.FormatUint(ev.Revision, 10))
	field(ev.Timestamp.UTC().Format(time.RFC3339Nano))
	for _, v := range []string{ev.Actor, ev.ActorRole, ev.Action, ev.Category, ev.EntityType, ev.EntityID, ev.EntityName, ev.Summary} {
		field(v)
	}
	field(strconv.Itoa(len(ev.ScopeGroups)))
	for _, g := range ev.ScopeGroups {
		field(g)
	}
	field(ev.BeforeState)
	field(ev.AfterState)
	field(rollbackStr)
	return hex.EncodeToString(mac.Sum(nil))
}

func auditHashV1(prevHash string, ev models.AuditEvent) string {
	rollbackStr := ""
	if ev.RollbackRule != nil {
		rollbackStr = formatRuleAuditJSON(*ev.RollbackRule)
	}
	payload := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		prevHash,
		ev.ID,
		ev.Revision,
		ev.Timestamp.UTC().Format(time.RFC3339Nano),
		ev.Actor,
		ev.ActorRole,
		ev.Action,
		ev.Category,
		ev.EntityType,
		ev.EntityID,
		ev.EntityName,
		ev.Summary,
		strings.Join(ev.ScopeGroups, ","),
		ev.BeforeState,
		ev.AfterState,
		rollbackStr,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyAuditChain checks hash integrity, linkage and the hash-version cutover of the retained
// audit window.
func (s *Store) VerifyAuditChain() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.state.AuditEvents), s.VerifyAuditChainLocked()
}

func (s *Store) VerifyAuditChainLocked() error {
	if trust := s.auditTrustErrLocked(); trust != "" {
		return errors.New(trust)
	}
	anchor, err := s.auditAnchorLocked()
	if err != nil {
		return err
	}
	v := newAuditVerifier(s.auditKeyLocked(false), anchor)
	v.window = true
	for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
		if err := v.add(s.state.AuditEvents[i]); err != nil {
			return fmt.Errorf("audit chain integrity violation: %w", err)
		}
	}
	return nil
}

// AuditSink appends every audit event as one JSON line to an append-only file (SIEM ingestion,
// long-term retention beyond the in-memory window) and to the structured application log.
// Every line is flushed to disk before Write returns, and a failed or partial write is cut off
// again, so the file never holds a torn line; the failure is reported (Err) until a write succeeds.
// The file is reopened when it was renamed or removed (logrotate without copytruncate), so rotation
// never loses events. With RotateAtSize the sink also rotates by itself (Windows and containers have no
// logrotate, and Windows cannot rename a file another process holds open): the full file is renamed to
// audit.jsonl-YYYYMMDDhhmmss and older generations are gzip-compressed one rotation later. Rotated
// generations are never deleted: retention is the operator's decision. Symbolic links and FIFOs are
// refused for the log and its generations.
type AuditSink struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	fi       os.FileInfo
	size     int64 // end of the last complete line in the open file
	maxBytes int64
	lastHash string // event_hash of the newest event in the file trail ("" = empty trail)
	err      error  // last write failure, nil once a write succeeded again
	// readers is held shared while a reader lists and opens the generations, so that compression
	// cannot remove an original between the two; streaming happens on the open handles afterwards.
	readers  sync.RWMutex
	compress sync.WaitGroup
	log      *slog.Logger
	// writeAt is the file write (replaced in tests to simulate a full disk).
	writeAt func(f *os.File, b []byte, off int64) (int, error)
	// changed is told (under mu, must not block) when the file left the path or was truncated.
	changed func(reason string)
}

// OnChange sets the function told when the log was rotated (by the sink or logrotate) or truncated
// by another program; the store verifies the complete trail then. It is called with the sink's lock
// held and must not block.
func (a *AuditSink) OnChange(fn func(reason string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.changed = fn
	a.mu.Unlock()
}

func (a *AuditSink) changedLocked(reason string) {
	if a.changed != nil {
		a.changed(reason)
	}
}

func NewAuditSink(path string, logger *slog.Logger) (*AuditSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &AuditSink{path: path, log: logger.With("component", "audit"), writeAt: (*os.File).WriteAt}
	removeStaleCompressions(path)
	if err := a.open(); err != nil {
		return nil, err
	}
	head, err := a.readTrailHead()
	if err != nil {
		// A damaged trail must not keep the control-plane from starting: the newest event is unknown,
		// so nothing links to it, and the verification reports the damage.
		a.log.Error("the newest event of the audit log cannot be read", "error", err)
		head = "unreadable"
	}
	a.lastHash = head
	return a, nil
}

// RotateAtSize enables size-based rotation (0 disables it).
func (a *AuditSink) RotateAtSize(maxBytes int64) {
	a.mu.Lock()
	a.maxBytes = maxBytes
	a.mu.Unlock()
}

// open (re)opens the log file. A torn last line left by a crash during a write is removed: that
// event never completed, and its configuration change was never saved either.
func (a *AuditSink) open() error {
	f, err := openAuditFile(a.path, true)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	size := fi.Size()
	end, err := completeLinesEnd(f, size)
	if err == nil && end < size {
		a.log.Warn("audit log ends with an incomplete line (interrupted write); removing it", "bytes", size-end)
		err = f.Truncate(end)
		size = end
	}
	if err != nil {
		f.Close()
		return err
	}
	if a.f != nil {
		_ = a.f.Close()
	}
	a.f, a.fi, a.size = f, fi, size
	return nil
}

// readTrailHead returns the hash of the newest event in the file trail: the last line of the live
// file, or of the newest generation right after a rotation.
func (a *AuditSink) readTrailHead() (string, error) {
	files := []*auditTrailFile{{path: a.path, f: a.f, limit: a.size}}
	if a.size == 0 {
		gens, err := openAuditGenerations(a.path)
		if err != nil {
			return "", err
		}
		gens = orderAuditGenerations(gens)
		defer closeTrail(gens)
		files = gens
	}
	for i := len(files) - 1; i >= 0; i-- {
		ev, err := files[i].lastEvent()
		if err != nil {
			return "", err
		}
		if ev.EventHash != "" {
			return ev.EventHash, nil
		}
	}
	return "", nil
}

// reopenIfRotatedLocked switches to a new file when the path no longer refers to the open file. If
// the path cannot be opened the old handle is closed too: writing on into a file that left the path
// could lose events (it may have been deleted).
func (a *AuditSink) reopenIfRotatedLocked() error {
	if a.f != nil {
		if st, err := os.Lstat(a.path); err == nil && os.SameFile(st, a.fi) {
			if fi, err := a.f.Stat(); err == nil && fi.Size() < a.size {
				a.log.Warn("audit log was truncated by another program", "size", fi.Size(), "expected", a.size)
				a.size = fi.Size()
				a.changedLocked("truncation")
			}
			return nil
		}
		a.changedLocked("rotation")
	}
	if err := a.open(); err != nil {
		if a.f != nil {
			_ = a.f.Close()
			a.f = nil
		}
		return fmt.Errorf("open %s: %w", a.path, err)
	}
	return nil
}

// Write appends ev to the audit log and flushes it to disk. On error the event is not in the file
// (a partial line is cut off again) and the sink reports the failure until a later write succeeds.
func (a *AuditSink) Write(ev models.AuditEvent) error {
	if a == nil {
		return nil
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	a.mu.Lock()
	err = a.writeLocked(append(line, '\n'))
	a.err = err
	if err == nil {
		a.lastHash = ev.EventHash
		if a.maxBytes > 0 && a.size >= a.maxBytes {
			a.rotateLocked()
		}
	}
	a.mu.Unlock()
	if err != nil {
		a.log.Error("audit log write failed", "audit_id", ev.ID, "error", err)
		return err
	}
	a.log.Info("audit", "audit_id", ev.ID, "actor", ev.Actor, "role", ev.ActorRole, "action", ev.Action,
		"category", ev.Category, "entity", ev.EntityType+"/"+ev.EntityID, "summary", ev.Summary, "hash", ev.EventHash)
	return nil
}

func (a *AuditSink) writeLocked(line []byte) error {
	if err := a.reopenIfRotatedLocked(); err != nil {
		return err
	}
	n, err := a.writeAt(a.f, line, a.size)
	if err == nil && n < len(line) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.f.Sync()
	}
	if err != nil {
		// Never leave a torn line behind (disk full): cut the file back to the last complete event.
		if terr := a.f.Truncate(a.size); terr != nil {
			_ = a.f.Close()
			a.f = nil // reopened, and its torn tail removed, by the next write
		}
		return err
	}
	a.size += int64(n)
	return nil
}

// Err returns the last write failure (nil while the audit log is writable).
func (a *AuditSink) Err() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// LastHash returns the event_hash of the newest event in the file trail ("" for an empty trail).
func (a *AuditSink) LastHash() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastHash
}

// rotateLocked renames the full file to audit.jsonl-<UTC timestamp> and continues in a new file.
// It is skipped (and retried with the next event) when that generation name, compressed or not, is
// taken already.
func (a *AuditSink) rotateLocked() {
	target := a.path + "-" + time.Now().UTC().Format("20060102150405")
	for _, p := range []string{target, target + ".gz"} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return
		}
	}
	if err := a.f.Sync(); err != nil {
		a.log.Error("audit log rotation: sync failed", "error", err)
		return
	}
	_ = a.f.Close() // Windows cannot rename an open file
	a.f = nil
	if err := os.Rename(a.path, target); err != nil {
		a.log.Error("audit log rotation failed", "error", err)
	} else {
		a.log.Info("audit log rotated", "generation", filepath.Base(target))
		a.changedLocked("rotation")
		var older []string
		for _, p := range auditGenerationNames(a.path) {
			if p != target && sinkGeneration(a.path, p) {
				older = append(older, p)
			}
		}
		if len(older) > 0 {
			a.compress.Add(1)
			go a.compressGenerations(older)
		}
	}
	if err := a.open(); err != nil {
		a.err = fmt.Errorf("reopen after rotation: %w", err)
		a.log.Error("audit log reopen failed", "error", err)
	}
}

// sinkGeneration reports whether p is an uncompressed generation written by rotateLocked (logrotate
// compresses its own).
func sinkGeneration(path, p string) bool {
	suffix := filepath.Base(p)[len(filepath.Base(path)):]
	return len(suffix) == 15 && suffix[0] == '-' && allDigits(suffix[1:])
}

func (a *AuditSink) compressGenerations(paths []string) {
	defer a.compress.Done()
	for _, p := range paths {
		if err := compressAuditGeneration(p, &a.readers); err != nil {
			a.log.Error("audit log compression failed", "generation", filepath.Base(p), "error", err)
		}
	}
}

// compressAuditGeneration writes p.gz next to p and removes p. The compressed copy is written to a
// new temporary file (O_EXCL: a planted link is never followed), gets its final name only if that
// name is free (hard link, never replacing an existing file), and the original is removed only if
// it is still the file that was compressed and p.gz is the copy written here.
func compressAuditGeneration(p string, readers *sync.RWMutex) error {
	in, err := openAuditFile(p, false)
	if err != nil {
		return err
	}
	defer in.Close()
	inInfo, err := in.Stat()
	if err != nil {
		return err
	}
	final := p + ".gz"
	if _, err := os.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s exists already; the generation stays uncompressed", filepath.Base(final))
	}
	out, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".gz.tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if serr := out.Sync(); err == nil {
		err = serr
	}
	tmpInfo, serr := out.Stat()
	if err == nil {
		err = serr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	in.Close()
	if err != nil {
		return err
	}
	readers.Lock()
	defer readers.Unlock()
	if err := os.Link(tmp, final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		// File systems without hard links: rename after checking the name once more.
		if _, lerr := os.Lstat(final); !errors.Is(lerr, fs.ErrNotExist) {
			return fmt.Errorf("%s exists already; the generation stays uncompressed", filepath.Base(final))
		}
		if err := os.Rename(tmp, final); err != nil {
			return err
		}
	}
	gzInfo, err := os.Lstat(final)
	if err != nil || !gzInfo.Mode().IsRegular() || !os.SameFile(gzInfo, tmpInfo) {
		return fmt.Errorf("%s was replaced during compression; %s kept", filepath.Base(final), filepath.Base(p))
	}
	if st, err := os.Lstat(p); err != nil || !os.SameFile(st, inInfo) {
		return fmt.Errorf("%s changed during compression; kept", filepath.Base(p))
	}
	return os.Remove(p)
}

// removeStaleCompressions deletes temporary files of a compression interrupted by a crash (the
// uncompressed generation is only removed after the compressed copy is complete).
func removeStaleCompressions(path string) {
	matches, _ := filepath.Glob(path + "-*.gz.tmp*")
	for _, m := range matches {
		if fi, err := os.Lstat(m); err == nil && !fi.IsDir() {
			_ = os.Remove(m)
		}
	}
}

// snapshot opens the complete file trail, oldest first. Handles are taken while the sink is locked
// (no rotation or compression in between) and the live file is read only up to the last line written
// before the snapshot, so a slow reader sees a consistent trail and blocks nobody.
func (a *AuditSink) snapshot() ([]*auditTrailFile, error) {
	a.mu.Lock()
	a.readers.RLock()
	files, err := openAuditGenerations(a.path)
	if err == nil {
		live, lerr := openAuditFile(a.path, false)
		switch {
		case errors.Is(lerr, fs.ErrNotExist): // renamed by logrotate (nocreate), no event since
		case lerr != nil:
			closeTrail(files)
			files, err = nil, fmt.Errorf("audit log: %w", lerr)
		default:
			files = append(files, &auditTrailFile{path: a.path, f: live, limit: -1})
		}
	}
	if err == nil && a.f != nil {
		// The file the sink appends to (live, or renamed by logrotate and not reopened yet).
		for _, t := range files {
			if fi, serr := t.f.Stat(); serr == nil && os.SameFile(fi, a.fi) {
				t.limit = a.size
			}
		}
	}
	a.readers.RUnlock()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	n := len(files)
	if n > 0 && files[n-1].path == a.path {
		return append(orderAuditGenerations(files[:n-1]), files[n-1]), nil
	}
	return orderAuditGenerations(files), nil
}

// Sync flushes the audit log file to disk.
func (a *AuditSink) Sync() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.f != nil {
		_ = a.f.Sync()
	}
	a.mu.Unlock()
}

func (a *AuditSink) Close() error {
	if a == nil {
		return nil
	}
	a.compress.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	f := a.f
	a.f = nil
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// appendAuditLocked links the event into the SHA-256 hash chain. The chain is never recomputed:
// trimming the in-memory window simply drops the oldest events (they remain in the JSONL sink),
// so any modification of a retained event is detectable by VerifyAuditChainLocked.
func (s *Store) appendAuditLocked(ev models.AuditEvent) {
	if ev.ID == "" {
		ev.ID = newRandomID("aud")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Revision = s.state.Revision + 1
	prevHash := zeroHash
	if len(s.state.AuditEvents) > 0 && s.state.AuditEvents[0].EventHash != "" {
		prevHash = s.state.AuditEvents[0].EventHash
	}
	ev.PrevHash = prevHash
	ev.HashVersion = 2
	ev.EventHash = computeAuditEventHash(prevHash, ev, s.auditKeyLocked(true))

	s.state.AuditEvents = append([]models.AuditEvent{ev}, s.state.AuditEvents...)
	if len(s.state.AuditEvents) > maxAuditEvents {
		s.state.AuditEvents = s.state.AuditEvents[:maxAuditEvents]
	}
	s.auditCheckpointLocked().Events++
	if s.cluster != nil {
		// Committed (and written to the local sink) together with the configuration change.
		s.pendingAudit = append(s.pendingAudit, ev)
		return
	}
	s.emitAudit(ev)
}

func (s *Store) seedAuditEventsLocked(now time.Time) {
	for i := range s.state.Rules {
		if s.state.Rules[i].Version == 0 {
			s.state.Rules[i].Version = 1
		}
	}
	// Mark rule-gh-microsoft as v2 to show a realistic version upgrade history
	var prevMicrosoftRule *models.PolicyRule
	var currMicrosoftAfter string
	var dockerRuleSnap *models.PolicyRule
	var dockerRuleAfter string
	for i := range s.state.Rules {
		if s.state.Rules[i].ID == "rule-gh-microsoft" {
			s.state.Rules[i].Version = 2
			prev := s.state.Rules[i]
			prev.Version = 1
			prev.FollowRedirects = false
			prev.CompanionRules = []string{"codeload.github.com/microsoft/**"}
			prev.Description = "Initial v1 rule without 302 object redirect lineage enabled"
			prevMicrosoftRule = &prev
			currMicrosoftAfter = formatRuleAuditJSON(s.state.Rules[i])
		}
		if s.state.Rules[i].ID == "rule-docker-library" {
			snap := s.state.Rules[i]
			dockerRuleSnap = &snap
			dockerRuleAfter = formatRuleAuditJSON(s.state.Rules[i])
		}
	}

	var prevMicrosoftBefore string
	if prevMicrosoftRule != nil {
		prevMicrosoftBefore = formatRuleAuditJSON(*prevMicrosoftRule)
	}

	events := []models.AuditEvent{
		{
			ID:          "aud-seed-106",
			Revision:    6,
			Timestamp:   now.Add(-14 * time.Minute),
			Actor:       "root@ci-runner-fra02.internal.corp",
			ActorRole:   "SERVER_PORTAL",
			Action:      "REQUEST_SUBMITTED",
			Category:    "APPROVAL",
			EntityType:  "access_request",
			EntityID:    "req-1001",
			EntityName:  "github.com/hashicorp/**",
			Summary:     "Submitted outbound access request from Block Page for Terraform v1.9.8 release asset (notified MS Teams & Slack)",
			ScopeGroups: []string{"grp-ci-runners"},
			AfterState:  "{\n  \"requested_url\": \"https://github.com/hashicorp/terraform/releases/download/v1.9.8/terraform_1.9.8_linux_amd64.zip\",\n  \"suggested_pattern\": \"github.com/hashicorp/**\",\n  \"follow_redirects\": true,\n  \"duration\": \"24h\"\n}",
		},
		{
			ID:          "aud-seed-105",
			Revision:    5,
			Timestamp:   now.Add(-28 * time.Minute),
			Actor:       "teamlead",
			ActorRole:   string(models.RoleTeamLead),
			Action:      "SESSION_STARTED",
			Category:    "SESSION",
			EntityType:  "learning_session",
			EntityID:    "sess-live-201",
			EntityName:  "PyTorch 2.5 + HuggingFace Model Bootstrap",
			Summary:     "Started 30m learning session on gpu-h100-node04 (10.50.2.14) and auto-compiled 4 candidate path rules",
			ScopeGroups: []string{"grp-ai-gpu"},
			AfterState:  "{\n  \"server_ip\": \"10.50.2.14\",\n  \"mode\": \"record_and_allow\",\n  \"compiled_candidates\": 4\n}",
		},
		{
			ID:           "aud-seed-104",
			Revision:     4,
			Timestamp:    now.Add(-2 * time.Hour),
			Actor:        "infosec",
			ActorRole:    string(models.RoleInfoSecApprover),
			Action:       "RULE_UPDATED",
			Category:     "RULE",
			EntityType:   "policy_rule",
			EntityID:     "rule-gh-microsoft",
			EntityName:   "GitHub: Microsoft Org & Release Objects Only (v1 → v2)",
			Summary:      "Upgraded rule-gh-microsoft to v2: enabled FollowRedirects (302 CDN object lineage) and added api.github.com + raw.githubusercontent.com companions",
			ScopeGroups:  []string{"grp-ci-runners", "grp-k8s-prod"},
			BeforeState:  prevMicrosoftBefore,
			AfterState:   currMicrosoftAfter,
			RollbackRule: prevMicrosoftRule,
		},
		{
			ID:          "aud-seed-103",
			Revision:    3,
			Timestamp:   now.Add(-5 * time.Hour),
			Actor:       "infosec",
			ActorRole:   string(models.RoleInfoSecApprover),
			Action:      "TLS_BYPASS_ADDED",
			Category:    "TLS_BYPASS",
			EntityType:  "tls_bypass",
			EntityID:    "tls-winupdate",
			EntityName:  "*.windowsupdate.com",
			Summary:     "Added SSL/TLS No-Break passthrough exception for Microsoft Windows Update (certificate pinning protection)",
			ScopeGroups: []string{"grp-windows-srv"},
			AfterState:  "{\n  \"pattern\": \"*.windowsupdate.com\",\n  \"category\": \"OS Update / Certificate Pinning\",\n  \"enabled\": true\n}",
		},
		{
			ID:           "aud-seed-102",
			Revision:     2,
			Timestamp:    now.Add(-18 * time.Hour),
			Actor:        "teamlead",
			ActorRole:    string(models.RoleTeamLead),
			Action:       "RULE_CREATED",
			Category:     "RULE",
			EntityType:   "policy_rule",
			EntityID:     "rule-docker-library",
			EntityName:   "Docker Hub: Official Library Images (/v2/library/**) (v1)",
			Summary:      "Published official Docker Hub /v2/library/** policy with Cloudflare/S3 blob redirect tracking",
			ScopeGroups:  []string{"grp-k8s-prod", "grp-ci-runners"},
			AfterState:   dockerRuleAfter,
			RollbackRule: dockerRuleSnap,
		},
	}

	// Build cryptographic hash chain from oldest (end of slice) to newest (index 0)
	prevHash := zeroHash
	for i := len(events) - 1; i >= 0; i-- {
		events[i].PrevHash, events[i].HashVersion = prevHash, 2
		events[i].EventHash = computeAuditEventHash(prevHash, events[i], s.auditKeyLocked(true))
		prevHash = events[i].EventHash
	}

	s.state.AuditEvents = events
	s.auditCheckpointLocked().Events = len(events)
	if s.state.Revision < 6 {
		s.state.Revision = 6
	}
}

// ExportAudit writes the complete audit trail as JSON Lines, oldest first: from shared storage in
// cluster mode, otherwise from the audit log (audit.jsonl and every rotated generation, also when the
// live file was just renamed away). Only without any audit log file the in-memory window is exported.
func (s *Store) ExportAudit(ctx context.Context, w io.Writer, auditLogPath string) error {
	if s.cluster != nil {
		return s.cluster.StreamAudit(ctx, func(raw []byte) error {
			if _, err := w.Write(raw); err != nil {
				return err
			}
			_, err := w.Write([]byte{'\n'})
			return err
		})
	}
	files, ok, err := s.openFileTrail(auditLogPath)
	if err != nil {
		return err
	}
	if !ok {
		s.mu.RLock()
		events := append([]models.AuditEvent(nil), s.state.AuditEvents...)
		s.mu.RUnlock()
		enc := json.NewEncoder(w)
		for i := len(events) - 1; i >= 0; i-- {
			if err := enc.Encode(events[i]); err != nil {
				return err
			}
		}
		return nil
	}
	defer closeTrail(files)
	for _, t := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := t.copyTo(w); err != nil {
			return err
		}
	}
	return nil
}

// openFileTrail opens the file trail, oldest first: the sink's consistent snapshot or, for a store
// without sink, the files at path. ok is false when there is no audit log file at all.
func (s *Store) openFileTrail(path string) (files []*auditTrailFile, ok bool, err error) {
	if sink := s.opts.AuditSink; sink != nil {
		files, err = sink.snapshot()
		return files, true, err
	}
	if path == "" {
		return nil, false, nil
	}
	if files, err = openAuditGenerations(path); err != nil {
		return nil, true, err
	}
	files = orderAuditGenerations(files)
	live, err := openAuditFile(path, false)
	switch {
	case err == nil:
		files = append(files, &auditTrailFile{path: path, f: live, limit: -1})
	case !errors.Is(err, fs.ErrNotExist):
		closeTrail(files)
		return nil, true, err
	}
	return files, len(files) > 0, nil
}

// auditKeyLocked returns the audit chain key; with create it is generated on first use (inside a
// write, so in a cluster every node ends up with the same key from the shared configuration).
func (s *Store) auditKeyLocked(create bool) []byte {
	if s.state.AuditChainKey == "" {
		if !create {
			return nil
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		s.state.AuditChainKey = sealed.String(hex.EncodeToString(b))
		s.markDirtyLocked()
	}
	return decodeAuditKey(s.state.AuditChainKey)
}

func decodeAuditKey(v sealed.String) []byte {
	if v == "" {
		return nil
	}
	k, err := hex.DecodeString(string(v))
	if err != nil {
		return []byte(v)
	}
	return k
}

// AuditVerification is the result of verifying the complete audit trail.
type AuditVerification struct {
	OK      bool   `json:"ok"`
	Events  int    `json:"events"`
	FirstID string `json:"first_id,omitempty"`
	LastID  string `json:"last_id,omitempty"`
	Legacy  int    `json:"legacy_events"` // events in the pre-2.1 (unkeyed) format, only valid before the cutover
	// StartsAtGenesis: the first event links to the genesis hash (false after the operator applied
	// a retention point; the trail must then start exactly there).
	StartsAtGenesis bool `json:"starts_at_genesis"`
	// HeadMatches: the trail reaches the newest event known to the control-plane.
	HeadMatches bool `json:"head_matches"`
	// CheckpointMatches: the newest event is exactly the CheckpointEvents-th event from the sealed
	// origin, as the sealed checkpoint saved with the configuration says (complete verification).
	CheckpointMatches bool `json:"checkpoint_matches"`
	CheckpointEvents  int  `json:"checkpoint_events,omitempty"`
	// LegacyPending: the unkeyed prefix ending at LegacyHead awaits acceptance by a Super Admin.
	LegacyPending bool   `json:"legacy_pending"`
	LegacyHead    string `json:"legacy_head,omitempty"`
	Error         string `json:"error,omitempty"`
}

// VerifyCompleteAudit streams the complete audit trail (database or audit.jsonl plus rotated
// generations, oldest first) and checks every hash and link, that the trail starts at its sealed
// origin, that unkeyed (pre-2.1) events occur only in the accepted prefix before the keyed cutover,
// that it reaches the newest event of the store, and that this newest event is exactly where the
// sealed checkpoint saved with the configuration says (no events cut off the end). The result counts
// as a complete verification (AuditFullCheck): a modified trail is recorded as an integrity violation.
func (s *Store) VerifyCompleteAudit(ctx context.Context, auditLogPath string) AuditVerification {
	res, err := s.checkCompleteTrail(ctx, auditLogPath, false, "api")
	if err != nil {
		res.OK, res.Error = false, err.Error()
	} else {
		res.OK = true
	}
	return res
}

// verifyCompleteTrail verifies the complete trail; allowPending accepts a legacy prefix that still
// awaits acceptance (used to accept it).
func (s *Store) verifyCompleteTrail(ctx context.Context, auditLogPath string, allowPending bool) (AuditVerification, error) {
	s.mu.RLock()
	trust := s.auditTrustErrLocked()
	key := s.auditKeyLocked(false)
	anchor, anchorErr := s.auditAnchorLocked()
	head, headRev, events := "", uint64(0), 0
	if len(s.state.AuditEvents) > 0 {
		head, headRev = s.state.AuditEvents[0].EventHash, s.state.AuditEvents[0].Revision
	}
	if cp := s.state.AuditCheckpoint; cp != nil {
		events = cp.Events
	}
	s.mu.RUnlock()
	switch {
	case trust != "":
		return AuditVerification{}, &auditIntegrityError{msg: trust, kind: integrityRecorded}
	case anchorErr != nil:
		return AuditVerification{}, anchorErr
	}
	if snap, ok := s.cluster.(auditSnapshotter); ok {
		// The anchor and checkpoint stored with the trail, from the same database snapshot.
		return s.verifyClusterTrail(ctx, snap, allowPending)
	}
	v := newAuditVerifier(key, anchor)
	v.head, v.allowPending = head, allowPending
	// Without an audit log file the trail is the in-memory window, which may start anywhere.
	v.window = s.cluster == nil && s.opts.AuditSink == nil
	if s.cluster == nil {
		v.headEvents, v.headRevision = events, headRev
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.ExportAudit(ctx, pw, auditLogPath)) }()
	defer pr.Close()
	err := scanAuditLines(pr, func(_ int, ev models.AuditEvent) error { return v.add(ev) })
	if le := (*auditLineError)(nil); errors.As(err, &le) {
		err = &auditIntegrityError{msg: err.Error()}
	}
	if err == nil {
		err = v.finish()
	}
	return v.res, err
}

// auditIntegrityError is a verification failure caused by the content of the trail or its seals (not
// by reading them).
type auditIntegrityError struct {
	msg  string
	kind integrityKind
}

func (e *auditIntegrityError) Error() string { return e.msg }

type integrityKind int

const (
	integrityViolation integrityKind = iota // modified, inserted, removed or reordered events or seals
	integrityRecorded                       // a violation recorded earlier
	// integrityStart: the trail does not start at its sealed origin. That is also the state between
	// removing old generations (or rows) for retention and applying the retention point, so it is
	// alerted but not recorded as a violation.
	integrityStart
	integrityPending // the legacy prefix awaits acceptance (everything else verified)
)

func integrityErr(kind integrityKind, format string, args ...any) error {
	return &auditIntegrityError{msg: fmt.Sprintf(format, args...), kind: kind}
}

// auditVerifier checks a trail event by event, oldest first.
type auditVerifier struct {
	key    []byte
	anchor auditAnchor
	head   string // newest event known to the store ("" = none)
	window bool   // a window of the trail: it may start anywhere and the head is not required
	// headEvents and headRevision are the sealed checkpoint: the head is the headEvents-th event from
	// the origin and carries headRevision (0 = not checked).
	headEvents   int
	headRevision uint64
	allowPending bool // accept a legacy prefix that awaits acceptance

	res        AuditVerification
	prev       string
	keyed      bool // a keyed (version 2) event was seen
	legacyDone bool // the sealed end of the unkeyed prefix was seen
	sawHead    bool
	headAt     int    // position of the head event
	headRevAt  uint64 // revision of the head event
}

func newAuditVerifier(key []byte, anchor auditAnchor) *auditVerifier {
	v := &auditVerifier{key: key, anchor: anchor}
	if anchor.LegacyPending {
		v.res.LegacyPending, v.res.LegacyHead = true, anchor.LegacyHead
	}
	return v
}

func (v *auditVerifier) add(ev models.AuditEvent) error {
	v.res.Events++
	if v.res.FirstID == "" {
		v.res.FirstID = ev.ID
		v.res.StartsAtGenesis = ev.PrevHash == zeroHash
		if !v.window && ev.PrevHash != v.anchor.Origin {
			return integrityErr(integrityStart, "the trail starts at event %s, which does not link to its sealed origin (older events missing or replaced)", ev.ID)
		}
	}
	v.res.LastID = ev.ID
	if ev.HashVersion < 2 {
		// The unkeyed hash can be recomputed by anyone: it is accepted only for the sealed prefix
		// written before 2.1, never after the cutover (hash-version downgrade).
		if v.keyed || v.legacyDone || v.anchor.LegacyHead == zeroHash || v.anchor.LegacyHead == "" {
			return integrityErr(integrityViolation, "event %s uses the unkeyed pre-2.1 hash after the keyed cutover (hash-version downgrade)", ev.ID)
		}
		v.res.Legacy++
	} else if !v.keyed {
		v.keyed = true
		if v.res.Legacy > 0 && !v.legacyDone {
			return integrityErr(integrityViolation, "the unkeyed pre-2.1 events before event %s do not end at the sealed cutover", ev.ID)
		}
	}
	if ev.EventHash != computeAuditEventHash(ev.PrevHash, ev, v.key) {
		return integrityErr(integrityViolation, "hash mismatch at event %s (modified or forged)", ev.ID)
	}
	if v.prev != "" && ev.PrevHash != v.prev {
		return integrityErr(integrityViolation, "chain broken before event %s (events missing, reordered or inserted)", ev.ID)
	}
	if ev.HashVersion < 2 && ev.EventHash == v.anchor.LegacyHead {
		v.legacyDone = true
	}
	if ev.EventHash == v.head {
		v.sawHead, v.headAt, v.headRevAt = true, v.res.Events, ev.Revision
	}
	v.prev = ev.EventHash
	return nil
}

func (v *auditVerifier) finish() error {
	v.res.HeadMatches = v.head == "" || v.sawHead
	if !v.res.HeadMatches {
		return integrityErr(integrityViolation, "the trail ends before the newest event known to the control-plane (%s): newest events are missing", shortHash(v.head))
	}
	if !v.window && v.headEvents > 0 {
		v.res.CheckpointEvents = v.headEvents
		if v.headAt != v.headEvents {
			return integrityErr(integrityViolation, "the trail holds %d events from its sealed origin up to its newest event %s, the sealed checkpoint %d: events were removed or inserted",
				v.headAt, shortHash(v.head), v.headEvents)
		}
		if v.headRevAt != v.headRevision {
			return integrityErr(integrityViolation, "the newest event %s carries revision %d, the sealed checkpoint %d (replaced)", shortHash(v.head), v.headRevAt, v.headRevision)
		}
		v.res.CheckpointMatches = true
	}
	if v.anchor.LegacyPending && !v.allowPending {
		return integrityErr(integrityPending, "legacy_pending: the %d unkeyed (pre-2.1) events up to event hash %s are not trusted until a Super Admin accepts them after comparing them with an independent copy (the trail exported before the upgrade)",
			v.anchor.LegacyEvents, v.anchor.LegacyHead)
	}
	return nil
}

func shortHash(h string) string {
	switch {
	case h == zeroHash:
		return "genesis"
	case len(h) > 12:
		return h[:12] + "…"
	}
	return h
}
