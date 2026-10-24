package store

import (
	"bufio"
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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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

// VerifyAuditChain checks hash integrity and linkage of the retained audit window.
func (s *Store) VerifyAuditChain() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.state.AuditEvents), s.VerifyAuditChainLocked()
}

func (s *Store) VerifyAuditChainLocked() error {
	key := s.auditKeyLocked(false)
	for i := 0; i < len(s.state.AuditEvents); i++ {
		ev := s.state.AuditEvents[i]
		expectedHash := computeAuditEventHash(ev.PrevHash, ev, key)
		if ev.EventHash != expectedHash {
			return fmt.Errorf("audit chain integrity violation at event %s: hash mismatch", ev.ID)
		}
		if i+1 < len(s.state.AuditEvents) {
			older := s.state.AuditEvents[i+1]
			if ev.PrevHash != older.EventHash {
				return fmt.Errorf("audit chain link broken between %s and %s", ev.ID, older.ID)
			}
		}
	}
	return nil
}

// AuditSink appends every audit event as one JSON line to an append-only file (SIEM ingestion,
// long-term retention beyond the in-memory window) and to the structured application log.
// The file is reopened when it was renamed or removed (logrotate without copytruncate), so rotation
// never loses events. With RotateAtSize the sink also rotates by itself (Windows and containers have no
// logrotate, and Windows cannot rename a file another process holds open): the full file is renamed to
// audit.jsonl-YYYYMMDDhhmmss and older generations are gzip-compressed one rotation later. Rotated
// generations are never deleted: retention is the operator's decision.
type AuditSink struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	fi       os.FileInfo
	size     int64
	maxBytes int64
	// readers is held shared while an export or verification reads the generations; rotation and
	// compression wait for it so a reader never misses a renamed or replaced file.
	readers  sync.RWMutex
	compress sync.WaitGroup
	log      *slog.Logger
}

func NewAuditSink(path string, logger *slog.Logger) (*AuditSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &AuditSink{path: path, log: logger.With("component", "audit")}
	if err := a.open(); err != nil {
		return nil, err
	}
	removeStaleCompressions(path)
	return a, nil
}

// RotateAtSize enables size-based rotation (0 disables it).
func (a *AuditSink) RotateAtSize(maxBytes int64) {
	a.mu.Lock()
	a.maxBytes = maxBytes
	a.mu.Unlock()
}

func (a *AuditSink) open() error {
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if a.f != nil {
		_ = a.f.Close()
	}
	a.f, a.fi, a.size = f, fi, fi.Size()
	return nil
}

// reopenIfRotatedLocked switches to a new file when the path no longer refers to the open file.
func (a *AuditSink) reopenIfRotatedLocked() {
	if a.f != nil {
		if st, err := os.Stat(a.path); err == nil && os.SameFile(st, a.fi) {
			return
		}
	}
	if err := a.open(); err != nil {
		a.log.Error("audit log reopen failed", "error", err)
	}
}

func (a *AuditSink) Write(ev models.AuditEvent) {
	if a == nil {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.reopenIfRotatedLocked()
	werr := errors.New("audit log is not open")
	if a.f != nil {
		var n int
		n, werr = a.f.Write(append(line, '\n'))
		a.size += int64(n)
		if werr == nil && a.maxBytes > 0 && a.size >= a.maxBytes {
			a.rotateLocked()
		}
	}
	a.mu.Unlock()
	if werr != nil {
		a.log.Error("audit log write failed", "error", werr)
	}
	a.log.Info("audit", "audit_id", ev.ID, "actor", ev.Actor, "role", ev.ActorRole, "action", ev.Action,
		"category", ev.Category, "entity", ev.EntityType+"/"+ev.EntityID, "summary", ev.Summary, "hash", ev.EventHash)
}

// rotateLocked renames the full file to audit.jsonl-<UTC timestamp> and continues in a new file.
// It is skipped (and retried with the next event) while a reader holds the generations or when a
// generation with the same timestamp exists.
func (a *AuditSink) rotateLocked() {
	if !a.readers.TryLock() {
		return
	}
	defer a.readers.Unlock()
	target := a.path + "-" + time.Now().UTC().Format("20060102150405")
	if _, err := os.Lstat(target); err == nil {
		return
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
		var older []string
		for _, p := range rotatedAuditFiles(a.path) {
			if p != target && !strings.HasSuffix(p, ".gz") && sinkGeneration(a.path, p) {
				older = append(older, p)
			}
		}
		if len(older) > 0 {
			a.compress.Add(1)
			go a.compressGenerations(older)
		}
	}
	if err := a.open(); err != nil {
		a.log.Error("audit log reopen failed", "error", err)
	}
}

// sinkGeneration reports whether p is a generation written by rotateLocked (logrotate compresses its own).
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

// compressAuditGeneration writes p.gz next to p and removes p. The compressed file is complete before
// it gets its final name, and the swap waits for running readers.
func compressAuditGeneration(p string, readers *sync.RWMutex) error {
	in, err := os.Open(p)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := p + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if serr := out.Sync(); err == nil {
		err = serr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	in.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	readers.Lock()
	defer readers.Unlock()
	if err := os.Rename(tmp, p+".gz"); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Remove(p)
}

// removeStaleCompressions deletes temporary files of a compression interrupted by a crash (the
// uncompressed generation is only removed after the compressed copy is complete).
func removeStaleCompressions(path string) {
	matches, _ := filepath.Glob(path + "-*.gz.tmp")
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// HoldGenerations keeps rotation and compression from renaming files until release is called.
func (a *AuditSink) HoldGenerations() (release func()) {
	if a == nil {
		return func() {}
	}
	a.readers.RLock()
	return a.readers.RUnlock
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
	if err := a.f.Sync(); err != nil {
		return err
	}
	return a.f.Close()
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
	if s.state.Revision < 6 {
		s.state.Revision = 6
	}
}

// ExportAudit writes the complete audit trail as JSON Lines, oldest first: from shared storage in
// cluster mode, otherwise from the append-only audit log file (the in-memory window holds only the
// latest events).
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
	if s.opts.AuditSink != nil {
		s.opts.AuditSink.Sync()
		defer s.opts.AuditSink.HoldGenerations()()
	}
	if _, err := os.Stat(auditLogPath); err == nil {
		for _, p := range append(rotatedAuditFiles(auditLogPath), auditLogPath) {
			if err := copyAuditFile(w, p); err != nil {
				return err
			}
		}
		return nil
	}
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

// rotatedAuditFiles lists rotated generations of the audit log, oldest first: logrotate "dateext"
// (audit.jsonl-20260101[.gz]), the sink's own rotation (audit.jsonl-20260101083000[.gz]) and numbered
// (audit.jsonl.1[.gz], higher = older) names. While a generation is being compressed both files may
// exist for a moment; the uncompressed one is listed.
func rotatedAuditFiles(path string) []string {
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
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		present[e.Name()] = true
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == base || !strings.HasPrefix(name, base) {
			continue
		}
		suffix := strings.TrimSuffix(name[len(base):], ".gz")
		if strings.HasSuffix(name, ".gz") && present[base+suffix] {
			continue
		}
		switch {
		case (len(suffix) == 9 || len(suffix) == 15) && suffix[0] == '-' && allDigits(suffix[1:]):
			gens = append(gens, gen{filepath.Join(filepath.Dir(path), name), "1" + (suffix[1:] + "000000")[:14]})
		case len(suffix) > 1 && suffix[0] == '.' && allDigits(suffix[1:]) && len(suffix) <= 6:
			n, _ := strconv.Atoi(suffix[1:])
			gens = append(gens, gen{filepath.Join(filepath.Dir(path), name), fmt.Sprintf("0%08d", 99999999-n)})
		}
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i].key < gens[j].key })
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

func copyAuditFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // rotated away meanwhile
		}
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		defer gz.Close()
		r = gz
	}
	_, err = io.Copy(w, r)
	return err
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
	k, err := hex.DecodeString(string(s.state.AuditChainKey))
	if err != nil {
		return []byte(s.state.AuditChainKey)
	}
	return k
}

// AuditVerification is the result of verifying the complete audit trail.
type AuditVerification struct {
	OK      bool   `json:"ok"`
	Events  int    `json:"events"`
	FirstID string `json:"first_id,omitempty"`
	LastID  string `json:"last_id,omitempty"`
	Legacy  int    `json:"legacy_events"` // events in the pre-2.1 (unkeyed) format
	Error   string `json:"error,omitempty"`
}

// VerifyCompleteAudit streams the complete audit trail (database or audit.jsonl plus rotated
// generations, oldest first) and checks every hash and link.
func (s *Store) VerifyCompleteAudit(ctx context.Context, auditLogPath string) AuditVerification {
	s.mu.RLock()
	key := s.auditKeyLocked(false)
	s.mu.RUnlock()
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.ExportAudit(ctx, pw, auditLogPath)) }()
	defer pr.Close()
	var res AuditVerification
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	prev := ""
	for sc.Scan() {
		var ev models.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			res.Error = fmt.Sprintf("line %d is not a valid audit event", res.Events+1)
			return res
		}
		res.Events++
		if res.FirstID == "" {
			res.FirstID = ev.ID
		}
		res.LastID = ev.ID
		if ev.HashVersion < 2 {
			res.Legacy++
		}
		if ev.EventHash != computeAuditEventHash(ev.PrevHash, ev, key) {
			res.Error = fmt.Sprintf("hash mismatch at event %s (modified or forged)", ev.ID)
			return res
		}
		if prev != "" && ev.PrevHash != prev {
			res.Error = fmt.Sprintf("chain broken before event %s (events missing, reordered or inserted)", ev.ID)
			return res
		}
		prev = ev.EventHash
	}
	if err := sc.Err(); err != nil {
		res.Error = "reading the audit trail failed: " + err.Error()
		return res
	}
	res.OK = true
	return res
}
