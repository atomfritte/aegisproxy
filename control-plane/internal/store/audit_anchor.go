package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

// ErrAuditUnavailable is returned for changes while the audit log cannot be written (file storage:
// the audit log is the trail of record, so nothing is changed without it).
var ErrAuditUnavailable = errors.New("audit log unavailable")

// auditAnchor seals the boundaries of the audit trail: where it starts (the prev_hash of its oldest
// event: the genesis hash, or the retention point the operator applied after removing old
// generations) and where the unkeyed pre-2.1 prefix ends. It is stored encrypted in the configuration
// and keyed with the audit chain key, so somebody with write access to the files or the database can
// neither pass off a trail re-hashed with the unkeyed algorithm nor cut events off its start.
type auditAnchor struct {
	Origin       string    `json:"origin"`
	LegacyEvents int       `json:"legacy_events"`
	LegacyHead   string    `json:"legacy_head"` // event_hash of the last unkeyed event (zeroHash = none)
	SealedAt     time.Time `json:"sealed_at"`
	MAC          string    `json:"mac"`
}

func (a auditAnchor) mac(key []byte) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "aegis-audit-anchor-v1|%s|%d|%s", a.Origin, a.LegacyEvents, a.LegacyHead)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) auditAnchorLocked() (auditAnchor, error) {
	var a auditAnchor
	if s.state.AuditAnchor == "" {
		return a, errors.New("the audit trail anchor is missing")
	}
	if err := json.Unmarshal([]byte(s.state.AuditAnchor), &a); err != nil {
		return a, errors.New("the audit trail anchor is unreadable")
	}
	if !hmac.Equal([]byte(a.MAC), []byte(a.mac(s.auditKeyLocked(false)))) {
		return a, errors.New("the audit trail anchor does not match the audit chain key (modified)")
	}
	return a, nil
}

func (s *Store) sealAuditAnchorLocked(a auditAnchor) {
	a.SealedAt = time.Now().UTC()
	a.MAC = a.mac(s.auditKeyLocked(true))
	b, _ := json.Marshal(a)
	s.state.AuditAnchor = sealed.String(b)
	s.markDirtyLocked()
}

// requireSealedAuditSecrets refuses a configuration whose audit chain key or anchor is stored in
// plain text although secrets are encrypted: AegisProxy always writes them sealed, so a plain value
// was put there by somebody who wants to re-key the chain.
func requireSealedAuditSecrets(doc []byte) error {
	if !sealed.Enabled() {
		return nil
	}
	var raw struct {
		Key    string `json:"audit_chain_key"`
		Anchor string `json:"audit_anchor"`
	}
	if json.Unmarshal(doc, &raw) != nil {
		return nil // reported by the full decoder
	}
	if raw.Key != "" && !sealed.IsSealed(raw.Key) {
		return errors.New("the audit chain key is stored unencrypted: the configuration was modified outside AegisProxy (restore it from a backup)")
	}
	if raw.Anchor != "" && !sealed.IsSealed(raw.Anchor) {
		return errors.New("the audit trail anchor is stored unencrypted: the configuration was modified outside AegisProxy (restore it from a backup)")
	}
	return nil
}

// anchorScan collects what an anchor needs from a trail read oldest first.
type anchorScan struct {
	events     int
	origin     string
	legacy     int
	legacyHead string
	keyed      bool
}

func (a *anchorScan) add(ev models.AuditEvent) error {
	if a.events == 0 {
		a.origin = ev.PrevHash
	}
	a.events++
	if ev.HashVersion >= 2 {
		a.keyed = true
	} else if !a.keyed {
		a.legacy++
		a.legacyHead = ev.EventHash
	}
	return nil
}

// establishAuditAnchorLocked seals the anchor of a trail that has none yet: a new installation, or the
// first start after an upgrade from a release without anchors. The unkeyed prefix is what precedes the
// first keyed event. A trail without any keyed event although an audit chain key exists was re-hashed
// with the unkeyed algorithm and is not sealed.
func (s *Store) establishAuditAnchorLocked(sc anchorScan, announce bool) {
	if sc.legacy > 0 && !sc.keyed && s.state.AuditChainKey != "" {
		s.auditIntegrityErr = "the audit trail holds only unkeyed (pre-2.1) events although an audit chain key exists: it was re-hashed (hash-version downgrade)"
		s.log.Error("audit trail integrity violation", "error", s.auditIntegrityErr)
		return
	}
	a := auditAnchor{Origin: zeroHash, LegacyHead: zeroHash, LegacyEvents: sc.legacy}
	if sc.events > 0 {
		a.Origin = sc.origin
	}
	if sc.legacy > 0 {
		a.LegacyHead = sc.legacyHead
	}
	s.sealAuditAnchorLocked(a)
	if announce && sc.events > 0 {
		s.log.Info("sealed the audit trail anchor", "origin", shortHash(a.Origin), "legacy_events", a.LegacyEvents)
		s.appendAuditLocked(models.AuditEvent{
			Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_ANCHOR_SEALED", Category: "SYSTEM",
			EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
			Summary: fmt.Sprintf("Sealed the audit trail anchor: the trail starts at %s; %d unkeyed pre-2.1 events precede the keyed cutover and none is accepted after it",
				shortHash(a.Origin), a.LegacyEvents),
		})
	}
}

// ensureFileAuditAnchorLocked validates the anchor at start-up (file storage) or seals one: from the
// in-memory trail of a new installation, from the complete audit log of an existing one.
func (s *Store) ensureFileAuditAnchorLocked(existing bool) {
	if s.state.AuditAnchor != "" {
		if _, err := s.auditAnchorLocked(); err != nil {
			s.auditIntegrityErr = err.Error()
			s.log.Error("audit trail integrity violation", "error", err)
		}
		return
	}
	var sc anchorScan
	if existing && s.opts.AuditSink != nil {
		files, err := s.opts.AuditSink.snapshot()
		if err == nil {
			err = scanTrail(files, sc.add)
			closeTrail(files)
		}
		if err != nil {
			s.auditIntegrityErr = "the audit log cannot be read to seal its anchor: " + err.Error()
			s.log.Error("audit trail integrity violation", "error", s.auditIntegrityErr)
			return
		}
	}
	if sc.events == 0 {
		for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
			_ = sc.add(s.state.AuditEvents[i])
		}
	}
	s.establishAuditAnchorLocked(sc, existing)
}

// ensureClusterAuditAnchor seals the anchor of a cluster that has none (upgrade, or a replica of an
// older release rewrote the configuration without it). The shared trail is scanned outside the
// cluster write lock.
func (s *Store) ensureClusterAuditAnchor() error {
	s.mu.Lock()
	present := s.state.AuditAnchor != ""
	if present {
		if _, err := s.auditAnchorLocked(); err != nil {
			s.auditIntegrityErr = err.Error()
			s.log.Error("audit trail integrity violation", "error", err)
		}
	}
	s.mu.Unlock()
	if present {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var sc anchorScan
	if err := s.cluster.StreamAudit(ctx, func(raw []byte) error {
		var ev models.AuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return err
		}
		return sc.add(ev)
	}); err != nil {
		return fmt.Errorf("scan the audit trail: %w", err)
	}
	return s.withWrite(func() error {
		if s.state.AuditAnchor == "" {
			s.establishAuditAnchorLocked(sc, sc.events > 0)
		}
		return nil
	})
}

// syncAuditSinkLocked appends the window events the audit log file is missing, oldest first:
// normally just the newest one, more after a failed write or when the window was never written
// (seeded installation).
func (s *Store) syncAuditSinkLocked() error {
	sink := s.opts.AuditSink
	win := s.state.AuditEvents
	if sink == nil || len(win) == 0 {
		return nil
	}
	n := len(win)
	if head := sink.LastHash(); head != "" {
		n = slices.IndexFunc(win, func(ev models.AuditEvent) bool { return ev.EventHash == head })
		if n < 0 {
			// The file continues somewhere else (diverged): verification reports the fork.
			s.log.Error("audit log and audit window diverged", "file_head", shortHash(head), "window_head", shortHash(win[0].EventHash))
			n = 1
		}
	}
	for i := n - 1; i >= 0; i-- {
		if err := sink.Write(win[i]); err != nil {
			return err
		}
	}
	return nil
}

// auditWritableLocked refuses changes while the audit log cannot be written (file storage). A
// recovered log first receives the events it missed meanwhile.
func (s *Store) auditWritableLocked() error {
	sink := s.opts.AuditSink
	if s.cluster != nil || sink == nil || sink.Err() == nil {
		return nil
	}
	err := sink.reopen()
	if err == nil {
		err = s.syncAuditSinkLocked()
	}
	if err != nil {
		return fmt.Errorf("%w (%v): configuration changes are refused until it can be written again", ErrAuditUnavailable, err)
	}
	sink.clearErr()
	s.log.Info("audit log writable again")
	return nil
}

// retryAuditSink lets a recovered audit log catch up without waiting for the next change.
func (s *Store) retryAuditSink() {
	if s.cluster != nil || s.opts.AuditSink.Err() == nil {
		return
	}
	s.mu.Lock()
	_ = s.auditWritableLocked()
	s.mu.Unlock()
}

// reopen reopens the log after a failure; the failure stays reported until the caller appended the
// events the file missed (clearErr).
func (a *AuditSink) reopen() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.reopenIfRotatedLocked(); err != nil {
		a.err = err
		return err
	}
	return nil
}

func (a *AuditSink) clearErr() {
	a.mu.Lock()
	a.err = nil
	a.mu.Unlock()
}

// reconcileAuditTrailLocked runs at start-up (file storage). The audit log is written synchronously
// while the state file is saved asynchronously (within a second), so after a crash, or after the
// state was restored from an older backup, the log holds events the loaded state does not know. They
// are adopted into the window when they verify and link to it (a recovery event records that their
// configuration changes are not in effect), so new events continue the chain instead of forking it.
// Events the log is missing are appended to it.
func (s *Store) reconcileAuditTrailLocked() {
	sink := s.opts.AuditSink
	if sink == nil {
		return
	}
	fileHead, win := sink.LastHash(), s.state.AuditEvents
	if fileHead == "" || slices.ContainsFunc(win, func(ev models.AuditEvent) bool { return ev.EventHash == fileHead }) {
		if err := s.syncAuditSinkLocked(); err != nil {
			s.log.Error("audit log could not be completed", "error", err)
		}
		return
	}
	stateHead := ""
	if len(win) > 0 {
		stateHead = win[0].EventHash
	}
	tail, total, err := s.auditEventsAfterLocked(stateHead)
	if err != nil {
		s.auditIntegrityErr = "the audit log and the state diverged: " + err.Error()
		s.log.Error("audit trail integrity violation", "error", s.auditIntegrityErr)
		return
	}
	adopted := make([]models.AuditEvent, 0, len(tail)+len(win))
	for i := len(tail) - 1; i >= 0; i-- {
		adopted = append(adopted, tail[i])
		s.state.Revision = max(s.state.Revision, tail[i].Revision)
	}
	s.state.AuditEvents = append(adopted, win...)
	if len(s.state.AuditEvents) > maxAuditEvents {
		s.state.AuditEvents = s.state.AuditEvents[:maxAuditEvents]
	}
	ids := make([]string, 0, 20)
	for _, ev := range tail[max(len(tail)-20, 0):] {
		ids = append(ids, ev.ID)
	}
	if total > len(ids) {
		ids = append(ids, fmt.Sprintf("… (%d in total)", total))
	}
	s.log.Warn("adopted audit events that are newer than the loaded state (unclean shutdown or restored backup)", "events", total)
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_TRAIL_RECOVERED", Category: "SYSTEM",
		EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
		Summary: fmt.Sprintf("Recovered %d audit event(s) written before an unclean shutdown or a restore of an older state; their configuration changes are not part of the loaded state and not in effect: %s",
			total, strings.Join(ids, ", ")),
	})
	s.markDirtyLocked()
}

// auditEventsAfterLocked returns the events the file trail holds after the event with hash head (all
// of them for an empty head), verified and linked; only the newest maxAuditEvents are returned.
func (s *Store) auditEventsAfterLocked(head string) ([]models.AuditEvent, int, error) {
	files, err := s.opts.AuditSink.snapshot()
	if err != nil {
		return nil, 0, err
	}
	defer closeTrail(files)
	key := s.auditKeyLocked(false)
	// After a crash the missing events sit at the end of the live file: try that first.
	sets := [][]*auditTrailFile{files}
	if len(files) > 1 {
		sets = [][]*auditTrailFile{files[len(files)-1:], files}
	}
	for _, set := range sets {
		found, total, prev := head == "", 0, head
		var tail []models.AuditEvent
		err := scanTrail(set, func(ev models.AuditEvent) error {
			if !found {
				found = ev.EventHash == head
				return nil
			}
			if prev != "" && ev.PrevHash != prev {
				return fmt.Errorf("event %s does not link to its predecessor", ev.ID)
			}
			if (ev.HashVersion < 2 && key != nil) || ev.EventHash != computeAuditEventHash(ev.PrevHash, ev, key) {
				return fmt.Errorf("event %s does not verify", ev.ID)
			}
			prev = ev.EventHash
			total++
			if tail = append(tail, ev); len(tail) > 2*maxAuditEvents {
				tail = append([]models.AuditEvent(nil), tail[len(tail)-maxAuditEvents:]...)
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
		if found {
			return tail[max(len(tail)-maxAuditEvents, 0):], total, nil
		}
	}
	return nil, 0, errors.New("the newest event of the state is not in the audit log")
}

// AuditStatus summarizes the audit trail for the posture check and the metrics.
type AuditStatus struct {
	// Writable is false while the audit log cannot be written (file storage refuses changes then).
	Writable bool   `json:"writable"`
	Error    string `json:"error,omitempty"`
	// LegacyEvents counts the unkeyed pre-2.1 events of the sealed prefix.
	LegacyEvents int `json:"legacy_events"`
}

func (s *Store) AuditStatus() AuditStatus {
	st := AuditStatus{Writable: true}
	if err := s.opts.AuditSink.Err(); err != nil {
		st.Writable, st.Error = false, err.Error()
	}
	s.mu.RLock()
	if a, err := s.auditAnchorLocked(); err == nil {
		st.LegacyEvents = a.LegacyEvents
	}
	s.mu.RUnlock()
	return st
}

// ApplyAuditRetention moves the sealed origin of the trail to its oldest remaining event after the
// operator removed old generations (or rows) for retention. The remaining trail must verify
// completely; the change itself is an audit event. Super Admins only.
func (s *Store) ApplyAuditRetention(ctx context.Context, auditLogPath string, actor *auth.TokenClaims) (AuditVerification, error) {
	if actor == nil || actor.Role != models.RoleSuperAdmin {
		return AuditVerification{}, errors.New("RBAC Policy: only Super Admins can apply an audit retention point")
	}
	s.mu.RLock()
	key := s.auditKeyLocked(false)
	anchor, err := s.auditAnchorLocked()
	head := ""
	if len(s.state.AuditEvents) > 0 {
		head = s.state.AuditEvents[0].EventHash
	}
	s.mu.RUnlock()
	if err != nil {
		return AuditVerification{}, err
	}
	var origin string
	v := &auditVerifier{key: key, anchor: anchor, head: head, window: true}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.ExportAudit(ctx, pw, auditLogPath)) }()
	err = scanAuditLines(pr, func(_ int, ev models.AuditEvent) error {
		if v.res.Events == 0 {
			origin = ev.PrevHash
		}
		return v.add(ev)
	})
	pr.Close()
	if err == nil {
		err = v.finish()
	}
	if err != nil {
		v.res.Error = err.Error()
		return v.res, fmt.Errorf("the remaining audit trail does not verify: %w", err)
	}
	if v.res.Events == 0 || origin == anchor.Origin {
		return v.res, errors.New("the audit trail still starts at its sealed origin: nothing to apply")
	}
	err = s.withWrite(func() error {
		cur, err := s.auditAnchorLocked()
		if err != nil {
			return err
		}
		prevOrigin := cur.Origin
		cur.Origin = origin
		s.sealAuditAnchorLocked(cur)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "AUDIT_RETENTION_APPLIED", Category: "SYSTEM",
			EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
			Summary: fmt.Sprintf("Applied an audit retention point: the trail now starts at event %s (previous origin %s); older events were removed by the operator",
				v.res.FirstID, shortHash(prevOrigin)),
		})
		return nil
	})
	if err != nil {
		return v.res, err
	}
	v.res.OK = true
	return v.res, nil
}
