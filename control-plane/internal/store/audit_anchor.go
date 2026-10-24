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
//
// An unkeyed prefix is never trusted automatically: the anchor sealed at the first start after an
// upgrade from a release before 2.1 is LegacyPending, and every verification fails until a Super
// Admin accepts the prefix explicitly (AcceptLegacyAudit) after comparing it with an independent copy.
// Somebody who removes the audit chain key and the anchor to pass off a re-hashed trail ends up there
// too, with an alert, and cannot get past it without that Super Admin.
type auditAnchor struct {
	Origin        string    `json:"origin"`
	LegacyEvents  int       `json:"legacy_events"`
	LegacyHead    string    `json:"legacy_head"` // event_hash of the last unkeyed event (zeroHash = none)
	LegacyPending bool      `json:"legacy_pending,omitempty"`
	SealedAt      time.Time `json:"sealed_at"`
	MAC           string    `json:"mac"`
}

func (a auditAnchor) mac(key []byte) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "aegis-audit-anchor-v2|%s|%d|%s|%t", a.Origin, a.LegacyEvents, a.LegacyHead, a.LegacyPending)
	return hex.EncodeToString(m.Sum(nil))
}

// parseAuditAnchor decodes a stored anchor and checks it against the audit chain key.
func parseAuditAnchor(raw sealed.String, key []byte) (auditAnchor, error) {
	var a auditAnchor
	if raw == "" {
		return a, errors.New("the audit trail anchor is missing")
	}
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return a, errors.New("the audit trail anchor is unreadable")
	}
	if key == nil || !hmac.Equal([]byte(a.MAC), []byte(a.mac(key))) {
		return a, errors.New("the audit trail anchor does not match the audit chain key (modified, or the key was removed)")
	}
	return a, nil
}

func (s *Store) auditAnchorLocked() (auditAnchor, error) {
	return parseAuditAnchor(s.state.AuditAnchor, s.auditKeyLocked(false))
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
	last       string // event_hash of the newest event read
	// through limits keyed and legacy to the events up to the one with this hash (the newest event
	// when the trail was loaded): events appended since, by migrations, do not tell how the trail was
	// written. past is set once it was read (or from the start when the trail was empty).
	through string
	past    bool
}

func (a *anchorScan) add(ev models.AuditEvent) error {
	if a.events == 0 {
		a.origin = ev.PrevHash
	}
	a.events++
	a.last = ev.EventHash
	if !a.past {
		if ev.HashVersion >= 2 {
			a.keyed = true
		} else if !a.keyed {
			a.legacy++
			a.legacyHead = ev.EventHash
		}
	}
	if a.through != "" && ev.EventHash == a.through {
		a.past = true
	}
	return nil
}

// auditLoaded is what the configuration said about the trail when it was loaded, before migrations or
// anything else appended to it.
type auditLoaded struct {
	key, checkpoint bool
	head            string // newest event of the window ("" = none)
}

func (s *Store) noteAuditLoadedLocked() {
	s.auditAtLoad = auditLoaded{key: s.state.AuditChainKey != "", checkpoint: s.state.AuditCheckpoint != nil}
	if len(s.state.AuditEvents) > 0 {
		s.auditAtLoad.head = s.state.AuditEvents[0].EventHash
	}
}

// establishAuditAnchorLocked seals the anchor of a trail that has none; trailEvents is the number of
// events up to the newest one of the window. Only a new installation (existing false) gets its
// genesis anchor without further ado. An existing installation without an anchor is an upgrade from a
// release before 2.1 — or somebody removed the anchor (and the audit chain key) to pass off a
// re-written trail: the unkeyed prefix is sealed as pending and an alert raised. A trail with keyed
// events, or an audit chain key without an anchor, comes from 2.1 or later: the anchor was removed,
// which is an integrity violation and nothing is sealed.
func (s *Store) establishAuditAnchorLocked(sc anchorScan, existing bool, trailEvents int) {
	s.auditCheckpointLocked().Events = trailEvents
	a := auditAnchor{Origin: zeroHash, LegacyHead: zeroHash}
	if sc.events > 0 {
		a.Origin = sc.origin
	}
	switch {
	case !existing:
		s.sealAuditAnchorLocked(a)
		return
	case sc.keyed || s.auditAtLoad.key || s.auditAtLoad.checkpoint:
		s.auditViolationLocked("the audit trail anchor is missing although the trail was written by 2.1 or later (keyed events, an audit chain key or a checkpoint exist): it was removed — the oldest events may have been cut off or the trail replaced")
		return
	}
	a.LegacyEvents, a.LegacyPending = sc.legacy, true
	if sc.legacy > 0 {
		a.LegacyHead = sc.legacyHead
	}
	s.sealAuditAnchorLocked(a)
	s.log.Warn("sealed the audit trail anchor of an existing installation: the unkeyed (pre-2.1) prefix awaits acceptance by a Super Admin",
		"legacy_events", a.LegacyEvents, "legacy_head", a.LegacyHead)
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_ANCHOR_SEALED", Category: "SYSTEM",
		EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
		Summary: fmt.Sprintf("Sealed the audit trail anchor of an existing installation without one: the trail starts at %s; its %d unkeyed (pre-2.1) events up to %s are NOT trusted until a Super Admin accepts them",
			shortHash(a.Origin), a.LegacyEvents, a.LegacyHead),
	})
	s.raiseAuditAlertLocked(SecurityEventAuditLegacyPending, fmt.Sprintf(
		"The audit trail holds %d unkeyed events (last event hash %s) and no anchor: expected once after the upgrade from a release before 2.1. If this installation already ran 2.1, the audit chain key and anchor were removed to pass off a re-written trail: do not accept it, restore from a backup. Verification fails until a Super Admin accepts the legacy events.",
		a.LegacyEvents, a.LegacyHead))
}

// ensureFileAuditAnchorLocked validates the anchor at start-up (file storage) or seals one: from the
// in-memory trail of a new installation, from the complete audit log of an existing one.
func (s *Store) ensureFileAuditAnchorLocked(existing bool) {
	if s.state.AuditAnchor != "" {
		if _, err := s.auditAnchorLocked(); err != nil {
			s.auditViolationLocked(err.Error())
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
			s.auditViolationLocked("the audit log cannot be read to seal its anchor: " + err.Error())
			return
		}
	}
	if sc.events == 0 {
		for i := len(s.state.AuditEvents) - 1; i >= 0; i-- {
			_ = sc.add(s.state.AuditEvents[i])
		}
	}
	n, _ := countThrough(s.state.AuditEvents, sc.last, sc.events)
	s.establishAuditAnchorLocked(sc, existing, n)
}

// ensureClusterAuditAnchor seals the anchor of a cluster that has none (upgrade, or somebody removed
// it). The shared trail is scanned outside the cluster write lock; an anchor that is present was
// checked by initCluster.
func (s *Store) ensureClusterAuditAnchor() error {
	s.mu.RLock()
	present := s.state.AuditAnchor != ""
	s.mu.RUnlock()
	for attempt := 0; !present && attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		s.mu.RLock()
		sc := anchorScan{through: s.auditAtLoad.head, past: s.auditAtLoad.head == ""}
		s.mu.RUnlock()
		err := s.cluster.StreamAudit(ctx, func(raw []byte) error {
			var ev models.AuditEvent
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			return sc.add(ev)
		})
		cancel()
		if err != nil {
			return fmt.Errorf("scan the audit trail: %w", err)
		}
		err = s.withWrite(func() error {
			if present = s.state.AuditAnchor != ""; present {
				return nil
			}
			n, ok := countThrough(s.state.AuditEvents, sc.last, sc.events)
			if !ok {
				return nil // the trail moved on meanwhile: scan again
			}
			s.establishAuditAnchorLocked(sc, true, n)
			present = true
			s.reportAuditViolationsLocked()
			return nil
		})
		if err != nil {
			return err
		}
	}
	if !present {
		return errors.New("the audit trail kept changing while it was scanned")
	}
	return nil
}

// checkClusterAuditLocked checks the anchor and checkpoint of a stored cluster configuration against
// the window read in the same transaction (start-up, and whenever a write loads a newer revision).
func (s *Store) checkClusterAuditLocked() {
	if s.state.AuditAnchor == "" {
		return // ensureClusterAuditAnchor decides at start-up
	}
	if cp := s.state.AuditCheckpoint; cp != nil && cp.Violation != "" {
		return // recorded already: every verification fails with it
	}
	if _, err := s.auditAnchorLocked(); err != nil {
		s.auditViolationLocked(err.Error())
	}
	s.checkAuditCheckpointLocked()
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
// Events the log is missing are appended to it. The recovery event is returned for the caller to
// append once the anchor was checked.
func (s *Store) reconcileAuditTrailLocked() *models.AuditEvent {
	sink := s.opts.AuditSink
	if sink == nil {
		return nil
	}
	fileHead, win := sink.LastHash(), s.state.AuditEvents
	if fileHead == "" || slices.ContainsFunc(win, func(ev models.AuditEvent) bool { return ev.EventHash == fileHead }) {
		if err := s.syncAuditSinkLocked(); err != nil {
			s.log.Error("audit log could not be completed", "error", err)
		}
		return nil
	}
	stateHead := ""
	if len(win) > 0 {
		stateHead = win[0].EventHash
	}
	tail, total, err := s.auditEventsAfterLocked(stateHead)
	if err != nil {
		s.auditViolationLocked("the audit log and the state diverged: " + err.Error())
		return nil
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
	if cp := s.state.AuditCheckpoint; cp != nil {
		cp.Events += total
	}
	ids := make([]string, 0, 20)
	for _, ev := range tail[max(len(tail)-20, 0):] {
		ids = append(ids, ev.ID)
	}
	if total > len(ids) {
		ids = append(ids, fmt.Sprintf("… (%d in total)", total))
	}
	s.log.Warn("adopted audit events that are newer than the loaded state (unclean shutdown or restored backup)", "events", total)
	s.markDirtyLocked()
	return &models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_TRAIL_RECOVERED", Category: "SYSTEM",
		EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
		Summary: fmt.Sprintf("Recovered %d audit event(s) written before an unclean shutdown or a restore of an older state; their configuration changes are not part of the loaded state and not in effect: %s",
			total, strings.Join(ids, ", ")),
	}
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
	// LegacyPending: the unkeyed prefix (ending at LegacyHead) awaits acceptance by a Super Admin.
	LegacyPending bool   `json:"legacy_pending"`
	LegacyHead    string `json:"legacy_head,omitempty"`
	// Integrity reports a violation detected at start-up or recorded earlier, or an invalid anchor.
	Integrity string `json:"integrity_error,omitempty"`
	// CheckpointEvents counts the events from the sealed origin up to the newest one.
	CheckpointEvents int `json:"checkpoint_events"`
}

func (s *Store) AuditStatus() AuditStatus {
	st := AuditStatus{Writable: true}
	if err := s.opts.AuditSink.Err(); err != nil {
		st.Writable, st.Error = false, err.Error()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.auditAnchorLocked()
	if err == nil {
		st.LegacyEvents, st.LegacyPending = a.LegacyEvents, a.LegacyPending
		if a.LegacyPending {
			st.LegacyHead = a.LegacyHead
		}
	}
	switch trust := s.auditTrustErrLocked(); {
	case trust != "":
		st.Integrity = trust
	case err != nil:
		st.Integrity = err.Error()
	}
	if cp := s.state.AuditCheckpoint; cp != nil {
		st.CheckpointEvents = cp.Events
	}
	return st
}

// ApplyAuditRetention moves the sealed origin of the trail to its oldest remaining event after the
// operator removed old generations (or rows) for retention. The remaining trail must verify
// completely; the change itself is an audit event and raises an alert. Super Admins only.
func (s *Store) ApplyAuditRetention(ctx context.Context, auditLogPath string, actor *auth.TokenClaims) (AuditVerification, error) {
	if actor == nil || actor.Role != models.RoleSuperAdmin {
		return AuditVerification{}, errors.New("RBAC Policy: only Super Admins can apply an audit retention point")
	}
	s.mu.RLock()
	trust := s.auditTrustErrLocked()
	key := s.auditKeyLocked(false)
	anchor, err := s.auditAnchorLocked()
	head, events := "", 0
	if len(s.state.AuditEvents) > 0 {
		head = s.state.AuditEvents[0].EventHash
	}
	if cp := s.state.AuditCheckpoint; cp != nil {
		events = cp.Events
	}
	s.mu.RUnlock()
	switch {
	case trust != "":
		return AuditVerification{}, errors.New(trust)
	case err != nil:
		return AuditVerification{}, err
	}
	var origin string
	v := newAuditVerifier(key, anchor)
	v.head, v.window = head, true
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
	removed := max(events-v.headAt, 0)
	err = s.withWrite(func() error {
		cur, err := s.auditAnchorLocked()
		if err != nil {
			return err
		}
		prevOrigin := cur.Origin
		cur.Origin = origin
		s.sealAuditAnchorLocked(cur)
		cp := s.auditCheckpointLocked()
		cp.Events = max(cp.Events-removed, 0)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "AUDIT_RETENTION_APPLIED", Category: "SYSTEM",
			EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
			Summary: fmt.Sprintf("Applied an audit retention point: the trail now starts at event %s (previous origin %s); %d older events were removed by the operator",
				v.res.FirstID, shortHash(prevOrigin), removed),
		})
		s.raiseAuditAlertLocked(SecurityEventAuditRetention, fmt.Sprintf("%s moved the start of the audit trail to event %s: %d older events were removed and are no longer verifiable here (previous origin %s)",
			actor.Username, v.res.FirstID, removed, shortHash(prevOrigin)))
		return nil
	})
	if err != nil {
		return v.res, err
	}
	v.res.OK = true
	return v.res, nil
}

// AcceptLegacyAudit trusts the unkeyed (pre-2.1) prefix of the trail sealed as pending at the upgrade,
// after a Super Admin compared it with an independent copy (the trail exported before the upgrade,
// the SIEM): legacyEvents and legacyHead confirm what was compared, and the rest of the trail must
// verify. The acceptance is an audit event and raises an alert. Super Admins only.
func (s *Store) AcceptLegacyAudit(ctx context.Context, auditLogPath string, legacyEvents int, legacyHead string, actor *auth.TokenClaims) (AuditVerification, error) {
	if actor == nil || actor.Role != models.RoleSuperAdmin {
		return AuditVerification{}, errors.New("RBAC Policy: only Super Admins can accept legacy audit events")
	}
	legacyHead = strings.ToLower(strings.TrimSpace(legacyHead))
	s.mu.RLock()
	anchor, err := s.auditAnchorLocked()
	s.mu.RUnlock()
	switch {
	case err != nil:
		return AuditVerification{}, err
	case !anchor.LegacyPending:
		return AuditVerification{}, errors.New("no legacy audit events await acceptance")
	case legacyEvents != anchor.LegacyEvents || legacyHead != anchor.LegacyHead:
		return AuditVerification{}, fmt.Errorf("the confirmation does not match the audit trail: it holds %d unkeyed events ending at event hash %s", anchor.LegacyEvents, anchor.LegacyHead)
	}
	res, err := s.verifyCompleteTrail(ctx, auditLogPath, true)
	if err != nil {
		res.Error = err.Error()
		return res, fmt.Errorf("the audit trail does not verify: %w", err)
	}
	err = s.withWrite(func() error {
		cur, err := s.auditAnchorLocked()
		if err != nil {
			return err
		}
		if !cur.LegacyPending || cur.LegacyEvents != anchor.LegacyEvents || cur.LegacyHead != anchor.LegacyHead {
			return errors.New("the audit trail anchor changed meanwhile: verify the trail again")
		}
		cur.LegacyPending = false
		s.sealAuditAnchorLocked(cur)
		s.appendAuditLocked(models.AuditEvent{
			Actor: actor.Username, ActorRole: string(actor.Role), Action: "AUDIT_LEGACY_ACCEPTED", Category: "SYSTEM",
			EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
			Summary: fmt.Sprintf("Accepted the %d unkeyed (pre-2.1) audit events up to event hash %s as the legacy prefix of the trail after comparing them with an independent copy",
				cur.LegacyEvents, cur.LegacyHead),
		})
		s.raiseAuditAlertLocked(SecurityEventAuditLegacyAccepted, fmt.Sprintf("%s accepted %d unkeyed (pre-2.1) audit events up to event hash %s: they are trusted from now on although their hash can be recomputed by anyone",
			actor.Username, cur.LegacyEvents, cur.LegacyHead))
		return nil
	})
	if err != nil {
		return res, err
	}
	res.OK, res.LegacyPending, res.LegacyHead = true, false, ""
	return res, nil
}
