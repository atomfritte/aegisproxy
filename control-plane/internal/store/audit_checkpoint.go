package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/sealed"
)

// AuditCheckpoint seals the newest end of the audit trail. It is saved together with the
// configuration (the same state file write, or the same database transaction as the audit rows)
// and keyed with the audit chain key, so cutting off the newest events, or removing the checkpoint,
// is detected at the next start and by every verification. Only a rollback of the configuration and
// the trail together to an earlier consistent copy remains undetectable locally: the AUDIT_CHECKPOINT
// records in the exported audit stream reveal it (docs/operations.md).
type AuditCheckpoint struct {
	Head          string `json:"head"`           // event_hash of the newest event (zeroHash: empty trail)
	HeadRevision  uint64 `json:"head_revision"`  // revision recorded in that event
	Events        int    `json:"events"`         // events from the sealed origin up to the head
	StateRevision uint64 `json:"state_revision"` // configuration revision saved with the checkpoint
	// Violation keeps the first integrity violation detected (at start-up, on a cluster reload or by a
	// complete verification): every later verification fails with it until the data is restored from
	// a backup.
	Violation   string     `json:"violation,omitempty"`
	ViolationAt *time.Time `json:"violation_at,omitempty"`
	MAC         string     `json:"mac"`
}

func (c AuditCheckpoint) mac(key []byte) string {
	at := ""
	if c.ViolationAt != nil {
		at = c.ViolationAt.UTC().Format(time.RFC3339Nano)
	}
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "aegis-audit-checkpoint-v1|%s|%d|%d|%d|%s|%d:%s", c.Head, c.HeadRevision, c.Events, c.StateRevision, at, len(c.Violation), c.Violation)
	return hex.EncodeToString(m.Sum(nil))
}

// auditCheckpointLocked returns the live checkpoint: Events and the recorded violation are kept up to
// date, head and MAC are filled in when the state is saved (sealedCheckpointLocked).
func (s *Store) auditCheckpointLocked() *AuditCheckpoint {
	if s.state.AuditCheckpoint == nil {
		s.state.AuditCheckpoint = &AuditCheckpoint{}
	}
	return s.state.AuditCheckpoint
}

// sealedCheckpointLocked is the checkpoint as it is saved with the current state.
func (s *Store) sealedCheckpointLocked() *AuditCheckpoint {
	key := s.auditKeyLocked(false)
	if s.state.AuditCheckpoint == nil || key == nil {
		return nil
	}
	cp := *s.state.AuditCheckpoint
	cp.Head, cp.HeadRevision = zeroHash, 0
	if len(s.state.AuditEvents) > 0 {
		cp.Head, cp.HeadRevision = s.state.AuditEvents[0].EventHash, s.state.AuditEvents[0].Revision
	}
	cp.StateRevision = s.state.Revision
	cp.MAC = cp.mac(key)
	return &cp
}

// verifyAuditCheckpoint checks a saved checkpoint against the window and revision saved with it.
func verifyAuditCheckpoint(cp *AuditCheckpoint, key []byte, window []models.AuditEvent, rev uint64) error {
	if cp == nil {
		return errors.New("the audit trail checkpoint is missing although the trail is anchored: it was removed (the newest events may have been cut off)")
	}
	if key == nil || !hmac.Equal([]byte(cp.MAC), []byte(cp.mac(key))) {
		return errors.New("the audit trail checkpoint does not match the audit chain key (modified)")
	}
	head, headRev := zeroHash, uint64(0)
	if len(window) > 0 {
		head, headRev = window[0].EventHash, window[0].Revision
	}
	if cp.Head != head || cp.HeadRevision != headRev {
		return fmt.Errorf("the newest audit event is %s (revision %d) but the sealed checkpoint names %s (revision %d, %d events): the newest events were removed or the trail was replaced",
			shortHash(head), headRev, shortHash(cp.Head), cp.HeadRevision, cp.Events)
	}
	if cp.StateRevision != rev {
		return fmt.Errorf("the configuration is at revision %d but the sealed audit checkpoint was saved with revision %d: the configuration was replaced", rev, cp.StateRevision)
	}
	return nil
}

// checkAuditCheckpointLocked verifies the checkpoint loaded with an anchored trail (start-up, before
// anything is appended): it must verify and name the newest event and the revision it was saved with.
func (s *Store) checkAuditCheckpointLocked() {
	if s.state.AuditAnchor == "" {
		return // no anchor: an upgrade, or the anchor was removed (establishAuditAnchorLocked decides)
	}
	cp := s.state.AuditCheckpoint
	if err := verifyAuditCheckpoint(cp, s.auditKeyLocked(false), s.state.AuditEvents, s.state.Revision); err != nil {
		s.auditViolationLocked(err.Error())
		if cp == nil || cp.Events < len(s.state.AuditEvents) {
			s.auditCheckpointLocked().Events = len(s.state.AuditEvents) // best effort: the violation is kept anyway
		}
	}
}

// auditViolationLocked notes an integrity violation; reportAuditViolationsLocked records it.
func (s *Store) auditViolationLocked(msg string) {
	s.log.Error("audit trail integrity violation", "error", msg)
	if s.auditIntegrityErr == "" {
		s.auditIntegrityErr = msg
	} else if !strings.Contains(s.auditIntegrityErr, msg) {
		s.auditIntegrityErr += "; " + msg
	}
	s.auditViolations = append(s.auditViolations, msg)
}

// reportAuditViolationsLocked records the violations noted since the last report (start-up checks,
// cluster reloads, complete verifications): in the sealed checkpoint (so every later verification
// fails, also after restarts), as an audit event (exported to the SIEM with the audit stream) and as
// a high-severity security event with a notification.
func (s *Store) reportAuditViolationsLocked() {
	if len(s.auditViolations) == 0 {
		return
	}
	msg := strings.Join(s.auditViolations, "; ")
	s.auditViolations = nil
	cp := s.auditCheckpointLocked()
	if cp.Violation != "" && strings.Contains(cp.Violation, msg) {
		return // recorded and announced at an earlier start already
	}
	if cp.Violation == "" {
		now := time.Now().UTC()
		cp.Violation, cp.ViolationAt = msg, &now
	}
	s.appendAuditLocked(models.AuditEvent{
		Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_INTEGRITY_VIOLATION", Category: "SECURITY",
		EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
		Summary: "Audit trail integrity violation detected: " + msg + ". Verification fails until the data is restored from a backup; compare with the exported audit trail.",
	})
	s.markDirtyLocked()
	s.raiseAuditAlertLocked(SecurityEventAuditViolation, "Audit trail integrity violation: "+msg)
}

// auditTrustErrLocked explains why the trail cannot be trusted whatever its content: a violation
// detected at this start or recorded earlier.
func (s *Store) auditTrustErrLocked() string {
	if s.auditIntegrityErr != "" {
		return s.auditIntegrityErr
	}
	if cp := s.state.AuditCheckpoint; cp != nil && cp.Violation != "" {
		at := ""
		if cp.ViolationAt != nil {
			at = " on " + cp.ViolationAt.UTC().Format(time.RFC3339)
		}
		return "integrity violation recorded" + at + ": " + cp.Violation
	}
	return ""
}

// Security event types about the audit trail itself.
const (
	SecurityEventAuditViolation      = "AUDIT_INTEGRITY_VIOLATION"
	SecurityEventAuditLegacyPending  = "AUDIT_LEGACY_PENDING"
	SecurityEventAuditLegacyAccepted = "AUDIT_LEGACY_ACCEPTED"
	SecurityEventAuditRetention      = "AUDIT_RETENTION_APPLIED"
	// SecurityEventAuditVerification: the complete verification failed without recording a violation
	// (the trail does not start at its sealed origin, or it could not be read twice in a row).
	SecurityEventAuditVerification = "AUDIT_VERIFICATION_FAILED"
)

// raiseAuditAlertLocked raises a high-severity security event for an audit-trail change somebody has
// to look at (violation, pending or accepted legacy prefix, retention point): it is stored, replicated,
// exported with the security stream and sent to the SecOps channels.
func (s *Store) raiseAuditAlertLocked(typ, detail string) {
	ev, isNew := s.upsertSecurityEventLocked(models.SecurityEvent{
		Type: typ, Severity: "high", Action: "detected", Host: "audit-trail", Detail: detail, Source: "Audit trail",
	})
	s.markDirtyLocked()
	if s.telemetry != nil {
		s.telemetry.add(nil, []models.SecurityEvent{ev}, nil)
	}
	if s.raisedAudit == nil {
		s.raisedAudit = map[string]bool{}
	}
	s.raisedAudit[typ] = true
	if !isNew {
		return
	}
	s.log.Warn("security event", "type", ev.Type, "severity", ev.Severity, "action", ev.Action, "detail", ev.Detail)
	s.announceSecurityEventLocked(ev)
}

// announceSecurityEventLocked exports a new security event and sends its notification. Before the
// store is live (goLive) it is queued instead: the exporter has no sinks and the notifier no
// channels yet, and a de-duplicated event would never be announced again.
func (s *Store) announceSecurityEventLocked(ev models.SecurityEvent) {
	if !s.alertsLive {
		s.pendingAlerts = append(s.pendingAlerts, ev)
		return
	}
	s.opts.Exporter.Publish(export.SecurityEvent(ev))
	if s.notifier != nil && s.state.NotifyConfig.NotifySecurityEvents {
		s.notifier.NotifySecurityEvent(ev)
	}
}

// remindAuditStateLocked raises the alert again, once per start, for audit-trail states that persist
// across restarts: a recorded integrity violation and a legacy prefix awaiting acceptance.
func (s *Store) remindAuditStateLocked() {
	if cp := s.state.AuditCheckpoint; cp != nil && cp.Violation != "" && !s.raisedAudit[SecurityEventAuditViolation] {
		at := ""
		if cp.ViolationAt != nil {
			at = " on " + cp.ViolationAt.UTC().Format(time.RFC3339)
		}
		s.raiseAuditAlertLocked(SecurityEventAuditViolation, "Audit trail integrity violation recorded"+at+" is still in effect (verification fails until the data is restored from a backup): "+cp.Violation)
	}
	if a, err := s.auditAnchorLocked(); err == nil && a.LegacyPending && !s.raisedAudit[SecurityEventAuditLegacyPending] {
		s.raiseAuditAlertLocked(SecurityEventAuditLegacyPending, fmt.Sprintf(
			"The %d unkeyed (pre-2.1) audit events up to event hash %s still await acceptance by a Super Admin: verification fails until then.",
			a.LegacyEvents, a.LegacyHead))
	}
}

// exportSpoolKeyLocked derives the key that authenticates the records in the export spools from the
// audit chain key (nil while there is none).
func (s *Store) exportSpoolKeyLocked() []byte {
	key := s.auditKeyLocked(false)
	if key == nil {
		return nil
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("aegis-export-spool-v1"))
	return m.Sum(nil)
}

// Checkpoint records in the exported audit stream: after every auditCheckpointEvery events, and at
// least every auditCheckpointInterval while the trail grows.
const (
	auditCheckpointEvery    = 100
	auditCheckpointInterval = 15 * time.Minute
)

// exportAuditCheckpointLocked publishes an AUDIT_CHECKPOINT record (not part of the hash chain) to the
// audit stream, so the SIEM keeps the sealed end of the trail independently of this installation: a
// trail that later ends before, or no longer contains, an exported head was rolled back.
func (s *Store) exportAuditCheckpointLocked() {
	cp := s.sealedCheckpointLocked()
	if cp == nil {
		return
	}
	s.lastCheckpointExport, s.lastCheckpointHead, s.lastCheckpointEvents = time.Now(), cp.Head, cp.Events
	if s.opts.Exporter == nil {
		return
	}
	detail, _ := json.Marshal(cp)
	s.opts.Exporter.Publish(export.AuditCheckpointEvent(models.AuditEvent{
		ID: fmt.Sprintf("ckpt-%d-%s", cp.Events, cp.Head[:min(len(cp.Head), 16)]), Revision: cp.StateRevision, Timestamp: time.Now().UTC(),
		Actor: "system", ActorRole: "SYSTEM", Action: "AUDIT_CHECKPOINT", Category: "SYSTEM",
		EntityType: "audit_trail", EntityID: "audit", EntityName: "Audit trail",
		Summary: fmt.Sprintf("Audit trail checkpoint: %d events from the sealed origin up to event hash %s (revision %d); not part of the hash chain",
			cp.Events, cp.Head, cp.HeadRevision),
		AfterState: string(detail),
	}))
}

// exportAuditCheckpointIfDue publishes a checkpoint record when the trail grew since the last one and
// the interval passed (called from the background loops).
func (s *Store) exportAuditCheckpointIfDue() {
	s.mu.RLock()
	head := ""
	if len(s.state.AuditEvents) > 0 {
		head = s.state.AuditEvents[0].EventHash
	}
	due := head != s.lastCheckpointHead && time.Since(s.lastCheckpointExport) >= auditCheckpointInterval
	s.mu.RUnlock()
	if due {
		s.mu.Lock()
		s.exportAuditCheckpointLocked()
		s.mu.Unlock()
	}
}

// auditCounter is implemented by cluster transactions that count the stored audit events.
type auditCounter interface {
	CountAudit(ctx context.Context) (int, error)
}

// auditSnapshotter is implemented by cluster backends that read the configuration and the complete
// audit trail from one consistent snapshot.
type auditSnapshotter interface {
	AuditSnapshot(ctx context.Context, config func(doc []byte, rev uint64) error, fn func(raw []byte) error) error
}

// auditSeals are the audit fields of a stored configuration document.
type auditSeals struct {
	Revision        uint64           `json:"revision"`
	AuditChainKey   sealed.String    `json:"audit_chain_key"`
	AuditAnchor     sealed.String    `json:"audit_anchor"`
	AuditCheckpoint *AuditCheckpoint `json:"audit_checkpoint"`
}

// verifyClusterTrail verifies the shared trail against the anchor and checkpoint stored with it, read
// from one database snapshot (independent of what this node holds in memory).
func (s *Store) verifyClusterTrail(ctx context.Context, snap auditSnapshotter, allowPending bool) (AuditVerification, error) {
	var v *auditVerifier
	err := snap.AuditSnapshot(ctx, func(doc []byte, rev uint64) error {
		if err := requireSealedAuditSecrets(doc); err != nil {
			return &auditIntegrityError{msg: err.Error()}
		}
		var seals auditSeals
		if err := json.Unmarshal(doc, &seals); err != nil {
			return integrityErr(integrityViolation, "decode the stored configuration: %v", err)
		}
		key := decodeAuditKey(seals.AuditChainKey)
		anchor, err := parseAuditAnchor(seals.AuditAnchor, key)
		if err != nil {
			return &auditIntegrityError{msg: err.Error()}
		}
		cp := seals.AuditCheckpoint
		if cp == nil {
			return integrityErr(integrityViolation, "the audit trail checkpoint is missing from the stored configuration: it was removed (the newest events may have been cut off)")
		}
		if key == nil || !hmac.Equal([]byte(cp.MAC), []byte(cp.mac(key))) {
			return integrityErr(integrityViolation, "the stored audit trail checkpoint does not match the audit chain key (modified)")
		}
		if cp.Violation != "" {
			return integrityErr(integrityRecorded, "integrity violation recorded: %s", cp.Violation)
		}
		if cp.StateRevision != rev {
			return integrityErr(integrityViolation, "the stored configuration is at revision %d but its audit checkpoint was sealed with revision %d (replaced)", rev, cp.StateRevision)
		}
		v = newAuditVerifier(key, anchor)
		v.allowPending, v.headEvents, v.headRevision = allowPending, cp.Events, cp.HeadRevision
		if cp.Head != zeroHash {
			v.head = cp.Head
		}
		return nil
	}, func(raw []byte) error {
		var ev models.AuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return integrityErr(integrityViolation, "event %d of the trail is unreadable: %v", v.res.Events+1, err)
		}
		return v.add(ev)
	})
	if v == nil {
		return AuditVerification{}, err
	}
	if err == nil {
		err = v.finish()
	}
	return v.res, err
}

// countThrough returns the number of events up to the head of window when the event with hash last
// is the base-th event of the trail (false when last is not in the window).
func countThrough(window []models.AuditEvent, last string, base int) (int, bool) {
	if last == "" {
		return len(window), base == 0
	}
	i := slices.IndexFunc(window, func(ev models.AuditEvent) bool { return ev.EventHash == last })
	if i < 0 {
		return base, false
	}
	return base + i, true
}
