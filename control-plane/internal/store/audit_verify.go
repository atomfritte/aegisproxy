package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// The checks at start-up and on cluster reloads compare the seals with the in-memory window only.
// The complete trail (audit.jsonl and every generation, or all aegis_audit rows) is verified in the
// background: at start-up, every AuditVerifyInterval, after the audit log rotated or was truncated,
// and with every GET /api/audit/verify. A modified trail found there is recorded as an integrity
// violation like one found at start-up (sealed, audited, alerted).

// Variables for tests.
var (
	auditVerifyRetry        = 10 * time.Minute // next attempt after a verification that could not finish
	auditVerifyMinGap       = 15 * time.Minute // rotations do not verify more often than this
	auditVerifyConfirmDelay = 2 * time.Second  // a violation is confirmed by a second verification
)

// AuditFullCheck is the state of the complete verification of the audit trail.
type AuditFullCheck struct {
	Interval      time.Duration // AuditVerifyInterval (0: verified on request only)
	Running       bool
	At            *time.Time // end of the last verification (nil: none finished yet)
	Trigger       string     // start-up | scheduled | rotation | truncation | api
	OK            bool
	Events        int
	LegacyPending bool // everything verified except the legacy prefix awaiting acceptance
	Error         string
}

type fullCheckState struct {
	mu       sync.Mutex
	last     AuditFullCheck
	running  int
	failures int         // consecutive verifications that could not finish
	kick     chan string // requested verification (trigger)
}

// AuditFullCheck reports the last complete verification of the audit trail.
func (s *Store) AuditFullCheck() AuditFullCheck {
	s.full.mu.Lock()
	defer s.full.mu.Unlock()
	c := s.full.last
	c.Interval, c.Running = s.opts.AuditVerifyInterval, s.full.running > 0
	return c
}

// kickAuditVerify requests a complete verification (never blocks: the audit sink calls it with its
// lock held).
func (s *Store) kickAuditVerify(trigger string) {
	select {
	case s.full.kick <- trigger:
	default:
	}
}

func (s *Store) auditVerifyLoop() {
	defer s.persistWG.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	t := time.NewTimer(0)
	defer t.Stop()
	trigger := "start-up"
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
		case trigger = <-s.full.kick:
			if at := s.AuditFullCheck().At; at != nil && time.Since(*at) < auditVerifyMinGap {
				t.Reset(auditVerifyMinGap - time.Since(*at))
				continue
			}
		}
		next := s.opts.AuditVerifyInterval
		var ie *auditIntegrityError
		if _, err := s.checkCompleteTrail(ctx, "", true, trigger); err != nil && !errors.As(err, &ie) {
			next = min(next, auditVerifyRetry)
		}
		t.Reset(next)
		trigger = "scheduled"
	}
}

// checkCompleteTrail verifies the complete trail and keeps the outcome as the last complete
// verification. A modified trail, confirmed by a second verification (a trail changing under the
// first one, such as a generation being compressed, is not recorded), is recorded as an integrity
// violation. A trail that no longer starts at its sealed origin raises an alert, and so do two
// verifications in a row that could not finish.
func (s *Store) checkCompleteTrail(ctx context.Context, path string, allowPending bool, trigger string) (AuditVerification, error) {
	s.full.mu.Lock()
	s.full.running++
	s.full.mu.Unlock()
	// While the audit log cannot be written (file storage) the newest events are not in it yet.
	unwritable := s.auditLogErr()
	res, err := s.verifyCompleteTrail(ctx, path, allowPending)
	if ie := (*auditIntegrityError)(nil); errors.As(err, &ie) && ie.kind == integrityViolation {
		select {
		case <-time.After(auditVerifyConfirmDelay):
			unwritable = errors.Join(unwritable, s.auditLogErr())
			res, err = s.verifyCompleteTrail(ctx, path, allowPending)
		case <-ctx.Done():
		}
	}
	s.finishFullCheck(ctx, trigger, res, err, errors.Join(unwritable, s.auditLogErr()))
	return res, err
}

// auditLogErr is the write failure of the audit log (file storage), nil while it can be written.
func (s *Store) auditLogErr() error {
	if s.cluster != nil {
		return nil
	}
	return s.opts.AuditSink.Err()
}

func (s *Store) finishFullCheck(ctx context.Context, trigger string, res AuditVerification, err, unwritable error) {
	now := time.Now().UTC()
	c := AuditFullCheck{At: &now, Trigger: trigger, OK: err == nil, Events: res.Events, LegacyPending: res.LegacyPending}
	ie := (*auditIntegrityError)(nil)
	integrity := errors.As(err, &ie)
	if integrity && ie.kind == integrityViolation && unwritable != nil {
		// Events missing from the log while it was not writable: no verdict on the trail.
		err, integrity = fmt.Errorf("the audit log was not writable (%v): %s", unwritable, err.Error()), false
	}
	var violation, alert string
	s.full.mu.Lock()
	s.full.running--
	switch {
	case err == nil:
		s.full.failures = 0
	case ctx.Err() != nil:
		s.full.mu.Unlock()
		return // stopping: no verdict
	case !integrity:
		c.Error = "the complete verification could not finish: " + err.Error()
		if s.full.failures++; s.full.failures == 2 {
			alert = "The complete verification of the audit trail could not finish twice in a row (" + err.Error() +
				"): until it does, changes to the trail outside the in-memory window are not detected."
		}
	default:
		s.full.failures = 0
		c.Error = err.Error()
		switch ie.kind {
		case integrityPending:
			// Everything else verified; the legacy prefix is reported on its own.
			c.OK, c.Error = true, ""
		case integrityViolation:
			violation = fmt.Sprintf("complete verification (%s): %s", trigger, err)
		case integrityStart:
			alert = "The audit trail does not start at its sealed origin: " + err.Error() + ". That is expected only between removing old generations (or rows) for retention and applying the retention point (POST /api/audit/retention); otherwise the oldest events were deleted: compare the trail with the SIEM copy."
		}
	}
	s.full.last = c
	s.full.mu.Unlock()

	switch {
	case c.OK:
		s.log.Info("audit trail verified completely", "trigger", trigger, "events", c.Events)
	default:
		s.log.Error("complete verification of the audit trail failed", "trigger", trigger, "events", c.Events, "error", c.Error)
	}
	if violation != "" {
		s.recordAuditViolation(violation)
	}
	if alert != "" {
		s.mu.Lock()
		s.raiseAuditAlertLocked(SecurityEventAuditVerification, alert)
		s.mu.Unlock()
	}
}

// recordAuditViolation records a violation found by a complete verification like one found at
// start-up: sealed into the checkpoint (file storage: saved with the state; cluster: committed with
// a write), audited and alerted.
func (s *Store) recordAuditViolation(msg string) {
	s.mu.Lock()
	s.auditViolationLocked(msg)
	if s.cluster == nil {
		s.reportAuditViolationsLocked()
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if err := s.withWrite(func() error { return nil }); err != nil {
		// The commit was rolled back: the next write records it.
		s.mu.Lock()
		s.auditViolations = append(s.auditViolations, msg)
		s.mu.Unlock()
		s.log.Error("the audit trail integrity violation is not recorded in cluster storage yet; the next change records it", "error", err)
	}
}
