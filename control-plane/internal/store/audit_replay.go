package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"aegisproxy/control-plane/internal/export"
	"aegisproxy/control-plane/internal/models"
)

// The log export replays audit events from this node's trail after a restart (export.AuditSource):
// every sink carrying audit records keeps a cursor, so records a crash took out of its queue are
// delivered again. In cluster mode each node exports the events it wrote, so only the local audit
// log is read.

var errNoLocalTrail = errors.New("no local audit log to replay from")

// LatestAudit returns the newest audit event written by this node.
func (s *Store) LatestAudit() (models.AuditEvent, bool) {
	if s.cluster == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if len(s.state.AuditEvents) == 0 {
			return models.AuditEvent{}, false
		}
		return s.state.AuditEvents[0], true
	}
	files, ok, err := s.openFileTrail("")
	if err != nil || !ok {
		return models.AuditEvent{}, false
	}
	defer closeTrail(files)
	for i := len(files) - 1; i >= 0; i-- {
		if ev, err := files[i].lastEvent(); err == nil && ev.ID != "" {
			return ev, true
		}
	}
	return models.AuditEvent{}, false
}

// ReplayAuditAfter streams the audit events of this node that follow afterID to fn, oldest first.
// When afterID is no longer in the trail (rotated away), the events newer than afterTime are
// replayed. found reports whether afterID was found.
func (s *Store) ReplayAuditAfter(ctx context.Context, afterID string, afterTime time.Time, fn func(models.AuditEvent) error) (bool, error) {
	found := false
	visit := func(ev models.AuditEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case found:
		case afterID != "" && ev.ID == afterID:
			found = true
			return nil
		case !ev.Timestamp.After(afterTime):
			return nil
		}
		return fn(ev)
	}
	var window []models.AuditEvent // newest first
	if s.cluster == nil {
		// Shortcut: the cursor is usually within the in-memory window, which the audit log mirrors.
		s.mu.RLock()
		if i := slices.IndexFunc(s.state.AuditEvents, func(e models.AuditEvent) bool { return e.ID == afterID }); afterID != "" && i >= 0 {
			window = slices.Clone(s.state.AuditEvents[:i+1])
		} else {
			window = slices.Clone(s.state.AuditEvents)
		}
		s.mu.RUnlock()
		if afterID != "" && len(window) > 0 && window[len(window)-1].ID == afterID {
			for i := len(window) - 1; i >= 0; i-- {
				if err := visit(window[i]); err != nil {
					return found, err
				}
			}
			return found, nil
		}
	}
	files, ok, err := s.openFileTrail("")
	if err != nil {
		return false, err
	}
	if !ok {
		if s.cluster != nil {
			return false, errNoLocalTrail
		}
		for i := len(window) - 1; i >= 0; i-- { // no audit log: the window is all there is
			if err := visit(window[i]); err != nil {
				return found, err
			}
		}
		return found, nil
	}
	defer closeTrail(files)
	err = scanTrail(files, visit)
	return found, err
}

// RecordExportAlert raises an export alert (audit or security records set aside or lost by a log
// export sink) as a security event: shown on the dashboard, sent to the notification channels and
// exported. Repeats within 15 minutes are counted on the existing event.
func (s *Store) RecordExportAlert(a export.Alert) {
	ev := models.SecurityEvent{Type: export.AlertEventType, Severity: a.Severity, Action: "detected",
		Detail: a.Detail, Source: "log-export"}
	s.mu.Lock()
	created, isNew := s.upsertSecurityEventLocked(ev)
	if isNew {
		s.markDirtyLocked()
	} else {
		s.markTelemetryDirtyLocked()
	}
	notifyCfg := s.state.NotifyConfig
	s.mu.Unlock()
	if s.telemetry != nil {
		s.telemetry.add(nil, []models.SecurityEvent{created}, nil)
	}
	if !isNew {
		return
	}
	s.log.Error("log export alert", "sink", a.SinkName, "sink_id", a.SinkID, "severity", a.Severity, "detail", a.Detail)
	s.opts.Exporter.Publish(export.SecurityEvent(created))
	if s.notifier != nil && notifyCfg.NotifySecurityEvents {
		s.notifier.NotifySecurityEvent(created)
	}
}
