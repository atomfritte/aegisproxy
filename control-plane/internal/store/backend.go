package store

import (
	"context"
	"time"

	"aegisproxy/control-plane/internal/models"
)

// ClusterBackend is shared storage that lets several control-plane replicas run active-active.
//
// Consistency model:
//   - Configuration (users, fleet, rules, bypasses, sessions, requests, threat-protection settings,
//     revoked sessions) is one versioned document. Every mutation runs inside BeginWrite, which takes a
//     cluster-wide lock, so writes are linearizable and the audit hash chain stays linear.
//   - Replicas learn about new revisions via push notification (LISTEN/NOTIFY) with polling as fallback.
//   - Telemetry (flows, security events, rule hit counters) is append/upsert-only and replicated
//     asynchronously within ~1s.
type ClusterBackend interface {
	Name() string
	NodeID() string
	// LoadConfig returns the stored configuration document (nil, 0 when the cluster is empty).
	LoadConfig(ctx context.Context) ([]byte, uint64, error)
	// StoredRevision is a cheap revision probe used for change polling.
	StoredRevision(ctx context.Context) (uint64, error)
	// BeginWrite acquires the cluster-wide write lock.
	BeginWrite(ctx context.Context, knownRev uint64) (ClusterTx, error)
	RecentAudit(ctx context.Context, limit int) ([]models.AuditEvent, error)
	// StreamAudit emits the complete audit trail oldest first (export).
	StreamAudit(ctx context.Context, fn func(raw []byte) error) error
	RecentFlows(ctx context.Context, limit int) ([]models.TrafficFlow, int64, error)
	RecentSecurityEvents(ctx context.Context, limit int) ([]models.SecurityEvent, error)
	PushTelemetry(ctx context.Context, b TelemetryBatch) error
	PullFlows(ctx context.Context, afterSeq int64, limit int) ([]models.TrafficFlow, int64, error)
	PullSecurityEvents(ctx context.Context, since time.Time) ([]models.SecurityEvent, error)
	RuleStats(ctx context.Context) (map[string]RuleStat, error)
	Prune(ctx context.Context, flowRetention, eventRetention time.Duration) error
	// Listen blocks until ctx is done, invoking fn for every config revision committed by any node.
	Listen(ctx context.Context, fn func(rev uint64))
	Close()
}

type ClusterTx interface {
	// StoredDoc returns the stored document if its revision differs from knownRev (else nil).
	StoredDoc() []byte
	StoredRevision() uint64
	// RecentAudit reads the audit window inside the locked transaction.
	RecentAudit(ctx context.Context, limit int) ([]models.AuditEvent, error)
	// ImportAudit appends existing audit events (migration from file storage) in the given order,
	// skipping events whose ID is stored already.
	ImportAudit(ctx context.Context, audits []models.AuditEvent) error
	Commit(ctx context.Context, doc []byte, rev uint64, audits []models.AuditEvent) error
	Rollback(ctx context.Context)
}

type RuleStat struct {
	Hits  int64 `json:"hits"`
	Bytes int64 `json:"bytes"`
}

type TelemetryBatch struct {
	Flows  []models.TrafficFlow
	Events []models.SecurityEvent
	Stats  map[string]RuleStat
}

func (b *TelemetryBatch) empty() bool {
	return len(b.Flows) == 0 && len(b.Events) == 0 && len(b.Stats) == 0
}
