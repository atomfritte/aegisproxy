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
//   - The package firewall's work-store (requests, assessments, analysis jobs) is a second versioned
//     document, committed in the SAME write transaction as the configuration (so cross-node coordination
//     such as sandbox-job leases stays linearizable) but stored in its own row, so its high-churn writes
//     do not re-serialize or re-replicate the (large) configuration document. Replicas pick up work-store
//     changes by polling its revision.
//   - Telemetry (flows, security events, rule hit counters) is append/upsert-only and replicated
//     asynchronously within ~1s.
type ClusterBackend interface {
	Name() string
	NodeID() string
	// LoadConfig returns the stored configuration document (nil, 0 when the cluster is empty).
	LoadConfig(ctx context.Context) ([]byte, uint64, error)
	// LoadPackageWork returns the stored package work-store document (nil, 0 when empty).
	LoadPackageWork(ctx context.Context) ([]byte, uint64, error)
	// StoredRevision is a cheap configuration-revision probe used for change polling.
	StoredRevision(ctx context.Context) (uint64, error)
	// StoredPackageWorkRevision is a cheap work-store-revision probe used for change polling.
	StoredPackageWorkRevision(ctx context.Context) (uint64, error)
	// BeginWrite acquires the cluster-wide write lock and reports the stored config + work-store if newer.
	BeginWrite(ctx context.Context, knownRev, knownPkgRev uint64) (ClusterTx, error)
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
	// StoredDoc returns the stored configuration document if its revision differs from knownRev (else nil).
	StoredDoc() []byte
	StoredRevision() uint64
	// StoredPackageWorkDoc returns the stored work-store document if its revision differs from
	// knownPkgRev (else nil); StoredPackageWorkRevision is its stored revision.
	StoredPackageWorkDoc() []byte
	StoredPackageWorkRevision() uint64
	// RecentAudit reads the audit window inside the locked transaction.
	RecentAudit(ctx context.Context, limit int) ([]models.AuditEvent, error)
	// ImportAudit appends existing audit events (migration from file storage) in the given order,
	// skipping events whose ID is stored already.
	ImportAudit(ctx context.Context, audits []models.AuditEvent) error
	// Commit writes the configuration document (when doc != nil) and/or the work-store document (when
	// pkgDoc != nil) plus any audit events, atomically. A nil document leaves that row untouched.
	Commit(ctx context.Context, doc []byte, rev uint64, audits []models.AuditEvent, pkgDoc []byte, pkgRev uint64) error
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
