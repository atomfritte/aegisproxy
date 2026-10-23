package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"aegisproxy/control-plane/internal/models"
)

const pgSchema = `
CREATE TABLE IF NOT EXISTS aegis_config (
	id          SMALLINT PRIMARY KEY CHECK (id = 1),
	revision    BIGINT NOT NULL,
	doc         JSONB NOT NULL,
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS aegis_audit (
	seq         BIGSERIAL PRIMARY KEY,
	id          TEXT NOT NULL UNIQUE,
	ts          TIMESTAMPTZ NOT NULL,
	actor       TEXT NOT NULL,
	action      TEXT NOT NULL,
	category    TEXT NOT NULL,
	event_hash  TEXT NOT NULL,
	prev_hash   TEXT NOT NULL,
	node_id     TEXT NOT NULL,
	doc         JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS aegis_audit_ts ON aegis_audit (ts);
CREATE TABLE IF NOT EXISTS aegis_flows (
	seq         BIGSERIAL PRIMARY KEY,
	ts          TIMESTAMPTZ NOT NULL,
	node_id     TEXT NOT NULL,
	server_id   TEXT NOT NULL,
	verdict     TEXT NOT NULL,
	host        TEXT NOT NULL,
	doc         JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS aegis_flows_ts ON aegis_flows (ts);
CREATE INDEX IF NOT EXISTS aegis_flows_server_ts ON aegis_flows (server_id, ts);
CREATE TABLE IF NOT EXISTS aegis_security_events (
	id          TEXT PRIMARY KEY,
	ts          TIMESTAMPTZ NOT NULL,
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
	type        TEXT NOT NULL,
	severity    TEXT NOT NULL,
	doc         JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS aegis_security_events_updated ON aegis_security_events (updated_at);
CREATE TABLE IF NOT EXISTS aegis_rule_stats (
	rule_id     TEXT PRIMARY KEY,
	hits        BIGINT NOT NULL DEFAULT 0,
	bytes       BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS aegis_schema (version INT NOT NULL);
`

const (
	pgNotifyChannel = "aegis_config"
	pgSchemaVersion = 1
	pgMigrationLock = 0x6165676973 // "aegis"
)

type PostgresBackend struct {
	pool   *pgxpool.Pool
	nodeID string
	log    *slog.Logger
}

// NewPostgresBackend connects, applies the schema (idempotent, serialized by an advisory lock)
// and returns the backend. Use sslmode=verify-full in production DSNs.
func NewPostgresBackend(ctx context.Context, dsn string, logger *slog.Logger) (*PostgresBackend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse AEGIS_DATABASE_URL: %w", err)
	}
	if cfg.MaxConns < 8 {
		cfg.MaxConns = 8
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "aegis-control-plane"
	cfg.HealthCheckPeriod = 15 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	host, _ := os.Hostname()
	b := &PostgresBackend{pool: pool, nodeID: fmt.Sprintf("%s-%s", host, newRandomID("n")[2:10]), log: logger.With("component", "postgres")}
	if err := b.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return b, nil
}

func (b *PostgresBackend) migrate(ctx context.Context) error {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", pgMigrationLock); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, pgSchema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	var n int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM aegis_schema").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(ctx, "INSERT INTO aegis_schema (version) VALUES ($1)", pgSchemaVersion); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (b *PostgresBackend) Name() string   { return "postgres" }
func (b *PostgresBackend) NodeID() string { return b.nodeID }
func (b *PostgresBackend) Close()         { b.pool.Close() }

func (b *PostgresBackend) LoadConfig(ctx context.Context) ([]byte, uint64, error) {
	var rev int64
	var doc []byte
	err := b.pool.QueryRow(ctx, "SELECT revision, doc FROM aegis_config WHERE id = 1").Scan(&rev, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if rev == 0 {
		return nil, 0, nil
	}
	return doc, uint64(rev), nil
}

func (b *PostgresBackend) StoredRevision(ctx context.Context) (uint64, error) {
	var rev int64
	err := b.pool.QueryRow(ctx, "SELECT revision FROM aegis_config WHERE id = 1").Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return uint64(rev), err
}

type pgTx struct {
	b      *PostgresBackend
	tx     pgx.Tx
	rev    uint64
	doc    []byte
	closed bool
}

func (b *PostgresBackend) BeginWrite(ctx context.Context, knownRev uint64) (ClusterTx, error) {
	tx, err := b.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '10s'"); err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO aegis_config (id, revision, doc) VALUES (1, 0, '{}'::jsonb) ON CONFLICT (id) DO NOTHING`); err != nil {
		tx.Rollback(ctx)
		return nil, err
	}
	var rev int64
	var doc []byte
	if err := tx.QueryRow(ctx, "SELECT revision, doc FROM aegis_config WHERE id = 1 FOR UPDATE").Scan(&rev, &doc); err != nil {
		tx.Rollback(ctx)
		return nil, fmt.Errorf("acquire cluster write lock: %w", err)
	}
	t := &pgTx{b: b, tx: tx, rev: uint64(rev)}
	if uint64(rev) != knownRev && rev != 0 {
		t.doc = doc
	}
	return t, nil
}

func (t *pgTx) StoredDoc() []byte      { return t.doc }
func (t *pgTx) StoredRevision() uint64 { return t.rev }

func (t *pgTx) RecentAudit(ctx context.Context, limit int) ([]models.AuditEvent, error) {
	return queryAudit(ctx, t.tx, limit)
}

type pgQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func queryAudit(ctx context.Context, q pgQuerier, limit int) ([]models.AuditEvent, error) {
	rows, err := q.Query(ctx, "SELECT doc FROM aegis_audit ORDER BY seq DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditEvent
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ev models.AuditEvent
		if err := json.Unmarshal(raw, &ev); err == nil {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (t *pgTx) Commit(ctx context.Context, doc []byte, rev uint64, audits []models.AuditEvent) error {
	if rev <= t.rev {
		return fmt.Errorf("refusing to commit non-increasing revision %d (stored %d)", rev, t.rev)
	}
	if _, err := t.tx.Exec(ctx, "UPDATE aegis_config SET revision = $1, doc = $2, updated_at = now(), updated_by = $3 WHERE id = 1",
		int64(rev), doc, t.b.nodeID); err != nil {
		return err
	}
	if len(audits) > 0 {
		batch := &pgx.Batch{}
		for _, ev := range audits {
			raw, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			batch.Queue(`INSERT INTO aegis_audit (id, ts, actor, action, category, event_hash, prev_hash, node_id, doc)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				ev.ID, ev.Timestamp, ev.Actor, ev.Action, ev.Category, ev.EventHash, ev.PrevHash, t.b.nodeID, raw)
		}
		if err := t.tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("append audit events: %w", err)
		}
	}
	if _, err := t.tx.Exec(ctx, "SELECT pg_notify($1, $2)", pgNotifyChannel, fmt.Sprint(rev)); err != nil {
		return err
	}
	t.closed = true
	return t.tx.Commit(ctx)
}

func (t *pgTx) Rollback(ctx context.Context) {
	if !t.closed {
		t.closed = true
		_ = t.tx.Rollback(context.WithoutCancel(ctx))
	}
}

func (b *PostgresBackend) RecentAudit(ctx context.Context, limit int) ([]models.AuditEvent, error) {
	return queryAudit(ctx, b.pool, limit)
}

func (b *PostgresBackend) StreamAudit(ctx context.Context, fn func(raw []byte) error) error {
	var last int64
	for {
		rows, err := b.pool.Query(ctx, "SELECT seq, doc FROM aegis_audit WHERE seq > $1 ORDER BY seq LIMIT 5000", last)
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&last, &raw); err != nil {
				rows.Close()
				return err
			}
			n++
			if err := fn(raw); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if n < 5000 {
			return nil
		}
	}
}

func (b *PostgresBackend) RecentFlows(ctx context.Context, limit int) ([]models.TrafficFlow, int64, error) {
	var maxSeq int64
	if err := b.pool.QueryRow(ctx, "SELECT COALESCE(max(seq), 0) FROM aegis_flows").Scan(&maxSeq); err != nil {
		return nil, 0, err
	}
	rows, err := b.pool.Query(ctx, "SELECT doc FROM aegis_flows ORDER BY seq DESC LIMIT $1", limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.TrafficFlow
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var f models.TrafficFlow
		if json.Unmarshal(raw, &f) == nil {
			out = append(out, f)
		}
	}
	return out, maxSeq, rows.Err()
}

func (b *PostgresBackend) RecentSecurityEvents(ctx context.Context, limit int) ([]models.SecurityEvent, error) {
	rows, err := b.pool.Query(ctx, "SELECT doc FROM aegis_security_events ORDER BY ts DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SecurityEvent
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ev models.SecurityEvent
		if json.Unmarshal(raw, &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (b *PostgresBackend) PushTelemetry(ctx context.Context, tb TelemetryBatch) error {
	if tb.empty() {
		return nil
	}
	batch := &pgx.Batch{}
	for _, f := range tb.Flows {
		raw, err := json.Marshal(f)
		if err != nil {
			continue
		}
		batch.Queue("INSERT INTO aegis_flows (ts, node_id, server_id, verdict, host, doc) VALUES ($1, $2, $3, $4, $5, $6)",
			f.Timestamp, b.nodeID, f.ServerID, f.Verdict, f.Host, raw)
	}
	for _, ev := range tb.Events {
		raw, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		batch.Queue(`INSERT INTO aegis_security_events (id, ts, type, severity, doc) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = clock_timestamp()`,
			ev.ID, ev.Timestamp, ev.Type, ev.Severity, raw)
	}
	for id, st := range tb.Stats {
		batch.Queue(`INSERT INTO aegis_rule_stats (rule_id, hits, bytes) VALUES ($1, $2, $3)
			ON CONFLICT (rule_id) DO UPDATE SET hits = aegis_rule_stats.hits + EXCLUDED.hits, bytes = aegis_rule_stats.bytes + EXCLUDED.bytes`,
			id, st.Hits, st.Bytes)
	}
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PullFlows returns flows recorded by other nodes. Because BIGSERIAL values can commit out of
// order, callers re-scan a trailing window and de-duplicate by flow ID.
func (b *PostgresBackend) PullFlows(ctx context.Context, afterSeq int64, limit int) ([]models.TrafficFlow, int64, error) {
	rows, err := b.pool.Query(ctx, "SELECT seq, doc FROM aegis_flows WHERE seq > $1 AND node_id <> $2 ORDER BY seq LIMIT $3",
		afterSeq, b.nodeID, limit)
	if err != nil {
		return nil, afterSeq, err
	}
	defer rows.Close()
	maxSeq := afterSeq
	var out []models.TrafficFlow
	for rows.Next() {
		var seq int64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return nil, afterSeq, err
		}
		maxSeq = max(maxSeq, seq)
		var f models.TrafficFlow
		if json.Unmarshal(raw, &f) == nil {
			out = append(out, f)
		}
	}
	return out, maxSeq, rows.Err()
}

func (b *PostgresBackend) PullSecurityEvents(ctx context.Context, since time.Time) ([]models.SecurityEvent, error) {
	rows, err := b.pool.Query(ctx, "SELECT doc FROM aegis_security_events WHERE updated_at > $1 ORDER BY updated_at LIMIT 1000", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SecurityEvent
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ev models.SecurityEvent
		if json.Unmarshal(raw, &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (b *PostgresBackend) RuleStats(ctx context.Context) (map[string]RuleStat, error) {
	rows, err := b.pool.Query(ctx, "SELECT rule_id, hits, bytes FROM aegis_rule_stats")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]RuleStat{}
	for rows.Next() {
		var id string
		var st RuleStat
		if err := rows.Scan(&id, &st.Hits, &st.Bytes); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

func (b *PostgresBackend) Prune(ctx context.Context, flowRetention, eventRetention time.Duration) error {
	if _, err := b.pool.Exec(ctx, "DELETE FROM aegis_flows WHERE ts < $1", time.Now().Add(-flowRetention)); err != nil {
		return err
	}
	_, err := b.pool.Exec(ctx, "DELETE FROM aegis_security_events WHERE ts < $1", time.Now().Add(-eventRetention))
	return err
}

func (b *PostgresBackend) Listen(ctx context.Context, fn func(rev uint64)) {
	for ctx.Err() == nil {
		if err := b.listenOnce(ctx, fn); err != nil && ctx.Err() == nil {
			b.log.Warn("LISTEN connection lost; retrying (polling fallback stays active)", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (b *PostgresBackend) listenOnce(ctx context.Context, fn func(rev uint64)) error {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgNotifyChannel); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "UNLISTEN "+pgNotifyChannel) }()
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var rev uint64
		if _, err := fmt.Sscan(n.Payload, &rev); err == nil {
			fn(rev)
		}
	}
}
