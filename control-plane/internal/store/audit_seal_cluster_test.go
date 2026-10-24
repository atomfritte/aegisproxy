package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

// Cluster variants of the round-2 audit findings (run with AEGIS_TEST_DATABASE_URL).

type clusterRow struct {
	seq int64
	ev  models.AuditEvent
}

func clusterRows(t *testing.T, be *PostgresBackend) []clusterRow {
	t.Helper()
	rows, err := be.pool.Query(context.Background(), "SELECT seq, doc FROM aegis_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []clusterRow
	for rows.Next() {
		var r clusterRow
		var raw []byte
		if err := rows.Scan(&r.seq, &raw); err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(raw, &r.ev)
		out = append(out, r)
	}
	return out
}

// editClusterDoc changes the stored configuration document in place (same revision).
func editClusterDoc(t *testing.T, be *PostgresBackend, edit func(doc map[string]json.RawMessage)) {
	t.Helper()
	var raw []byte
	if err := be.pool.QueryRow(context.Background(), "SELECT doc FROM aegis_config WHERE id = 1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(raw, &doc)
	edit(doc)
	raw, _ = json.Marshal(doc)
	if _, err := be.pool.Exec(context.Background(), "UPDATE aegis_config SET doc = $1 WHERE id = 1", raw); err != nil {
		t.Fatal(err)
	}
}

func clusterBackend(t *testing.T, dsn string) *PostgresBackend {
	t.Helper()
	be, err := NewPostgresBackend(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(be.Close)
	return be
}

// Finding 1 (cluster): audit_chain_key, audit_anchor and audit_checkpoint removed from
// aegis_config.doc and the rows re-hashed unkeyed: pending until a Super Admin accepts it.
func TestClusterAuditKeyAndAnchorRemovalIsNeverAccepted(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	absent := filepath.Join(t.TempDir(), "absent.jsonl")
	a := newClusterNode(t, dsn, t.TempDir())
	mkAuditGroups(t, a, 3)
	a.Close()
	be := clusterBackend(t, dsn)
	rows := clusterRows(t, be)
	prev := zeroHash
	for i := range rows {
		ev := &rows[i].ev
		ev.HashVersion, ev.PrevHash = 0, prev
		ev.EventHash = auditHashV1(prev, *ev)
		prev = ev.EventHash
		raw, _ := json.Marshal(ev)
		if _, err := be.pool.Exec(context.Background(), "UPDATE aegis_audit SET doc = $1, event_hash = $2, prev_hash = $3 WHERE seq = $4",
			raw, ev.EventHash, ev.PrevHash, rows[i].seq); err != nil {
			t.Fatal(err)
		}
	}
	editClusterDoc(t, be, func(doc map[string]json.RawMessage) {
		delete(doc, "audit_chain_key")
		delete(doc, "audit_anchor")
		delete(doc, "audit_checkpoint")
	})

	b := newClusterNode(t, dsn, t.TempDir())
	res := mustFailVerify(t, b, absent, "legacy_pending")
	if !res.LegacyPending || res.Legacy != len(rows) || res.LegacyHead != prev {
		t.Fatalf("pending prefix: %+v", res)
	}
	if !b.AuditStatus().LegacyPending {
		t.Fatalf("pending prefix not reported: %+v", b.AuditStatus())
	}
	eventually(t, "legacy_pending alert", func() bool { return hasAuditAlert(b, SecurityEventAuditLegacyPending) })
	mkAuditGroups(t, b, 1)
	c := newClusterNode(t, dsn, t.TempDir())
	mustFailVerify(t, c, absent, "legacy_pending")

	// Only an explicit Super Admin decision ends it, and it holds for every node.
	if _, err := c.AcceptLegacyAudit(context.Background(), absent, len(rows), prev, adminClaims); err != nil {
		t.Fatal(err)
	}
	for _, node := range []*Store{b, c} {
		if res := node.VerifyCompleteAudit(context.Background(), absent); !res.OK || res.Legacy != len(rows) || !res.CheckpointMatches {
			t.Fatalf("after acceptance: %+v", res)
		}
	}
}

// Findings 1 and 2 (cluster): the anchor is removed from a keyed trail (the start cut off).
func TestClusterAuditAnchorRemovalIsViolation(t *testing.T) {
	dsn := testDSN(t)
	resetDB(t, dsn)
	absent := filepath.Join(t.TempDir(), "absent.jsonl")
	a := newClusterNode(t, dsn, t.TempDir())
	mkAuditGroups(t, a, 3)
	a.Close()
	be := clusterBackend(t, dsn)
	rows := clusterRows(t, be)
	if _, err := be.pool.Exec(context.Background(), "DELETE FROM aegis_audit WHERE seq <= $1", rows[1].seq); err != nil {
		t.Fatal(err)
	}
	editClusterDoc(t, be, func(doc map[string]json.RawMessage) { delete(doc, "audit_anchor") })

	b := newClusterNode(t, dsn, t.TempDir())
	mustFailVerify(t, b, absent, "anchor is missing")
	if b.AuditStatus().Integrity == "" {
		t.Fatalf("violation not reported: %+v", b.AuditStatus())
	}
	eventually(t, "violation alert", func() bool { return hasAuditAlert(b, SecurityEventAuditViolation) })
	b.Close()
	c := newClusterNode(t, dsn, t.TempDir())
	mustFailVerify(t, c, absent, "anchor is missing")
}

// Finding 3 (cluster): the newest rows are deleted from aegis_audit.
func TestClusterAuditTailTruncationIsDetected(t *testing.T) {
	for _, stripCheckpoint := range []bool{false, true} {
		dsn := testDSN(t)
		resetDB(t, dsn)
		absent := filepath.Join(t.TempDir(), "absent.jsonl")
		a := newClusterNode(t, dsn, t.TempDir())
		mkAuditGroups(t, a, 3)
		if res := a.VerifyCompleteAudit(context.Background(), absent); !res.OK || !res.CheckpointMatches {
			t.Fatalf("intact trail: %+v", res)
		}
		be := clusterBackend(t, dsn)
		rows := clusterRows(t, be)
		if _, err := be.pool.Exec(context.Background(), "DELETE FROM aegis_audit WHERE seq = $1", rows[len(rows)-1].seq); err != nil {
			t.Fatal(err)
		}
		want := "newest events are missing"
		if stripCheckpoint {
			editClusterDoc(t, be, func(doc map[string]json.RawMessage) { delete(doc, "audit_checkpoint") })
			want = "checkpoint is missing"
		}
		// Detected by a running node (the verification reads the sealed checkpoint from the database) ...
		mustFailVerify(t, a, absent, want)
		a.Close()
		// ... and by every node that starts later, also after the violation was recorded.
		b := newClusterNode(t, dsn, t.TempDir())
		mustFailVerify(t, b, absent, "")
		if b.AuditStatus().Integrity == "" {
			t.Fatalf("violation not reported: %+v", b.AuditStatus())
		}
		// Raised during start-up; the node shows it once the telemetry round trip replicated it.
		eventually(t, "violation alert", func() bool { return hasAuditAlert(b, SecurityEventAuditViolation) })
		b.Close()
		c := newClusterNode(t, dsn, t.TempDir())
		mustFailVerify(t, c, absent, "integrity violation recorded")
		c.Close()
	}
}
