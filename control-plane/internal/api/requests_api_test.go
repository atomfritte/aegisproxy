package api

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/store"
)

func TestRequestReadEndpoints(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	var ids []string
	for _, host := range []string{"a.example.org", "b.example.org"} {
		req, _, err := h.st.CreateAccessRequest(models.AccessRequest{ServerIP: "10.0.0.9", RequestedURL: "https://" + host + "/x", Host: host, Path: "/x",
			Requester: "dev", Reason: "build dependency", Duration: "7d"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, req.ID)
	}
	resp := h.do(t, "GET", "/api/requests/"+ids[0], nil, nil)
	var got models.AccessRequest
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&got) != nil || got.ID != ids[0] || got.Host != "a.example.org" {
		t.Fatalf("GET request: %d %+v", resp.StatusCode, got)
	}
	if resp := h.do(t, "GET", "/api/requests/req-missing", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("missing request: %d", resp.StatusCode)
	}
	var list struct {
		Requests []models.AccessRequest `json:"requests"`
		Total    int                    `json:"total"`
	}
	resp = h.do(t, "GET", "/api/requests?status=pending&limit=1", nil, nil)
	if json.NewDecoder(resp.Body).Decode(&list) != nil || list.Total != 2 || len(list.Requests) != 1 {
		t.Fatalf("list: %+v", list)
	}
	resp = h.do(t, "GET", "/api/requests?status=approved", nil, nil)
	list.Requests, list.Total = nil, -1
	if json.NewDecoder(resp.Body).Decode(&list) != nil || list.Total != 0 || list.Requests == nil {
		t.Fatalf("approved filter: %+v", list)
	}
}

func TestAuditExportStreamsCompleteTrail(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.cfg.AuditLogPath = filepath.Join(dir, "audit.jsonl")
	// Two rotated generations plus the current file: the export must contain all of them in order.
	os.WriteFile(h.cfg.AuditLogPath+"-20260801", []byte(`{"id":"aud-old"}`+"\n"), 0o600)
	os.WriteFile(h.cfg.AuditLogPath+"-20260901", []byte(`{"id":"aud-mid"}`+"\n"), 0o600)
	os.WriteFile(h.cfg.AuditLogPath, []byte(`{"id":"aud-new"}`+"\n"), 0o600)
	h.login(t)
	resp := h.do(t, "GET", "/api/audit/export", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var ids []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var ev models.AuditEvent
		json.Unmarshal(sc.Bytes(), &ev)
		ids = append(ids, ev.ID)
	}
	if len(ids) != 3 || ids[0] != "aud-old" || ids[1] != "aud-mid" || ids[2] != "aud-new" {
		t.Fatalf("exported %v", ids)
	}

	// Without a file the in-memory window is exported (oldest first).
	h.cfg.AuditLogPath = filepath.Join(dir, "absent", "audit.jsonl")
	resp = h.do(t, "GET", "/api/audit/export", nil, nil)
	sc = bufio.NewScanner(resp.Body)
	n := 0
	for sc.Scan() {
		n++
	}
	if want := len(h.st.GetSnapshot().AuditEvents); n != want || n == 0 {
		t.Fatalf("fallback export %d lines, want %d", n, want)
	}
}

func TestPublishRecordingSessionConflicts(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	if _, err := h.st.UpsertServer(models.Server{ID: "srv-l", Hostname: "l", IP: "10.0.0.7"}, adminClaimsFor(h)); err != nil {
		t.Fatal(err)
	}
	sess, err := h.st.StartLearningSession("s", "", "srv-l", 15, "record_only", adminClaimsFor(h))
	if err != nil {
		t.Fatal(err)
	}
	body := store.SessionPublish{RulePrefix: "p", NewSetName: "p", Candidates: []models.CompiledRuleCandidate{{HostPattern: "example.org", PathPattern: "/**", Selected: true}}}
	if resp := h.do(t, "POST", "/api/sessions/"+sess.ID+"/publish", body, map[string]string{"X-Requested-With": "aegis-ui"}); resp.StatusCode != 409 {
		t.Fatalf("publish while recording: %d, want 409", resp.StatusCode)
	}
}
