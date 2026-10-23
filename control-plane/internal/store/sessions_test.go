package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/auth"
	"aegisproxy/control-plane/internal/models"
)

func TestLearningSessionLifecycle(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	setupFleet(t, st)
	// grp-gpu selects servers by label only; the lead of grp-gpu may learn on them.
	if _, err := st.UpsertGroup(models.ServerGroup{ID: "grp-gpu", Name: "GPU", MatchLabels: map[string]string{"pool": "gpu"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertServer(models.Server{ID: "srv-gpu-1", Hostname: "gpu-1", IP: "10.7.0.5", Labels: map[string]string{"pool": "gpu"}}, adminClaims); err != nil {
		t.Fatal(err)
	}
	gpuLead := &auth.TokenClaims{UserID: "usr-gpu", Username: "gpu-lead", Role: models.RoleTeamLead, AllowedGroups: []string{"grp-gpu"}}
	sess, err := st.StartLearningSession("pip mirror", "", "srv-gpu-1", 30, "record_only", gpuLead)
	if err != nil {
		t.Fatalf("team lead of a label-selected group could not start a session: %v", err)
	}
	if len(sess.GroupIDs) != 1 || sess.GroupIDs[0] != "grp-gpu" {
		t.Fatalf("session groups %v, want effective groups", sess.GroupIDs)
	}
	if _, err := st.StartLearningSession("x", "", "srv-ci-1", 30, "record_only", gpuLead); err == nil {
		t.Fatal("team lead started a session on a server outside their groups")
	}

	cand := []models.CompiledRuleCandidate{{HostPattern: "pypi.org", PathPattern: "/simple/**", Methods: []string{"GET"}, Selected: true, HitCount: 3}}
	_, _, err = st.PublishSessionRules(sess.ID, SessionPublish{Candidates: cand, RulePrefix: "pip", NewSetName: "pip", TargetGroupIDs: []string{"grp-gpu"}}, gpuLead)
	if !errors.Is(err, ErrSessionRecording) {
		t.Fatalf("publishing a recording session: %v, want ErrSessionRecording", err)
	}
	if got, _ := st.GetSession(sess.ID); !got.Recording(time.Now()) {
		t.Fatal("rejected publish ended the recording")
	}
	if _, err := st.StopLearningSession(sess.ID, gpuLead); err != nil {
		t.Fatal(err)
	}
	if _, err := st.StopLearningSession(sess.ID, gpuLead); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("stopping an ended session: %v", err)
	}
	if _, rules, err := st.PublishSessionRules(sess.ID, SessionPublish{Candidates: cand, RulePrefix: "pip", NewSetName: "pip", TargetGroupIDs: []string{"grp-gpu"}}, gpuLead); err != nil || len(rules) != 1 {
		t.Fatalf("publish after stop: %v %d", err, len(rules))
	}
	if got, _ := st.GetSession(sess.ID); got.Status != "published" {
		t.Fatalf("status %s after publish", got.Status)
	}
	if _, err := st.StopLearningSession(sess.ID, gpuLead); err == nil {
		t.Fatal("published session could be stopped (status regression)")
	}
}

func TestServerImportReportsAllRowErrors(t *testing.T) {
	st := newTestStore(t, t.TempDir(), false)
	res, err := st.ImportServers([]models.Server{{ID: "Bad ID!", Hostname: "", IP: "300.1.1.1", SubnetCIDR: "10.0.0.0/33"}}, true, adminClaims)
	if err != nil {
		t.Fatal(err)
	}
	msg := res[0].Error
	for _, want := range []string{"server id", "hostname", "invalid IP", "invalid subnet"} {
		if !strings.Contains(msg, want) {
			t.Errorf("row error %q lacks %q", msg, want)
		}
	}
}

func TestSecurityEventEngineAttribution(t *testing.T) {
	f := models.TrafficFlow{Verdict: models.VerdictAllowed, Host: "x.example",
		SecurityFlags: []string{"AV_FOUND:YARA: Suspicious_Macro", "AV_ERROR:icap:ICAP timeout after 30s", "AV_FOUND:Win.Test.EICAR_HDB-1", "DLP:icap:PCI data"}}
	var got []string
	for _, ev := range securityEventsForFlow(f) {
		got = append(got, ev.Source)
	}
	want := []string{"YARA", "ICAP", "ClamAV", "ICAP DLP"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("event sources %v, want %v", got, want)
	}
}
