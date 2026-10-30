package coordinator

import (
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func adv(id, sev string, withdrawn, malware bool, aliases ...string) models.PackageAdvisory {
	return models.PackageAdvisory{ID: id, Severity: sev, Withdrawn: withdrawn, Malware: malware, Aliases: aliases}
}

func ids(advs []models.PackageAdvisory) []string {
	out := make([]string, 0, len(advs))
	for _, a := range advs {
		out = append(out, a.ID)
	}
	return out
}

func TestNewAdvisories(t *testing.T) {
	cur := &models.PackageAssessment{Advisories: []models.PackageAdvisory{
		adv("GHSA-aaaa", "high", false, false),
		adv("GHSA-bbbb", "critical", false, false, "CVE-2026-2"),
		adv("GHSA-cccc", "low", true, false), // withdrawn → never "new"
		adv("MAL-1", "critical", false, true),
	}}

	t.Run("no prior assessment: all non-withdrawn are new", func(t *testing.T) {
		got := ids(newAdvisories(nil, cur))
		want := []string{"GHSA-aaaa", "GHSA-bbbb", "MAL-1"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("known by ID is excluded", func(t *testing.T) {
		prev := &models.PackageAssessment{Advisories: []models.PackageAdvisory{adv("GHSA-aaaa", "high", false, false)}}
		got := ids(newAdvisories(prev, cur))
		for _, id := range got {
			if id == "GHSA-aaaa" {
				t.Fatalf("GHSA-aaaa was already known, should not be new: %v", got)
			}
		}
		if len(got) != 2 { // GHSA-bbbb, MAL-1
			t.Fatalf("got %v, want 2 new", got)
		}
	})

	t.Run("known by alias is excluded", func(t *testing.T) {
		// prev knew the advisory under its CVE alias; cur reports it under the GHSA id — still not new.
		prev := &models.PackageAssessment{Advisories: []models.PackageAdvisory{adv("CVE-2026-2", "critical", false, false)}}
		for _, id := range ids(newAdvisories(prev, cur)) {
			if id == "GHSA-bbbb" {
				t.Fatalf("GHSA-bbbb shares alias CVE-2026-2 with a known advisory, should not be new")
			}
		}
	})

	t.Run("withdrawn is never new", func(t *testing.T) {
		for _, id := range ids(newAdvisories(nil, cur)) {
			if id == "GHSA-cccc" {
				t.Fatal("withdrawn advisory must not be reported as new")
			}
		}
	})
}

func TestAnyMalware(t *testing.T) {
	if anyMalware([]models.PackageAdvisory{adv("GHSA-x", "high", false, false)}) {
		t.Fatal("no malware present")
	}
	if !anyMalware([]models.PackageAdvisory{adv("GHSA-x", "high", false, false), adv("MAL-1", "critical", false, true)}) {
		t.Fatal("malware present")
	}
}

func assess(advs ...models.PackageAdvisory) *models.PackageAssessment {
	return &models.PackageAssessment{Advisories: advs}
}

func TestReauditDecision(t *testing.T) {
	high := adv("GHSA-high", "high", false, false)
	crit := adv("GHSA-crit", "critical", false, false)
	mal := adv("MAL-1", "critical", false, true)

	cases := []struct {
		name       string
		prev, cur  *models.PackageAssessment
		threshold  string
		wantRevoke bool
		wantAction string
	}{
		{"baseline: no prior, no findings, no threshold", nil, assess(), "", false, ""},
		{"baseline suppresses pre-existing findings (auto-revoke off)", nil, assess(crit, mal), "", false, ""},
		{"baseline still revokes when the threshold is met", nil, assess(crit), "critical", true, "revoked"},
		{"baseline still revokes on malware regardless of threshold", nil, assess(mal), "high", true, "revoked"},
		{"new advisory below threshold is reported, not revoked", assess(high), assess(high, crit), "", false, "advisory"},
		{"new malware is reported as malware (auto-revoke off)", assess(high), assess(high, mal), "", false, "malware"},
		{"nothing new: silent", assess(high), assess(high), "", false, ""},
		{"revoke takes precedence over the advisory alert", assess(high), assess(high, crit), "critical", true, "revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			revoke, action, advs := reauditDecision(tc.prev, tc.cur, tc.threshold)
			if revoke != tc.wantRevoke || action != tc.wantAction {
				t.Fatalf("got (revoke=%v, action=%q), want (revoke=%v, action=%q)", revoke, action, tc.wantRevoke, tc.wantAction)
			}
			if action == "" && advs != nil {
				t.Fatalf("no action but advisories returned: %v", ids(advs))
			}
			if action != "" && len(advs) == 0 {
				t.Fatal("an action was chosen but no advisories were attached")
			}
		})
	}
}
