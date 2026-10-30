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
