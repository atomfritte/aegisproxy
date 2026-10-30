package advisory

import "testing"

func TestCVSSBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// Canonical examples from the CVSS v3.1 specification and well-known CVEs.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1}, // reflected XSS
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.7},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 0}, // unsupported version
		{"garbage", 0},
	}
	for _, c := range cases {
		got := cvssBaseScore(c.vector)
		if got != c.want {
			t.Errorf("cvssBaseScore(%q) = %v, want %v", c.vector, got, c.want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{{0, "unknown"}, {3.9, "low"}, {4.0, "medium"}, {6.9, "medium"}, {7.0, "high"}, {8.9, "high"}, {9.0, "critical"}, {10, "critical"}}
	for _, c := range cases {
		if got := severityFromCVSS(c.score); got != c.want {
			t.Errorf("severityFromCVSS(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}
