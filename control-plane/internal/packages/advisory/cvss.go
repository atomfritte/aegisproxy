package advisory

import (
	"math"
	"strings"
)

// cvssBaseScore computes the CVSS v3.0 / v3.1 base score from a vector string
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). Vectors of other versions (v2, v4) return 0, so
// the caller falls back to the database-provided severity word. The formula is the official CVSS v3
// specification.
func cvssBaseScore(vector string) float64 {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	av, ok1 := cvssAV[m["AV"]]
	ac, ok2 := cvssAC[m["AC"]]
	ui, ok3 := cvssUI[m["UI"]]
	c, ok4 := cvssImpact[m["C"]]
	i, ok5 := cvssImpact[m["I"]]
	a, ok6 := cvssImpact[m["A"]]
	scope := m["S"]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || (scope != "U" && scope != "C") {
		return 0
	}
	pr := cvssPR(m["PR"], scope == "C")
	if pr < 0 {
		return 0
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "C" {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "C" {
		base = roundUp(math.Min(1.08*(impact+exploit), 10))
	} else {
		base = roundUp(math.Min(impact+exploit, 10))
	}
	return base
}

var (
	cvssAV     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC     = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI     = map[string]float64{"N": 0.85, "R": 0.62}
	cvssImpact = map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
)

// cvssPR depends on scope: a changed scope raises the privilege weights for Low/High.
func cvssPR(v string, scopeChanged bool) float64 {
	switch v {
	case "N":
		return 0.85
	case "L":
		if scopeChanged {
			return 0.68
		}
		return 0.62
	case "H":
		if scopeChanged {
			return 0.5
		}
		return 0.27
	}
	return -1
}

// roundUp implements the CVSS v3.1 "roundup" to one decimal place.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
