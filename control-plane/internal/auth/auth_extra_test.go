package auth

import "testing"

func TestIsBroadHostPatternPublicSuffixes(t *testing.T) {
	for p, want := range map[string]bool{
		"*": true, "*.com": true, "*.co.uk": true, "*.github.io": true, "*.ngrok-free.app": true, "*.workers.dev": true,
		"*.blogspot.com": true, "*.example.com": false, "*.corp.example.co.uk": false, "pkgs.example.org": false,
		"myorg.github.io": false, "*.myorg.github.io": false,
	} {
		if got := IsBroadHostPattern(p); got != want {
			t.Errorf("IsBroadHostPattern(%q) = %v, want %v", p, got, want)
		}
	}
}
