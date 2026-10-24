package threatintel

import (
	"net/netip"
	"strings"
	"testing"

	"aegisproxy/control-plane/internal/models"
)

func TestParseFormats(t *testing.T) {
	hosts := "# comment\n0.0.0.0 evil.example\n127.0.0.1 localhost\n0.0.0.0 bad.example # trailing\n::1 ip6-localhost\n"
	e, _ := Parse(models.FeedFormatHosts, strings.NewReader(hosts))
	if len(e.Domains) != 2 || e.Domains[0] != "evil.example" || e.Domains[1] != "bad.example" {
		t.Fatalf("hosts parse: %v", e.Domains)
	}
	domains := "||ads.example^\n*.wild.example\nPlain.Example.\n1.2.3.4\nnot a domain at all\n"
	e, _ = Parse(models.FeedFormatDomains, strings.NewReader(domains))
	if len(e.Domains) != 3 || len(e.IPs) != 1 {
		t.Fatalf("domains parse: %v ips=%v", e.Domains, e.IPs)
	}
	ips := "; Spamhaus\n1.10.16.0/20 ; SBL1\n203.0.113.7\n0.0.0.0/0\n2001:db8::/32\n"
	e, _ = Parse(models.FeedFormatIPs, strings.NewReader(ips))
	if len(e.Prefixes) != 2 || len(e.IPs) != 1 {
		t.Fatalf("ips parse: prefixes=%v ips=%v (0.0.0.0/0 must be refused)", e.Prefixes, e.IPs)
	}
	urls := "https://Evil.Example:443/payload.sh?x=1#frag\nftp://nope.example/\n"
	e, _ = Parse(models.FeedFormatURLs, strings.NewReader(urls))
	if len(e.URLs) != 1 || e.URLs[0] != "https://evil.example/payload.sh?x=1" {
		t.Fatalf("urls parse: %v", e.URLs)
	}
	hashes := strings.Repeat("A", 64) + "\nzz\n"
	e, _ = Parse(models.FeedFormatSHA256, strings.NewReader(hashes))
	if len(e.Hashes) != 1 || e.Hashes[0] != strings.Repeat("a", 64) {
		t.Fatalf("sha256 parse: %v", e.Hashes)
	}
}

func buildTestSnapshot() *Snapshot {
	b := newBuilder()
	exact := b.addSource(Source{ID: "f1", Name: "Feed One", Category: "malware"})
	b.add(exact, &Entries{Domains: []string{"evil.example"}, URLs: []string{"https://cdn.example/bad.exe"}}, false)
	sub := b.addSource(Source{ID: "f2", Name: "Feed Two", Category: "phishing"})
	b.add(sub, &Entries{Domains: []string{"phish.example", "fp.example"}}, true)
	nets := b.addSource(Source{ID: "f3", Name: "DROP", Category: "hijacked_network"})
	b.add(nets, &Entries{
		IPs:      []netip.Addr{netip.MustParseAddr("198.51.100.9")},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Hashes:   []string{strings.Repeat("b", 64)},
	}, false)
	b.exc = []models.ThreatException{{Type: "domain", Value: "fp.example"}}
	return b.build([]string{"test"})
}

func TestSnapshotMatching(t *testing.T) {
	s := buildTestSnapshot()
	cases := []struct {
		host string
		want bool
	}{
		{"evil.example", true},
		{"sub.evil.example", false}, // exact-only feed
		{"phish.example", true},
		{"login.phish.example", true}, // subdomain feed
		{"fp.example", false},         // exception
		{"x.fp.example", false},       // exception covers subdomains
		{"203.0.113.77", true},        // CIDR
		{"198.51.100.9", true},
		{"[::ffff:198.51.100.9]", true},
		{"good.example", false},
		{"example", false},
	}
	for _, c := range cases {
		if _, got := s.MatchHost(c.host); got != c.want {
			t.Errorf("MatchHost(%q)=%v want %v", c.host, got, c.want)
		}
	}
	if m, ok := s.MatchURL("HTTPS://cdn.example/bad.exe"); !ok || m.Category != "malware" {
		t.Errorf("url match failed: %+v %v", m, ok)
	}
	if _, ok := s.MatchHash(strings.Repeat("B", 64)); !ok {
		t.Error("hash match failed")
	}
	if got := s.Lookup("https://login.phish.example/x"); len(got) != 1 {
		t.Errorf("lookup: %+v", got)
	}
	st := s.Status()
	if st.Domains != 3 || st.CIDRs != 1 || st.IPs != 1 || st.Hashes != 1 {
		t.Errorf("status counts: %+v", st)
	}
	if _, err := s.ExportGzip(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFeedURL(t *testing.T) {
	for _, bad := range []string{"http://x.example/list", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://168.63.129.16/machine", "https://[fd00:ec2::254]/latest", "https://100.100.100.200/latest", "https://user:pw@x.example/", "https://intranet.local/x"} {
		if ValidateFeedURL(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := ValidateFeedURL("https://feodotracker.abuse.ch/downloads/ipblocklist.txt"); err != nil {
		t.Error(err)
	}
}

func TestDefaultCatalogValid(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range DefaultFeeds() {
		if seen[f.ID] {
			t.Errorf("duplicate feed id %s", f.ID)
		}
		seen[f.ID] = true
		if err := ValidateFeedURL(f.URL); err != nil {
			t.Errorf("feed %s: %v", f.ID, err)
		}
		if f.Enabled && strings.Contains(strings.ToLower(f.License), "non-commercial") {
			t.Errorf("feed %s has a non-commercial license but is enabled by default", f.ID)
		}
	}
}
