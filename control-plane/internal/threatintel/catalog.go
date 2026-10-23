package threatintel

import "aegisproxy/control-plane/internal/models"

// DefaultFeeds is the built-in feed catalog. Feeds with permissive licenses and moderate size are
// enabled by default; very large lists and lists with non-commercial licenses ship disabled so
// that enabling them is a conscious decision by InfoSec.
//
// Note: abuse.ch retired the unauthenticated URLhaus/ThreatFox/MalwareBazaar bulk exports
// (HTTP 410). Their data can still be added as a custom feed with an "Auth-Key" header, and
// the malware-filter project republishes the URLhaus domain set (CC0) which is used below.
func DefaultFeeds() []models.ThreatFeed {
	return []models.ThreatFeed{
		{
			ID: "urlhaus-filter-domains", Name: "URLhaus Malware Domains (malware-filter mirror)",
			Description: "Domains actively distributing malware, derived from abuse.ch URLhaus.",
			URL:         "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
			Format:      models.FeedFormatDomains, Category: "malware", License: "CC0-1.0",
			Enabled: true, Builtin: true, MatchSubdomains: false, RefreshMinutes: 120,
		},
		{
			ID: "feodo-ipblocklist", Name: "abuse.ch Feodo Tracker Botnet C2 IPs",
			Description: "Command-and-control servers of Dridex, Emotet, TrickBot, QakBot, BazarLoader and others.",
			URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Format:      models.FeedFormatIPs, Category: "botnet_c2", License: "CC0-1.0",
			Enabled: true, Builtin: true, RefreshMinutes: 60,
		},
		{
			ID: "sslbl-ipblocklist", Name: "abuse.ch SSLBL Botnet C2 IPs",
			Description: "IPs associated with malicious SSL certificates used by botnet C2 servers.",
			URL:         "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
			Format:      models.FeedFormatIPs, Category: "botnet_c2", License: "CC0-1.0",
			Enabled: true, Builtin: true, RefreshMinutes: 60,
		},
		{
			ID: "spamhaus-drop", Name: "Spamhaus DROP (Don't Route Or Peer)",
			Description: "Hijacked netblocks controlled by cybercriminals; no legitimate traffic should go there.",
			URL:         "https://www.spamhaus.org/drop/drop.txt",
			Format:      models.FeedFormatIPs, Category: "hijacked_network", License: "Spamhaus DROP terms (free)",
			Enabled: true, Builtin: true, RefreshMinutes: 720,
		},
		{
			ID: "et-compromised-ips", Name: "Emerging Threats Compromised IPs",
			Description: "Known compromised hosts observed attacking or serving malware (Proofpoint ET Open).",
			URL:         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Format:      models.FeedFormatIPs, Category: "compromised_host", License: "ET Open (BSD)",
			Enabled: true, Builtin: true, RefreshMinutes: 360,
		},
		{
			ID: "blocklistproject-ransomware", Name: "Block List Project: Ransomware",
			Description: "Domains associated with ransomware distribution and payment portals.",
			URL:         "https://blocklistproject.github.io/Lists/ransomware.txt",
			Format:      models.FeedFormatHosts, Category: "ransomware", License: "Unlicense",
			Enabled: true, Builtin: true, MatchSubdomains: true, RefreshMinutes: 1440,
		},
		{
			ID: "phishing-filter-domains", Name: "Phishing Domains (malware-filter, OpenPhish/PhishTank)",
			Description: "Active phishing domains. Upstream sources have their own terms of use; review before enabling commercially.",
			URL:         "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
			Format:      models.FeedFormatDomains, Category: "phishing", License: "CC0-1.0 (upstream terms apply)",
			Enabled: false, Builtin: true, RefreshMinutes: 120,
		},
		{
			ID: "certpl-phishing", Name: "CERT Polska Phishing Domains",
			Description: "Phishing domains curated by CERT.PL (domain + subdomains).",
			URL:         "https://hole.cert.pl/domains/v2/domains.txt",
			Format:      models.FeedFormatDomains, Category: "phishing", License: "CERT.PL terms",
			Enabled: false, Builtin: true, MatchSubdomains: true, RefreshMinutes: 360,
		},
		{
			ID: "phishing-army", Name: "Phishing Army Blocklist",
			Description: "Community-aggregated phishing domains.",
			URL:         "https://phishing.army/download/phishing_army_blocklist.txt",
			Format:      models.FeedFormatDomains, Category: "phishing", License: "CC BY-NC 4.0 (non-commercial)",
			Enabled: false, Builtin: true, RefreshMinutes: 360,
		},
		{
			ID: "hagezi-tif", Name: "HaGeZi Threat Intelligence Feeds (large)",
			Description: "Very comprehensive malware/phishing/scam/C2 domain aggregation (several million domains, high memory use).",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
			Format:      models.FeedFormatDomains, Category: "threat_intel", License: "GPL-3.0",
			Enabled: false, Builtin: true, MatchSubdomains: true, RefreshMinutes: 720,
		},
		{
			ID: "stevenblack-unified", Name: "StevenBlack Unified Hosts (ads + malware)",
			Description: "Ad, tracking and malware hosts. Usually too broad for server egress; enable deliberately.",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			Format:      models.FeedFormatHosts, Category: "adware_tracking", License: "MIT",
			Enabled: false, Builtin: true, RefreshMinutes: 1440,
		},
	}
}
