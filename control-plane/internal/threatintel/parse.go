// Package threatintel downloads, parses and compiles threat-intelligence blocklists
// (malicious domains, URLs, IPs/CIDRs and file hashes) into an immutable lookup snapshot.
package threatintel

import (
	"bufio"
	"io"
	"net/netip"
	"net/url"
	"strings"

	"aegisproxy/control-plane/internal/models"
)

// Entries is the parsed content of one feed or of the custom indicator list.
type Entries struct {
	Domains  []string
	URLs     []string
	IPs      []netip.Addr
	Prefixes []netip.Prefix
	Hashes   []string
}

func (e *Entries) Len() int {
	return len(e.Domains) + len(e.URLs) + len(e.IPs) + len(e.Prefixes) + len(e.Hashes)
}

const maxLineLen = 4096

// Parse reads a feed in the given format. Invalid lines are skipped silently: public lists
// routinely contain comments, headers and the odd malformed entry.
func Parse(format string, r io.Reader) (*Entries, error) {
	out := &Entries{}
	if format == formatTyped {
		return out, parseTyped(r, out)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) > maxLineLen {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == ';' || line[0] == '[' {
			continue
		}
		switch format {
		case models.FeedFormatHosts:
			parseHostsLine(line, out)
		case models.FeedFormatDomains:
			parseDomainLine(line, out)
		case models.FeedFormatURLs:
			if u, ok := NormalizeURL(firstField(line)); ok {
				out.URLs = append(out.URLs, u)
			}
		case models.FeedFormatIPs:
			addIPOrPrefix(firstField(stripComment(line)), out)
		case models.FeedFormatSHA256:
			if h, ok := NormalizeHash(firstField(line)); ok {
				out.Hashes = append(out.Hashes, h)
			}
		}
	}
	return out, sc.Err()
}

func stripComment(line string) string {
	for _, sep := range []string{";", "#"} {
		if i := strings.Index(line, sep); i >= 0 {
			line = line[:i]
		}
	}
	return strings.TrimSpace(line)
}

func firstField(line string) string {
	if f := strings.Fields(line); len(f) > 0 {
		return f[0]
	}
	return ""
}

var hostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

func parseHostsLine(line string, out *Entries) {
	fields := strings.Fields(stripComment(line))
	if len(fields) == 0 {
		return
	}
	start := 0
	if _, err := netip.ParseAddr(fields[0]); err == nil {
		start = 1
	}
	for _, f := range fields[start:] {
		if hostsSkip[strings.ToLower(f)] {
			continue
		}
		if d, ok := NormalizeDomain(f); ok {
			out.Domains = append(out.Domains, d)
		}
	}
}

func parseDomainLine(line string, out *Entries) {
	line = stripComment(line)
	if strings.Contains(line, " ") || strings.Contains(line, "\t") {
		parseHostsLine(line, out)
		return
	}
	// Adblock syntax: ||example.com^ (options after '$' are ignored)
	if i := strings.IndexByte(line, '$'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimSuffix(line, "^")
	line = strings.TrimPrefix(line, "*.")
	line = strings.TrimPrefix(line, ".")
	if a, err := netip.ParseAddr(line); err == nil {
		out.IPs = append(out.IPs, a.Unmap())
		return
	}
	if d, ok := NormalizeDomain(line); ok {
		out.Domains = append(out.Domains, d)
	}
}

func addIPOrPrefix(s string, out *Entries) {
	if s == "" {
		return
	}
	if strings.Contains(s, "/") {
		if p, err := netip.ParsePrefix(s); err == nil {
			p = p.Masked()
			if p.Bits() == p.Addr().BitLen() {
				out.IPs = append(out.IPs, p.Addr().Unmap())
			} else if p.Bits() >= 8 { // refuse absurdly broad prefixes (e.g. 0.0.0.0/0)
				out.Prefixes = append(out.Prefixes, p)
			}
		}
		return
	}
	if a, err := netip.ParseAddr(s); err == nil {
		out.IPs = append(out.IPs, a.Unmap())
	}
}

// NormalizeDomain lowercases and validates a hostname. It rejects IP literals, single-label
// names and anything with characters outside the LDH set (plus '_' which appears in the wild).
func NormalizeDomain(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return d, true
}

// NormalizeHash validates a SHA-256 hex digest.
func NormalizeHash(s string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(s))
	if len(h) != 64 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return h, true
}

// NormalizeURL canonicalizes an absolute http(s) URL for exact matching:
// lowercase scheme and host, default ports removed, empty path -> "/", fragment dropped.
// The data-plane implements the same function.
func NormalizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxLineLen {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	out := scheme + "://" + host + p
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, true
}
