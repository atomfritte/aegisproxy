package api

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// proxyHostSet trusts the current addresses of DNS names as reverse proxies, e.g. the headless Service
// of the console pods in Kubernetes, whose pod IPs change on every rollout. Lookups run in the
// background; requests never wait for DNS. When a lookup fails, the host's last answer stays valid for
// maxStale and is dropped afterwards, so an address that was recycled for another pod is not trusted
// indefinitely.
type proxyHostSet struct {
	hosts    []string
	refresh  time.Duration
	maxStale time.Duration
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	log      *slog.Logger
	metrics  *Metrics

	mu         sync.Mutex
	state      map[string]*proxyHostState
	addrs      map[netip.Addr]bool
	updated    time.Time
	refreshing bool
}

type proxyHostState struct {
	addrs  []netip.Addr
	lastOK time.Time // zero: never resolved
}

func newProxyHostSet(hosts []string, log *slog.Logger, metrics *Metrics) *proxyHostSet {
	if len(hosts) == 0 {
		return nil
	}
	p := &proxyHostSet{hosts: hosts, refresh: 30 * time.Second, maxStale: defaultMaxStale, log: log, metrics: metrics,
		addrs: map[netip.Addr]bool{},
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", absoluteName(host))
		}}
	p.resolve() // prime the set before the first request
	return p
}

// absoluteName makes a qualified name absolute (trailing dot) so the resolver never tries the DNS
// search list first: "console.aegis.svc.cluster.local" has fewer dots than the Kubernetes ndots:5, so
// it would otherwise be looked up below the node's search domains, where somebody else may publish it.
// Single-label names ("console" in Docker Compose) are left to the search list by design.
func absoluteName(host string) string {
	if strings.Contains(host, ".") && !strings.HasSuffix(host, ".") {
		return host + "."
	}
	return host
}

// contains reports whether a is a current address of one of the hosts and schedules a refresh when
// the answer is older than the refresh interval.
func (p *proxyHostSet) contains(a netip.Addr) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.updated) > p.refresh && !p.refreshing {
		p.refreshing = true
		go p.resolve()
	}
	return p.addrs[a.Unmap()]
}

func (p *proxyHostSet) resolve() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	answers := make(map[string]answer, len(p.hosts))
	for _, h := range p.hosts {
		addrs, err := p.lookup(ctx, h)
		answers[h] = answer{addrs, err}
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == nil {
		p.state = map[string]*proxyHostState{}
	}
	maxStale := p.maxStale
	if maxStale <= 0 {
		maxStale = defaultMaxStale
	}
	failed := false
	next := map[netip.Addr]bool{}
	for _, h := range p.hosts {
		st := p.state[h]
		if st == nil {
			st = &proxyHostState{}
			p.state[h] = st
		}
		if ans := answers[h]; ans.err == nil {
			st.addrs, st.lastOK = nil, now
			for _, a := range ans.addrs {
				st.addrs = append(st.addrs, a.Unmap())
			}
		} else {
			failed = true
			switch {
			case len(st.addrs) > 0 && now.Sub(st.lastOK) > maxStale:
				if p.log != nil {
					p.log.Warn("trusted proxy host lookups keep failing; no longer trusting its previous addresses", "host", h,
						"last_success", st.lastOK, "error", ans.err)
				}
				if p.metrics != nil {
					p.metrics.Inc("aegis_trusted_proxy_host_expired_total", "host", h)
				}
				st.addrs = nil
			case p.log != nil:
				p.log.Warn("trusted proxy host lookup failed; keeping its previous addresses for now", "host", h,
					"addresses", len(st.addrs), "error", ans.err)
			}
			if p.metrics != nil {
				p.metrics.Inc("aegis_trusted_proxy_host_lookup_failures_total", "host", h)
			}
		}
		for _, a := range st.addrs {
			next[a] = true
		}
	}
	p.addrs = next
	p.updated, p.refreshing = now, false
	if failed && p.refresh > retryAfterFailure {
		// retry soon, e.g. while the proxy container/pod is still starting
		p.updated = p.updated.Add(retryAfterFailure - p.refresh)
	}
}

// proxyHostStatus is the per-host view for /metrics.
type proxyHostStatus struct {
	host  string
	addrs int
	age   float64 // seconds since the last successful lookup (-1 = never)
}

func (p *proxyHostSet) hostStatus() []proxyHostStatus {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]proxyHostStatus, 0, len(p.hosts))
	for _, h := range p.hosts {
		st := proxyHostStatus{host: h, age: -1}
		if hs := p.state[h]; hs != nil {
			st.addrs = len(hs.addrs)
			if !hs.lastOK.IsZero() {
				st.age = time.Since(hs.lastOK).Seconds()
			}
		}
		out = append(out, st)
	}
	return out
}

const (
	retryAfterFailure = 5 * time.Second
	defaultMaxStale   = 5 * time.Minute // 10 refresh intervals
)
