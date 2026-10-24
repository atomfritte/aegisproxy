package api

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// proxyHostSet trusts the current addresses of DNS names as reverse proxies, e.g. the headless Service
// of the console pods in Kubernetes, whose pod IPs change on every rollout. Lookups run in the
// background; requests never wait for DNS and the last successful answer stays valid on errors.
type proxyHostSet struct {
	hosts   []string
	refresh time.Duration
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
	log     *slog.Logger

	mu         sync.Mutex
	addrs      map[netip.Addr]bool
	updated    time.Time
	refreshing bool
}

func newProxyHostSet(hosts []string, log *slog.Logger) *proxyHostSet {
	if len(hosts) == 0 {
		return nil
	}
	p := &proxyHostSet{hosts: hosts, refresh: 30 * time.Second, log: log, addrs: map[netip.Addr]bool{},
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}
	p.resolve() // prime the set before the first request
	return p
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
	next := map[netip.Addr]bool{}
	failed := false
	for _, h := range p.hosts {
		addrs, err := p.lookup(ctx, h)
		if err != nil {
			failed = true
			if p.log != nil {
				p.log.Warn("trusted proxy host lookup failed; keeping the previous addresses", "host", h, "error", err)
			}
			continue
		}
		for _, a := range addrs {
			next[a.Unmap()] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !failed || len(next) > 0 {
		p.addrs = next
	}
	p.updated, p.refreshing = time.Now(), false
	if failed && p.refresh > retryAfterFailure {
		// retry soon, e.g. while the proxy container/pod is still starting
		p.updated = p.updated.Add(retryAfterFailure - p.refresh)
	}
}

const retryAfterFailure = 5 * time.Second
