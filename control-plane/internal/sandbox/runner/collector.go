package runner

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

// ColHub holds the currently-active Collector. The long-lived sinks read it on every event, so the orchestrator
// can swap in a fresh Collector between phases without rebinding the loopback ports. It is safe for concurrent
// use.
type ColHub struct {
	p atomic.Pointer[Collector]
}

// NewColHub returns a hub pointing at c.
func NewColHub(c *Collector) *ColHub {
	h := &ColHub{}
	h.p.Store(c)
	return h
}

// Set swaps in a new collector for the next phase.
func (h *ColHub) Set(c *Collector) { h.p.Store(c) }

// C returns the active collector.
func (h *ColHub) C() *Collector { return h.p.Load() }

// capture is one piece of text observed by a sink, tagged with where it came from, for canary scanning.
type capture struct {
	where string // http | dns | tcp
	text  string
}

// Collector gathers everything the DNS resolver and the HTTP(S)/TCP sinks observe during one phase. It is safe
// for concurrent use by all the sink goroutines.
type Collector struct {
	mu    sync.Mutex
	start time.Time

	dns      map[string]*sandbox.DNSQuery // key: name|type
	dnsOrder []string
	http     []sandbox.HTTPRequest
	tcp      []sandbox.Connection

	hostByIP map[string]string // 127.10.x.y -> hostname last handed out
	ipByHost map[string]string
	nextIP   uint32 // offset into 127.10.0.0/16

	captures []capture
	dropped  int

	maxHTTP, maxTCP, maxDNS, maxCaptures int
}

// NewCollector starts a collector whose relative timestamps are measured from start.
func NewCollector(start time.Time) *Collector {
	return &Collector{
		start:       start,
		dns:         map[string]*sandbox.DNSQuery{},
		hostByIP:    map[string]string{},
		ipByHost:    map[string]string{},
		maxHTTP:     1000,
		maxTCP:      1000,
		maxDNS:      2000,
		maxCaptures: 4000,
	}
}

func (c *Collector) relMs() int64 { return time.Since(c.start).Milliseconds() }

// AssignIP returns a stable, unique 127.10.x.y address for a hostname (::1 handling is the caller's for AAAA).
func (c *Collector) AssignIP(host string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ip, ok := c.ipByHost[host]; ok {
		return ip
	}
	// 127.10.(hi).(lo), starting at 127.10.0.1 and skipping .0 / .255 low octets.
	c.nextIP++
	hi := byte((c.nextIP >> 8) & 0xff)
	lo := byte(c.nextIP & 0xff)
	if lo == 0 || lo == 255 {
		c.nextIP++
		lo = byte(c.nextIP & 0xff)
	}
	ip := fmt.Sprintf("127.10.%d.%d", hi, lo)
	c.ipByHost[host] = ip
	c.hostByIP[ip] = host
	return ip
}

// Resolve maps a sandbox address back to the hostname it was handed out for (for Connection records).
func (c *Collector) Resolve(ip string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostByIP[ip]
}

// RecordDNS records a resolver query.
func (c *Collector) RecordDNS(name, qtype string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := name + "|" + qtype
	if q, ok := c.dns[key]; ok {
		q.Count++
	} else if len(c.dns) < c.maxDNS {
		c.dns[key] = &sandbox.DNSQuery{Name: clampStr(name, 256), Type: qtype, Count: 1, FirstMs: c.relMs()}
		c.dnsOrder = append(c.dnsOrder, key)
	} else {
		c.dropped++
	}
	c.addCaptureLocked("dns", name)
}

// RecordHTTP records a web request a sink received.
func (c *Collector) RecordHTTP(r sandbox.HTTPRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.http) < c.maxHTTP {
		c.http = append(c.http, r)
	} else {
		c.dropped++
	}
	capText := r.Method + " " + r.URL
	for k, v := range r.Headers {
		capText += " " + k + ": " + v
	}
	capText += " " + r.BodyPreview
	c.addCaptureLocked("http", capText)
}

// RecordTCP records a generic TCP-sink hit (address is the sandbox address the client reached).
func (c *Collector) RecordTCP(addr string, port int, preview string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn := sandbox.Connection{
		TimeMs: c.relMs(), Protocol: "tcp", Address: addr, Port: port,
		Hostname: c.hostByIP[addr], Result: "sink", Preview: clampStr(printableStr(preview), 2048),
	}
	if len(c.tcp) < c.maxTCP {
		c.tcp = append(c.tcp, conn)
	} else {
		c.dropped++
	}
	c.addCaptureLocked("tcp", preview)
}

func (c *Collector) addCaptureLocked(where, text string) {
	if text == "" {
		return
	}
	if len(c.captures) < c.maxCaptures {
		c.captures = append(c.captures, capture{where: where, text: text})
	}
}

// snapshotCaptures returns a copy of the captures for canary scanning.
func (c *Collector) snapshotCaptures() []capture {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capture, len(c.captures))
	copy(out, c.captures)
	return out
}

// Network assembles the collected DNS/HTTP into a sandbox.Network (TCP sink hits are merged by the caller with
// the strace-derived connections).
func (c *Collector) Network() sandbox.Network {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := sandbox.Network{Dropped: c.dropped}
	for _, key := range c.dnsOrder {
		n.DNS = append(n.DNS, *c.dns[key])
	}
	n.HTTP = append(n.HTTP, c.http...)
	return n
}

// tcpConns returns the sink-captured TCP connections (with payload previews).
func (c *Collector) tcpConns() []sandbox.Connection {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]sandbox.Connection, len(c.tcp))
	copy(out, c.tcp)
	return out
}

// mergeConnections folds sink-captured TCP connections (which carry payload previews) into the strace-derived
// connection list: a sink hit to an address/port already seen from a connect() just adds its preview; otherwise
// it is appended.
func mergeConnections(straceConns, sinkConns []sandbox.Connection, limit int) ([]sandbox.Connection, int) {
	out := append([]sandbox.Connection(nil), straceConns...)
	dropped := 0
	for _, s := range sinkConns {
		matched := false
		for i := range out {
			if out[i].Address == s.Address && out[i].Port == s.Port {
				if out[i].Preview == "" && s.Preview != "" {
					out[i].Preview = s.Preview
				}
				if out[i].Hostname == "" {
					out[i].Hostname = s.Hostname
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if len(out) < limit {
			out = append(out, s)
		} else {
			dropped++
		}
	}
	// Stable order by time then address.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TimeMs != out[j].TimeMs {
			return out[i].TimeMs < out[j].TimeMs
		}
		return out[i].Address < out[j].Address
	})
	return out, dropped
}

// printableStr is printable() for a string argument.
func printableStr(s string) string { return printable([]byte(s), len(s)+1) }
