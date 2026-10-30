// Package coordinator drives the package firewall's asynchronous work: it resolves a request's
// dependency graph, assesses every version (advisories, signatures, provenance), queues sandbox
// analysis, applies the rules and cooldown, and either auto-approves or holds the request for review.
// It also runs the background re-audit and watch loops. It ties the store (state) to the packages
// service (registry, resolution, assessment); the store does not depend on this package, so there is
// no import cycle.
package coordinator

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"aegisproxy/control-plane/internal/models"
	"aegisproxy/control-plane/internal/packages"
	"aegisproxy/control-plane/internal/store"
)

// Coordinator orchestrates request resolution and analysis.
type Coordinator struct {
	store   *store.Store
	svc     *packages.Service
	reports *packages.ReportStore
	log     *slog.Logger

	wake   chan string // request IDs to (re)process; "" = scan for pending work
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	// Maintenance bookkeeping (accessed only from the single maintenance goroutine).
	lastReaudit time.Time
	lastWatch   time.Time
}

// New builds a coordinator.
func New(st *store.Store, svc *packages.Service, reports *packages.ReportStore, logger *slog.Logger) *Coordinator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Coordinator{
		store:   st,
		svc:     svc,
		reports: reports,
		log:     logger.With("component", "packages-coordinator"),
		wake:    make(chan string, 256),
		closed:  make(chan struct{}),
	}
}

// Start launches the background worker and the re-audit / watch loops.
func (c *Coordinator) Start() {
	c.wg.Add(1)
	go c.worker()
	c.wg.Add(1)
	go c.maintenance()
	// Resume any requests that were mid-flight at shutdown.
	c.Kick("")
}

// Close stops the coordinator.
func (c *Coordinator) Close() {
	c.once.Do(func() { close(c.closed) })
	c.wg.Wait()
}

// Kick asks the worker to process a request (or, with "", to scan for pending work).
func (c *Coordinator) Kick(reqID string) {
	select {
	case c.wake <- reqID:
	default:
	}
}

func (c *Coordinator) worker() {
	defer c.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case id := <-c.wake:
			if id != "" {
				c.process(id)
			} else {
				c.scanPending()
			}
		case <-ticker.C:
			c.scanPending()
		}
	}
}

// scanPending processes requests still resolving/analyzing (crash recovery, re-evaluation after jobs).
func (c *Coordinator) scanPending() {
	for _, r := range c.store.PackageRequests("", "") {
		select {
		case <-c.closed:
			return
		default:
		}
		if r.Status == models.PackageReqResolving || r.Status == models.PackageReqAnalyzing {
			c.process(r.ID)
		}
	}
}

// ctx returns a per-operation context bounded by the coordinator lifetime.
func (c *Coordinator) ctx(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
