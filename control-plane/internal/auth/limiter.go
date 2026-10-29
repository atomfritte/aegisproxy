package auth

import (
	"sync"
	"time"
)

// LoginLimiter throttles credential guessing per account and per source with exponential lockout
// (threshold failures -> 1 min, doubling up to 15 min). Attempts are reserved before the (slow)
// credential check: failures plus attempts still in flight count toward the threshold, so a burst of
// parallel requests cannot run more checks than one sequential attacker could.
type LoginLimiter struct {
	mu        sync.Mutex
	entries   map[string]*loginAttempt
	threshold int
	maxLock   time.Duration
	lastSweep time.Time
}

type loginAttempt struct {
	failures    int
	inFlight    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// Key is one throttling dimension of an attempt. Factor multiplies the account threshold (0 = 1);
// MaxLock caps its lockout (0 = the limiter's maximum). A full limiter skips a Shed key it does not
// track yet (another key of the attempt bounds it, e.g. the per-proxy ceiling) and refuses attempts
// that need any other new key.
type Key struct {
	Name    string
	Factor  int
	MaxLock time.Duration
	Shed    bool
}

// Threshold factors of the keys used by the API.
const (
	FactorAccount = 1  // one account
	FactorSource  = 4  // one client address: several operators can share one egress IP
	FactorProxy   = 10 // every client behind one reverse proxy that is not trusted (ceiling against spraying)
)

// busyRetry is returned while the attempts in flight already reach a threshold (nothing is locked yet).
const busyRetry = time.Second

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		entries:   make(map[string]*loginAttempt),
		threshold: 5,
		maxLock:   15 * time.Minute,
	}
}

// Attempt is a reservation made by Begin; exactly one of Fail, Success or Release must follow.
type Attempt struct {
	l    *LoginLimiter
	keys []Key
	done bool
}

// Begin reserves one attempt on every key. It returns the time to wait instead when a key is locked
// out, or when its failures plus the attempts in flight already reach its threshold.
func (l *LoginLimiter) Begin(keys ...Key) (*Attempt, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now)
	full := len(l.entries) >= maxLimiterEntries
	var wait time.Duration
	for _, k := range keys {
		if k.Name == "" {
			continue
		}
		e, ok := l.entries[k.Name]
		if !ok {
			if full && !k.Shed {
				// Every entry is a lockout or an attempt in flight: refuse rather than forget one.
				wait = max(wait, busyRetry)
			}
			continue
		}
		// After a lockout expired one attempt at a time may probe again; its failure locks longer.
		allowance := max(l.thresholdOf(k)-e.failures, 1)
		switch {
		case now.Before(e.lockedUntil):
			wait = max(wait, e.lockedUntil.Sub(now))
		case e.inFlight >= allowance:
			wait = max(wait, busyRetry)
		}
	}
	if wait > 0 {
		return nil, wait
	}
	a := &Attempt{l: l}
	for _, k := range keys {
		if k.Name == "" {
			continue
		}
		if _, ok := l.entries[k.Name]; !ok && full && k.Shed {
			continue
		}
		e := l.entryLocked(k.Name, now)
		e.inFlight++
		a.keys = append(a.keys, k)
	}
	return a, 0
}

// Check returns how long the keys are still locked out (0 = allowed) without reserving an attempt.
func (l *LoginLimiter) Check(names ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range names {
		if e, ok := l.entries[k]; ok && now.Before(e.lockedUntil) {
			wait = max(wait, e.lockedUntil.Sub(now))
		}
	}
	return wait
}

// Fail records a failed attempt on every key of the reservation.
func (a *Attempt) Fail() {
	if a == nil || a.done {
		return
	}
	a.done = true
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range a.keys {
		e := l.entryLocked(k.Name, now)
		e.inFlight = max(e.inFlight-1, 0)
		e.failures++
		if t := l.thresholdOf(k); e.failures >= t {
			lock := time.Minute << min(e.failures-t, 4)
			limit := l.maxLock
			if k.MaxLock > 0 && k.MaxLock < limit {
				limit = k.MaxLock
			}
			e.lockedUntil = now.Add(min(lock, limit))
		}
	}
}

// Success ends the reservation and resets the named keys (e.g. the account after a correct password).
func (a *Attempt) Success(reset ...string) {
	if a == nil || a.done {
		return
	}
	a.done = true
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseLocked(a.keys)
	for _, name := range reset {
		if e, ok := l.entries[name]; ok {
			e.failures, e.lockedUntil = 0, time.Time{}
			if e.inFlight == 0 {
				delete(l.entries, name)
			}
		}
	}
}

// Release ends the reservation without counting it (e.g. the request was refused for another reason).
func (a *Attempt) Release() {
	if a == nil || a.done {
		return
	}
	a.done = true
	a.l.mu.Lock()
	a.l.releaseLocked(a.keys)
	a.l.mu.Unlock()
}

func (l *LoginLimiter) releaseLocked(keys []Key) {
	for _, k := range keys {
		if e, ok := l.entries[k.Name]; ok {
			e.inFlight = max(e.inFlight-1, 0)
		}
	}
}

func (l *LoginLimiter) thresholdOf(k Key) int {
	return l.threshold * max(k.Factor, 1)
}

func (l *LoginLimiter) entryLocked(name string, now time.Time) *loginAttempt {
	e, ok := l.entries[name]
	if !ok {
		e = &loginAttempt{}
		l.entries[name] = e
	}
	e.lastSeen = now
	return e
}

const maxLimiterEntries = 100_000

// sweepLocked forgets idle entries, at most once per minute (once per second while the limiter is
// full), so a flood of new keys never makes every attempt scan the whole map.
func (l *LoginLimiter) sweepLocked(now time.Time) {
	if len(l.entries) <= 1024 {
		return
	}
	interval := time.Minute
	if len(l.entries) >= maxLimiterEntries {
		interval = time.Second
	}
	if now.Sub(l.lastSweep) < interval {
		return
	}
	l.lastSweep = now
	idle := time.Hour
	if len(l.entries) >= maxLimiterEntries/2 {
		idle = 5 * time.Minute
	}
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > idle && now.After(e.lockedUntil) && e.inFlight == 0 {
			delete(l.entries, k)
		}
	}
	// Hard bound: drop entries that are neither locked out nor in use (oldest first is not needed for safety).
	for k, e := range l.entries {
		if len(l.entries) < maxLimiterEntries {
			break
		}
		if now.After(e.lockedUntil) && e.inFlight == 0 {
			delete(l.entries, k)
		}
	}
}
