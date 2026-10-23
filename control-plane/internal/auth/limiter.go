package auth

import (
	"sync"
	"time"
)

// LoginLimiter throttles credential guessing per account and per source IP with
// exponential lockout (5 failures -> 1 min, doubling up to 15 min).
type LoginLimiter struct {
	mu        sync.Mutex
	entries   map[string]*loginAttempt
	threshold int
	maxLock   time.Duration
}

type loginAttempt struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		entries:   make(map[string]*loginAttempt),
		threshold: 5,
		maxLock:   15 * time.Minute,
	}
}

// Check returns how long the key is still locked out (0 = allowed).
func (l *LoginLimiter) Check(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		if e, ok := l.entries[k]; ok && now.Before(e.lockedUntil) {
			if d := e.lockedUntil.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait
}

// Fail records a failed attempt. ipKeys use a 4x higher threshold than account keys since many
// operators can share one egress IP.
func (l *LoginLimiter) Fail(accountKey, ipKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.gcLocked(now)
	l.failLocked(accountKey, l.threshold, now)
	l.failLocked(ipKey, l.threshold*4, now)
}

func (l *LoginLimiter) failLocked(key string, threshold int, now time.Time) {
	if key == "" {
		return
	}
	e, ok := l.entries[key]
	if !ok {
		e = &loginAttempt{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = now
	if e.failures >= threshold {
		lock := time.Minute << min(e.failures-threshold, 4)
		if lock > l.maxLock {
			lock = l.maxLock
		}
		e.lockedUntil = now.Add(lock)
	}
}

func (l *LoginLimiter) Success(accountKey string) {
	l.mu.Lock()
	delete(l.entries, accountKey)
	l.mu.Unlock()
}

const maxLimiterEntries = 50000

func (l *LoginLimiter) gcLocked(now time.Time) {
	if len(l.entries) < 4096 {
		return
	}
	idle := time.Hour
	if len(l.entries) >= maxLimiterEntries/2 {
		idle = 5 * time.Minute
	}
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > idle && now.After(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
	// Hard bound: drop entries that are not locked out (oldest first is not needed for safety).
	for k, e := range l.entries {
		if len(l.entries) < maxLimiterEntries {
			break
		}
		if now.After(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}
