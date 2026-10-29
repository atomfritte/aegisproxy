package auth

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// Attempts are reserved before the credential check: a burst of parallel attempts gets no more checks
// than the threshold allows (previously each lockout window let one burst of any size through).
func TestLoginLimiterReservesParallelAttempts(t *testing.T) {
	l := NewLoginLimiter()
	keys := []Key{{Name: "u:alice"}, {Name: "ip:198.51.100.7", Factor: FactorSource}}
	var (
		mu       sync.Mutex
		admitted []*Attempt
		refused  int
		wg       sync.WaitGroup
	)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, wait := l.Begin(keys...)
			mu.Lock()
			defer mu.Unlock()
			if wait > 0 {
				refused++
				return
			}
			admitted = append(admitted, a)
		}()
	}
	wg.Wait()
	if len(admitted) != 5 || refused != 55 {
		t.Fatalf("60 parallel attempts: %d admitted, %d refused; want 5 admitted (threshold)", len(admitted), refused)
	}
	for _, a := range admitted {
		a.Fail()
	}
	if l.Check("u:alice") <= 0 {
		t.Fatal("the account must be locked after the admitted attempts failed")
	}
}

// A released reservation (the request was refused for another reason) is not counted; resolving an
// attempt twice is harmless.
func TestLoginLimiterReleaseAndIdempotence(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 20; i++ {
		a, wait := l.Begin(Key{Name: "scim-ip:203.0.113.5", Factor: FactorSource})
		if wait > 0 {
			t.Fatalf("released attempts must not count (attempt %d refused)", i)
		}
		a.Release()
		a.Fail()
		a.Release()
	}
	if e := l.entries["scim-ip:203.0.113.5"]; e == nil || e.failures != 0 || e.inFlight != 0 {
		t.Fatalf("entry after released attempts: %+v", e)
	}
}

// Each key has its own threshold, and MaxLock caps a key's lockout (break-glass accounts).
func TestLoginLimiterFactorsAndMaxLock(t *testing.T) {
	l := NewLoginLimiter()
	proxy := Key{Name: "proxy:10.0.0.9", Factor: FactorProxy}
	for i := 0; i < 5*FactorProxy; i++ {
		// a different claimed client each time: only the per-proxy ceiling accumulates
		a, wait := l.Begin(Key{Name: "ip:10.0.0.9|" + strconv.Itoa(i), Factor: FactorSource}, proxy)
		if wait > 0 {
			t.Fatalf("proxy ceiling reached early at failure %d", i)
		}
		a.Fail()
	}
	if _, wait := l.Begin(Key{Name: "ip:10.0.0.9|fresh", Factor: FactorSource}, proxy); wait <= 0 {
		t.Fatal("the per-proxy ceiling must stop spraying with invented client addresses")
	}

	bg := Key{Name: "u:breakglass", Factor: 2, MaxLock: time.Minute}
	for i := 0; i < 10+6; i++ { // threshold 10, then the lock would double up to 15 min
		if e := l.entries["u:breakglass"]; e != nil {
			e.lockedUntil = time.Time{} // let every attempt through to grow the lock
		}
		a, wait := l.Begin(bg)
		if wait > 0 {
			t.Fatalf("attempt %d refused", i)
		}
		a.Fail()
	}
	if wait := l.Check("u:breakglass"); wait <= 0 || wait > time.Minute {
		t.Fatalf("break-glass lockout %s, want at most 1 minute", wait)
	}
}

// R3-3: break-glass sign-ins behind an untrusted proxy depend on its ceiling, so sustained failures from
// behind that proxy must not grow its lockout beyond the break-glass maximum of one minute.
func TestLoginLimiterProxyCeilingLockIsCapped(t *testing.T) {
	l := NewLoginLimiter()
	proxy := Key{Name: "proxy:10.0.0.9", Factor: FactorProxy, MaxLock: time.Minute}
	for i := 0; i < 5*FactorProxy+10; i++ { // one failure after every expired lock
		if e := l.entries[proxy.Name]; e != nil {
			e.lockedUntil = time.Time{}
		}
		a, wait := l.Begin(Key{Name: "ip:10.0.0.9|" + strconv.Itoa(i), Factor: FactorSource, Shed: true}, proxy)
		if wait > 0 {
			t.Fatalf("attempt %d refused", i)
		}
		a.Fail()
	}
	if wait := l.Check(proxy.Name); wait <= 0 || wait > time.Minute {
		t.Fatalf("per-proxy lockout %s, want at most 1 minute", wait)
	}
}

// R3-3: idle entries are swept at most once per minute (no scan of the whole map on every attempt), and
// a limiter full of lockouts sheds new Shed keys and refuses attempts that need any other new key.
func TestLoginLimiterMemoryIsBounded(t *testing.T) {
	l := NewLoginLimiter()
	now := time.Now()
	for i := 0; i < 2000; i++ {
		l.entries["ip:idle"+strconv.Itoa(i)] = &loginAttempt{lastSeen: now.Add(-2 * time.Hour)}
	}
	l.lastSweep = now
	a, _ := l.Begin(Key{Name: "u:alice"})
	a.Release()
	if len(l.entries) != 2001 {
		t.Fatalf("swept within a minute of the last sweep: %d entries", len(l.entries))
	}
	l.lastSweep = now.Add(-2 * time.Minute)
	a, _ = l.Begin(Key{Name: "u:alice"})
	a.Release()
	if len(l.entries) != 1 {
		t.Fatalf("%d entries after the sweep, want only u:alice", len(l.entries))
	}

	for i := len(l.entries); i < maxLimiterEntries; i++ {
		l.entries["ip:locked"+strconv.Itoa(i)] = &loginAttempt{failures: 20, lockedUntil: now.Add(time.Hour), lastSeen: now}
	}
	proxy := Key{Name: "proxy:10.0.0.9", Factor: FactorProxy}
	l.entries[proxy.Name] = &loginAttempt{lastSeen: now}
	l.lastSweep = time.Now() // the next sweep (once per second while full) would drop the idle proxy entry
	a, wait := l.Begin(Key{Name: "ip:10.0.0.9|198.51.100.1", Factor: FactorSource, Shed: true}, proxy)
	if wait > 0 {
		t.Fatalf("a full limiter refused an attempt it can bound with the proxy ceiling: %s", wait)
	}
	if _, tracked := l.entries["ip:10.0.0.9|198.51.100.1"]; tracked || len(a.keys) != 1 {
		t.Fatalf("a full limiter tracked a new claimed client: keys %+v", a.keys)
	}
	a.Fail()
	if _, wait := l.Begin(Key{Name: "u:new-account"}); wait != busyRetry {
		t.Fatalf("a full limiter forgot a lockout or skipped a new account key: wait %s", wait)
	}
	if len(l.entries) > maxLimiterEntries+1 {
		t.Fatalf("%d entries, want at most %d", len(l.entries), maxLimiterEntries+1)
	}
}
