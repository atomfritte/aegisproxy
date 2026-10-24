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
