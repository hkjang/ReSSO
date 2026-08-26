package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestFailureLimiterBlocksAfterMaxAndClearsAfterWindow(t *testing.T) {
	limiter := NewFailureLimiter(3, time.Minute, 16)
	current := time.Unix(1_700_000_000, 0)
	limiter.now = func() time.Time { return current }

	for attempt := range 3 {
		if allowed, _ := limiter.Allowed("client"); !allowed {
			t.Fatalf("attempt %d was blocked before reaching the maximum", attempt)
		}
		limiter.Fail("client")
	}
	allowed, retryAfter := limiter.Allowed("client")
	if allowed {
		t.Fatal("limiter did not block after the maximum number of failures")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("unexpected retry-after %s", retryAfter)
	}
	if allowed, _ := limiter.Allowed("other"); !allowed {
		t.Fatal("an unrelated key must not be blocked")
	}

	current = current.Add(time.Minute)
	if allowed, _ := limiter.Allowed("client"); !allowed {
		t.Fatal("limiter did not clear the window after it expired")
	}
}

func TestFailureLimiterResetClearsKey(t *testing.T) {
	limiter := NewFailureLimiter(1, time.Minute, 16)
	limiter.Fail("client")
	if allowed, _ := limiter.Allowed("client"); allowed {
		t.Fatal("limiter should block after reaching the maximum")
	}
	limiter.Reset("client")
	if allowed, _ := limiter.Allowed("client"); !allowed {
		t.Fatal("reset did not clear the key")
	}
}

func TestFailureLimiterKeepsTrackedKeysBounded(t *testing.T) {
	limiter := NewFailureLimiter(1, time.Hour, 8)
	for index := range 200 {
		limiter.Fail(string(rune('a'+index%26)) + string(rune('a'+index/26)))
	}
	if len(limiter.windows) > 8 {
		t.Fatalf("limiter tracked %d keys, expected at most 8", len(limiter.windows))
	}
}

func TestFailureLimiterDisabledWhenMaxIsNotPositive(t *testing.T) {
	limiter := NewFailureLimiter(0, time.Minute, 8)
	limiter.Fail("client")
	if allowed, _ := limiter.Allowed("client"); !allowed {
		t.Fatal("a limiter with a non-positive maximum must allow every attempt")
	}
}

// The client bucket's key is the client_id the request carried, so the caller
// chooses it. That made the bound this limiter exists for removable: guess a
// secret until the key blocks, then send one request each under fresh
// identifiers until the map is full and the blocked window - by then the
// oldest one there is - is dropped, and carry on guessing. Sixteen requests
// undid a block that three failures had set.
//
// Evicting the fewest failures first ties the price of displacing a block to
// the same number that set it. It is not immunity and this checks the bound
// rather than claiming one: paid cycling still displaces, at capacity x max
// failed attempts, every one of which is also counted against the caller's
// address.
func TestBlockedKeyIsNotDisplacedByCyclingIdentifiers(t *testing.T) {
	const capacity = 8
	limiter := NewFailureLimiter(3, 5*time.Minute, capacity)
	base := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	step := 0
	limiter.now = func() time.Time { return base.Add(time.Duration(step) * time.Second) }

	// The key that matters is blocked first, so it is also the oldest.
	for i := 0; i < 3; i++ {
		limiter.Fail("realm|victim-client")
	}
	if allowed, _ := limiter.Allowed("realm|victim-client"); allowed {
		t.Fatal("the victim key is not blocked, so the probe below proves nothing")
	}

	// Then the caller cycles identifiers of its own choosing. Nothing stops it:
	// the client bucket's key is whatever client_id the request carried.
	for i := 0; i < capacity*2; i++ {
		step++
		limiter.Fail(fmt.Sprintf("realm|junk-%d", i))
	}

	if allowed, _ := limiter.Allowed("realm|victim-client"); allowed {
		t.Errorf("%d requests under identifiers of the caller's own choosing undid a block that %d "+
			"failures set, which is the bound this limiter exists for", capacity*2, 3)
	}

	// What it costs to displace it now.
	cost := 0
	for round := 0; round < 40; round++ {
		step++
		for i := 0; i < 3; i++ {
			limiter.Fail(fmt.Sprintf("realm|paid-%d", round))
			cost++
		}
		if ok, _ := limiter.Allowed("realm|victim-client"); ok {
			break
		}
	}
	// Stated rather than assumed: displacing it costs what the block cost, per
	// key, and the test says so if that ever becomes cheaper.
	if ok, _ := limiter.Allowed("realm|victim-client"); !ok {
		t.Errorf("the block was never displaced in %d rounds, so the cost below is not the real one", 40)
	}
	if cost < capacity*3 {
		t.Errorf("displacing a block took %d failed attempts, fewer than the %d that filling the map "+
			"with blocked keys should cost", cost, capacity*3)
	}
}
