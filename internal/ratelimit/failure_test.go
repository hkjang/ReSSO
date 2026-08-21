package ratelimit

import (
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
