// Package ratelimit provides an in-memory failure counter for hot paths that
// must not pay for a database round trip on every request.
//
// The login endpoints deliberately use the shared PostgreSQL buckets in
// internal/store so that a limit survives restarts and applies across
// instances. The OIDC token, introspection and revocation endpoints cannot
// afford that: they are called by every relying party on every token refresh,
// and an advisory-locked read-modify-write per call would dominate their cost.
// Counting only *failed* client authentications keeps the successful path free
// while still bounding credential guessing against a single instance.
package ratelimit

import (
	"sync"
	"time"
)

type window struct {
	startedAt time.Time
	failures  int
}

// FailureLimiter counts failures per key inside a fixed window. The tracked
// key count is bounded so an attacker cycling client identifiers or source
// addresses cannot grow the map without limit.
type FailureLimiter struct {
	mu       sync.Mutex
	windows  map[string]window
	max      int
	duration time.Duration
	capacity int
	now      func() time.Time
}

// NewFailureLimiter blocks a key once it records max failures within the given
// window. A non-positive max disables limiting.
func NewFailureLimiter(max int, duration time.Duration, capacity int) *FailureLimiter {
	if capacity < 1 {
		capacity = 1
	}
	return &FailureLimiter{windows: make(map[string]window), max: max, duration: duration,
		capacity: capacity, now: time.Now}
}

func (l *FailureLimiter) enabled() bool {
	return l != nil && l.max > 0 && l.duration > 0
}

// Allowed reports whether a key may attempt authentication, and how long the
// caller should wait when it may not.
func (l *FailureLimiter) Allowed(key string) (bool, time.Duration) {
	if !l.enabled() {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	current, ok := l.windows[key]
	if !ok {
		return true, 0
	}
	now := l.now()
	expiresAt := current.startedAt.Add(l.duration)
	if !expiresAt.After(now) {
		delete(l.windows, key)
		return true, 0
	}
	if current.failures < l.max {
		return true, 0
	}
	return false, expiresAt.Sub(now)
}

// Fail records one failed attempt for a key.
func (l *FailureLimiter) Fail(key string) {
	if !l.enabled() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	current, ok := l.windows[key]
	if !ok || !current.startedAt.Add(l.duration).After(now) {
		l.evictLocked(now)
		l.windows[key] = window{startedAt: now, failures: 1}
		return
	}
	// Saturate instead of incrementing forever so the counter cannot overflow
	// and so a blocked key always clears exactly one window after its start.
	if current.failures < l.max {
		current.failures++
	}
	l.windows[key] = current
}

// Reset clears a key after a successful authentication.
func (l *FailureLimiter) Reset(key string) {
	if !l.enabled() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.windows, key)
}

// evictLocked keeps the map bounded. Expired windows go first; if the map is
// still full, the oldest window is dropped. Dropping the oldest is safe because
// it is the closest to expiring anyway.
func (l *FailureLimiter) evictLocked(now time.Time) {
	if len(l.windows) < l.capacity {
		return
	}
	for key, value := range l.windows {
		if !value.startedAt.Add(l.duration).After(now) {
			delete(l.windows, key)
		}
	}
	for len(l.windows) >= l.capacity {
		var oldestKey string
		var oldest time.Time
		for key, value := range l.windows {
			if oldest.IsZero() || value.startedAt.Before(oldest) {
				oldestKey, oldest = key, value.startedAt
			}
		}
		delete(l.windows, oldestKey)
	}
}
