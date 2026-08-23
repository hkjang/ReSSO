package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

type RateLimitDecision struct {
	Allowed           bool
	Attempts          int
	RetryAfterSeconds int
}

// ConsumeLoginRateLimit counts every request in a shared PostgreSQL bucket.
// It is intended for coarse IP throttling before authentication work begins.
func (s *Store) ConsumeLoginRateLimit(ctx context.Context, bucket string, maximum int, window time.Duration) (RateLimitDecision, error) {
	decision, err := s.recordLoginRateLimit(ctx, bucket, maximum, window)
	if err != nil {
		return RateLimitDecision{}, err
	}
	decision.Allowed = decision.Attempts <= maximum
	return decision, nil
}

// CheckLoginRateLimit checks a failure bucket without consuming an attempt.
// Expired and missing buckets are allowed.
func (s *Store) CheckLoginRateLimit(ctx context.Context, bucket string, maximum int, window time.Duration) (RateLimitDecision, error) {
	decision, err := s.mutateLoginRateLimit(ctx, bucket, maximum, window, 0)
	if err != nil {
		return RateLimitDecision{}, err
	}
	decision.Allowed = decision.Attempts < maximum
	return decision, nil
}

// RecordLoginFailure increments an account failure bucket. Reaching the
// configured maximum limits the current response and subsequent attempts.
func (s *Store) RecordLoginFailure(ctx context.Context, bucket string, maximum int, window time.Duration) (RateLimitDecision, error) {
	decision, err := s.recordLoginRateLimit(ctx, bucket, maximum, window)
	if err != nil {
		return RateLimitDecision{}, err
	}
	decision.Allowed = decision.Attempts < maximum
	return decision, nil
}

func (s *Store) ResetLoginRateLimit(ctx context.Context, bucket string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rateLimitLockID(bucket)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM login_rate_limits WHERE bucket_hash=ANY($1::bytea[])`, s.Sealer.Digests(bucket)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) recordLoginRateLimit(ctx context.Context, bucket string, maximum int, window time.Duration) (RateLimitDecision, error) {
	return s.mutateLoginRateLimit(ctx, bucket, maximum, window, 1)
}

// mutateLoginRateLimit merges every digest-key representation of a logical
// bucket under a key-independent advisory lock. This preserves counters while
// old-active and new-active instances overlap during a digest-key rotation.
func (s *Store) mutateLoginRateLimit(ctx context.Context, bucket string, maximum int, window time.Duration, increment int) (RateLimitDecision, error) {
	seconds, ok := rateLimitSeconds(maximum, window)
	if !ok {
		// A limiter that cannot work must not answer that everything is fine.
		// The three callers derived Allowed from a zero decision and reached
		// three different conclusions from the same unusable settings — and a
		// window of zero, which turns the limiter off outright, came back
		// allowed from all three. These values come from literals in the
		// handlers rather than from configuration, so this is a mistake in the
		// code, and failing the request is how it gets found instead of
		// running with the throttle silently absent.
		return RateLimitDecision{}, fmt.Errorf(
			"%w: login rate limit needs a maximum of at least 1 and a positive window, got %d and %s",
			ErrInvalidInput, maximum, window)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RateLimitDecision{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rateLimitLockID(bucket)); err != nil {
		return RateLimitDecision{}, err
	}

	rows, err := tx.Query(ctx, `SELECT window_started_at,attempts
		FROM login_rate_limits
		WHERE bucket_hash=ANY($1::bytea[])
			AND window_started_at > now()-make_interval(secs => $2)
		FOR UPDATE`, s.Sealer.Digests(bucket), seconds)
	if err != nil {
		return RateLimitDecision{}, err
	}
	var windowStarted time.Time
	attempts := 0
	for rows.Next() {
		var started time.Time
		var count int
		if err := rows.Scan(&started, &count); err != nil {
			rows.Close()
			return RateLimitDecision{}, err
		}
		attempts += count
		// Use the newest surviving window when split representations are
		// consolidated. This may retain older attempts slightly longer during a
		// rotation, but never expires newer attempts early and opens a bypass.
		if windowStarted.IsZero() || started.After(windowStarted) {
			windowStarted = started
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RateLimitDecision{}, err
	}
	rows.Close()

	if _, err := tx.Exec(ctx, `DELETE FROM login_rate_limits WHERE bucket_hash=ANY($1::bytea[])`, s.Sealer.Digests(bucket)); err != nil {
		return RateLimitDecision{}, err
	}
	attempts += increment
	if attempts == 0 {
		if err := tx.Commit(ctx); err != nil {
			return RateLimitDecision{}, err
		}
		return RateLimitDecision{Allowed: true}, nil
	}
	// Keep the row bounded while retaining both caller semantics and the first
	// limited transition: account buckets block at maximum; IP buckets first
	// block at maximum+1 and settle at maximum+2 to avoid repeated audit events.
	capAt := maximum
	maxInt := int(^uint(0) >> 1)
	if maximum <= maxInt-2 {
		capAt += 2
	}
	if attempts > capAt {
		attempts = capAt
	}

	var decision RateLimitDecision
	var started any
	if !windowStarted.IsZero() {
		started = windowStarted
	}
	err = tx.QueryRow(ctx, `INSERT INTO login_rate_limits(bucket_hash,window_started_at,attempts,updated_at)
		VALUES($1,COALESCE($2::timestamptz,now()),$3,now())
		RETURNING attempts,
		GREATEST(1,ceil(extract(epoch FROM
			(window_started_at+make_interval(secs => $4)-now()))))::integer`,
		s.Sealer.Digest(bucket), started, attempts, seconds).Scan(&decision.Attempts, &decision.RetryAfterSeconds)
	if err != nil {
		return RateLimitDecision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RateLimitDecision{}, err
	}
	return decision, nil
}

func rateLimitLockID(bucket string) int64 {
	digest := sha256.Sum256([]byte("ReSSO login rate-limit lock\x00" + bucket))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func rateLimitSeconds(maximum int, window time.Duration) (int, bool) {
	if maximum < 1 || window <= 0 {
		return 0, false
	}
	return int(math.Ceil(window.Seconds())), true
}
