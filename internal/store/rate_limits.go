package store

import (
	"context"
	"time"
)

// AllowLoginAttempt uses PostgreSQL as the shared rate-limit state so limits
// remain effective when multiple ReSSO instances serve the same Realm.
func (s *Store) AllowLoginAttempt(ctx context.Context, bucket string, maximum int, window time.Duration) (bool, error) {
	if maximum < 1 || window <= 0 {
		return false, nil
	}
	var attempts int
	err := s.Pool.QueryRow(ctx, `INSERT INTO login_rate_limits(bucket_hash,window_started_at,attempts,updated_at)
		VALUES($1,now(),1,now())
		ON CONFLICT(bucket_hash) DO UPDATE SET
		attempts=CASE WHEN login_rate_limits.window_started_at <= now()-make_interval(secs => $2)
			THEN 1 ELSE login_rate_limits.attempts+1 END,
		window_started_at=CASE WHEN login_rate_limits.window_started_at <= now()-make_interval(secs => $2)
			THEN now() ELSE login_rate_limits.window_started_at END,
		updated_at=now()
		RETURNING attempts`, s.Sealer.Digest(bucket), int(window.Seconds())).Scan(&attempts)
	return attempts <= maximum, err
}
