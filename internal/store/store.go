// Package store is ReSSO's PostgreSQL data layer. It owns every query,
// migration and encrypted value, and performs no outbound network requests.
package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/password"
)

type Store struct {
	Pool              *pgxpool.Pool
	Sealer            *cryptoutil.Sealer
	dummyPasswordHash string
	signingKeys       sync.Map

	// OnSessionRevoked is optional and set once during startup.
	OnSessionRevoked SessionRevocationHook
}

func Open(ctx context.Context, dsn string, sealer *cryptoutil.Sealer) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	// Defaults, not overrides. pgx already reads pool_max_conns and
	// pool_min_conns from the connection string, and these lines used to
	// overwrite whatever it had parsed — so an operator who tuned the pool the
	// way pgx documents got no error and no effect. Twenty is enough for this
	// service, which holds no connection across the password hash or a
	// directory walk, but a large installation is entitled to say otherwise
	// and be listened to.
	if !dsnSpecifies(dsn, "pool_max_conns") {
		poolConfig.MaxConns = 20
	}
	if !dsnSpecifies(dsn, "pool_min_conns") {
		poolConfig.MinConns = 2
	}
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	dummyHash, err := password.Hash("ReSSO-invalid-credential-placeholder")
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize authentication timing guard: %w", err)
	}
	return &Store{Pool: pool, Sealer: sealer, dummyPasswordHash: dummyHash}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// dsnSpecifies reports whether the connection string carries the named pool
// parameter. pgx substitutes its own default when one is absent, and that
// default is indistinguishable from the same value written out, so the text is
// what has to be asked. Both syntaxes pgx accepts are covered: the URL form
// where parameters follow a ? or &, and the keyword form where they are
// separated by spaces.
func dsnSpecifies(dsn, parameter string) bool {
	for index := 0; ; {
		found := strings.Index(dsn[index:], parameter+"=")
		if found < 0 {
			return false
		}
		at := index + found
		if at == 0 || strings.ContainsRune("?& \t", rune(dsn[at-1])) {
			return true
		}
		index = at + len(parameter)
	}
}

// ClockSkew reports how far this process's clock has drifted from the
// database's, positive when this process is ahead, together with the round
// trip the reading cost — which bounds how precise the figure can be.
//
// They are two clocks, and every lifetime in the service is written against
// one and judged against the other: a session's expires_at is computed here
// and tested by the database, a lockout is computed by the database and tested
// here. A difference between them does not break anything outright, it shifts
// every one of those windows by its size, which is why it is the kind of fault
// that gets diagnosed as half a dozen unrelated oddities. ReSSO is built to run
// offline, where there is frequently no time source keeping the two in step, so
// nothing else was going to notice.
func (s *Store) ClockSkew(ctx context.Context) (skew, roundTrip time.Duration, err error) {
	before := time.Now().UTC()
	var databaseNow time.Time
	if err := s.Pool.QueryRow(ctx, "SELECT now()").Scan(&databaseNow); err != nil {
		return 0, 0, err
	}
	after := time.Now().UTC()
	roundTrip = after.Sub(before)
	// The reading is taken at some point during the round trip, so the midpoint
	// is the best estimate of when the database answered.
	return before.Add(roundTrip / 2).Sub(databaseNow), roundTrip, nil
}
