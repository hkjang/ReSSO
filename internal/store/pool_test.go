package store

import "testing"

// pgx reads pool_max_conns and pool_min_conns from the connection string, and
// the pool sizes here used to overwrite whatever it had parsed. An operator who
// tuned the pool the way pgx documents got no error and no effect — a setting
// accepted and discarded.
func TestDSNPoolParametersAreRecognised(t *testing.T) {
	for _, recognised := range []struct {
		dsn       string
		parameter string
		want      bool
	}{
		{"postgres://u:p@h/db?sslmode=disable", "pool_max_conns", false},
		{"postgres://u:p@h/db?sslmode=disable&pool_max_conns=50", "pool_max_conns", true},
		{"postgres://u:p@h/db?pool_max_conns=50&sslmode=disable", "pool_max_conns", true},
		{"postgres://u:p@h/db?pool_min_conns=9", "pool_min_conns", true},
		{"postgres://u:p@h/db?pool_min_conns=9", "pool_max_conns", false},
		// The keyword form pgx also accepts.
		{"host=h user=u pool_max_conns=50", "pool_max_conns", true},
		{"host=h user=u", "pool_max_conns", false},
		// A different parameter that merely ends with the name must not count,
		// which is the reason this looks at what precedes the match.
		{"postgres://u:p@h/db?x_pool_max_conns=50", "pool_max_conns", false},
		{"postgres://u:p@h/db?application_name=pool_max_conns", "pool_max_conns", false},
	} {
		if got := dsnSpecifies(recognised.dsn, recognised.parameter); got != recognised.want {
			t.Errorf("dsnSpecifies(%q, %q) = %v, want %v",
				recognised.dsn, recognised.parameter, got, recognised.want)
		}
	}
}
