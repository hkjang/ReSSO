package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// EnsureSearchIndexes creates the optional trigram indexes that make the
// administration console's user and audit-actor searches index scans instead of
// sequential ones. Both search with a leading wildcard, which no B-tree index
// can serve, so a Realm with many federated users — or an audit trail holding a
// year of events — otherwise pays a full table scan for every keystroke, twice,
// because the page is also counted.
//
// This is deliberately not a migration:
//
//   - It depends on the pg_trgm extension, which only a database owner can
//     install. Installing it from a migration would place it in whatever schema
//     happens to be first on search_path, which is not ReSSO's to decide.
//   - Recording it as an applied migration would mean a deployment that enables
//     pg_trgm later never gets the indexes. Running it at startup instead makes
//     enabling the extension take effect on the next restart.
//
// A database without the extension keeps the previous behaviour. Failures are
// reported to the caller for logging and never prevent startup.
func (s *Store) EnsureSearchIndexes(ctx context.Context) (bool, error) {
	var extensionSchema string
	err := s.Pool.QueryRow(ctx, `SELECT n.nspname FROM pg_extension e
		JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_trgm'`).Scan(&extensionSchema)
	if errors.Is(err, pgx.ErrNoRows) {
		// The extension is simply not installed, which is a supported setup.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up the pg_trgm extension: %w", err)
	}
	// The operator class is schema-qualified from the catalog rather than
	// resolved through search_path, so an extension installed outside the
	// application's search_path still works.
	// Each index is attempted and the failures reported together. Returning at
	// the first one left the rest uncreated while the caller logged a single
	// line, so a search by e-mail or display name went on scanning the whole
	// table with nothing to say which of the three was missing.
	indexes := []struct{ column, statement string }{
		{"username", `CREATE INDEX IF NOT EXISTS idx_users_username_trgm ON users USING gin (lower(username) %s.gin_trgm_ops)`},
		{"email", `CREATE INDEX IF NOT EXISTS idx_users_email_trgm ON users USING gin (lower(email) %s.gin_trgm_ops)`},
		{"display name", `CREATE INDEX IF NOT EXISTS idx_users_display_name_trgm ON users USING gin (lower(display_name) %s.gin_trgm_ops)`},
		// Narrowing the audit trail to one account is the first thing anyone
		// does with it during an incident, and it is the same leading-wildcard
		// shape. Without this it is a sequential scan of a table that keeps a
		// year of every login: measured on 400k rows, finding an actor with
		// five entries scanned all 400k in 34ms, and 0.1ms with the index.
		{"audit actor", `CREATE INDEX IF NOT EXISTS idx_audit_actor_trgm ON audit_events USING gin (lower(actor_name) %s.gin_trgm_ops)`},
	}
	quoted := quoteIdentifier(extensionSchema)
	var failures []error
	for _, index := range indexes {
		if _, err := s.Pool.Exec(ctx, fmt.Sprintf(index.statement, quoted)); err != nil {
			failures = append(failures, fmt.Errorf("search index on %s: %w", index.column, err))
		}
	}
	if len(failures) > 0 {
		return false, errors.Join(failures...)
	}
	return true, nil
}

func quoteIdentifier(value string) string {
	escaped := ""
	for _, character := range value {
		if character == '"' {
			escaped += `""`
			continue
		}
		escaped += string(character)
	}
	return `"` + escaped + `"`
}
