package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// EnsureSearchIndexes creates the optional trigram indexes that make the
// administration console's user search an index scan instead of a sequential
// one. The console searches with a leading wildcard, which no B-tree index can
// serve, so a Realm with many federated users otherwise pays a full table scan
// for every keystroke — twice, because the page is also counted.
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
	statements := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_username_trgm ON users USING gin (lower(username) %s.gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email_trgm ON users USING gin (lower(email) %s.gin_trgm_ops)`,
		`CREATE INDEX IF NOT EXISTS idx_users_display_name_trgm ON users USING gin (lower(display_name) %s.gin_trgm_ops)`,
	}
	quoted := quoteIdentifier(extensionSchema)
	for _, statement := range statements {
		if _, err := s.Pool.Exec(ctx, fmt.Sprintf(statement, quoted)); err != nil {
			return false, fmt.Errorf("create trigram search index: %w", err)
		}
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
