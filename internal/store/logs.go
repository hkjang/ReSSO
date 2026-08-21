package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type SystemLog struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Level      string          `json:"level"`
	Component  string          `json:"component"`
	Message    string          `json:"message"`
	TraceID    string          `json:"trace_id"`
	Attributes json.RawMessage `json:"attributes"`
}

func (s *Store) WriteSystemLog(ctx context.Context, level, component, message, traceID string, attributes map[string]any) error {
	if attributes == nil {
		attributes = map[string]any{}
	}
	encoded, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO system_logs(level,component,message,trace_id,attributes)
        VALUES($1,$2,$3,$4,$5)`, level, component, message, traceID, encoded)
	return err
}

// SystemLogEntry is one buffered log record awaiting persistence.
type SystemLogEntry struct {
	OccurredAt time.Time
	Level      string
	Component  string
	Message    string
	TraceID    string
	Attributes map[string]any
}

// WriteSystemLogs persists a batch in a single round trip. Every HTTP request
// emits a log line, so writing them one statement at a time made the log
// mirror the busiest writer in the database.
func (s *Store) WriteSystemLogs(ctx context.Context, entries []SystemLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(entries))
	for _, entry := range entries {
		attributes := entry.Attributes
		if attributes == nil {
			attributes = map[string]any{}
		}
		encoded, err := json.Marshal(attributes)
		if err != nil {
			// One unencodable record must not discard the whole batch.
			encoded = []byte(`{"attributes_error":"could not be encoded"}`)
		}
		rows = append(rows, []any{entry.OccurredAt, entry.Level, entry.Component,
			entry.Message, entry.TraceID, encoded})
	}
	_, err := s.Pool.CopyFrom(ctx, pgx.Identifier{"system_logs"},
		[]string{"occurred_at", "level", "component", "message", "trace_id", "attributes"},
		pgx.CopyFromRows(rows))
	return err
}

func (s *Store) ListSystemLogs(ctx context.Context, level, query string, limit, offset int) ([]SystemLog, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,occurred_at,level,component,message,trace_id,attributes
        FROM system_logs WHERE ($1='' OR level=$1) AND ($2='' OR message ILIKE '%' || $2 || '%'
        OR component ILIKE '%' || $2 || '%' OR trace_id ILIKE '%' || $2 || '%')
        ORDER BY occurred_at DESC LIMIT $3 OFFSET $4`, level, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]SystemLog, 0)
	for rows.Next() {
		var row SystemLog
		if err := rows.Scan(&row.ID, &row.OccurredAt, &row.Level, &row.Component,
			&row.Message, &row.TraceID, &row.Attributes); err != nil {
			return nil, err
		}
		logs = append(logs, row)
	}
	return logs, rows.Err()
}

func (s *Store) PruneOperationalData(ctx context.Context) error {
	// Fixed retention is intentional: no additional environment configuration
	// is needed, while audit events remain available for one year.
	statements := []string{
		"UPDATE signing_keys SET status='RETIRED' WHERE status='PASSIVE' AND retire_at<now()",
		"DELETE FROM system_logs WHERE occurred_at < now() - interval '30 days'",
		"DELETE FROM audit_events WHERE occurred_at < now() - interval '365 days'",
		"DELETE FROM authorization_requests WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM authorization_codes WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM revoked_access_tokens WHERE expires_at < now()",
		"DELETE FROM login_rate_limits WHERE updated_at < now() - interval '1 day'",
		// Refresh tokens were only collected through the session cascade, so a
		// long-lived session accumulated every rotation it ever performed.
		"DELETE FROM refresh_tokens WHERE expires_at < now() - interval '7 days'",
		"DELETE FROM sso_sessions WHERE expires_at < now() - interval '30 days'",
	}
	for _, statement := range statements {
		if _, err := s.Pool.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
