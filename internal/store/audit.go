package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	RealmID    *uuid.UUID
	ActorID    *uuid.UUID
	ActorName  string
	EventType  string
	Result     string
	TargetType string
	TargetID   string
	IPAddress  string
	UserAgent  string
	TraceID    string
	Detail     map[string]any
}

func (s *Store) WriteAudit(ctx context.Context, event AuditEvent) error {
	detail := event.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO audit_events(realm_id,actor_id,actor_name,event_type,result,
        target_type,target_id,ip_address,user_agent,trace_id,detail)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, event.RealmID, event.ActorID, event.ActorName,
		event.EventType, event.Result, event.TargetType, event.TargetID, event.IPAddress, event.UserAgent,
		event.TraceID, encoded)
	return err
}

type AuditRow struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	RealmID    *uuid.UUID      `json:"realm_id,omitempty"`
	ActorName  string          `json:"actor_name"`
	EventType  string          `json:"event_type"`
	Result     string          `json:"result"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	IPAddress  string          `json:"ip_address"`
	TraceID    string          `json:"trace_id"`
	Detail     json.RawMessage `json:"detail"`
}

func (s *Store) ListAudit(ctx context.Context, realmID *uuid.UUID, limit, offset int) ([]AuditRow, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,occurred_at,realm_id,actor_name,event_type,result,target_type,
        target_id,ip_address,trace_id,detail FROM audit_events
        WHERE ($1::uuid IS NULL OR realm_id=$1) ORDER BY occurred_at DESC LIMIT $2 OFFSET $3`, realmID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AuditRow, 0)
	for rows.Next() {
		var row AuditRow
		if err := rows.Scan(&row.ID, &row.OccurredAt, &row.RealmID, &row.ActorName, &row.EventType,
			&row.Result, &row.TargetType, &row.TargetID, &row.IPAddress, &row.TraceID, &row.Detail); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
