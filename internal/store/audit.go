package store

import (
	"context"
	"encoding/json"
	"strings"
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

// AuditFilter narrows an audit search. Every field is optional. Investigating
// an incident previously meant scrolling a fixed page of the newest events,
// with no way to select an event type, an outcome or an actor, and no way to
// reach anything older.
type AuditFilter struct {
	RealmID   *uuid.UUID
	EventType string
	Result    string
	Actor     string
	TraceID   string
	// Ascending reconstructs an incident from its start; the default newest
	// first answers "what just happened".
	Ascending bool
	Limit     int
	Offset    int
}

// AuditPage carries a page of events plus the total that matched, so the
// console can page through them and say how many there are.
type AuditPage struct {
	Items []AuditRow `json:"items"`
	Total int        `json:"total"`
}

// order is a fixed keyword chosen by a boolean, never request text.
func (f AuditFilter) order() string {
	if f.Ascending {
		return "ASC"
	}
	return "DESC"
}

func (f AuditFilter) normalized() AuditFilter {
	f.EventType = strings.TrimSpace(f.EventType)
	f.Result = strings.TrimSpace(f.Result)
	f.Actor = strings.TrimSpace(f.Actor)
	f.TraceID = strings.TrimSpace(f.TraceID)
	if f.Limit < 1 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return f
}

const auditWhere = `WHERE ($1::uuid IS NULL OR realm_id=$1)
        AND ($2='' OR event_type=$2)
        AND ($3='' OR result=$3)
        AND ($4='' OR actor_name ILIKE '%' || $4 || '%')
        AND ($5='' OR trace_id=$5)`

func (s *Store) ListAudit(ctx context.Context, filter AuditFilter) (AuditPage, error) {
	filter = filter.normalized()
	page := AuditPage{Items: make([]AuditRow, 0)}
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events "+auditWhere,
		filter.RealmID, filter.EventType, filter.Result, filter.Actor, filter.TraceID).Scan(&page.Total); err != nil {
		return AuditPage{}, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,occurred_at,realm_id,actor_name,event_type,result,target_type,
        target_id,ip_address,trace_id,detail FROM audit_events `+auditWhere+`
        ORDER BY occurred_at `+filter.order()+`, id `+filter.order()+` LIMIT $6 OFFSET $7`,
		filter.RealmID, filter.EventType, filter.Result, filter.Actor, filter.TraceID, filter.Limit, filter.Offset)
	if err != nil {
		return AuditPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var row AuditRow
		if err := rows.Scan(&row.ID, &row.OccurredAt, &row.RealmID, &row.ActorName, &row.EventType,
			&row.Result, &row.TargetType, &row.TargetID, &row.IPAddress, &row.TraceID, &row.Detail); err != nil {
			return AuditPage{}, err
		}
		page.Items = append(page.Items, row)
	}
	return page, rows.Err()
}

// AuditEventTypes lists the event types actually present, so the console can
// offer a filter that matches the data instead of a hardcoded guess.
func (s *Store) AuditEventTypes(ctx context.Context, realmID *uuid.UUID) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT event_type FROM audit_events
        WHERE ($1::uuid IS NULL OR realm_id=$1) ORDER BY event_type`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	types := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		types = append(types, value)
	}
	return types, rows.Err()
}
