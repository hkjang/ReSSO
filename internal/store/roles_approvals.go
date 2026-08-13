package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/domain"
)

type Role struct {
	ID          uuid.UUID `json:"id"`
	RealmID     uuid.UUID `json:"realm_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Store) ListRoles(ctx context.Context, realmID uuid.UUID) ([]Role, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,realm_id,name,description,created_at,updated_at
        FROM roles WHERE realm_id=$1 ORDER BY name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.RealmID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *Store) CreateRole(ctx context.Context, realmID uuid.UUID, name, description string) (Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Role{}, errors.New("role name is required")
	}
	now := time.Now().UTC()
	role := Role{ID: uuid.New(), RealmID: realmID, Name: name, Description: strings.TrimSpace(description), CreatedAt: now, UpdatedAt: now}
	_, err := s.Pool.Exec(ctx, `INSERT INTO roles(id,realm_id,name,description,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,$5)`, role.ID, role.RealmID, role.Name, role.Description, now)
	return role, err
}

func (s *Store) ApprovalEnabled(ctx context.Context, realmID uuid.UUID) (bool, error) {
	var enabled bool
	err := s.Pool.QueryRow(ctx, "SELECT approval_enabled FROM realms WHERE id=$1", realmID).Scan(&enabled)
	return enabled, err
}

type roleAssignmentPayload struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

func (s *Store) CreateRoleApprovalRequest(ctx context.Context, requester domain.User, roleID uuid.UUID, reason string) (domain.ApprovalRequest, error) {
	enabled, err := s.ApprovalEnabled(ctx, requester.RealmID)
	if err != nil {
		return domain.ApprovalRequest{}, err
	}
	if !enabled {
		return domain.ApprovalRequest{}, ErrNotFound
	}
	var roleRealm uuid.UUID
	if err := s.Pool.QueryRow(ctx, "SELECT realm_id FROM roles WHERE id=$1", roleID).Scan(&roleRealm); err != nil || roleRealm != requester.RealmID {
		return domain.ApprovalRequest{}, errors.New("requested role is not in the user's realm")
	}
	payload, _ := json.Marshal(roleAssignmentPayload{UserID: requester.ID, RoleID: roleID})
	request := domain.ApprovalRequest{ID: uuid.New(), RealmID: requester.RealmID, RequesterID: requester.ID,
		ReviewerID: requester.ManagerID, Kind: "ROLE_ASSIGNMENT", Payload: payload, Reason: strings.TrimSpace(reason),
		Status: "PENDING", CreatedAt: time.Now().UTC()}
	_, err = s.Pool.Exec(ctx, `INSERT INTO approval_requests(id,realm_id,requester_id,reviewer_id,kind,payload,
        reason,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, request.ID, request.RealmID,
		request.RequesterID, request.ReviewerID, request.Kind, request.Payload, request.Reason, request.Status, request.CreatedAt)
	return request, err
}

func scanApproval(row pgx.Row) (domain.ApprovalRequest, error) {
	var request domain.ApprovalRequest
	err := row.Scan(&request.ID, &request.RealmID, &request.RequesterID, &request.ReviewerID,
		&request.Kind, &request.Payload, &request.Reason, &request.Status, &request.DecisionNote,
		&request.CreatedAt, &request.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ApprovalRequest{}, ErrNotFound
	}
	return request, err
}

func (s *Store) ListApprovalRequests(ctx context.Context, realmID *uuid.UUID, requesterID, reviewerID *uuid.UUID) ([]domain.ApprovalRequest, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,realm_id,requester_id,reviewer_id,kind,payload,reason,status,
        decision_note,created_at,decided_at FROM approval_requests
        WHERE ($1::uuid IS NULL OR realm_id=$1) AND ($2::uuid IS NULL OR requester_id=$2)
        AND ($3::uuid IS NULL OR reviewer_id=$3) ORDER BY created_at DESC LIMIT 500`, realmID, requesterID, reviewerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := make([]domain.ApprovalRequest, 0)
	for rows.Next() {
		request, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *Store) DecideApprovalRequest(ctx context.Context, requestID, reviewerID uuid.UUID, platformAdmin bool, approve bool, note string) (domain.ApprovalRequest, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.ApprovalRequest{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	request, err := scanApproval(tx.QueryRow(ctx, `SELECT id,realm_id,requester_id,reviewer_id,kind,payload,reason,
        status,decision_note,created_at,decided_at FROM approval_requests WHERE id=$1 FOR UPDATE`, requestID))
	if err != nil {
		return domain.ApprovalRequest{}, err
	}
	if request.Status != "PENDING" {
		return domain.ApprovalRequest{}, ErrConflict
	}
	if !platformAdmin && (request.ReviewerID == nil || *request.ReviewerID != reviewerID) {
		return domain.ApprovalRequest{}, errors.New("reviewer is not authorized for this request")
	}
	status := "REJECTED"
	if approve {
		status = "APPROVED"
		if request.Kind == "ROLE_ASSIGNMENT" {
			var payload roleAssignmentPayload
			if err := json.Unmarshal(request.Payload, &payload); err != nil {
				return domain.ApprovalRequest{}, fmt.Errorf("decode approval payload: %w", err)
			}
			command, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
                SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM users u JOIN roles r ON r.realm_id=u.realm_id
                WHERE u.id=$1 AND r.id=$2 AND u.realm_id=$3) ON CONFLICT DO NOTHING`, payload.UserID, payload.RoleID, request.RealmID)
			if err != nil || command.RowsAffected() == 0 {
				return domain.ApprovalRequest{}, errors.New("approval target is no longer valid")
			}
		}
	}
	decidedAt := time.Now().UTC()
	_, err = tx.Exec(ctx, `UPDATE approval_requests SET status=$2,decision_note=$3,decided_at=$4 WHERE id=$1`,
		request.ID, status, strings.TrimSpace(note), decidedAt)
	if err != nil {
		return domain.ApprovalRequest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ApprovalRequest{}, err
	}
	request.Status, request.DecisionNote, request.DecidedAt = status, strings.TrimSpace(note), &decidedAt
	return request, nil
}
