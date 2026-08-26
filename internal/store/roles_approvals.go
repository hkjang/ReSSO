package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	// AssignedUsers lets the console say what deleting a role would take away
	// and from how many people, instead of asking for a blind confirmation.
	AssignedUsers int `json:"assigned_users"`
	// Builtin marks the Realm roles that cannot be deleted.
	Builtin bool `json:"builtin"`
}

func (s *Store) ListRoles(ctx context.Context, realmID uuid.UUID) ([]Role, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.id,r.realm_id,r.name,r.description,r.created_at,r.updated_at,
        (SELECT count(*) FROM user_roles ur WHERE ur.role_id=r.id),
        r.name = ANY($2::text[])
        FROM roles r WHERE r.realm_id=$1 ORDER BY r.name`, realmID, builtinRoleNames)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.RealmID, &role.Name, &role.Description, &role.CreatedAt,
			&role.UpdatedAt, &role.AssignedUsers, &role.Builtin); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *Store) CreateRole(ctx context.Context, realmID uuid.UUID, name, description string) (Role, error) {
	name, err := displayableName("Role 이름", name)
	if err != nil {
		return Role{}, err
	}
	if name == "" {
		return Role{}, invalidf("Role 이름이 필요합니다.")
	}
	now := time.Now().UTC()
	role := Role{ID: uuid.New(), RealmID: realmID, Name: name, Description: strings.TrimSpace(description), CreatedAt: now, UpdatedAt: now}
	_, err = s.Pool.Exec(ctx, `INSERT INTO roles(id,realm_id,name,description,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,$5)`, role.ID, role.RealmID, role.Name, role.Description, now)
	if conflict, taken := conflictFromUnique(err); taken {
		return Role{}, conflict
	}
	return role, err
}

func (s *Store) UpdateRole(ctx context.Context, realmID, roleID uuid.UUID, description string) (Role, error) {
	command, err := s.Pool.Exec(ctx, `UPDATE roles SET description=$3,updated_at=now()
		WHERE id=$1 AND realm_id=$2`, roleID, realmID, strings.TrimSpace(description))
	if err != nil {
		return Role{}, err
	}
	if command.RowsAffected() == 0 {
		return Role{}, ErrNotFound
	}
	var role Role
	err = s.Pool.QueryRow(ctx, `SELECT id,realm_id,name,description,created_at,updated_at
		FROM roles WHERE id=$1`, roleID).Scan(&role.ID, &role.RealmID, &role.Name, &role.Description,
		&role.CreatedAt, &role.UpdatedAt)
	return role, err
}

// builtinRoleNames are created with every Realm and cannot be removed.
var builtinRoleNames = []string{"user", "realm-admin", "offline_access"}

// RoleRemoval is what a deletion took away. The audit event can only name the
// row by an id that resolves to nothing once it is gone, so what it was and
// who lost it has to be carried out of here.
type RoleRemoval struct {
	Name            string
	UsersUnassigned int64
}

// DeleteRole removes a Realm Role that the Realm did not come with.
//
// Why it was refused is asked separately from whether a row went, because one
// bare conflict covered both reasons and the generic sentence for a conflict
// is "an identical item already exists" — which says nothing true about a
// deletion. An administrator removing the built-in user Role was told that,
// and so was one working from a stale screen whose Role is already gone.
func (s *Store) DeleteRole(ctx context.Context, realmID, roleID uuid.UUID) (RoleRemoval, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RoleRemoval{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name string
	err = tx.QueryRow(ctx, "SELECT name FROM roles WHERE id=$1 AND realm_id=$2 FOR UPDATE",
		roleID, realmID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleRemoval{}, ErrNotFound
	}
	if err != nil {
		return RoleRemoval{}, err
	}
	if slices.Contains(builtinRoleNames, name) {
		return RoleRemoval{}, conflictf("%q은(는) Realm과 함께 만들어지는 기본 Role이라 삭제할 수 없습니다.", name)
	}
	// The assignments would go anyway, by cascade. Removing them here instead
	// is what makes the number exact rather than inferred.
	unassigned, err := tx.Exec(ctx, "DELETE FROM user_roles WHERE role_id=$1", roleID)
	if err != nil {
		return RoleRemoval{}, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM roles WHERE id=$1 AND realm_id=$2", roleID, realmID); err != nil {
		return RoleRemoval{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RoleRemoval{}, err
	}
	return RoleRemoval{Name: name, UsersUnassigned: unassigned.RowsAffected()}, nil
}

type ClientRole struct {
	ID          uuid.UUID `json:"id"`
	ClientID    uuid.UUID `json:"client_id"`
	ClientKey   string    `json:"client_key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) ListClientRoles(ctx context.Context, realmID, clientID uuid.UUID) ([]ClientRole, error) {
	rows, err := s.Pool.Query(ctx, `SELECT cr.id,cr.client_id,c.client_id,cr.name,cr.description,cr.created_at
		FROM client_roles cr JOIN clients c ON c.id=cr.client_id
		WHERE c.realm_id=$1 AND ($2::uuid IS NULL OR c.id=$2) ORDER BY c.client_id,cr.name`, realmID, nullableUUID(clientID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]ClientRole, 0)
	for rows.Next() {
		var role ClientRole
		if err := rows.Scan(&role.ID, &role.ClientID, &role.ClientKey, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func nullableUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func (s *Store) CreateClientRole(ctx context.Context, realmID, clientID uuid.UUID, name, description string) (ClientRole, error) {
	name, err := displayableName("Client Role 이름", name)
	if err != nil {
		return ClientRole{}, err
	}
	if name == "" {
		return ClientRole{}, invalidf("Client Role 이름이 필요합니다.")
	}
	role := ClientRole{ID: uuid.New(), ClientID: clientID, Name: name,
		Description: strings.TrimSpace(description), CreatedAt: time.Now().UTC()}
	err = s.Pool.QueryRow(ctx, "SELECT client_id FROM clients WHERE id=$1 AND realm_id=$2", clientID, realmID).Scan(&role.ClientKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClientRole{}, ErrNotFound
	}
	if err != nil {
		return ClientRole{}, err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO client_roles(id,client_id,name,description,created_at)
		VALUES($1,$2,$3,$4,$5)`, role.ID, clientID, role.Name, role.Description, role.CreatedAt)
	if conflict, taken := conflictFromUnique(err); taken {
		return ClientRole{}, conflict
	}
	return role, err
}

func (s *Store) DeleteClientRole(ctx context.Context, realmID, clientID, roleID uuid.UUID) (RoleRemoval, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RoleRemoval{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name string
	err = tx.QueryRow(ctx, `SELECT cr.name FROM client_roles cr JOIN clients c ON c.id=cr.client_id
		WHERE cr.id=$1 AND cr.client_id=$2 AND c.realm_id=$3 FOR UPDATE OF cr`,
		roleID, clientID, realmID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleRemoval{}, ErrNotFound
	}
	if err != nil {
		return RoleRemoval{}, err
	}
	unassigned, err := tx.Exec(ctx, "DELETE FROM user_client_roles WHERE client_role_id=$1", roleID)
	if err != nil {
		return RoleRemoval{}, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM client_roles WHERE id=$1", roleID); err != nil {
		return RoleRemoval{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RoleRemoval{}, err
	}
	return RoleRemoval{Name: name, UsersUnassigned: unassigned.RowsAffected()}, nil
}

type UserRoleMappings struct {
	AvailableRealmRoles    []Role       `json:"available_realm_roles"`
	AvailableClientRoles   []ClientRole `json:"available_client_roles"`
	RealmRoleIDs           []uuid.UUID  `json:"realm_role_ids"`
	FederationRealmRoleIDs []uuid.UUID  `json:"federation_realm_role_ids"`
	ClientRoleIDs          []uuid.UUID  `json:"client_role_ids"`
}

func (s *Store) GetUserRoleMappings(ctx context.Context, realmID, userID uuid.UUID) (UserRoleMappings, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND realm_id=$2)", userID, realmID).Scan(&exists); err != nil {
		return UserRoleMappings{}, err
	}
	if !exists {
		return UserRoleMappings{}, ErrNotFound
	}
	result := UserRoleMappings{RealmRoleIDs: []uuid.UUID{}, FederationRealmRoleIDs: []uuid.UUID{}, ClientRoleIDs: []uuid.UUID{}}
	var err error
	result.AvailableRealmRoles, err = s.ListRoles(ctx, realmID)
	if err != nil {
		return UserRoleMappings{}, err
	}
	result.AvailableClientRoles, err = s.ListClientRoles(ctx, realmID, uuid.Nil)
	if err != nil {
		return UserRoleMappings{}, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT ur.role_id,EXISTS(SELECT 1 FROM federation_role_assignments fra
		WHERE fra.user_id=ur.user_id AND fra.role_id=ur.role_id) FROM user_roles ur
		JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.realm_id=$2`, userID, realmID)
	if err != nil {
		return UserRoleMappings{}, err
	}
	for rows.Next() {
		var roleID uuid.UUID
		var federation bool
		if err := rows.Scan(&roleID, &federation); err != nil {
			rows.Close()
			return UserRoleMappings{}, err
		}
		result.RealmRoleIDs = append(result.RealmRoleIDs, roleID)
		if federation {
			result.FederationRealmRoleIDs = append(result.FederationRealmRoleIDs, roleID)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return UserRoleMappings{}, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT ucr.client_role_id FROM user_client_roles ucr
		JOIN client_roles cr ON cr.id=ucr.client_role_id JOIN clients c ON c.id=cr.client_id
		WHERE ucr.user_id=$1 AND c.realm_id=$2`, userID, realmID)
	if err != nil {
		return UserRoleMappings{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var roleID uuid.UUID
		if err := rows.Scan(&roleID); err != nil {
			return UserRoleMappings{}, err
		}
		result.ClientRoleIDs = append(result.ClientRoleIDs, roleID)
	}
	return result, rows.Err()
}

func (s *Store) ReplaceUserRoleMappings(ctx context.Context, realmID, userID uuid.UUID,
	realmRoleIDs, clientRoleIDs []uuid.UUID) (UserRoleMappings, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return UserRoleMappings{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userExists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND realm_id=$2)", userID, realmID).Scan(&userExists); err != nil || !userExists {
		if err == nil {
			err = ErrNotFound
		}
		return UserRoleMappings{}, err
	}
	var realmRoleCount, clientRoleCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM roles WHERE realm_id=$1 AND id=ANY($2::uuid[])", realmID, realmRoleIDs).Scan(&realmRoleCount); err != nil {
		return UserRoleMappings{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM client_roles cr JOIN clients c ON c.id=cr.client_id
		WHERE c.realm_id=$1 AND cr.id=ANY($2::uuid[])`, realmID, clientRoleIDs).Scan(&clientRoleCount); err != nil {
		return UserRoleMappings{}, err
	}
	if realmRoleCount != len(realmRoleIDs) || clientRoleCount != len(clientRoleIDs) {
		// Typed, so the caller can tell a request that named the wrong Roles
		// from a database that would not take the write. Both used to come
		// back as one untyped error, which the handler echoed verbatim: a
		// failed write reached the administrator as its SQLSTATE, under a
		// status saying they had sent something wrong.
		return UserRoleMappings{}, invalidf("하나 이상의 Role이 이 Realm의 것이 아닙니다.")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_roles ur WHERE ur.user_id=$1
		AND NOT EXISTS(SELECT 1 FROM federation_role_assignments fra
		    WHERE fra.user_id=ur.user_id AND fra.role_id=ur.role_id)`, userID); err != nil {
		return UserRoleMappings{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
		SELECT $1,unnest($2::uuid[]) ON CONFLICT DO NOTHING`, userID, realmRoleIDs); err != nil {
		return UserRoleMappings{}, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM user_client_roles WHERE user_id=$1", userID); err != nil {
		return UserRoleMappings{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_client_roles(user_id,client_role_id)
		SELECT $1,unnest($2::uuid[]) ON CONFLICT DO NOTHING`, userID, clientRoleIDs); err != nil {
		return UserRoleMappings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return UserRoleMappings{}, err
	}
	return s.GetUserRoleMappings(ctx, realmID, userID)
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
		return domain.ApprovalRequest{}, invalidf("요청한 Role이 이 사용자의 Realm에 없습니다.")
	}
	// A second request for a role already waiting on the same reviewer asks
	// nothing new, and the reviewer sees the same row twice. Clicking again
	// because nothing appeared to happen is the ordinary way this arises. Two
	// requests racing here would both pass this check, which costs a duplicate
	// row and no more, so it is left as a check rather than a constraint that
	// an upgraded database with existing duplicates could not accept.
	var alreadyWaiting bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approval_requests
        WHERE requester_id=$1 AND status='PENDING' AND kind='ROLE_ASSIGNMENT'
        AND payload->>'role_id'=$2::text)`, requester.ID, roleID.String()).Scan(&alreadyWaiting); err != nil {
		return domain.ApprovalRequest{}, err
	}
	if alreadyWaiting {
		return domain.ApprovalRequest{}, conflictf("이 Role은 이미 승인 대기 중입니다.")
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

// ApprovalRequestView resolves the identifiers an approval request stores into
// the names a reviewer needs. Listing the raw record showed a truncated
// requester UUID and the bare kind, so a reviewer granting a role could see
// neither who was asking nor which role they would receive.
type ApprovalRequestView struct {
	domain.ApprovalRequest
	RealmName            string `json:"realm_name"`
	RequesterUsername    string `json:"requester_username"`
	RequesterDisplayName string `json:"requester_display_name"`
	ReviewerUsername     string `json:"reviewer_username,omitempty"`
	// TargetRoleName is set for ROLE_ASSIGNMENT requests and names the role
	// that approving would grant.
	TargetRoleName string `json:"target_role_name,omitempty"`
}

// ListApprovalRequests lists approval requests, optionally narrowed to a Realm,
// a requester or a reviewer.
//
// It also reports whether more matched than it returned, so the screen does not
// have to guess from the row count — which claims something is hidden when the
// Realm holds exactly the cap. One extra row is read and dropped.
func (s *Store) ListApprovalRequests(ctx context.Context, realmID *uuid.UUID, requesterID, reviewerID *uuid.UUID) ([]ApprovalRequestView, bool, error) {
	const cap = 500
	// The role identifier inside the payload is compared as text: it is
	// untrusted JSON, and casting it to uuid would fail the whole query on a
	// malformed value rather than simply not matching.
	//
	// Waiting requests are ordered ahead of decided ones, because the cap
	// below is applied before the console filters for the ones still waiting.
	// Newest-first alone meant a request nobody had answered dropped out of
	// the page once five hundred newer ones had been decided — the reviewer's
	// queue read as empty while somebody waited, with nothing to page to.
	rows, err := s.Pool.Query(ctx, `SELECT a.id,a.realm_id,a.requester_id,a.reviewer_id,a.kind,a.payload,a.reason,
        a.status,a.decision_note,a.created_at,a.decided_at,
        COALESCE(rl.name,''),COALESCE(u.username,''),COALESCE(u.display_name,''),
        COALESCE(rv.username,''),COALESCE(ro.name,'')
        FROM approval_requests a
        LEFT JOIN realms rl ON rl.id=a.realm_id
        LEFT JOIN users u ON u.id=a.requester_id
        LEFT JOIN users rv ON rv.id=a.reviewer_id
        LEFT JOIN roles ro ON a.kind='ROLE_ASSIGNMENT' AND ro.id::text=a.payload->>'role_id'
        WHERE ($1::uuid IS NULL OR a.realm_id=$1) AND ($2::uuid IS NULL OR a.requester_id=$2)
        AND ($3::uuid IS NULL OR a.reviewer_id=$3)
        ORDER BY (a.status='PENDING') DESC, a.created_at DESC LIMIT $4`, realmID, requesterID, reviewerID, cap+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	requests := make([]ApprovalRequestView, 0)
	for rows.Next() {
		var view ApprovalRequestView
		if err := rows.Scan(&view.ID, &view.RealmID, &view.RequesterID, &view.ReviewerID, &view.Kind,
			&view.Payload, &view.Reason, &view.Status, &view.DecisionNote, &view.CreatedAt, &view.DecidedAt,
			&view.RealmName, &view.RequesterUsername, &view.RequesterDisplayName,
			&view.ReviewerUsername, &view.TargetRoleName); err != nil {
			return nil, false, err
		}
		requests = append(requests, view)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(requests) > cap {
		return requests[:cap], true, nil
	}
	return requests, false, nil
}

func (s *Store) DecideApprovalRequest(ctx context.Context, requestID, reviewerID uuid.UUID,
	platformAdmin, realmAdmin bool, adminRealmID uuid.UUID, approve bool, note string) (domain.ApprovalRequest, error) {
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
		return domain.ApprovalRequest{}, conflictf("이미 결정된 요청입니다.")
	}
	// Nobody signs off on their own request. Administrators are exempt only
	// because they can assign the role outright, so requiring a second party
	// there would protect nothing; for everyone else this is the whole point
	// of the workflow, and it is checked here rather than only where
	// manager_id is written so that a pairing already sitting in an upgraded
	// database cannot be cashed in.
	if request.RequesterID == reviewerID && !platformAdmin && !realmAdmin {
		return domain.ApprovalRequest{}, forbiddenf("요청한 본인은 그 요청을 결정할 수 없습니다.")
	}
	adminForRealm := realmAdmin && request.RealmID == adminRealmID
	if !platformAdmin && !adminForRealm && (request.ReviewerID == nil || *request.ReviewerID != reviewerID) {
		return domain.ApprovalRequest{}, forbiddenf("이 요청의 검토자로 지정되지 않았습니다.")
	}
	// A designated reviewer still has to belong to the realm the request was
	// raised in; the check above compares identifiers, not standing.
	if !platformAdmin && !adminForRealm {
		var reviewerRealm uuid.UUID
		if err := tx.QueryRow(ctx, "SELECT realm_id FROM users WHERE id=$1", reviewerID).Scan(&reviewerRealm); err != nil {
			return domain.ApprovalRequest{}, err
		}
		if reviewerRealm != request.RealmID {
			return domain.ApprovalRequest{}, forbiddenf("검토자가 이 요청과 다른 Realm에 속해 있습니다.")
		}
	}
	status := "REJECTED"
	if approve {
		status = "APPROVED"
		if request.Kind == "ROLE_ASSIGNMENT" {
			var payload roleAssignmentPayload
			if err := json.Unmarshal(request.Payload, &payload); err != nil {
				return domain.ApprovalRequest{}, fmt.Errorf("decode approval payload: %w", err)
			}
			// Whether the pairing still exists is asked separately from
			// whether a row was written. Reading no rows written as "no
			// longer valid" made approving a request whose role had already
			// been granted — by an administrator, or by a duplicate request
			// decided first — fail with a message about a target that was
			// perfectly fine. The reviewer wanted the person to hold the
			// role, and they do.
			var targetExists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN roles r ON r.realm_id=u.realm_id
                WHERE u.id=$1 AND r.id=$2 AND u.realm_id=$3)`,
				payload.UserID, payload.RoleID, request.RealmID).Scan(&targetExists); err != nil {
				return domain.ApprovalRequest{}, err
			}
			if !targetExists {
				return domain.ApprovalRequest{}, invalidf("요청 대상 사용자나 Role이 더 이상 존재하지 않습니다.")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
                VALUES($1,$2) ON CONFLICT DO NOTHING`, payload.UserID, payload.RoleID); err != nil {
				return domain.ApprovalRequest{}, err
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
