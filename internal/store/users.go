package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/password"
)

const maxEmailLength = 320

const userColumns = `id,realm_id,username,email,email_verified,display_name,enabled,platform_admin,manager_id,
    federation_id,external_id,external_dn,federation_synced_at,failed_attempts,locked_until,
    password_changed_at,created_at,updated_at`

func scanUser(row pgx.Row) (domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.RealmID, &user.Username, &user.Email, &user.EmailVerified, &user.DisplayName, &user.Enabled,
		&user.PlatformAdmin, &user.ManagerID, &user.FederationID, &user.ExternalID, &user.ExternalDN,
		&user.FederationSyncedAt, &user.FailedAttempts, &user.LockedUntil,
		&user.PasswordChanged, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, ErrNotFound
	}
	return user, err
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return scanUser(s.Pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE id=$1", id))
}

func (s *Store) ListUsers(ctx context.Context, realmID uuid.UUID, query string, limit, offset int) ([]domain.User, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	pattern := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	rows, err := s.Pool.Query(ctx, "SELECT "+userColumns+` FROM users WHERE realm_id=$1 AND
        ($2='' OR lower(username) LIKE $3 OR lower(email) LIKE $3 OR lower(display_name) LIKE $3)
        ORDER BY username LIMIT $4 OFFSET $5`, realmID, strings.TrimSpace(query), pattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]domain.User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context, realmID uuid.UUID, query string) (int, error) {
	pattern := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	var total int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE realm_id=$1 AND
		($2='' OR lower(username) LIKE $3 OR lower(email) LIKE $3 OR lower(display_name) LIKE $3)`,
		realmID, strings.TrimSpace(query), pattern).Scan(&total)
	return total, err
}

type CreateUserInput struct {
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	DisplayName   string     `json:"display_name"`
	Password      string     `json:"password"`
	Enabled       bool       `json:"enabled"`
	ManagerID     *uuid.UUID `json:"manager_id,omitempty"`
}

func (s *Store) CreateUser(ctx context.Context, realmID uuid.UUID, input CreateUserInput) (domain.User, error) {
	input.Username = strings.TrimSpace(input.Username)
	var err error
	input.Email, err = normalizeOptionalEmail(input.Email)
	if err != nil {
		return domain.User{}, err
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.Username == "" || input.Password == "" {
		return domain.User{}, errors.New("username and password are required")
	}
	var minLength int
	if err := s.Pool.QueryRow(ctx, "SELECT password_min_length FROM realms WHERE id=$1", realmID).Scan(&minLength); err != nil {
		return domain.User{}, err
	}
	if len([]rune(input.Password)) < minLength {
		return domain.User{}, fmt.Errorf("password must contain at least %d characters", minLength)
	}
	if input.DisplayName == "" {
		input.DisplayName = input.Username
	}
	hashed, err := password.Hash(input.Password)
	if err != nil {
		return domain.User{}, err
	}
	now := time.Now().UTC()
	user := domain.User{ID: uuid.New(), RealmID: realmID, Username: input.Username, Email: input.Email,
		EmailVerified: input.Email != "" && input.EmailVerified,
		DisplayName:   input.DisplayName, Enabled: input.Enabled, ManagerID: input.ManagerID,
		PasswordChanged: now, CreatedAt: now, UpdatedAt: now}
	_, err = s.Pool.Exec(ctx, `INSERT INTO users(id,realm_id,username,email,email_verified,display_name,password_hash,enabled,
		manager_id,password_changed_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$10)`,
		user.ID, realmID, user.Username, user.Email, user.EmailVerified, user.DisplayName, hashed, user.Enabled, user.ManagerID, now)
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
        SELECT $1,id FROM roles WHERE realm_id=$2 AND name='user' ON CONFLICT DO NOTHING`, user.ID, realmID)
	return user, nil
}

type UpdateProfileInput struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type UpdateUserInput struct {
	Email         string     `json:"email"`
	EmailVerified *bool      `json:"email_verified,omitempty"`
	DisplayName   string     `json:"display_name"`
	Enabled       bool       `json:"enabled"`
	ManagerID     *uuid.UUID `json:"manager_id,omitempty"`
}

func (s *Store) UpdateUser(ctx context.Context, userID uuid.UUID, input UpdateUserInput) (domain.User, error) {
	current, err := s.UserByID(ctx, userID)
	if err != nil {
		return domain.User{}, err
	}
	email, err := normalizeOptionalEmail(input.Email)
	if err != nil {
		return domain.User{}, err
	}
	displayName := strings.TrimSpace(input.DisplayName)
	emailChanged := !strings.EqualFold(strings.TrimSpace(current.Email), email)
	if emailChanged || current.DisplayName != displayName {
		if err := s.updateFederatedAttributes(ctx, current, email, displayName); err != nil {
			return domain.User{}, err
		}
	}
	command, err := s.Pool.Exec(ctx, `UPDATE users SET email_verified=CASE
		WHEN $2='' OR $7::boolean THEN false
		WHEN $6::boolean IS NULL THEN email_verified ELSE $6 END,
		email=$2,display_name=$3,enabled=$4,
		manager_id=$5,updated_at=now() WHERE id=$1`, userID, email, displayName, input.Enabled, input.ManagerID, input.EmailVerified, emailChanged)
	if err != nil {
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	if command.RowsAffected() == 0 {
		return domain.User{}, ErrNotFound
	}
	return s.UserByID(ctx, userID)
}

func (s *Store) UpdateProfile(ctx context.Context, userID uuid.UUID, input UpdateProfileInput) (domain.User, error) {
	current, err := s.UserByID(ctx, userID)
	if err != nil {
		return domain.User{}, err
	}
	email, err := normalizeOptionalEmail(input.Email)
	if err != nil {
		return domain.User{}, err
	}
	displayName := strings.TrimSpace(input.DisplayName)
	emailChanged := !strings.EqualFold(strings.TrimSpace(current.Email), email)
	if emailChanged || current.DisplayName != displayName {
		if err := s.updateFederatedAttributes(ctx, current, email, displayName); err != nil {
			return domain.User{}, err
		}
	}
	_, err = s.Pool.Exec(ctx, `UPDATE users SET email_verified=CASE WHEN $2='' OR $4::boolean THEN false ELSE email_verified END,
		email=$2,display_name=$3,updated_at=now() WHERE id=$1`,
		userID, email, displayName, emailChanged)
	if err != nil {
		return domain.User{}, fmt.Errorf("update profile: %w", err)
	}
	return s.UserByID(ctx, userID)
}

func normalizeOptionalEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" {
		return "", nil
	}
	if len([]rune(email)) > maxEmailLength {
		return "", fmt.Errorf("%w: email must contain at most %d characters", ErrInvalidInput, maxEmailLength)
	}
	if !validMailbox(email) {
		return "", fmt.Errorf("%w: email must be a single RFC address", ErrInvalidInput)
	}
	return email, nil
}

// validMailbox deliberately accepts the conservative ASCII dot-atom subset of
// RFC 5322. Display names, comments, quoted local parts, domain literals and
// internationalized addresses are rejected rather than normalized ambiguously.
func validMailbox(value string) bool {
	if strings.Count(value, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(value, "@")
	if len(local) < 1 || len(local) > 64 || len(domain) < 1 || len(domain) > 255 {
		return false
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		if !isEmailLocalByte(local[i]) {
			return false
		}
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isASCIILetterOrDigit(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isEmailLocalByte(value byte) bool {
	if isASCIILetterOrDigit(value) {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(value))
}

func isASCIILetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func (s *Store) ChangePassword(ctx context.Context, userID uuid.UUID, current, replacement string, adminReset bool) error {
	user, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	var hash string
	var realmID uuid.UUID
	if err := s.Pool.QueryRow(ctx, "SELECT password_hash,realm_id FROM users WHERE id=$1", userID).Scan(&hash, &realmID); err != nil {
		return err
	}
	if !adminReset && user.FederationID == nil {
		ok, err := password.Verify(current, hash)
		if err != nil || !ok {
			return errors.New("current password is incorrect")
		}
	}
	var minLength int
	if err := s.Pool.QueryRow(ctx, "SELECT password_min_length FROM realms WHERE id=$1", realmID).Scan(&minLength); err != nil {
		return err
	}
	if len([]rune(replacement)) < minLength {
		return fmt.Errorf("new password must contain at least %d characters", minLength)
	}
	if user.FederationID != nil {
		if err := s.changeFederatedPassword(ctx, user, current, replacement); err != nil {
			return err
		}
		_, err := s.Pool.Exec(ctx, `UPDATE users SET password_changed_at=now(),failed_attempts=0,
            locked_until=NULL,updated_at=now() WHERE id=$1`, userID)
		return err
	}
	newHash, err := password.Hash(replacement)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE users SET password_hash=$2,password_changed_at=now(),failed_attempts=0,
        locked_until=NULL,updated_at=now() WHERE id=$1`, userID, newHash)
	return err
}

type AuthenticationResult struct {
	User           domain.User
	Success        bool
	FailureReason  string
	SessionSeconds int
	AuthMethod     string
}

func (s *Store) AuthenticatePassword(ctx context.Context, realm domain.Realm, username, suppliedPassword string) (AuthenticationResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AuthenticationResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var user domain.User
	var passwordHash string
	var maxAttempts, lockoutSeconds int
	err = tx.QueryRow(ctx, `SELECT u.id,u.realm_id,u.username,u.email,u.email_verified,u.display_name,u.enabled,u.platform_admin,
        u.manager_id,u.failed_attempts,u.locked_until,u.password_changed_at,u.created_at,u.updated_at,u.password_hash,
        r.max_login_attempts,r.lockout_seconds FROM users u JOIN realms r ON r.id=u.realm_id
        WHERE u.realm_id=$1 AND lower(u.username)=lower($2) FOR UPDATE`, realm.ID, strings.TrimSpace(username)).Scan(
		&user.ID, &user.RealmID, &user.Username, &user.Email, &user.EmailVerified, &user.DisplayName, &user.Enabled, &user.PlatformAdmin,
		&user.ManagerID, &user.FailedAttempts, &user.LockedUntil, &user.PasswordChanged, &user.CreatedAt, &user.UpdatedAt,
		&passwordHash, &maxAttempts, &lockoutSeconds)
	if errors.Is(err, pgx.ErrNoRows) {
		// Equalize the dominant Argon2 work factor for unknown users.
		_, _ = password.Verify(suppliedPassword, s.dummyPasswordHash)
		return AuthenticationResult{FailureReason: "INVALID_CREDENTIALS"}, nil
	}
	if err != nil {
		return AuthenticationResult{}, err
	}
	now := time.Now().UTC()
	if !realm.Enabled || !user.Enabled {
		return AuthenticationResult{User: user, FailureReason: "ACCOUNT_DISABLED"}, nil
	}
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		return AuthenticationResult{User: user, FailureReason: "ACCOUNT_LOCKED"}, nil
	}
	ok, verifyErr := password.Verify(suppliedPassword, passwordHash)
	if verifyErr != nil {
		return AuthenticationResult{}, verifyErr
	}
	if !ok {
		attempts := user.FailedAttempts + 1
		var lockedUntil *time.Time
		if attempts >= maxAttempts {
			locked := now.Add(time.Duration(lockoutSeconds) * time.Second)
			lockedUntil = &locked
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET failed_attempts=$2,locked_until=$3,updated_at=now()
            WHERE id=$1`, user.ID, attempts, lockedUntil); err != nil {
			return AuthenticationResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AuthenticationResult{}, err
		}
		reason := "INVALID_CREDENTIALS"
		if lockedUntil != nil {
			reason = "ACCOUNT_LOCKED"
		}
		return AuthenticationResult{User: user, FailureReason: reason}, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET failed_attempts=0,locked_until=NULL,updated_at=now() WHERE id=$1`, user.ID); err != nil {
		return AuthenticationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthenticationResult{}, err
	}
	user.FailedAttempts, user.LockedUntil = 0, nil
	return AuthenticationResult{User: user, Success: true, SessionSeconds: realm.SessionTTLSeconds}, nil
}

func (s *Store) RealmRolesForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id
        WHERE ur.user_id=$1 ORDER BY r.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *Store) ClientRolesForUser(ctx context.Context, userID uuid.UUID) (map[string][]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.client_id,cr.name FROM user_client_roles ucr
        JOIN client_roles cr ON cr.id=ucr.client_role_id JOIN clients c ON c.id=cr.client_id
        WHERE ucr.user_id=$1 ORDER BY c.client_id,cr.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string][]string{}
	for rows.Next() {
		var client, role string
		if err := rows.Scan(&client, &role); err != nil {
			return nil, err
		}
		result[client] = append(result[client], role)
	}
	return result, rows.Err()
}

func (s *Store) UserHasRealmRole(ctx context.Context, userID uuid.UUID, name string) (bool, error) {
	var assigned bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles ur
		JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.name=$2)`, userID, name).Scan(&assigned)
	return assigned, err
}
