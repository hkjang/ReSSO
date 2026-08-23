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
    password_changed_at,(locked_until IS NOT NULL AND locked_until > now()),created_at,updated_at`

func scanUser(row pgx.Row) (domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.RealmID, &user.Username, &user.Email, &user.EmailVerified, &user.DisplayName, &user.Enabled,
		&user.PlatformAdmin, &user.ManagerID, &user.FederationID, &user.ExternalID, &user.ExternalDN,
		&user.FederationSyncedAt, &user.FailedAttempts, &user.LockedUntil,
		&user.PasswordChanged, &user.Locked, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, ErrNotFound
	}
	return user, err
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return scanUser(s.Pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE id=$1", id))
}

// userSortColumns whitelists the orderings the console may ask for. The value
// is interpolated into the statement, so it must never come from the request.
var userSortColumns = map[string]string{
	"username":            "lower(username)",
	"display_name":        "lower(display_name)",
	"email":               "lower(email)",
	"created_at":          "created_at",
	"password_changed_at": "password_changed_at",
}

// UserSort names an ordering. An unknown column falls back to the username so
// a stale or hand-written request cannot produce an error page.
type UserSort struct {
	Column     string
	Descending bool
}

func (s UserSort) orderBy() string {
	column, ok := userSortColumns[s.Column]
	if !ok {
		column = userSortColumns["username"]
	}
	direction := "ASC"
	if s.Descending {
		direction = "DESC"
	}
	// The username tiebreak keeps paging stable when the sorted values repeat.
	return column + " " + direction + ", lower(username) ASC"
}

func (s *Store) ListUsers(ctx context.Context, realmID uuid.UUID, query string, sort UserSort, limit, offset int) ([]domain.User, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	pattern := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	rows, err := s.Pool.Query(ctx, "SELECT "+userColumns+` FROM users WHERE realm_id=$1 AND
        ($2='' OR lower(username) LIKE $3 OR lower(email) LIKE $3 OR lower(display_name) LIKE $3)
        ORDER BY `+sort.orderBy()+` LIMIT $4 OFFSET $5`, realmID, strings.TrimSpace(query), pattern, limit, offset)
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

// validateManagerID rejects a manager assignment that would hollow out the
// approval workflow.
//
// A request's reviewer is the requester's manager, and that is the only thing
// standing between asking for a role and holding it. Pointing manager_id at
// the user themselves makes the requester their own approver; pointing it into
// another realm hands the decision to somebody with no standing there, since
// the reviewer check compares identifiers and not realms. Neither is a
// meaningful reporting line, so both are refused where they are written.
func (s *Store) validateManagerID(ctx context.Context, userID, realmID uuid.UUID, managerID *uuid.UUID) error {
	if managerID == nil {
		return nil
	}
	if *managerID == userID {
		return fmt.Errorf("%w: a user cannot be their own manager", ErrInvalidManager)
	}
	var managerRealm uuid.UUID
	err := s.Pool.QueryRow(ctx, "SELECT realm_id FROM users WHERE id=$1", *managerID).Scan(&managerRealm)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: manager does not exist", ErrInvalidManager)
	}
	if err != nil {
		return err
	}
	if managerRealm != realmID {
		return fmt.Errorf("%w: manager must belong to the same realm", ErrInvalidManager)
	}
	return nil
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
	hashed, err := password.HashContext(ctx, input.Password)
	if err != nil {
		return domain.User{}, err
	}
	now := time.Now().UTC()
	userID := uuid.New()
	if err := s.validateManagerID(ctx, userID, realmID, input.ManagerID); err != nil {
		return domain.User{}, err
	}
	user := domain.User{ID: userID, RealmID: realmID, Username: input.Username, Email: input.Email,
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
	if err := s.validateManagerID(ctx, userID, current.RealmID, input.ManagerID); err != nil {
		return domain.User{}, err
	}
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
	// Disabling is the emergency stop, so it has to stop something. Without
	// this the account was only hidden: the cookie stopped resolving while the
	// session row stayed live, so re-enabling the account later handed the
	// same session back, and every relying party went on believing the person
	// was signed in the whole time.
	if current.Enabled && !input.Enabled {
		if err := s.EndSessionsOfDisabledUsers(ctx, []uuid.UUID{userID}); err != nil {
			return domain.User{}, fmt.Errorf("end sessions of disabled user: %w", err)
		}
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
		ok, err := password.VerifyContext(ctx, current, hash)
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
	newHash, err := password.HashContext(ctx, replacement)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE users SET password_hash=$2,password_changed_at=now(),failed_attempts=0,
        locked_until=NULL,updated_at=now() WHERE id=$1`, userID, newHash)
	return err
}

type AuthenticationResult struct {
	User          domain.User
	Success       bool
	FailureReason string
	// CredentialsValid reports that the password was right even though the
	// attempt failed, which happens when the account is locked or disabled.
	// It is what lets the caller name the real obstacle without telling an
	// anonymous guesser that the account exists.
	CredentialsValid bool
	SessionSeconds   int
	AuthMethod       string
}

// AuthenticatePassword verifies a local password without holding a database
// transaction across the Argon2 work. The previous implementation opened a
// SELECT ... FOR UPDATE and only committed after verification, so every
// in-flight login pinned a pooled connection for the whole hash duration and a
// burst of logins starved every other query — token issuance included. The
// row lock also served to serialize the failure counter; the atomic UPDATE in
// recordFailedLogin replaces it.
func (s *Store) AuthenticatePassword(ctx context.Context, realm domain.Realm, username, suppliedPassword string) (AuthenticationResult, error) {
	var user domain.User
	var passwordHash string
	err := s.Pool.QueryRow(ctx, "SELECT "+userColumns+`,password_hash FROM users
        WHERE realm_id=$1 AND lower(username)=lower($2)`, realm.ID, strings.TrimSpace(username)).Scan(
		&user.ID, &user.RealmID, &user.Username, &user.Email, &user.EmailVerified, &user.DisplayName,
		&user.Enabled, &user.PlatformAdmin, &user.ManagerID, &user.FederationID, &user.ExternalID,
		&user.ExternalDN, &user.FederationSyncedAt, &user.FailedAttempts, &user.LockedUntil,
		&user.PasswordChanged, &user.Locked, &user.CreatedAt, &user.UpdatedAt, &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		// Equalize the dominant Argon2 work factor for unknown users.
		_, _ = s.dummyPasswordVerification(ctx, suppliedPassword)
		return AuthenticationResult{FailureReason: "INVALID_CREDENTIALS"}, nil
	}
	if err != nil {
		return AuthenticationResult{}, err
	}
	// The password is checked even when the account is already barred, for two
	// reasons. Skipping the hash answered a locked account in a fraction of
	// the time an ordinary rejection takes, which told an attacker the account
	// exists and is locked — exactly what the identical error message is there
	// to withhold, and the same leak the dummy verification above exists to
	// close for unknown users. And knowing the credentials were right is what
	// makes it safe to tell the person that their account is locked rather
	// than that they have forgotten their password: whoever supplies the
	// correct password already knows more than enumeration would reveal.
	barred := accountFailureReason(realm, user, time.Now().UTC())
	ok, verifyErr := password.VerifyContext(ctx, suppliedPassword, passwordHash)
	if verifyErr != nil {
		return AuthenticationResult{}, verifyErr
	}
	if barred != "" {
		// No failure is recorded: the account is already barred, and counting
		// these would let an attacker keep extending someone's lockout.
		return AuthenticationResult{User: user, FailureReason: barred, CredentialsValid: ok}, nil
	}
	if !ok {
		locked, err := s.recordFailedLogin(ctx, user.ID)
		if err != nil {
			return AuthenticationResult{}, err
		}
		reason := "INVALID_CREDENTIALS"
		if locked {
			reason = "ACCOUNT_LOCKED"
		}
		return AuthenticationResult{User: user, FailureReason: reason}, nil
	}
	accepted, err := s.completeSuccessfulLogin(ctx, user.ID)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if !accepted {
		// A concurrent burst locked or disabled the account while this
		// attempt was hashing. Refuse rather than clearing the lockout.
		return AuthenticationResult{User: user, FailureReason: "ACCOUNT_LOCKED"}, nil
	}
	user.FailedAttempts, user.LockedUntil = 0, nil
	return AuthenticationResult{User: user, Success: true, SessionSeconds: realm.SessionTTLSeconds}, nil
}

// recordFailedLogin increments the failure counter and applies the realm
// lockout policy in one statement, so concurrent attempts cannot lose
// increments without a row lock. It reports whether the account is now locked.
func (s *Store) recordFailedLogin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var locked bool
	err := s.Pool.QueryRow(ctx, `UPDATE users u SET
        failed_attempts=u.failed_attempts+1,
        locked_until=CASE WHEN u.failed_attempts+1 >= r.max_login_attempts
            THEN now()+make_interval(secs => r.lockout_seconds) ELSE u.locked_until END,
        updated_at=now()
        FROM realms r WHERE u.id=$1 AND r.id=u.realm_id
        RETURNING (u.locked_until IS NOT NULL AND u.locked_until>now())`, userID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return locked, err
}

// completeSuccessfulLogin clears the failure counter only while the account is
// still usable, closing the window between reading the lockout state and
// finishing verification.
func (s *Store) completeSuccessfulLogin(ctx context.Context, userID uuid.UUID) (bool, error) {
	command, err := s.Pool.Exec(ctx, `UPDATE users SET failed_attempts=0,locked_until=NULL,updated_at=now()
        WHERE id=$1 AND enabled=true AND (locked_until IS NULL OR locked_until<=now())`, userID)
	if err != nil {
		return false, err
	}
	return command.RowsAffected() == 1, nil
}

// UnlockUser clears a lockout without changing the password. Until now the
// only way an administrator could release a locked account was to reset its
// password, which forces an unnecessary credential change on a user who was
// simply locked out by mistyping. It reports whether the account was locked.
func (s *Store) UnlockUser(ctx context.Context, realmID, userID uuid.UUID) (bool, error) {
	// The prior state is captured in its own CTE so the reported value cannot
	// depend on when the RETURNING clause observes the updated row.
	var wasLocked bool
	err := s.Pool.QueryRow(ctx, `WITH previous AS (
            SELECT id,locked_until,failed_attempts FROM users WHERE id=$1 AND realm_id=$2 FOR UPDATE
        ), cleared AS (
            UPDATE users SET failed_attempts=0,locked_until=NULL,updated_at=now()
            WHERE id=(SELECT id FROM previous) RETURNING id
        )
        SELECT (previous.locked_until IS NOT NULL AND previous.locked_until>now()) OR previous.failed_attempts>0
        FROM previous JOIN cleared ON cleared.id=previous.id`, userID, realmID).Scan(&wasLocked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return wasLocked, err
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
