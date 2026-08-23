package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hkjang/ReSSO/internal/domain"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrInvalidInput = errors.New("invalid input")

// MessagedError carries a sentence written for the person who will read it,
// alongside the sentinel that decides the status code.
//
// Creating something with a name that is taken, or a Realm name that does not
// fit the shape, reached the console as the raw constraint violation —
// `duplicate key value violates unique constraint "clients_realm_id_client_id_key"
// (SQLSTATE 23505)` — for every one of user, client, role and Realm. Naming
// collisions are the most ordinary mistake an administrator makes, so that was
// the most likely error in the product to be answered with an internal
// constraint name. The policy numbers next to these fields already got the
// opposite treatment, and say so in the comment above realmPolicyBounds.
type MessagedError struct {
	Sentinel error
	Message  string
}

func (e *MessagedError) Error() string { return e.Message }
func (e *MessagedError) Unwrap() error { return e.Sentinel }

// conflictf reports that a value is already taken, in words.
func conflictf(format string, arguments ...any) error {
	return &MessagedError{Sentinel: ErrConflict, Message: fmt.Sprintf(format, arguments...)}
}

// invalidf reports a value that cannot be stored, in words.
func invalidf(format string, arguments ...any) error {
	return &MessagedError{Sentinel: ErrInvalidInput, Message: fmt.Sprintf(format, arguments...)}
}

// takenValueMessages says what each unique constraint means when a write
// collides with it. The names are read from the error PostgreSQL returns and
// come from the migrations, listed here rather than guessed at the call site:
// the users table alone has three, and answering an email collision with "that
// username is taken" sends somebody to change a field that was never the
// problem.
//
// The value the caller supplied is deliberately absent from these sentences.
// Which value is at fault is exactly what the constraint decides, so pairing a
// message with a value chosen by the call site is how the two come apart.
var takenValueMessages = map[string]string{
	"users_realm_id_username_key": "이미 사용 중인 사용자 이름입니다.",
	"idx_users_realm_username_ci": "이미 사용 중인 사용자 이름입니다. 대소문자만 다른 이름도 같은 것으로 봅니다.",
	// The plain UNIQUE(realm_id, email) from 001 was dropped by 003 in favour
	// of this partial index, which lets more than one account have no email.
	"idx_users_realm_email_ci":           "이 Realm의 다른 사용자가 이미 쓰고 있는 이메일 주소입니다.",
	"realms_name_key":                    "이미 사용 중인 Realm 이름입니다.",
	"realms_issuer_url_key":              "다른 Realm이 이미 쓰고 있는 Issuer URL입니다.",
	"clients_realm_id_client_id_key":     "이미 사용 중인 Client ID입니다.",
	"roles_realm_id_name_key":            "이 Realm에 이미 있는 Role 이름입니다.",
	"client_roles_client_id_name_key":    "이 Client에 이미 있는 Role 이름입니다.",
	"user_federations_realm_id_name_key": "이미 사용 중인 LDAP 공급자 이름입니다.",
}

// conflictFromUnique translates a unique-constraint violation into a sentence,
// and reports whether the error was one at all.
//
// Looking the value up before the write would still race, so the constraint
// stays the authority and this only says what it said. A constraint that is not
// listed above still gets a readable answer, one that does not claim to know
// which field it was.
func conflictFromUnique(err error) (error, bool) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return nil, false
	}
	if message, known := takenValueMessages[pgErr.ConstraintName]; known {
		return conflictf("%s", message), true
	}
	return conflictf("같은 값을 이미 쓰고 있는 항목이 있습니다."), true
}

// realmNamePattern mirrors the CHECK constraint on realms.name, so a name that
// does not fit is reported as the rule it broke. The console's own form states
// this rule in its helper text while only a browser was enforcing it.
var realmNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ErrInvalidManager marks a rejected reporting line. It is distinct from a
// generic invalid input so the console can say which field is wrong and why,
// rather than leaving an administrator to guess at a bare 400.
var ErrInvalidManager = errors.New("invalid manager")
var ErrFederationReadOnly = errors.New("LDAP federation is read-only")
var ErrFederationPasswordExternal = errors.New("password is managed by the source LDAP directory")
var ErrFederationOperation = errors.New("LDAP federation operation failed")

const realmColumns = `id,name,display_name,issuer_url,enabled,approval_enabled,
    access_token_ttl_seconds,refresh_token_ttl_seconds,session_ttl_seconds,idle_timeout_seconds,
    password_min_length,max_login_attempts,lockout_seconds,created_at,updated_at`

func scanRealm(row pgx.Row) (domain.Realm, error) {
	var realm domain.Realm
	err := row.Scan(&realm.ID, &realm.Name, &realm.DisplayName, &realm.IssuerURL, &realm.Enabled,
		&realm.ApprovalEnabled, &realm.AccessTokenTTLSeconds, &realm.RefreshTokenTTLSeconds,
		&realm.SessionTTLSeconds, &realm.IdleTimeoutSeconds, &realm.PasswordMinLength, &realm.MaxLoginAttempts,
		&realm.LockoutSeconds, &realm.CreatedAt, &realm.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Realm{}, ErrNotFound
	}
	return realm, err
}

func (s *Store) RealmByName(ctx context.Context, name string) (domain.Realm, error) {
	return scanRealm(s.Pool.QueryRow(ctx, "SELECT "+realmColumns+" FROM realms WHERE name=$1", strings.ToLower(name)))
}

func (s *Store) RealmByID(ctx context.Context, id uuid.UUID) (domain.Realm, error) {
	return scanRealm(s.Pool.QueryRow(ctx, "SELECT "+realmColumns+" FROM realms WHERE id=$1", id))
}

func (s *Store) ListRealms(ctx context.Context) ([]domain.Realm, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+realmColumns+" FROM realms ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var realms []domain.Realm
	for rows.Next() {
		realm, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		realms = append(realms, realm)
	}
	return realms, rows.Err()
}

type CreateRealmInput struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	IssuerURL   string `json:"issuer_url"`
}

func (s *Store) CreateRealm(ctx context.Context, input CreateRealmInput) (domain.Realm, error) {
	now := time.Now().UTC()
	realm := domain.Realm{
		ID: uuid.New(), Name: strings.ToLower(strings.TrimSpace(input.Name)),
		DisplayName: strings.TrimSpace(input.DisplayName), IssuerURL: strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/"),
		Enabled: true, AccessTokenTTLSeconds: 300, RefreshTokenTTLSeconds: 1800,
		SessionTTLSeconds: 28800, CreatedAt: now, UpdatedAt: now,
	}
	if realm.Name != "" && !realmNamePattern.MatchString(realm.Name) {
		return domain.Realm{}, invalidf(
			"Realm 이름은 소문자·숫자·하이픈만 쓸 수 있고 소문자나 숫자로 시작해야 합니다 (최대 63자)")
	}
	if realm.Name == "" || realm.DisplayName == "" || realm.IssuerURL == "" {
		return domain.Realm{}, errors.New("name, display_name and issuer_url are required")
	}
	if err := validateIssuerURL(realm.IssuerURL); err != nil {
		return domain.Realm{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.Realm{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO realms(id,name,display_name,issuer_url,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$5)`, realm.ID, realm.Name, realm.DisplayName, realm.IssuerURL, now)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return domain.Realm{}, conflict
		}
		return domain.Realm{}, fmt.Errorf("create realm: %w", err)
	}
	for _, name := range []string{"user", "realm-admin", "offline_access"} {
		_, err = tx.Exec(ctx, `INSERT INTO roles(id,realm_id,name,description) VALUES($1,$2,$3,$4)`,
			uuid.New(), realm.ID, name, "Built-in "+name+" role")
		if err != nil {
			return domain.Realm{}, fmt.Errorf("create built-in realm roles: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Realm{}, fmt.Errorf("commit realm creation: %w", err)
	}
	return realm, nil
}

type UpdateRealmInput struct {
	DisplayName            string `json:"display_name"`
	IssuerURL              string `json:"issuer_url"`
	Enabled                bool   `json:"enabled"`
	ApprovalEnabled        bool   `json:"approval_enabled"`
	AccessTokenTTLSeconds  int    `json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int    `json:"refresh_token_ttl_seconds"`
	SessionTTLSeconds      int    `json:"session_ttl_seconds"`
	// IdleTimeoutSeconds is zero to disable, otherwise within the bounds below.
	IdleTimeoutSeconds int `json:"idle_timeout_seconds"`
	// The password and lockout policy lived only in the database until now:
	// it was enforced on every login and password change but could not be
	// read or set by an administrator, and the console guessed at its value.
	PasswordMinLength int `json:"password_min_length"`
	MaxLoginAttempts  int `json:"max_login_attempts"`
	LockoutSeconds    int `json:"lockout_seconds"`
}

// realmPolicyBounds mirrors the CHECK constraints in 001_initial.sql so that
// an out-of-range value is reported as a readable message instead of a
// constraint violation.
func validateRealmPolicy(input UpdateRealmInput) error {
	for _, bound := range []struct {
		label     string
		value     int
		low, high int
	}{
		{"password_min_length", input.PasswordMinLength, 8, 128},
		{"max_login_attempts", input.MaxLoginAttempts, 3, 50},
		{"lockout_seconds", input.LockoutSeconds, 30, 86400},
		{"access_token_ttl_seconds", input.AccessTokenTTLSeconds, 60, 3600},
		{"refresh_token_ttl_seconds", input.RefreshTokenTTLSeconds, 300, 2592000},
		{"session_ttl_seconds", input.SessionTTLSeconds, 300, 2592000},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return fmt.Errorf("%w: %s must be between %d and %d", ErrInvalidInput,
				bound.label, bound.low, bound.high)
		}
	}
	// Zero is the documented way to turn the idle check off, so it is checked
	// apart from the ranges above.
	if input.IdleTimeoutSeconds != 0 && (input.IdleTimeoutSeconds < 300 || input.IdleTimeoutSeconds > 2592000) {
		return fmt.Errorf("%w: idle_timeout_seconds must be 0 or between 300 and 2592000", ErrInvalidInput)
	}
	if input.IdleTimeoutSeconds != 0 && input.IdleTimeoutSeconds > input.SessionTTLSeconds {
		return fmt.Errorf("%w: idle_timeout_seconds must not exceed session_ttl_seconds", ErrInvalidInput)
	}
	return nil
}

func (s *Store) UpdateRealm(ctx context.Context, id uuid.UUID, input UpdateRealmInput) (domain.Realm, error) {
	issuerURL := strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/")
	if err := validateIssuerURL(issuerURL); err != nil {
		return domain.Realm{}, err
	}
	if err := validateRealmPolicy(input); err != nil {
		return domain.Realm{}, err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE realms SET display_name=$2,issuer_url=$3,enabled=$4,
        approval_enabled=$5,access_token_ttl_seconds=$6,refresh_token_ttl_seconds=$7,
        session_ttl_seconds=$8,password_min_length=$9,max_login_attempts=$10,
        lockout_seconds=$11,idle_timeout_seconds=$12,updated_at=now() WHERE id=$1`, id, strings.TrimSpace(input.DisplayName),
		issuerURL, input.Enabled, input.ApprovalEnabled,
		input.AccessTokenTTLSeconds, input.RefreshTokenTTLSeconds, input.SessionTTLSeconds,
		input.PasswordMinLength, input.MaxLoginAttempts, input.LockoutSeconds, input.IdleTimeoutSeconds)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return domain.Realm{}, conflict
		}
		return domain.Realm{}, fmt.Errorf("update realm: %w", err)
	}
	return s.RealmByID(ctx, id)
}

func validateIssuerURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("issuer_url must be an absolute URL without query or fragment")
	}
	host := parsed.Hostname()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
		return errors.New("issuer_url must use HTTPS except for localhost development")
	}
	return nil
}
