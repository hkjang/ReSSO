package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/domain"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrInvalidInput = errors.New("invalid input")
var ErrFederationReadOnly = errors.New("LDAP federation is read-only")
var ErrFederationPasswordExternal = errors.New("password is managed by the source LDAP directory")
var ErrFederationOperation = errors.New("LDAP federation operation failed")

const realmColumns = `id,name,display_name,issuer_url,enabled,approval_enabled,
    access_token_ttl_seconds,refresh_token_ttl_seconds,session_ttl_seconds,created_at,updated_at`

func scanRealm(row pgx.Row) (domain.Realm, error) {
	var realm domain.Realm
	err := row.Scan(&realm.ID, &realm.Name, &realm.DisplayName, &realm.IssuerURL, &realm.Enabled,
		&realm.ApprovalEnabled, &realm.AccessTokenTTLSeconds, &realm.RefreshTokenTTLSeconds,
		&realm.SessionTTLSeconds, &realm.CreatedAt, &realm.UpdatedAt)
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
}

func (s *Store) UpdateRealm(ctx context.Context, id uuid.UUID, input UpdateRealmInput) (domain.Realm, error) {
	issuerURL := strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/")
	if err := validateIssuerURL(issuerURL); err != nil {
		return domain.Realm{}, err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE realms SET display_name=$2,issuer_url=$3,enabled=$4,
        approval_enabled=$5,access_token_ttl_seconds=$6,refresh_token_ttl_seconds=$7,
        session_ttl_seconds=$8,updated_at=now() WHERE id=$1`, id, strings.TrimSpace(input.DisplayName),
		issuerURL, input.Enabled, input.ApprovalEnabled,
		input.AccessTokenTTLSeconds, input.RefreshTokenTTLSeconds, input.SessionTTLSeconds)
	if err != nil {
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
