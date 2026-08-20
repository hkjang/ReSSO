package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
)

type PersonalAPIKey struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	Scopes      []string   `json:"scopes"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RotatedFrom *uuid.UUID `json:"rotated_from,omitempty"`
}

type CreatedAPIKey struct {
	Key    PersonalAPIKey `json:"key"`
	Secret string         `json:"secret"`
}

func (s *Store) CreatePersonalAPIKey(ctx context.Context, userID uuid.UUID, name string, scopes []string, expiresAt *time.Time, rotatedFrom *uuid.UUID) (CreatedAPIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return CreatedAPIKey{}, errors.New("API key name is required")
	}
	prefixRandom, err := cryptoutil.RandomToken(16)
	if err != nil {
		return CreatedAPIKey{}, err
	}
	secretPart, err := cryptoutil.RandomToken(32)
	if err != nil {
		return CreatedAPIKey{}, err
	}
	// The prefix is an identifier, not an authenticator. Twelve base64url
	// characters provide ample uniqueness while fitting the indexed column.
	prefix := "rk_" + prefixRandom[:12]
	secret := prefix + "." + secretPart
	key := PersonalAPIKey{ID: uuid.New(), Name: name, Prefix: prefix, Scopes: scopes,
		CreatedAt: time.Now().UTC(), ExpiresAt: expiresAt, RotatedFrom: rotatedFrom}
	_, err = s.Pool.Exec(ctx, `INSERT INTO personal_api_keys(id,user_id,name,prefix,secret_hash,scopes,created_at,
        expires_at,rotated_from) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, key.ID, userID, key.Name, key.Prefix,
		s.Sealer.Digest(secret), key.Scopes, key.CreatedAt, key.ExpiresAt, key.RotatedFrom)
	if err != nil {
		return CreatedAPIKey{}, fmt.Errorf("create personal API key: %w", err)
	}
	return CreatedAPIKey{Key: key, Secret: secret}, nil
}

func (s *Store) ListPersonalAPIKeys(ctx context.Context, userID uuid.UUID) ([]PersonalAPIKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,name,prefix,scopes,created_at,expires_at,last_used_at,revoked_at,rotated_from
        FROM personal_api_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]PersonalAPIKey, 0)
	for rows.Next() {
		var key PersonalAPIKey
		if err := rows.Scan(&key.ID, &key.Name, &key.Prefix, &key.Scopes, &key.CreatedAt,
			&key.ExpiresAt, &key.LastUsedAt, &key.RevokedAt, &key.RotatedFrom); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) AuthenticateAPIKey(ctx context.Context, raw string) (domain.Principal, error) {
	dot := strings.IndexByte(raw, '.')
	if dot < 4 || dot > 40 {
		return domain.Principal{}, ErrNotFound
	}
	prefix := raw[:dot]
	var principal domain.Principal
	var expected []byte
	err := s.Pool.QueryRow(ctx, `SELECT u.id,u.realm_id,u.username,u.platform_admin,
		EXISTS(SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
		    WHERE ur.user_id=u.id AND r.name='realm-admin'),k.scopes,k.secret_hash
        FROM personal_api_keys k JOIN users u ON u.id=k.user_id
        WHERE k.prefix=$1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>now())
        AND u.enabled=true`, prefix).Scan(&principal.UserID, &principal.RealmID, &principal.Username,
		&principal.PlatformAdmin, &principal.RealmAdmin, &principal.Scopes, &expected)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !s.Sealer.MatchDigest(raw, expected)) {
		return domain.Principal{}, ErrNotFound
	}
	if err != nil {
		return domain.Principal{}, err
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE personal_api_keys SET last_used_at=now()
        WHERE prefix=$1 AND (last_used_at IS NULL OR last_used_at<now()-interval '5 minutes')`, prefix)
	return principal, nil
}

func (s *Store) RevokePersonalAPIKey(ctx context.Context, userID, keyID uuid.UUID) error {
	command, err := s.Pool.Exec(ctx, `UPDATE personal_api_keys SET revoked_at=COALESCE(revoked_at,now())
        WHERE id=$1 AND user_id=$2`, keyID, userID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotatePersonalAPIKey(ctx context.Context, userID, keyID uuid.UUID) (CreatedAPIKey, error) {
	var name string
	var scopes []string
	var expires *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT name,scopes,expires_at FROM personal_api_keys
        WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, keyID, userID).Scan(&name, &scopes, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return CreatedAPIKey{}, ErrNotFound
	}
	if err != nil {
		return CreatedAPIKey{}, err
	}
	created, err := s.CreatePersonalAPIKey(ctx, userID, name, scopes, expires, &keyID)
	if err != nil {
		return CreatedAPIKey{}, err
	}
	if err := s.RevokePersonalAPIKey(ctx, userID, keyID); err != nil {
		return CreatedAPIKey{}, err
	}
	return created, nil
}
