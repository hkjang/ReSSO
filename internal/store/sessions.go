package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
)

type NewSession struct {
	Session   domain.Session
	Token     string
	CSRFToken string
}

func (s *Store) CreateSession(ctx context.Context, realmID, userID uuid.UUID, ttl time.Duration, ip, userAgent, method string) (NewSession, error) {
	token, err := cryptoutil.RandomToken(32)
	if err != nil {
		return NewSession{}, err
	}
	csrf, err := cryptoutil.RandomToken(24)
	if err != nil {
		return NewSession{}, err
	}
	now := time.Now().UTC()
	session := domain.Session{ID: uuid.New(), RealmID: realmID, UserID: userID, IPAddress: ip,
		UserAgent: userAgent, AuthMethod: method, CreatedAt: now, LastAccess: now, ExpiresAt: now.Add(ttl)}
	_, err = s.Pool.Exec(ctx, `INSERT INTO sso_sessions(id,realm_id,user_id,token_hash,csrf_hash,ip_address,
        user_agent,auth_method,created_at,last_access,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10)`,
		session.ID, realmID, userID, s.Sealer.Digest(token), s.Sealer.Digest(csrf), ip, userAgent, method, now, session.ExpiresAt)
	if err != nil {
		return NewSession{}, fmt.Errorf("create SSO session: %w", err)
	}
	return NewSession{Session: session, Token: token, CSRFToken: csrf}, nil
}

type AuthenticatedSession struct {
	Session  domain.Session
	User     domain.User
	CSRFHash []byte
}

func (s *Store) SessionByToken(ctx context.Context, rawToken string) (AuthenticatedSession, error) {
	if rawToken == "" {
		return AuthenticatedSession{}, ErrNotFound
	}
	var result AuthenticatedSession
	err := s.Pool.QueryRow(ctx, `SELECT s.id,s.realm_id,s.user_id,u.username,s.ip_address,s.user_agent,s.auth_method,
        s.created_at,s.last_access,s.expires_at,s.revoked_at,s.csrf_hash,
        u.id,u.realm_id,u.username,u.email,u.display_name,u.enabled,u.platform_admin,u.manager_id,
        u.failed_attempts,u.locked_until,u.password_changed_at,u.created_at,u.updated_at
        FROM sso_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.enabled=true`, s.Sealer.Digest(rawToken)).Scan(
		&result.Session.ID, &result.Session.RealmID, &result.Session.UserID, &result.Session.Username,
		&result.Session.IPAddress, &result.Session.UserAgent, &result.Session.AuthMethod, &result.Session.CreatedAt,
		&result.Session.LastAccess, &result.Session.ExpiresAt, &result.Session.RevokedAt, &result.CSRFHash,
		&result.User.ID, &result.User.RealmID, &result.User.Username, &result.User.Email, &result.User.DisplayName,
		&result.User.Enabled, &result.User.PlatformAdmin, &result.User.ManagerID, &result.User.FailedAttempts,
		&result.User.LockedUntil, &result.User.PasswordChanged, &result.User.CreatedAt, &result.User.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthenticatedSession{}, ErrNotFound
	}
	if err != nil {
		return AuthenticatedSession{}, err
	}
	if time.Since(result.Session.LastAccess) > time.Minute {
		_, _ = s.Pool.Exec(ctx, "UPDATE sso_sessions SET last_access=now() WHERE id=$1", result.Session.ID)
	}
	return result, nil
}

func (s *Store) ValidateCSRF(session AuthenticatedSession, csrf string) bool {
	return csrf != "" && s.Sealer.MatchDigest(csrf, session.CSRFHash)
}

func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	command, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE session_id=$1`, id)
	return nil
}

func (s *Store) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, except *uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=COALESCE(revoked_at,now())
        WHERE user_id=$1 AND ($2::uuid IS NULL OR id<>$2)`, userID, except)
	_, _ = s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
        WHERE user_id=$1 AND ($2::uuid IS NULL OR session_id<>$2)`, userID, except)
	return err
}

func (s *Store) ListSessions(ctx context.Context, realmID *uuid.UUID, userID *uuid.UUID, limit int) ([]domain.Session, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `SELECT s.id,s.realm_id,s.user_id,u.username,s.ip_address,s.user_agent,
        s.auth_method,s.created_at,s.last_access,s.expires_at,s.revoked_at FROM sso_sessions s
        JOIN users u ON u.id=s.user_id WHERE ($1::uuid IS NULL OR s.realm_id=$1)
        AND ($2::uuid IS NULL OR s.user_id=$2) ORDER BY s.last_access DESC LIMIT $3`, realmID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]domain.Session, 0)
	for rows.Next() {
		var session domain.Session
		if err := rows.Scan(&session.ID, &session.RealmID, &session.UserID, &session.Username,
			&session.IPAddress, &session.UserAgent, &session.AuthMethod, &session.CreatedAt,
			&session.LastAccess, &session.ExpiresAt, &session.RevokedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}
