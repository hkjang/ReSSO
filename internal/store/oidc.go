package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
)

type AuthorizationRequest struct {
	ID                  uuid.UUID
	RealmID             uuid.UUID
	ClientID            uuid.UUID
	RedirectURI         string
	ResponseType        string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	ExpiresAt           time.Time
}

func (s *Store) CreateAuthorizationRequest(ctx context.Context, request AuthorizationRequest) (string, error) {
	token, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", err
	}
	if request.ID == uuid.Nil {
		request.ID = uuid.New()
	}
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO authorization_requests(id,token_hash,realm_id,client_id,redirect_uri,
        response_type,scope,state,nonce,code_challenge,code_challenge_method,prompt,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, request.ID, s.Sealer.Digest(token),
		request.RealmID, request.ClientID, request.RedirectURI, request.ResponseType, request.Scope,
		request.State, request.Nonce, request.CodeChallenge, request.CodeChallengeMethod, request.Prompt, request.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("save authorization request: %w", err)
	}
	return token, nil
}

func scanAuthorizationRequest(row pgx.Row) (AuthorizationRequest, error) {
	var request AuthorizationRequest
	err := row.Scan(&request.ID, &request.RealmID, &request.ClientID, &request.RedirectURI,
		&request.ResponseType, &request.Scope, &request.State, &request.Nonce, &request.CodeChallenge,
		&request.CodeChallengeMethod, &request.Prompt, &request.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationRequest{}, ErrNotFound
	}
	return request, err
}

func (s *Store) AuthorizationRequestByToken(ctx context.Context, token string) (AuthorizationRequest, error) {
	return scanAuthorizationRequest(s.Pool.QueryRow(ctx, `SELECT id,realm_id,client_id,redirect_uri,response_type,
        scope,state,nonce,code_challenge,code_challenge_method,prompt,expires_at FROM authorization_requests
        WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now()`, s.Sealer.Digest(token)))
}

func (s *Store) ConsumeAuthorizationRequest(ctx context.Context, token string) (AuthorizationRequest, error) {
	return scanAuthorizationRequest(s.Pool.QueryRow(ctx, `UPDATE authorization_requests SET consumed_at=now()
        WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now()
        RETURNING id,realm_id,client_id,redirect_uri,response_type,scope,state,nonce,code_challenge,
        code_challenge_method,prompt,expires_at`, s.Sealer.Digest(token)))
}

type AuthorizationCode struct {
	ID                  uuid.UUID
	RealmID             uuid.UUID
	ClientID            uuid.UUID
	UserID              uuid.UUID
	SessionID           uuid.UUID
	RedirectURI         string
	Scope               []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code AuthorizationCode) (string, error) {
	raw, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", err
	}
	if code.ID == uuid.Nil {
		code.ID = uuid.New()
	}
	if code.ExpiresAt.IsZero() {
		code.ExpiresAt = time.Now().UTC().Add(90 * time.Second)
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO authorization_codes(id,code_hash,realm_id,client_id,user_id,session_id,
        redirect_uri,scope,nonce,code_challenge,code_challenge_method,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, code.ID, s.Sealer.Digest(raw), code.RealmID,
		code.ClientID, code.UserID, code.SessionID, code.RedirectURI, code.Scope, code.Nonce,
		code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("save authorization code: %w", err)
	}
	return raw, nil
}

func scanAuthorizationCode(row pgx.Row) (AuthorizationCode, error) {
	var code AuthorizationCode
	err := row.Scan(&code.ID, &code.RealmID, &code.ClientID, &code.UserID, &code.SessionID,
		&code.RedirectURI, &code.Scope, &code.Nonce, &code.CodeChallenge, &code.CodeChallengeMethod, &code.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationCode{}, ErrNotFound
	}
	return code, err
}

func (s *Store) RedeemAuthorizationCode(ctx context.Context, raw string, validate func(AuthorizationCode) error) (AuthorizationCode, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	code, err := scanAuthorizationCode(tx.QueryRow(ctx, `SELECT id,realm_id,client_id,user_id,session_id,
		redirect_uri,scope,nonce,code_challenge,code_challenge_method,expires_at FROM authorization_codes
		WHERE code_hash=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, s.Sealer.Digest(raw)))
	if err != nil {
		return AuthorizationCode{}, err
	}
	if err := validate(code); err != nil {
		return AuthorizationCode{}, err
	}
	if _, err := tx.Exec(ctx, "UPDATE authorization_codes SET consumed_at=now() WHERE id=$1", code.ID); err != nil {
		return AuthorizationCode{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthorizationCode{}, err
	}
	return code, nil
}

type RefreshToken struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	ParentID  *uuid.UUID
	RealmID   uuid.UUID
	ClientID  uuid.UUID
	UserID    *uuid.UUID
	SessionID *uuid.UUID
	Scope     []string
	ExpiresAt time.Time
}

func (s *Store) CreateRefreshToken(ctx context.Context, token RefreshToken) (string, error) {
	raw, err := cryptoutil.RandomToken(48)
	if err != nil {
		return "", err
	}
	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	if token.FamilyID == uuid.Nil {
		token.FamilyID = uuid.New()
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO refresh_tokens(id,token_hash,family_id,parent_id,realm_id,client_id,
        user_id,session_id,scope,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, token.ID,
		s.Sealer.Digest(raw), token.FamilyID, token.ParentID, token.RealmID, token.ClientID,
		token.UserID, token.SessionID, token.Scope, token.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}
	return raw, nil
}

var ErrTokenReuse = errors.New("refresh token reuse detected")

// RotateRefreshToken enforces one-time use. Reuse revokes the entire token
// family so a stolen older token cannot silently maintain persistence.
func (s *Store) RotateRefreshToken(ctx context.Context, raw string, reducedScopes []string) (RefreshToken, string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RefreshToken{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var old RefreshToken
	var rotatedAt, revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT id,family_id,parent_id,realm_id,client_id,user_id,session_id,scope,
        expires_at,rotated_at,revoked_at FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE`, s.Sealer.Digest(raw)).Scan(
		&old.ID, &old.FamilyID, &old.ParentID, &old.RealmID, &old.ClientID, &old.UserID,
		&old.SessionID, &old.Scope, &old.ExpiresAt, &rotatedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, "", ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, "", err
	}
	if rotatedAt != nil || revokedAt != nil {
		_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, old.FamilyID)
		if err := tx.Commit(ctx); err != nil {
			return RefreshToken{}, "", err
		}
		return RefreshToken{}, "", ErrTokenReuse
	}
	if old.ExpiresAt.Before(time.Now().UTC()) {
		return RefreshToken{}, "", ErrNotFound
	}
	if old.SessionID != nil {
		var sessionActive bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sso_sessions WHERE id=$1 AND
            revoked_at IS NULL AND expires_at>now())`, old.SessionID).Scan(&sessionActive); err != nil || !sessionActive {
			return RefreshToken{}, "", ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE refresh_tokens SET rotated_at=now() WHERE id=$1", old.ID); err != nil {
		return RefreshToken{}, "", err
	}
	rawNew, err := cryptoutil.RandomToken(48)
	if err != nil {
		return RefreshToken{}, "", err
	}
	newToken := old
	newToken.ID = uuid.New()
	newToken.ParentID = &old.ID
	if reducedScopes != nil {
		newToken.Scope = reducedScopes
	}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens(id,token_hash,family_id,parent_id,realm_id,client_id,
        user_id,session_id,scope,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, newToken.ID,
		s.Sealer.Digest(rawNew), newToken.FamilyID, newToken.ParentID, newToken.RealmID, newToken.ClientID,
		newToken.UserID, newToken.SessionID, newToken.Scope, newToken.ExpiresAt); err != nil {
		return RefreshToken{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return RefreshToken{}, "", err
	}
	return newToken, rawNew, nil
}

func (s *Store) InspectRefreshToken(ctx context.Context, raw string) (RefreshToken, bool, error) {
	var token RefreshToken
	var active bool
	err := s.Pool.QueryRow(ctx, `SELECT id,family_id,parent_id,realm_id,client_id,user_id,session_id,scope,
        expires_at,(rotated_at IS NULL AND revoked_at IS NULL AND expires_at>now()) FROM refresh_tokens
        WHERE token_hash=$1`, s.Sealer.Digest(raw)).Scan(&token.ID, &token.FamilyID, &token.ParentID,
		&token.RealmID, &token.ClientID, &token.UserID, &token.SessionID, &token.Scope, &token.ExpiresAt, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, false, ErrNotFound
	}
	return token, active, err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, raw string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
        WHERE family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1)`, s.Sealer.Digest(raw))
	return err
}

func (s *Store) RevokeAccessJTI(ctx context.Context, jti uuid.UUID, expiresAt time.Time) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO revoked_access_tokens(jti,expires_at) VALUES($1,$2)
        ON CONFLICT(jti) DO NOTHING`, jti, expiresAt)
	return err
}

func (s *Store) IsAccessJTIRevoked(ctx context.Context, jti uuid.UUID) (bool, error) {
	var revoked bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM revoked_access_tokens
        WHERE jti=$1 AND expires_at>now())`, jti).Scan(&revoked)
	return revoked, err
}
