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
        WHERE token_hash=ANY($1::bytea[]) AND consumed_at IS NULL AND expires_at>now()`, s.Sealer.Digests(token)))
}

func (s *Store) ConsumeAuthorizationRequest(ctx context.Context, token string) (AuthorizationRequest, error) {
	return scanAuthorizationRequest(s.Pool.QueryRow(ctx, `UPDATE authorization_requests SET consumed_at=now()
        WHERE token_hash=ANY($1::bytea[]) AND consumed_at IS NULL AND expires_at>now()
        RETURNING id,realm_id,client_id,redirect_uri,response_type,scope,state,nonce,code_challenge,
        code_challenge_method,prompt,expires_at`, s.Sealer.Digests(token)))
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

func scanAuthorizationCodeWithState(row pgx.Row, consumed *bool) (AuthorizationCode, error) {
	var code AuthorizationCode
	err := row.Scan(&code.ID, &code.RealmID, &code.ClientID, &code.UserID, &code.SessionID,
		&code.RedirectURI, &code.Scope, &code.Nonce, &code.CodeChallenge, &code.CodeChallengeMethod,
		&code.ExpiresAt, consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationCode{}, ErrNotFound
	}
	return code, err
}

// ErrCodeReuse reports that an authorization code was presented twice. Only
// one of the two callers can have been the relying party, and the server has
// no way to tell which, so the caller should treat it as a leaked code.
var ErrCodeReuse = errors.New("authorization code reuse detected")

// RedeemAuthorizationCode consumes a code exactly once.
//
// A second presentation is not merely rejected. Redeeming a code is the step
// that turns a value carried through a browser redirect into tokens, so a code
// arriving twice means it leaked — through a referrer header, a shared device,
// or a mis-registered redirect target — and one of the two callers holds
// tokens it should not. Because the legitimate relying party cannot be
// identified after the fact, every refresh token this code could have produced
// is revoked, mirroring how a replayed refresh token takes down its family.
// Access tokens already minted stay valid until they expire; the refresh
// tokens are what would have made the compromise durable.
func (s *Store) RedeemAuthorizationCode(ctx context.Context, raw string, validate func(AuthorizationCode) error) (AuthorizationCode, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var consumed bool
	code, err := scanAuthorizationCodeWithState(tx.QueryRow(ctx, `SELECT id,realm_id,client_id,user_id,session_id,
		redirect_uri,scope,nonce,code_challenge,code_challenge_method,expires_at,consumed_at IS NOT NULL
		FROM authorization_codes WHERE code_hash=ANY($1::bytea[]) FOR UPDATE`, s.Sealer.Digests(raw)), &consumed)
	if err != nil {
		return AuthorizationCode{}, err
	}
	if consumed {
		// Scoped to the session and client this code was issued for, so one
		// relying party's incident does not sign the user out of the others.
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
			WHERE session_id=$1 AND client_id=$2 AND revoked_at IS NULL`, code.SessionID, code.ClientID); err != nil {
			return AuthorizationCode{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AuthorizationCode{}, err
		}
		return code, ErrCodeReuse
	}
	// An expired code produced nothing, so there is nothing to revoke and it
	// is indistinguishable from a code that never existed.
	if !code.ExpiresAt.After(time.Now()) {
		return AuthorizationCode{}, ErrNotFound
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

// refreshRotationGrace lets a token that was already rotated be presented
// again for a short window. Browsers and mobile clients routinely fire two
// refreshes at once (parallel tabs, a retried request whose response was lost
// on the network), and treating that as theft logs the user out of every
// client at once. Only presentations outside this window — or of an explicitly
// revoked token — are treated as reuse.
const refreshRotationGrace = 30 * time.Second

// RotateRefreshToken enforces one-time use outside refreshRotationGrace. Reuse
// revokes the entire token family so a stolen older token cannot silently
// maintain persistence.
func (s *Store) RotateRefreshToken(ctx context.Context, raw string, reducedScopes []string) (RefreshToken, string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RefreshToken{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var old RefreshToken
	var rotatedAt, revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT id,family_id,parent_id,realm_id,client_id,user_id,session_id,scope,
        expires_at,rotated_at,revoked_at FROM refresh_tokens WHERE token_hash=ANY($1::bytea[]) FOR UPDATE`, s.Sealer.Digests(raw)).Scan(
		&old.ID, &old.FamilyID, &old.ParentID, &old.RealmID, &old.ClientID, &old.UserID,
		&old.SessionID, &old.Scope, &old.ExpiresAt, &rotatedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, "", ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, "", err
	}
	withinGrace := rotatedAt != nil && revokedAt == nil && time.Since(*rotatedAt) <= refreshRotationGrace
	if (rotatedAt != nil || revokedAt != nil) && !withinGrace {
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
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sso_sessions s
            JOIN realms r ON r.id=s.realm_id WHERE s.id=$1 AND `+sessionIsLive+`)`,
			old.SessionID).Scan(&sessionActive); err != nil || !sessionActive {
			return RefreshToken{}, "", ErrNotFound
		}
	}
	// COALESCE keeps the first rotation timestamp so the grace window is fixed
	// from the original rotation and cannot be extended by repeated retries.
	if _, err := tx.Exec(ctx, "UPDATE refresh_tokens SET rotated_at=COALESCE(rotated_at,now()) WHERE id=$1", old.ID); err != nil {
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
        WHERE token_hash=ANY($1::bytea[])`, s.Sealer.Digests(raw)).Scan(&token.ID, &token.FamilyID, &token.ParentID,
		&token.RealmID, &token.ClientID, &token.UserID, &token.SessionID, &token.Scope, &token.ExpiresAt, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, false, ErrNotFound
	}
	return token, active, err
}

// RollbackRefreshRotation undoes a rotation whose exchange never completed.
//
// Refreshing is two steps: rotate the token, then mint the tokens that go back
// to the caller. If the second step fails — the signing key cannot be opened,
// the session ended between the two, the database stumbled — the caller is
// left holding a token the server has already marked rotated. It works for the
// length of the grace window and then, on the next attempt, looks exactly like
// a replayed token: the family is revoked, the user is signed out of that
// relying party, and an incident that never happened is written to the audit
// log. Undoing the rotation is what makes the caller's retry ordinary.
//
// Only an untouched successor is removed. If a concurrent refresh has already
// built on it, that exchange succeeded and its tokens are somebody's now.
func (s *Store) RollbackRefreshRotation(ctx context.Context, oldID, newID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `DELETE FROM refresh_tokens
        WHERE id=$1 AND rotated_at IS NULL AND revoked_at IS NULL`, newID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return nil
	}
	// The predecessor is restored only while it is still the live token, so a
	// family revoked in the meantime stays revoked.
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET rotated_at=NULL
        WHERE id=$1 AND revoked_at IS NULL
        AND NOT EXISTS(SELECT 1 FROM refresh_tokens c WHERE c.parent_id=$1)`, oldID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeRefreshToken(ctx context.Context, raw string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
        WHERE family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=ANY($1::bytea[]) LIMIT 1)`, s.Sealer.Digests(raw))
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
